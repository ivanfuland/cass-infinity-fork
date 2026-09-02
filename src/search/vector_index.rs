//! Vector index facade for cass.
//!
//! cass uses the frankensearch FSVI vector index format and search primitives
//! (via the `frankensearch` crate). The older CVVI format has been retired.
//!
//! This module keeps cass-specific helpers (paths, role codes) in one place.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use crate::storage::api::Conn as FrankenConnection;
use half::f16;

pub use frankensearch::index::{Quantization, SearchParams, VectorIndex, VectorIndexWriter};

use crate::sources::provenance::SourceKind;
use crate::storage::sqlite::FrankenStorage;

/// Directory under the cass data dir where vector artifacts are stored.
pub const VECTOR_INDEX_DIR: &str = "vector_index";

// Message role codes stored in doc_id metadata and used for filtering.
pub const ROLE_USER: u8 = 0;
pub const ROLE_ASSISTANT: u8 = 1;
pub const ROLE_SYSTEM: u8 = 2;
pub const ROLE_TOOL: u8 = 3;

/// Map a role string (from SQLite / connectors) to a compact u8 code.
#[must_use]
pub fn role_code_from_str(role: &str) -> Option<u8> {
    match role {
        "user" => Some(ROLE_USER),
        // cass historically used both "agent" and "assistant" for model responses;
        // 6-role franken adds "reasoning" (model-authored thinking).
        "assistant" | "agent" | "reasoning" => Some(ROLE_ASSISTANT),
        // "developer" is the legacy pre-6-role name for system-authored codex messages.
        "system" | "developer" => Some(ROLE_SYSTEM),
        // legacy "tool"/"toolResult" + 6-role "tool_call"/"tool_result" all filter as TOOL.
        "tool" | "toolResult" | "tool_call" | "tool_result" => Some(ROLE_TOOL),
        _ => None,
    }
}

/// Parse a list of role strings into a set of role codes.
///
/// # Errors
///
/// Returns an error if any role string is unknown.
pub fn parse_role_codes<I, S>(roles: I) -> Result<HashSet<u8>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut out = HashSet::new();
    for role in roles {
        let role_str = role.as_ref();
        let code =
            role_code_from_str(role_str).ok_or_else(|| anyhow!("unknown role: {role_str}"))?;
        out.insert(code);
    }
    Ok(out)
}

/// Path to the primary FSVI vector index for a given embedder.
#[must_use]
pub fn vector_index_path(data_dir: &Path, embedder_id: &str) -> PathBuf {
    data_dir
        .join(VECTOR_INDEX_DIR)
        .join(format!("index-{embedder_id}.fsvi"))
}

/// Semantic doc_id fields encoded into FSVI records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticDocId {
    pub message_id: u64,
    pub chunk_idx: u8,
    pub agent_id: u32,
    pub workspace_id: u32,
    pub source_id: u32,
    pub role: u8,
    pub created_at_ms: i64,
    pub content_hash: Option<[u8; 32]>,
}

impl SemanticDocId {
    /// Encode this semantic vector record doc_id into the string form stored in FSVI.
    ///
    /// Hot-path encoder: runs once per embedded message during indexing and
    /// for every search hit that goes through semantic lookup. Build the
    /// output in a single pre-sized `String` with `itoa::Buffer` for the
    /// integer fields instead of `format!`, which walks the formatter-trait
    /// machinery per arg and grows its internal buffer on demand.
    #[must_use]
    pub fn to_doc_id_string(&self) -> String {
        // Capacity estimate: "m|" (2) + seven integer fields up to 20 chars
        // + six '|' separators + optional 64-hex hash + one '|' if present.
        // Slight over-allocation is fine and avoids any realloc.
        let capacity = 2 + (7 * 20) + 6 + if self.content_hash.is_some() { 65 } else { 0 };
        let mut out = String::with_capacity(capacity);
        let mut buf = itoa::Buffer::new();
        out.push_str("m|");
        out.push_str(buf.format(self.message_id));
        out.push('|');
        out.push_str(buf.format(self.chunk_idx));
        out.push('|');
        out.push_str(buf.format(self.agent_id));
        out.push('|');
        out.push_str(buf.format(self.workspace_id));
        out.push('|');
        out.push_str(buf.format(self.source_id));
        out.push('|');
        out.push_str(buf.format(self.role));
        out.push('|');
        out.push_str(buf.format(self.created_at_ms));
        if let Some(hash) = self.content_hash {
            out.push('|');
            // Stack-buffered hex encode: avoids the 64-byte heap alloc that
            // `hex::encode(hash)` performs internally. Hex output is pure
            // ASCII so str::from_utf8 can't fail on the filled slice.
            let mut hex_buf = [0u8; 64];
            hex::encode_to_slice(hash, &mut hex_buf)
                .expect("32 bytes encode to exactly 64 hex chars");
            out.push_str(std::str::from_utf8(&hex_buf).expect("hex output is always valid ASCII"));
        }
        out
    }
}

/// Parse a cass semantic doc_id string.
///
/// Accepts doc_ids with trailing segments (future expansion) and an optional
/// 64-hex content hash suffix.
#[must_use]
pub fn parse_semantic_doc_id(doc_id: &str) -> Option<SemanticDocId> {
    // Fast reject: every cass semantic doc_id starts with "m|". `strip_prefix`
    // avoids the full iterator setup + first `.next()` comparison when the
    // discriminator doesn't match. `splitn(8, '|')` caps the field scan at
    // exactly the 7 required fields + a single tail holding the optional
    // content hash (which itself never contains '|').
    let rest = doc_id.strip_prefix("m|")?;
    let mut parts = rest.splitn(8, '|');
    let parsed = SemanticDocId {
        message_id: parts.next()?.parse().ok()?,
        chunk_idx: parts.next()?.parse().ok()?,
        agent_id: parts.next()?.parse().ok()?,
        workspace_id: parts.next()?.parse().ok()?,
        source_id: parts.next()?.parse().ok()?,
        role: parts.next()?.parse().ok()?,
        created_at_ms: parts.next()?.parse().ok()?,
        content_hash: parts.next().and_then(|hash_hex| {
            if hash_hex.len() != 64 {
                return None;
            }
            let mut hash = [0u8; 32];
            hex::decode_to_slice(hash_hex, &mut hash).ok()?;
            Some(hash)
        }),
    };

    Some(parsed)
}

fn source_id_hash(source_id: &str) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(source_id.as_bytes());
    hasher.finalize()
}

/// Lookup maps for converting human filters (agent slug, workspace path, source id)
/// into compact numeric IDs embedded into semantic doc_id strings.
#[derive(Debug, Clone)]
pub struct SemanticFilterMaps {
    agent_slug_to_id: HashMap<String, u32>,
    workspace_path_to_id: HashMap<String, u32>,
    source_id_to_id: HashMap<String, u32>,
    remote_source_ids: HashSet<u32>,
}

impl SemanticFilterMaps {
    pub fn from_storage(storage: &FrankenStorage) -> Result<Self> {
        Self::from_connection(storage.raw())
    }

    pub fn from_connection(conn: &FrankenConnection) -> Result<Self> {
        let mut agent_slug_to_id = HashMap::new();
        let agent_rows = conn.query_all_map(
            "SELECT id, slug FROM agents",
            &[],
            |row| {
                let id: i64 = row.get_typed(0)?;
                let slug: String = row.get_typed(1)?;
                Ok((id, slug))
            },
        )?;
        for (id, slug) in agent_rows {
            let id_u32 = u32::try_from(id).map_err(|_| anyhow!("agent id out of range"))?;
            agent_slug_to_id.insert(slug, id_u32);
        }

        let mut workspace_path_to_id = HashMap::new();
        let workspace_rows = conn.query_all_map(
            "SELECT id, path FROM workspaces",
            &[],
            |row| {
                let id: i64 = row.get_typed(0)?;
                let path: String = row.get_typed(1)?;
                Ok((id, path))
            },
        )?;
        for (id, path) in workspace_rows {
            let id_u32 = u32::try_from(id).map_err(|_| anyhow!("workspace id out of range"))?;
            workspace_path_to_id.insert(path, id_u32);
        }

        let mut source_id_to_id = HashMap::new();
        let mut remote_source_ids = HashSet::new();
        let source_rows = conn.query_all_map(
            "SELECT id, kind FROM sources",
            &[],
            |row| {
                let id: String = row.get_typed(0)?;
                let kind: String = row.get_typed(1)?;
                Ok((id, kind))
            },
        )?;
        for (id, kind) in source_rows {
            let id_u32 = source_id_hash(&id);
            if SourceKind::parse(&kind).is_none_or(|k| k.is_remote()) {
                remote_source_ids.insert(id_u32);
            }
            source_id_to_id.insert(id, id_u32);
        }

        Ok(Self {
            agent_slug_to_id,
            workspace_path_to_id,
            source_id_to_id,
            remote_source_ids,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_tests(
        agent_slug_to_id: HashMap<String, u32>,
        workspace_path_to_id: HashMap<String, u32>,
        source_id_to_id: HashMap<String, u32>,
        remote_source_ids: HashSet<u32>,
    ) -> Self {
        Self {
            agent_slug_to_id,
            workspace_path_to_id,
            source_id_to_id,
            remote_source_ids,
        }
    }

}

/// Collapsed semantic search hit (best chunk per message).
#[derive(Debug, Clone)]
pub struct VectorSearchResult {
    pub message_id: u64,
    pub chunk_idx: u8,
    pub score: f32,
}

/// Scalar dot product benchmark helper.
#[must_use]
pub fn dot_product_scalar_bench(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

/// SIMD dot product benchmark helper (uses frankensearch's portable SIMD).
#[must_use]
pub fn dot_product_simd_bench(a: &[f32], b: &[f32]) -> f32 {
    frankensearch::index::dot_product_f32_f32(a, b).expect("dot product inputs must match length")
}

/// Scalar dot product benchmark helper for f16 stored vectors vs f32 query.
#[must_use]
pub fn dot_product_f16_scalar_bench(stored: &[f16], query: &[f32]) -> f32 {
    stored.iter().zip(query).map(|(x, y)| x.to_f32() * y).sum()
}

/// SIMD dot product benchmark helper for f16 stored vectors vs f32 query.
#[must_use]
pub fn dot_product_f16_simd_bench(stored: &[f16], query: &[f32]) -> f32 {
    frankensearch::index::dot_product_f16_f32(stored, query)
        .expect("dot product inputs must match length")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_code_from_str_accepts_known_roles() {
        let cases = [
            ("user", Some(ROLE_USER)),
            ("assistant", Some(ROLE_ASSISTANT)),
            ("agent", Some(ROLE_ASSISTANT)),
            ("system", Some(ROLE_SYSTEM)),
            ("tool", Some(ROLE_TOOL)),
            // 6-role franken connector contract (Task 2.2).
            ("tool_call", Some(ROLE_TOOL)),
            ("tool_result", Some(ROLE_TOOL)),
            ("reasoning", Some(ROLE_ASSISTANT)),
            // Legacy strings that predate the 6-role rename; must still
            // filter correctly for old rows already in the DB.
            ("toolResult", Some(ROLE_TOOL)),
            ("developer", Some(ROLE_SYSTEM)),
            ("unknown", None),
        ];

        for (role, expected_code) in cases {
            assert_eq!(role_code_from_str(role), expected_code, "{role}");
        }
    }

    #[test]
    fn parse_role_codes_rejects_unknown_roles() {
        let err = parse_role_codes(["user", "bogus"]).unwrap_err();
        assert!(err.to_string().contains("unknown role"));
    }

    #[test]
    fn vector_index_path_points_to_fsvi() {
        let dir = Path::new("/tmp/cass");
        let p = vector_index_path(dir, "fnv1a-384");
        assert!(p.ends_with("vector_index/index-fnv1a-384.fsvi"));
    }

    #[test]
    fn semantic_doc_id_roundtrip_with_hash() {
        let hash = [0u8; 32];
        let doc_id = SemanticDocId {
            message_id: 42,
            chunk_idx: 2,
            agent_id: 3,
            workspace_id: 7,
            source_id: 11,
            role: 1,
            created_at_ms: 1_700_000_000_000,
            content_hash: Some(hash),
        }
        .to_doc_id_string();
        let parsed = parse_semantic_doc_id(&doc_id).expect("parse");
        assert_eq!(parsed.message_id, 42);
        assert_eq!(parsed.chunk_idx, 2);
        assert_eq!(parsed.agent_id, 3);
        assert_eq!(parsed.workspace_id, 7);
        assert_eq!(parsed.source_id, 11);
        assert_eq!(parsed.role, 1);
        assert_eq!(parsed.created_at_ms, 1_700_000_000_000);
        assert_eq!(parsed.content_hash, Some(hash));
    }

    #[test]
    fn semantic_doc_id_roundtrip_without_hash() {
        let doc_id = SemanticDocId {
            message_id: 42,
            chunk_idx: 2,
            agent_id: 3,
            workspace_id: 7,
            source_id: 11,
            role: 1,
            created_at_ms: 1_700_000_000_000,
            content_hash: None,
        }
        .to_doc_id_string();
        let parsed = parse_semantic_doc_id(&doc_id).expect("parse");
        assert_eq!(parsed.message_id, 42);
        assert_eq!(parsed.chunk_idx, 2);
        assert_eq!(parsed.agent_id, 3);
        assert_eq!(parsed.workspace_id, 7);
        assert_eq!(parsed.source_id, 11);
        assert_eq!(parsed.role, 1);
        assert_eq!(parsed.created_at_ms, 1_700_000_000_000);
        assert_eq!(parsed.content_hash, None);
    }
}
