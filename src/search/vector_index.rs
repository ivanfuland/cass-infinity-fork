//! Vector index facade for cass.
//!
//! W3-5: the frankensearch-backed FSVI vector index format (`VectorIndex`/
//! `VectorIndexWriter`/`Quantization`/`SearchParams`, plus the query-time
//! HNSW-ANN path and `cass index --build-hnsw`) has been retired -- a
//! builder with no reader (search-side HNSW consumption was already cut in
//! 3f7aa054) whose two stated reasons for staying (a W3-2 migrator that
//! still needed to read `.fsvi`, and hash being the "always-on" fallback
//! embedder) both no longer hold: W3-2 itself was cancelled, and the hash
//! embedder's own write path was retired in 4064e8fc. The DB-vector-domain
//! (`message_embeddings` + sqlite-vec) engine is the sole vector search
//! path now. This module keeps the still-live cass-specific helpers (doc_id
//! encoding, role codes, portable-SIMD dot product) in one place.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use half::f16;
use wide::f32x8;

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

/// SIMD dot product benchmark helper (portable SIMD via `wide`).
#[must_use]
pub fn dot_product_simd_bench(a: &[f32], b: &[f32]) -> f32 {
    dot_product_f32_f32(a, b).expect("dot product inputs must match length")
}

/// Scalar dot product benchmark helper for f16 stored vectors vs f32 query.
#[must_use]
pub fn dot_product_f16_scalar_bench(stored: &[f16], query: &[f32]) -> f32 {
    stored.iter().zip(query).map(|(x, y)| x.to_f32() * y).sum()
}

/// SIMD dot product benchmark helper for f16 stored vectors vs f32 query.
#[must_use]
pub fn dot_product_f16_simd_bench(stored: &[f16], query: &[f32]) -> f32 {
    dot_product_f16_f32(stored, query).expect("dot product inputs must match length")
}

// ============================================================================
// W3-5 verbatim restore of `frankensearch-index/src/simd.rs`'s portable-SIMD
// dot product primitives (git rev `2cad158f4468ece7076e3fe529c8e5c20b2e020e`,
// <https://github.com/Dicklesworthstone/frankensearch>), now that the
// `frankensearch` Cargo dependency itself is retired. These two functions
// are pure SIMD arithmetic (`wide::f32x8`), unrelated to the FSVI file
// format retired above; their only consumers are `benches/runtime_perf.rs`,
// `benches/search_perf.rs`, and `tests/simd_tests.rs` (SIMD-vs-scalar
// correctness/speed validation), which is why they're restored rather than
// deleted alongside the FSVI format. `dot_product_f16_bytes_f32`/
// `dot_product_f32_bytes_f32`/`cosine_similarity_f16` from the same
// upstream file are dropped: zero consumers in this crate.
// ============================================================================

/// Dot product between two f32 vectors.
///
/// # Errors
///
/// Returns an error when slice lengths differ.
pub fn dot_product_f32_f32(a: &[f32], b: &[f32]) -> Result<f32> {
    ensure_same_len(a.len(), b.len())?;
    Ok(dot_product_f32_f32_unchecked(a, b))
}

/// Dot product between an f16 stored vector and an f32 query vector.
///
/// # Errors
///
/// Returns an error when slice lengths differ.
pub fn dot_product_f16_f32(stored: &[f16], query: &[f32]) -> Result<f32> {
    ensure_same_len(stored.len(), query.len())?;

    let mut sum = f32x8::splat(0.0);
    let mut stored_chunks = stored.chunks_exact(8);
    let mut query_chunks = query.chunks_exact(8);

    for (stored_chunk, query_chunk) in stored_chunks.by_ref().zip(query_chunks.by_ref()) {
        let s = [
            stored_chunk[0].to_f32(),
            stored_chunk[1].to_f32(),
            stored_chunk[2].to_f32(),
            stored_chunk[3].to_f32(),
            stored_chunk[4].to_f32(),
            stored_chunk[5].to_f32(),
            stored_chunk[6].to_f32(),
            stored_chunk[7].to_f32(),
        ];
        let q = [
            query_chunk[0],
            query_chunk[1],
            query_chunk[2],
            query_chunk[3],
            query_chunk[4],
            query_chunk[5],
            query_chunk[6],
            query_chunk[7],
        ];
        sum += f32x8::from(s) * f32x8::from(q);
    }

    let mut result = sum.reduce_add();
    for (s, q) in stored_chunks
        .remainder()
        .iter()
        .zip(query_chunks.remainder())
    {
        result += s.to_f32() * q;
    }
    Ok(result)
}

fn dot_product_f32_f32_unchecked(a: &[f32], b: &[f32]) -> f32 {
    let mut sum = f32x8::splat(0.0);
    let mut a_chunks = a.chunks_exact(8);
    let mut b_chunks = b.chunks_exact(8);

    for (a_chunk, b_chunk) in a_chunks.by_ref().zip(b_chunks.by_ref()) {
        let a_arr = [
            a_chunk[0], a_chunk[1], a_chunk[2], a_chunk[3], a_chunk[4], a_chunk[5], a_chunk[6],
            a_chunk[7],
        ];
        let b_arr = [
            b_chunk[0], b_chunk[1], b_chunk[2], b_chunk[3], b_chunk[4], b_chunk[5], b_chunk[6],
            b_chunk[7],
        ];
        sum += f32x8::from(a_arr) * f32x8::from(b_arr);
    }

    let mut result = sum.reduce_add();
    for (x, y) in a_chunks.remainder().iter().zip(b_chunks.remainder()) {
        result += x * y;
    }
    result
}

fn ensure_same_len(expected: usize, found: usize) -> Result<()> {
    if expected != found {
        return Err(anyhow!(
            "dot product dimension mismatch: expected {expected}, found {found}"
        ));
    }
    Ok(())
}

/// Default on-disk location for the (now-retired-writer) HNSW index for a
/// given embedder. W3-5: `cass index --build-hnsw` (the sole writer) is
/// retired -- kept only so `cass doctor`/asset-state reporting can still
/// detect a leftover `.chsw` file from a pre-decommission install.
#[must_use]
pub fn hnsw_index_path(data_dir: &Path, embedder_id: &str) -> PathBuf {
    data_dir
        .join(VECTOR_INDEX_DIR)
        .join(format!("hnsw-{embedder_id}.chsw"))
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
