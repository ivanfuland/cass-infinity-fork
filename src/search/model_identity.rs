//! Read-only semantic model identity and directory metadata.
//!
//! Local in-process inference is retired: neither the ONNX/fastembed embedder nor
//! the local Infinity HTTP engine is part of this build, and embedding is served
//! exclusively by the configured external model API. What survives here is the
//! purely *descriptive* half of the old local-model world — the stable model ids,
//! dimensions, alias canonicalization and the on-disk cache directory layout the
//! read-only status surfaces still report against. Nothing in this module loads,
//! downloads or executes a model.
//!
//! `embedder_id_static`/`model_id_static` are the compatibility anchors the
//! vector index and the read-only generation status were historically keyed on;
//! they are kept byte-for-byte so historical databases stay legible.

use std::path::{Path, PathBuf};

// MiniLM constants (baseline identity).
const MINILM_MODEL_ID: &str = "all-minilm-l6-v2";
const MINILM_DIR_NAME: &str = "all-MiniLM-L6-v2";

/// Stable embedder identifier for MiniLM (matches vector index naming).
pub fn embedder_id_static() -> &'static str {
    "minilm-384"
}

/// Stable model identifier for MiniLM.
pub fn model_id_static() -> &'static str {
    MINILM_MODEL_ID
}

/// Dimensions of the known local model identities.
pub const MINILM_DIMENSION: usize = 384;
/// Snowflake Arctic Embed S output dimension.
pub const SNOWFLAKE_DIMENSION: usize = 384;
/// Nomic Embed Text v1.5 output dimension.
pub const NOMIC_DIMENSION: usize = 768;

/// Default MiniLM model directory relative to the cass data dir.
pub fn default_model_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("models").join(MINILM_DIR_NAME)
}

/// Get the on-disk model directory name for a canonical embedder name.
pub fn model_dir_for(data_dir: &Path, embedder_name: &str) -> Option<PathBuf> {
    let dir_name = match canonical_name(embedder_name)? {
        "minilm" => MINILM_DIR_NAME,
        "snowflake-arctic-s" => "snowflake-arctic-embed-s",
        "nomic-embed" => "nomic-embed-text-v1.5",
        _ => return None,
    };
    Some(data_dir.join("models").join(dir_name))
}

/// Resolve the runtime model directory for an embedder.
///
/// `model_dir_for` is the cass-managed cache location. This variant honors the
/// explicit `FRANKENSEARCH_MODEL_DIR` override used by operators who pre-stage a
/// model bundle outside the cass data directory.
pub fn runtime_model_dir_for(data_dir: &Path, embedder_name: &str) -> Option<PathBuf> {
    model_dir_override().or_else(|| model_dir_for(data_dir, embedder_name))
}

/// Canonicalize a model alias to its short registry name.
pub fn canonical_name(embedder_name: &str) -> Option<&'static str> {
    match embedder_name.trim().to_ascii_lowercase().as_str() {
        "fastembed" | "minilm" | "all-minilm-l6-v2" | "minilm-384" => Some("minilm"),
        "snowflake"
        | "snowflake-arctic-s"
        | "snowflake-arctic-embed-s"
        | "snowflake-arctic-s-384" => Some("snowflake-arctic-s"),
        "nomic" | "nomic-embed" | "nomic-embed-text-v1.5" | "nomic-embed-768" => Some("nomic-embed"),
        _ => None,
    }
}

/// The `embedding_generations.embedder_id` a canonical local model would use.
pub fn embedder_id_for(canonical_name: &str) -> Option<&'static str> {
    match canonical_name {
        "minilm" => Some("minilm-384"),
        "snowflake-arctic-s" => Some("snowflake-arctic-s-384"),
        "nomic-embed" => Some("nomic-embed-768"),
        _ => None,
    }
}

/// The embedding width of a canonical local model.
pub fn dimension_for(canonical_name: &str) -> Option<usize> {
    match canonical_name {
        "minilm" => Some(MINILM_DIMENSION),
        "snowflake-arctic-s" => Some(SNOWFLAKE_DIMENSION),
        "nomic-embed" => Some(NOMIC_DIMENSION),
        _ => None,
    }
}

/// The `FRANKENSEARCH_MODEL_DIR` override, expanded, when set and non-empty.
pub fn model_dir_override() -> Option<PathBuf> {
    dotenvy::var("FRANKENSEARCH_MODEL_DIR")
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|raw| !raw.is_empty())
        .map(|raw| expand_home(&raw))
}

fn expand_home(raw: &str) -> PathBuf {
    if raw == "~" {
        return dotenvy::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(raw));
    }
    if let Some(rest) = raw.strip_prefix("~/") {
        return dotenvy::var("HOME")
            .map(|home| PathBuf::from(home).join(rest))
            .unwrap_or_else(|_| PathBuf::from(raw));
    }
    PathBuf::from(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_name_accepts_policy_and_index_aliases() {
        assert_eq!(canonical_name("fastembed"), Some("minilm"));
        assert_eq!(canonical_name("all-minilm-l6-v2"), Some("minilm"));
        assert_eq!(canonical_name("minilm-384"), Some("minilm"));
        assert_eq!(canonical_name("snowflake"), Some("snowflake-arctic-s"));
        assert_eq!(canonical_name("nomic-embed-text-v1.5"), Some("nomic-embed"));
        assert_eq!(canonical_name("unknown"), None);
    }

    #[test]
    fn embedder_ids_and_dimensions_are_stable() {
        assert_eq!(embedder_id_for("minilm"), Some("minilm-384"));
        assert_eq!(dimension_for("minilm"), Some(384));
        assert_eq!(embedder_id_for("nomic-embed"), Some("nomic-embed-768"));
        assert_eq!(dimension_for("nomic-embed"), Some(768));
        assert_eq!(embedder_id_static(), "minilm-384");
        assert_eq!(model_id_static(), "all-minilm-l6-v2");
    }

    #[test]
    fn model_dir_layout_is_under_models() {
        let base = Path::new("/tmp/cass");
        let dir = default_model_dir(base);
        assert!(dir.starts_with(base.join("models")));
        assert_eq!(model_dir_for(base, "minilm"), Some(dir));
        assert_eq!(model_dir_for(base, "unknown"), None);
    }

    #[test]
    fn runtime_model_dir_honors_override() {
        // With no override set, the managed cache layout is used verbatim.
        let base = Path::new("/tmp/cass");
        assert_eq!(
            runtime_model_dir_for(base, "minilm"),
            Some(default_model_dir(base))
        );
    }
}
