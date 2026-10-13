//! Model-identity stability contract.
//!
//! Local in-process inference (the ONNX/fastembed embedder and the local
//! Infinity HTTP engine) is retired; this file replaces the old cass#256
//! baseline-feature-gate test whose whole subject — the `semantic` Cargo
//! feature — no longer exists.
//!
//! What remains load-bearing is the *descriptive* local-model identity the
//! read-only status surfaces and the vector-index layout are keyed on. These
//! pins catch accidental alias/id/dimension/directory drift, because a changed
//! value silently changes what a stored generation fingerprint and a status
//! surface mean.

use coding_agent_search::search::model_identity;

#[test]
fn canonical_name_accepts_documented_aliases() {
    assert_eq!(model_identity::canonical_name("minilm"), Some("minilm"));
    assert_eq!(model_identity::canonical_name("fastembed"), Some("minilm"));
    assert_eq!(
        model_identity::canonical_name("all-minilm-l6-v2"),
        Some("minilm")
    );
    assert_eq!(model_identity::canonical_name("MINILM-384"), Some("minilm"));
    assert_eq!(
        model_identity::canonical_name("snowflake-arctic-embed-s"),
        Some("snowflake-arctic-s")
    );
    assert_eq!(
        model_identity::canonical_name("nomic-embed-text-v1.5"),
        Some("nomic-embed")
    );
    assert!(model_identity::canonical_name("not-a-model").is_none());
}

#[test]
fn embedder_ids_and_dimensions_are_stable() {
    // Referenced by status JSON and by the semantic asset-state probe; drift
    // would silently break the status surface.
    assert_eq!(model_identity::embedder_id_static(), "minilm-384");
    assert_eq!(model_identity::model_id_static(), "all-minilm-l6-v2");
    assert_eq!(model_identity::embedder_id_for("minilm"), Some("minilm-384"));
    assert_eq!(model_identity::dimension_for("minilm"), Some(384));
    assert_eq!(
        model_identity::embedder_id_for("nomic-embed"),
        Some("nomic-embed-768")
    );
    assert_eq!(model_identity::dimension_for("nomic-embed"), Some(768));
}

#[test]
fn default_model_dir_layout_is_stable() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = model_identity::default_model_dir(tmp.path());
    assert!(
        dir.ends_with("models/all-MiniLM-L6-v2"),
        "default model dir layout drifted: {dir:?}"
    );
}
