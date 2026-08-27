//! w1b Task B8: the legacy-engine-era incremental migration engine
//! (`SqliteStorage::open_or_rebuild`, `meta.schema_version`-keyed fixtures)
//! this file used to test is retired -- the rusqlite engine's sole version
//! authority is `PRAGMA user_version` via `storage::schema::ensure`, which
//! has its own `#[cfg(test)]` coverage in `src/storage/schema.rs`. Every
//! test that exercised the old engine (`test_migration_creates_backup`,
//! `test_migration_preserves_data`, `test_migration_handles_corruption`,
//! `test_schema_version_5_to_current`, `test_fts_rebuild`,
//! `test_failed_migration_preserves_original`) is gone -- see
//! `w1b-b4-deleted-tests.md` for the closed-world record. The one test that
//! had nothing to do with schema migration in the first place
//! (`test_legacy_single_slot_config` tests `pages::encrypt::EncryptionConfig`
//! JSON deserialization) survives unchanged below.

// =============================================================================
// Key Slot Migration Tests
// =============================================================================

/// Test that old encryption configs without recovery slots work.
#[test]
fn test_legacy_single_slot_config() {
    use serde_json::json;

    let legacy_config = json!({
        "version": 1,
        "export_id": "AAAAAAAAAAAAAAAAAAAAAA==",
        "base_nonce": "AAAAAAAAAAAA",
        "compression": "deflate",
        "kdf_defaults": {
            "memory_kb": 65536,
            "iterations": 3,
            "parallelism": 4
        },
        "payload": {
            "chunk_size": 8388608,
            "chunk_count": 1,
            "total_compressed_size": 1024,
            "total_plaintext_size": 2048,
            "files": ["data.db"]
        },
        "key_slots": [{
            "id": 0,
            "slot_type": "password",
            "kdf": "argon2id",
            "salt": "c2FsdHNhbHRzYWx0c2FsdA==",
            "wrapped_dek": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "nonce": "AAAAAAAAAAAA",
            "argon2_params": {
                "memory_kb": 65536,
                "iterations": 3,
                "parallelism": 4
            }
        }]
    });

    // Should parse without recovery slot
    let config: coding_agent_search::pages::encrypt::EncryptionConfig =
        serde_json::from_value(legacy_config).unwrap();

    assert_eq!(config.key_slots.len(), 1);
    assert_eq!(
        config.key_slots[0].slot_type,
        coding_agent_search::pages::encrypt::SlotType::Password
    );
}
