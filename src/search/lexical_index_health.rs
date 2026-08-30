//! W2-6 Task1: FTS5/`lex_docs` domain health-check interface.
//!
//! Reseats the public "is the searchable index there / healthy / fresh"
//! surface that used to live in [`crate::search::tantivy`] against tantivy's
//! filesystem index directory, onto the `lex_docs`/`fts_lex` SQLite domain
//! (`agent_search.db`) instead. Callers that used to pass a tantivy index
//! directory path now pass the `agent_search.db` file path.
//!
//! Two of the old six functions (`searchable_index_fingerprint`,
//! `lexical_search_evidence_bundle_manifest`'s chunk-manifest shape) are not
//! reseated here -- see W2-6 Task1/Task2 closed-world accounting: the former
//! served a staged-rebuild checkpoint state machine that no longer exists
//! under W2-2/W2-3's in-transaction dual write, and the latter's
//! federated-shard evidence-chunk model has no SQLite-domain equivalent. The
//! `lexical_search_evidence_bundle_manifest` CLI surface (`cass sources
//! artifact-manifest`) survives as [`LexicalDomainAttestation`] instead
//! (control-plane 2026-08-30 ruling): db file sha256 + user_version +
//! lex_docs/fts_lex row counts, matching this project's existing
//! staging-handoff attestation triple shape.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::search::tantivy::SearchableIndexSummary;
use crate::storage::api::Conn;

/// "Is there a usable lexical index at `db_path`" -- a "has content but no
/// coverage" detector, not a bare schema-presence check (control-plane
/// 2026-08-30 ruling, superseding an earlier "table present" draft).
///
/// `lex_docs`/`fts_lex` get created unconditionally by schema migration the
/// moment `agent_search.db` is opened at all, so "table present" is true for
/// nearly every real installation regardless of whether anything was ever
/// indexed into it -- a dead signal that can never catch the case that
/// matters (a v1->v2-migrated database that never ran `--full`/rebuild, or
/// any other way the domain ended up structurally empty while the relational
/// data is not). The tantivy original avoided this because its `meta.json`
/// only appeared after a real index build ran; there is no SQLite-domain
/// equivalent of "never built" other than looking at the data itself.
///
/// Definition: `exists = NOT (messages has any row AND lex_docs has no row)`.
/// Equivalently: an empty corpus is vacuously "exists" (nothing to index
/// yet, not a failure); a non-empty corpus with zero `lex_docs` rows is
/// "not exists" (self-heal should rebuild). Partial backfill (some but not
/// all qualifying messages projected) still reads as "exists" here -- this
/// function only answers "was the domain ever populated at all", not "is it
/// complete/fresh"; that finer-grained divergence is
/// [`validate_searchable_index_contract_quick`]/[`validate_searchable_index_contract_full`]'s
/// and a future full doc-count reconciliation's job, not this one's.
pub fn searchable_index_exists(db_path: &Path) -> bool {
    if !db_path.exists() {
        return false;
    }
    let Ok(conn) = Conn::open_read(db_path) else {
        return false;
    };
    let lex_docs_table_present: i64 = conn
        .query_row_map(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'lex_docs'",
            &[],
            |row| row.get_typed(0),
        )
        .unwrap_or(0);
    if lex_docs_table_present == 0 {
        return false;
    }
    let has_messages: i64 = conn
        .query_row_map("SELECT EXISTS(SELECT 1 FROM messages LIMIT 1)", &[], |row| {
            row.get_typed(0)
        })
        .unwrap_or(0);
    if has_messages == 0 {
        return true;
    }
    let has_lex_docs: i64 = conn
        .query_row_map("SELECT EXISTS(SELECT 1 FROM lex_docs LIMIT 1)", &[], |row| {
            row.get_typed(0)
        })
        .unwrap_or(0);
    has_lex_docs != 0
}

/// Two-tier contract check (control-plane 2026-08-30 amendment, after the
/// full check was found riding the hot search-query path at ~3-4 minutes on
/// a million-row corpus): the name carries the cost so nobody wires the
/// wrong tier by accident.
///
/// - [`validate_searchable_index_contract_quick`]: file-system-level cost
///   (try-open + a `LIMIT 1` probe), matching the old tantivy version's
///   cost class. Use on every hot-path call (e.g. per-search self-heal
///   diagnosis). Catches "can't open" / "basic structure broken" / "domain
///   never built", not "content silently drifted from the index".
/// - [`validate_searchable_index_contract_full`]: the delta w2-d1 judgment,
///   `INSERT INTO fts_lex(fts_lex, rank) VALUES('integrity-check', 1)`,
///   which re-tokenizes and compares every row -- full-corpus cost. Reserve
///   for explicit, infrequent scenarios: doctor's post-repair probe,
///   doctor's explicit health check, and the W2-7 门① gate. The old tantivy
///   hot path couldn't catch content/index drift either (it only compared a
///   file hash) -- routing this off the hot path is not a capability
///   regression, just not accidentally wiring a new capability into it.
///
/// Both must run against cass's own bundled SQLite engine (the same
/// connection path production writes use), not an external `sqlite3` CLI,
/// because a differing trigram tokenizer build reports false `malformed`
/// (delta w2-d1).
pub fn validate_searchable_index_contract_quick(db_path: &Path) -> Result<()> {
    if !searchable_index_exists(db_path) {
        anyhow::bail!(
            "lexical index domain is missing in {} (no lex_docs table)",
            db_path.display()
        );
    }
    let conn = Conn::open_read(db_path)
        .with_context(|| format!("opening {} for quick lexical contract check", db_path.display()))?;
    // `query_opt_map` tolerates the table being empty (0 rows is a valid,
    // healthy state -- LIMIT 1 on an empty table is not a failure); it only
    // errors if the query itself can't execute (basic structure broken).
    conn.query_opt_map("SELECT rowid FROM fts_lex LIMIT 1", &[], |row| {
        row.get_typed::<i64>(0)
    })
    .with_context(|| {
        format!(
            "quick fts5 probe (SELECT rowid FROM fts_lex LIMIT 1) failed against {}",
            db_path.display()
        )
    })?;
    Ok(())
}

pub fn validate_searchable_index_contract_full(db_path: &Path) -> Result<()> {
    if !searchable_index_exists(db_path) {
        anyhow::bail!(
            "lexical index domain is missing in {} (no lex_docs table)",
            db_path.display()
        );
    }
    let conn = Conn::open_writable(db_path, crate::storage::api::Profile::Production)
        .with_context(|| format!("opening {} for fts5 integrity-check", db_path.display()))?;
    conn.execute("INSERT INTO fts_lex(fts_lex, rank) VALUES('integrity-check', 1)", &[])
        .with_context(|| {
            format!(
                "fts5 rank=1 integrity-check failed against {}",
                db_path.display()
            )
        })?;
    Ok(())
}

/// FTS5-domain equivalent of the old tantivy segment/doc-count summary.
/// `segments` has no SQLite-domain analogue (external-content FTS5 is not
/// segmented the way a tantivy index is); it is pinned to `1` rather than
/// removed from the struct, since no consumer reads it (only `.docs`) and
/// dropping the field would force a needless struct-shape change across
/// every caller.
pub fn searchable_index_summary(db_path: &Path) -> Result<Option<SearchableIndexSummary>> {
    if !searchable_index_exists(db_path) {
        return Ok(None);
    }
    let conn = Conn::open_read(db_path)
        .with_context(|| format!("opening {} for lexical index summary", db_path.display()))?;
    let docs: i64 = conn
        .query_row_map("SELECT COUNT(*) FROM lex_docs", &[], |row| row.get_typed(0))
        .context("counting lex_docs rows for lexical index summary")?;
    Ok(Some(SearchableIndexSummary {
        docs: docs as usize,
        segments: 1,
    }))
}

/// FTS5-domain equivalent of the old tantivy `meta.json` mtime fallback:
/// there is no per-row lex_docs write timestamp, so the DB file's own mtime
/// is the same order of precision as the old approximation (tantivy's
/// `meta.json` mtime was also just "when did the index directory last get
/// touched", not a precise last-lexical-write timestamp).
pub fn searchable_index_modified_time(db_path: &Path) -> Option<SystemTime> {
    fs::metadata(db_path).and_then(|m| m.modified()).ok()
}

/// SQLite-domain replacement for the old federated evidence-bundle manifest:
/// the three-plus-one attestation values already used by this project's
/// staging-handoff process (db file sha256 + `user_version` + row counts for
/// both `lex_docs` and `fts_lex`, which self-consistency-check each other
/// since `fts_lex` is `lex_docs`'s external-content shadow).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LexicalDomainAttestation {
    pub db_sha256: String,
    pub user_version: i64,
    pub lex_docs_rows: i64,
    pub fts_lex_rows: i64,
}

impl LexicalDomainAttestation {
    /// Compute a fresh attestation from the live database at `db_path`.
    pub fn compute(db_path: &Path) -> Result<Self> {
        let db_sha256 = file_sha256_hex(db_path)
            .with_context(|| format!("hashing {} for lexical domain attestation", db_path.display()))?;
        let conn = Conn::open_read(db_path).with_context(|| {
            format!("opening {} for lexical domain attestation", db_path.display())
        })?;
        let user_version = crate::storage::schema::read_user_version(&conn)
            .context("reading user_version for lexical domain attestation")?;
        let lex_docs_rows: i64 = conn
            .query_row_map("SELECT COUNT(*) FROM lex_docs", &[], |row| row.get_typed(0))
            .context("counting lex_docs rows for lexical domain attestation")?;
        let fts_lex_rows: i64 = conn
            .query_row_map("SELECT COUNT(*) FROM fts_lex", &[], |row| row.get_typed(0))
            .context("counting fts_lex rows for lexical domain attestation")?;
        Ok(Self {
            db_sha256,
            user_version,
            lex_docs_rows,
            fts_lex_rows,
        })
    }

    /// Sidecar path an attestation for `db_path` is written to/read from:
    /// same directory as the DB file, fixed filename (mirrors the old
    /// `evidence-bundle-manifest.json` "next to the artifact" convention).
    pub fn path(db_path: &Path) -> PathBuf {
        db_path
            .parent()
            .map(|dir| dir.join("lexical-domain-attestation.json"))
            .unwrap_or_else(|| PathBuf::from("lexical-domain-attestation.json"))
    }

    pub fn save(&self, db_path: &Path) -> Result<PathBuf> {
        let path = Self::path(db_path);
        let bytes = serde_json::to_vec_pretty(self).context("serializing lexical domain attestation")?;
        fs::write(&path, bytes)
            .with_context(|| format!("writing lexical domain attestation to {}", path.display()))?;
        Ok(path)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)
            .with_context(|| format!("reading lexical domain attestation from {}", path.display()))?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing lexical domain attestation from {}", path.display()))
    }
}

fn file_sha256_hex(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("reading {} for sha256", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex_encode(&hasher.finalize()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
    use crate::storage::sqlite::SqliteStorage;
    use tempfile::TempDir;

    fn scratch_db_path() -> (TempDir, PathBuf) {
        let dir = TempDir::new().expect("create scratch dir");
        let path = dir.path().join("agent_search.db");
        (dir, path)
    }

    fn open_storage_with_schema(db_path: &Path) -> SqliteStorage {
        SqliteStorage::open(db_path).expect("open storage (runs migrations incl. lex_docs/fts_lex)")
    }

    fn insert_one_message(storage: &SqliteStorage, external_id: &str, content: &str) {
        let agent_id = storage
            .ensure_agent(&Agent {
                id: None,
                slug: "claude_code".into(),
                name: "claude_code".into(),
                version: None,
                kind: AgentKind::Cli,
            })
            .expect("ensure_agent");
        storage
            .insert_conversation_tree(
                agent_id,
                None,
                &Conversation {
                    id: None,
                    agent_slug: "claude_code".into(),
                    workspace: None,
                    external_id: Some(external_id.into()),
                    title: Some(format!("title for {external_id}")),
                    source_path: PathBuf::from(format!("/tmp/{external_id}.jsonl")),
                    started_at: Some(1_700_000_000_000),
                    ended_at: None,
                    approx_tokens: None,
                    metadata_json: serde_json::Value::Null,
                    messages: vec![Message {
                        id: None,
                        idx: 0,
                        role: MessageRole::User,
                        author: Some("user".into()),
                        created_at: Some(1_700_000_000_000),
                        content: content.into(),
                        extra_json: serde_json::Value::Null,
                        snippets: Vec::new(),
                    }],
                    source_id: "local".into(),
                    origin_host: None,
                },
            )
            .expect("insert_conversation_tree");
    }

    #[test]
    fn exists_false_when_db_file_missing() {
        let (_dir, db_path) = scratch_db_path();
        assert!(!searchable_index_exists(&db_path));
    }

    #[test]
    fn exists_true_when_corpus_is_empty_vacuously() {
        let (_dir, db_path) = scratch_db_path();
        let _storage = open_storage_with_schema(&db_path);
        assert!(searchable_index_exists(&db_path));
    }

    /// The scenario the "table present" draft could never catch: a v1->v2
    /// migrated (or otherwise never-backfilled) database that has real
    /// messages but zero corresponding `lex_docs` rows.
    #[test]
    fn exists_false_when_messages_present_but_lex_docs_never_backfilled() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "never-backfilled-1", "this message has no lex_docs row");
        drop(storage);

        // Simulate a migrated-but-never-rebuilt database by deleting the
        // dual-written lex_docs row the normal insert path just created,
        // without touching messages.
        let conn = Conn::open_writable(&db_path, crate::storage::api::Profile::Production).unwrap();
        conn.execute("DELETE FROM lex_docs", &[]).unwrap();
        drop(conn);

        // Probe validity check (波1 铁律: verify the injected fault actually
        // produced the intended state before relying on it).
        let messages_present: i64 = Conn::open_read(&db_path)
            .unwrap()
            .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(messages_present, 1, "fault injection precondition: messages row must survive");
        let lex_docs_present: i64 = Conn::open_read(&db_path)
            .unwrap()
            .query_row_map("SELECT COUNT(*) FROM lex_docs", &[], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(lex_docs_present, 0, "fault injection precondition: lex_docs must be empty");

        assert!(
            !searchable_index_exists(&db_path),
            "a non-empty corpus with zero lex_docs rows must read as not-exists"
        );
    }

    #[test]
    fn exists_true_when_backfill_is_only_partial() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "partial-1", "kept");
        insert_one_message(&storage, "partial-2", "dropped");
        drop(storage);

        let conn = Conn::open_writable(&db_path, crate::storage::api::Profile::Production).unwrap();
        conn.execute(
            "DELETE FROM lex_docs WHERE doc_id = (SELECT id FROM messages WHERE content = 'dropped')",
            &[],
        )
        .unwrap();
        drop(conn);

        assert!(
            searchable_index_exists(&db_path),
            "partial backfill is 'was ever populated', not 'is complete' -- must still read as exists"
        );
    }

    #[test]
    fn validate_contract_full_ok_on_healthy_populated_schema() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "health-1", "contract check content");
        drop(storage);
        validate_searchable_index_contract_full(&db_path).expect("integrity-check must pass");
    }

    #[test]
    fn validate_contract_full_err_when_index_domain_missing() {
        let (_dir, db_path) = scratch_db_path();
        assert!(validate_searchable_index_contract_full(&db_path).is_err());
    }

    #[test]
    fn validate_contract_quick_ok_on_healthy_populated_schema() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "quick-health-1", "contract check content");
        drop(storage);
        validate_searchable_index_contract_quick(&db_path).expect("quick probe must pass");
    }

    #[test]
    fn validate_contract_quick_ok_on_empty_schema() {
        let (_dir, db_path) = scratch_db_path();
        let _storage = open_storage_with_schema(&db_path);
        validate_searchable_index_contract_quick(&db_path)
            .expect("quick probe must pass on an empty-but-valid domain (LIMIT 1 on 0 rows is not a failure)");
    }

    #[test]
    fn validate_contract_quick_err_when_index_domain_missing() {
        let (_dir, db_path) = scratch_db_path();
        assert!(validate_searchable_index_contract_quick(&db_path).is_err());
    }

    /// The quick tier's whole reason for existing: it must stay cheap
    /// (file-system-level, not full-corpus) and therefore does NOT catch
    /// the content/index desync scenario only the full tier's re-tokenized
    /// integrity-check can see. This is by design (see the module-level
    /// two-tier doc comment) -- pin it so nobody "fixes" the quick tier
    /// into re-acquiring full-tier cost by accident.
    #[test]
    fn validate_contract_quick_does_not_catch_content_index_desync_that_full_does() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "desync-1", "original content");
        drop(storage);

        let conn = Conn::open_writable(&db_path, crate::storage::api::Profile::Production).unwrap();
        conn.execute(
            "UPDATE lex_docs SET content = 'tampered content the fts_lex index does not know about'",
            &[],
        )
        .unwrap();
        drop(conn);

        assert!(
            validate_searchable_index_contract_quick(&db_path).is_ok(),
            "quick tier is file-system-level cost and must not detect content/index desync"
        );
        assert!(
            validate_searchable_index_contract_full(&db_path).is_err(),
            "full tier's re-tokenize-and-compare must detect the same desync"
        );
    }

    #[test]
    fn summary_none_when_index_absent() {
        let (_dir, db_path) = scratch_db_path();
        assert!(searchable_index_summary(&db_path).unwrap().is_none());
    }

    #[test]
    fn summary_docs_count_matches_lex_docs_rows_and_segments_is_one() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "summary-1", "first message");
        insert_one_message(&storage, "summary-2", "second message");
        drop(storage);

        let summary = searchable_index_summary(&db_path)
            .unwrap()
            .expect("summary must be Some once the domain has rows");
        assert_eq!(summary.docs, 2);
        assert_eq!(summary.segments, 1);
    }

    #[test]
    fn modified_time_none_when_absent() {
        let (_dir, db_path) = scratch_db_path();
        assert!(searchable_index_modified_time(&db_path).is_none());
    }

    #[test]
    fn modified_time_some_when_db_file_present() {
        let (_dir, db_path) = scratch_db_path();
        let _storage = open_storage_with_schema(&db_path);
        assert!(searchable_index_modified_time(&db_path).is_some());
    }

    #[test]
    fn attestation_reflects_live_row_counts_and_user_version() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "attest-1", "attestation content");
        drop(storage);

        let attestation = LexicalDomainAttestation::compute(&db_path).expect("compute attestation");
        assert_eq!(attestation.lex_docs_rows, 1);
        assert_eq!(attestation.fts_lex_rows, 1);
        assert!(attestation.user_version >= 2, "w2 schema must be at least v2 (lex_docs/fts_lex added)");
        assert_eq!(attestation.db_sha256.len(), 64, "sha256 hex digest must be 64 chars");
    }

    #[test]
    fn attestation_sha256_changes_when_db_bytes_change() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "tamper-1", "before");
        drop(storage);
        let before = LexicalDomainAttestation::compute(&db_path).unwrap();

        let storage = SqliteStorage::open(&db_path).unwrap();
        insert_one_message(&storage, "tamper-2", "after");
        drop(storage);
        let after = LexicalDomainAttestation::compute(&db_path).unwrap();

        assert_ne!(before.db_sha256, after.db_sha256);
        assert_eq!(after.lex_docs_rows, 2);
    }

    #[test]
    fn attestation_round_trips_through_save_and_load() {
        let (_dir, db_path) = scratch_db_path();
        let storage = open_storage_with_schema(&db_path);
        insert_one_message(&storage, "roundtrip-1", "roundtrip content");
        drop(storage);

        let computed = LexicalDomainAttestation::compute(&db_path).unwrap();
        let saved_path = computed.save(&db_path).unwrap();
        assert_eq!(saved_path, LexicalDomainAttestation::path(&db_path));

        let loaded = LexicalDomainAttestation::load(&saved_path).unwrap();
        assert_eq!(loaded, computed);
    }
}
