//! PR8 C2 — conversation identity (`identity_host`) write path and
//! `merge_conflicts` (spec hard constraints 2 and 3).
//!
//! Every case is driven through the **real ingest persist dispatcher**
//! (`indexer::persist::persist_conversations_batched_inner`), so the
//! `CASS_INDEXER_BEGIN_CONCURRENT` branch is the production one, not a
//! re-implementation: `for_each_persist_path` runs each body twice — once with
//! the env var absent (serial batched path) and once set to `1`
//! (begin-concurrent writer path) — against a **fresh tempdir database** each
//! time, so the two runs cannot contaminate each other.
//!
//! Globals touched, and who else touches them (INV-3):
//! - `CASS_INDEXER_BEGIN_CONCURRENT` is process-global and read per call by
//!   `begin_concurrent_writes_enabled()`. `#[serial]` keeps these four tests off
//!   each other; `EnvGuard` restores the previous value (including on panic);
//!   the window covers only the persist call, never an assertion.
//! - Every test owns its own `TempDir`, database path and storage handle; no
//!   static, shared file or fixed path is shared between tests.
//!
//! Coverage boundary (stated so the report can be read honestly): these cases
//! exercise the storage/identity/merge code and both persist paths, but they do
//! **not** run a connector scan — the `inject_provenance` -> metadata carrier
//! that feeds `identity_host` here is covered by the `--lib indexer::` unit
//! tests (`ingest_identity_for_root_*`, `inject_provenance_*`).

use std::path::PathBuf;
use std::sync::Mutex;

use serial_test::serial;

use coding_agent_search::connectors::{NormalizedConversation, NormalizedMessage};
use coding_agent_search::indexer::persist::persist_normalized_conversations_for_tests;
use coding_agent_search::storage::api::Conn;
use coding_agent_search::storage::sqlite::FrankenStorage;

const BEGIN_CONCURRENT_ENV: &str = "CASS_INDEXER_BEGIN_CONCURRENT";

/// `CASS_INDEXER_BEGIN_CONCURRENT` is process-global; `#[serial]` serializes the
/// tests, and this mutex additionally covers the env window itself so a future
/// non-`#[serial]` test in this binary cannot observe a half-set value.
static ENV_SERIALIZE: Mutex<()> = Mutex::new(());

struct EnvGuard(Option<std::ffi::OsString>);

impl EnvGuard {
    fn capture() -> Self {
        Self(std::env::var_os(BEGIN_CONCURRENT_ENV))
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        // Safe in test scope: process env is owned by this test binary.
        unsafe {
            match self.0.take() {
                Some(value) => std::env::set_var(BEGIN_CONCURRENT_ENV, value),
                None => std::env::remove_var(BEGIN_CONCURRENT_ENV),
            }
        }
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    db_path: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("create scratch dir");
        let data_dir = dir.path().join("cass-data");
        std::fs::create_dir_all(&data_dir).expect("mkdir data_dir");
        let db_path = data_dir.join("agent_search.db");
        Self { _dir: dir, data_dir, db_path }
    }

    fn open(&self) -> FrankenStorage {
        FrankenStorage::open(&self.db_path).expect("open production storage (fresh build)")
    }

    fn read(&self) -> Conn {
        Conn::open_read(&self.db_path).expect("open read-only connection")
    }
}

/// Run `body` once per persist path, each on its own fresh harness. The path
/// name is handed to the body so every assertion message names which of the two
/// paths failed.
fn for_each_persist_path(mut body: impl FnMut(&Harness, &str)) {
    let _serialize = ENV_SERIALIZE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let _restore = EnvGuard::capture();
    for (path_name, concurrent) in [("serial", false), ("begin-concurrent", true)] {
        let harness = Harness::new();
        // Safe in test scope: this binary owns the process env.
        unsafe {
            if concurrent {
                std::env::set_var(BEGIN_CONCURRENT_ENV, "1");
            } else {
                std::env::remove_var(BEGIN_CONCURRENT_ENV);
            }
        }
        body(&harness, path_name);
    }
}

fn msg(idx: i64, content: &str) -> NormalizedMessage {
    NormalizedMessage {
        idx,
        role: "user".to_string(),
        author: None,
        created_at: Some(1_700_000_000_000 + idx * 1_000),
        content: content.to_string(),
        extra: serde_json::json!({}),
        snippets: Vec::new(),
        invocations: Vec::new(),
    }
}

/// One conversation as a connector would hand it over, with the C2 identity
/// carrier (`metadata.cass.identity`) that `indexer::inject_provenance` writes
/// in production. `source_id` stays an attribute (first-ingest value).
fn conv(
    root_id: &str,
    identity_host: &str,
    source_id: &str,
    external_id: &str,
    source_path: &str,
    messages: Vec<NormalizedMessage>,
) -> NormalizedConversation {
    NormalizedConversation {
        agent_slug: "codex".to_string(),
        external_id: Some(external_id.to_string()),
        title: Some(format!("{root_id} {external_id}")),
        workspace: None,
        source_path: PathBuf::from(source_path),
        started_at: Some(1_700_000_000_000),
        ended_at: None,
        metadata: serde_json::json!({
            "cass": {
                "origin": {"source_id": source_id, "kind": "local", "host": null},
                "identity": {"identity_host": identity_host, "root_id": root_id}
            }
        }),
        messages,
    }
}

fn persist(storage: &FrankenStorage, harness: &Harness, convs: Vec<NormalizedConversation>) -> (usize, usize) {
    persist_normalized_conversations_for_tests(storage, &harness.data_dir, convs)
        .expect("persisting through the real ingest persist path must succeed")
}

fn scalar_i64(conn: &Conn, sql: &str) -> i64 {
    conn.query_row_map(sql, &[], |row| row.get_typed(0)).expect(sql)
}

fn conversation_rows(conn: &Conn) -> Vec<(i64, String, Option<String>, String)> {
    conn.query_all_map(
        "SELECT id, identity_host, origin_host, source_id FROM conversations ORDER BY id",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?)),
    )
    .expect("select conversations")
}

fn message_contents(conn: &Conn, conversation_id: i64) -> Vec<String> {
    conn.query_all_map(
        "SELECT content FROM messages WHERE conversation_id = ?1 ORDER BY idx",
        &[coding_agent_search::storage::api::Value::Integer(conversation_id)],
        |row| row.get_typed(0),
    )
    .expect("select message contents")
}

fn merge_conflicts(storage: &FrankenStorage, conversation_id: i64) -> Vec<serde_json::Value> {
    let metadata = storage
        .conversation_metadata_for_tests(conversation_id)
        .expect("read logical metadata");
    metadata
        .get("merge_conflicts")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// AC-1 / AC-7
// ---------------------------------------------------------------------------

/// AC-1: two roots carrying the *same* `identity_host` and the same
/// `(agent_id, external_id)` collapse into exactly one conversation whose
/// message set is the union; the tail-only root does not create a second row.
///
/// AC-7 rides along on the same fixture: the surviving row keeps
/// `identity_host = 'local'`, keeps `origin_host` NULL (the baseline
/// local-is-NULL semantics the ~100 read sites depend on), and keeps the
/// **first-ingested** `source_id` even though the second root declares another
/// one.
#[test]
#[serial]
fn two_roots_same_host_merge_to_one() {
    for_each_persist_path(|harness, path_name| {
        let storage = harness.open();

        let root_a = conv(
            "root-a",
            "local",
            "local",
            "sess-alpha.jsonl",
            "/root-a/sessions/2026/01/01/sess-alpha.jsonl",
            vec![msg(0, "a0"), msg(1, "a1"), msg(2, "a2")],
        );
        let root_b = conv(
            "root-b",
            "local",
            "remote-b",
            "sess-alpha.jsonl",
            "/root-b/sessions/2026/01/01/sess-alpha.jsonl",
            vec![msg(0, "a0"), msg(1, "a1"), msg(2, "a2"), msg(3, "b3"), msg(4, "b4")],
        );

        let (conversations, messages) = persist(&storage, harness, vec![root_a]);
        assert_eq!(conversations, 1, "[{path_name}] first root inserts one conversation");
        assert_eq!(messages, 3, "[{path_name}] first root inserts three messages");

        let (conversations, messages) = persist(&storage, harness, vec![root_b]);
        assert_eq!(
            conversations, 0,
            "[{path_name}] the same identity key from a second root must merge, not insert"
        );
        assert_eq!(messages, 2, "[{path_name}] only the two tail messages are new");

        let conn = harness.read();
        assert_eq!(
            scalar_i64(&conn, "SELECT COUNT(*) FROM conversations"),
            1,
            "[{path_name}] two roots of one identity must leave exactly one conversation"
        );
        let rows = conversation_rows(&conn);
        let (id, identity_host, origin_host, source_id) = rows[0].clone();
        assert_eq!(identity_host, "local", "[{path_name}] AC-7 identity_host");
        assert_eq!(origin_host, None, "[{path_name}] AC-7 origin_host must stay NULL for local");
        assert_eq!(source_id, "local", "[{path_name}] AC-7 source_id is the first-ingest attribute value");
        assert_eq!(
            message_contents(&conn, id),
            vec!["a0", "a1", "a2", "b3", "b4"],
            "[{path_name}] merged message set is the union, first-ingest order preserved"
        );
    });
}

// ---------------------------------------------------------------------------
// AC-2
// ---------------------------------------------------------------------------

/// AC-2: the same `idx` with a different `content_hash` keeps the
/// first-ingested body and appends exactly one `merge_conflicts` entry
/// `{idx, root_id, content_hash, seen_at}`; replaying the identical conflict
/// does not append a second entry (dedup key `(idx, content_hash)`).
#[test]
#[serial]
fn conflict_recorded_once() {
    for_each_persist_path(|harness, path_name| {
        let storage = harness.open();

        let root_a = conv(
            "root-a",
            "local",
            "local",
            "sess-conflict.jsonl",
            "/root-a/sessions/2026/01/01/sess-conflict.jsonl",
            vec![msg(0, "shared-0"), msg(1, "from-root-a")],
        );
        let root_b = conv(
            "root-b",
            "local",
            "local",
            "sess-conflict.jsonl",
            "/root-b/sessions/2026/01/01/sess-conflict.jsonl",
            vec![msg(0, "shared-0"), msg(1, "from-root-b"), msg(2, "tail-2")],
        );

        persist(&storage, harness, vec![root_a]);
        let conn = harness.read();
        let conversation_id = conversation_rows(&conn)[0].0;
        drop(conn);

        persist(&storage, harness, vec![root_b.clone()]);
        let conn = harness.read();
        assert_eq!(
            scalar_i64(&conn, "SELECT COUNT(*) FROM conversations"),
            1,
            "[{path_name}] a conflicting idx must still merge into the one conversation"
        );
        assert_eq!(
            message_contents(&conn, conversation_id),
            vec!["shared-0", "from-root-a", "tail-2"],
            "[{path_name}] first-ingested body wins; the non-conflicting tail index is appended"
        );
        drop(conn);

        let conflicts = merge_conflicts(&storage, conversation_id);
        assert_eq!(
            conflicts.len(),
            1,
            "[{path_name}] exactly one merge_conflicts entry, got {conflicts:?}"
        );
        let entry = &conflicts[0];
        assert_eq!(entry.get("idx").and_then(serde_json::Value::as_i64), Some(1), "[{path_name}]");
        assert_eq!(
            entry.get("root_id").and_then(serde_json::Value::as_str),
            Some("root-b"),
            "[{path_name}] the conflict names the root that lost it"
        );
        assert!(
            entry
                .get("content_hash")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|hash| hash.len() == 64),
            "[{path_name}] content_hash is a hex digest, got {entry:?}"
        );
        assert!(
            entry.get("seen_at").and_then(serde_json::Value::as_i64).is_some(),
            "[{path_name}] seen_at is set, got {entry:?}"
        );

        // Replay the identical conflict: the dedup key is (idx, content_hash),
        // so nothing new may be appended and nothing may be re-inserted.
        let (conversations, messages) = persist(&storage, harness, vec![root_b]);
        assert_eq!(conversations, 0, "[{path_name}] replay inserts no conversation");
        assert_eq!(messages, 0, "[{path_name}] replay inserts no message");
        assert_eq!(
            merge_conflicts(&storage, conversation_id).len(),
            1,
            "[{path_name}] replaying the same conflict must not append a second entry"
        );
    });
}

// ---------------------------------------------------------------------------
// AC-3
// ---------------------------------------------------------------------------

/// AC-3: the same `(agent_id, external_id)` under two different
/// `identity_host` values stays two conversations, each with its own body
/// readable; a further root sharing the *first* host merges into the existing
/// row through the lookup table instead of inserting a third.
#[test]
#[serial]
fn different_hosts_stay_separate() {
    for_each_persist_path(|harness, path_name| {
        let storage = harness.open();

        let local_root = conv(
            "root-a",
            "local",
            "local",
            "sess-split.jsonl",
            "/root-a/sessions/2026/01/01/sess-split.jsonl",
            vec![msg(0, "local-body")],
        );
        // `source_id` is deliberately the *same* attribute value for both roots:
        // it is a first-ingest attribute, not a key dimension, so the only thing
        // that may keep these two apart is `identity_host`. (Two roots of one
        // machine legitimately report the same origin source_id.)
        let mac_root = conv(
            "root-ivanmac",
            "ivanmac",
            "local",
            "sess-split.jsonl",
            "/root-ivanmac/sessions/2026/01/01/sess-split.jsonl",
            vec![msg(0, "ivanmac-body")],
        );

        persist(&storage, harness, vec![local_root]);
        persist(&storage, harness, vec![mac_root]);

        let conn = harness.read();
        let rows = conversation_rows(&conn);
        assert_eq!(rows.len(), 2, "[{path_name}] different identity_host must not dedup, got {rows:?}");
        let mut hosts: Vec<&str> = rows.iter().map(|(_, host, _, _)| host.as_str()).collect();
        hosts.sort_unstable();
        assert_eq!(hosts, vec!["ivanmac", "local"], "[{path_name}] one row per host");
        for (id, _, _, _) in &rows {
            assert_eq!(
                scalar_i64(&conn, &format!("SELECT COUNT(*) FROM messages WHERE conversation_id = {id}")),
                1,
                "[{path_name}] every host's body survives"
            );
        }
        let local_id = rows.iter().find(|(_, host, _, _)| host == "local").expect("local row").0;
        let mac_id = rows.iter().find(|(_, host, _, _)| host == "ivanmac").expect("ivanmac row").0;
        assert_eq!(message_contents(&conn, local_id), vec!["local-body"], "[{path_name}]");
        assert_eq!(message_contents(&conn, mac_id), vec!["ivanmac-body"], "[{path_name}] ivanmac body survives");

        // The lookup table is keyed by identity_host too: the local key must
        // already point at the local conversation (this is what the third root
        // below hits instead of a fresh insert).
        let lookup_targets = conn
            .query_all_map(
                "SELECT lookup_key, conversation_id FROM conversation_external_tail_lookup ORDER BY lookup_key",
                &[],
                |row| Ok((row.get_typed::<String>(0)?, row.get_typed::<i64>(1)?)),
            )
            .expect("select tail lookup rows");
        assert_eq!(lookup_targets.len(), 2, "[{path_name}] one lookup row per host, got {lookup_targets:?}");
        let local_lookup = lookup_targets
            .iter()
            .find(|(key, _)| key.contains(":local:"))
            .expect("local lookup key");
        // Shape: `<len>:<identity_host>:<agent_id>:<len>:<external_id>`.
        assert!(
            local_lookup.0.starts_with("5:local:"),
            "[{path_name}] the lookup key is keyed by identity_host, got {:?}",
            local_lookup.0
        );
        assert_eq!(local_lookup.1, local_id, "[{path_name}] local lookup points at the local row");
        drop(conn);

        // Third root, same host as the first, one extra message.
        let local_tail = conv(
            "root-c",
            "local",
            "local",
            "sess-split.jsonl",
            "/root-c/sessions/2026/01/01/sess-split.jsonl",
            vec![msg(0, "local-body"), msg(1, "local-tail")],
        );
        let (conversations, messages) = persist(&storage, harness, vec![local_tail]);
        assert_eq!(conversations, 0, "[{path_name}] same-host third root must hit the lookup, not insert");
        assert_eq!(messages, 1, "[{path_name}] only the new tail message lands");

        let conn = harness.read();
        assert_eq!(
            scalar_i64(&conn, "SELECT COUNT(*) FROM conversations"),
            2,
            "[{path_name}] still two conversations after the same-host third root"
        );
        assert_eq!(
            message_contents(&conn, local_id),
            vec!["local-body", "local-tail"],
            "[{path_name}] the third root merged into the existing local row"
        );
        assert_eq!(
            message_contents(&conn, mac_id),
            vec!["ivanmac-body"],
            "[{path_name}] the other host is untouched"
        );
    });
}

// ---------------------------------------------------------------------------
// AC-5
// ---------------------------------------------------------------------------

/// AC-5: only UNIQUE / PRIMARY KEY violations may be swallowed as "already
/// exists". A non-UNIQUE constraint failure (here: the `agent_id` foreign key)
/// must reach the caller as a constraint error naming that constraint, not be
/// absorbed into the duplicate-recovery path whose follow-up lookup then reports
/// the misleading "duplicate conflict but existing row was not found".
///
/// The positive half of the same classification — a genuine UNIQUE conflict is
/// still absorbed — is what `two_roots_same_host_merge_to_one` and
/// `different_hosts_stay_separate` assert from the outside (they merge instead
/// of erroring).
#[test]
#[serial]
fn constraint_classification_is_unique_only() {
    use coding_agent_search::model::types::{Conversation, Message, MessageRole};
    use coding_agent_search::storage::api::StorageError;

    let harness = Harness::new();
    let storage = harness.open();

    let source_path = PathBuf::from("/root-a/sessions/2026/01/01/sess-fk.jsonl");
    let conversation = Conversation {
        id: None,
        agent_slug: "codex".to_string(),
        workspace: None,
        external_id: Some("sess-fk.jsonl".to_string()),
        title: Some("fk".to_string()),
        source_path: source_path.clone(),
        started_at: Some(1_700_000_000_000),
        ended_at: None,
        approx_tokens: None,
        metadata_json: serde_json::json!({"cass": {"identity": {"identity_host": "local", "root_id": "root-a"}}}),
        messages: vec![Message {
            id: None,
            idx: 0,
            role: MessageRole::User,
            author: None,
            created_at: Some(1_700_000_000_000),
            content: "body".to_string(),
            extra_json: serde_json::json!({}),
            snippets: Vec::new(),
            excluded: None,
        }],
        source_id: "local".to_string(),
        origin_host: None,
    };

    // 999_999 is not in `agents`, so `conversations.agent_id` violates its
    // FOREIGN KEY. `PRAGMA foreign_keys` is ON for every profile.
    let error = match storage.insert_conversation_tree(999_999, None, &conversation) {
        Ok(_) => panic!("a foreign-key violation must not be reported as a duplicate"),
        Err(error) => error,
    };

    let constraint = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<StorageError>())
        .unwrap_or_else(|| panic!("the foreign-key failure must surface as a StorageError, got: {error:#}"));
    match constraint {
        StorageError::Constraint { detail } => {
            assert!(
                detail.starts_with("FOREIGN KEY"),
                "the non-UNIQUE constraint must be named verbatim, got detail={detail:?}"
            );
        }
        other => panic!("expected StorageError::Constraint for the FK violation, got {other:?}"),
    }

    // Nothing was written, and nothing was silently recorded as a merge.
    let conn = harness.read();
    assert_eq!(
        scalar_i64(&conn, "SELECT COUNT(*) FROM conversations"),
        0,
        "a rejected insert must not leave a conversation row behind"
    );
    assert_eq!(
        scalar_i64(&conn, "SELECT COUNT(*) FROM conversation_external_tail_lookup"),
        0,
        "a rejected insert must not leave a lookup row behind"
    );
    // Sanity on the fixture: the FK really is the thing that fired, not a
    // missing agent row being tolerated by a disabled pragma.
    assert_eq!(
        scalar_i64(&conn, "PRAGMA foreign_keys"),
        1,
        "this assertion is vacuous unless foreign keys are enforced"
    );
    let agent_exists = scalar_i64(&conn, "SELECT COUNT(*) FROM agents WHERE id = 999999");
    assert_eq!(agent_exists, 0, "fixture sanity: the referenced agent must not exist");
}
