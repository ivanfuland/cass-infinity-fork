//! w3-3 Step 3 (spec 门③, R2-W3-B4): lifecycle-mutation matrix for the two
//! A类/C类 write entry points reachable through `FrankenStorage`'s fully
//! public API (`insert_conversation_tree` for 插入, `forget_conversations_
//! by_source_glob` for 删除). The B类 (replace) scenario plus the w3-d9②
//! rollback-atomicity scenario live in `src/storage/sqlite.rs`'s own
//! `e5_replace_tests` module instead — `franken_replace_conversation_
//! messages_in_tx` is `pub(crate)`, invisible to this external test crate
//! (w3-3 Step 3 write-entry-point survey already noted this visibility
//! split; see that report for why B类 has zero production callers today).
//!
//! Assertion scope per R3-N2's clarified contract: each scenario proves
//! same-transaction "旧嵌入清除 + 代际就绪失效" plus an exact hole-ledger
//! reconciliation — never that a fresh embedding shows up (catch-up's job,
//! out of this file's scope, simulated nowhere here).

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::storage::api::Value as V;
use coding_agent_search::storage::schema;
use coding_agent_search::storage::sqlite::FrankenStorage;

macro_rules! fparams {
    () => {
        &[] as &[V]
    };
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+] as &[V]
    };
}

const TS: i64 = 1_770_551_400_000; // 2026-02-06 10:30:00 UTC

fn open_storage(path: &std::path::Path) -> FrankenStorage {
    FrankenStorage::open(path).expect("open production storage")
}

fn ensure_agent(storage: &FrankenStorage) -> i64 {
    storage
        .ensure_agent(&Agent {
            id: None,
            slug: "claude_code".into(),
            name: "Claude Code".into(),
            version: Some("1.0".into()),
            kind: AgentKind::Cli,
        })
        .expect("ensure agent")
}

fn msg(idx: i64, role: MessageRole, content: &str) -> Message {
    Message {
        id: None,
        idx,
        role,
        author: None,
        created_at: Some(TS + idx * 1_000),
        content: content.into(),
        extra_json: serde_json::Value::Null,
        snippets: vec![],
    }
}

fn conversation(external_id: &str, source_path: &str, messages: Vec<Message>) -> Conversation {
    Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace: None,
        external_id: Some(external_id.into()),
        title: Some("w3-3 lifecycle fixture".into()),
        source_path: std::path::PathBuf::from(source_path),
        started_at: Some(TS),
        ended_at: Some(TS + 60_000),
        approx_tokens: None,
        metadata_json: serde_json::Value::Null,
        messages,
        source_id: "local".into(),
        origin_host: None,
    }
}

fn conv_id_of(storage: &FrankenStorage, external_id: &str) -> i64 {
    storage
        .raw()
        .query_row_map("SELECT id FROM conversations WHERE external_id = ?1", fparams![external_id], |row| {
            row.get_typed::<i64>(0)
        })
        .unwrap()
}

fn message_id_at_idx(storage: &FrankenStorage, conv_id: i64, idx: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT id FROM messages WHERE conversation_id = ?1 AND idx = ?2",
            fparams![conv_id, idx],
            |row| row.get_typed(0),
        )
        .unwrap()
}

fn active_generation_audit_status(storage: &FrankenStorage) -> String {
    storage
        .raw()
        .query_row_map("SELECT audit_status FROM embedding_generations WHERE is_active = 1", fparams![], |row| {
            row.get_typed(0)
        })
        .unwrap()
}

fn embedding_row_count(storage: &FrankenStorage, generation_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1",
            fparams![generation_id],
            |row| row.get_typed(0),
        )
        .unwrap()
}

fn hole_doc_ids(storage: &FrankenStorage, generation_id: i64) -> Vec<i64> {
    let mut ids: Vec<i64> = storage
        .raw()
        .query_all_map("SELECT doc_id FROM embedding_holes WHERE generation_id = ?1", fparams![generation_id], |row| {
            row.get_typed(0)
        })
        .unwrap();
    ids.sort_unstable();
    ids
}

/// Creates an active, `audit_status = 'passed'` generation (dim=4) and
/// seeds one embedding row for `message_id`, so a scenario has a real "旧
/// 嵌入" to observe getting cleared or left alone.
fn seed_active_passed_generation_with_one_embedding(storage: &FrankenStorage, message_id: i64, conversation_id: i64) -> i64 {
    let conn = storage.raw();
    let gen_id = conn
        .with_tx_no_replay(coding_agent_search::storage::api::TxMode::Immediate, |tx| {
            schema::create_embedding_generation(tx, "bge-m3", 4, 1, TS)
        })
        .unwrap();
    conn.with_tx_no_replay(coding_agent_search::storage::api::TxMode::Immediate, |tx| {
        schema::insert_message_embedding(
            tx,
            gen_id,
            message_id,
            conversation_id,
            &[1.0, 0.0, 0.0, 0.0],
            "seed-hash",
            None,
            TS,
        )
    })
    .unwrap();
    conn.execute(
        "UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1",
        fparams![gen_id],
    )
    .unwrap();
    gen_id
}

/// A类 (插入): appending a brand-new message to an already-embedded
/// conversation must (a) leave the *existing* message's embedding
/// untouched (pure append is not a content change for messages that were
/// already there), (b) register a hole for the *new* message id, and (c)
/// demote the active generation's certified-ready status — all inside the
/// same transaction `insert_conversation_tree` itself opens.
#[test]
fn insert_conversation_tree_append_registers_a_hole_and_demotes_readiness_without_touching_the_existing_embedding() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let agent_id = ensure_agent(&storage);

    let initial = conversation("w3-3-a-class", "/fixtures/w3-3-a-class.jsonl", vec![msg(0, MessageRole::User, "first message")]);
    storage.insert_conversation_tree(agent_id, None, &initial).expect("initial insert");
    let conv_id = conv_id_of(&storage, "w3-3-a-class");
    let first_message_id = message_id_at_idx(&storage, conv_id, 0);

    let gen_id = seed_active_passed_generation_with_one_embedding(&storage, first_message_id, conv_id);
    assert_eq!(embedding_row_count(&storage, gen_id), 1, "前置：第一条消息有一行旧嵌入");
    assert_eq!(active_generation_audit_status(&storage), "passed", "前置：代际起始为 passed");

    // Same external_id, one more message appended at idx=1 -- this is the
    // "existing conversation" branch's append path (A类), not a replace.
    let appended = conversation(
        "w3-3-a-class",
        "/fixtures/w3-3-a-class.jsonl",
        vec![msg(0, MessageRole::User, "first message"), msg(1, MessageRole::Agent, "second message")],
    );
    storage.insert_conversation_tree(agent_id, None, &appended).expect("append insert");
    let second_message_id = message_id_at_idx(&storage, conv_id, 1);

    // (a) untouched: the first message's embedding must still be there,
    // unmodified -- append is not a content mutation for messages that
    // were already committed.
    assert_eq!(embedding_row_count(&storage, gen_id), 1, "既有消息的旧嵌入不该因为纯追加被动");
    assert_eq!(hole_doc_ids(&storage, gen_id), vec![second_message_id], "洞账必须精确等于新追加的那一条消息 id");
    assert_eq!(active_generation_audit_status(&storage), "pending", "代际就绪必须在追加同事务内失效");
}

/// C类 (删除): `cass forget --apply` deleting a conversation must clear its
/// embedding via `ON DELETE CASCADE` and demote the active generation's
/// certified-ready status in the same transaction.
#[test]
fn forget_conversations_clears_the_embedding_and_demotes_readiness_in_the_same_transaction() {
    let dir = tempfile::TempDir::new().unwrap();
    let storage = open_storage(&dir.path().join("db.sqlite"));
    let agent_id = ensure_agent(&storage);

    let conv = conversation("w3-3-c-class", "/fixtures/w3-3-c-class.jsonl", vec![msg(0, MessageRole::User, "will be forgotten")]);
    storage.insert_conversation_tree(agent_id, None, &conv).expect("initial insert");
    let conv_id = conv_id_of(&storage, "w3-3-c-class");
    let message_id = message_id_at_idx(&storage, conv_id, 0);

    let gen_id = seed_active_passed_generation_with_one_embedding(&storage, message_id, conv_id);
    assert_eq!(embedding_row_count(&storage, gen_id), 1, "前置：目标消息有一行旧嵌入");
    assert_eq!(active_generation_audit_status(&storage), "passed", "前置：代际起始为 passed");

    let result = storage
        .forget_conversations_by_source_glob("/fixtures/w3-3-c-class.jsonl", false)
        .expect("forget --apply");
    assert_eq!(result.conversations_deleted, 1, "sanity: 确实删掉了这一条会话");

    assert_eq!(embedding_row_count(&storage, gen_id), 0, "旧嵌入必须被同事务清除（CASCADE）");
    assert!(hole_doc_ids(&storage, gen_id).is_empty(), "被删除的消息不该留下洞账（doc_id 本身也 CASCADE 掉了）");
    assert_eq!(active_generation_audit_status(&storage), "pending", "代际就绪必须在删除同事务内失效");
}
