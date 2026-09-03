//! W2-3 Step 1/3: write-path mutation matrix (spec 门②) — insert / append
//! ("更新") / delete scenarios, each asserting `fts_lex`/`lex_docs` row
//! counts and MATCH results exactly track the relational write.
//!
//! **Scope note**: the *replace* and *rollback + fail-closed* scenarios are
//! NOT here — they need `sync_lexical_domain_for_conversation_in_tx` and
//! `franken_update_conversation_projection_fields_in_tx`/
//! `commit_replace_in_tx`, all `pub(crate)`, invisible to this integration
//! test crate (same visibility wall `storage::testing` was built to bridge
//! for schema/connection access, not for these). Those two scenarios live as
//! unit tests in `src/storage/sqlite.rs` instead (`replace_with_new_title_
//! and_workspace_refreshes_lex_docs_and_fts_lex` covers replace; a dedicated
//! fail-closed unit test covers rollback). This file covers the three
//! scenarios reachable through public API (`insert_conversation_tree`,
//! `purge_agent_archive_data`).

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::storage::sqlite::SqliteStorage;
use std::path::PathBuf;

fn open_storage() -> (tempfile::TempDir, SqliteStorage) {
    let dir = tempfile::TempDir::new().expect("create scratch dir");
    let db_path = dir.path().join("agent_search.db");
    let storage = SqliteStorage::open(&db_path).expect("open storage");
    (dir, storage)
}

fn ensure_agent(storage: &SqliteStorage, slug: &str) -> i64 {
    storage
        .ensure_agent(&Agent {
            id: None,
            slug: slug.into(),
            name: slug.into(),
            version: None,
            kind: AgentKind::Cli,
        })
        .expect("ensure_agent")
}

fn conv(external_id: &str, messages: Vec<Message>) -> Conversation {
    Conversation {
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
        messages,
        source_id: "local".into(),
        origin_host: None,
    }
}

fn msg(idx: i64, content: &str) -> Message {
    Message {
        id: None,
        idx,
        role: MessageRole::User,
        author: Some("user".into()),
        created_at: Some(1_700_000_000_000 + idx),
        content: content.into(),
        extra_json: serde_json::Value::Null,
        snippets: Vec::new(),
    }
}

fn lex_docs_count(storage: &SqliteStorage, conversation_id: i64) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM lex_docs WHERE doc_id IN \
             (SELECT id FROM messages WHERE conversation_id = ?1)",
            &[coding_agent_search::storage::api::Value::from(conversation_id)],
            |row| row.get_typed(0),
        )
        .unwrap()
}

fn fts_lex_match_count(storage: &SqliteStorage, term: &str) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM fts_lex WHERE fts_lex MATCH ?1",
            &[coding_agent_search::storage::api::Value::from(term)],
            |row| row.get_typed(0),
        )
        .unwrap()
}

fn conversation_id_by_external_id(storage: &SqliteStorage, external_id: &str) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT id FROM conversations WHERE external_id = ?1",
            &[coding_agent_search::storage::api::Value::from(external_id)],
            |row| row.get_typed(0),
        )
        .unwrap()
}

/// Scenario 1/5: insert. A brand-new conversation's message must land in
/// both `lex_docs` and `fts_lex`, recallable by content.
#[test]
fn insert_populates_lex_docs_and_fts_lex() {
    let (_dir, storage) = open_storage();
    let agent_id = ensure_agent(&storage, "claude_code");
    storage
        .insert_conversation_tree(agent_id, None, &conv("wm-insert-1", vec![msg(0, "unique_insert_marker_qwe111")]))
        .unwrap();

    let conversation_id = conversation_id_by_external_id(&storage, "wm-insert-1");
    assert_eq!(lex_docs_count(&storage, conversation_id), 1);
    assert_eq!(fts_lex_match_count(&storage, "qwe111"), 1);
}

/// Scenario 2/5: "更新" (append to an existing conversation — this codebase
/// has no in-place `UPDATE messages`; the only way message-level content
/// changes is a brand-new message being appended or a full replace, see
/// W2-0 Step 1's five-column source table). Appending a second message must
/// grow `lex_docs`/`fts_lex` by exactly one row without disturbing the
/// first.
#[test]
fn append_grows_lex_docs_and_fts_lex_without_disturbing_the_first_message() {
    let (_dir, storage) = open_storage();
    let agent_id = ensure_agent(&storage, "claude_code");
    let base = conv("wm-append-1", vec![msg(0, "unique_append_marker_asd222")]);
    storage.insert_conversation_tree(agent_id, None, &base).unwrap();
    let conversation_id = conversation_id_by_external_id(&storage, "wm-append-1");
    assert_eq!(lex_docs_count(&storage, conversation_id), 1);

    let appended = Conversation { messages: vec![msg(1, "unique_append_marker_zxc333")], ..base.clone() };
    storage.insert_conversation_tree(agent_id, None, &appended).unwrap();

    assert_eq!(lex_docs_count(&storage, conversation_id), 2, "append must add exactly one more lex_docs row");
    assert_eq!(fts_lex_match_count(&storage, "asd222"), 1, "the first message must remain recallable");
    assert_eq!(fts_lex_match_count(&storage, "zxc333"), 1, "the appended message must be recallable");
}

/// Scenario 3/5: delete. `purge_agent_archive_data` cascades
/// conversations -> messages -> lex_docs via `ON DELETE CASCADE`, but
/// `fts_lex` (an FTS5 external-content table) has no FK relationship to
/// `lex_docs` and is therefore NOT touched by that cascade -- W2-3 added an
/// explicit `fts_lex` cleanup ahead of each conversation-delete site
/// (`purge_agent_archive_data`, `forget_conversations_by_source_glob`,
/// `collapse_external_id_prefix_duplicates`) specifically to close this gap.
/// This test is the regression guard for that fix: without it, this
/// assertion would find a stale, orphaned `fts_lex` row still MATCHing the
/// deleted message's content.
#[test]
fn delete_via_agent_purge_leaves_no_orphaned_fts_lex_rows() {
    let (_dir, storage) = open_storage();
    let agent_id = ensure_agent(&storage, "claude_code");
    storage
        .insert_conversation_tree(agent_id, None, &conv("wm-delete-1", vec![msg(0, "unique_delete_marker_rty444")]))
        .unwrap();
    assert_eq!(fts_lex_match_count(&storage, "rty444"), 1, "sanity: indexed before delete");

    storage.purge_agent_archive_data("claude_code").unwrap();

    let orphaned_lex_docs: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM lex_docs", &[], |row| row.get_typed(0))
        .unwrap();
    assert_eq!(orphaned_lex_docs, 0, "lex_docs must be empty after the cascade");

    let orphaned_fts_hits: i64 = storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM fts_lex WHERE fts_lex MATCH 'rty444'",
            &[],
            |row| row.get_typed(0),
        )
        .unwrap();
    assert_eq!(orphaned_fts_hits, 0, "fts_lex must not retain an orphaned entry after agent purge deletes the conversation");
}
