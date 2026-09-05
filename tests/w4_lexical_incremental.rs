//! T5 (plan v5.1) Step 1: failing-then-green tests for the lexical domain's
//! 8 MiB cap removal, `lexical_eligible` whitelist, and per-message
//! incremental sync -- the subset exercisable entirely through the public
//! storage API (`insert_conversation_tree`/`insert_conversations_batched`,
//! `raw()` SQL, `crate::search::eligibility::lexical_eligible`). The three
//! remaining Step 1 tests that need `pub(crate)` access to the sync
//! functions/full-rebuild themselves (`lexical_message_update_resyncs_only_
//! target`, `lexical_three_sites_agree`, `lexical_rebuild_is_streaming`) or
//! to `phase3_restore::commit_replace_in_tx`
//! (`lexical_replace_path_dispatches_message_and_envelope`) live inline in
//! `src/storage/sqlite.rs`'s and `src/phase3_restore.rs`'s own test modules
//! instead -- a deviation from the plan's single-file Files listing,
//! documented in the T5 terminal report.
//!
//! Connections are opened via `FrankenStorage::open` (the real production
//! entry point), matching the fixture-fidelity discipline `w4_schema_v5.rs`
//! and `w3_vector_schema.rs` already follow.

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::search::eligibility::lexical_eligible;
use coding_agent_search::storage::api::Value as V;
use coding_agent_search::storage::sqlite::FrankenStorage;

macro_rules! fparams {
    () => {
        &[] as &[V]
    };
    ($($val:expr),+ $(,)?) => {
        &[$(coding_agent_search::storage::api::IntoValue::into_value($val)),+] as &[V]
    };
}

fn scratch_db_path() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().expect("create scratch dir");
    let path = dir.path().join("agent_search.db");
    (dir, path)
}

fn open_storage(path: &std::path::Path) -> FrankenStorage {
    FrankenStorage::open(path).expect("open production storage")
}

fn ensure_test_agent(storage: &FrankenStorage) -> i64 {
    storage
        .ensure_agent(&Agent {
            id: None,
            slug: "claude_code".into(),
            name: "Claude Code".into(),
            version: None,
            kind: AgentKind::Cli,
        })
        .expect("ensure agent")
}

fn message(idx: i64, role: MessageRole, content: impl Into<String>, created_at: i64) -> Message {
    Message {
        id: None,
        idx,
        role,
        author: None,
        created_at: Some(created_at),
        content: content.into(),
        extra_json: serde_json::Value::Null,
        snippets: Vec::new(),
    }
}

fn conversation(
    external_id: &str,
    title: &str,
    workspace: Option<std::path::PathBuf>,
    messages: Vec<Message>,
) -> Conversation {
    Conversation {
        id: None,
        agent_slug: "claude_code".into(),
        workspace,
        external_id: Some(external_id.into()),
        title: Some(title.into()),
        source_path: std::path::PathBuf::from(format!("/fixtures/{external_id}.jsonl")),
        started_at: Some(1_700_000_000_000),
        ended_at: Some(1_700_000_000_100),
        approx_tokens: None,
        metadata_json: serde_json::Value::Null,
        messages,
        source_id: "local".into(),
        origin_host: None,
    }
}

fn lex_docs_row(storage: &FrankenStorage, doc_id: i64) -> Option<(String, String, String, String)> {
    storage
        .raw()
        .query_opt_map(
            "SELECT content, title, agent, workspace FROM lex_docs WHERE doc_id = ?1",
            fparams![doc_id],
            |row| {
                Ok((
                    row.get_typed::<String>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<String>(2)?,
                    row.get_typed::<String>(3)?,
                ))
            },
        )
        .expect("query lex_docs row")
}

fn fts_match_count(storage: &FrankenStorage, term: &str) -> i64 {
    storage
        .raw()
        .query_row_map(
            "SELECT COUNT(*) FROM fts_lex WHERE fts_lex MATCH ?1",
            fparams![term],
            |row| row.get_typed(0),
        )
        .expect("fts_lex MATCH query")
}

fn message_ids_for_conversation(storage: &FrankenStorage, conversation_id: i64) -> Vec<i64> {
    storage
        .raw()
        .query_all_map(
            "SELECT id FROM messages WHERE conversation_id = ?1 ORDER BY idx",
            fparams![conversation_id],
            |row| row.get_typed(0),
        )
        .expect("list message ids")
}

/// T5 Step 1: a conversation whose cumulative message content is well past
/// the old 8 MiB per-conversation cap must have EVERY message indexed,
/// including the tail -- T5 removes the cap entirely (plan v5.1 "保真").
#[test]
fn lexical_no_conversation_cap_indexes_tail_of_9mib_conversation() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);

    // ~9 MiB head message (well past the old 8 MiB cap on its own), plus a
    // small tail message carrying a unique sentinel term.
    let head_content = "alpha ".repeat((9 * 1024 * 1024) / "alpha ".len() + 1);
    let conv = conversation(
        "nine-mib-conv",
        "nine mib fixture",
        None,
        vec![
            message(0, MessageRole::User, head_content, 1_700_000_000_010),
            message(
                1,
                MessageRole::Assistant,
                "tailsentinelword9mib marks the very end of the conversation",
                1_700_000_000_020,
            ),
        ],
    );
    storage
        .insert_conversation_tree(agent_id, None, &conv)
        .expect("insert 9 MiB conversation");

    assert_eq!(
        fts_match_count(&storage, "tailsentinelword9mib"),
        1,
        "the tail message past the old 8 MiB cap must be indexed and MATCH-able -- \
         T5 removes the per-conversation lexical cap entirely"
    );
    assert_eq!(
        fts_match_count(&storage, "alpha"),
        1,
        "the ~9 MiB head message must also be indexed whole, not truncated"
    );
}

/// T5 Step 1: `lexical_eligible` (T3) is the single whitelist -- reasoning
/// content is excluded, and role aliases (`agent`, `tool_call`,
/// `tool_result`/`toolResult`) are included, exactly matching what
/// `lexical_eligible` itself reports for each role.
#[test]
fn lexical_excludes_reasoning_and_includes_aliases() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);

    let conv = conversation(
        "alias-and-reasoning-conv",
        "alias fixture",
        None,
        vec![
            message(0, MessageRole::User, "usertermxyz one", 1_700_000_000_010),
            message(
                1,
                MessageRole::Other("reasoning".into()),
                "reasoningtermxyz should never be indexed",
                1_700_000_000_020,
            ),
            message(2, MessageRole::Agent, "agenttermxyz assistant alias", 1_700_000_000_030),
            message(
                3,
                MessageRole::Other("tool_call".into()),
                "toolcalltermxyz invoking a tool",
                1_700_000_000_040,
            ),
            message(
                4,
                MessageRole::Other("toolResult".into()),
                "toolresulttermxyz camelCase alias result",
                1_700_000_000_050,
            ),
        ],
    );
    storage
        .insert_conversation_tree(agent_id, None, &conv)
        .expect("insert alias/reasoning conversation");

    let conversation_id: i64 = storage
        .raw()
        .query_row_map(
            "SELECT id FROM conversations WHERE external_id = ?1",
            fparams!["alias-and-reasoning-conv"],
            |row| row.get_typed(0),
        )
        .expect("look up conversation id");
    let doc_ids = message_ids_for_conversation(&storage, conversation_id);
    assert_eq!(doc_ids.len(), 5, "all five raw message rows must exist regardless of eligibility");

    for (idx, doc_id) in doc_ids.iter().enumerate() {
        let doc_id = *doc_id;
        let indexed = lex_docs_row(&storage, doc_id).is_some();
        let (raw_role, content): (String, String) = storage
            .raw()
            .query_row_map(
                "SELECT role, content FROM messages WHERE id = ?1",
                fparams![doc_id],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )
            .expect("look up message role/content");
        assert_eq!(
            indexed,
            lexical_eligible(&raw_role, &content),
            "message idx {idx} (role {raw_role:?}) lex_docs presence must exactly match \
             lexical_eligible's own verdict -- single source of truth, no divergence"
        );
    }

    assert_eq!(fts_match_count(&storage, "usertermxyz"), 1, "user role must be indexed");
    assert_eq!(fts_match_count(&storage, "reasoningtermxyz"), 0, "reasoning role must be excluded");
    assert_eq!(fts_match_count(&storage, "agenttermxyz"), 1, "agent alias (assistant) must be indexed");
    assert_eq!(fts_match_count(&storage, "toolcalltermxyz"), 1, "tool_call alias must be indexed");
    assert_eq!(fts_match_count(&storage, "toolresulttermxyz"), 1, "toolResult alias must be indexed");
}

/// T5 Step 1: appending one new message to an already-indexed conversation
/// must sync only that new message's lex_docs/fts_lex row -- a TEMP TRIGGER
/// recording every `lex_docs` `doc_id` deleted during the append must stay
/// empty (nothing pre-existing gets deleted-and-reinserted).
#[test]
fn lexical_incremental_append_touches_only_new_message() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);

    let conv = conversation(
        "append-only-new-conv",
        "append fixture",
        None,
        vec![message(0, MessageRole::User, "firstmessagetermxyz original", 1_700_000_000_010)],
    );
    storage
        .insert_conversation_tree(agent_id, None, &conv)
        .expect("insert initial conversation");

    storage
        .raw()
        .execute_batch(
            "CREATE TEMP TABLE deleted_doc_ids (doc_id INTEGER PRIMARY KEY); \
             CREATE TEMP TRIGGER record_lex_docs_deletes AFTER DELETE ON lex_docs \
             BEGIN INSERT OR IGNORE INTO deleted_doc_ids(doc_id) VALUES (OLD.doc_id); END;",
        )
        .expect("install temp trigger");

    let mut conv_appended = conv.clone();
    conv_appended.messages.push(message(
        1,
        MessageRole::Assistant,
        "secondmessagetermxyz newly appended",
        1_700_000_000_020,
    ));
    storage
        .insert_conversation_tree(agent_id, None, &conv_appended)
        .expect("append second message");

    let recorded_deletes: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM deleted_doc_ids", fparams![], |row| row.get_typed(0))
        .expect("count recorded deletes");
    assert_eq!(
        recorded_deletes, 0,
        "appending a new message must never delete an existing conversation's lex_docs rows -- \
         only the message-level sync path (scoped to the new message id) should run"
    );

    assert_eq!(fts_match_count(&storage, "firstmessagetermxyz"), 1, "the original message must remain indexed");
    assert_eq!(fts_match_count(&storage, "secondmessagetermxyz"), 1, "the newly appended message must be indexed");
}

/// T5 Step 1: re-ingesting the same conversation with only its title/
/// workspace changed (messages unchanged) must UPDATE all of that
/// conversation's `lex_docs` rows' four projection columns (content
/// untouched), and the new title term must be MATCH-able while the old one
/// is not.
#[test]
fn lexical_envelope_change_reprojects_all_rows_in_conversation() {
    let (_dir, db_path) = scratch_db_path();
    let storage = open_storage(&db_path);
    let agent_id = ensure_test_agent(&storage);
    let workspace_old = storage
        .ensure_workspace(std::path::Path::new("/tmp/workspace-envelope-old"), None)
        .expect("ensure old workspace");
    let workspace_new = storage
        .ensure_workspace(std::path::Path::new("/tmp/workspace-envelope-new"), None)
        .expect("ensure new workspace");

    let conv = conversation(
        "envelope-change-conv",
        "oldtitletermxyz marker",
        Some(std::path::PathBuf::from("/tmp/workspace-envelope-old")),
        vec![
            message(0, MessageRole::User, "message A body text", 1_700_000_000_010),
            message(1, MessageRole::Assistant, "message B body text", 1_700_000_000_020),
        ],
    );
    let outcome = storage
        .insert_conversations_batched(&[(agent_id, Some(workspace_old), &conv)])
        .expect("initial insert")
        .into_iter()
        .next()
        .expect("one outcome");
    let conversation_id = outcome.conversation_id;
    let doc_ids = message_ids_for_conversation(&storage, conversation_id);
    assert_eq!(doc_ids.len(), 2, "fixture must have exactly messages A and B");

    let mut conv_renamed = conv.clone();
    conv_renamed.title = Some("newtitletermxyz marker".into());
    conv_renamed.workspace = Some(std::path::PathBuf::from("/tmp/workspace-envelope-new"));
    storage
        .insert_conversations_batched(&[(agent_id, Some(workspace_new), &conv_renamed)])
        .expect("re-ingest with changed envelope");

    for doc_id in &doc_ids {
        let (content, title, _agent, workspace) =
            lex_docs_row(&storage, *doc_id).expect("lex_docs row must still exist after envelope change");
        assert_eq!(title, "newtitletermxyz marker", "title projection must be the new value for doc_id {doc_id}");
        assert_eq!(
            workspace, "/tmp/workspace-envelope-new",
            "workspace projection must be the new value for doc_id {doc_id}"
        );
        assert!(
            content.contains("body text"),
            "content must be untouched by an envelope-only change for doc_id {doc_id}, got {content:?}"
        );
    }

    assert_eq!(fts_match_count(&storage, "newtitletermxyz"), 2, "new title term must MATCH both A and B");
    assert_eq!(fts_match_count(&storage, "oldtitletermxyz"), 0, "old title term must no longer be recallable");
}
