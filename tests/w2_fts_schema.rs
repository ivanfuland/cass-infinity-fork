//! W2-2 Step 2: failing tests for the `lex_docs` + `fts_lex` schema domain
//! (spec R1-N01, R0-N05; OQ2 decided external-content — control plane
//! 2026-08-29). These tests insert directly into `lex_docs`/`fts_lex` to
//! validate the schema's own capability; the transactional sync wiring
//! (triggers / in-transaction dual write) is W2-3's job, not tested here.

use coding_agent_search::storage::api::Profile;
use coding_agent_search::storage::schema;
use coding_agent_search::storage::testing::open_writable_for_tests;

fn scratch_conn() -> (tempfile::TempDir, coding_agent_search::storage::api::Conn) {
    let dir = tempfile::TempDir::new().expect("create scratch dir");
    let path = dir.path().join("agent_search.db");
    let conn = open_writable_for_tests(&path, Profile::Production).expect("open writer");
    schema::ensure(&conn).expect("schema::ensure should build the fresh schema (incl. lex_docs/fts_lex)");
    (dir, conn)
}

/// `lex_docs.doc_id` carries a real `REFERENCES messages(id) ON DELETE
/// CASCADE` FK (matching the plan's "doc_id INTEGER PK ↔ messages.id"
/// identity contract), so these schema-capability tests must first create a
/// minimal real parent chain (agent/conversation/message) for `doc_id` to
/// reference -- not just a bare row satisfying the FTS5 columns.
fn insert_message_parent_chain(
    conn: &coding_agent_search::storage::api::Conn,
    message_id: i64,
    content: &str,
    title: &str,
    agent_slug: &str,
    source_path: &str,
) {
    use coding_agent_search::storage::api::Value as V;
    conn.execute(
        "INSERT INTO agents(id, slug, name, kind, created_at, updated_at) \
         VALUES (?1, ?2, ?2, 'cli', 0, 0)",
        &[V::from(message_id), V::from(agent_slug)],
    )
    .expect("insert parent agent");
    conn.execute(
        "INSERT INTO conversations(id, agent_id, title, source_path) VALUES (?1, ?1, ?2, ?3)",
        &[V::from(message_id), V::from(title), V::from(source_path)],
    )
    .expect("insert parent conversation");
    conn.execute(
        "INSERT INTO messages(id, conversation_id, idx, role, content) \
         VALUES (?1, ?1, 0, 'user', ?2)",
        &[V::from(message_id), V::from(content)],
    )
    .expect("insert parent message");
}

fn insert_lex_doc(
    conn: &coding_agent_search::storage::api::Conn,
    doc_id: i64,
    content: &str,
    title: &str,
    agent: &str,
    workspace: &str,
    source_path: &str,
) {
    use coding_agent_search::storage::api::Value as V;
    insert_message_parent_chain(conn, doc_id, content, title, agent, source_path);
    conn.execute(
        "INSERT INTO lex_docs(doc_id, content, title, agent, workspace, source_path) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &[
            V::from(doc_id),
            V::from(content),
            V::from(title),
            V::from(agent),
            V::from(workspace),
            V::from(source_path),
        ],
    )
    .expect("insert into lex_docs");
    conn.execute(
        "INSERT INTO fts_lex(rowid, content, title, agent, workspace, source_path) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        &[
            V::from(doc_id),
            V::from(content),
            V::from(title),
            V::from(agent),
            V::from(workspace),
            V::from(source_path),
        ],
    )
    .expect("insert into fts_lex");
}

/// R1-N01: five-column recall — a title-only term (absent from content) must
/// still be recallable via `fts_lex MATCH`. Fails today: `lex_docs`/`fts_lex`
/// do not exist yet.
#[test]
fn fts_lex_five_column_match_recalls_title_only_term() {
    let (_dir, conn) = scratch_conn();
    insert_lex_doc(
        &conn,
        1,
        "this body text says nothing special",
        "zzyzxqorb unique title marker",
        "claude_code",
        "/home/ivan/projects/demo",
        "/home/ivan/.claude/projects/demo/session.jsonl",
    );

    let hits: i64 = conn
        .query_row_map(
            "SELECT count(*) FROM fts_lex WHERE fts_lex MATCH 'zzyzxqorb'",
            &[],
            |row| row.get_typed(0),
        )
        .expect("query fts_lex by title-only term");
    assert_eq!(hits, 1, "title-only term must be recallable via fts_lex MATCH");
}

/// spec R0-N05 pinning test: `porter trigram` tokenizer order actually
/// tokenizes on trigrams, so a bare three-character Chinese phrase (no
/// whitespace segmentation available) is still recallable via MATCH.
#[test]
fn fts_lex_trigram_matches_three_char_chinese() {
    let (_dir, conn) = scratch_conn();
    insert_lex_doc(
        &conn,
        1,
        "前置内容 三字中文短语示例 后置内容",
        "",
        "codex",
        "/home/ivan/projects/demo",
        "/home/ivan/.codex/sessions/demo.jsonl",
    );

    let hits: i64 = conn
        .query_row_map(
            "SELECT count(*) FROM fts_lex WHERE fts_lex MATCH '三字中文'",
            &[],
            |row| row.get_typed(0),
        )
        .expect("query fts_lex by three-char Chinese phrase");
    assert_eq!(hits, 1, "porter trigram tokenizer must recall a bare 3-char Chinese phrase");
}

/// spec 门①口径: `INSERT INTO fts_lex(fts_lex, rank) VALUES('integrity-check', 1)`
/// must not error. An `integrity_check` PRAGMA against an empty/absent FTS5
/// table is vacuously "ok" and does not exercise the real internal
/// structure check, so this specific rank=1 form is the actual gate.
#[test]
fn fts_lex_integrity_check_rank_one_passes() {
    let (_dir, conn) = scratch_conn();
    insert_lex_doc(
        &conn,
        1,
        "some content for integrity check coverage",
        "some title",
        "claude_code",
        "/home/ivan/projects/demo",
        "/home/ivan/.claude/projects/demo/session.jsonl",
    );

    conn.execute("INSERT INTO fts_lex(fts_lex, rank) VALUES('integrity-check', 1)", &[])
        .expect("fts5 rank=1 integrity-check command must pass on a populated table");
}
