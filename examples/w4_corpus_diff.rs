//! T10 (plan v5.1): `w4_corpus_diff` -- the corpus-preservation gate.
//! Proves that reingesting a corpus (`--old` -> some pipeline -> `--new`)
//! lost no session and no message, keyed by `(source_path, external_id)`
//! (the same identity a real reingest uses to recognize "this is the same
//! conversation I've already seen", independent of row id, which a fresh
//! reingest is free to reassign).
//!
//! For every old-side conversation: its session key must exist on the new
//! side, its new-side `messages` row count must be `>=` its old-side count,
//! and every old-side message's `(idx, content_hash_hex(content))` identity
//! must exist among the new-side conversation's messages (raw-content hash,
//! *not* the chunking-domain's normalized-text hash -- this gate is about
//! content preservation, not chunking correctness).
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w4_corpus_diff -- --old <path> --new
//! <path> --json <out>`. Exit codes: 0 no loss detected; 1
//! `conversations_missing > 0` or `messages_missing > 0`; 2 precondition
//! error (either db path missing).

use std::collections::HashMap;
use std::path::PathBuf;

use clap::Parser;
use coding_agent_search::search::canonicalize::content_hash_hex;
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(name = "w4_corpus_diff")]
struct Cli {
    #[arg(long)]
    old: PathBuf,
    #[arg(long)]
    new: PathBuf,
    #[arg(long)]
    json: PathBuf,
}

type SessionKey = (String, Option<String>); // (source_path, external_id)

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
struct CorpusDiffReport {
    conversations_missing: i64,
    messages_missing: i64,
    conversations_grown: i64,
    old_conversations_total: i64,
    new_conversations_total: i64,
}

impl CorpusDiffReport {
    fn passed(&self) -> bool {
        self.conversations_missing == 0 && self.messages_missing == 0
    }
}

fn load_conversations(storage: &FrankenStorage) -> anyhow::Result<HashMap<SessionKey, i64>> {
    let rows: Vec<(i64, String, Option<String>)> = storage.raw().query_all_map(
        "SELECT id, source_path, external_id FROM conversations",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
    )?;
    let mut map = HashMap::with_capacity(rows.len());
    for (id, source_path, external_id) in rows {
        map.insert((source_path, external_id), id);
    }
    Ok(map)
}

fn message_identity_set(
    storage: &FrankenStorage,
    conversation_id: i64,
) -> anyhow::Result<std::collections::HashSet<(i64, String)>> {
    let rows: Vec<(i64, String)> = storage.raw().query_all_map(
        "SELECT idx, content FROM messages WHERE conversation_id = ?1",
        &[coding_agent_search::storage::api::Value::from(conversation_id)],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    )?;
    Ok(rows.into_iter().map(|(idx, content)| (idx, content_hash_hex(&content))).collect())
}

fn message_count(storage: &FrankenStorage, conversation_id: i64) -> anyhow::Result<i64> {
    let count = storage.raw().query_row_map(
        "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1",
        &[coding_agent_search::storage::api::Value::from(conversation_id)],
        |row| row.get_typed(0),
    )?;
    Ok(count)
}

fn compute_diff(old: &FrankenStorage, new: &FrankenStorage) -> anyhow::Result<CorpusDiffReport> {
    let old_convs = load_conversations(old)?;
    let new_convs = load_conversations(new)?;

    let mut conversations_missing = 0i64;
    let mut messages_missing = 0i64;
    let mut conversations_grown = 0i64;

    for (key, &old_conv_id) in &old_convs {
        match new_convs.get(key) {
            None => {
                conversations_missing += 1;
                messages_missing += message_count(old, old_conv_id)?;
            }
            Some(&new_conv_id) => {
                let old_count = message_count(old, old_conv_id)?;
                let new_count = message_count(new, new_conv_id)?;
                if new_count > old_count {
                    conversations_grown += 1;
                }
                let old_ids = message_identity_set(old, old_conv_id)?;
                let new_ids = message_identity_set(new, new_conv_id)?;
                messages_missing += old_ids.difference(&new_ids).count() as i64;
            }
        }
    }

    Ok(CorpusDiffReport {
        conversations_missing,
        messages_missing,
        conversations_grown,
        old_conversations_total: old_convs.len() as i64,
        new_conversations_total: new_convs.len() as i64,
    })
}

/// Returns `(exit_code, report)`. `report` is `None` only for a precondition
/// failure (exit 2), in which case the caller should not attempt to write
/// `--json`.
fn run(old_path: &std::path::Path, new_path: &std::path::Path) -> (i32, Option<CorpusDiffReport>, String) {
    if !old_path.is_file() {
        return (2, None, format!("precondition error: --old db {} does not exist", old_path.display()));
    }
    if !new_path.is_file() {
        return (2, None, format!("precondition error: --new db {} does not exist", new_path.display()));
    }
    let old = match FrankenStorage::open_readonly(old_path) {
        Ok(s) => s,
        Err(e) => return (2, None, format!("precondition error opening --old: {e:#}")),
    };
    let new = match FrankenStorage::open_readonly(new_path) {
        Ok(s) => s,
        Err(e) => return (2, None, format!("precondition error opening --new: {e:#}")),
    };
    match compute_diff(&old, &new) {
        Err(e) => (2, None, format!("precondition error computing diff: {e:#}")),
        Ok(report) => {
            let code = if report.passed() { 0 } else { 1 };
            let msg = format!(
                "corpus_diff: conversations_missing={} messages_missing={} conversations_grown={} \
                 old_conversations_total={} new_conversations_total={}",
                report.conversations_missing,
                report.messages_missing,
                report.conversations_grown,
                report.old_conversations_total,
                report.new_conversations_total
            );
            (code, Some(report), msg)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let (code, report, message) = run(&cli.old, &cli.new);
    println!("{message}");
    if let Some(report) = &report {
        let json = serde_json::to_string_pretty(report).expect("CorpusDiffReport must serialize");
        std::fs::write(&cli.json, json).expect("writing --json output must succeed");
    }
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
    use coding_agent_search::sources::provenance::LOCAL_SOURCE_ID;
    use coding_agent_search::storage::api::TxMode;
    use tempfile::TempDir;

    fn seed_db(path: &std::path::Path, n_conversations: usize, n_messages_each: usize) {
        let storage = FrankenStorage::open(path).unwrap();
        let agent = Agent { id: None, slug: "codex".into(), name: "Codex".into(), version: Some("0.1".into()), kind: AgentKind::Cli };
        let agent_id = storage.ensure_agent(&agent).unwrap();

        let mut conversations = Vec::new();
        for c in 0..n_conversations {
            let mut messages = Vec::new();
            for i in 0..n_messages_each {
                messages.push(Message {
                    id: None,
                    idx: i as i64,
                    role: MessageRole::User,
                    author: Some("user".into()),
                    created_at: Some(1_700_000_000_000 + i as i64),
                    content: format!("corpus-diff fixture message {c}-{i} with enough text to be non-trivial."),
                    extra_json: serde_json::json!({}),
                    snippets: Vec::new(),
                });
            }
            conversations.push(Conversation {
                id: None,
                agent_slug: "codex".into(),
                workspace: Some(PathBuf::from("/tmp/workspace")),
                external_id: Some(format!("corpus-diff-fixture-{c}")),
                title: Some("Corpus diff fixture".into()),
                source_path: PathBuf::from(format!("/tmp/corpus-diff-fixture-{c}.jsonl")),
                started_at: Some(1_700_000_000_000),
                ended_at: Some(1_700_000_000_000 + n_messages_each as i64),
                approx_tokens: Some(64),
                metadata_json: serde_json::Value::Null,
                messages,
                source_id: LOCAL_SOURCE_ID.into(),
                origin_host: None,
            });
        }
        let batch: Vec<(i64, Option<i64>, &Conversation)> = conversations.iter().map(|c| (agent_id, None, c)).collect();
        storage.insert_conversations_batched(&batch).unwrap();
    }

    #[test]
    fn identical_corpora_pass_with_zero_missing() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 5, 10);
        seed_db(&new, 5, 10);

        let (code, report, message) = run(&old, &new);
        assert_eq!(code, 0, "identical corpora must pass: {message}");
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 0);
        assert_eq!(report.messages_missing, 0);
    }

    #[test]
    fn deleted_conversation_is_detected_exit_1() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 5, 10);
        seed_db(&new, 5, 10);

        let writer = FrankenStorage::open_writer(&new).unwrap();
        writer.raw().execute("DELETE FROM conversations WHERE id = 1", &[]).unwrap();
        drop(writer);

        let (code, report, message) = run(&old, &new);
        assert_eq!(code, 1, "a deleted conversation must fail the gate: {message}");
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 1);
        assert_eq!(report.messages_missing, 10, "the deleted conversation's 10 messages must all count as missing");
    }

    #[test]
    fn deleted_message_is_detected_exit_1() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 5, 10);
        seed_db(&new, 5, 10);

        let writer = FrankenStorage::open_writer(&new).unwrap();
        writer.raw().execute("DELETE FROM messages WHERE conversation_id = 2 AND idx = 3", &[]).unwrap();
        drop(writer);

        let (code, report, message) = run(&old, &new);
        assert_eq!(code, 1, "a deleted message must fail the gate: {message}");
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 0);
        assert_eq!(report.messages_missing, 1);
    }

    #[test]
    fn modified_content_is_detected_exit_1() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 5, 10);
        seed_db(&new, 5, 10);

        let writer = FrankenStorage::open_writer(&new).unwrap();
        writer
            .raw()
            .with_tx(TxMode::Immediate, |tx| {
                tx.execute(
                    "UPDATE messages SET content = 'this content was mutated' WHERE conversation_id = 3 AND idx = 4",
                    &[],
                )
            })
            .unwrap();
        drop(writer);

        let (code, report, message) = run(&old, &new);
        assert_eq!(code, 1, "a mutated message content must fail the gate (hash mismatch): {message}");
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 0);
        assert_eq!(report.messages_missing, 1);
    }

    #[test]
    fn grown_conversation_is_reported_but_does_not_fail() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 3, 5);
        seed_db(&new, 3, 5);

        // Add one extra message to conversation 1 on the new side, matching
        // the fixture's idx/content convention exactly (idx=5 is the next
        // free idx for a 5-message conversation) -- this is legitimate
        // growth, not a content divergence.
        let writer = FrankenStorage::open_writer(&new).unwrap();
        writer
            .raw()
            .execute(
                "INSERT INTO messages(conversation_id, idx, role, content) VALUES (1, 5, 'user', 'a sixth message added on the new side')",
                &[],
            )
            .unwrap();
        drop(writer);

        let (code, report, message) = run(&old, &new);
        assert_eq!(code, 0, "growth alone must not fail the gate: {message}");
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 0);
        assert_eq!(report.messages_missing, 0);
        assert_eq!(report.conversations_grown, 1);
    }

    #[test]
    fn missing_db_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("does-not-exist.db");
        let new = dir.path().join("new.db");
        seed_db(&new, 1, 1);

        let (code, report, message) = run(&old, &new);
        assert_eq!(code, 2, "missing --old db must be a precondition error: {message}");
        assert!(report.is_none());
    }
}
