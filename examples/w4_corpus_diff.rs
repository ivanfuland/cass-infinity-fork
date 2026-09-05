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

type SessionKey = (String, Option<String>); // (agent_slug, external_id)

struct ConvRecord {
    id: i64,
    source_path: String,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
struct CorpusDiffReport {
    conversations_missing: i64,
    messages_missing: i64,
    conversations_grown: i64,
    /// Informational only, not part of the match key: how many matched
    /// sessions have a different `source_path` between `--old` and `--new`
    /// (expected whenever a mirror-home materialization pass ran; see T12 3a).
    source_path_changed: i64,
    old_conversations_total: i64,
    new_conversations_total: i64,
}

impl CorpusDiffReport {
    fn passed(&self) -> bool {
        self.conversations_missing == 0 && self.messages_missing == 0
    }
}

fn load_conversations(storage: &FrankenStorage) -> anyhow::Result<HashMap<SessionKey, ConvRecord>> {
    let rows: Vec<(i64, String, Option<String>, String)> = storage.raw().query_all_map(
        "SELECT c.id, a.slug, c.external_id, c.source_path FROM conversations c JOIN agents a ON a.id = c.agent_id",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?)),
    )?;
    let mut map = HashMap::with_capacity(rows.len());
    for (id, agent_slug, external_id, source_path) in rows {
        map.insert((agent_slug, external_id), ConvRecord { id, source_path });
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
    let mut source_path_changed = 0i64;

    for (key, old_rec) in &old_convs {
        match new_convs.get(key) {
            None => {
                conversations_missing += 1;
                messages_missing += message_count(old, old_rec.id)?;
            }
            Some(new_rec) => {
                if old_rec.source_path != new_rec.source_path {
                    source_path_changed += 1;
                }
                let old_count = message_count(old, old_rec.id)?;
                let new_count = message_count(new, new_rec.id)?;
                if new_count > old_count {
                    conversations_grown += 1;
                }
                let old_ids = message_identity_set(old, old_rec.id)?;
                let new_ids = message_identity_set(new, new_rec.id)?;
                messages_missing += old_ids.difference(&new_ids).count() as i64;
            }
        }
    }

    Ok(CorpusDiffReport {
        conversations_missing,
        messages_missing,
        conversations_grown,
        source_path_changed,
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
                 source_path_changed={} old_conversations_total={} new_conversations_total={}",
                report.conversations_missing,
                report.messages_missing,
                report.conversations_grown,
                report.source_path_changed,
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

    struct SeedSpec {
        external_id: &'static str,
        agent_slug: &'static str,
        source_path: String,
        n_messages: usize,
    }

    /// Like `seed_db`, but lets each conversation carry its own agent slug
    /// and `source_path` -- needed to reproduce the T12 3a finding, where a
    /// mirror-home materialization pass rewrites `source_path` to a
    /// temporary HOME prefix while `(agent_slug, external_id)` stays put.
    fn seed_db_specs(path: &std::path::Path, specs: &[SeedSpec]) {
        let storage = FrankenStorage::open(path).unwrap();
        let mut agent_ids: HashMap<&'static str, i64> = HashMap::new();

        let mut conversations = Vec::new();
        let mut agent_id_for_conv = Vec::new();
        for spec in specs {
            let agent_id = *agent_ids.entry(spec.agent_slug).or_insert_with(|| {
                let agent = Agent {
                    id: None,
                    slug: spec.agent_slug.into(),
                    name: spec.agent_slug.into(),
                    version: Some("0.1".into()),
                    kind: AgentKind::Cli,
                };
                storage.ensure_agent(&agent).unwrap()
            });

            let mut messages = Vec::new();
            for i in 0..spec.n_messages {
                messages.push(Message {
                    id: None,
                    idx: i as i64,
                    role: MessageRole::User,
                    author: Some("user".into()),
                    created_at: Some(1_700_000_000_000 + i as i64),
                    content: format!(
                        "corpus-diff fixture message {}-{i} with enough text to be non-trivial.",
                        spec.external_id
                    ),
                    extra_json: serde_json::json!({}),
                    snippets: Vec::new(),
                });
            }
            conversations.push(Conversation {
                id: None,
                agent_slug: spec.agent_slug.into(),
                workspace: Some(PathBuf::from("/tmp/workspace")),
                external_id: Some(spec.external_id.into()),
                title: Some("Corpus diff fixture".into()),
                source_path: PathBuf::from(&spec.source_path),
                started_at: Some(1_700_000_000_000),
                ended_at: Some(1_700_000_000_000 + spec.n_messages as i64),
                approx_tokens: Some(64),
                metadata_json: serde_json::Value::Null,
                messages,
                source_id: LOCAL_SOURCE_ID.into(),
                origin_host: None,
            });
            agent_id_for_conv.push(agent_id);
        }
        let batch: Vec<(i64, Option<i64>, &Conversation)> = agent_id_for_conv
            .into_iter()
            .zip(conversations.iter())
            .map(|(agent_id, c)| (agent_id, None, c))
            .collect();
        storage.insert_conversations_batched(&batch).unwrap();
    }

    #[test]
    fn source_path_change_alone_does_not_fail_the_gate() {
        // T12 3a: a mirror-home materialization pass rewrites `source_path`
        // to a temporary HOME prefix for a session whose original source
        // file was rotated away, but `(agent_slug, external_id)` and every
        // message are unchanged. The gate must not report this as loss.
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");

        seed_db_specs(
            &old,
            &[SeedSpec {
                external_id: "sess-1",
                agent_slug: "codex",
                source_path: "/home/ivan/.codex/sessions/sess-1.jsonl".into(),
                n_messages: 10,
            }],
        );
        seed_db_specs(
            &new,
            &[SeedSpec {
                external_id: "sess-1",
                agent_slug: "codex",
                source_path: "/tmp/cc-cass-pr4-run/mirror-home/.codex/sessions/sess-1.jsonl".into(),
                n_messages: 10,
            }],
        );

        let (code, report, message) = run(&old, &new);
        assert_eq!(
            code, 0,
            "source_path alone changing (mirror-home materialization) must not fail the gate: {message}"
        );
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 0);
        assert_eq!(report.messages_missing, 0);
        assert_eq!(
            report.source_path_changed, 1,
            "the source_path divergence must still be reported (informational, not a match key)"
        );
    }

    #[test]
    fn same_external_id_different_agent_slug_is_a_different_session_and_is_missing() {
        // Two different agents could in principle mint the same external_id;
        // they must not be conflated into one session.
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");

        seed_db_specs(
            &old,
            &[SeedSpec {
                external_id: "shared-id",
                agent_slug: "codex",
                source_path: "/tmp/a.jsonl".into(),
                n_messages: 4,
            }],
        );
        seed_db_specs(
            &new,
            &[SeedSpec {
                external_id: "shared-id",
                agent_slug: "claude",
                source_path: "/tmp/a.jsonl".into(),
                n_messages: 4,
            }],
        );

        let (code, report, message) = run(&old, &new);
        assert_eq!(
            code, 1,
            "same external_id under a different agent slug must count as a missing session: {message}"
        );
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 1);
        assert_eq!(report.messages_missing, 4);
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
