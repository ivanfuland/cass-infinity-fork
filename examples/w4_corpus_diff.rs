//! T10 (plan v5.1): `w4_corpus_diff` -- the corpus-preservation gate.
//! Proves that reingesting a corpus (`--old` -> some pipeline -> `--new`)
//! lost no session and no message, keyed by `(source_path, external_id)`
//! (the same identity a real reingest uses to recognize "this is the same
//! conversation I've already seen", independent of row id, which a fresh
//! reingest is free to reassign).
//!
//! For every old-side conversation: its session key must exist on the new
//! side, its new-side `messages` row count must be `>=` its old-side count,
//! and every old-side message's `(idx, sha)` identity must exist among the
//! new-side conversation's messages (raw-content hash, *not* the
//! chunking-domain's normalized-text hash -- this gate is about content
//! preservation, not chunking correctness).
//!
//! PR6 T5 (spec §五 corpus_diff 行) changed what that `sha` is. An exclusion
//! row -- ingest cleared `content` and recorded the body's pre-clear sha in
//! `messages.excluded` -- used to hash to the empty string and read as a
//! lost message. Its identity is now `excluded.sha256`, i.e. the same value
//! the old side still holds. The old side is allowed to predate schema v6
//! (the frozen `copy/` is v4), so the column is probed with
//! `PRAGMA table_info(messages)` rather than assumed.
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w4_corpus_diff -- --old <path> --new
//! <path> --json <out> [--exempt-null-rewrites <jsonl>]`. Exit codes: 0 no
//! loss detected; 1 `conversations_missing > 0` or `messages_missing > 0`; 2
//! precondition error (either db path missing, an unreadable
//! `--exempt-null-rewrites` file, or a duplicate session key).

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use clap::Parser;
use coding_agent_search::search::canonicalize::content_hash_hex;
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(name = "w4_corpus_diff")]
struct Cli {
    #[arg(long)]
    old: PathBuf,
    #[arg(long)]
    new: PathBuf,
    #[arg(long)]
    json: PathBuf,
    /// JSONL of `{source_id, agent_slug, old_source_path, new_source_path}`.
    /// Every session with a NULL `external_id` is keyed by `source_path`, so a
    /// legitimate path rewrite (a mirror-home materialization pass) reads as a
    /// missing session. Each line exempts one such rewrite from the diff. T6
    /// Step 3a generates it from the two databases and the control plane
    /// reviews it before use.
    #[arg(long)]
    exempt_null_rewrites: Option<PathBuf>,
}

// R1-B4 (exec92): keyed like the schema-6 unique key `(source_id, agent_id,
// external_id)`. Schema 7 (PR8 C1) changed the unique key to
// `(identity_host, agent_id, external_id)`; this diff key still uses
// `source_id`. (agent_slug, external_id) alone collapses two sessions from
// different sources (a real, reachable shape once a corpus has more than
// one `sources` row) into a single map entry, so an entire missing session
// can go undetected whenever the surviving source happens to share the
// same (agent_slug, external_id).
//
// R2-#3 (exec94): `external_id` can be NULL (a session with no external
// id), and Rust's `HashMap` treats every `None` as the same key value --
// so two distinct local sessions sharing `(source_id, agent_slug, None)`
// but different `source_path` still collapsed into one map entry even
// after the source_id fix above. When `external_id` is `None`,
// `source_path` is the only remaining discriminator (it is *not* part of
// the key when `external_id` is present, since a real materialization
// pass is allowed to change `source_path` for the same external session --
// see `source_path_changed` below -- but a session with no external id has
// no other stable identity to fall back on).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum SessionKey {
    ByExternalId(String, String, String),
    ByPath(String, String, String),
}

fn session_key(source_id: &str, agent_slug: &str, external_id: Option<&str>, source_path: &str) -> SessionKey {
    match external_id {
        Some(id) => SessionKey::ByExternalId(source_id.to_string(), agent_slug.to_string(), id.to_string()),
        None => SessionKey::ByPath(source_id.to_string(), agent_slug.to_string(), source_path.to_string()),
    }
}

struct ConvRecord {
    id: i64,
    source_path: String,
}

/// One `--exempt-null-rewrites` line.
#[derive(Debug, Deserialize)]
struct ExemptNullRewrite {
    source_id: String,
    agent_slug: String,
    old_source_path: String,
    new_source_path: String,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
struct CorpusDiffReport {
    conversations_missing: i64,
    messages_missing: i64,
    conversations_grown: i64,
    /// Informational only, not part of the match key: how many matched
    /// sessions have a different `source_path` between `--old` and `--new`
    /// (expected whenever a mirror-home materialization pass ran; see T12 3a).
    /// An `--exempt-null-rewrites` hit does not count here.
    source_path_changed: i64,
    old_conversations_total: i64,
    new_conversations_total: i64,
    /// PR6 T5: how many new-side exclusion rows carried their identity across
    /// via `excluded.sha256` -- i.e. how many old-side `(idx, sha)` pairs were
    /// matched by a marker rather than by a still-present body. This is the
    /// count the corpus-diff gate compares against the exclusion manifest.
    /// Disclosure only: a wrong value here cannot fail the gate, because a
    /// wrong value also shows up as `messages_missing`.
    excluded_transform_ok: i64,
    /// PR6 T5: duplicate session keys seen while loading either side. Always 0
    /// in a report that was written out; a non-zero count is a precondition
    /// error (exit 2) and the report is emitted anyway so the colliding keys
    /// are visible.
    duplicates_fail_loud: i64,
}

impl CorpusDiffReport {
    fn passed(&self) -> bool {
        self.conversations_missing == 0 && self.messages_missing == 0
    }
}

fn load_conversations(
    storage: &FrankenStorage,
) -> anyhow::Result<(HashMap<SessionKey, ConvRecord>, Vec<String>)> {
    let rows: Vec<(i64, String, String, Option<String>, String)> = storage.raw().query_all_map(
        "SELECT c.id, c.source_id, a.slug, c.external_id, c.source_path FROM conversations c JOIN agents a ON a.id = c.agent_id",
        &[],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?, row.get_typed(3)?, row.get_typed(4)?)),
    )?;
    let mut map = HashMap::with_capacity(rows.len());
    let mut duplicates = Vec::new();
    for (id, source_id, agent_slug, external_id, source_path) in rows {
        let key = session_key(&source_id, &agent_slug, external_id.as_deref(), &source_path);
        // PR6 T5: a duplicate key used to be a silent last-write-wins
        // `insert` -- the earlier row stopped being compared at all, so a
        // whole lost session could hide behind its twin. Two rows sharing the
        // provenance unique key are a broken corpus, not something to guess
        // about: keep the first and report the collision.
        if map.contains_key(&key) {
            duplicates.push(format!("{key:?} (second row id {id})"));
            continue;
        }
        map.insert(key, ConvRecord { id, source_path });
    }
    Ok((map, duplicates))
}

/// Whether `messages` carries the schema-v6 `excluded` column. The old side of
/// a corpus diff is routinely a v4 database (the frozen `copy/`), where any
/// SQL naming that column is a hard error rather than a NULL.
fn messages_has_excluded_column(storage: &FrankenStorage) -> anyhow::Result<bool> {
    let columns: Vec<String> = storage
        .raw()
        .query_all_map("PRAGMA table_info(messages)", &[], |row| row.get_typed::<String>(1))?;
    Ok(columns.iter().any(|column| column == "excluded"))
}

/// The `sha256` inside an `excluded` marker, or `None` when the column is NULL,
/// unparseable, or shaped without one.
fn excluded_sha(excluded_json: &Option<String>) -> Option<String> {
    let text = excluded_json.as_deref()?;
    let value: serde_json::Value = serde_json::from_str(text).ok()?;
    value.get("sha256")?.as_str().map(str::to_string)
}

/// `(idx, sha)` identities for one conversation, plus the `idx -> excluded.sha256`
/// map for the rows that carried one.
///
/// PR6 T5: sha is `content_hash_hex(content)` for a normal row, but for an
/// exclusion row it is `excluded.sha256` -- the hash of the body that was there
/// before ingest cleared `content`. Hashing the cleared (empty) body made every
/// legitimately excluded row read as a lost message.
fn message_identity_set(
    storage: &FrankenStorage,
    conversation_id: i64,
    has_excluded_column: bool,
) -> anyhow::Result<(std::collections::HashSet<(i64, String)>, HashMap<i64, String>)> {
    let conversation = coding_agent_search::storage::api::Value::from(conversation_id);
    let mut identities = std::collections::HashSet::new();
    let mut excluded_shas = HashMap::new();

    if has_excluded_column {
        let rows: Vec<(i64, String, Option<String>)> = storage.raw().query_all_map(
            "SELECT idx, content, json(excluded) FROM messages WHERE conversation_id = ?1",
            &[conversation],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
        )?;
        for (idx, content, excluded_json) in rows {
            match excluded_sha(&excluded_json) {
                Some(sha) => {
                    excluded_shas.insert(idx, sha.clone());
                    identities.insert((idx, sha));
                }
                None => {
                    identities.insert((idx, content_hash_hex(&content)));
                }
            }
        }
        return Ok((identities, excluded_shas));
    }

    let rows: Vec<(i64, String)> = storage.raw().query_all_map(
        "SELECT idx, content FROM messages WHERE conversation_id = ?1",
        &[conversation],
        |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
    )?;
    identities.extend(rows.into_iter().map(|(idx, content)| (idx, content_hash_hex(&content))));
    Ok((identities, excluded_shas))
}

fn message_count(storage: &FrankenStorage, conversation_id: i64) -> anyhow::Result<i64> {
    let count = storage.raw().query_row_map(
        "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1",
        &[coding_agent_search::storage::api::Value::from(conversation_id)],
        |row| row.get_typed(0),
    )?;
    Ok(count)
}

/// The `--exempt-null-rewrites` lookup key for a session, or `None` for a key
/// that cannot be rewritten in the first place (anything with an
/// `external_id`, which is what the exemption list is for).
fn exempt_key(key: &SessionKey) -> Option<(String, String, String)> {
    match key {
        SessionKey::ByPath(source_id, agent_slug, source_path) => {
            Some((source_id.clone(), agent_slug.clone(), source_path.clone()))
        }
        SessionKey::ByExternalId(..) => None,
    }
}

fn remapped_key(key: &SessionKey, new_source_path: &str) -> SessionKey {
    match key {
        SessionKey::ByPath(source_id, agent_slug, _) => SessionKey::ByPath(
            source_id.clone(),
            agent_slug.clone(),
            new_source_path.to_string(),
        ),
        SessionKey::ByExternalId(..) => key.clone(),
    }
}

fn load_exempt_null_rewrites(
    path: &Path,
) -> anyhow::Result<HashMap<(String, String, String), String>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
    let mut exemptions = HashMap::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: ExemptNullRewrite = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("parsing {}:{}: {e}", path.display(), line_number + 1))?;
        exemptions.insert(
            (entry.source_id, entry.agent_slug, entry.old_source_path),
            entry.new_source_path,
        );
    }
    Ok(exemptions)
}

fn compute_diff(
    old: &FrankenStorage,
    new: &FrankenStorage,
    exempt_null_rewrites: &HashMap<(String, String, String), String>,
) -> anyhow::Result<CorpusDiffReport> {
    let (old_convs, mut duplicates) = load_conversations(old)?;
    let (new_convs, new_duplicates) = load_conversations(new)?;
    duplicates.extend(new_duplicates);
    let old_has_excluded = messages_has_excluded_column(old)?;
    let new_has_excluded = messages_has_excluded_column(new)?;

    let mut conversations_missing = 0i64;
    let mut messages_missing = 0i64;
    let mut conversations_grown = 0i64;
    let mut source_path_changed = 0i64;
    let mut excluded_transform_ok = 0i64;

    for (key, old_rec) in &old_convs {
        // A NULL-`external_id` session is keyed by `source_path`, so a
        // legitimate rewrite of that path looks like a lost session. An
        // exemption line says "this exact path became that one" and is the
        // only thing allowed to re-point the lookup.
        let mut new_rec = new_convs.get(key);
        let mut matched_via_exemption = false;
        if new_rec.is_none()
            && let Some(new_path) = exempt_key(key).and_then(|k| exempt_null_rewrites.get(&k))
        {
            new_rec = new_convs.get(&remapped_key(key, new_path));
            matched_via_exemption = new_rec.is_some();
        }

        match new_rec {
            None => {
                conversations_missing += 1;
                messages_missing += message_count(old, old_rec.id)?;
            }
            Some(new_rec) => {
                if !matched_via_exemption && old_rec.source_path != new_rec.source_path {
                    source_path_changed += 1;
                }
                let old_count = message_count(old, old_rec.id)?;
                let new_count = message_count(new, new_rec.id)?;
                if new_count > old_count {
                    conversations_grown += 1;
                }
                let (old_ids, _) = message_identity_set(old, old_rec.id, old_has_excluded)?;
                let (new_ids, new_excluded_shas) =
                    message_identity_set(new, new_rec.id, new_has_excluded)?;
                messages_missing += old_ids.difference(&new_ids).count() as i64;
                for (idx, sha) in &new_excluded_shas {
                    if old_ids.contains(&(*idx, sha.clone())) {
                        excluded_transform_ok += 1;
                    }
                }
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
        excluded_transform_ok,
        duplicates_fail_loud: duplicates.len() as i64,
    })
}

/// Returns `(exit_code, report)`. `report` is `None` only for a precondition
/// failure that produced no diff at all; a duplicate-session-key failure
/// carries its report so the colliding keys are visible.
fn run(
    old_path: &std::path::Path,
    new_path: &std::path::Path,
    exempt_null_rewrites_path: Option<&Path>,
) -> (i32, Option<CorpusDiffReport>, String) {
    if !old_path.is_file() {
        return (2, None, format!("precondition error: --old db {} does not exist", old_path.display()));
    }
    if !new_path.is_file() {
        return (2, None, format!("precondition error: --new db {} does not exist", new_path.display()));
    }
    let exempt = match exempt_null_rewrites_path {
        Some(path) => match load_exempt_null_rewrites(path) {
            Ok(map) => map,
            Err(e) => return (2, None, format!("precondition error: {e:#}")),
        },
        None => HashMap::new(),
    };
    let old = match FrankenStorage::open_readonly(old_path) {
        Ok(s) => s,
        Err(e) => return (2, None, format!("precondition error opening --old: {e:#}")),
    };
    let new = match FrankenStorage::open_readonly(new_path) {
        Ok(s) => s,
        Err(e) => return (2, None, format!("precondition error opening --new: {e:#}")),
    };
    match compute_diff(&old, &new, &exempt) {
        Err(e) => (2, None, format!("precondition error computing diff: {e:#}")),
        Ok(report) => {
            let code = if report.duplicates_fail_loud > 0 {
                2
            } else if report.passed() {
                0
            } else {
                1
            };
            let msg = format!(
                "corpus_diff: conversations_missing={} messages_missing={} conversations_grown={} \
                 source_path_changed={} old_conversations_total={} new_conversations_total={} \
                 excluded_transform_ok={} duplicates_fail_loud={}",
                report.conversations_missing,
                report.messages_missing,
                report.conversations_grown,
                report.source_path_changed,
                report.old_conversations_total,
                report.new_conversations_total,
                report.excluded_transform_ok,
                report.duplicates_fail_loud,
            );
            (code, Some(report), msg)
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let (code, report, message) = run(&cli.old, &cli.new, cli.exempt_null_rewrites.as_deref());
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
                    excluded: None,
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

    /// PR6 T5: turn one already-seeded message into an exclusion row the way
    /// ingest does -- `content` cleared, `excluded` JSONB carrying the sha256
    /// of the (redacted) body that was there before. `seed_db`'s message text
    /// is deterministic, so the caller can name the conversation/message
    /// index and let this recompute the pre-clear sha.
    fn mark_message_excluded(path: &std::path::Path, conversation_id: i64, message_idx: i64) {
        let body = format!(
            "corpus-diff fixture message {}-{message_idx} with enough text to be non-trivial.",
            conversation_id - 1
        );
        let marker = serde_json::json!({
            "reason": "cass_recall",
            "rule_version": 1,
            "bytes": body.len(),
            "sha256": content_hash_hex(&body),
            "fingerprint_blake3": "00".repeat(32),
            "parse_error": null,
            "anchor": {"tool_call_id": null, "tool_name": null, "paths": null, "shell": null},
            "src": null,
            "raw": {"blob": "blobs/blake3/aa/aa.raw", "idx": message_idx, "event_key": "evt", "blocks": [0]},
        });
        let writer = FrankenStorage::open_writer(path).unwrap();
        let updated = writer
            .raw()
            .execute(
                "UPDATE messages SET content = '', excluded = jsonb(?1) WHERE conversation_id = ?2 AND idx = ?3",
                &[
                    coding_agent_search::storage::api::Value::from(marker.to_string()),
                    coding_agent_search::storage::api::Value::from(conversation_id),
                    coding_agent_search::storage::api::Value::from(message_idx),
                ],
            )
            .unwrap();
        assert_eq!(updated, 1, "the fixture message to exclude must exist");
    }

    /// PR6 T5 (spec §五 corpus_diff 行): the identity of an excluded message is
    /// `excluded.sha256` -- the sha of the body as it was BEFORE the ingest
    /// cleared it -- not the sha of the now-empty `content` column. Keyed on
    /// `content`, every legitimately excluded row reads as a lost message.
    #[test]
    fn excluded_row_is_not_counted_as_a_missing_message() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 2, 3);
        seed_db(&new, 2, 3);
        mark_message_excluded(&new, 1, 1);

        let (code, report, message) = run(&old, &new, None);
        assert_eq!(
            code, 0,
            "an excluded row carries its pre-clear sha in the marker; it must not read as a missing message: {message}"
        );
        let report = report.unwrap();
        assert_eq!(
            report.messages_missing, 0,
            "the excluded row's identity must come from excluded.sha256: {report:?}"
        );
        assert_eq!(
            report.excluded_transform_ok, 1,
            "the marker-carried identity must be counted for the manifest comparison: {report:?}"
        );
        assert_eq!(report.duplicates_fail_loud, 0);
    }

    /// Rewrite a freshly-built v6 database into the v4 shape the frozen
    /// `copy/` actually has: no `excluded` column at all, and therefore no
    /// expression index over it. `ALTER TABLE ... DROP COLUMN` refuses while an
    /// index references the column, so the index goes first.
    fn drop_excluded_column(path: &std::path::Path) {
        let writer = FrankenStorage::open_writer(path).unwrap();
        writer
            .raw()
            .execute_batch(
                "DROP INDEX IF EXISTS idx_messages_excluded_blob; \
                 ALTER TABLE messages DROP COLUMN excluded;",
            )
            .unwrap();
        drop(writer);
    }

    /// The old side of a T6 corpus diff is the PR4 reingest library, which
    /// predates schema v6 -- so `json(excluded)` there must never be issued.
    #[test]
    fn v4_old_corpus_without_the_excluded_column_is_read() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 2, 3);
        drop_excluded_column(&old);
        seed_db(&new, 2, 3);

        let (code, report, message) = run(&old, &new, None);
        assert_eq!(code, 0, "a v4 old side must not error out: {message}");
        let report = report.unwrap();
        assert_eq!(report.messages_missing, 0);
        assert_eq!(
            report.excluded_transform_ok, 0,
            "a v4 side has no markers to carry an identity across: {report:?}"
        );
    }

    /// Two rows sharing the provenance unique key are a broken corpus. The
    /// pre-fix map kept whichever row came last, so the other row's messages
    /// were never compared at all and a whole lost session could hide.
    #[test]
    fn duplicate_session_key_fails_loud_exit_2() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 2, 3);
        seed_db(&new, 2, 3);

        let writer = FrankenStorage::open_writer(&old).unwrap();
        writer
            .raw()
            .execute_batch("DROP INDEX IF EXISTS idx_conversations_identity;")
            .unwrap();
        writer
            .raw()
            .execute(
                "INSERT INTO conversations(id, agent_id, source_id, external_id, source_path) \
                 SELECT 999, agent_id, source_id, external_id, '/tmp/duplicate.jsonl' \
                 FROM conversations WHERE id = 1",
                &[],
            )
            .unwrap();
        drop(writer);

        let (code, report, message) = run(&old, &new, None);
        assert_eq!(
            code, 2,
            "a duplicate session key must fail loud rather than pick a winner: {message}"
        );
        let report = report.expect("the report carries which keys collided");
        assert_eq!(report.duplicates_fail_loud, 1, "{report:?}");
    }

    fn exempt_line(old_source_path: &str, new_source_path: &str) -> String {
        serde_json::json!({
            "source_id": LOCAL_SOURCE_ID,
            "agent_slug": "codex",
            "old_source_path": old_source_path,
            "new_source_path": new_source_path,
        })
        .to_string()
    }

    /// A NULL-`external_id` session is keyed by `source_path`, so a legitimate
    /// mirror-home rewrite reads as a lost session. An exemption line is the
    /// only thing allowed to re-point that lookup -- and when it does, the
    /// rewrite must not also be counted as a `source_path_changed`.
    #[test]
    fn exempt_null_rewrite_repoints_a_null_external_id_session() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_null_external_id_pair(&old);
        seed_null_external_id_pair(&new);

        let writer = FrankenStorage::open_writer(&new).unwrap();
        writer
            .raw()
            .execute(
                "UPDATE conversations SET source_path = '/tmp/mirror-home/local-a.jsonl' \
                 WHERE source_path LIKE '%local-a%'",
                &[],
            )
            .unwrap();
        drop(writer);

        let (code, report, message) = run(&old, &new, None);
        assert_eq!(code, 1, "the rewrite must be visible without an exemption: {message}");
        assert_eq!(report.unwrap().conversations_missing, 1);

        let exempt = dir.path().join("exempt.jsonl");
        std::fs::write(
            &exempt,
            format!(
                "{}\n",
                exempt_line("/tmp/local-a.jsonl", "/tmp/mirror-home/local-a.jsonl")
            ),
        )
        .unwrap();

        let (code, report, message) = run(&old, &new, Some(&exempt));
        assert_eq!(code, 0, "an exempted rewrite is not a loss: {message}");
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 0, "{report:?}");
        assert_eq!(
            report.source_path_changed, 0,
            "the exemption already accounts for the rewrite; it must not be counted again: {report:?}"
        );
    }

    #[test]
    fn identical_corpora_pass_with_zero_missing() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_db(&old, 5, 10);
        seed_db(&new, 5, 10);

        let (code, report, message) = run(&old, &new, None);
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

        let (code, report, message) = run(&old, &new, None);
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

        let (code, report, message) = run(&old, &new, None);
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

        let (code, report, message) = run(&old, &new, None);
        assert_eq!(code, 1, "a mutated message content must fail the gate (hash mismatch): {message}");
        let report = report.unwrap();
        assert_eq!(report.conversations_missing, 0);
        assert_eq!(report.messages_missing, 1);
    }

    /// R1-B4 (exec92): two sessions from *different* sources sharing the
    /// same `(agent_slug, external_id)` are a real, distinct-identity shape
    /// (the schema-6 unique key added `source_id`; schema 7's unique key is
    /// `(identity_host, agent_id, external_id)`) -- the old `(agent_slug, external_id)`-only key
    /// collapsed both into one `HashMap` entry, so deleting one of them
    /// from `--new` went entirely undetected (whichever side survived the
    /// collision "matched" the deleted one).
    fn seed_cross_source_pair(path: &std::path::Path) {
        let storage = FrankenStorage::open(path).unwrap();
        let agent = Agent { id: None, slug: "codex".into(), name: "Codex".into(), version: Some("0.1".into()), kind: AgentKind::Cli };
        let agent_id = storage.ensure_agent(&agent).unwrap();
        let make = |source_id: &str, path_suffix: &str| Conversation {
            id: None,
            agent_slug: "codex".into(),
            workspace: Some(PathBuf::from("/tmp/workspace")),
            external_id: Some("dup-ext-id".into()),
            title: Some("cross-source collision fixture".into()),
            source_path: PathBuf::from(format!("/tmp/{path_suffix}.jsonl")),
            started_at: Some(1_700_000_000_000),
            ended_at: Some(1_700_000_000_005),
            approx_tokens: Some(64),
            metadata_json: serde_json::Value::Null,
            messages: vec![Message {
                id: None,
                idx: 0,
                role: MessageRole::User,
                author: Some("user".into()),
                created_at: Some(1_700_000_000_000),
                content: format!("cross-source fixture message for {source_id}"),
                extra_json: serde_json::json!({}),
                snippets: Vec::new(),
                excluded: None,
            }],
            source_id: source_id.into(),
            origin_host: None,
        };
        let conversations = vec![make(LOCAL_SOURCE_ID, "local-session"), make("work-laptop", "work-laptop-session")];
        let batch: Vec<(i64, Option<i64>, &Conversation)> = conversations.iter().map(|c| (agent_id, None, c)).collect();
        storage.insert_conversations_batched(&batch).unwrap();
    }

    #[test]
    fn cross_source_same_agent_and_external_id_collision_is_detected_exit_1() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_cross_source_pair(&old);
        seed_cross_source_pair(&new);

        // Delete the "work-laptop" side entirely from the new corpus. Under
        // the old (agent_slug, external_id)-only key this pair had already
        // collapsed to a single `HashMap` entry, so this deletion produced
        // `conversations_missing=0` -- a real session loss that passed the
        // gate silently.
        let writer = FrankenStorage::open_writer(&new).unwrap();
        writer.raw().execute("DELETE FROM conversations WHERE source_id = 'work-laptop'", &[]).unwrap();
        drop(writer);

        let (code, report, message) = run(&old, &new, None);
        assert_eq!(code, 1, "a whole session lost behind a cross-source (agent, external_id) collision must fail the gate: {message}");
        let report = report.unwrap();
        assert_eq!(
            report.conversations_missing, 1,
            "the deleted work-laptop session must be counted, not masked by the surviving local session sharing the same (agent, external_id): {report:?}"
        );
    }

    /// R2-#3 (exec94): two sessions with no external id at all
    /// (`external_id: None`, a real shape -- e.g. a session materialized
    /// without one) sharing `(source_id, agent_slug)` but at different
    /// `source_path`s must not collapse into one `HashMap` entry. Rust's
    /// `HashMap` treats every `None` as equal, so before this fix both
    /// mapped to the same key regardless of `source_path`.
    fn seed_null_external_id_pair(path: &std::path::Path) {
        let storage = FrankenStorage::open(path).unwrap();
        let agent = Agent { id: None, slug: "codex".into(), name: "Codex".into(), version: Some("0.1".into()), kind: AgentKind::Cli };
        let agent_id = storage.ensure_agent(&agent).unwrap();
        let make = |path_suffix: &str| Conversation {
            id: None,
            agent_slug: "codex".into(),
            workspace: Some(PathBuf::from("/tmp/workspace")),
            external_id: None,
            title: Some("null-external-id fixture".into()),
            source_path: PathBuf::from(format!("/tmp/{path_suffix}.jsonl")),
            started_at: Some(1_700_000_000_000),
            ended_at: Some(1_700_000_000_005),
            approx_tokens: Some(64),
            metadata_json: serde_json::Value::Null,
            messages: vec![Message {
                id: None,
                idx: 0,
                role: MessageRole::User,
                author: Some("user".into()),
                created_at: Some(1_700_000_000_000),
                content: format!("null-external-id fixture message for {path_suffix}"),
                extra_json: serde_json::json!({}),
                snippets: Vec::new(),
                excluded: None,
            }],
            source_id: LOCAL_SOURCE_ID.into(),
            origin_host: None,
        };
        let conversations = vec![make("local-a"), make("local-b")];
        let batch: Vec<(i64, Option<i64>, &Conversation)> = conversations.iter().map(|c| (agent_id, None, c)).collect();
        storage.insert_conversations_batched(&batch).unwrap();
    }

    #[test]
    fn null_external_id_sessions_with_different_source_paths_are_distinct() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.db");
        let new = dir.path().join("new.db");
        seed_null_external_id_pair(&old);
        seed_null_external_id_pair(&new);

        // Delete "local-b" entirely from the new corpus. Under the old
        // (source_id, agent_slug, external_id)-only key, both null-
        // external-id sessions collapsed to a single `HashMap` entry (same
        // source_id, same agent_slug, both external_id=None), so this
        // deletion produced `conversations_missing=0`.
        let writer = FrankenStorage::open_writer(&new).unwrap();
        writer.raw().execute("DELETE FROM conversations WHERE source_path LIKE '%local-b%'", &[]).unwrap();
        drop(writer);

        let (code, report, message) = run(&old, &new, None);
        assert_eq!(code, 1, "a whole null-external-id session lost behind a source_path collision must fail the gate: {message}");
        let report = report.unwrap();
        assert_eq!(
            report.conversations_missing, 1,
            "the deleted local-b session must be counted, not masked by the surviving local-a session sharing (source_id, agent_slug, None): {report:?}"
        );
        assert_eq!(report.old_conversations_total, 2, "both null-external-id sessions must be distinct map entries on the old side: {report:?}");
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

        let (code, report, message) = run(&old, &new, None);
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
                    excluded: None,
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

        let (code, report, message) = run(&old, &new, None);
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

        let (code, report, message) = run(&old, &new, None);
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

        let (code, report, message) = run(&old, &new, None);
        assert_eq!(code, 2, "missing --old db must be a precondition error: {message}");
        assert!(report.is_none());
    }
}
