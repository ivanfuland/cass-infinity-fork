//! T10 (plan v5.1): `w4_content_copy` -- copy only the *content layer*
//! (`conversations`, `messages`, and their `PRAGMA foreign_key_list`
//! ancestor tables) from a v4-or-v5 source database into a freshly built v5
//! target database. Derived tables (`lex_docs`/`fts_lex`/`message_chunks`/
//! `chunk_holes`/`chunk_staging`/`embedding_generations`/vec0 tables) are
//! never touched -- the target
//! is meant to be re-indexed from scratch by the caller (T10's
//! `w4_corpus_diff` compares a `--from` copy like this one against a
//! freshly-reingested new v5 db to prove no content was lost across a
//! reingest).
//!
//! Parent-table discovery is real `PRAGMA foreign_key_list` introspection
//! against the target's own (freshly `schema::ensure`d) schema, not a
//! hardcoded table list -- BFS from `["conversations", "messages"]` outward
//! along FK edges, then a topological sort (parents before children) so the
//! copy can run under normal FK enforcement (no `defer_foreign_keys`
//! needed). Row identity (every column, including primary keys) is
//! preserved verbatim: this is a byte-faithful content snapshot, not a
//! re-import.
//!
//! Column lists are the intersection of `PRAGMA table_info` on the target
//! (authoritative current-schema columns) and `PRAGMA <src>.table_info` on
//! the attached source, so a source db with a strict subset of columns (an
//! older v4 db, or a table missing a newer column) doesn't error the copy --
//! target-only columns get their schema default, source-only extra columns
//! are simply not read.
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w4_content_copy -- --from <path> --to
//! <path>`. Exit codes: 0 copy succeeded and source/target `messages` row
//! counts match; 1 copy completed but a row-count mismatch was detected
//! (should be structurally impossible -- a real defect if seen); 2
//! precondition error (source db missing, or target's parent directory does
//! not exist).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use coding_agent_search::storage::api::Value;
use coding_agent_search::storage::sqlite::FrankenStorage;

#[derive(Parser, Debug)]
#[command(name = "w4_content_copy")]
struct Cli {
    #[arg(long)]
    from: PathBuf,
    #[arg(long)]
    to: PathBuf,
}

/// One row per content-layer table's copy outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TableCopyReport {
    table: String,
    rows_copied: i64,
}

#[derive(Debug, Clone)]
struct ContentCopyReport {
    tables: Vec<TableCopyReport>,
    src_messages: i64,
    dst_messages: i64,
}

impl ContentCopyReport {
    fn messages_match(&self) -> bool {
        self.src_messages == self.dst_messages
    }
}

/// BFS the FK graph of `roots` on `conn` (expected to be the freshly-built
/// target's `main` schema) outward to every ancestor table, via real
/// `PRAGMA foreign_key_list` introspection. Returns the discovered table
/// set in an order where every table's FK parents already precede it
/// (topological, parents first) -- required so the copy can run under live
/// FK enforcement.
fn discover_content_tables_topo(
    storage: &FrankenStorage,
    roots: &[&str],
) -> Result<Vec<String>> {
    let mut edges: HashMap<String, HashSet<String>> = HashMap::new(); // child -> parents
    let mut frontier: Vec<String> = roots.iter().map(|s| s.to_string()).collect();
    let mut seen: HashSet<String> = frontier.iter().cloned().collect();

    while let Some(table) = frontier.pop() {
        let parents: Vec<String> = storage.raw().query_all_map(
            &format!("PRAGMA foreign_key_list({table})"),
            &[],
            |row| row.get_typed::<String>(2), // column index 2 = referenced table
        )?;
        let parent_set: HashSet<String> = parents.into_iter().collect();
        for parent in &parent_set {
            if seen.insert(parent.clone()) {
                frontier.push(parent.clone());
            }
        }
        edges.entry(table).or_default().extend(parent_set);
    }

    // Kahn-style topo sort: repeatedly emit any not-yet-emitted table whose
    // parents (restricted to the discovered set) are all already emitted.
    let mut remaining: HashSet<String> = seen.clone();
    let mut ordered: Vec<String> = Vec::with_capacity(seen.len());
    let mut emitted: HashSet<String> = HashSet::new();
    while !remaining.is_empty() {
        let ready: Vec<String> = remaining
            .iter()
            .filter(|t| {
                edges
                    .get(*t)
                    .map(|parents| parents.iter().all(|p| !seen.contains(p) || emitted.contains(p)))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        anyhow::ensure!(
            !ready.is_empty(),
            "content-table FK graph has a cycle or unresolved dependency among {:?}",
            remaining
        );
        let mut ready_sorted = ready;
        ready_sorted.sort();
        for t in ready_sorted {
            remaining.remove(&t);
            emitted.insert(t.clone());
            ordered.push(t);
        }
    }
    Ok(ordered)
}

fn table_columns(storage: &FrankenStorage, schema: &str, table: &str) -> Result<Vec<String>> {
    let sql = if schema.is_empty() {
        format!("PRAGMA table_info({table})")
    } else {
        format!("PRAGMA {schema}.table_info({table})")
    };
    let cols: Vec<String> = storage.raw().query_all_map(&sql, &[], |row| row.get_typed::<String>(1))?;
    anyhow::ensure!(!cols.is_empty(), "table {table:?} has no columns in schema {schema:?} (does it exist?)");
    Ok(cols)
}

fn copy_content_layer(from: &Path, to: &Path) -> Result<ContentCopyReport> {
    anyhow::ensure!(from.is_file(), "source db {} does not exist or is not a file", from.display());
    let parent_missing = match to.parent() {
        Some(p) if !p.as_os_str().is_empty() => !p.exists(),
        _ => false,
    };
    anyhow::ensure!(!parent_missing, "target's parent directory does not exist: {}", to.display());

    let storage = FrankenStorage::open_writer(to).with_context(|| format!("opening/ensuring fresh v5 target at {}", to.display()))?;

    // R1-B5 (exec92): the whole design ("copy only, never merge content
    // into an existing db") assumes `to` is a freshly-built, empty v5
    // target -- `open_writer` above happily opens an *existing* db with
    // real content too. Without this check, copying into an already-
    // populated target let every conflicting row through the `OR IGNORE`
    // below (see next comment) silently keep its stale pre-existing
    // content while still reporting a matching row count and exit 0.
    let existing_conversations: i64 =
        storage.raw().query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| row.get_typed(0))?;
    let existing_messages: i64 =
        storage.raw().query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))?;
    anyhow::ensure!(
        existing_conversations == 0 && existing_messages == 0,
        "target {} is not empty ({existing_conversations} conversation(s), {existing_messages} message(s)) -- \
         w4_content_copy only supports copying into a freshly-built, empty v5 target, never merging into or \
         overwriting an existing one",
        to.display()
    );

    let from_uri = format!("file:{}?mode=ro", from.display());
    storage
        .raw()
        .execute("ATTACH DATABASE ?1 AS src", &[Value::from(from_uri)])
        .context("ATTACH source database read-only as 'src'")?;

    // R2-#10 (exec94): every table copy below used to run as an
    // independent autocommit statement -- a failure partway through (e.g.
    // disk full on a later table) left the target with some tables
    // populated and others not, and a retry couldn't tell "empty target,
    // start fresh" from "half-copied target, resume" (the empty-target
    // check above rejects both the same way). Wrapping the whole copy loop
    // plus its verification reads in one transaction makes a failure
    // atomic: `ROLLBACK` puts the target back to the empty state the
    // caller can retry from. ATTACH stays outside the transaction (SQLite
    // allows ATTACH inside `BEGIN IMMEDIATE`, but DETACH of a database
    // used within the transaction fails with "database src is locked"
    // until that transaction has committed or rolled back), so DETACH
    // below always runs after the COMMIT/ROLLBACK decision, not before.
    storage.raw().execute("BEGIN IMMEDIATE;", &[]).context("BEGIN IMMEDIATE for content copy")?;
    let copy_result: Result<ContentCopyReport> = (|| {
        let order = discover_content_tables_topo(&storage, &["conversations", "messages"])?;

        let mut tables_report = Vec::with_capacity(order.len());
        for table in &order {
            let target_cols: HashSet<String> = table_columns(&storage, "", table)?.into_iter().collect();
            let src_cols: HashSet<String> = table_columns(&storage, "src", table)?.into_iter().collect();
            let mut shared: Vec<String> = target_cols.intersection(&src_cols).cloned().collect();
            shared.sort();
            anyhow::ensure!(!shared.is_empty(), "table {table:?} has zero shared columns between src and target");
            let col_list = shared.join(", ");
            // R1-B5 (exec92): the `sources` copy must stay scoped
            // separately from every other table -- a fresh v5 target built
            // by `schema::ensure` already seeds that table's well-known
            // `local` row, and the source db (built the same way) carries
            // a real `sources['local']` row of its own (potentially with
            // `machine_id`/`platform`/`config_json` populated) that would
            // otherwise collide on `INSERT` with a `UNIQUE`/primary-key
            // violation before any real content copies.
            //
            // R2-#4 (exec94): `OR IGNORE` (the pre-fix behavior) kept the
            // target's empty seed row and silently discarded the source's
            // real one on that PK collision -- this "copy" is meant to be
            // a byte-faithful content snapshot, so the source's row must
            // win. `OR REPLACE` on `sources` only (every other table stays
            // a plain `INSERT`, which still fails loudly on any other
            // future PK collision, same as before).
            let ignore_clause = if table == "sources" { " OR REPLACE" } else { "" };
            let sql = format!("INSERT{ignore_clause} INTO main.{table} ({col_list}) SELECT {col_list} FROM src.{table}");
            let rows_copied = storage.raw().execute(&sql, &[]).with_context(|| format!("copying content-layer table {table:?}"))?;
            tables_report.push(TableCopyReport { table: table.clone(), rows_copied: rows_copied as i64 });
        }

        let src_messages: i64 =
            storage.raw().query_row_map("SELECT COUNT(*) FROM src.messages", &[], |row| row.get_typed(0))?;
        let dst_messages: i64 =
            storage.raw().query_row_map("SELECT COUNT(*) FROM main.messages", &[], |row| row.get_typed(0))?;

        storage.raw().execute("COMMIT;", &[]).context("COMMIT content copy")?;
        Ok(ContentCopyReport { tables: tables_report, src_messages, dst_messages })
    })();
    if copy_result.is_err() {
        let _ = storage.raw().execute("ROLLBACK;", &[]);
    }
    storage.raw().execute_batch("DETACH DATABASE src").context("DETACH src")?;

    copy_result
}

/// Runs the copy and returns the process exit code (0/1/2) plus the report
/// text printed to stdout on success. Precondition failures (`--from`
/// missing, `--to`'s parent directory missing) surface as `Err` from
/// [`copy_content_layer`] itself (which does not distinguish "which kind of
/// precondition" in its `Result`) -- this wrapper is the single place that
/// decides 1 vs 2, by checking the two exit-2 preconditions itself *before*
/// delegating to `copy_content_layer` for the actual copy + row-count
/// verdict (exit 0 vs 1).
fn run(from: &Path, to: &Path) -> (i32, String) {
    if !from.is_file() {
        return (2, format!("precondition error: source db {} does not exist or is not a file", from.display()));
    }
    let parent_missing = match to.parent() {
        Some(p) if !p.as_os_str().is_empty() => !p.exists(),
        _ => false,
    };
    if parent_missing {
        return (2, format!("precondition error: target's parent directory does not exist: {}", to.display()));
    }

    match copy_content_layer(from, to) {
        Err(e) => (2, format!("precondition/setup error: {e:#}")),
        Ok(report) => {
            let mut lines = Vec::new();
            for t in &report.tables {
                lines.push(format!("{}={}", t.table, t.rows_copied));
            }
            let summary = format!(
                "content_copy: {} src_messages={} dst_messages={} match={}",
                lines.join(" "),
                report.src_messages,
                report.dst_messages,
                report.messages_match()
            );
            if report.messages_match() { (0, summary) } else { (1, summary) }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let (code, message) = run(&cli.from, &cli.to);
    println!("{message}");
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
    use coding_agent_search::sources::provenance::LOCAL_SOURCE_ID;
    use tempfile::TempDir;

    fn seed_source_db(dir: &Path, n_conversations: usize, n_messages_each: usize) -> PathBuf {
        let db_path = dir.join("source.db");
        let storage = FrankenStorage::open(&db_path).unwrap();
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
                    content: format!("content-copy fixture message {c}-{i} with enough text to be non-trivial."),
                    extra_json: serde_json::json!({}),
                    snippets: Vec::new(),
                });
            }
            conversations.push(Conversation {
                id: None,
                agent_slug: "codex".into(),
                workspace: Some(PathBuf::from("/tmp/workspace")),
                external_id: Some(format!("content-copy-fixture-{c}")),
                title: Some("Content copy fixture".into()),
                source_path: PathBuf::from(format!("/tmp/content-copy-fixture-{c}.jsonl")),
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
        db_path
    }

    #[test]
    fn round_trip_counts_equal() {
        let dir = TempDir::new().unwrap();
        let from = seed_source_db(dir.path(), 5, 20);
        let to = dir.path().join("target").join("fresh.db");
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();

        let (code, message) = run(&from, &to);
        assert_eq!(code, 0, "round-trip copy must succeed: {message}");
        assert!(message.contains("match=true"), "report must show matching message counts: {message}");

        let target = FrankenStorage::open_readonly(&to).unwrap();
        let dst_messages: i64 = target.raw().query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0)).unwrap();
        assert_eq!(dst_messages, 100, "5 conversations * 20 messages = 100");
        let dst_conversations: i64 =
            target.raw().query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| row.get_typed(0)).unwrap();
        assert_eq!(dst_conversations, 5);
    }

    /// R2-#4 (exec94): the source db's real `sources['local']` row (with
    /// `machine_id` populated) must win over the fresh target's empty seed
    /// row -- pre-fix `INSERT OR IGNORE` kept the target's empty seed row
    /// on the primary-key collision and silently discarded the source's
    /// real metadata.
    #[test]
    fn sources_row_is_replaced_not_ignored_on_copy() {
        let dir = TempDir::new().unwrap();
        let from = seed_source_db(dir.path(), 1, 1);

        let writer = FrankenStorage::open_writer(&from).unwrap();
        writer
            .upsert_source(&coding_agent_search::sources::provenance::Source {
                machine_id: Some("m1".into()),
                ..coding_agent_search::sources::provenance::Source::local()
            })
            .unwrap();
        drop(writer);

        let to = dir.path().join("target").join("fresh.db");
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        let (code, message) = run(&from, &to);
        assert_eq!(code, 0, "copy must still succeed: {message}");

        let target = FrankenStorage::open_readonly(&to).unwrap();
        let machine_id: Option<String> = target
            .raw()
            .query_row_map("SELECT machine_id FROM sources WHERE id = ?1", &[Value::from(LOCAL_SOURCE_ID)], |row| {
                row.get_typed(0)
            })
            .unwrap();
        assert_eq!(
            machine_id.as_deref(),
            Some("m1"),
            "source's real sources.local row must win over the target's empty seed row"
        );
    }

    /// R2-#10 (exec94): a failure partway through the copy loop (here,
    /// `messages` -- a child table in FK order, so `conversations` and its
    /// other ancestors have already been INSERTed by the time this fails --
    /// is missing from the source) must not leave the target half-
    /// populated. The whole copy runs in one transaction now, so the
    /// already-copied `conversations` rows must roll back too.
    #[test]
    fn partial_copy_failure_rolls_back_already_copied_tables() {
        let dir = TempDir::new().unwrap();
        let from = seed_source_db(dir.path(), 3, 5);

        let writer = FrankenStorage::open_writer(&from).unwrap();
        writer.raw().execute_batch("DROP TABLE messages;").unwrap();
        drop(writer);

        let to = dir.path().join("target").join("fresh.db");
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();

        let (code, message) = run(&from, &to);
        assert_eq!(code, 2, "a mid-copy failure must be a precondition error, not report success: {message}");

        let target = FrankenStorage::open_readonly(&to).unwrap();
        let dst_conversations: i64 =
            target.raw().query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| row.get_typed(0)).unwrap();
        assert_eq!(
            dst_conversations, 0,
            "a failed copy must roll back already-copied tables, not leave a half-populated target: got {dst_conversations}"
        );
    }

    #[test]
    fn missing_parent_directory_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let from = seed_source_db(dir.path(), 1, 3);
        let to = dir.path().join("does-not-exist-parent").join("nested").join("fresh.db");

        let (code, message) = run(&from, &to);
        assert_eq!(code, 2, "missing parent directory must be a precondition error (exit 2): {message}");
    }

    #[test]
    fn missing_source_db_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let from = dir.path().join("does-not-exist.db");
        let to = dir.path().join("fresh.db");

        let (code, message) = run(&from, &to);
        assert_eq!(code, 2, "missing source db must be a precondition error (exit 2): {message}");
    }

    /// R1-B5 (exec92): copying into the *same* target a second time must
    /// refuse (not silently keep the target's already-copied content while
    /// still reporting `match=true`/exit 0) -- pre-fix, `INSERT OR IGNORE`
    /// on every table let every conflicting row from the second copy be
    /// silently dropped, so a source mutated between the two copies (same
    /// message ids, edited content) would report success while the
    /// target's stale pre-existing rows never got updated.
    #[test]
    fn copying_into_an_already_populated_target_is_refused_exit_2() {
        let dir = TempDir::new().unwrap();
        let from = seed_source_db(dir.path(), 3, 5);
        let to = dir.path().join("target").join("fresh.db");
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();

        let (first_code, first_message) = run(&from, &to);
        assert_eq!(first_code, 0, "the first copy into a fresh target must succeed: {first_message}");

        let (second_code, second_message) = run(&from, &to);
        assert_eq!(second_code, 2, "a second copy into the now-populated target must be refused as a precondition error: {second_message}");
        assert!(
            second_message.contains("not empty"),
            "the refusal must name the target as non-empty, not report a false match: {second_message}"
        );
    }
}
