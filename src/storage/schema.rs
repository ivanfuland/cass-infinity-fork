//! New-database schema and idempotent, version-gated migration for the
//! rusqlite storage engine (w1b Task B7, plan 次级契约⑥).
//!
//! `PRAGMA user_version` is the sole version authority for databases built
//! through [`ensure`] — this is a *separate* mechanism from the pre-existing
//! `meta.schema_version` / `_schema_migrations` bookkeeping in
//! `storage::sqlite` (the legacy-engine-era migration engine, retired
//! together with the franken backend at Task B8). See
//! `w1b-b7-step0-version-mechanism-audit.md` (control-plane artifacts) for
//! the full audit of that older mechanism and why the two are not merged
//! here: the old engine does real incremental DDL migration across ~20
//! historical schema revisions with franken-specific workarounds (e.g.
//! avoiding `DROP TABLE`, which triggers a known the legacy embedded engine autoindex
//! limitation); this module only ever builds today's final table shape in
//! one shot and gates on a version number for the (currently nonexistent)
//! future migrations above it.
//!
//! [`FRESH_SCHEMA_DDL`] is a byte-for-byte capture of the table/index set an
//! empty database ends up with after the old engine runs its full v13..v21
//! migration chain (dumped via `sqlite3 <fresh db> .schema` — see the B7
//! Step 1 report for the exact recipe), plus the two data-seeding
//! `INSERT`s the old fresh-build path also runs (the `.schema` dump only
//! shows DDL, not rows, so these had to be found separately and copied
//! verbatim from `storage::sqlite::MIGRATION_FRESH_SCHEMA`'s own text: the
//! bootstrap `sources` row with id `'local'`, and the default
//! `model_pricing` rate table). Every other `INSERT` in the old engine's
//! post-v13 migrations (`conversation_tail_state`,
//! `conversation_external_lookup`, `conversation_external_tail_lookup`) is
//! a `SELECT ... FROM conversations` backfill of pre-existing data, which
//! is a no-op against an empty database and needs no equivalent here.
//! Minus the objects SQLite manages automatically as a side effect of
//! other statements in the same script:
//! `sqlite_sequence` (auto-created by the first `AUTOINCREMENT` column) and
//! the four `fts_messages_*` FTS5 shadow tables (auto-created by the
//! `CREATE VIRTUAL TABLE ... USING fts5(...)` statement) — `fts_lex` (w2
//! Task W2-2, external-content mode) auto-creates the same four-shadow
//! shape (`fts_lex_config`/`_data`/`_docsize`/`_idx`; no `_content` shadow,
//! since external-content mode defers hydration to `lex_docs` rather than
//! keeping its own copy — see OQ2 measurement, control plane 2026-08-29).
//! Explicitly re-creating those manually one at a time is invalid on real
//! SQLite (`sqlite_sequence` name is reserved) and pointless for the FTS5
//! shadows;
//! this is also the mechanism behind the plan's "standard SQLite rebuild
//! naturally has no `fts_messages_config` autoindex birth-scar" note — that
//! scar is a legacy embedded engine quirk from an older incremental path, not
//! something this fresh, single-shot DDL can reproduce even if it wanted to.
//!
//! `meta` and `_schema_migrations` are kept as empty tables in the DDL
//! (table-set parity with the current schema, per plan's "现有表集合语义不变") —
//! `ensure` itself does not populate them. Whether/how the Stage B wiring
//! that calls `ensure` from `SqliteStorage`'s build path (Task B7 Step 2)
//! needs to keep those legacy fields in sync for other code that still
//! reads them is that wiring step's decision, not this module's.

use super::api::{Conn, StorageError, TxMode};

/// The schema version [`ensure`] currently knows how to produce. There is
/// no migration path defined above this yet — bump this and add a real
/// upgrade step in [`ensure`] (not just widen the accepted range) the day a
/// second version is needed.
///
/// Version 2 (w2 Task W2-2) adds the `lex_docs`/`fts_lex` domain below.
/// `ensure`'s `version == 1` branch (w2 Task W2-3 Step 4) migrates a
/// pre-existing version-1 database in place by adding just those two
/// tables and bumping `user_version` -- it does not backfill historical
/// message content into them (that is the `--full` rebuild's job, a
/// separate future task).
///
/// Version 3 (W2-6 Task戊) drops the legacy `fts_messages` FTS5 shadow: the
/// production write/consistency/rebuild machinery that kept it in sync was
/// retired earlier in W2-6, and search runs entirely on the `fts_lex`/
/// `lex_docs` domain added at version 2. `ensure`'s `version < 3` migration
/// step (see below) DROPs the table (`DROP TABLE` also removes its FTS5
/// shadow tables -- `_data`/`_idx`/`_docsize`/`_config`, all four of them,
/// verified empirically since this table is contentless (`content=''`) and
/// therefore never had a `_content` shadow to begin with).
pub const CURRENT_SCHEMA_VERSION: i64 = 3;

/// The `lex_docs`/`fts_lex` domain DDL (w2 Task W2-2, OQ2: external-content
/// mode) — **must stay byte-for-byte identical** to the matching two lines
/// at the tail of [`FRESH_SCHEMA_DDL`] below. Duplicated (not extracted into
/// one shared constant `FRESH_SCHEMA_DDL` could reference) because
/// `FRESH_SCHEMA_DDL` is a `const &str` raw-string literal and Rust's
/// `concat!` only accepts literal tokens, not paths to other `const`s; a
/// `fn` returning an owned `String` would ripple into every existing
/// `&str`-typed call site (`execute_batch`, the DDL-statement-count test).
/// Used by the version 1 → 2 upgrade path in [`ensure`] to backfill the new
/// tables into a pre-existing version-1 database (w2 Task W2-3 Step 4,
/// R1-X-N1: a wave-1 database must not be left behind by wave 2).
const V2_LEX_DOMAIN_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS lex_docs (doc_id INTEGER PRIMARY KEY REFERENCES messages (id) ON DELETE CASCADE, content TEXT NOT NULL, title TEXT NOT NULL, agent TEXT NOT NULL, workspace TEXT NOT NULL, source_path TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS fts_lex USING fts5(content, title, agent, workspace, source_path, content = 'lex_docs', content_rowid = 'doc_id', tokenize = 'porter trigram');
"#;

/// W2-6 Task1 (X-5 fix): unconditionally drop and recreate the
/// `lex_docs`/`fts_lex` domain. Derived data's repair story is "rebuild from
/// the source of truth", not "patch in place" (rebuild-not-convert
/// doctrine) -- safe to call regardless of whether the domain is missing,
/// empty, or internally corrupted, because `DROP TABLE IF EXISTS` tolerates
/// all three and the `CREATE` statements are the exact ones schema
/// migration itself uses ([`V2_LEX_DOMAIN_DDL`]). `fts_lex` is dropped
/// before `lex_docs` (its external-content table) though nothing currently
/// enforces that order at the SQL level.
///
/// Only rebuilds the empty shape -- callers must repopulate afterward via
/// [`crate::storage::sqlite::FrankenStorage::rebuild_lex_domain_from_db`].
pub(crate) fn recreate_lex_domain_tables(conn: &Conn) -> Result<(), StorageError> {
    conn.execute_batch("DROP TABLE IF EXISTS fts_lex; DROP TABLE IF EXISTS lex_docs;")?;
    conn.execute_batch(V2_LEX_DOMAIN_DDL)?;
    Ok(())
}

/// Full DDL for a version-2 database, applied verbatim inside a single
/// transaction. See the module doc comment for provenance and the two
/// auto-managed exclusions (`sqlite_sequence`, `fts_messages_*` shadows).
/// Its final two lines (the `lex_docs`/`fts_lex` domain) must stay
/// byte-for-byte identical to [`V2_LEX_DOMAIN_DDL`] above — a unit test
/// (`fresh_schema_ddl_tail_matches_v2_lex_domain_migration_ddl`) enforces
/// this so the two copies cannot silently drift apart.
const FRESH_SCHEMA_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS _schema_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')));
CREATE TABLE IF NOT EXISTS meta ("key" TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agents (id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, version TEXT, kind TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS workspaces (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, display_name TEXT);
CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, kind TEXT NOT NULL, host_label TEXT, machine_id TEXT, platform TEXT, config_json TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
INSERT OR IGNORE INTO sources (id, kind, host_label, created_at, updated_at) VALUES ('local', 'local', NULL, strftime('%s','now')*1000, strftime('%s','now')*1000);
CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL REFERENCES agents (id), workspace_id INTEGER REFERENCES workspaces (id), source_id TEXT NOT NULL DEFAULT 'local' REFERENCES sources (id), external_id TEXT, title TEXT, source_path TEXT NOT NULL, started_at INTEGER, ended_at INTEGER, approx_tokens INTEGER, metadata_json TEXT, origin_host TEXT, metadata_bin BLOB, total_input_tokens INTEGER, total_output_tokens INTEGER, total_cache_read_tokens INTEGER, total_cache_creation_tokens INTEGER, grand_total_tokens INTEGER, estimated_cost_usd REAL, primary_model TEXT, api_call_count INTEGER, tool_call_count INTEGER, user_message_count INTEGER, assistant_message_count INTEGER, last_message_idx INTEGER, last_message_created_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_provenance ON conversations(source_id, agent_id, external_id);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES conversations (id) ON DELETE CASCADE, idx INTEGER NOT NULL, role TEXT NOT NULL, author TEXT, created_at INTEGER, content TEXT NOT NULL, extra_json TEXT, extra_bin BLOB, UNIQUE (conversation_id, idx));
CREATE TABLE IF NOT EXISTS snippets (id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE, file_path TEXT, start_line INTEGER, end_line INTEGER, language TEXT, snippet_text TEXT);
CREATE TABLE IF NOT EXISTS tags (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS conversation_tags (conversation_id INTEGER NOT NULL REFERENCES conversations (id) ON DELETE CASCADE, tag_id INTEGER NOT NULL REFERENCES tags (id) ON DELETE CASCADE, PRIMARY KEY (conversation_id, tag_id));
CREATE TABLE IF NOT EXISTS daily_stats (day_id INTEGER NOT NULL, agent_slug TEXT NOT NULL, source_id TEXT NOT NULL DEFAULT 'all', session_count INTEGER NOT NULL DEFAULT 0, message_count INTEGER NOT NULL DEFAULT 0, total_chars INTEGER NOT NULL DEFAULT 0, last_updated INTEGER NOT NULL, PRIMARY KEY (day_id, agent_slug, source_id));
CREATE TABLE IF NOT EXISTS embedding_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, db_path TEXT NOT NULL, model_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', total_docs INTEGER NOT NULL DEFAULT 0, completed_docs INTEGER NOT NULL DEFAULT 0, error_message TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), started_at TEXT, completed_at TEXT);
CREATE UNIQUE INDEX IF NOT EXISTS idx_embedding_jobs_active ON embedding_jobs(db_path, model_id) WHERE status IN ('pending', 'running');
CREATE TABLE IF NOT EXISTS token_usage (id INTEGER PRIMARY KEY AUTOINCREMENT, message_id INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE, conversation_id INTEGER NOT NULL, agent_id INTEGER NOT NULL, workspace_id INTEGER, source_id TEXT NOT NULL DEFAULT 'local', timestamp_ms INTEGER NOT NULL, day_id INTEGER NOT NULL, model_name TEXT, model_family TEXT, model_tier TEXT, service_tier TEXT, provider TEXT, input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER, cache_creation_tokens INTEGER, thinking_tokens INTEGER, total_tokens INTEGER, estimated_cost_usd REAL, role TEXT NOT NULL, content_chars INTEGER NOT NULL, has_tool_calls INTEGER NOT NULL DEFAULT 0, tool_call_count INTEGER NOT NULL DEFAULT 0, data_source TEXT NOT NULL DEFAULT 'api', UNIQUE (message_id));
CREATE TABLE IF NOT EXISTS token_daily_stats (day_id INTEGER NOT NULL, agent_slug TEXT NOT NULL, source_id TEXT NOT NULL DEFAULT 'all', model_family TEXT NOT NULL DEFAULT 'all', api_call_count INTEGER NOT NULL DEFAULT 0, user_message_count INTEGER NOT NULL DEFAULT 0, assistant_message_count INTEGER NOT NULL DEFAULT 0, tool_message_count INTEGER NOT NULL DEFAULT 0, total_input_tokens INTEGER NOT NULL DEFAULT 0, total_output_tokens INTEGER NOT NULL DEFAULT 0, total_cache_read_tokens INTEGER NOT NULL DEFAULT 0, total_cache_creation_tokens INTEGER NOT NULL DEFAULT 0, total_thinking_tokens INTEGER NOT NULL DEFAULT 0, grand_total_tokens INTEGER NOT NULL DEFAULT 0, total_content_chars INTEGER NOT NULL DEFAULT 0, total_tool_calls INTEGER NOT NULL DEFAULT 0, estimated_cost_usd REAL NOT NULL DEFAULT 0.0, session_count INTEGER NOT NULL DEFAULT 0, last_updated INTEGER NOT NULL, PRIMARY KEY (day_id, agent_slug, source_id, model_family));
CREATE TABLE IF NOT EXISTS model_pricing (model_pattern TEXT NOT NULL, provider TEXT NOT NULL, input_cost_per_mtok REAL NOT NULL, output_cost_per_mtok REAL NOT NULL, cache_read_cost_per_mtok REAL, cache_creation_cost_per_mtok REAL, effective_date TEXT NOT NULL, PRIMARY KEY (model_pattern, effective_date));
INSERT OR IGNORE INTO model_pricing VALUES
    ('claude-opus-4%', 'anthropic', 15.0, 75.0, 1.5, 18.75, '2025-10-01'),
    ('claude-sonnet-4%', 'anthropic', 3.0, 15.0, 0.3, 3.75, '2025-10-01'),
    ('claude-haiku-4%', 'anthropic', 0.80, 4.0, 0.08, 1.0, '2025-10-01'),
    ('gpt-4o%', 'openai', 2.50, 10.0, NULL, NULL, '2025-01-01'),
    ('gpt-4-turbo%', 'openai', 10.0, 30.0, NULL, NULL, '2024-04-01'),
    ('gpt-4.1%', 'openai', 2.0, 8.0, NULL, NULL, '2025-04-01'),
    ('o3%', 'openai', 2.0, 8.0, NULL, NULL, '2025-04-01'),
    ('o4-mini%', 'openai', 1.10, 4.40, NULL, NULL, '2025-04-01'),
    ('gemini-2%flash%', 'google', 0.075, 0.30, NULL, NULL, '2025-01-01'),
    ('gemini-2%pro%', 'google', 1.25, 10.0, NULL, NULL, '2025-01-01');
CREATE TABLE IF NOT EXISTS message_metrics (message_id INTEGER PRIMARY KEY REFERENCES messages (id) ON DELETE CASCADE, created_at_ms INTEGER NOT NULL, hour_id INTEGER NOT NULL, day_id INTEGER NOT NULL, agent_slug TEXT NOT NULL, workspace_id INTEGER NOT NULL DEFAULT 0, source_id TEXT NOT NULL DEFAULT 'local', role TEXT NOT NULL, content_chars INTEGER NOT NULL, content_tokens_est INTEGER NOT NULL, api_input_tokens INTEGER, api_output_tokens INTEGER, api_cache_read_tokens INTEGER, api_cache_creation_tokens INTEGER, api_thinking_tokens INTEGER, api_service_tier TEXT, api_data_source TEXT NOT NULL DEFAULT 'estimated', tool_call_count INTEGER NOT NULL DEFAULT 0, has_tool_calls INTEGER NOT NULL DEFAULT 0, has_plan INTEGER NOT NULL DEFAULT 0, model_name TEXT, model_family TEXT NOT NULL DEFAULT 'unknown', model_tier TEXT NOT NULL DEFAULT 'unknown', provider TEXT NOT NULL DEFAULT 'unknown');
CREATE TABLE IF NOT EXISTS usage_hourly (hour_id INTEGER NOT NULL, agent_slug TEXT NOT NULL, workspace_id INTEGER NOT NULL DEFAULT 0, source_id TEXT NOT NULL DEFAULT 'local', message_count INTEGER NOT NULL DEFAULT 0, user_message_count INTEGER NOT NULL DEFAULT 0, assistant_message_count INTEGER NOT NULL DEFAULT 0, tool_call_count INTEGER NOT NULL DEFAULT 0, plan_message_count INTEGER NOT NULL DEFAULT 0, api_coverage_message_count INTEGER NOT NULL DEFAULT 0, content_tokens_est_total INTEGER NOT NULL DEFAULT 0, content_tokens_est_user INTEGER NOT NULL DEFAULT 0, content_tokens_est_assistant INTEGER NOT NULL DEFAULT 0, api_tokens_total INTEGER NOT NULL DEFAULT 0, api_input_tokens_total INTEGER NOT NULL DEFAULT 0, api_output_tokens_total INTEGER NOT NULL DEFAULT 0, api_cache_read_tokens_total INTEGER NOT NULL DEFAULT 0, api_cache_creation_tokens_total INTEGER NOT NULL DEFAULT 0, api_thinking_tokens_total INTEGER NOT NULL DEFAULT 0, last_updated INTEGER NOT NULL DEFAULT 0, plan_content_tokens_est_total INTEGER NOT NULL DEFAULT 0, plan_api_tokens_total INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (hour_id, agent_slug, workspace_id, source_id));
CREATE TABLE IF NOT EXISTS usage_daily (day_id INTEGER NOT NULL, agent_slug TEXT NOT NULL, workspace_id INTEGER NOT NULL DEFAULT 0, source_id TEXT NOT NULL DEFAULT 'local', message_count INTEGER NOT NULL DEFAULT 0, user_message_count INTEGER NOT NULL DEFAULT 0, assistant_message_count INTEGER NOT NULL DEFAULT 0, tool_call_count INTEGER NOT NULL DEFAULT 0, plan_message_count INTEGER NOT NULL DEFAULT 0, api_coverage_message_count INTEGER NOT NULL DEFAULT 0, content_tokens_est_total INTEGER NOT NULL DEFAULT 0, content_tokens_est_user INTEGER NOT NULL DEFAULT 0, content_tokens_est_assistant INTEGER NOT NULL DEFAULT 0, api_tokens_total INTEGER NOT NULL DEFAULT 0, api_input_tokens_total INTEGER NOT NULL DEFAULT 0, api_output_tokens_total INTEGER NOT NULL DEFAULT 0, api_cache_read_tokens_total INTEGER NOT NULL DEFAULT 0, api_cache_creation_tokens_total INTEGER NOT NULL DEFAULT 0, api_thinking_tokens_total INTEGER NOT NULL DEFAULT 0, last_updated INTEGER NOT NULL DEFAULT 0, plan_content_tokens_est_total INTEGER NOT NULL DEFAULT 0, plan_api_tokens_total INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day_id, agent_slug, workspace_id, source_id));
CREATE TABLE IF NOT EXISTS usage_models_daily (day_id INTEGER NOT NULL, agent_slug TEXT NOT NULL, workspace_id INTEGER NOT NULL DEFAULT 0, source_id TEXT NOT NULL DEFAULT 'local', model_family TEXT NOT NULL DEFAULT 'unknown', model_tier TEXT NOT NULL DEFAULT 'unknown', message_count INTEGER NOT NULL DEFAULT 0, user_message_count INTEGER NOT NULL DEFAULT 0, assistant_message_count INTEGER NOT NULL DEFAULT 0, tool_call_count INTEGER NOT NULL DEFAULT 0, plan_message_count INTEGER NOT NULL DEFAULT 0, api_coverage_message_count INTEGER NOT NULL DEFAULT 0, content_tokens_est_total INTEGER NOT NULL DEFAULT 0, content_tokens_est_user INTEGER NOT NULL DEFAULT 0, content_tokens_est_assistant INTEGER NOT NULL DEFAULT 0, api_tokens_total INTEGER NOT NULL DEFAULT 0, api_input_tokens_total INTEGER NOT NULL DEFAULT 0, api_output_tokens_total INTEGER NOT NULL DEFAULT 0, api_cache_read_tokens_total INTEGER NOT NULL DEFAULT 0, api_cache_creation_tokens_total INTEGER NOT NULL DEFAULT 0, api_thinking_tokens_total INTEGER NOT NULL DEFAULT 0, last_updated INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (day_id, agent_slug, workspace_id, source_id, model_family, model_tier));
CREATE INDEX IF NOT EXISTS idx_conversations_agent_started ON conversations(agent_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_conversations_source_id ON conversations(source_id);
CREATE INDEX IF NOT EXISTS idx_conversations_source_path ON conversations(source_path);
CREATE INDEX IF NOT EXISTS idx_daily_stats_agent ON daily_stats(agent_slug, day_id);
CREATE INDEX IF NOT EXISTS idx_daily_stats_source ON daily_stats(source_id, day_id);
CREATE INDEX IF NOT EXISTS idx_token_usage_day ON token_usage(day_id, agent_id);
CREATE INDEX IF NOT EXISTS idx_token_usage_conv ON token_usage(conversation_id);
CREATE INDEX IF NOT EXISTS idx_token_usage_model ON token_usage(model_family, day_id);
CREATE INDEX IF NOT EXISTS idx_token_usage_workspace ON token_usage(workspace_id, day_id);
CREATE INDEX IF NOT EXISTS idx_token_usage_timestamp ON token_usage(timestamp_ms);
CREATE INDEX IF NOT EXISTS idx_token_daily_stats_agent ON token_daily_stats(agent_slug, day_id);
CREATE INDEX IF NOT EXISTS idx_token_daily_stats_model ON token_daily_stats(model_family, day_id);
CREATE INDEX IF NOT EXISTS idx_mm_hour ON message_metrics(hour_id);
CREATE INDEX IF NOT EXISTS idx_mm_day ON message_metrics(day_id);
CREATE INDEX IF NOT EXISTS idx_mm_agent_hour ON message_metrics(agent_slug, hour_id);
CREATE INDEX IF NOT EXISTS idx_mm_agent_day ON message_metrics(agent_slug, day_id);
CREATE INDEX IF NOT EXISTS idx_mm_workspace_hour ON message_metrics(workspace_id, hour_id);
CREATE INDEX IF NOT EXISTS idx_mm_source_hour ON message_metrics(source_id, hour_id);
CREATE INDEX IF NOT EXISTS idx_mm_model_family_day ON message_metrics(model_family, day_id);
CREATE INDEX IF NOT EXISTS idx_mm_provider_day ON message_metrics(provider, day_id);
CREATE INDEX IF NOT EXISTS idx_uh_agent ON usage_hourly(agent_slug, hour_id);
CREATE INDEX IF NOT EXISTS idx_uh_workspace ON usage_hourly(workspace_id, hour_id);
CREATE INDEX IF NOT EXISTS idx_uh_source ON usage_hourly(source_id, hour_id);
CREATE INDEX IF NOT EXISTS idx_ud_agent ON usage_daily(agent_slug, day_id);
CREATE INDEX IF NOT EXISTS idx_ud_workspace ON usage_daily(workspace_id, day_id);
CREATE INDEX IF NOT EXISTS idx_ud_source ON usage_daily(source_id, day_id);
CREATE INDEX IF NOT EXISTS idx_umd_model_day ON usage_models_daily(model_family, day_id);
CREATE INDEX IF NOT EXISTS idx_umd_agent_day ON usage_models_daily(agent_slug, day_id);
CREATE INDEX IF NOT EXISTS idx_umd_workspace_day ON usage_models_daily(workspace_id, day_id);
CREATE INDEX IF NOT EXISTS idx_umd_source_day ON usage_models_daily(source_id, day_id);
CREATE TABLE IF NOT EXISTS conversation_tail_state (conversation_id INTEGER PRIMARY KEY, ended_at INTEGER, last_message_idx INTEGER, last_message_created_at INTEGER);
CREATE TABLE IF NOT EXISTS conversation_external_lookup (lookup_key TEXT PRIMARY KEY, conversation_id INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS conversation_external_tail_lookup (lookup_key TEXT PRIMARY KEY, conversation_id INTEGER NOT NULL, ended_at INTEGER, last_message_idx INTEGER, last_message_created_at INTEGER);
CREATE TABLE IF NOT EXISTS operation_commit_receipt (id INTEGER PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, operation TEXT NOT NULL, state TEXT NOT NULL, snapshot_root TEXT, committed_at_ms INTEGER NOT NULL, detail TEXT);
CREATE TABLE IF NOT EXISTS lex_docs (doc_id INTEGER PRIMARY KEY REFERENCES messages (id) ON DELETE CASCADE, content TEXT NOT NULL, title TEXT NOT NULL, agent TEXT NOT NULL, workspace TEXT NOT NULL, source_path TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS fts_lex USING fts5(content, title, agent, workspace, source_path, content = 'lex_docs', content_rowid = 'doc_id', tokenize = 'porter trigram');
"#;

/// `PRAGMA user_version` is not parameterizable, so it is spliced into a
/// small standalone statement rather than folded into [`FRESH_SCHEMA_DDL`]
/// (which is a `const`, and thus can't carry a runtime version number
/// through `format!`).
fn set_user_version_sql(version: i64) -> String {
    format!("PRAGMA user_version = {version};")
}

/// `pub(crate)`: the Stage B transition shim in `storage::sqlite` (Task B7
/// wiring) needs to branch on this before deciding whether a database goes
/// through `ensure` or the pre-existing incremental migration path.
pub(crate) fn read_user_version(conn: &Conn) -> Result<i64, StorageError> {
    conn.query_row_map("PRAGMA user_version;", &[], |row| row.get_typed(0))
}

/// A database is "empty" for `ensure`'s purposes when it has zero rows in
/// `sqlite_master` — no tables, indexes, views, or triggers of any kind,
/// user-created or internal. This is deliberately stricter than "has none
/// of our named tables": a database with *any* pre-existing schema object
/// is not a database `ensure` gets to build from scratch.
fn database_is_empty(conn: &Conn) -> Result<bool, StorageError> {
    let object_count: i64 =
        conn.query_row_map("SELECT count(*) FROM sqlite_master;", &[], |row| row.get_typed(0))?;
    Ok(object_count == 0)
}

fn reject(detail: impl Into<String>) -> StorageError {
    StorageError::Other { code: None, detail: detail.into() }
}

/// Ensure `conn` has a valid, current-version schema, building one from
/// scratch if the database is empty. Idempotent: calling this twice on the
/// same already-current database is a no-op both times.
///
/// - Empty database → build [`FRESH_SCHEMA_DDL`] and set
///   `user_version = CURRENT_SCHEMA_VERSION`, all inside one transaction
///   (SQLite's own transactional DDL guarantee is what makes the
///   "interrupted mid-build" fault-injection tests below pass without any
///   extra bookkeeping here: any interruption before `COMMIT` leaves the
///   database exactly as empty as it started, and a retry takes the same
///   fresh-build branch again).
/// - `user_version == 0` and non-empty → this looks like a database that
///   predates `user_version` tracking entirely (a legacy-engine-era
///   archive, or a half-built database from a build that was interrupted
///   *after* some other process broke the single-transaction contract).
///   Rejected outright — this module does not attempt in-place conversion;
///   the caller's story for that case is "rebuild the archive", not
///   "migrate this file".
/// - `0 < user_version < CURRENT_SCHEMA_VERSION` → apply every pending
///   migration step in version order, in a single transaction, then bump
///   `user_version` straight to [`CURRENT_SCHEMA_VERSION`] (not "+1" per
///   call): a database more than one version behind must not require a
///   second `ensure` call to finish catching up, since callers invoke this
///   once per open. Steps so far:
///   - `version < 2`: add the `lex_docs`/`fts_lex` domain
///     ([`V2_LEX_DOMAIN_DDL`]). Idempotent via `IF NOT EXISTS` on both
///     statements.
///   - `version < 3` (W2-6 Task戊): `DROP TABLE IF EXISTS fts_messages` —
///     the legacy FTS5 shadow, superseded by the `fts_lex`/`lex_docs`
///     domain. Idempotent via `IF EXISTS`.
/// - `user_version == CURRENT_SCHEMA_VERSION` → already built, nothing to do.
/// - `user_version > CURRENT_SCHEMA_VERSION` → this binary is older than
///   the database it's looking at. Rejected: opening it would silently
///   ignore schema it doesn't understand.
pub fn ensure(conn: &Conn) -> Result<(), StorageError> {
    let version = read_user_version(conn)?;

    if version == 0 {
        if !database_is_empty(conn)? {
            return Err(reject(
                "database has user_version=0 but is not empty; this is not a database \
                 `schema::ensure` can open in place (it looks like a pre-rusqlite archive, \
                 or a half-built database from an interrupted process that did not go \
                 through a single transaction) -- rebuild the archive instead of trying to \
                 convert this file",
            ));
        }
        return conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            tx.execute_batch(FRESH_SCHEMA_DDL)?;
            tx.execute_batch(&set_user_version_sql(CURRENT_SCHEMA_VERSION))?;
            Ok(())
        });
    }

    if version > CURRENT_SCHEMA_VERSION {
        return Err(reject(format!(
            "database schema version {version} is newer than supported version \
             {CURRENT_SCHEMA_VERSION}"
        )));
    }

    if version < CURRENT_SCHEMA_VERSION {
        // w2 Task W2-3 Step 4 (R1-X-N1) + W2-6 Task戊: a pre-existing database
        // opened by newer code must not be silently left behind. Every
        // pending step below is idempotent (`IF NOT EXISTS` / `IF EXISTS`),
        // so applying steps the database already has is harmless -- a retry
        // after an interrupted attempt, or a second `ensure` call on an
        // already-current database, re-runs (or skips) harmlessly. All
        // pending steps apply in one transaction so a single `ensure` call
        // fully catches a database up regardless of how far behind it is.
        return conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            if version < 2 {
                tx.execute_batch(V2_LEX_DOMAIN_DDL)?;
            }
            if version < 3 {
                tx.execute_batch("DROP TABLE IF EXISTS fts_messages;")?;
            }
            tx.execute_batch(&set_user_version_sql(CURRENT_SCHEMA_VERSION))?;
            Ok(())
        });
    }

    // version == CURRENT_SCHEMA_VERSION: already built, nothing to do.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::api::Profile;
    use std::path::Path;

    fn open_sqlite_writer(path: &Path) -> Conn {
        // w1b Task B8: `Conn::open_writable` itself now dispatches to
        // `SqliteBackend` -- no separate test-only bridge needed.
        Conn::open_writable(path, Profile::Production).expect("open sqlite backend for schema test")
    }

    /// The returned `TempDir` must stay alive for as long as the path is in
    /// use — its `Drop` removes the directory, so callers keep the binding
    /// (`let _dir = ...`), not just the `PathBuf`.
    fn scratch_db_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::TempDir::new().expect("create scratch dir");
        let path = dir.path().join("agent_search.db");
        (dir, path)
    }

    fn table_names(conn: &Conn) -> Vec<String> {
        conn.query_all_map(
            "SELECT name FROM sqlite_master WHERE type IN ('table', 'index') ORDER BY name;",
            &[],
            |row| row.get_typed(0),
        )
        .unwrap()
    }

    #[test]
    fn ensure_builds_fresh_schema_and_sets_user_version() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        ensure(&conn).expect("ensure should build a fresh schema");

        let version = read_user_version(&conn).unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);

        let names = table_names(&conn);
        assert!(names.contains(&"agents".to_string()));
        assert!(names.contains(&"conversations".to_string()));
        assert!(names.contains(&"messages".to_string()));
        assert!(names.contains(&"idx_conversations_provenance".to_string()));
        // W2-6 Task戊: fts_messages is retired at version 3 -- a fresh
        // database must never create it (or its FTS5 shadows) again.
        assert!(!names.contains(&"fts_messages".to_string()));
        assert!(!names.contains(&"fts_messages_data".to_string()));
        // w2 Task W2-2: lex_docs + fts_lex (external-content, OQ2 decision).
        assert!(names.contains(&"lex_docs".to_string()));
        assert!(names.contains(&"fts_lex_data".to_string()));
        assert!(
            !names.contains(&"fts_lex_content".to_string()),
            "external-content mode must not maintain its own content shadow"
        );
    }

    /// Regression guard for the seed-data gap a `.schema`-only dump cannot
    /// see (found the hard way: an earlier version of this DDL had the
    /// correct table/index *structure* but no data, which broke every
    /// caller expecting the bootstrap `sources` row and the default
    /// `model_pricing` rates to already exist on a fresh database).
    #[test]
    fn ensure_seeds_bootstrap_source_and_default_model_pricing() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");

        let source_ids: Vec<String> =
            conn.query_all_map("SELECT id FROM sources ORDER BY id;", &[], |row| row.get_typed(0))
                .unwrap();
        assert_eq!(source_ids, vec!["local".to_string()]);

        let pricing_row_count: i64 =
            conn.query_row_map("SELECT count(*) FROM model_pricing;", &[], |row| row.get_typed(0))
                .unwrap();
        assert_eq!(pricing_row_count, 10, "default model_pricing rate table must be seeded");
    }

    #[test]
    fn ensure_is_idempotent_on_an_already_current_database() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        ensure(&conn).expect("first ensure should succeed");
        let names_after_first = table_names(&conn);

        ensure(&conn).expect("second ensure on an already-current db should be a no-op, not fail");
        let names_after_second = table_names(&conn);

        assert_eq!(names_after_first, names_after_second);
        assert_eq!(read_user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn ensure_rejects_nonempty_database_with_zero_user_version() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        // Simulate a pre-rusqlite (or otherwise foreign) database: some
        // schema exists, but user_version was never set.
        conn.execute_batch("CREATE TABLE some_legacy_table (id INTEGER PRIMARY KEY);").unwrap();
        assert_eq!(read_user_version(&conn).unwrap(), 0);

        let err = ensure(&conn).expect_err("non-empty user_version=0 database must be rejected");
        let message = err.to_string();
        assert!(
            message.contains("not empty") || message.contains("rebuild"),
            "error should explain this is a rebuild-not-convert case, got: {message}"
        );
    }

    #[test]
    fn ensure_rejects_database_newer_than_supported() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        conn.execute_batch(&set_user_version_sql(CURRENT_SCHEMA_VERSION + 1)).unwrap();

        let err = ensure(&conn).expect_err("a newer-than-supported user_version must be rejected");
        assert!(
            err.to_string().contains("newer than supported"),
            "error should name the newer-than-supported condition, got: {err}"
        );
    }

    /// Guards against the two DDL copies (`FRESH_SCHEMA_DDL`'s tail and
    /// `V2_LEX_DOMAIN_DDL`) silently drifting apart — see both constants'
    /// doc comments for why they are duplicated instead of shared.
    #[test]
    fn fresh_schema_ddl_tail_matches_v2_lex_domain_migration_ddl() {
        assert!(
            FRESH_SCHEMA_DDL.trim_end().ends_with(V2_LEX_DOMAIN_DDL.trim()),
            "FRESH_SCHEMA_DDL's final two statements must be byte-for-byte identical to \
             V2_LEX_DOMAIN_DDL (the version 1 -> 2 migration applies exactly this text to a \
             pre-existing database, and it must produce the same lex_docs/fts_lex shape a \
             fresh build gets)"
        );
    }

    /// w2 Task W2-3 Step 4 (R1-X-N1): opening a real wave-1-shaped database
    /// (`user_version = 1`, no `lex_docs`/`fts_lex`) must not leave it behind
    /// -- `ensure` must add the new domain and advance to version 2,
    /// idempotently (a second `ensure` call, or a retry after an interrupted
    /// first attempt, must not fail or duplicate anything).
    #[test]
    fn ensure_migrates_a_wave1_database_to_the_lex_domain_and_is_idempotent() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        // Build a version-1 shape directly (the pre-W2-2 DDL: everything up
        // to and including fts_messages -- the legacy FTS5 shadow a real
        // wave-1 database still had -- but not lex_docs/fts_lex).
        let v1_ddl = FRESH_SCHEMA_DDL
            .trim_end()
            .strip_suffix(V2_LEX_DOMAIN_DDL.trim())
            .expect("FRESH_SCHEMA_DDL must end with V2_LEX_DOMAIN_DDL's text");
        conn.execute_batch(v1_ddl).unwrap();
        conn.execute_batch(LEGACY_FTS_MESSAGES_DDL_FOR_TEST).unwrap();
        conn.execute_batch(&set_user_version_sql(1)).unwrap();
        let v1_names = table_names(&conn);
        assert!(
            !v1_names.contains(&"lex_docs".to_string()),
            "sanity: the hand-built v1 shape must not already have lex_docs"
        );
        assert!(
            v1_names.contains(&"fts_messages".to_string()),
            "sanity: a real wave-1 database still had fts_messages"
        );

        ensure(&conn).expect("ensure must migrate a version-1 database forward");
        assert_eq!(read_user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        let names = table_names(&conn);
        assert!(names.contains(&"lex_docs".to_string()));
        assert!(names.contains(&"fts_lex_data".to_string()));
        // W2-6 Task戊: a database more than one version behind must catch
        // all the way up in a single `ensure` call -- fts_messages must be
        // dropped too, not just the version 1->2 lex_docs add applied.
        assert!(
            !names.contains(&"fts_messages".to_string()),
            "a version-1 database must also get the version 2->3 fts_messages drop"
        );

        // Idempotent: a second call (simulating either a deliberate re-run or
        // recovery after an interrupted first migration) must not fail.
        ensure(&conn).expect("a second ensure call on an already-migrated database must be a no-op");
        assert_eq!(read_user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        assert_eq!(table_names(&conn), names, "re-running the migration must not change the table set");
    }

    /// W2-6 Task戊: a version-2 database (the `lex_docs`/`fts_lex` domain
    /// already added by the version 1->2 step, but `fts_messages` not yet
    /// dropped -- the shape every real database had right up until this
    /// task) must get `fts_messages` dropped and land on version 3,
    /// idempotently.
    #[test]
    fn ensure_migrates_a_wave2_database_by_dropping_fts_messages_and_is_idempotent() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        conn.execute_batch(FRESH_SCHEMA_DDL).unwrap();
        conn.execute_batch(LEGACY_FTS_MESSAGES_DDL_FOR_TEST).unwrap();
        conn.execute_batch(&set_user_version_sql(2)).unwrap();
        let v2_names = table_names(&conn);
        assert!(
            v2_names.contains(&"fts_messages".to_string()),
            "sanity: the hand-built v2 shape must have fts_messages"
        );

        ensure(&conn).expect("ensure must migrate a version-2 database forward");
        assert_eq!(read_user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        let names = table_names(&conn);
        assert!(
            !names.contains(&"fts_messages".to_string()),
            "fts_messages must be dropped"
        );
        assert!(
            !names.contains(&"fts_messages_data".to_string()),
            "fts_messages's FTS5 shadow tables must be dropped along with it"
        );
        assert!(
            names.contains(&"lex_docs".to_string()),
            "the fts_messages drop must not touch the unrelated lex_docs/fts_lex domain"
        );

        // Idempotent: a second call (simulating either a deliberate re-run or
        // recovery after an interrupted first migration) must not fail.
        ensure(&conn).expect("a second ensure call on an already-migrated database must be a no-op");
        assert_eq!(read_user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        assert_eq!(table_names(&conn), names, "re-running the migration must not change the table set");
    }

    #[test]
    fn ensure_produces_a_database_stock_sqlite3_confirms_is_healthy() {
        let (_dir, path) = scratch_db_path();
        {
            let conn = open_sqlite_writer(&path);
            ensure(&conn).expect("ensure should succeed");
            conn.close().expect("close cleanly so the CLI can read a checkpointed file");
        }

        let output = std::process::Command::new("sqlite3")
            .arg(&path)
            .arg("PRAGMA integrity_check;")
            .output()
            .expect("stock sqlite3 CLI must be available to run this assertion");
        assert!(output.status.success(), "sqlite3 exited non-zero: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(stdout.trim(), "ok", "stock sqlite3 integrity_check output: {stdout}");
    }

    /// Fault injection, 步内 granularity (R2-F8 + R3-N4): interrupt the
    /// fresh-build transaction after only some of its DDL has executed,
    /// then roll back (dropping the `Tx` without committing) instead of
    /// letting `ensure` finish it -- the same end state a real process
    /// crash mid-transaction leaves behind, since SQLite's own crash
    /// recovery undoes anything that never reached `COMMIT`. `ensure` must
    /// then converge cleanly on retry, exactly as it would on a database
    /// that was never touched.
    ///
    /// There is deliberately no separate 步间 (between-migration-step)
    /// fault-injection test: that granularity is about crashing between
    /// two already-applied migration *steps*, and today there is only one
    /// step (`CURRENT_SCHEMA_VERSION == 1`, the fresh build itself) -- there
    /// is no second step yet to crash between. This test point is recorded
    /// here so the day a real version-2 migration is added, the missing
    /// 步间 case is an obvious, deliberate gap to fill, not a silent one.
    #[test]
    fn ensure_recovers_after_interrupted_partial_ddl_application() {
        for statements_before_interrupt in [0usize, 1, 5, FRESH_SCHEMA_DDL_STATEMENT_COUNT_FOR_TEST]
        {
            let (_dir, path) = scratch_db_path();
            let conn = open_sqlite_writer(&path);

            {
                let tx = conn.transaction_with_mode(TxMode::Immediate).unwrap();
                let statements: Vec<&str> = FRESH_SCHEMA_DDL
                    .split(';')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect();
                for stmt in statements.iter().take(statements_before_interrupt) {
                    tx.execute_batch(&format!("{stmt};")).unwrap();
                }
                // `tx` drops here without `commit()` -- Tx's Drop rolls back
                // (see conn.rs), simulating a crash before this transaction
                // ever reached durable state.
            }

            assert!(
                database_is_empty(&conn).unwrap(),
                "an uncommitted partial DDL application must leave no trace \
                 (statements_before_interrupt = {statements_before_interrupt})"
            );

            ensure(&conn).unwrap_or_else(|err| {
                panic!(
                    "ensure must converge after a simulated crash \
                     (statements_before_interrupt = {statements_before_interrupt}): {err}"
                )
            });
            assert_eq!(read_user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        }
    }

    /// W2-6 Task1 (X-5 fix): `recreate_lex_domain_tables` must genuinely
    /// DROP+CREATE, not a no-op "if not exists" -- existing rows must not
    /// survive, since the whole point is being safe to call on a domain
    /// whose internal structure may already be corrupted.
    #[test]
    fn recreate_lex_domain_tables_wipes_existing_rows() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");

        conn.execute(
            "INSERT INTO agents(id, slug, name, kind, created_at, updated_at) \
             VALUES (1, 'a', 'a', 'cli', 0, 0)",
            &[],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO conversations(id, agent_id, title, source_path) VALUES (1, 1, 't', 'p')",
            &[],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (1, 1, 0, 'user', 'c')",
            &[],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO lex_docs(doc_id, content, title, agent, workspace, source_path) \
             VALUES (1, 'c', 't', 'a', 'w', 'p')",
            &[],
        )
        .unwrap();
        conn.execute("INSERT INTO fts_lex(rowid, content, title, agent, workspace, source_path) VALUES (1, 'c', 't', 'a', 'w', 'p')", &[])
            .unwrap();

        let before: i64 = conn
            .query_row_map("SELECT COUNT(*) FROM lex_docs", &[], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(before, 1, "sanity: row must exist before recreate");

        recreate_lex_domain_tables(&conn).expect("recreate must succeed on a healthy domain");

        let after: i64 = conn
            .query_row_map("SELECT COUNT(*) FROM lex_docs", &[], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(after, 0, "recreate must drop the old table, not leave old rows behind");
    }

    /// Must also work when the domain is entirely missing (simulating the
    /// self-heal "domain was never built" path re-using the same code).
    #[test]
    fn recreate_lex_domain_tables_builds_domain_that_was_entirely_missing() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        conn.execute_batch("DROP TABLE IF EXISTS fts_lex; DROP TABLE IF EXISTS lex_docs;")
            .expect("drop lex domain to simulate a missing domain");
        assert!(!table_names(&conn).contains(&"lex_docs".to_string()));

        recreate_lex_domain_tables(&conn).expect("recreate must rebuild a missing domain");

        let names = table_names(&conn);
        assert!(names.contains(&"lex_docs".to_string()));
        assert!(names.contains(&"fts_lex_data".to_string()));
    }

    /// One past the last real statement, so the loop above also covers
    /// "every statement ran, only the version pragma is missing" -- the
    /// latest possible interruption point inside the transaction. Bumped
    /// from 58 to 60 by w2 Task W2-2's `lex_docs`/`fts_lex` addition, then
    /// down to 59 by W2-6 Task戊 removing the `fts_messages` statement.
    const FRESH_SCHEMA_DDL_STATEMENT_COUNT_FOR_TEST: usize = 59;

    /// The historical `fts_messages` DDL, byte-for-byte identical to the
    /// statement W2-6 Task戊 removed from [`FRESH_SCHEMA_DDL`]. A real
    /// database built at version 1 or 2 (before this task) always had this
    /// table -- kept here, test-only, so the version 1->3 and 2->3 migration
    /// tests can hand-build an authentic pre-drop fixture instead of
    /// depending on production DDL that must no longer contain it.
    const LEGACY_FTS_MESSAGES_DDL_FOR_TEST: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS fts_messages USING fts5(content, title, agent, workspace, source_path, created_at UNINDEXED, content = '', tokenize = 'porter');";
}
