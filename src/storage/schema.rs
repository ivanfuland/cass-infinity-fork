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

use super::api::{Conn, StorageError, Tx, TxMode, params};

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
///
/// Version 4 (w3 Task W3-1, spec §3.1 向量域) adds the vector-domain tables:
/// `embedding_generations` (代际元数据: embedder_id/dim/canonicalize_version/
/// byte_order/audit_status/single-active pointer via a partial unique
/// index), `message_embeddings` (权威向量表, `UNIQUE(generation_id, doc_id)`,
/// `doc_id` cascades from `messages`), and `embedding_holes` (R4-B5 hole
/// ledger -- parallel catch-up completeness tracking; only the table shape
/// ships here, consumption logic is W3-2's job). No `vec0` virtual table and
/// no `sqlite-vec` dependency yet -- that is W3-3's retrieval-segment scope;
/// this version only ships the authoritative relational shape.
pub const CURRENT_SCHEMA_VERSION: i64 = 4;

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

/// The vector-domain DDL (w3 Task W3-1, spec §3.1) — **must stay byte-for-byte
/// identical** to the matching tail of [`FRESH_SCHEMA_DDL`] below, for the
/// same reason [`V2_LEX_DOMAIN_DDL`] is a separate duplicated constant
/// rather than something `FRESH_SCHEMA_DDL` references (`concat!` only
/// accepts literal tokens). Used by the version 3 → 4 upgrade path in
/// [`ensure`] to backfill the vector domain into a pre-existing
/// version-&lt;4 database (a unit test,
/// `fresh_schema_ddl_tail_matches_v4_vector_domain_migration_ddl`, enforces
/// the two copies cannot silently drift apart).
///
/// Column shape decisions (spec §3.1 interface line, R4-B4/B5/N8, R0-B07):
/// - `embedding_generations`: `dim`/`embedder_id`/`canonicalize_version`/
///   `byte_order` are the代际 identity fields; `audit_status` tracks the
///   W3-4 activation-audit outcome (`pending`/`passed`/`failed` — a
///   migrator or catch-up writer stamps `pending` per Task W3-2's
///   interface); `is_active` is the active-generation pointer, with
///   `idx_embedding_generations_single_active` (a `WHERE is_active = 1`
///   partial unique index) making "at most one active generation" a DDL
///   invariant rather than an application-level promise — a plain `SELECT
///   ... WHERE is_active = 1` inside the same read transaction as a
///   `message_embeddings` read is therefore automatically the "same SQLite
///   snapshot" reader spec's R4-B4 requires, with no separate pointer table
///   needed.
/// - `message_embeddings`: DDL `CHECK(length(embedding) % 4 = 0)` is the
///   cross-row-agnostic backstop (a per-generation exact-dim check cannot
///   live in a table CHECK — it would need a cross-table lookup, which
///   SQLite CHECK constraints cannot express); the strict per-generation
///   dim check, the finite (non-NaN/non-Inf) check, and the norm/BLOB
///   recompute consistency all live in the write-side helpers below
///   ([`insert_message_embedding`]). `CHECK(norm > 0)` is a second DDL
///   backstop for R4-N8's zero-norm rejection (also catches a NaN norm,
///   since IEEE-754 `NaN > 0` is `false`). `doc_id` cascades from
///   `messages` (R0-B07's `ON DELETE CASCADE`); `generation_id` does not
///   cascade from `embedding_generations` — deleting a generation's rows in
///   bulk is W3-4's explicit "旧代际延迟清理" job, not an implicit
///   side-effect of dropping the generation's metadata row.
/// - `embedding_holes`: R4-B5's hole ledger — `PRIMARY KEY
///   (generation_id, doc_id)` makes re-detecting the same hole an idempotent
///   `INSERT OR IGNORE`, not a fresh duplicate row; `doc_id` cascades from
///   `messages` (a hole for a message that no longer exists is moot).
///   Consumption (writing/resolving holes during catch-up) is W3-2's job —
///   this version only ships the table shape plus basic CRUD capability.
const V4_VECTOR_DOMAIN_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS embedding_generations (id INTEGER PRIMARY KEY AUTOINCREMENT, embedder_id TEXT NOT NULL, dim INTEGER NOT NULL CHECK (dim > 0), canonicalize_version INTEGER NOT NULL, byte_order TEXT NOT NULL DEFAULT 'le' CHECK (byte_order IN ('le', 'be')), audit_status TEXT NOT NULL DEFAULT 'pending' CHECK (audit_status IN ('pending', 'passed', 'failed')), is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)), created_at INTEGER NOT NULL, activated_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS idx_embedding_generations_single_active ON embedding_generations(is_active) WHERE is_active = 1;
CREATE TABLE IF NOT EXISTS message_embeddings (generation_id INTEGER NOT NULL REFERENCES embedding_generations (id), doc_id INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE, conversation_id INTEGER NOT NULL, embedding BLOB NOT NULL CHECK (length(embedding) % 4 = 0), norm REAL NOT NULL CHECK (norm > 0), content_hash TEXT NOT NULL, content_version INTEGER, created_at INTEGER NOT NULL, UNIQUE (generation_id, doc_id));
CREATE INDEX IF NOT EXISTS idx_message_embeddings_generation ON message_embeddings(generation_id);
CREATE INDEX IF NOT EXISTS idx_message_embeddings_doc ON message_embeddings(doc_id);
CREATE TABLE IF NOT EXISTS embedding_holes (generation_id INTEGER NOT NULL REFERENCES embedding_generations (id), doc_id INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE, detected_at INTEGER NOT NULL, reason TEXT, PRIMARY KEY (generation_id, doc_id));
"#;

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
CREATE TABLE IF NOT EXISTS embedding_generations (id INTEGER PRIMARY KEY AUTOINCREMENT, embedder_id TEXT NOT NULL, dim INTEGER NOT NULL CHECK (dim > 0), canonicalize_version INTEGER NOT NULL, byte_order TEXT NOT NULL DEFAULT 'le' CHECK (byte_order IN ('le', 'be')), audit_status TEXT NOT NULL DEFAULT 'pending' CHECK (audit_status IN ('pending', 'passed', 'failed')), is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)), created_at INTEGER NOT NULL, activated_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS idx_embedding_generations_single_active ON embedding_generations(is_active) WHERE is_active = 1;
CREATE TABLE IF NOT EXISTS message_embeddings (generation_id INTEGER NOT NULL REFERENCES embedding_generations (id), doc_id INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE, conversation_id INTEGER NOT NULL, embedding BLOB NOT NULL CHECK (length(embedding) % 4 = 0), norm REAL NOT NULL CHECK (norm > 0), content_hash TEXT NOT NULL, content_version INTEGER, created_at INTEGER NOT NULL, UNIQUE (generation_id, doc_id));
CREATE INDEX IF NOT EXISTS idx_message_embeddings_generation ON message_embeddings(generation_id);
CREATE INDEX IF NOT EXISTS idx_message_embeddings_doc ON message_embeddings(doc_id);
CREATE TABLE IF NOT EXISTS embedding_holes (generation_id INTEGER NOT NULL REFERENCES embedding_generations (id), doc_id INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE, detected_at INTEGER NOT NULL, reason TEXT, PRIMARY KEY (generation_id, doc_id));
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
///   - `version < 4` (w3 Task W3-1): add the vector domain
///     ([`V4_VECTOR_DOMAIN_DDL`]: `embedding_generations`/
///     `message_embeddings`/`embedding_holes`). Idempotent via `IF NOT
///     EXISTS` on every statement.
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
            if version < 4 {
                tx.execute_batch(V4_VECTOR_DOMAIN_DDL)?;
            }
            tx.execute_batch(&set_user_version_sql(CURRENT_SCHEMA_VERSION))?;
            Ok(())
        });
    }

    // version == CURRENT_SCHEMA_VERSION: already built, nothing to do.
    Ok(())
}

// =============================================================================
// Vector domain write-side helpers (w3 Task W3-1, spec §3.1).
//
// DDL CHECK constraints in [`V4_VECTOR_DOMAIN_DDL`] are the cross-row-agnostic
// backstop only (`length(embedding) % 4 = 0`, `norm > 0`) -- everything a DDL
// CHECK cannot express (exact per-generation dim, per-element finiteness, and
// norm/BLOB recompute consistency) is enforced here, at the single write path
// this module exposes for the table. There is deliberately no other sanctioned
// way to insert a row: any caller reaching for raw SQL `INSERT INTO
// message_embeddings` bypasses these checks and only gets the DDL backstop.
// =============================================================================

/// Only byte order this version's write path produces or accepts. Matches
/// [`V4_VECTOR_DOMAIN_DDL`]'s `byte_order` column default; `'be'` is a valid
/// DDL value (schema-level extension point) but has no producer yet.
pub const VECTOR_BYTE_ORDER_LE: &str = "le";

/// Serialize an f32 vector to its little-endian BLOB encoding (the only
/// encoding this version's write path produces -- see
/// [`VECTOR_BYTE_ORDER_LE`]). Manual byte-by-byte encoding, not
/// `bytemuck::cast_slice`, because the round trip back
/// ([`le_blob_to_f32_vector`]) reads a BLOB `Vec<u8>` handed back by SQLite
/// with no alignment guarantee, and `bytemuck` would have to make the same
/// concession on that side anyway -- one manual codec on both sides is
/// simpler than a fast path for the write direction only.
pub fn f32_vector_to_le_blob(vector: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(vector.len() * 4);
    for x in vector {
        out.extend_from_slice(&x.to_le_bytes());
    }
    out
}

/// Decode a little-endian BLOB back into an f32 vector. The DDL's
/// `CHECK(length(embedding) % 4 = 0)` guarantees `blob.len()` is a multiple
/// of 4 for any row that made it into the table, but this function is also
/// used by tests against hand-built byte slices, so it re-checks rather
/// than trusting the DDL invariant by assumption.
pub fn le_blob_to_f32_vector(blob: &[u8]) -> Result<Vec<f32>, StorageError> {
    if blob.len() % 4 != 0 {
        return Err(StorageError::Constraint {
            detail: format!(
                "embedding BLOB length {} is not a multiple of 4 bytes",
                blob.len()
            ),
        });
    }
    Ok(blob
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

/// L2 norm, accumulated in `f64` (matching the `norm REAL` column's SQLite
/// storage class) for the same value both at write time and when a test
/// recomputes it from a stored BLOB to check norm/BLOB consistency (spec
/// §3.1's "norm 与 BLOB 重算一致性").
pub fn l2_norm(vector: &[f32]) -> f64 {
    vector.iter().map(|x| f64::from(*x) * f64::from(*x)).sum::<f64>().sqrt()
}

/// Insert a new, empty (`audit_status = 'pending'`, `is_active = 0`)
/// embedding generation and return its `id`. Callers needing "just landed a
/// new generation" semantics (Task W3-2's migrator, catch-up writers) call
/// this once per generation, then [`insert_message_embedding`] per row.
pub fn create_embedding_generation(
    tx: &Tx,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
    created_at_ms: i64,
) -> Result<i64, StorageError> {
    tx.execute(
        "INSERT INTO embedding_generations \
         (embedder_id, dim, canonicalize_version, byte_order, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        &params![
            embedder_id,
            dim,
            i64::from(canonicalize_version),
            VECTOR_BYTE_ORDER_LE,
            created_at_ms
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// The write-side validation gate for `message_embeddings` (spec §3.1 Step
/// 1's four invariants, in order): strict per-generation dimension match
/// (DDL only checks `% 4 == 0`), per-element finiteness (rejects
/// NaN/Inf -- `f32::is_finite` catches both), non-zero norm (R4-N8), and the
/// stored `norm` column is always the same recomputation
/// ([`l2_norm`]) that also drives the zero-norm check, so norm/BLOB
/// consistency is a structural guarantee of this being the sole write path
/// rather than something checked after the fact.
#[allow(clippy::too_many_arguments)]
pub fn insert_message_embedding(
    tx: &Tx,
    generation_id: i64,
    doc_id: i64,
    conversation_id: i64,
    vector: &[f32],
    content_hash: &str,
    content_version: Option<i64>,
    created_at_ms: i64,
) -> Result<(), StorageError> {
    let expected_dim: i64 = tx.query_row_map(
        "SELECT dim FROM embedding_generations WHERE id = ?1",
        &params![generation_id],
        |row| row.get_typed(0),
    )?;

    let actual_dim = i64::try_from(vector.len()).map_err(|_| StorageError::Constraint {
        detail: format!("vector length {} does not fit in i64", vector.len()),
    })?;
    if actual_dim != expected_dim {
        return Err(StorageError::Constraint {
            detail: format!(
                "generation {generation_id} expects dim={expected_dim}, got vector of \
                 dim={actual_dim} for doc_id={doc_id}"
            ),
        });
    }

    if let Some(bad_idx) = vector.iter().position(|x| !x.is_finite()) {
        return Err(StorageError::Constraint {
            detail: format!(
                "embedding for doc_id={doc_id} has a non-finite element at index {bad_idx} \
                 (NaN/Inf are rejected)"
            ),
        });
    }

    let norm = l2_norm(vector);
    if !(norm > 0.0) {
        return Err(StorageError::Constraint {
            detail: format!(
                "embedding for doc_id={doc_id} has zero (or non-positive) norm {norm}; \
                 zero-norm vectors are rejected (R4-N8)"
            ),
        });
    }

    let blob = f32_vector_to_le_blob(vector);
    tx.execute(
        "INSERT INTO message_embeddings \
         (generation_id, doc_id, conversation_id, embedding, norm, content_hash, \
          content_version, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        &params![
            generation_id,
            doc_id,
            conversation_id,
            blob,
            norm,
            content_hash,
            content_version,
            created_at_ms
        ],
    )?;
    Ok(())
}

/// Read the current active generation's `id`, if any. A plain `SELECT`
/// against the `WHERE is_active = 1` partial-unique-indexed column -- when
/// called inside the same read transaction as a `message_embeddings` query,
/// this is the "same SQLite snapshot" active-pointer read spec's R4-B4
/// requires, with no separate pointer table or extra locking needed.
pub fn active_generation_id(conn: &Conn) -> Result<Option<i64>, StorageError> {
    conn.query_opt_map(
        "SELECT id FROM embedding_generations WHERE is_active = 1",
        &[],
        |row| row.get_typed(0),
    )
}

/// Switch the active-generation pointer to `new_generation_id`, atomically
/// with `verify` (spec §3.1's "指针切换与完整性校验同一事务", w3-d9②'s
///修复原子性判例): `verify` runs first, inside the same `Immediate`
/// transaction as the pointer flip. If `verify` returns `Err`, the whole
/// transaction rolls back via `Tx`'s `Drop` -- the previous active
/// generation (if any) is left untouched, not just "not yet switched".
/// `verify`'s own contract here is intentionally minimal (an
/// application-supplied predicate over the transaction) — the full W3-4
/// activation audit (`COUNT(length != 4*dim) = 0` + finite/norm resample +
/// positive-content check + identity-set anti-join + canonicalize-version
/// match + `PRAGMA foreign_key_check`) is that task's scope, not built here;
/// this function only guarantees the atomicity contract the audit will run
/// inside of.
pub fn switch_active_generation(
    conn: &Conn,
    new_generation_id: i64,
    activated_at_ms: i64,
    verify: impl FnOnce(&Tx) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    conn.with_tx_no_replay(TxMode::Immediate, |tx| {
        verify(tx)?;
        tx.execute("UPDATE embedding_generations SET is_active = 0 WHERE is_active = 1", &[])?;
        tx.execute(
            "UPDATE embedding_generations SET is_active = 1, activated_at = ?1 WHERE id = ?2",
            &params![activated_at_ms, new_generation_id],
        )?;
        Ok(())
    })
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
        // w3 Task W3-1: the vector domain (embedding_generations,
        // message_embeddings, embedding_holes) must exist on a fresh build.
        assert!(names.contains(&"embedding_generations".to_string()));
        assert!(names.contains(&"message_embeddings".to_string()));
        assert!(names.contains(&"embedding_holes".to_string()));
        assert!(names.contains(&"idx_embedding_generations_single_active".to_string()));
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

    /// Guards against the two DDL copies (`FRESH_SCHEMA_DDL`'s
    /// lex-domain section and `V2_LEX_DOMAIN_DDL`) silently drifting apart
    /// — see both constants' doc comments for why they are duplicated
    /// instead of shared. `V4_VECTOR_DOMAIN_DDL` was appended after the lex
    /// domain in `FRESH_SCHEMA_DDL` (w3 Task W3-1), so this is no longer a
    /// literal-tail check (see
    /// `fresh_schema_ddl_tail_matches_v4_vector_domain_migration_ddl` for
    /// that check against the new tail) -- a contiguous-substring check is
    /// exactly as strong a drift guard.
    #[test]
    fn fresh_schema_ddl_lex_domain_section_matches_v2_lex_domain_migration_ddl() {
        assert!(
            FRESH_SCHEMA_DDL.contains(V2_LEX_DOMAIN_DDL.trim()),
            "FRESH_SCHEMA_DDL must contain V2_LEX_DOMAIN_DDL's text verbatim (the version \
             1 -> 2 migration applies exactly this text to a pre-existing database, and it \
             must produce the same lex_docs/fts_lex shape a fresh build gets)"
        );
    }

    /// Guards against the two DDL copies (`FRESH_SCHEMA_DDL`'s tail and
    /// `V4_VECTOR_DOMAIN_DDL`) silently drifting apart — see both constants'
    /// doc comments for why they are duplicated instead of shared.
    #[test]
    fn fresh_schema_ddl_tail_matches_v4_vector_domain_migration_ddl() {
        assert!(
            FRESH_SCHEMA_DDL.trim_end().ends_with(V4_VECTOR_DOMAIN_DDL.trim()),
            "FRESH_SCHEMA_DDL's final statements must be byte-for-byte identical to \
             V4_VECTOR_DOMAIN_DDL (the version 3 -> 4 migration applies exactly this text to \
             a pre-existing database, and it must produce the same vector-domain shape a \
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
        // wave-1 database still had -- but not lex_docs/fts_lex, and not the
        // w3 vector domain either). Strip the tails in the order they were
        // appended: V4 (newest) first, then V2.
        let v3_shape_ddl = FRESH_SCHEMA_DDL
            .trim_end()
            .strip_suffix(V4_VECTOR_DOMAIN_DDL.trim())
            .expect("FRESH_SCHEMA_DDL must end with V4_VECTOR_DOMAIN_DDL's text");
        let v1_ddl = v3_shape_ddl
            .trim_end()
            .strip_suffix(V2_LEX_DOMAIN_DDL.trim())
            .expect("FRESH_SCHEMA_DDL minus the vector domain must end with V2_LEX_DOMAIN_DDL's text");
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
        // w3 Task W3-1 (plan ⑥ "vN->latest e2e"): a version-1 database more
        // than one migration step behind must also land the vector domain
        // added at version 4 -- this is the v1->4 end-to-end case.
        assert!(
            names.contains(&"embedding_generations".to_string()),
            "a version-1 database must also get the version 3->4 vector domain add"
        );
        assert!(names.contains(&"message_embeddings".to_string()));
        assert!(names.contains(&"embedding_holes".to_string()));

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

        // A real wave-2 database predates the w3 vector domain (added at
        // version 4) -- strip it off `FRESH_SCHEMA_DDL` before using it as
        // this fixture's base, same reasoning as the v1 fixture above.
        let v3_shape_ddl = FRESH_SCHEMA_DDL
            .trim_end()
            .strip_suffix(V4_VECTOR_DOMAIN_DDL.trim())
            .expect("FRESH_SCHEMA_DDL must end with V4_VECTOR_DOMAIN_DDL's text");
        conn.execute_batch(v3_shape_ddl).unwrap();
        conn.execute_batch(LEGACY_FTS_MESSAGES_DDL_FOR_TEST).unwrap();
        conn.execute_batch(&set_user_version_sql(2)).unwrap();
        let v2_names = table_names(&conn);
        assert!(
            v2_names.contains(&"fts_messages".to_string()),
            "sanity: the hand-built v2 shape must have fts_messages"
        );
        assert!(
            !v2_names.contains(&"embedding_generations".to_string()),
            "sanity: the hand-built v2 shape must not already have the vector domain"
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
        // w3 Task W3-1: a version-2 database must also get the version 3->4
        // vector domain add (a single `ensure` call catches all the way up).
        assert!(names.contains(&"embedding_generations".to_string()));
        assert!(names.contains(&"message_embeddings".to_string()));
        assert!(names.contains(&"embedding_holes".to_string()));

        // Idempotent: a second call (simulating either a deliberate re-run or
        // recovery after an interrupted first migration) must not fail.
        ensure(&conn).expect("a second ensure call on an already-migrated database must be a no-op");
        assert_eq!(read_user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        assert_eq!(table_names(&conn), names, "re-running the migration must not change the table set");
    }

    /// w3 Task W3-1 Step 2b (R1-X-N1 + w3-d6②, "与波2同款"): open a real
    /// wave-2-terminal-state database at `user_version = 3` (the shape every
    /// real database produced before this task -- `FRESH_SCHEMA_DDL` minus
    /// the vector-domain tail, exactly what the pre-W3-1 production
    /// `ensure` wrote for a fresh build) and assert the upgrade path lands
    /// the vector domain and reaches `CURRENT_SCHEMA_VERSION`, idempotently.
    /// This is the "波间升级" case the plan calls out distinctly from the
    /// v1/v2 hand-built fixtures above: it is byte-identical production DDL
    /// (not a re-derived subset), i.e. exactly what real wave-2 databases
    /// (like the w3 staging snapshot, itself confirmed `user_version = 3`)
    /// look like schema-wise.
    #[test]
    fn ensure_migrates_a_real_wave2_terminal_v3_database_to_the_vector_domain_and_is_idempotent() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        let v3_ddl = FRESH_SCHEMA_DDL
            .trim_end()
            .strip_suffix(V4_VECTOR_DOMAIN_DDL.trim())
            .expect("FRESH_SCHEMA_DDL must end with V4_VECTOR_DOMAIN_DDL's text");
        conn.execute_batch(v3_ddl).unwrap();
        conn.execute_batch(&set_user_version_sql(3)).unwrap();
        let v3_names = table_names(&conn);
        assert!(
            !v3_names.contains(&"fts_messages".to_string()),
            "sanity: a real wave-2-terminal (v3) database must not have fts_messages"
        );
        assert!(
            v3_names.contains(&"lex_docs".to_string()),
            "sanity: a real v3 database must already have the lex domain"
        );
        assert!(
            !v3_names.contains(&"embedding_generations".to_string()),
            "sanity: a real v3 database must not yet have the vector domain"
        );

        ensure(&conn).expect("ensure must migrate a version-3 database forward");
        assert_eq!(read_user_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        let names = table_names(&conn);
        assert!(names.contains(&"embedding_generations".to_string()));
        assert!(names.contains(&"message_embeddings".to_string()));
        assert!(names.contains(&"embedding_holes".to_string()));
        assert!(names.contains(&"idx_embedding_generations_single_active".to_string()));
        // The vector-domain add must not touch the pre-existing relational
        // or lexical domains.
        assert!(names.contains(&"lex_docs".to_string()));
        assert!(names.contains(&"messages".to_string()));

        // Idempotent: a second call (either a deliberate re-run or recovery
        // after an interrupted first migration) must not fail or duplicate.
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
    /// down to 59 by W2-6 Task戊 removing the `fts_messages` statement, then
    /// up to 65 by w3 Task W3-1's `V4_VECTOR_DOMAIN_DDL` (6 statements:
    /// `embedding_generations` table + its single-active partial index,
    /// `message_embeddings` table + 2 indexes, `embedding_holes` table).
    const FRESH_SCHEMA_DDL_STATEMENT_COUNT_FOR_TEST: usize = 65;

    /// The historical `fts_messages` DDL, byte-for-byte identical to the
    /// statement W2-6 Task戊 removed from [`FRESH_SCHEMA_DDL`]. A real
    /// database built at version 1 or 2 (before this task) always had this
    /// table -- kept here, test-only, so the version 1->3 and 2->3 migration
    /// tests can hand-build an authentic pre-drop fixture instead of
    /// depending on production DDL that must no longer contain it.
    const LEGACY_FTS_MESSAGES_DDL_FOR_TEST: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS fts_messages USING fts5(content, title, agent, workspace, source_path, created_at UNINDEXED, content = '', tokenize = 'porter');";
}
