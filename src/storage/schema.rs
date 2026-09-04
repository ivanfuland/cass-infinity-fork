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

use super::api::{Conn, StorageError, Tx, TxMode, Value, params};

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
pub const CURRENT_SCHEMA_VERSION: i64 = 5;

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
///   Consumption (writing/resolving holes during catch-up) is w3-3 Step 3/4's
///   job (W3-2, the embedding-reuse migrator originally slated to consume
///   this, was cancelled per w3-d10 and its scope folded into w3-3) — this
///   version only ships the table shape plus basic CRUD capability.
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
CREATE TABLE IF NOT EXISTS embedding_generations (id INTEGER PRIMARY KEY AUTOINCREMENT, embedder_id TEXT NOT NULL, dim INTEGER NOT NULL CHECK (dim > 0), canonicalize_version INTEGER NOT NULL, chunking_policy_version INTEGER NOT NULL, fingerprint BLOB NOT NULL, byte_order TEXT NOT NULL DEFAULT 'le' CHECK (byte_order IN ('le', 'be')), audit_status TEXT NOT NULL DEFAULT 'pending' CHECK (audit_status IN ('pending', 'passed', 'failed')), is_active INTEGER NOT NULL DEFAULT 0 CHECK (is_active IN (0, 1)), created_at INTEGER NOT NULL, activated_at INTEGER);
CREATE UNIQUE INDEX IF NOT EXISTS idx_embedding_generations_single_active ON embedding_generations(is_active) WHERE is_active = 1;
CREATE TABLE IF NOT EXISTS message_embeddings (generation_id INTEGER NOT NULL REFERENCES embedding_generations (id), doc_id INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE, conversation_id INTEGER NOT NULL, embedding BLOB NOT NULL CHECK (length(embedding) % 4 = 0), norm REAL NOT NULL CHECK (norm > 0), content_hash TEXT NOT NULL, content_version INTEGER, created_at INTEGER NOT NULL, UNIQUE (generation_id, doc_id));
CREATE INDEX IF NOT EXISTS idx_message_embeddings_generation ON message_embeddings(generation_id);
CREATE INDEX IF NOT EXISTS idx_message_embeddings_doc ON message_embeddings(doc_id);
CREATE TABLE IF NOT EXISTS embedding_holes (generation_id INTEGER NOT NULL REFERENCES embedding_generations (id), doc_id INTEGER NOT NULL REFERENCES messages (id) ON DELETE CASCADE, detected_at INTEGER NOT NULL, reason TEXT, PRIMARY KEY (generation_id, doc_id));
CREATE TABLE IF NOT EXISTS message_chunks (chunk_id INTEGER PRIMARY KEY, generation_id INTEGER NOT NULL REFERENCES embedding_generations(id), message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, conversation_id INTEGER NOT NULL, chunk_idx INTEGER NOT NULL, byte_start INTEGER NOT NULL, byte_end INTEGER NOT NULL, content_hash TEXT NOT NULL, embedding BLOB NOT NULL CHECK(length(embedding) % 4 = 0), norm REAL NOT NULL CHECK(norm > 0), created_at INTEGER NOT NULL, UNIQUE(generation_id, message_id, chunk_idx));
CREATE INDEX IF NOT EXISTS idx_message_chunks_generation ON message_chunks(generation_id);
CREATE INDEX IF NOT EXISTS idx_message_chunks_message ON message_chunks(message_id);
CREATE INDEX IF NOT EXISTS idx_message_chunks_gen_conv ON message_chunks(generation_id, conversation_id);
CREATE TABLE IF NOT EXISTS chunk_holes (generation_id INTEGER NOT NULL REFERENCES embedding_generations(id), message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, chunk_idx INTEGER NOT NULL, detected_at INTEGER NOT NULL, reason TEXT, PRIMARY KEY(generation_id, message_id, chunk_idx));
CREATE TABLE IF NOT EXISTS chunk_staging (batch_id INTEGER NOT NULL, generation_id INTEGER NOT NULL REFERENCES embedding_generations(id), message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE, conversation_id INTEGER NOT NULL, chunk_idx INTEGER NOT NULL, byte_start INTEGER NOT NULL, byte_end INTEGER NOT NULL, content_hash TEXT NOT NULL, embedding BLOB NOT NULL CHECK(length(embedding) % 4 = 0), norm REAL NOT NULL CHECK(norm > 0), created_at INTEGER NOT NULL, PRIMARY KEY(generation_id, message_id, chunk_idx));
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
            // T4 (plan v5.1): grouped with the 1-4 rejection below under the
            // same SchemaRebuildRequired contract -- a user_version=0,
            // non-empty database (a pre-rusqlite archive, or a half-built
            // database from an interrupted process that never went through
            // a single transaction) is exactly as much "not a database
            // ensure can open in place" as a stale 1-4 database is; both
            // get the same "rebuild from the corpus" story, not two
            // different error shapes for callers to special-case.
            return Err(StorageError::SchemaRebuildRequired { found: 0, required: CURRENT_SCHEMA_VERSION });
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
        // T4 (plan v5.1): v5 is rebuild-only. Versions 1-4 predate the
        // chunk-table shape and are no longer incrementally migrated in
        // place (the v1->v2->v3->v4 DDL ladder above this comment, in
        // earlier revisions of this function, is retired along with this
        // branch) -- the caller's story for a pre-v5 database is "rebuild
        // from the corpus" (T12), not "convert this file". `version == 0 &&
        // non-empty` is handled above this branch and already rejects the
        // same way; this covers `1 <= version < CURRENT_SCHEMA_VERSION`.
        return Err(StorageError::SchemaRebuildRequired { found: version, required: CURRENT_SCHEMA_VERSION });
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
/// Find the newest `embedding_generations` row whose identity
/// (`embedder_id`+`dim`+`canonicalize_version`) matches exactly and whose
/// `audit_status` is `'pending'`, if any (w3-3 Step0/Step1 design ruling
/// ②). A catch-up worker calls this before deciding whether to create a
/// new generation: an identity match means there is already an
/// in-progress (or demoted-back-to-pending, R4-N... `demote_active_
/// generation_readiness_in_tx`) generation for this exact model, and its
/// `embedding_holes` are the worker's queue to keep draining rather than
/// abandoning hours of prior embedding work. A generation with a
/// *different* identity (model/dim/canonicalize upgrade) never matches
/// here and is intentionally left behind as-is -- W3-5's orphan-generation
/// collection, not this function's job.
///
/// `is_active` is deliberately NOT filtered: an already-active generation
/// can legitimately be `'pending'` again (new writes demoted it), and
/// resuming its holes is exactly the right behavior, not a special case.
pub fn find_reusable_pending_generation(
    conn: &Conn,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
) -> Result<Option<i64>, StorageError> {
    conn.query_opt_map(
        "SELECT id FROM embedding_generations \
         WHERE embedder_id = ?1 AND dim = ?2 AND canonicalize_version = ?3 \
           AND audit_status = 'pending' \
         ORDER BY id DESC LIMIT 1",
        &params![embedder_id, dim, i64::from(canonicalize_version)],
        |row| row.get_typed(0),
    )
}

/// Find the currently *active* `embedding_generations` row whose identity
/// (`embedder_id`+`dim`+`canonicalize_version`) matches exactly, if any
/// (R1-W3-N3). A catch-up worker started on a steady-state, fully-`passed`
/// corpus previously found no match here at all -- `find_reusable_pending_
/// generation` only ever looks at `audit_status='pending'`, and a
/// `passed`, `is_active=1` generation with zero outstanding holes stays
/// `passed` until a genuinely new message demotes it -- so the worker
/// created a brand-new, empty-holes generation and re-seeded + re-embedded
/// the *entire* corpus from scratch every run, which is exactly what makes
/// an hourly production cron model impossible. Checking for an
/// identity-matching active generation *first* (regardless of whether its
/// current `audit_status` is `passed` -- the steady-state case this
/// exists for -- or `pending` if new messages already demoted it, in
/// which case this and `find_reusable_pending_generation` would find the
/// same row; `failed` is the one status excluded below, R2-B7) lets the
/// worker resume draining the generation actually serving
/// reads: its `embedding_holes` are hole-driven and already correctly
/// incremental (new messages only ever register a hole against whichever
/// generation is currently active), so reusing it needs no new drain
/// logic, only this different generation-selection step.
/// R2-B7: `audit_status = 'failed'` is excluded -- a re-audit
/// (`run_activation_audit_and_record`) can flip an already-`is_active`
/// generation to `'failed'` (e.g. a corrupted BLOB found after the fact)
/// without touching `is_active` itself (that function's own contract: a
/// re-audit only upgrades/demotes certification, never picks which
/// generation serves reads). Reusing that row here would keep draining new
/// holes into a generation already known to be broken, permanently
/// self-locking it out of ever becoming clean -- there is no amount of
/// incremental catch-up that fixes BLOBs already written wrong. Excluding
/// it routes the caller to `find_reusable_pending_generation` or a fresh
/// generation instead, so a full rebuild actually happens; the old
/// failed-active row is untouched here and keeps serving reads (this
/// function's own doc comment above: `is_active` is a separate concern)
/// until the new candidate passes audit and `switch_active_generation`
/// flips the pointer.
pub fn find_active_generation_matching_identity(
    conn: &Conn,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
) -> Result<Option<i64>, StorageError> {
    conn.query_opt_map(
        "SELECT id FROM embedding_generations \
         WHERE embedder_id = ?1 AND dim = ?2 AND canonicalize_version = ?3 \
           AND is_active = 1 AND audit_status != 'failed' \
         LIMIT 1",
        &params![embedder_id, dim, i64::from(canonicalize_version)],
        |row| row.get_typed(0),
    )
}

/// Bulk-seed `embedding_holes` for `generation_id` from a caller-supplied
/// list of already-eligible `doc_id`s (w3-3 Step0/Step1: genesis backfill
/// bootstrap). `register_embedding_hole_for_new_message_in_tx` only fires
/// for messages inserted *after* a generation exists -- it has no way to
/// retroactively register holes for a corpus that predates the
/// generation, which is exactly genesis backfill's starting condition.
///
/// The caller is responsible for eligibility filtering (w3-3 Step0's
/// eligibility chain, `packet.projections.semantic.message_indices` plus
/// the caller's own canonicalize-non-empty check -- R1-W3-N3 forbids
/// seeding a hole for a `doc_id` that can never resolve to a real
/// embedding).
///
/// Idempotent and safe to call repeatedly, including against a
/// resumed generation that already fully or partially embedded some of
/// `doc_ids` (w3-3 Step0's "no resume machinery" design: a caller does
/// not need to know what a prior run already finished before calling
/// this again) -- `NOT EXISTS` against `message_embeddings` skips any
/// `doc_id` already embedded under `generation_id` (re-seeding its hole
/// would otherwise resurrect a hole this generation already resolved,
/// and the worker's next pass would then hit `message_embeddings`'s
/// `UNIQUE (generation_id, doc_id)` trying to embed it a second time),
/// and `INSERT OR IGNORE` skips any `doc_id` whose hole is already
/// pending from an unfinished prior run.
///
/// Returns the number of rows this call actually inserted (rows already
/// present, or already embedded, are not recounted).
pub fn seed_embedding_holes(
    tx: &Tx,
    generation_id: i64,
    doc_ids: &[i64],
    detected_at_ms: i64,
    reason: &str,
) -> Result<u64, StorageError> {
    let mut inserted = 0u64;
    for &doc_id in doc_ids {
        let changed = tx.execute(
            "INSERT OR IGNORE INTO embedding_holes (generation_id, doc_id, detected_at, reason) \
             SELECT ?1, ?2, ?3, ?4 \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM message_embeddings \
                 WHERE generation_id = ?1 AND doc_id = ?2 \
             )",
            &params![generation_id, doc_id, detected_at_ms, reason],
        )?;
        inserted = inserted.saturating_add(u64::try_from(changed).unwrap_or(0));
    }
    Ok(inserted)
}

/// The `chunking_policy_version` a legacy (pre-T2) generation is stamped
/// with (T4, plan v5.1): `0` is not a real chunking policy (T2's
/// `CHUNKING_POLICY_VERSION` starts at `1`), so it can never collide with a
/// real one, and it lets [`find_active_generation_matching_identity_v5`]/
/// [`find_reusable_pending_generation_v5`] exclude legacy rows by a plain
/// `chunking_policy_version != 0` (or `> 0`) filter rather than a nullable
/// column.
pub const LEGACY_CHUNKING_POLICY_VERSION: u32 = 0;

/// The `fingerprint` a legacy (pre-T2) generation is stamped with (T4, plan
/// v5.1) -- `fingerprint BLOB NOT NULL` has no default, so a row must carry
/// *something*; this literal marks it as never having gone through T2's
/// real fingerprinting.
pub const LEGACY_GENERATION_FINGERPRINT: &[u8] = b"legacy-v4";

/// **Deprecated thin wrapper (T4, plan v5.1): kept only so pre-T4 call
/// sites keep compiling until T11 deletes it.** Writes
/// `chunking_policy_version = `[`LEGACY_CHUNKING_POLICY_VERSION`]` (`0`) and
/// `fingerprint = `[`LEGACY_GENERATION_FINGERPRINT`]` explicitly (the
/// columns have no DDL default) so the row is well-formed but permanently
/// invisible to [`find_active_generation_matching_identity_v5`]/
/// [`find_reusable_pending_generation_v5`], which both require
/// `chunking_policy_version` to match a real (non-zero) requested value.
/// New call sites must use [`create_embedding_generation_v5`] instead.
#[deprecated(note = "removed in T11")]
pub fn create_embedding_generation(
    tx: &Tx,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
    created_at_ms: i64,
) -> Result<i64, StorageError> {
    tx.execute(
        "INSERT INTO embedding_generations \
         (embedder_id, dim, canonicalize_version, chunking_policy_version, fingerprint, byte_order, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &params![
            embedder_id,
            dim,
            i64::from(canonicalize_version),
            i64::from(LEGACY_CHUNKING_POLICY_VERSION),
            LEGACY_GENERATION_FINGERPRINT.to_vec(),
            VECTOR_BYTE_ORDER_LE,
            created_at_ms
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// T4 (plan v5.1): identity now also includes `chunking_policy_version`
/// (T2's `CHUNKING_POLICY_VERSION`), and every row must carry a real,
/// non-empty `fingerprint` (three-sentinel cosine-similarity identity per
/// the plan's parameter-freeze table). `fingerprint.is_empty()` is rejected
/// with `Constraint` rather than silently accepted -- an empty fingerprint
/// can never be meaningfully compared against a future re-fingerprint, so
/// it is never a legitimate value, not even for a brand-new generation.
/// Returns the new row's `id`.
pub fn create_embedding_generation_v5(
    tx: &Tx,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
    chunking_policy_version: u32,
    fingerprint: &[u8],
    created_at_ms: i64,
) -> Result<i64, StorageError> {
    if fingerprint.is_empty() {
        return Err(StorageError::Constraint {
            detail: "fingerprint must not be empty".to_string(),
        });
    }
    tx.execute(
        "INSERT INTO embedding_generations \
         (embedder_id, dim, canonicalize_version, chunking_policy_version, fingerprint, byte_order, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        &params![
            embedder_id,
            dim,
            i64::from(canonicalize_version),
            i64::from(chunking_policy_version),
            fingerprint.to_vec(),
            VECTOR_BYTE_ORDER_LE,
            created_at_ms
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// T4 (plan v5.1) sibling of [`find_active_generation_matching_identity`]:
/// identity now includes `chunking_policy_version`, and legacy rows (stamped
/// `chunking_policy_version = 0` by the deprecated
/// [`create_embedding_generation`] wrapper) never match here since callers
/// always pass a real (non-zero) policy version -- `chunking_policy_version
/// = ?4` with `?4` bound to a real value structurally excludes `0` rows,
/// no separate filter needed. Returns `(id, fingerprint)` so a caller can
/// compare the stored fingerprint against a freshly computed one without a
/// second round trip.
pub fn find_active_generation_matching_identity_v5(
    conn: &Conn,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
    chunking_policy_version: u32,
) -> Result<Option<(i64, Vec<u8>)>, StorageError> {
    conn.query_opt_map(
        "SELECT id, fingerprint FROM embedding_generations \
         WHERE embedder_id = ?1 AND dim = ?2 AND canonicalize_version = ?3 \
           AND chunking_policy_version = ?4 AND is_active = 1 AND audit_status != 'failed' \
         LIMIT 1",
        &params![
            embedder_id,
            dim,
            i64::from(canonicalize_version),
            i64::from(chunking_policy_version)
        ],
        |row| Ok((row.get_typed::<i64>(0)?, row.get_typed::<Vec<u8>>(1)?)),
    )
}

/// T4 (plan v5.1) sibling of [`find_reusable_pending_generation`]: same
/// `chunking_policy_version = ?4` structural exclusion of legacy
/// (policy-`0`) rows as
/// [`find_active_generation_matching_identity_v5`] above. Returns `(id,
/// fingerprint)`.
pub fn find_reusable_pending_generation_v5(
    conn: &Conn,
    embedder_id: &str,
    dim: i64,
    canonicalize_version: u32,
    chunking_policy_version: u32,
) -> Result<Option<(i64, Vec<u8>)>, StorageError> {
    conn.query_opt_map(
        "SELECT id, fingerprint FROM embedding_generations \
         WHERE embedder_id = ?1 AND dim = ?2 AND canonicalize_version = ?3 \
           AND chunking_policy_version = ?4 AND audit_status = 'pending' \
         ORDER BY id DESC LIMIT 1",
        &params![
            embedder_id,
            dim,
            i64::from(canonicalize_version),
            i64::from(chunking_policy_version)
        ],
        |row| Ok((row.get_typed::<i64>(0)?, row.get_typed::<Vec<u8>>(1)?)),
    )
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

/// Recall-filter metadata *view* version (R4-N1, w3-3 Step 2, plan §3.1
/// "含召回过滤元数据视图版本口径"): a single global constant, **not** a
/// per-row derived value. It versions the *definition* of which message
/// fields feed [`insert_message_embedding_cas`]'s staleness check (today:
/// `content` + `role`) — bump it only when that definition itself changes
/// (e.g. a future field joins the check), never per message. Per-message
/// `content`/`role` drift is already caught by the dedicated hash/equality
/// comparisons in [`insert_message_embedding_cas`]; this constant lets a
/// *view* change (not a *row* change) be told apart from those, so rows
/// written under an older view definition remain identifiable.
///
/// **Bump discipline**: any change to the staleness-check field set in
/// [`insert_message_embedding_cas`] must increment this constant in the
/// same commit.
pub const RECALL_FILTER_METADATA_VIEW_VERSION: i64 = 1;

/// Why a message's content-hash-plus-role went stale before `insert_message_embedding_cas` ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasStaleReason {
    /// `doc_id` no longer exists in `messages` — deleted (replace/forget/
    /// dedup/purge, `ON DELETE CASCADE` already removed any prior embedding
    /// row for it) between the worker's read and this write.
    MessageMissing,
    /// `messages.content` changed under the worker: the freshly recomputed
    /// hash does not match what the caller embedded.
    ContentChanged { expected_content_hash: String, current_content_hash: String },
    /// `messages.role` changed under the worker (R4-N1: role/agent-scoped
    /// filter metadata changing must invalidate the same way content does).
    RoleChanged { expected_role: String, current_role: String },
}

/// Outcome of a CAS-guarded embedding insert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasInsertOutcome {
    Inserted,
    /// Discarded, not written. The caller (async embedding worker) is
    /// responsible for re-queuing `doc_id` for a fresh embedding pass — this
    /// function never writes a stale vector and never blocks waiting for
    /// one.
    Stale(CasStaleReason),
}

/// CAS-guarded [`insert_message_embedding`] (R3-B2, w3-3 Step 2): the async
/// embedding worker reads a message's `content`/`role`, spends real
/// wall-clock time computing the embedding, then comes back to write it. If
/// the source row changed in between ("读旧内容→源更新→旧结果迟到"),
/// writing the now-stale vector would silently poison the vector domain
/// with a result nobody asked for, and nothing would ever notice it needs
/// re-embedding.
///
/// This function re-reads `messages.content`/`role` for `doc_id` **inside
/// the same write transaction** as the insert. SQLite's single-writer model
/// (this crate's D2 concurrency contract) makes that read-then-write
/// atomic — no other transaction can interleave a write to this row between
/// the `SELECT` and the `INSERT` below — so the comparison below is a true
/// compare-and-set, not a check that can itself race. `expected_content_hash`
/// must be `content_hash_hex(canonicalize_for_embedding(content))` computed
/// by the caller when it read the content it embedded (same recipe this
/// function uses to recompute the current value); `expected_role` is the
/// raw `messages.role` string the caller read at that time.
///
/// Returns `Ok(CasInsertOutcome::Stale(..))` — never an `Err` — for every
/// staleness case this function itself detects (message deleted / content
/// changed / role changed): discarding a stale write is expected, routine
/// behavior for an async worker racing relational writers, not a failure.
///
/// On success (w3-3 Step 4, R4-B5), also resolves — in this same
/// transaction — any `embedding_holes` row previously registered for
/// `(generation_id, doc_id)` (a no-op `DELETE` if none exists, e.g. this is
/// a first-pass embed with no catch-up gap involved). The hole ledger is
/// this crate's completeness watermark (R4-B5 forbids a single-max-id
/// watermark precisely because it misses holes left behind by out-of-order
/// catch-up retries); resolving a hole is therefore as much a part of "the
/// write" as the embedding row itself, and a crash between committing the
/// embedding and resolving its hole would leave completeness tracking
/// wrong in either direction — hence one transaction, not two.
#[allow(clippy::too_many_arguments)]
pub fn insert_message_embedding_cas(
    tx: &Tx,
    generation_id: i64,
    doc_id: i64,
    conversation_id: i64,
    vector: &[f32],
    expected_content_hash: &str,
    expected_role: &str,
    created_at_ms: i64,
) -> Result<CasInsertOutcome, StorageError> {
    let current = tx.query_opt_map(
        "SELECT content, role FROM messages WHERE id = ?1",
        &params![doc_id],
        |row| -> Result<(String, String), StorageError> {
            Ok((row.get_typed::<String>(0)?, row.get_typed::<String>(1)?))
        },
    )?;
    let Some((current_content, current_role)) = current else {
        return Ok(CasInsertOutcome::Stale(CasStaleReason::MessageMissing));
    };

    let current_content_hash = crate::search::canonicalize::content_hash_hex(
        &crate::search::canonicalize::canonicalize_for_embedding(&current_content),
    );
    if current_content_hash != expected_content_hash {
        return Ok(CasInsertOutcome::Stale(CasStaleReason::ContentChanged {
            expected_content_hash: expected_content_hash.to_string(),
            current_content_hash,
        }));
    }
    if current_role != expected_role {
        return Ok(CasInsertOutcome::Stale(CasStaleReason::RoleChanged {
            expected_role: expected_role.to_string(),
            current_role,
        }));
    }

    match insert_message_embedding(
        tx,
        generation_id,
        doc_id,
        conversation_id,
        vector,
        expected_content_hash,
        Some(RECALL_FILTER_METADATA_VIEW_VERSION),
        created_at_ms,
    ) {
        Ok(()) => {
            // w3-3 Step 4 (R4-B5): resolving a hole is completeness-tracking
            // state, exactly like the hole's own registration -- it must
            // commit atomically with the embedding row it resolves, in this
            // same transaction, not as a separate follow-up write a crash
            // between the two could leave inconsistent (an embedding row
            // with no matching resolved-hole update, or vice versa).
            // `DELETE ... WHERE` matching zero rows (no hole was ever
            // registered for this doc_id/generation, e.g. it was embedded
            // on the first pass with no catch-up involved) is a correct
            // no-op, not an error.
            tx.execute(
                "DELETE FROM embedding_holes WHERE generation_id = ?1 AND doc_id = ?2",
                &params![generation_id, doc_id],
            )?;
            Ok(CasInsertOutcome::Inserted)
        }
        // Defense in depth, not the primary guard: the read-check above
        // already makes this branch unreachable under the single-writer
        // model documented on this function (nothing can delete `doc_id`
        // between our SELECT and this INSERT within one transaction). It
        // exists so that IF a future refactor ever split the read and the
        // write across transactions, a late `FOREIGN KEY constraint failed`
        // here still degrades to the same graceful `Stale` signal instead
        // of propagating as a fatal error that would abort an entire
        // catch-up batch over one message that lost its race.
        Err(StorageError::Constraint { detail }) if detail_indicates_foreign_key_violation(&detail) => {
            Ok(CasInsertOutcome::Stale(CasStaleReason::MessageMissing))
        }
        Err(e) => Err(e),
    }
}

fn detail_indicates_foreign_key_violation(detail: &str) -> bool {
    detail.to_ascii_uppercase().contains("FOREIGN KEY")
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
/// R2-B3(a): before this fix, an UPDATE against a nonexistent
/// `new_generation_id` still reported `Ok(())` (SQLite's `UPDATE` against
/// zero matching rows is not an error) -- after already having cleared
/// `is_active` on the real, previously-active row, leaving the database
/// with NO active generation at all and the caller none the wiser. This
/// checks the target's existence in the same transaction, *before*
/// touching the current active pointer, and separately confirms the
/// activating `UPDATE` itself actually changed exactly one row -- either
/// failure aborts the whole transaction (SQLite rolls back both `UPDATE`s
/// together), so the old active generation is provably left intact.
pub fn switch_active_generation(
    conn: &Conn,
    new_generation_id: i64,
    activated_at_ms: i64,
    verify: impl FnOnce(&Tx) -> Result<(), StorageError>,
) -> Result<(), StorageError> {
    conn.with_tx_no_replay(TxMode::Immediate, |tx| {
        verify(tx)?;
        let target_exists: i64 = tx.query_row_map(
            "SELECT COUNT(*) FROM embedding_generations WHERE id = ?1",
            &params![new_generation_id],
            |row| row.get_typed(0),
        )?;
        if target_exists == 0 {
            return Err(StorageError::Constraint {
                detail: format!(
                    "switch_active_generation: target generation {new_generation_id} does not \
                     exist; refusing to switch (R2-B3)"
                ),
            });
        }
        tx.execute("UPDATE embedding_generations SET is_active = 0 WHERE is_active = 1", &[])?;
        let changed = tx.execute(
            "UPDATE embedding_generations SET is_active = 1, activated_at = ?1 WHERE id = ?2",
            &params![activated_at_ms, new_generation_id],
        )?;
        if changed != 1 {
            return Err(StorageError::Constraint {
                detail: format!(
                    "switch_active_generation: expected to activate exactly 1 row for generation \
                     {new_generation_id}, changed {changed} (R2-B3)"
                ),
            });
        }
        Ok(())
    })
}

/// R1-W3-B2: cheap in-transaction re-verification of the two invariants a
/// concurrent writer could have invalidated between the full activation
/// audit (necessarily out-of-transaction -- an expensive multi-query audit
/// must not hold a write lock open for its whole duration) reading them
/// and this transaction's pointer flip. Not a second full audit: just the
/// O(1) recheck that is actually worth the write-lock hold time.
///
/// Meant to be called as (or from) [`switch_active_generation`]'s `verify`
/// closure, with `pre_audit_watermark_message_id` set to `SELECT
/// COALESCE(MAX(id), 0) FROM messages` and `pre_audit_message_count` set to
/// `SELECT COUNT(*) FROM messages`, both read *before* the full audit ran.
/// An `Err` here aborts the whole switch transaction -- the pointer flip
/// and the `audit_status='passed'` write the caller's closure typically
/// makes alongside this call never happen -- so the caller's next call
/// re-scans and re-audits `new_generation_id` from scratch; no
/// partial/stale promotion is ever committed.
///
/// Three invariants, all cheap:
/// - `embedding_holes` for `new_generation_id` must still be empty (a
///   fresh `COUNT`, not the audit's now-stale read).
/// - `messages`' high-water mark must not have grown since the audit
///   started. Growth means a message landed while this candidate
///   generation was not yet active -- ingest-time hooks only register a
///   hole against the *currently active* generation, so this candidate
///   would never have gotten a hole for it and would otherwise be
///   promoted still silently missing that message.
/// - R2-B2: `messages`' row count must not have *shrunk*, closing the gap
///   the watermark alone leaves open -- a concurrent delete of a
///   non-max-id message (forget/purge) doesn't move `MAX(id)` at all, so
///   the watermark check alone would miss it. This candidate generation
///   still carries an embedding for the now-deleted doc_id (its hole was
///   already resolved before the delete, or it was never eligible to
///   begin with), so promoting it anyway would activate an index with a
///   stale row check ④'s eligibility anti-join has no way to catch after
///   the fact (the deleted message can no longer even be read back to
///   compare against). Deliberately just a row count, not a full
///   corpus-mutation epoch/generation counter (control-plane-adjudicated
///   REJECTED as over-engineering for this call site: insert is caught by
///   the watermark, delete by this count, and in-place content edits have
///   no production write path at all per w3-3 Step 3's write-entry-point
///   survey -- the three together already cover every mutation shape that
///   actually exists, so a generalized epoch mechanism would be tracking
///   mutation shapes this codebase cannot produce).
pub fn verify_no_activation_toctou_drift_in_tx(
    tx: &Tx,
    generation_id: i64,
    pre_audit_watermark_message_id: i64,
    pre_audit_message_count: i64,
) -> Result<(), StorageError> {
    let holes_now: i64 = tx.query_row_map(
        "SELECT COUNT(*) FROM embedding_holes WHERE generation_id = ?1",
        &params![generation_id],
        |row| row.get_typed(0),
    )?;
    if holes_now != 0 {
        return Err(StorageError::Constraint {
            detail: format!(
                "generation {generation_id} gained {holes_now} embedding_holes row(s) between \
                 the activation audit and this switch transaction; refusing to activate \
                 (TOCTOU guard, R1-W3-B2)"
            ),
        });
    }
    let watermark_now: i64 =
        tx.query_row_map("SELECT COALESCE(MAX(id), 0) FROM messages", &[], |row| row.get_typed(0))?;
    if watermark_now != pre_audit_watermark_message_id {
        return Err(StorageError::Constraint {
            detail: format!(
                "messages high-water mark drifted from {pre_audit_watermark_message_id} to \
                 {watermark_now} between the activation audit and this switch transaction; \
                 refusing to activate generation {generation_id} (TOCTOU guard, R1-W3-B2)"
            ),
        });
    }
    let count_now: i64 = tx.query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))?;
    if count_now != pre_audit_message_count {
        return Err(StorageError::Constraint {
            detail: format!(
                "messages row count drifted from {pre_audit_message_count} to {count_now} between \
                 the activation audit and this switch transaction (a deletion the watermark alone \
                 cannot see); refusing to activate generation {generation_id} (TOCTOU guard, R2-B2)"
            ),
        });
    }
    Ok(())
}

// -------------------------------------------------------------------------
// w3-3 Step 3 (spec 门③, R2-W3-B4): same-transaction lifecycle invalidation
// primitives. `ON DELETE CASCADE` on `message_embeddings.doc_id` and
// `embedding_holes.doc_id` already removes both rows for a deleted message
// as a structural side effect of the `DELETE FROM messages` statement
// itself (no code below does that part) — what CASCADE cannot do is (a)
// register a hole for a *newly inserted* message id (nothing about an
// `INSERT INTO messages` implies "this needs an embedding" to SQLite) or
// (b) demote a generation's certified-ready status when the message set it
// was certified against has since changed. Both of those are this module's
// job, and per R2-W3-B4 they must run in the *same* transaction as the
// relational write — the async catch-up worker has no way to retroactively
// join an already-committed transaction.
// -------------------------------------------------------------------------

/// Register `doc_id` as needing an embedding under the currently active
/// generation, if one exists. Called for every newly inserted message
/// (w3-3 Step 3, A类/B类 write entry points) in the same transaction as the
/// `INSERT INTO messages` that created it.
///
/// No-op when there is no active generation (bootstrap / vector domain not
/// yet activated) — there is nothing to register a hole against, and that
/// is the overwhelmingly common case for every write entry point that does
/// not yet involve the vector domain at all (unaffected by this call).
/// `INSERT OR IGNORE` makes re-registering the same `(generation_id,
/// doc_id)` pair idempotent, matching the table's own doc comment.
pub fn register_embedding_hole_for_new_message_in_tx(
    tx: &Tx,
    doc_id: i64,
    detected_at_ms: i64,
    reason: &str,
) -> Result<(), StorageError> {
    let active: Option<i64> =
        tx.query_opt_map("SELECT id FROM embedding_generations WHERE is_active = 1", &[], |row| row.get_typed(0))?;
    let Some(generation_id) = active else {
        return Ok(());
    };
    tx.execute(
        "INSERT OR IGNORE INTO embedding_holes (generation_id, doc_id, detected_at, reason) \
         VALUES (?1, ?2, ?3, ?4)",
        &params![generation_id, doc_id, detected_at_ms, reason],
    )?;
    Ok(())
}

/// Write off (delete) an `embedding_holes` row for `doc_id` under
/// `generation_id` once the catch-up drain loop has confirmed the message
/// is *ineligible* for embedding (canonicalizes to an empty string, e.g. a
/// short acknowledgement like "OK." -- `register_embedding_hole_for_new_
/// message_in_tx` above registers a hole for every new message
/// unconditionally, with no eligibility filter of its own, R1-W3-B1).
///
/// The hole ledger's contract is an exact accounting of *eligible*
/// messages awaiting embedding, not of every message that ever existed --
/// an ineligible message can never resolve its hole through the normal
/// embed-and-CAS-write path (`insert_message_embedding_cas` only deletes a
/// hole on a successful embedding write), so leaving it registered would
/// keep `holes_after` permanently above zero and self-lock the generation
/// out of activation forever (the exact failure `run_db_vector_catchup_
/// backfill`'s draining loop must not reproduce). A no-op `DELETE` if the
/// hole was already resolved or never existed. Returns the number of rows
/// actually deleted (0 or 1) -- task book #81 R2-N4, same discipline as
/// [`prune_ineligible_message_embedding_in_tx`]'s R1-N3 fix: a caller
/// tallying `holes_written_off_ineligible` must report what was actually
/// affected, not the size of a candidate list computed before this ran.
pub fn write_off_ineligible_hole_in_tx(tx: &Tx, generation_id: i64, doc_id: i64) -> Result<u64, StorageError> {
    let affected = tx.execute(
        "DELETE FROM embedding_holes WHERE generation_id = ?1 AND doc_id = ?2",
        &params![generation_id, doc_id],
    )?;
    Ok(u64::try_from(affected).unwrap_or(0))
}

/// Prune a `message_embeddings` row that was embedded but has since fallen
/// out of the eligibility chain (task book #80, exec72) -- the reverse of
/// [`write_off_ineligible_hole_in_tx`] above (that one retires a hole for a
/// message that was *never* eligible; this one retires an already-written
/// embedding for a message that *used to be* eligible and no longer is,
/// most commonly a conversation's cumulative content crossing the shared
/// per-conversation content cap -- `FrankenStorage::fetch_messages_for_
/// lexical_rebuild`'s truncation, #290 -- which silently clears an
/// already-embedded tail message's content out of the same eligibility
/// scan that cap was never designed to gate).
///
/// Left in place, such a row makes activation audit ④'s bidirectional
/// anti-join (`embedded_not_eligible_count` in `db_vector_catchup.rs`)
/// permanently non-zero -- `run_db_vector_catchup_backfill`'s hole-driven
/// drain loop only ever grows `message_embeddings` toward the eligible set
/// and has no path that shrinks it back, so nothing else in this codebase
/// would ever delete this row. Callers do not need a matching `vec0`-side
/// delete: `run_db_vector_catchup_backfill` unconditionally calls
/// `vector_domain::rebuild_vec0_table_for_generation` right after its own
/// reverse-reconciliation step, which fully repopulates `vec0` from
/// `message_embeddings` in one drop+recreate+bulk-insert transaction, so a
/// row deleted here before that call never makes it into the rebuilt
/// index.
///
/// A no-op `DELETE` if the row was already gone (idempotent, matching
/// `write_off_ineligible_hole_in_tx`'s style). Returns the number of rows
/// actually deleted (0 or 1, `UNIQUE(generation_id, doc_id)`) -- R1-N3:
/// callers must report what was actually affected, not the size of a
/// candidate list computed before this ran, since a concurrent writer
/// could have already resolved/deleted the same row in between.
pub fn prune_ineligible_message_embedding_in_tx(tx: &Tx, generation_id: i64, doc_id: i64) -> Result<u64, StorageError> {
    let affected = tx.execute(
        "DELETE FROM message_embeddings WHERE generation_id = ?1 AND doc_id = ?2",
        &params![generation_id, doc_id],
    )?;
    Ok(u64::try_from(affected).unwrap_or(0))
}

/// Demote the active generation's certified-ready status (`audit_status`)
/// back to `'pending'`, if one exists and is not already `'pending'`.
/// Called in the same transaction as any relational write that mutates the
/// `messages` set a generation's `'passed'` audit_status certified
/// completeness against (w3-3 Step 3, all four lifecycle categories:
/// insert/更新(=replace)/delete/replace) — the mutation may have just
/// broken that certification (a new message with no embedding yet exists,
/// or a message the certification covered no longer does), so the claim
/// must not survive uninvalidated. Intentionally unconditional (not
/// case-by-case per mutation kind): over-invalidating just means W3-4's
/// activation audit re-verifies before the next promotion, which is cheap.
///
/// **Known behavioral debt (R1-W3-B3, 2026-09-02 round-1 review, disclosed
/// to Ivan, DEFERRED not fixed by task book #68):** demoting to
/// `'pending'` here does *not* stop this generation from continuing to
/// serve reads. `search_db_vector_domain` (`src/search/query.rs`) gates
/// solely on `is_active = 1` and never consults `audit_status` at read
/// time, so a demoted-but-still-active generation keeps answering queries
/// off its now-uncertified `vec0` index -- this function only ever blocks
/// *re-promotion* (the next activation audit must re-pass before
/// `audit_status` can read `'passed'` again), it does not gate *current*
/// service. The accepted tradeoff (same family as R1-W3-N6's daemon-
/// acceptance debt): hard-blocking search on `audit_status` would make the
/// vector domain unavailable for the entire ingest-to-catchup gap on every
/// single write, which is availability-hostile for a corpus under active
/// use; serving a brief coverage-gap window is the deliberate choice
/// instead. Not a false claim of correctness -- see W3-4's own six/seven-
/// invariant audit, which this demotion feeds -- but a real staleness
/// window a reader should know this function does not close.
///
/// No-op when there is no active generation, or the active generation is
/// already `'pending'` — the common case for every write entry point that
/// does not yet involve the vector domain at all.
pub fn demote_active_generation_readiness_in_tx(tx: &Tx) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE embedding_generations SET audit_status = 'pending' \
         WHERE is_active = 1 AND audit_status != 'pending'",
        &[],
    )?;
    Ok(())
}

/// Like [`demote_active_generation_readiness_in_tx`], but scoped to one
/// specific `generation_id` -- task book #81 R2-N3: the unscoped version
/// demotes *whatever* generation currently holds `is_active = 1`, which is
/// exactly right for the write entry points above (they always mutate
/// against the active generation, by construction). A caller that instead
/// knows the specific `generation_id` its own mutation targeted --
/// [`prune_ineligible_message_embedding_in_tx`]'s caller, in particular --
/// must not reach for the unscoped version: if that `generation_id` is
/// ever a *not-yet-active* candidate (a real generation reuse/upgrade
/// scenario, ruling ②) while some *other* generation is the currently
/// active one, the unscoped version would demote the wrong (currently
/// serving) generation instead of leaving it alone. This version demotes
/// `generation_id` if and only if it is both the row this call means to
/// touch and the currently active one.
///
/// No-op when `generation_id` is not active, or is already `'pending'`.
pub fn demote_generation_readiness_if_active_in_tx(tx: &Tx, generation_id: i64) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE embedding_generations SET audit_status = 'pending' \
         WHERE id = ?1 AND is_active = 1 AND audit_status != 'pending'",
        &params![generation_id],
    )?;
    Ok(())
}

// =============================================================================
// Chunk domain (T4, plan v5.1): `message_chunks`/`chunk_holes`/`chunk_staging`,
// span-aware staging/pruning, and the `_v5` generation primitives. Coexists
// with the v4 vector domain above (not wired into any call site here -- T5/
// T6/T8 do that); `message_embeddings`/`embedding_holes` and their `_v4`-era
// (unsuffixed) generation functions are untouched and stay live until T11.
// =============================================================================

/// One row of `message_chunks`/`chunk_staging` (the two tables share this
/// shape; `stage_chunk_rows_in_tx` writes it into staging, `insert_chunk_row_
/// in_tx` writes it directly into `message_chunks`, and `move_staging_to_
/// chunks_in_tx` moves a staged row from one to the other).
#[derive(Clone, Debug)]
pub struct ChunkRow {
    pub generation_id: i64,
    pub message_id: i64,
    pub conversation_id: i64,
    pub chunk_idx: u32,
    pub byte_start: usize,
    pub byte_end: usize,
    pub content_hash: String,
    pub embedding: Vec<f32>,
    pub norm: f32,
    pub created_at_ms: i64,
}

/// Outcome of a bulk-seed call ([`seed_chunk_holes`]). `statements` is
/// logging-only (how many batched `INSERT` statements it took), never a
/// pass/fail gate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SeedOutcome {
    pub rows_inserted: u64,
    pub rows_conflicted: u64,
    pub statements: u64,
}

/// Row cap per batched `INSERT` statement in [`seed_chunk_holes`]. Each row
/// binds 5 parameters, so 1,000 rows is 5,000 bound values per statement --
/// comfortably under SQLite's compiled-in variable limit on any build this
/// crate targets, with headroom to spare (unlike, say, 250,001 rows in one
/// statement, which the T4 mutation test drives past that limit on purpose).
const CHUNK_HOLES_BATCH_ROWS: usize = 1_000;

/// Row cap per batched `IN (...)` statement for the plain lookup/delete
/// helpers below ([`collect_chunk_ids_for_messages`] and friends) -- same
/// motivation as [`CHUNK_HOLES_BATCH_ROWS`], smaller because these bind one
/// parameter per row (plus a fixed few) rather than five.
const IN_CLAUSE_BATCH_ROWS: usize = 500;

fn in_clause_placeholders(n: usize) -> String {
    vec!["?"; n].join(",")
}

/// Bulk-seed `chunk_holes` for `generation_id` from a caller-supplied list
/// of `(message_id, chunk_idx)` pairs (the [`crate::search::eligibility::
/// ExpectedChunk`] key), batching at [`CHUNK_HOLES_BATCH_ROWS`] rows per
/// statement. Each statement is `INSERT ... ON CONFLICT(generation_id,
/// message_id, chunk_idx) DO NOTHING RETURNING message_id` -- idempotent
/// (a hole already registered is silently skipped, not duplicated or
/// errored), and `rows_inserted` is counted from the `RETURNING` set
/// itself (only genuinely-inserted rows appear there), not inferred from a
/// changed-row count that conflicts would also perturb.
pub fn seed_chunk_holes(
    tx: &Tx,
    generation_id: i64,
    holes: &[(i64, u32)],
    detected_at_ms: i64,
    reason: &str,
) -> Result<SeedOutcome, StorageError> {
    let mut outcome = SeedOutcome::default();
    for batch in holes.chunks(CHUNK_HOLES_BATCH_ROWS) {
        if batch.is_empty() {
            continue;
        }
        let mut sql = String::from(
            "INSERT INTO chunk_holes (generation_id, message_id, chunk_idx, detected_at, reason) VALUES ",
        );
        let mut params_vec: Vec<Value> = Vec::with_capacity(batch.len() * 5);
        for (i, (message_id, chunk_idx)) in batch.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push_str("(?,?,?,?,?)");
            params_vec.push(Value::from(generation_id));
            params_vec.push(Value::from(*message_id));
            params_vec.push(Value::from(*chunk_idx));
            params_vec.push(Value::from(detected_at_ms));
            params_vec.push(Value::from(reason.to_string()));
        }
        sql.push_str(
            " ON CONFLICT(generation_id, message_id, chunk_idx) DO NOTHING RETURNING message_id",
        );
        let returned: Vec<i64> = tx.query_all_map(&sql, &params_vec, |row| row.get_typed(0))?;
        outcome.rows_inserted += returned.len() as u64;
        outcome.rows_conflicted += (batch.len() - returned.len()) as u64;
        outcome.statements += 1;
    }
    Ok(outcome)
}

/// Register holes for `expected`'s `(message_id, chunk_idx)` keys against
/// every currently active-or-pending generation (`is_active = 1 OR
/// audit_status = 'pending'`) -- a message content change or a brand-new
/// message needs its expected chunks re-embedded under whichever
/// generation(s) are still live, not just the one the caller happens to be
/// thinking about. No-op (`SeedOutcome::default()`) when there is no such
/// generation, or `expected` is empty.
pub fn register_chunk_holes_for_message_in_tx(
    tx: &Tx,
    expected: &[crate::search::eligibility::ExpectedChunk],
    detected_at_ms: i64,
    reason: &str,
) -> Result<SeedOutcome, StorageError> {
    if expected.is_empty() {
        return Ok(SeedOutcome::default());
    }
    let generation_ids: Vec<i64> = tx.query_all_map(
        "SELECT id FROM embedding_generations WHERE is_active = 1 OR audit_status = 'pending'",
        &[],
        |row| row.get_typed(0),
    )?;
    if generation_ids.is_empty() {
        return Ok(SeedOutcome::default());
    }
    let holes: Vec<(i64, u32)> = expected.iter().map(|c| (c.message_id, c.chunk_idx)).collect();
    let mut outcome = SeedOutcome::default();
    for generation_id in generation_ids {
        let o = seed_chunk_holes(tx, generation_id, &holes, detected_at_ms, reason)?;
        outcome.rows_inserted += o.rows_inserted;
        outcome.rows_conflicted += o.rows_conflicted;
        outcome.statements += o.statements;
    }
    Ok(outcome)
}

/// `chunk_id`s of every `message_chunks` row for `generation_id` whose
/// `message_id` is in `message_ids`. Read-only; batched at
/// [`IN_CLAUSE_BATCH_ROWS`].
pub fn collect_chunk_ids_for_messages(
    tx: &Tx,
    generation_id: i64,
    message_ids: &[i64],
) -> Result<Vec<i64>, StorageError> {
    let mut ids = Vec::new();
    for batch in message_ids.chunks(IN_CLAUSE_BATCH_ROWS) {
        if batch.is_empty() {
            continue;
        }
        let placeholders = in_clause_placeholders(batch.len());
        let sql = format!(
            "SELECT chunk_id FROM message_chunks WHERE generation_id = ? AND message_id IN ({placeholders})"
        );
        let mut params_vec: Vec<Value> = Vec::with_capacity(batch.len() + 1);
        params_vec.push(Value::from(generation_id));
        for id in batch {
            params_vec.push(Value::from(*id));
        }
        let mut page: Vec<i64> = tx.query_all_map(&sql, &params_vec, |row| row.get_typed(0))?;
        ids.append(&mut page);
    }
    Ok(ids)
}

/// Delete `message_chunks` rows by `chunk_id`. Returns the number of rows
/// actually deleted.
pub fn delete_chunks_by_ids_in_tx(tx: &Tx, chunk_ids: &[i64]) -> Result<u64, StorageError> {
    let mut deleted = 0u64;
    for batch in chunk_ids.chunks(IN_CLAUSE_BATCH_ROWS) {
        if batch.is_empty() {
            continue;
        }
        let placeholders = in_clause_placeholders(batch.len());
        let sql = format!("DELETE FROM message_chunks WHERE chunk_id IN ({placeholders})");
        let params_vec: Vec<Value> = batch.iter().map(|id| Value::from(*id)).collect();
        deleted += tx.execute(&sql, &params_vec)? as u64;
    }
    Ok(deleted)
}

/// Delete `chunk_holes` rows for `generation_id` whose `message_id` is in
/// `message_ids`. Returns the number of rows actually deleted.
pub fn delete_chunk_holes_for_messages_in_tx(
    tx: &Tx,
    generation_id: i64,
    message_ids: &[i64],
) -> Result<u64, StorageError> {
    let mut deleted = 0u64;
    for batch in message_ids.chunks(IN_CLAUSE_BATCH_ROWS) {
        if batch.is_empty() {
            continue;
        }
        let placeholders = in_clause_placeholders(batch.len());
        let sql = format!(
            "DELETE FROM chunk_holes WHERE generation_id = ? AND message_id IN ({placeholders})"
        );
        let mut params_vec: Vec<Value> = Vec::with_capacity(batch.len() + 1);
        params_vec.push(Value::from(generation_id));
        for id in batch {
            params_vec.push(Value::from(*id));
        }
        deleted += tx.execute(&sql, &params_vec)? as u64;
    }
    Ok(deleted)
}

/// Delete `chunk_staging` rows for `generation_id` whose `message_id` is in
/// `message_ids`. Returns the number of rows actually deleted.
pub fn delete_staging_for_messages_in_tx(
    tx: &Tx,
    generation_id: i64,
    message_ids: &[i64],
) -> Result<u64, StorageError> {
    let mut deleted = 0u64;
    for batch in message_ids.chunks(IN_CLAUSE_BATCH_ROWS) {
        if batch.is_empty() {
            continue;
        }
        let placeholders = in_clause_placeholders(batch.len());
        let sql = format!(
            "DELETE FROM chunk_staging WHERE generation_id = ? AND message_id IN ({placeholders})"
        );
        let mut params_vec: Vec<Value> = Vec::with_capacity(batch.len() + 1);
        params_vec.push(Value::from(generation_id));
        for id in batch {
            params_vec.push(Value::from(*id));
        }
        deleted += tx.execute(&sql, &params_vec)? as u64;
    }
    Ok(deleted)
}

/// Insert one row directly into `message_chunks` (bypassing staging --
/// callers that already know the row is final, e.g. a first-time embed with
/// no reuse candidate). Returns the new `chunk_id`.
pub fn insert_chunk_row_in_tx(tx: &Tx, row: &ChunkRow) -> Result<i64, StorageError> {
    let blob = f32_vector_to_le_blob(&row.embedding);
    tx.execute(
        "INSERT INTO message_chunks \
         (generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        &params![
            row.generation_id,
            row.message_id,
            row.conversation_id,
            row.chunk_idx,
            row.byte_start as i64,
            row.byte_end as i64,
            row.content_hash.clone(),
            blob,
            f64::from(row.norm),
            row.created_at_ms
        ],
    )?;
    Ok(tx.last_insert_rowid())
}

/// Insert `rows` into `chunk_staging` under `batch_id` (a caller-chosen
/// grouping id -- `move_staging_to_chunks_in_tx` deliberately ignores it and
/// moves by explicit `(message_id, chunk_idx)` key instead, so a batch_id
/// collision or a caller that never learns the batch_id back is harmless).
/// Returns the number of rows inserted.
pub fn stage_chunk_rows_in_tx(tx: &Tx, batch_id: i64, rows: &[ChunkRow]) -> Result<u64, StorageError> {
    let mut inserted = 0u64;
    for row in rows {
        let blob = f32_vector_to_le_blob(&row.embedding);
        let changed = tx.execute(
            "INSERT INTO chunk_staging \
             (batch_id, generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            &params![
                batch_id,
                row.generation_id,
                row.message_id,
                row.conversation_id,
                row.chunk_idx,
                row.byte_start as i64,
                row.byte_end as i64,
                row.content_hash.clone(),
                blob,
                f64::from(row.norm),
                row.created_at_ms
            ],
        )?;
        inserted += changed as u64;
    }
    Ok(inserted)
}

/// Move staged rows into `message_chunks` by explicit `(message_id,
/// chunk_idx)` key -- **not** by `batch_id`: a key may have been staged in
/// an earlier batch than the one that happens to trigger the move (e.g. a
/// reuse candidate discovered later), and moving by key handles that
/// uniformly. A key with nothing currently staged is silently skipped (not
/// an error -- the caller's expected-chunk list and what's actually staged
/// are allowed to diverge; this only moves what it finds). Same transaction
/// also deletes the moved row's `chunk_staging` row and any matching
/// `chunk_holes` row (the hole this chunk was filling is now resolved).
/// Returns the new `chunk_id` for each key that had something staged, in
/// the order `keys` were given (not necessarily the same length as `keys`).
pub fn move_staging_to_chunks_in_tx(
    tx: &Tx,
    generation_id: i64,
    keys: &[(i64, u32)],
) -> Result<Vec<i64>, StorageError> {
    let mut new_chunk_ids = Vec::with_capacity(keys.len());
    for &(message_id, chunk_idx) in keys {
        let staged: Option<(i64, i64, i64, String, Vec<u8>, f64, i64)> = tx.query_opt_map(
            "SELECT conversation_id, byte_start, byte_end, content_hash, embedding, norm, created_at \
             FROM chunk_staging WHERE generation_id = ?1 AND message_id = ?2 AND chunk_idx = ?3",
            &params![generation_id, message_id, chunk_idx],
            |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<i64>(1)?,
                    row.get_typed::<i64>(2)?,
                    row.get_typed::<String>(3)?,
                    row.get_typed::<Vec<u8>>(4)?,
                    row.get_typed::<f64>(5)?,
                    row.get_typed::<i64>(6)?,
                ))
            },
        )?;

        let Some((conversation_id, byte_start, byte_end, content_hash, embedding, norm, created_at)) =
            staged
        else {
            continue;
        };

        tx.execute(
            "INSERT INTO message_chunks \
             (generation_id, message_id, conversation_id, chunk_idx, byte_start, byte_end, content_hash, embedding, norm, created_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            &params![
                generation_id,
                message_id,
                conversation_id,
                chunk_idx,
                byte_start,
                byte_end,
                content_hash,
                embedding,
                norm,
                created_at
            ],
        )?;
        new_chunk_ids.push(tx.last_insert_rowid());

        tx.execute(
            "DELETE FROM chunk_staging WHERE generation_id = ?1 AND message_id = ?2 AND chunk_idx = ?3",
            &params![generation_id, message_id, chunk_idx],
        )?;
        tx.execute(
            "DELETE FROM chunk_holes WHERE generation_id = ?1 AND message_id = ?2 AND chunk_idx = ?3",
            &params![generation_id, message_id, chunk_idx],
        )?;
    }
    Ok(new_chunk_ids)
}

/// Which of `expected`'s chunks already have a matching staged row for
/// `generation_id` -- a match requires **both** `content_hash` and span
/// (`byte_start`/`byte_end`) to agree with the staged row at that
/// `(message_id, chunk_idx)` key, not just the hash (two different spans
/// can coincidentally hash the same short prefix/suffix under a weaker
/// check; span is part of `ExpectedChunk`'s own identity, see
/// `expected_chunk_equality_includes_span` in `eligibility.rs`). A matched
/// row is a genuine reuse candidate: the caller does *not* need to
/// re-embed it, only call [`move_staging_to_chunks_in_tx`] with the
/// returned keys. Does not modify `batch_id` or anything else about the
/// staged row.
pub fn find_reusable_staging_in_tx(
    tx: &Tx,
    generation_id: i64,
    expected: &[crate::search::eligibility::ExpectedChunk],
) -> Result<Vec<(i64, u32)>, StorageError> {
    let mut reusable = Vec::new();
    for chunk in expected {
        let matched: Option<i64> = tx.query_opt_map(
            "SELECT 1 FROM chunk_staging \
             WHERE generation_id = ?1 AND message_id = ?2 AND chunk_idx = ?3 \
               AND content_hash = ?4 AND byte_start = ?5 AND byte_end = ?6",
            &params![
                generation_id,
                chunk.message_id,
                chunk.chunk_idx,
                chunk.content_hash.clone(),
                chunk.byte_start as i64,
                chunk.byte_end as i64
            ],
            |row| row.get_typed(0),
        )?;
        if matched.is_some() {
            reusable.push((chunk.message_id, chunk.chunk_idx));
        }
    }
    Ok(reusable)
}

/// Delete every `chunk_staging` row for `generation_id` whose
/// `(message_id, chunk_idx)` key is **not** in `keep` -- staged rows a
/// re-plan decided it no longer wants (e.g. the message's content changed
/// again before the stale staged embedding was ever moved into
/// `message_chunks`). Returns the number of rows deleted.
pub fn purge_stale_staging_in_tx(
    tx: &Tx,
    generation_id: i64,
    keep: &[(i64, u32)],
) -> Result<u64, StorageError> {
    let all_keys: Vec<(i64, u32)> = tx.query_all_map(
        "SELECT message_id, chunk_idx FROM chunk_staging WHERE generation_id = ?1",
        &params![generation_id],
        |row| Ok((row.get_typed::<i64>(0)?, row.get_typed::<u32>(1)?)),
    )?;
    let keep_set: std::collections::HashSet<(i64, u32)> = keep.iter().copied().collect();
    let mut deleted = 0u64;
    for (message_id, chunk_idx) in all_keys {
        if !keep_set.contains(&(message_id, chunk_idx)) {
            deleted += tx.execute(
                "DELETE FROM chunk_staging WHERE generation_id = ?1 AND message_id = ?2 AND chunk_idx = ?3",
                &params![generation_id, message_id, chunk_idx],
            )? as u64;
        }
    }
    Ok(deleted)
}

/// Delete one specific `chunk_holes` row (the hole for `message_id`'s
/// `chunk_idx` under `generation_id` was resolved by some means other than
/// [`move_staging_to_chunks_in_tx`], which already deletes the hole itself
/// as part of its own transaction). Returns the number of rows deleted (`0`
/// or `1`).
pub fn write_off_chunk_hole_in_tx(
    tx: &Tx,
    generation_id: i64,
    message_id: i64,
    chunk_idx: u32,
) -> Result<u64, StorageError> {
    let changed = tx.execute(
        "DELETE FROM chunk_holes WHERE generation_id = ?1 AND message_id = ?2 AND chunk_idx = ?3",
        &params![generation_id, message_id, chunk_idx],
    )?;
    Ok(changed as u64)
}

/// Delete every `message_chunks` row for `generation_id`+`message_id` whose
/// `(chunk_idx, byte_start, byte_end, content_hash)` does not exactly match
/// one of `expected`'s chunks for that same `message_id` -- content changed
/// underneath an existing chunk set (different chunking, different
/// content_hash, or a shrunk/grown chunk count) leaves stale chunks behind
/// that must go, not linger indexed under a hash/span the current content
/// no longer produces. Any single field mismatch is enough to drop the row
/// (span-aware: two chunks with the same `content_hash` but a different
/// span, e.g. from a chunking-policy edge-case shift, are NOT the same
/// chunk). Returns the deleted `chunk_id`s.
pub fn prune_chunks_not_in_expected_in_tx(
    tx: &Tx,
    generation_id: i64,
    message_id: i64,
    expected: &[crate::search::eligibility::ExpectedChunk],
) -> Result<Vec<i64>, StorageError> {
    let existing: Vec<(i64, u32, i64, i64, String)> = tx.query_all_map(
        "SELECT chunk_id, chunk_idx, byte_start, byte_end, content_hash FROM message_chunks \
         WHERE generation_id = ?1 AND message_id = ?2",
        &params![generation_id, message_id],
        |row| {
            Ok((
                row.get_typed::<i64>(0)?,
                row.get_typed::<u32>(1)?,
                row.get_typed::<i64>(2)?,
                row.get_typed::<i64>(3)?,
                row.get_typed::<String>(4)?,
            ))
        },
    )?;

    let expected_set: std::collections::HashSet<(u32, i64, i64, &str)> = expected
        .iter()
        .filter(|c| c.message_id == message_id)
        .map(|c| (c.chunk_idx, c.byte_start as i64, c.byte_end as i64, c.content_hash.as_str()))
        .collect();

    let mut pruned = Vec::new();
    for (chunk_id, chunk_idx, byte_start, byte_end, content_hash) in existing {
        let key = (chunk_idx, byte_start, byte_end, content_hash.as_str());
        if !expected_set.contains(&key) {
            tx.execute("DELETE FROM message_chunks WHERE chunk_id = ?1", &params![chunk_id])?;
            pruned.push(chunk_id);
        }
    }
    Ok(pruned)
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

    /// **Retired by T4 (plan v5.1), replaced by
    /// `fresh_schema_ddl_v4_message_embeddings_and_holes_survive_verbatim_into_v5`
    /// below.** The premise this test checked -- `FRESH_SCHEMA_DDL`'s tail is
    /// byte-for-byte identical to `V4_VECTOR_DOMAIN_DDL` as a whole -- is now
    /// false by design: T4 adds two `NOT NULL` columns to
    /// `embedding_generations` (`chunking_policy_version`/`fingerprint`) and
    /// appends the new `message_chunks`/`chunk_holes`/`chunk_staging` tables
    /// after it, so `FRESH_SCHEMA_DDL` no longer ends with
    /// `V4_VECTOR_DOMAIN_DDL`'s exact text, nor does that text appear
    /// anywhere else in `FRESH_SCHEMA_DDL` (the `embedding_generations`
    /// statement itself now differs). `V4_VECTOR_DOMAIN_DDL` stays frozen as
    /// the historical v4 shape (still used below to hand-build pre-v5
    /// database fixtures for the `SchemaRebuildRequired` tests), but the
    /// specific "whole-blob tail match" guarantee it used to enforce is gone.
    #[test]
    fn fresh_schema_ddl_v4_message_embeddings_and_holes_survive_verbatim_into_v5() {
        for stmt in V4_VECTOR_DOMAIN_DDL.trim().split(';').map(str::trim).filter(|s| !s.is_empty()) {
            if stmt.contains("message_embeddings") || stmt.contains("embedding_holes") {
                assert!(
                    FRESH_SCHEMA_DDL.contains(stmt),
                    "FRESH_SCHEMA_DDL must still contain this v4 statement verbatim -- T4 keeps \
                     message_embeddings/embedding_holes unchanged until T11 deletes them: {stmt}"
                );
            }
        }
    }

    /// Slice `FRESH_SCHEMA_DDL` at the first byte of the given anchor
    /// statement's `CREATE TABLE` marker, returning everything strictly
    /// before it. T4 (plan v5.1): replaces the old
    /// `strip_suffix(V4_VECTOR_DOMAIN_DDL.trim())`/
    /// `strip_suffix(V2_LEX_DOMAIN_DDL.trim())` technique the three
    /// `ensure_migrates_*` fixtures below used to hand-build pre-v5 database
    /// shapes -- that technique required `FRESH_SCHEMA_DDL`'s tail to be
    /// byte-identical to the migration DDL constants, which T4 breaks
    /// (`embedding_generations` gained two columns, so it no longer matches
    /// `V4_VECTOR_DOMAIN_DDL`'s copy). Anchoring on a stable, unchanged table
    /// name instead works regardless of what changed after that point.
    fn fresh_schema_ddl_before_table_for_test(table_name: &str) -> &'static str {
        let anchor = format!("CREATE TABLE IF NOT EXISTS {table_name} ");
        FRESH_SCHEMA_DDL
            .split_once(&anchor)
            .unwrap_or_else(|| panic!("FRESH_SCHEMA_DDL must contain a `{anchor}` statement"))
            .0
    }

    /// w2 Task W2-3 Step 4 (R1-X-N1), **rewritten by T4 (plan v5.1)**: v5 is
    /// rebuild-only (Global Constraints + T4 `ensure()` contract) -- a
    /// pre-existing version-1 database (`user_version = 1`, no
    /// `lex_docs`/`fts_lex`) is no longer incrementally migrated forward.
    /// `ensure` must reject it with `SchemaRebuildRequired{found: 1,
    /// required: CURRENT_SCHEMA_VERSION}` and leave the database's table set
    /// untouched (no partial DDL applied).
    #[test]
    fn ensure_rejects_a_wave1_database_with_schema_rebuild_required() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        // Build a version-1 shape directly (the pre-W2-2 DDL: everything up
        // to and including fts_messages -- the legacy FTS5 shadow a real
        // wave-1 database still had -- but not lex_docs/fts_lex, and not the
        // vector/chunk domains either).
        let v1_ddl = fresh_schema_ddl_before_table_for_test("lex_docs");
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

        let err = ensure(&conn).expect_err("ensure must reject a version-1 database, not migrate it");
        assert!(
            matches!(err, StorageError::SchemaRebuildRequired { found: 1, required: CURRENT_SCHEMA_VERSION }),
            "expected SchemaRebuildRequired{{found: 1, required: {CURRENT_SCHEMA_VERSION}}}, got {err:?}"
        );
        assert_eq!(read_user_version(&conn).unwrap(), 1, "a rejected ensure call must not touch user_version");
        assert_eq!(table_names(&conn), v1_names, "a rejected ensure call must not apply any DDL");
    }

    /// W2-6 Task戊, **rewritten by T4 (plan v5.1)**: a version-2 database
    /// (the `lex_docs`/`fts_lex` domain already added, `fts_messages` not
    /// yet dropped) is likewise rejected outright now, not migrated.
    #[test]
    fn ensure_rejects_a_wave2_database_with_schema_rebuild_required() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        let v3_shape_ddl = fresh_schema_ddl_before_table_for_test("embedding_generations");
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

        let err = ensure(&conn).expect_err("ensure must reject a version-2 database, not migrate it");
        assert!(
            matches!(err, StorageError::SchemaRebuildRequired { found: 2, required: CURRENT_SCHEMA_VERSION }),
            "expected SchemaRebuildRequired{{found: 2, required: {CURRENT_SCHEMA_VERSION}}}, got {err:?}"
        );
        assert_eq!(read_user_version(&conn).unwrap(), 2);
        assert_eq!(table_names(&conn), v2_names, "a rejected ensure call must not apply any DDL");
    }

    /// w3 Task W3-1 Step 2b, **rewritten by T4 (plan v5.1)**: a real
    /// wave-2-terminal-state database at `user_version = 3` (byte-identical
    /// production DDL, not a re-derived subset -- exactly what real wave-2
    /// databases, like the w3 staging snapshot, look like schema-wise) is
    /// likewise rejected outright now, not migrated forward to the vector
    /// domain.
    #[test]
    fn ensure_rejects_a_real_wave2_terminal_v3_database_with_schema_rebuild_required() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        let v3_ddl = fresh_schema_ddl_before_table_for_test("embedding_generations");
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

        let err = ensure(&conn).expect_err("ensure must reject a version-3 database, not migrate it");
        assert!(
            matches!(err, StorageError::SchemaRebuildRequired { found: 3, required: CURRENT_SCHEMA_VERSION }),
            "expected SchemaRebuildRequired{{found: 3, required: {CURRENT_SCHEMA_VERSION}}}, got {err:?}"
        );
        assert_eq!(read_user_version(&conn).unwrap(), 3);
        assert_eq!(table_names(&conn), v3_names, "a rejected ensure call must not apply any DDL");
    }

    /// T4 (plan v5.1): a version-4 database (the shape every real database
    /// produced before this task -- `FRESH_SCHEMA_DDL`'s v4-era tail,
    /// byte-identical production DDL) is likewise rejected, not migrated to
    /// v5. The fourth case the parametrized
    /// `schema_ensure_rejects_nonempty_user_version_0_1_2_3_4` test also
    /// covers generically; kept here too for the same detailed table-shape
    /// sanity checks the v1/v2/v3 siblings above have.
    #[test]
    fn ensure_rejects_a_v4_database_with_schema_rebuild_required() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);

        let v3_ddl = fresh_schema_ddl_before_table_for_test("embedding_generations");
        conn.execute_batch(v3_ddl).unwrap();
        conn.execute_batch(V4_VECTOR_DOMAIN_DDL).unwrap();
        conn.execute_batch(&set_user_version_sql(4)).unwrap();
        let v4_names = table_names(&conn);
        assert!(v4_names.contains(&"embedding_generations".to_string()));
        assert!(v4_names.contains(&"message_embeddings".to_string()));
        assert!(v4_names.contains(&"embedding_holes".to_string()));
        assert!(
            !v4_names.contains(&"message_chunks".to_string()),
            "sanity: the hand-built v4 shape must not already have the v5 chunk tables"
        );

        let err = ensure(&conn).expect_err("ensure must reject a version-4 database, not migrate it");
        assert!(
            matches!(err, StorageError::SchemaRebuildRequired { found: 4, required: CURRENT_SCHEMA_VERSION }),
            "expected SchemaRebuildRequired{{found: 4, required: {CURRENT_SCHEMA_VERSION}}}, got {err:?}"
        );
        assert_eq!(read_user_version(&conn).unwrap(), 4);
        assert_eq!(table_names(&conn), v4_names, "a rejected ensure call must not apply any DDL");
    }

    /// T4 (plan v5.1) Step 1: uniform, parametrized restatement of the four
    /// detailed `ensure_rejects_*` siblings above (0-nonempty/1/2/3/4) --
    /// deliberately doesn't inspect table shape at all (unlike the detailed
    /// siblings), because `ensure`'s `1 <= version < CURRENT_SCHEMA_VERSION`
    /// branch rejects on the bare version number alone, regardless of what
    /// tables actually exist; this test's job is to prove exactly that
    /// (no version in `{0-nonempty, 1, 2, 3, 4}` needs its real historical
    /// shape to be rejected).
    #[test]
    fn schema_ensure_rejects_nonempty_user_version_0_1_2_3_4() {
        for found in [0i64, 1, 2, 3, 4] {
            let (_dir, path) = scratch_db_path();
            let conn = open_sqlite_writer(&path);
            conn.execute_batch("CREATE TABLE probe_marker (id INTEGER PRIMARY KEY);").unwrap();
            conn.execute_batch(&set_user_version_sql(found)).unwrap();

            let err = ensure(&conn)
                .expect_err(&format!("ensure must reject a database at user_version={found}"));
            assert!(
                matches!(
                    err,
                    StorageError::SchemaRebuildRequired { found: f, required: CURRENT_SCHEMA_VERSION }
                        if f == found
                ),
                "expected SchemaRebuildRequired{{found: {found}, required: {CURRENT_SCHEMA_VERSION}}}, got {err:?}"
            );
        }
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
    /// `message_embeddings` table + 2 indexes, `embedding_holes` table),
    /// then up to 71 by T4 (plan v5.1)'s chunk domain (6 statements:
    /// `message_chunks` table + its 3 indexes, `chunk_holes` table,
    /// `chunk_staging` table -- `embedding_generations`'s 2 new columns are
    /// not a new statement, just a wider existing one). Verified against
    /// `FRESH_SCHEMA_DDL.split(';').filter(...).count()` directly (not
    /// hand-counted) each time this constant changed.
    const FRESH_SCHEMA_DDL_STATEMENT_COUNT_FOR_TEST: usize = 71;

    /// The historical `fts_messages` DDL, byte-for-byte identical to the
    /// statement W2-6 Task戊 removed from [`FRESH_SCHEMA_DDL`]. A real
    /// database built at version 1 or 2 (before this task) always had this
    /// table -- kept here, test-only, so the version 1->3 and 2->3 migration
    /// tests can hand-build an authentic pre-drop fixture instead of
    /// depending on production DDL that must no longer contain it.
    const LEGACY_FTS_MESSAGES_DDL_FOR_TEST: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS fts_messages USING fts5(content, title, agent, workspace, source_path, created_at UNINDEXED, content = '', tokenize = 'porter');";

    // -------------------------------------------------------------------
    // w3-3 Step 2: `insert_message_embedding_cas` (R3-B2) failure tests
    // -------------------------------------------------------------------

    fn insert_test_message_parent_chain(conn: &Conn, agent_id: i64, conversation_id: i64, message_id: i64, role: &str, content: &str) {
        conn.execute(
            "INSERT OR IGNORE INTO agents(id, slug, name, kind, created_at, updated_at) VALUES (?1, ?2, ?2, 'cli', 0, 0)",
            &params![agent_id, format!("agent-{agent_id}")],
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO conversations(id, agent_id, title, source_path) VALUES (?1, ?2, 't', ?3)",
            &params![conversation_id, agent_id, format!("/tmp/c-{conversation_id}.jsonl")],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages(id, conversation_id, idx, role, content) VALUES (?1, ?2, ?1, ?3, ?4)",
            &params![message_id, conversation_id, role, content],
        )
        .unwrap();
    }

    fn embedding_row_count_for_doc(conn: &Conn, generation_id: i64, doc_id: i64) -> i64 {
        conn.query_row_map(
            "SELECT COUNT(*) FROM message_embeddings WHERE generation_id = ?1 AND doc_id = ?2",
            &params![generation_id, doc_id],
            |row| row.get_typed(0),
        )
        .unwrap()
    }

    fn expected_hash_for(content: &str) -> String {
        crate::search::canonicalize::content_hash_hex(&crate::search::canonicalize::canonicalize_for_embedding(content))
    }

    /// Happy path: content and role at write time still match what the
    /// caller embedded -- the row must land, exactly like a plain
    /// `insert_message_embedding` call would.
    #[test]
    fn insert_message_embedding_cas_inserts_when_content_and_role_still_match() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "hello world");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        let expected_hash = expected_hash_for("hello world");

        let outcome = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                insert_message_embedding_cas(tx, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0], &expected_hash, "user", 1_000)
            })
            .expect("CAS insert must not error when content/role still match");

        assert_eq!(outcome, CasInsertOutcome::Inserted);
        assert_eq!(embedding_row_count_for_doc(&conn, gen_id, 1), 1);
    }

    /// The core race this function exists to close ("读旧内容→源更新→旧结果
    /// 迟到"): the worker read `content` at t0 and is only now (t2) trying to
    /// write the embedding it computed from it, but the row's content
    /// changed at t1. The raw `UPDATE` below is fixture-only -- production
    /// has no in-place content-update write path for an existing message id
    /// (w3-3 Step 3 write-entry-point survey confirmed this; content changes
    /// happen via replace, which reassigns a new id and so is caught by the
    /// `MessageMissing` case below, not this one) -- but the CAS primitive's
    /// own compare-and-set logic must be correct regardless of *which*
    /// mechanism produces a content change under a stable id, so the fixture
    /// drives that signal directly and deterministically.
    #[test]
    fn insert_message_embedding_cas_discards_stale_content_and_writes_nothing() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "old content");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        // t0: worker reads "old content" and computes its hash.
        let stale_hash = expected_hash_for("old content");
        // t1: source updates while the worker is still embedding.
        conn.execute("UPDATE messages SET content = ?1 WHERE id = 1", &params!["new content"]).unwrap();

        // t2: worker's late write, still carrying the t0 hash.
        let outcome = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                insert_message_embedding_cas(tx, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0], &stale_hash, "user", 1_000)
            })
            .expect("a stale CAS write must resolve to Ok(Stale(..)), not Err");

        assert_eq!(
            outcome,
            CasInsertOutcome::Stale(CasStaleReason::ContentChanged {
                expected_content_hash: stale_hash,
                current_content_hash: expected_hash_for("new content"),
            })
        );
        assert_eq!(
            embedding_row_count_for_doc(&conn, gen_id, 1),
            0,
            "the stale vector must not land in message_embeddings"
        );
    }

    /// R4-N1: role/agent-scoped filter metadata changing must invalidate the
    /// same way content does, independently reported (not folded into the
    /// content check).
    #[test]
    fn insert_message_embedding_cas_discards_stale_role_and_writes_nothing() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "same content");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        let expected_hash = expected_hash_for("same content");
        conn.execute("UPDATE messages SET role = 'tool_call' WHERE id = 1", &[]).unwrap();

        let outcome = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                insert_message_embedding_cas(tx, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0], &expected_hash, "user", 1_000)
            })
            .expect("a stale-role CAS write must resolve to Ok(Stale(..)), not Err");

        assert_eq!(
            outcome,
            CasInsertOutcome::Stale(CasStaleReason::RoleChanged {
                expected_role: "user".to_string(),
                current_role: "tool_call".to_string(),
            })
        );
        assert_eq!(embedding_row_count_for_doc(&conn, gen_id, 1), 0);
    }

    /// R2-B7: a re-audit (`run_activation_audit_and_record`) can flip an
    /// already-`is_active` generation to `audit_status='failed'` without
    /// touching `is_active` -- reusing that row here would permanently
    /// self-lock the catch-up worker into re-draining a generation already
    /// known broken (no amount of incremental hole-draining fixes a BLOB
    /// already written wrong). Mutation-relevant: the second assertion
    /// (still found once `audit_status` flips back to `passed`) proves the
    /// exclusion is specific to `'failed'`, not an accidental over-filter
    /// on `is_active` or identity that would also break the steady-state
    /// (`passed`) reuse case R1-W3-N3 exists for.
    #[test]
    fn find_active_generation_matching_identity_excludes_failed_audit_status() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");

        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        conn.execute(
            "UPDATE embedding_generations SET is_active = 1, audit_status = 'failed' WHERE id = ?1",
            &params![gen_id],
        )
        .unwrap();

        let found = find_active_generation_matching_identity(&conn, "bge-m3", 4, 1).unwrap();
        assert_eq!(
            found, None,
            "an active-but-failed generation must not be reused by the catch-up worker"
        );

        conn.execute("UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1", &params![gen_id])
            .unwrap();
        let found_passed = find_active_generation_matching_identity(&conn, "bge-m3", 4, 1).unwrap();
        assert_eq!(found_passed, Some(gen_id), "a passed active generation must still be found (not an over-filter)");
    }

    /// A worker that lost the race entirely (its doc_id was deleted --
    /// replace/forget/dedup/purge -- before it got back to write) must be
    /// told gracefully, not crash the caller. This exercises the primary
    /// guard (the upfront `SELECT` finds no row and returns `MessageMissing`
    /// directly) -- see
    /// [`insert_message_embedding_rejects_a_missing_doc_id_with_a_foreign_key_constraint`]
    /// below for the defense-in-depth `FOREIGN KEY` path.
    #[test]
    fn insert_message_embedding_cas_missing_doc_id_is_graceful_stale_not_an_error() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();

        let outcome = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                insert_message_embedding_cas(tx, gen_id, 999_999, 1, &[1.0, 0.0, 0.0, 0.0], "deadbeef", "user", 1_000)
            })
            .expect("writing to a doc_id that never existed must not error");

        assert_eq!(outcome, CasInsertOutcome::Stale(CasStaleReason::MessageMissing));
        assert_eq!(embedding_row_count_for_doc(&conn, gen_id, 999_999), 0);
    }

    /// Defense-in-depth path (advisor ruling ④, w3-3 Step 2): directly
    /// exercises `insert_message_embedding`'s own `FOREIGN KEY` failure (by
    /// calling it on a nonexistent `doc_id` the way the upfront `SELECT`
    /// would never let `insert_message_embedding_cas` reach in practice) and
    /// asserts the surfaced error is the ordinary `StorageError::Constraint`
    /// shape `detail_indicates_foreign_key_violation` is built to recognize
    /// -- proving that fallback match arm in `insert_message_embedding_cas`
    /// would actually fire (not dead code) if the upfront check were ever
    /// bypassed by a future refactor.
    #[test]
    fn insert_message_embedding_rejects_a_missing_doc_id_with_a_foreign_key_constraint() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();

        let err = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                insert_message_embedding(tx, gen_id, 999_999, 1, &[1.0, 0.0, 0.0, 0.0], "deadbeef", None, 1_000)
            })
            .expect_err("inserting an embedding for a doc_id absent from messages must fail the FK constraint");

        match err {
            StorageError::Constraint { detail } => assert!(
                detail_indicates_foreign_key_violation(&detail),
                "expected a FOREIGN KEY constraint detail, got: {detail}"
            ),
            other => panic!("expected StorageError::Constraint, got: {other:?}"),
        }
    }

    // -------------------------------------------------------------------
    // w3-3 Step 3: lifecycle invalidation primitives (unit level; the full
    // insert/replace/delete matrix against the real write entry points
    // lives in `tests/w3_vector_lifecycle.rs`)
    // -------------------------------------------------------------------

    fn active_audit_status(conn: &Conn) -> String {
        conn.query_row_map(
            "SELECT audit_status FROM embedding_generations WHERE is_active = 1",
            &[],
            |row| row.get_typed(0),
        )
        .unwrap()
    }

    fn set_generation_active_and_passed(conn: &Conn, generation_id: i64) {
        conn.execute(
            "UPDATE embedding_generations SET is_active = 1, audit_status = 'passed' WHERE id = ?1",
            &params![generation_id],
        )
        .unwrap();
    }

    #[test]
    fn register_embedding_hole_for_new_message_is_a_noop_with_no_active_generation() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "c");
        // A generation exists but is not active -- must still no-op, this
        // is the "vector domain not yet activated" case every ordinary
        // `cass index` run hits today.
        conn.with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000)).unwrap();

        conn.with_tx_no_replay(TxMode::Immediate, |tx| register_embedding_hole_for_new_message_in_tx(tx, 1, 1_000, "new_message"))
            .expect("must not error with no active generation");

        let holes: i64 =
            conn.query_row_map("SELECT COUNT(*) FROM embedding_holes", &[], |row| row.get_typed(0)).unwrap();
        assert_eq!(holes, 0);
    }

    #[test]
    fn register_embedding_hole_for_new_message_registers_against_the_active_generation() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "c");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        set_generation_active_and_passed(&conn, gen_id);

        conn.with_tx_no_replay(TxMode::Immediate, |tx| register_embedding_hole_for_new_message_in_tx(tx, 1, 1_000, "new_message"))
            .unwrap();

        let holes: Vec<(i64, i64, String)> = conn
            .query_all_map(
                "SELECT generation_id, doc_id, reason FROM embedding_holes",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
            )
            .unwrap();
        assert_eq!(holes, vec![(gen_id, 1, "new_message".to_string())]);
    }

    #[test]
    fn register_embedding_hole_for_new_message_is_idempotent() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "c");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        set_generation_active_and_passed(&conn, gen_id);

        conn.with_tx_no_replay(TxMode::Immediate, |tx| register_embedding_hole_for_new_message_in_tx(tx, 1, 1_000, "new_message"))
            .unwrap();
        conn.with_tx_no_replay(TxMode::Immediate, |tx| register_embedding_hole_for_new_message_in_tx(tx, 1, 2_000, "new_message"))
            .expect("re-registering the same (generation_id, doc_id) pair must not error");

        let holes: i64 =
            conn.query_row_map("SELECT COUNT(*) FROM embedding_holes", &[], |row| row.get_typed(0)).unwrap();
        assert_eq!(holes, 1, "INSERT OR IGNORE must not create a duplicate row");
    }

    #[test]
    fn demote_active_generation_readiness_is_a_noop_with_no_active_generation() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");

        conn.with_tx_no_replay(TxMode::Immediate, |tx| demote_active_generation_readiness_in_tx(tx))
            .expect("must not error with no active generation at all");
    }

    #[test]
    fn demote_active_generation_readiness_flips_passed_active_generation_to_pending() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        set_generation_active_and_passed(&conn, gen_id);
        assert_eq!(active_audit_status(&conn), "passed", "sanity: must start passed");

        conn.with_tx_no_replay(TxMode::Immediate, |tx| demote_active_generation_readiness_in_tx(tx)).unwrap();

        assert_eq!(active_audit_status(&conn), "pending");
    }

    #[test]
    fn demote_active_generation_readiness_leaves_a_non_active_generation_untouched() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        // Two generations: gen_a active+passed, gen_b inactive+passed (e.g.
        // a superseded generation awaiting W3-4's delayed cleanup). Only the
        // active one's readiness claim is what live writers can invalidate.
        let gen_a = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        let gen_b = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        set_generation_active_and_passed(&conn, gen_a);
        conn.execute(
            "UPDATE embedding_generations SET audit_status = 'passed' WHERE id = ?1",
            &params![gen_b],
        )
        .unwrap();

        conn.with_tx_no_replay(TxMode::Immediate, |tx| demote_active_generation_readiness_in_tx(tx)).unwrap();

        let gen_b_status: String = conn
            .query_row_map("SELECT audit_status FROM embedding_generations WHERE id = ?1", &params![gen_b], |row| row.get_typed(0))
            .unwrap();
        assert_eq!(gen_b_status, "passed", "the inactive generation's own certification must be untouched");
        assert_eq!(active_audit_status(&conn), "pending");
    }

    // -------------------------------------------------------------------
    // w3-3 Step 4 (R4-B5): hole-ledger resolution must commit atomically
    // with the embedding row it resolves ("watermark 同事务").
    // -------------------------------------------------------------------

    fn hole_count_for(conn: &Conn, generation_id: i64, doc_id: i64) -> i64 {
        conn.query_row_map(
            "SELECT COUNT(*) FROM embedding_holes WHERE generation_id = ?1 AND doc_id = ?2",
            &params![generation_id, doc_id],
            |row| row.get_typed(0),
        )
        .unwrap()
    }

    #[test]
    fn insert_message_embedding_cas_resolves_a_registered_hole_on_success() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "hello world");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        set_generation_active_and_passed(&conn, gen_id);
        conn.with_tx_no_replay(TxMode::Immediate, |tx| register_embedding_hole_for_new_message_in_tx(tx, 1, 500, "new_message"))
            .unwrap();
        assert_eq!(hole_count_for(&conn, gen_id, 1), 1, "sanity: hole must exist before the CAS write");
        let expected_hash = expected_hash_for("hello world");

        let outcome = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                insert_message_embedding_cas(tx, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0], &expected_hash, "user", 1_000)
            })
            .unwrap();

        assert_eq!(outcome, CasInsertOutcome::Inserted);
        assert_eq!(hole_count_for(&conn, gen_id, 1), 0, "the resolved hole must be gone after a successful CAS write");
    }

    #[test]
    fn insert_message_embedding_cas_stale_write_does_not_resolve_the_hole() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "old content");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        set_generation_active_and_passed(&conn, gen_id);
        conn.with_tx_no_replay(TxMode::Immediate, |tx| register_embedding_hole_for_new_message_in_tx(tx, 1, 500, "new_message"))
            .unwrap();
        let stale_hash = expected_hash_for("old content");
        conn.execute("UPDATE messages SET content = 'new content' WHERE id = 1", &[]).unwrap();

        let outcome = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                insert_message_embedding_cas(tx, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0], &stale_hash, "user", 1_000)
            })
            .unwrap();

        assert!(matches!(outcome, CasInsertOutcome::Stale(CasStaleReason::ContentChanged { .. })));
        assert_eq!(
            hole_count_for(&conn, gen_id, 1),
            1,
            "a stale/discarded write must leave the hole registered for a future retry"
        );
    }

    /// The core atomicity claim: the embedding insert and the hole-ledger
    /// delete that resolves it are two separate SQL statements inside
    /// `insert_message_embedding_cas` -- this proves they are still one
    /// atomic unit under a crash between "the write logically succeeded"
    /// and "the transaction commits", not two independent writes that
    /// could be split. Returning `Err` after a successful CAS call stands
    /// in for "the transaction failed to commit for any reason" (crash,
    /// disk full, a later statement in the same transaction failing) --
    /// `with_tx_no_replay` never reaches `Tx::commit`, so `Tx::drop` rolls
    /// the whole transaction back.
    #[test]
    fn insert_message_embedding_cas_hole_resolution_is_atomic_with_the_embedding_insert() {
        let (_dir, path) = scratch_db_path();
        let conn = open_sqlite_writer(&path);
        ensure(&conn).expect("ensure should build a fresh schema");
        insert_test_message_parent_chain(&conn, 1, 1, 1, "user", "hello world");
        let gen_id = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| create_embedding_generation(tx, "bge-m3", 4, 1, 1_000))
            .unwrap();
        set_generation_active_and_passed(&conn, gen_id);
        conn.with_tx_no_replay(TxMode::Immediate, |tx| register_embedding_hole_for_new_message_in_tx(tx, 1, 500, "new_message"))
            .unwrap();
        assert_eq!(hole_count_for(&conn, gen_id, 1), 1, "sanity: hole must exist before the CAS write");
        let expected_hash = expected_hash_for("hello world");

        let result: Result<(), StorageError> = conn.with_tx_no_replay(TxMode::Immediate, |tx| {
            let outcome = insert_message_embedding_cas(tx, gen_id, 1, 1, &[1.0, 0.0, 0.0, 0.0], &expected_hash, "user", 1_000)?;
            assert_eq!(outcome, CasInsertOutcome::Inserted, "sanity: the write itself must have succeeded pre-crash");
            Err(StorageError::Other { code: None, detail: "simulated mid-transaction crash".to_string() })
        });
        assert!(result.is_err(), "the forced error must propagate to the caller");

        // Both statements must have rolled back together -- not just the
        // insert, not just the hole delete.
        assert_eq!(
            embedding_row_count_for_doc(&conn, gen_id, 1),
            0,
            "the embedding row must not have survived the rollback"
        );
        assert_eq!(
            hole_count_for(&conn, gen_id, 1),
            1,
            "the hole must still be registered -- its resolution rolled back with everything else"
        );
    }
}
