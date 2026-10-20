-- Synthetic legacy fixture: schema-8 subset, 2026-10-13 (SRC05C-01).
--
-- Body extracted verbatim from the real historical DDL shipped at
--   0d0f3261f64a628210044d5e1f3f257bea7cc594  (src/storage/schema.rs, schema 8)
-- with `git show 0d0f3261f64a628210044d5e1f3f257bea7cc594:src/storage/schema.rs`.
-- Only the six tables this adapter must read are kept (meta, agents, workspaces,
-- sources, conversations, messages); the remaining schema-8 objects are omitted.
-- No statement below was reworded, reordered or reformatted.
--
-- Cross-checked against the schema-7 fixture: the six statements are byte
-- identical between 4a6a1865 (schema 7) and 0d0f3261 (schema 8), so the two
-- fixture files differ only in this provenance header.
--
-- The schema version marker is not part of this file: the tests set
-- `PRAGMA user_version = 8` after running it, matching how the schema-8 code
-- itself recorded the version (storage::schema::ensure -> set_user_version_sql).

CREATE TABLE IF NOT EXISTS meta ("key" TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agents (id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, version TEXT, kind TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS workspaces (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, display_name TEXT);
CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, kind TEXT NOT NULL, host_label TEXT, machine_id TEXT, platform TEXT, config_json TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL REFERENCES agents (id), workspace_id INTEGER REFERENCES workspaces (id), source_id TEXT NOT NULL DEFAULT 'local' REFERENCES sources (id), external_id TEXT, title TEXT, source_path TEXT NOT NULL, started_at INTEGER, ended_at INTEGER, approx_tokens INTEGER, metadata_json TEXT, origin_host TEXT, identity_host TEXT NOT NULL DEFAULT 'local', metadata_bin BLOB, total_input_tokens INTEGER, total_output_tokens INTEGER, total_cache_read_tokens INTEGER, total_cache_creation_tokens INTEGER, grand_total_tokens INTEGER, estimated_cost_usd REAL, primary_model TEXT, api_call_count INTEGER, tool_call_count INTEGER, user_message_count INTEGER, assistant_message_count INTEGER, last_message_idx INTEGER, last_message_created_at INTEGER);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES conversations (id) ON DELETE CASCADE, idx INTEGER NOT NULL, role TEXT NOT NULL, author TEXT, created_at INTEGER, content TEXT NOT NULL, extra_json TEXT, extra_bin BLOB, excluded BLOB, UNIQUE (conversation_id, idx));
