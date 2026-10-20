-- Synthetic legacy fixture: schema-7 subset, 2026-10-13 (SRC05C-01).
--
-- Body extracted verbatim from the real historical DDL shipped at
--   4a6a1865893cec7bf5a1fc1cf63c1a6dccfb069f  (src/storage/schema.rs, PR8, schema 7)
-- with `git show 4a6a1865893cec7bf5a1fc1cf63c1a6dccfb069f:src/storage/schema.rs`.
-- Only the six tables this adapter must read are kept (meta, agents, workspaces,
-- sources, conversations, messages); the remaining schema-7 objects are omitted.
-- No statement below was reworded, reordered or reformatted.
--
-- The schema version marker is not part of this file: the tests set
-- `PRAGMA user_version = 7` after running it, matching how the schema-7 code
-- itself recorded the version (storage::schema::ensure -> set_user_version_sql).

CREATE TABLE IF NOT EXISTS meta ("key" TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agents (id INTEGER PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, version TEXT, kind TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS workspaces (id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, display_name TEXT);
CREATE TABLE IF NOT EXISTS sources (id TEXT PRIMARY KEY, kind TEXT NOT NULL, host_label TEXT, machine_id TEXT, platform TEXT, config_json TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS conversations (id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL REFERENCES agents (id), workspace_id INTEGER REFERENCES workspaces (id), source_id TEXT NOT NULL DEFAULT 'local' REFERENCES sources (id), external_id TEXT, title TEXT, source_path TEXT NOT NULL, started_at INTEGER, ended_at INTEGER, approx_tokens INTEGER, metadata_json TEXT, origin_host TEXT, identity_host TEXT NOT NULL DEFAULT 'local', metadata_bin BLOB, total_input_tokens INTEGER, total_output_tokens INTEGER, total_cache_read_tokens INTEGER, total_cache_creation_tokens INTEGER, grand_total_tokens INTEGER, estimated_cost_usd REAL, primary_model TEXT, api_call_count INTEGER, tool_call_count INTEGER, user_message_count INTEGER, assistant_message_count INTEGER, last_message_idx INTEGER, last_message_created_at INTEGER);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL REFERENCES conversations (id) ON DELETE CASCADE, idx INTEGER NOT NULL, role TEXT NOT NULL, author TEXT, created_at INTEGER, content TEXT NOT NULL, extra_json TEXT, extra_bin BLOB, excluded BLOB, UNIQUE (conversation_id, idx));
