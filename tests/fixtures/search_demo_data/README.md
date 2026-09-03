# `search_demo_data` fixture — provenance and regeneration record

Checked-in robot CLI fixture: 2 conversations (aider connector), 6 messages,
plus small `daily_stats`/`usage_*`/`token_usage`/`message_metrics` analytics
rows. Consumed by ~20 integration test files (`grep -rl search_demo_data
tests/`), each via a `copy_search_demo_fixture()`-style helper that walks
this whole directory into a per-test tmp copy before running `cass` against
it — never operated on in place by the test suite itself.

## 2026-08-27 migration: pre-`conversation_tail_state` generation → current schema

**Symptom**: `agent_search.db` was frozen at `meta.schema_version=13`
(`user_version=0`, last touched by commit `c8743037`, unrelated to the w1b
rusqlite-swap wave). The retired incremental migration engine (Task B8(a),
commit `4b9059eb`) used to silently backfill missing tables/columns on any
open, including read-only opens — once retired, every code path that
queries `conversation_tail_state` (added by the old engine's v15/v18
migrations) crashed with a raw `no such table` SQL error against this
fixture: 37 tests across 13 target files, all sharing this one root cause
(single-root-cause fan-out, see w1b task-16 report #3/#7 for the full
failure inventory).

**Why a fixture edit, not just a code fix**: a companion fix (commit
`2f3e4ff8`) added a fail-closed generation guard at the lexical-rebuild
entry point so a legacy-generation database gets a clear diagnosis instead
of a raw SQL crash — but the fixture itself still needed to reach the
current schema generation to actually search successfully, which is what
these tests assert.

**Why not re-run real ingestion**: `conversations.source_path` points at
two aider connector transcripts. Conversation #2's source
(`tests/fixtures/aider/.aider.chat.history.md`) still exists in this repo.
Conversation #1's source (`/data/projects/coding_agent_session_search/.aider.chat.history.md`
— an absolute path from a different machine/container than this repo's
current checkout path) does not exist anywhere in this repo's git history
(`git log --all -- .aider.chat.history.md` is empty at the root) — aider's
own local chat-history file is conventionally never committed. Re-running
production ingestion to reconstruct byte-identical content was therefore
not possible for conversation #1, ruling out "regenerate via real `cass
index`" as the migration method.

**Method actually used — replay the old engine's own migration recipe,
not free-hand reconstruction.** Everything below is copied verbatim from
`git show 4b9059eb~1:src/storage/sqlite.rs` (the last commit before Task
B8(a) deleted the incremental migration engine), because that file's
`MIGRATION_V15_TAIL_STATE_TABLE` / `MIGRATION_V18` / `MIGRATION_V19` /
`MIGRATION_V20` constants are exactly what `run_migrations()` would have
executed against this exact fixture had it ever been opened one more time
under the old engine, before that engine was retired:

1. Built an empty, current-schema database via `storage::schema::ensure()`
   (the same function `SqliteStorage::open()` calls for a brand-new file) —
   this is the schema-authority source of truth, not hand-written DDL.
2. Copied all 16 non-empty content tables row-for-row, unmodified, from the
   old fixture (`sources`, `agents`, `workspaces`, `conversations` [24
   shared columns; explicit column list, see below], `messages`, `tags`,
   `conversation_tags`, `daily_stats`, `usage_daily`, `usage_hourly`,
   `token_usage`, `token_daily_stats`, `message_metrics`,
   `usage_models_daily`, `embedding_jobs`, `snippets`). `sources` used
   `INSERT OR REPLACE` to overwrite `ensure()`'s own default-seeded row
   with the old fixture's exact row (same id, different `created_at`).
   `model_pricing`'s 10 static rate rows were already byte-identical to
   `ensure()`'s own seed data (verified before skipping it) — the model
   pricing table was never dropped or altered.
3. `conversations` gained two columns since the old fixture was built:
   `last_message_idx`, `last_message_created_at` (added by
   `MIGRATION_V15_TAIL_STATE_TABLE`'s own
   `ALTER TABLE conversations ADD COLUMN ...`, both nullable, no default).
   The historical migration source has **no retroactive backfill UPDATE**
   for pre-existing rows — those two columns are only ever written going
   forward, by the append/insert code path. Left `NULL` for both existing
   conversations here, exactly matching what the old migration would have
   left them as.
4. Populated the three new tables the old engine's v18/v19/v20 migrations
   introduced, running their `INSERT OR REPLACE ... SELECT ...` bodies
   **verbatim, unedited** against the migrated content:
   - `conversation_tail_state` (v18): both conversations qualify (each has
     a non-NULL `ended_at`), each row is `(id, ended_at, NULL, NULL)`.
   - `conversation_external_lookup` (v19): both conversations have a
     non-NULL `external_id`, so both get a lookup-key row.
   - `conversation_external_tail_lookup` (v20): same qualifying set,
     correlated-subquery-copies whatever `conversation_tail_state` has.
5. `meta`: kept only the two still-meaningful keys, `last_scan_ts` and
   `last_indexed_at`, copied verbatim (`phase3_restore.rs` still reads
   `last_scan_ts` by name). Dropped `schema_version=13` — that field is
   exactly what this migration retires; carrying an obsolete version
   number into a current-generation database would misrepresent it.
   `_schema_migrations` and `operation_commit_receipt` (new empty
   bookkeeping tables) were left empty, matching what a fresh `ensure()`
   build itself leaves them as (`schema.rs`'s own module doc: "`ensure`
   itself does not populate them").
6. **`index/v1/` (the checked-in, deliberately stale tantivy generation)
   was deliberately left untouched.** Its whole purpose is to be a version
   mismatch against the live `CASS_SCHEMA_VERSION`, so every consuming
   test exercises the self-heal/rebuild-from-scratch code path on
   first search. That path is what was actually broken (the
   `conversation_tail_state` crash) — now that the canonical database has
   the table, the real `cass` binary rebuilds a fresh, matching-generation
   tantivy index into each test's own tmp copy on demand, exactly as
   designed. Verified end-to-end: copied the migrated db into a scratch
   data-dir and ran the real `cass search` binary against it — it
   self-healed a fresh `index/<current-generation>/` and returned a
   correct real hit, with zero raw SQL errors.

**FTS5 shadow-table set** (`fts_messages_content`/`_data`/`_docsize`/`_idx`)
differs between the old and new `fts_messages` virtual table definitions —
this is expected and not migrated: FTS content is a derived search index,
always rebuilt from `messages` by the engine's own indexing code, never
copied row-for-row.

**Verification performed before this fixture was committed** (all four
must hold, this list is the reproducible checklist for the next refresh):

- The 37+2 originally-failing tests (36 via the shared fixture + 1
  independent `tests/upgrade/compatibility.rs::test_search_without_fts`
  fixture-setup gap fixed alongside it, since it hit the identical
  `conversation_tail_state` table via a hand-rolled schema that predated
  the table — see that file's own history) all pass.
- All ~20 consuming test files run clean: zero new failures anywhere,
  confirmed by diffing against the Step 1 equivalence gate's original
  `candidate/failures.jsonl` (the handful of failures that remain — 13 in
  `golden_robot_json.rs`/`cli_robot.rs`, 1 in
  `metamorphic_introspect_schema.rs` — were already failing there, for
  reasons unrelated to this fixture).
- `git status --short tests/golden/` shows zero changes — no golden file
  was regenerated or touched.
- Closed-loop schema re-verification: an **independently generated**
  second `ensure()` build (not the one used to construct this fixture)
  diffed table-name-set and per-table DDL (whitespace-normalized) against
  this file — byte-identical across all 23 non-FTS tables, `user_version`
  matches, `PRAGMA integrity_check` reports `ok`.

## How to refresh this fixture again in the future

If the schema changes again and this fixture needs another pass: repeat
steps 1-6 above against whatever `git show <commit-before-the-retiring-
commit>:src/storage/sqlite.rs` (or the then-current schema module) records
as the historical migration recipe for the newly-added tables/columns —
do not hand-invent backfill values. If a future schema change has no
recorded historical recipe (this repo's migration engine is fully retired
as of Task B8), the safe fallback is real re-ingestion from the original
source transcripts, and if those are unavailable, escalate rather than
hand-fabricate content — the golden-file blast radius here is real (~20
consuming tests, some of them byte-exact JSON comparisons).
