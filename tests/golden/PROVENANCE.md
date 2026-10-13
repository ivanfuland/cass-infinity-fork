# Golden File Provenance

Golden files under this directory freeze known-good outputs from cass
subcommands. Each file should be human-reviewed before commit; any diff
from a golden in CI is either a bug or an intentional schema change
that requires re-approval.

## Regeneration

Cargo-based golden regeneration is CPU-heavy in this repo. Run it through
`rch` and pin `CARGO_TARGET_DIR` so local agents do not contend for the shared
machine target cache.

```bash
# Regenerate every golden
UPDATE_GOLDENS=1 rch exec -- env CARGO_TARGET_DIR=/tmp/cass-golden-target cargo test --test golden_robot_json
UPDATE_GOLDENS=1 rch exec -- env CARGO_TARGET_DIR=/tmp/cass-golden-target cargo test --test pages_export_golden

# Regenerate a specific test
UPDATE_GOLDENS=1 rch exec -- env CARGO_TARGET_DIR=/tmp/cass-golden-target cargo test --test golden_robot_json -- capabilities_json
UPDATE_GOLDENS=1 rch exec -- env CARGO_TARGET_DIR=/tmp/cass-golden-target cargo test --test pages_export_golden -- basic_export_html

# After regeneration, review and commit
git diff tests/golden/
git add tests/golden/
git commit -m "Update golden <name>: <why>"
```

## Scrubbing

Dynamic values are scrubbed before golden comparison — see
`tests/golden_robot_json.rs::scrub_robot_json` for the rule set:

| Token | Replacement | Reason |
|---|---|---|
| `"crate_version": "x.y.z"` | `"[VERSION]"` | Survives `cargo publish` bumps |
| ISO-8601 timestamps | `[TIMESTAMP]` | Non-deterministic |
| Paths rooted at the isolated test HOME | `[TEST_HOME]` | Test-dir specific |
| UUIDs | `[UUID]` | Non-deterministic |
| HTML export salt / IV / ciphertext | `[SCRUBBED-*]` | Keeps encrypted payload shape without freezing secret material |

Keys are also sorted and the payload is re-indented by
`serde_json::to_string_pretty` so whitespace / key-order drift is not
treated as shape drift.

## Files

### Planned answer-pack goldens

Bead `coding_agent_session_search-uuwye.6` tracks future goldens for
`cass pack`. Those goldens must follow the same review loop as existing robot
goldens: generate through `rch`, canonicalize dynamic values before freezing,
review every `tests/golden/` diff, and commit the test plus golden update
together.

Expected answer-pack golden families:

| Family | Path | Stability Strategy | Required Scrubbing |
|---|---|---|---|
| Robot JSON | `robot/pack_*.json.golden` | Scrubbed exact JSON after key sorting | generated times, elapsed times, request ids, temp paths, source roots, index generations |
| Compact JSON | `robot/pack_*_compact.json.golden` | Structural equality with pretty JSON plus exact compact payload | same as robot JSON |
| JSONL | `robot/pack_*.jsonl.golden` | Exact line order after canonicalization | same as robot JSON plus per-line dynamic metadata |
| TOON | `robot/pack_*.toon.golden` | Exact TOON if decoder equality is unavailable | same as robot JSON |
| Markdown | `robot_docs/pack_*.md.golden` or focused pack docs goldens | Exact canonicalized text after JSON goldens pass | temp paths, source roots, timestamps |

Answer-pack goldens are not conformant if they freeze model-generated
summaries, ambient local paths, wall-clock freshness, or unredacted secrets.
They should capture only extractive evidence selected from deterministic
fixtures and should prove that citations survive scrubbing.

### `robot/capabilities.json.golden`

Frozen output of `cass capabilities --json`. Captures the LLM-facing
contract surface: `api_version`, `contract_version`, `features` list,
`connectors` list, and `limits` block. `crate_version` is scrubbed.

**Generated from:** cass @ commit HEAD of the authoring commit (see
`git log tests/golden/robot/capabilities.json.golden`).
**Command:** `cass capabilities --json` with `XDG_DATA_HOME` pinned to
an isolated TempDir and `CASS_IGNORE_SOURCES_CONFIG=1` so no ambient
sources leak into the output.

### Removed: `robot/models_status*.json.golden`, `models_verify_*`, `models_check_update_*`

Retired with the model-API migration. These pinned the local weight-cache
lifecycle (`state="not_acquired"`, `state_detail`, `next_step`, `files[]`,
`cache_lifecycle`, `model_acquisition`, and `models check-update`'s
`reason=model_not_installed`). The local model acquisition, verification and
update surfaces no longer exist:

- `cass models status` is now an alias of `cass models list` and reports the
  configured HTTP model API profiles (`{schema: cass.model-api-list.v1,
  profiles: [...]}`); with no `--api-config` it is a configuration refusal
  (exit 2).
- `cass models verify` / `models install` / `models remove` /
  `models check-update` refuse with a migration error (exit 2).

The surviving contracts are asserted in `tests/golden_robot_json.rs`
(`models_status_without_a_model_api_config_refuses`,
`retired_models_verify_and_check_update_refuse_as_migration_errors`) and, for
the real profile listing against a real config file, in
`tests/api_model_commands.rs`. The `models-status` / `models-verify` /
`models-check-update` keys in `robot/introspect*.json.golden` were replaced by
`models-list` / `models-check`.

### `html_export/basic_export.html.golden`

Frozen full document from `cass export-html --json --no-cdns`
against a three-message Claude-style JSONL fixture generated by
`tests/pages_export_golden.rs::write_fixture_session`. Captures the doctype,
metadata, style block, script block, and rendered user/assistant message HTML.

**Command:** `cass export-html <fixture.jsonl> --output-dir <temp> --filename basic_export.html --json --no-cdns`
with `HOME`, `XDG_CONFIG_HOME`, and `XDG_DATA_HOME` pinned to an isolated
TempDir.

### `html_export/encrypted_export.html.golden`

Frozen full document from the same fixture and flags plus `--encrypt` with the
fixture phrase generated by `tests/pages_export_golden.rs`. Test builds set
`CASS_HTML_EXPORT_GOLDEN_BYTES_LABEL=z2hck-html-export-golden-v1` so
salt/IV/ciphertext are reproducible before the scrubber replaces those bytes
with `[SCRUBBED-*]` placeholders.

**Command:** `printf '%s\n' <fixture-phrase> | cass export-html <fixture.jsonl> --output-dir <temp> --filename encrypted_export.html --json --no-cdns --encrypt --password-stdin`.

### Pre-existing `robot/*` drift (not fixed here)

Several `tests/golden/robot/*` goldens were already stale at the commit this
change builds on (`e4acf395`), i.e. they did not match the binary at that commit
either. Evidence: `robot/health.json.golden` recorded
`quality_tier_embedder: "minilm"` while that commit's
`src/search/policy.rs` declared `DEFAULT_QUALITY_TIER_EMBEDDER = "infinity"`.

This change updates the goldens whose content it directly changes
(`capabilities.json` argument/env descriptions and the neutralised
`quality_tier_embedder` / `reranker` defaults, `health.json` for the same two
fields, `introspect.json` / `introspect_shape.json` for the `models-list` /
`models-check` response-schema keys that replaced `models-status` /
`models-verify` / `models-check-update`). Those files therefore also carry the
pre-existing drift listed below; it is *not* part of this change and is left for
the follow-up baseline-equivalence gate:

- `health*.json` / `status_quarantine*.json`: new `last_index` block.
- `doctor*.json` / `diag_quarantine.json`: `feature_compiled_in` flipped
  `true → false`, new `db_vector_domain` block, and different quarantine /
  reclaimable-byte counts.
- `capabilities*.json` / `introspect*.json`: a `regression` / `regression-input`
  command that the golden lacks.

Goldens with only that drift (no line this change touches) were left exactly as
they were.

### API03 final-surface refresh

The API-only surface cleanup updated four frozen outputs whose text it directly
changed; each was edited to the expected new value and then checked by its own
golden test against the real binary, so only the touched hunks moved:

- `robot_docs/commands.txt.golden` — `cass robot-docs commands` no longer lists
  the duplicated / retired `models list` / `models check` / `models backfill`
  lines.
- `robot_docs/exit-codes.txt.golden` — codes 20-24 are now shown as retired
  rather than as live model-acquisition / download failures.
- `robot/capabilities.json.golden` — the search `--model` / `--reranker` /
  `--daemon` / `--no-daemon` argument descriptions and the exit-code 15 / 20-24
  `agent_action` rows were rewritten; no other row changed.
- `robot/introspect.json.golden` — the same four search-argument descriptions.

The pre-existing `robot/*` drift listed above is unchanged by this refresh.

### API03I rerank machine schema

`response_schema_rerank_meta()` declared 22 of the 23 fields a rerank window
really emits: the `model_api` block an API-backed window carries was missing, so
the published schema did not describe the binary's own output, and validating
that output against it failed. The same function still enumerated the five
retired `ProviderChoice` selections for
`requested_provider`, although that field has held the operator's configured
profile id since the API-only rerank replaced the local/OpenRouter backends.

Only these two frozen outputs moved; the pre-existing `robot/*` drift listed
above is untouched by this change:

- `robot/introspect.json.golden` / `robot/introspect_shape.json.golden` — the
  `search` schema's `_meta.rerank` (and its `search-rerank-meta` alias) gains
  `model_api`, typed as `object` or `null` with `primary_profile`,
  `realized_profile`, `fallback_used`, `fallback_reason` and `attempts[]`, whose
  elements carry `profile`, `network_attempted`, `http_status`, `error_code`,
  `duration_ms`, `response_model`, `response_revision`, `serving_provider` and an
  optional `usage`. `requested_provider` loses its retired-provider `enum` and
  becomes a pattern-constrained profile id. `actual_provider` keeps its nullable
  legacy enum: the API-only path never proves a `ProviderChoice`, so it stays
  `null` there.
- `robot_docs/schemas.txt.golden` — the same schema, rendered as text; purely
  additive.

### API03K demo-archive rebuild and quarantine fixture path

Two independent fixture defects kept eight `robot/*` cases red, and one of them
had already frozen a wrong contract into the preceding refresh.

**The quarantine fixture wrote where no reader looks.**
`seed_diag_quarantine_fixture` based its layout on `data_dir.join("index")` and
then took that path's *parent*, so `.lexical-publish-backups/` and
`generation-quarantined/` landed directly under `<data_dir>/`. Every quarantine
surface instead resolves `expected_index_dir(data_dir)` (`<data_dir>/index/v8`)
first and takes **its** parent (`<data_dir>/index`) —
`collect_diag_quarantine_report_inner` and `diag_lexical_manifest_scan_root` in
`src/lib.rs`. The fixture now calls
`coding_agent_search::indexer::expected_index_dir`, and the four tests that
compare a full quarantine report — `diag_quarantine_json_matches_golden`,
`doctor_quarantine_json_matches_golden`, `status_quarantine_json_matches_golden`
and `status_quarantine_full_json_matches_golden` — assert the seeded totals — 2
failed seed bundle files, 2 retained publish backups, 1 lexical generation with
`build_state=failed` / `publish_state=quarantined` — **in addition to** their
golden, so an empty report can never again be frozen as the contract.
(`quarantine_summary_shape_matches_golden` consumes the same fixture but
asserts only that the three surfaces agree on the summary schema; it is not one
of the four.) `robot/diag_quarantine.json.golden` and
`robot/quarantine_summary_shape.json.golden` returned to passing with no edit to
those files, which is the independent evidence that the path was the whole
defect.

**The demo archive was frozen at a schema the CLI refuses.**
`cass search` and `cass stats` happy-path cases read
`tests/fixtures/search_demo_data`, whose `agent_search.db` still carries
`user_version = 1`; `ensure_readonly_schema_current` rejects anything below
`CURRENT_SCHEMA_VERSION`, so those four cases died before reaching their
subject, and "fixing" it by raising `user_version` would have forged a rebuild
that never happened. They now build their own archive under the temp HOME
through today's production write path — `FrankenStorage::open` +
`ensure_agent` / `ensure_workspace` / `insert_conversation_tree` — carrying the
same logical corpus the checked-in fixture records (2 conversations, 6 messages,
one `aider` agent, repo-root and `tests/fixtures/aider` workspaces, the same
titles and timestamps). The checked-in fixture is untouched and remains the
read-only historical record the other targets assert against.

The search cases additionally need derived lexical assets, which the storage
write path does not create, so they run `cass index --full` (lexical only, no
`--semantic`) before searching, and pass a frozen version-1 model API
configuration whose only profile points at a loopback HTTP service owned by the
test. The default (hybrid-preferred) intent is kept: the configuration is
valid, but no vector generation exists, so the search realises its visible
lexical strategy and sends the service nothing
(`model_api_stub_requests=[]` on every run). The loopback service is there so a
request could never reach a real endpoint if one were made, and it records every
request it answers.

The helper also clears `RETIRED_MODEL_ENV_VARS` on the child process. That is
environment hygiene, not a contract change: a model-dependent command refuses
when any of those variables is present, the empty string included, so a
developer or CI shell that still exports one would turn every search golden red
for a reason unrelated to this repository. The ambient environment is not
modified.

Refreshed (only these moved):

| Golden | What changed |
|---|---|
| `robot/capabilities_shape.json.golden` | `commands[0].arguments.items` becomes `{"type":"unknown"}`. |
| `robot/doctor_shape.json.golden` | Adds `db_vector_domain` (`null`). |
| `robot/health_shape.json.golden` | Adds `state.last_index` (7 all-null fields) and `state.db_vector_domain`. |
| `robot/diag_quarantine.json.golden` | Unchanged (it was never refreshed to the empty report). |
| `robot/doctor_quarantine.json.golden` | Replaces the frozen empty report with the seeded one. |
| `robot/status_quarantine.json.golden` | Same, on the `status` surface. |
| `robot/status_quarantine_full.json.golden` | Same; its content is identical to the non-full one. |
| `robot/search_robot.json.golden` | `score` re-derived over the rebuilt index; `created_at` becomes `null`; adds `message_id`. |
| `robot/search_robot_shape.json.golden` | `created_at` becomes `{"type":"null"}` — this run observes only `null`, so the frozen type is exactly `null`, not "integer or null"; adds `message_id` (`integer`). |
| `robot/stats_full_payload.json.golden` / `..._shape.json.golden` | Unchanged — the rebuilt archive reproduces the frozen envelope byte for byte. |

Two of those hunks are behaviour, not drift, and are worth naming:

- `created_at` is `null` because the default lexical path hydrates it as
  `CAST(m.created_at AS INTEGER)` (`sqlite_fts5_message_hydrate_query`) with no
  fallback, and every message in this corpus has a null `created_at`. The
  previous non-null value came from the retired Tantivy generation. The
  message-scan path *does* fall back to `conversations.started_at`
  (`src/search/query.rs:4890`); the default path does not. Freezing `null` here
  states what the binary does today; the asymmetry is reported, not repaired,
  by this change.
- `message_id` is the T9 chunk-domain provenance field the search goldens were
  never refreshed for.

## Follow-ups

Goldens still to add under bead u9osp scope (each needs its own
environment-scoped fixture — e.g. a TempDir with a known-empty or
known-seeded data dir before the command can produce deterministic
output):

- `robot/health.json.golden` — needs a seeded data dir with a stable
  fixture index so the `last_indexed_at` / counts are scrubbable.
- `robot/models_list.json.golden` — needs a pinned `--api-config` fixture so the
  profile listing (`cass.model-api-list.v1`) is deterministic. The retired
  local `models_status.json.golden` follow-up no longer applies.
- `robot/robot_docs.json.golden` — needs a topic-specific fixture
  since the output is a large formatted doc string per topic.
