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
