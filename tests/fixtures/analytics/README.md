# Analytics test fixtures

Per `coding_agent_session_search-vz9t8.3`. This directory holds the legacy embedded engine
database files used by the Plans-subview snapshot tests.

## Required fixtures

| File | Purpose |
|------|---------|
| `plans_normal.db` | 10 distinct plans, 1000 token rows, even distribution |
| `plans_sparse.db` | 1 plan, 5 token rows |
| `plans_empty.db` | 0 plans, 0 token rows (empty-state path) |

## Generation

The fixture DBs are not committed because they require the live cass binary
to seed via `cass index --full` against synthetic session data. Generation
scripts and committed artifacts are tracked as a follow-up bead.

## Regeneration of the snapshot files

Once the fixture DBs are present, regenerate the .snap files via:

```bash
ALLOW_REGEN_WITHOUT_FIXTURES=1 \
  bash scripts/tests/regenerate_plans_snapshots.sh
```

The `ALLOW_REGEN_WITHOUT_FIXTURES=1` guard exists so the script doesn't
silently produce stale snapshots when fixtures are missing.
