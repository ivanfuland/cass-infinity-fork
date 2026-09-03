# w2-baseline-v3.jsonl provenance (要点)

> Full capture log: control-plane `W2_ARTIFACTS/w2-baseline-v3-provenance.md`
> (exec47 Task甲, 2026-09-01). This file only carries the points a reader of
> the fixture needs; it is not a copy of the full methodology writeup.

## Self-referential semantics (jsonl itself carries no comments)

Starting at v3, the parity gate's anchor engine is FTS5 itself, no longer the
retired tantivy. The gate's meaning changed from "cross-engine migration
equivalence" (v1/v2 era: does the new FTS5 implementation reproduce the old
tantivy ranking) to a **self-referential anti-regression baseline**:
`w2-baseline-v3.jsonl` records what FTS5 actually returned, on a frozen
corpus snapshot, at capture time (HEAD `cca78275`, snapshot sha256
`1632137b...`) -- including 6 known misses. Any later re-run of
`w2_lexical_parity_gate` (against the same or a future frozen snapshot) is
comparing "has ranking drifted from this recorded point", not "does it match
an engine that no longer exists". To update the reference point, re-capture
baseline-v4/v5+ under the same discipline (health-check the source DB,
`VACUUM INTO` a frozen snapshot, capture, freeze) -- see the control-plane
doc for the full recipe.

## Known misses (not regressions -- baseline itself already carries them)

`anchor_hit=34/40`; the 6 misses are `duplicate` / `indexed` / `indexer` /
`connectors` / `duplicated` / `触发器` -- cross-verified against exec44/45's
diagnosis reports, a real and stable (not sampling-noise) ranking behavior of
the current FTS5 engine on this corpus slice.

## Identity

- Frozen corpus snapshot: `VACUUM INTO` of the w2 staging DB, sha256
  `1632137bb39601e5297c8ccb15bf04dcb57d74856b24c971f4d8a3163dd70a1b`,
  `user_version=3`, `lex_docs_rows=fts_lex_rows=1074725` (not committed --
  local-only, 19GB).
- Same 40 frozen queries as `tests/fixtures/w2_parity_queries.jsonl`
  (unchanged).
- Self-referential first run: all three parity criteria scored a full
  1.0/1.0/1.0 (expected -- confirms capture methodology, not a coincidence).

## v2 baseline

`w2-tantivy-baseline-v2.jsonl` (the tantivy-era denominator) stays archived
under the control-plane `W2_ARTIFACTS/` root, not copied into this repo --
`CASS_W2_PARITY_BASELINE` can still be pointed at it explicitly if a v2
comparison is ever needed again.
