# Archived batch tools

These scripts belong to completed work. Their original feature, schema and
environment assumptions are retained; archiving does not update their behavior
for the current API-only build.

| Previous location | Current location |
|---|---|
| `scripts/w1-*.sh`, `scripts/w1-*.py` | [w1/](w1/) |
| `scripts/cass09-static-proof.py` | [cass09-static-proof.py](cass09-static-proof.py) |

Run a tool from the repository root using its new path. The W1 gate helpers stay
together so their sibling imports still resolve. Its capture command resolves
the source repository root from the archived script's location.

Current build and installation commands are documented in the
[manual release guide](../../docs/manual-release.md).
