# Scripts

Use the root `./cass release`, `./cass install` and `./cass status` commands for
normal repository work. See [manual release](../docs/manual-release.md).

| Location | Purpose |
|---|---|
| `setup-cass-fork.sh`, `install-cass-fork-release.sh` | Current build and offline installation interfaces |
| [tests/](tests/) | Shell regression checks and test runners |
| `test-*.sh`, `validate*.sh`, `coverage*.sh` | Existing test, validation and coverage entry points |
| [perf/](perf/), [bakeoff/](bakeoff/) | Performance and comparison tools |
| [oracle/](oracle/) | Data and exclusion checks |
| [cli/](cli/), [daemon/](daemon/), [e2e/](e2e/) | Checks grouped by subsystem |
| [lib/](lib/) | Shared script helpers |
| [git-hooks/](git-hooks/) | Git hook setup |
| [historical_recovery/](historical_recovery/) | Historical-session recovery utilities |
| [archive/](archive/) | Scripts from completed batches, including the W1 gate tools |

The root `install.sh` and `install.ps1` retain their established paths because
published installer URLs and existing callers use them. They are separate from
the fork's current offline package installer.
