# Manual release and offline installation

Build on a development machine. Transfer the package. Install it on the target
machine without source code, Git, Rust, Cargo or network access. This workflow
uses no GitHub Actions and does not upload packages or activate services.

## Build a package

The first format supports **Linux x86-64 with GNU libc**. Build on that platform.
The target needs Bash, GNU coreutils, `tar`, `grep`, `ldd` and the runtime libraries
required by the programs, including zlib. The installer reports missing libraries
and an insufficient glibc version. It does not install system packages.

Use `scripts/setup-cass-fork.sh`, the existing build entry. The build machine
also needs its normal Rust toolchain/dependency setup and `readelf` (binutils).
Use a dedicated build clone with the required dependency siblings. Do not point
`FORK_DIR` at a development worktree. Pin `FORK_REF` to the full reviewed commit.
Choose new candidate paths for every attempt:

```bash
source_commit=FULL_REVIEWED_COMMIT
run_root="$HOME/cass-builds/$source_commit"
env -u CARGO_TARGET_DIR -u CARGO_BUILD_TARGET -u CARGO_ENCODED_RUSTFLAGS \
  CC=/usr/bin/gcc CC_x86_64_unknown_linux_gnu=/usr/bin/gcc \
  RUSTFLAGS=-Clinker=/usr/bin/gcc CASS_STRICT_PATH_DEP_VALIDATION=1 \
  FORK_REF="$source_commit" FORK_DIR="$run_root/build" \
  INSTALL_PATH="$run_root/candidates/cass" \
  MCP_INSTALL_PATH="$run_root/candidates/cass-mcp" \
  RELEASE_DIR="$run_root/releases" \
  bash scripts/setup-cass-fork.sh
```

The existing source contract checks dependency pins when the sibling checkouts
exist. Prepare the pinned `franken_agent_detection` sibling at
`$run_root/franken_agent_detection` before building; confirm it was checked rather
than skipped. The setup script prepares/pins `$run_root/asupersync` itself.
Do not add custom CPU/ISA flags. Unset native compiler flag variables such as
`CFLAGS`, `CXXFLAGS` and their target-specific variants. Empty `RUSTFLAGS` uses
the gcc linker default.

`PAIR_OK` means only the two candidates succeeded. Wait for **`RELEASE_OK`**.
The release directory then contains:

```text
cass-fork-<full-commit>-linux-x86_64/
  cass
  cass-mcp
  install.sh
  release.env
  SHA256SUMS
cass-fork-<full-commit>-linux-x86_64.tar.gz
cass-fork-<full-commit>-linux-x86_64.tar.gz.sha256
```

`release.env` records the binary source commit, both versions, platform and the
highest GLIBC symbol version required by either ELF. `source_commit` identifies
the Rust programs. The packaged installer comes from the setup tool being run;
`SHA256SUMS` covers its exact bytes too. Keep the build log with the package.
Existing outputs are never replaced. Failed staging files remain for inspection.

## Transfer and install

Copy the `.tar.gz` and its `.sha256` through your usual trusted transfer path.
Checksums detect changed bytes; they are not a signature or proof of origin.
On the target, in the directory holding both files:

```bash
release_id="cass-fork-<full-commit>-linux-x86_64"
sha256sum --check "$release_id.tar.gz.sha256"
tar -xzf "$release_id.tar.gz"
bash "$release_id/install.sh" --prefix "$HOME/.local/lib/cass-releases"
```

Proceed only if checksum verification succeeds. The installer verifies the four
fixed members, parses metadata as data, checks runtime compatibility and runs
both `--version` commands. It stages and rechecks the full version before
publishing it. **`INSTALL_OK` means installed, not active.** Save the two absolute
program paths it prints. A repeated installation rejects the existing version,
including files and dangling links. A failed stage remains unpublished.

For development checks, run
`bash scripts/tests/test-cass-release.sh /absolute/extracted-release-directory`.
This uses real binaries and isolated prefixes; it does not activate a service.

## Activate, verify, and roll back

Record the current CLI/MCP paths and the service's full command first. Keep that
version and its configuration. Use the existing service management procedure:
change only the MCP executable path and its `--cass-bin` to the two paths from
`INSTALL_OK`. Preserve the transport, address, authentication, environment and
all other arguments. Update any separately configured CLI path explicitly.
Restart only when deployment is authorized. See [MCP usage](mcp.md).

After activation, confirm the service is running with the expected paths. Run
the existing authenticated health check and a read-only MCP query against the
intended data. A running process or `--version` alone does not prove service
health. If verification fails, restore the recorded two executable paths and
restart with the previous arguments, then repeat the same health check.

Installation does not edit service files, `current` links, global CLI paths,
credentials, configuration, models, databases or indexes. Manage those separately.
Before activation, check database/schema compatibility. A data rebuild or schema
change needs its own backup and deployment procedure; changing executable paths
does not undo a data change. This package workflow performs none of those actions.
