# Manual release and offline installation

Use one repository and three commands. At the repository root:

```bash
./cass status
./cass release
./cass install
```

`./cass` is the repository manager. The installed `cass` remains the search CLI.
Release and installation are manual. Neither command uploads packages or activates
services. No GitHub Actions are used.

```text
repository/
  src/        CLI source
  mcp/        MCP source, with its existing independent Cargo workspace
  scripts/    shared build and installation tools
  .build/     dependency clones, build clone, target caches, candidates and logs
  dist/       version directories, tar.gz packages and checksums

~/.local/lib/cass-mcp/   installed production versions, outside the repository
```

`.build/` and `dist/` are ignored by Git. Configuration, credentials and databases
stay in their existing external locations. `./cass status` shows the actual MCP
executable running under the current user's service, when available. A package
in `dist/` is not an active production version.

## Build a package

The first format supports **Linux x86-64 with GNU libc**. Build on that platform.
The target needs Bash, GNU coreutils, `tar`, `grep`, `ldd` and the runtime libraries
required by the programs, including zlib. The installer reports missing libraries
and an insufficient glibc version. It does not install system packages.

The development machine needs Git, its normal Rust toolchain, gcc, binutils
(`strings` and `readelf`) and `flock`. Commit the reviewed source changes, then run:

```bash
./cass release
```

The command freezes this checkout's clean HEAD. It prepares the FAD dependency
at the URL and revision in that manifest, then delegates compilation to the
existing `scripts/setup-cass-fork.sh`. That script pins `asupersync`, builds both
programs and runs their source/version/ONNX checks. Dependency checkouts are
private to `.build/`; no global sibling checkout is changed. The two tools are
copied from the frozen Git commit before execution. Logs stay in `.build/logs/`.
The first build needs network access; later builds reuse the dependency caches.

Unset `CARGO_BUILD_TARGET`, `CARGO_ENCODED_RUSTFLAGS` and native compiler flag
variables such as `CFLAGS`/`CXXFLAGS` and their target-specific variants. Custom
CPU/ISA flags are rejected. Empty `RUSTFLAGS` uses the gcc linker default.

`PAIR_OK` means only the two candidates succeeded. Wait for **`RELEASE_OK`**.
`dist/` then contains:

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
`SHA256SUMS` covers its exact bytes too. Existing outputs are never replaced.
Failed staging files remain for inspection.

## Install on this machine

After `./cass release`, run:

```bash
./cass install
```

This selects the version for the current Git HEAD and invokes its packaged
installer. Both programs are installed under `~/.local/lib/cass-mcp/<release-id>/`.
An existing version is rejected and kept unchanged. **`INSTALL_OK` means installed,
not active.** Save the two printed paths for the existing service procedure below.
To install another extracted version or use an isolated installation root:

```bash
./cass install /absolute/extracted-release-directory --prefix /absolute/version-root
```

## Transfer and install

Copy the `.tar.gz` and its `.sha256` through your usual trusted transfer path.
Checksums detect changed bytes; they are not a signature or proof of origin.
On the target, in the directory holding both files:

```bash
release_id="cass-fork-<full-commit>-linux-x86_64"
sha256sum --check "$release_id.tar.gz.sha256"
tar -xzf "$release_id.tar.gz"
bash "$release_id/install.sh" --prefix "$HOME/.local/lib/cass-mcp"
```

Proceed only if checksum verification succeeds. The installer verifies the four
fixed members, parses metadata as data, checks runtime compatibility and runs
both `--version` commands. It stages and rechecks the full version before
publishing it. **`INSTALL_OK` means installed, not active.** Save the two absolute
program paths it prints. A repeated installation rejects the existing version,
including files and dangling links. A failed stage remains unpublished.

Development checks use `scripts/tests/test-cass-workspace.sh` for the root commands
and `scripts/tests/test-cass-release.sh` for bundle installation. Pass an absolute
extracted release directory to either script. Both use isolated prefixes and do
not activate a service.

The low-level `scripts/setup-cass-fork.sh` API still supports explicit candidate
paths: `INSTALL_PATH` for single CLI mode, plus `MCP_INSTALL_PATH` for paired mode,
and optional `RELEASE_DIR` for packages. Paired mode requires absolute fresh
targets and an unset `CARGO_TARGET_DIR`. It retains both lock files, same-source
checks and the no-overwrite publication rules. Legacy single CLI installation
still preserves its `.prev` backup behavior. Normal repository releases use the
root command so callers do not need to prepare these environment variables.

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
