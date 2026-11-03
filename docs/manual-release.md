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

The package format (`cass-fork-release/2`) supports **Linux x86-64 with GNU libc**. Build on that platform.
The target needs Bash 4.4 or later, GNU coreutils, GNU findutils (`find`), `tar`,
`grep`, `ldd` and the runtime libraries required by the programs, including zlib. The installer reports missing libraries
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
  templates/
    README.md
cass-fork-<full-commit>-linux-x86_64.tar.gz
cass-fork-<full-commit>-linux-x86_64.tar.gz.sha256
```

`release.env` has six keys: `format=cass-fork-release/2`, the binary source
commit, platform, both versions and the highest GLIBC symbol version required by
either ELF. `source_commit` identifies the Rust programs. The packaged installer
comes from the setup tool being run. `templates/` holds the files tracked under
`scripts/release-templates/` in the source commit's Git tree, exported with the
same relative paths. Untracked and ignored files are never packaged. It holds
deployment templates for later use and may contain only regular files and
directories. The release stops before compilation if that directory is missing,
holds a symbolic link or submodule, or has a file name with a backslash, newline
or carriage return.

`SHA256SUMS` has one line per regular file in the package except itself:
`<64 lowercase hex digits>`, two spaces, and the relative path. It covers `cass`,
`cass-mcp`, the exact bytes of `install.sh`, `release.env` and every file under
`templates/`. Lines are ordered by path with `LC_ALL=C sort`. Existing outputs
are never replaced. Failed staging files remain for inspection.

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

Proceed only if checksum verification succeeds. The installer accepts only
format 2. It rejects absolute paths, `..` segments and duplicate lines in
`SHA256SUMS`. The listed paths must equal the package's regular files except
`SHA256SUMS`: an extra, missing or changed file, or a symbolic link, stops the
installation. It parses metadata as data, checks runtime compatibility and runs
both `--version` commands. It stages and rechecks the full version, including
`templates/`, before publishing it. **`INSTALL_OK` means installed, not active.** Save the two absolute
program paths it prints. A repeated installation rejects the existing version,
including files and dangling links. A failed stage remains unpublished.

Packages built before format 2 (`cass-fork-release/1`, without `templates/`)
carry their own older `install.sh`. `./cass install <directory>` runs that
packaged installer, so such packages still install as before.

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

## Full deployment (format 2 packages)

`install.sh --deploy` publishes the version and then prepares one named
instance: the `current` pointer, the data directory and an installer-owned
configuration directory. It does not create service units, entry scripts or
timers, and it does not run a first sync.

```bash
bash install.sh --prefix /abs/version-root --deploy --instance work \
  --data-dir /abs/cass-data --config-dir /abs/cass-config \
  --embed-endpoint http://127.0.0.1:8080/v1/embeddings --embed-model MODEL --embed-revision REV \
  --rerank-endpoint https://rerank.example/v1/rerank --rerank-model MODEL --rerank-revision REV \
  --key-env MODEL_API_KEY --key-file /abs/key-file [--legacy-source /abs/legacy-root]
```

Without `--deploy` the installer behaves exactly as in the previous section.
All paths must be absolute. The instance name must match `[a-z0-9][a-z0-9-]{0,31}`.
The prefix, the data directory and the configuration directory must be three
separate trees: after resolving them with `realpath -m`, no two may be equal or
nested.

1. **Version.** The version directory is published as usual. If it already
   exists, it counts as done only when every file equals the package byte for
   byte; otherwise the run stops.
2. **Ownership.** The data directory and the configuration directory each carry
   the marker file `.cass-install-instance`, which holds the instance name and a
   newline. A missing or empty directory is created or claimed with mode 0700 and
   gets the marker. A directory with this instance's marker is kept. Any other
   non-empty directory, or a non-directory at that path, stops the run with exit
   code 3 before any file is written or any mode is changed.
3. **Configuration.** `--config-dir` is the `XDG_CONFIG_HOME` for cass. The
   installer writes `<config-dir>/cass/sources.toml`, `<config-dir>/model-api.toml`
   and `<config-dir>/model-api.env` (files 0600, directories 0700).
   `<config-dir>/cass` must not be a symbolic link. The installer refuses a
   configuration directory that would place these files in `$HOME/.config/cass`,
   and it never reads or writes the files there.
   - `sources.toml` sets `disabled_agents` to every connector reported by
     `cass capabilities --json` of the verified package binary, except `claude_code`, `codex` and
     `pi_agent`. Live session directories need no `[[sources]]` entry.
     `--legacy-source` adds one read-only local source named after the
     directory's basename, with `paths = ["<legacy>/.claude/projects"]`.
     Every non-empty line of the connector list must be one name matching
     `[a-z0-9_]`; otherwise the run stops before anything is written.
   - `model-api.toml` defines the profiles `embed` and `rerank` and makes them
     the defaults. The scope follows the endpoint host: `127.0.0.1`, `[::1]` and
     `localhost` are `loopback`; every other host is `remote` and must use https.
   - `model-api.env` is exactly one line, `<KEY_ENV>=<value>` and a LF. The value
     is the key file content without one trailing newline. An empty value, or one
     with quotes, whitespace, a backslash or a control character, is refused.
     The installer never prints the value.

   The files are generated in a staging directory inside the configuration
   directory, loaded there by the published binary (`cass sources list` and
   `cass models list`), and then renamed into place. An unchanged file is not
   rewritten.
4. **Pointer.** Last, after the data directory and all configuration files are
   in place, `<prefix>/current` is switched atomically (a new symbolic link
   renamed over the old one) to the version directory name. A failure in any
   earlier step leaves `current` at its previous target.

A repeated run with the same arguments changes nothing. Exit codes: 0 success,
1 general failure, 2 invalid argument or key file, 3 data or configuration
directory belongs to something else; TERM, INT and HUP exit with 143, 130 and
129. Every exit, including one caused by these signals, removes the staging
directory and temporary marker files. Arguments, the key file and both
directory states are checked before any file is written.
Development checks use `scripts/tests/test-cass-deploy.sh` with an absolute
extracted release directory.

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

Publish-only installation does not edit service files, `current` links, global CLI paths,
credentials, configuration, models, databases or indexes. Manage those separately.
Before activation, check database/schema compatibility. A data rebuild or schema
change needs its own backup and deployment procedure; changing executable paths
does not undo a data change. This package workflow performs none of those actions.
