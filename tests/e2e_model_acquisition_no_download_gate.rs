//! Real-binary gate: the API-only model surface never downloads a weight, never
//! creates a local model cache, and never needs a model configuration for lexical
//! work.
//!
//! Semantic mapping (model-API migration). This file used to drive the hardened
//! *local acquisition* contract: the `model_acquisition` block on
//! `cass models status` / `cass models verify`, its `skipped_network_reason`,
//! per-file `size_match` flags, and a hand-written `.12.3` proof-log record. That
//! local weight-download surface was retired -- `models status` is now an alias of
//! `models list` (the configured HTTP model API profiles), `models verify` /
//! `install` / `remove` / `check-update` refuse with a migration error, and
//! `src/search/model_download.rs` no longer exists. Fabricating a proof-log
//! record for a downloaded-weight workflow that no longer exists would be worse
//! than deleting it, so this file now asserts the property the old gate actually
//! protected, against the real binary: **model commands create no local model
//! cache and make no local inference fallback, and lexical work needs no model
//! configuration.**
//!
//! Authored panic-free (no unwrap/expect/panic) to stay at zero UBS findings.

use assert_cmd::cargo::cargo_bin;
use std::path::{Path, PathBuf};

/// Run the real `cass` binary in a fully isolated HOME so no ambient config or
/// model cache can leak in. Returns `(exit_code, stdout, stderr)`.
fn run_isolated_cass(home: &Path, args: &[&str]) -> Result<(Option<i32>, String, String), String> {
    let output = std::process::Command::new(cargo_bin("cass"))
        .args(args)
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("CASS_IGNORE_SOURCES_CONFIG", "1")
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join(".local/share"))
        .env("XDG_CONFIG_HOME", home.join(".config"))
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .output()
        .map_err(|e| format!("run cass {args:?}: {e}"))?;
    Ok((
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    ))
}

/// The `models/` directory the retired downloader used to populate under the
/// data dir (`~/.local/share/coding-agent-search/models`).
fn model_cache_dir(home: &Path) -> PathBuf {
    home.join(".local/share/coding-agent-search/models")
}

fn assert_no_model_cache(home: &Path, label: &str) -> Result<(), String> {
    let dir = model_cache_dir(home);
    if dir.exists() {
        return Err(format!(
            "{label} must not create a local model cache; {} appeared",
            dir.display()
        ));
    }
    Ok(())
}

#[test]
fn model_commands_create_no_local_model_cache_and_lexical_needs_no_config() -> Result<(), String> {
    let tmp = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;

    // A lexical search must not require a model configuration, and must not
    // touch the local model cache. An empty home may legitimately yield a
    // missing index/DB (exit 3) or a result (0); what it must never yield is a
    // usage/config refusal (2), a "semantic unavailable" refusal (15), or a
    // signal death.
    let (code, _out, err) =
        run_isolated_cass(tmp.path(), &["search", "nothing", "--json", "--mode", "lexical"])?;
    if matches!(code, Some(2) | Some(15) | None) {
        return Err(format!(
            "lexical search must not require a model config; got exit {code:?}; stderr: {err}"
        ));
    }
    assert_no_model_cache(tmp.path(), "lexical search")?;

    // `models status` is an alias of `models list` and reports configured HTTP
    // model API profiles; with no --api-config it is a configuration refusal,
    // never a local-cache inspection and never a download.
    let (scode, sout, serr) = run_isolated_cass(tmp.path(), &["models", "status", "--json"])?;
    if !matches!(scode, Some(2)) {
        return Err(format!(
            "models status with no --api-config must refuse with exit 2; got {scode:?}; stdout: {sout}; stderr: {serr}"
        ));
    }
    assert_no_model_cache(tmp.path(), "models status")?;

    // The retired local-weight subcommands refuse with a migration error and
    // must not create or touch a local model directory.
    for args in [
        &["models", "verify", "--json"][..],
        &["models", "check-update", "--json"][..],
        &["models", "install", "--yes"][..],
        &["models", "remove", "--yes"][..],
    ] {
        let (mcode, mout, merr) = run_isolated_cass(tmp.path(), args)?;
        if !matches!(mcode, Some(2)) {
            return Err(format!(
                "{args:?} must be a migration refusal (exit 2); got {mcode:?}; stdout: {mout}; stderr: {merr}"
            ));
        }
        assert_no_model_cache(tmp.path(), &format!("{args:?}"))?;
    }
    Ok(())
}
