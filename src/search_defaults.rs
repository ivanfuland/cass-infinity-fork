//! Configurable defaults for `cass search` / `cass pack` (gh #303).
//!
//! Historically the `--timeout`, `--limit` and `--mode` flags on `cass search`
//! had only their clap-level defaults: omit `--timeout` and the search ran with
//! no wall-clock bound at all, so a broad query with `--limit 0` could spin a
//! large index indefinitely with no way to auto-terminate. Agents that drive
//! cass via fixed prompt templates could not opt into a default timeout without
//! appending `--timeout <ms>` to every single invocation across every agent
//! config — fragile, and easy to forget.
//!
//! This module lets the operator set *defaults* for `cass search` and
//! `cass pack` once, via either:
//!
//! 1. An **environment variable** — `CASS_SEARCH_TIMEOUT_MS` (the issue also
//!    mentions `CASS_SEARCH_TIMEOUT`; both are accepted, `_MS` wins if both are
//!    set, since the value is unambiguously milliseconds to match the existing
//!    `--timeout` flag). Likewise `CASS_SEARCH_MODE`, and the search window
//!    limits `CASS_RRF_LIMIT` / `CASS_RERANK_LIMIT`.
//! 2. A **config file** — `~/.config/cass/cass.toml` (XDG-resolved exactly like
//!    the existing `sources.toml`), with a `[search]` table:
//!
//!    ```toml
//!    [search]
//!    timeout_ms   = 300000   # 5 minutes
//!    rrf_limit    = 200      # candidate window for rrf fusion
//!    rerank_limit = 5        # candidate window for reranking
//!    mode         = "hybrid"
//!    ```
//!
//! The original issue example used YAML; cass already standardizes on TOML for
//! its user config (`sources.toml`), so the config file is TOML for consistency
//! and to reuse the existing `toml` dependency and XDG path resolution. No new
//! dependency is introduced.
//!
//! The legacy `limit` key (`CASS_SEARCH_LIMIT`) is **still consumed by `cass
//! pack`** through `resolve_limit` / `limit_env` and keeps its old behavior, but
//! `cass search` no longer accepts it: `resolve_window_limits` returns a
//! migration error whenever the legacy value is set. `--rrf-limit` and
//! `--rerank-limit` replace it for search; wiring those flags into the CLI is a
//! later change, so this module only fixes the resolution contract.
//!
//! ## Precedence (highest wins)
//!
//! ```text
//! explicit CLI flag  >  environment variable  >  config file  >  built-in default
//! ```
//!
//! For `timeout` the built-in default is "no timeout" (`None`), preserving the
//! pre-#303 behavior for anyone who configures nothing. For `mode` the built-in
//! default is "unset" (`None` → hybrid-preferred downstream). For the search
//! window limits the built-in defaults are `rrf_limit = 200` and `rerank_limit
//! = 5` when reranking is enabled, and `rrf_limit = 0` ("no explicit window")
//! when it is not; see `resolve_window_limits`. (`cass pack` still sees clap's
//! built-in `0` via `resolve_limit`.)
//!
//! All resolution logic is pure (`resolve_*` take the already-read env/config
//! values as arguments) so it is unit-tested without mutating process-global env
//! — important because the test suite runs in parallel and every search test
//! transitively reads env.

use std::path::PathBuf;

use serde::Deserialize;

/// The `[search]` table of `~/.config/cass/cass.toml`.
///
/// Every field is optional: an absent field falls through to the next lower
/// precedence source. Unknown keys are ignored (forward-compatible).
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
pub struct SearchDefaults {
    /// Default search timeout in milliseconds. `None` = no timeout (legacy
    /// behavior). A value of `0` is treated as "no timeout" as well, so the
    /// config can't accidentally make every search fail instantly.
    pub timeout_ms: Option<u64>,
    /// Legacy result limit. Still read by `cass pack`; `cass search` rejects it
    /// with a migration error (see `resolve_window_limits`).
    pub limit: Option<usize>,
    /// Default rrf candidate-pool window for `cass search`. `None` = fall
    /// through to the next lower source. Resolved by `resolve_window_limits`.
    pub rrf_limit: Option<usize>,
    /// Default rerank window for `cass search`. `None` = fall through to the
    /// next lower source. Only meaningful when reranking is enabled; resolved
    /// by `resolve_window_limits`.
    pub rerank_limit: Option<usize>,
    /// Default search mode: `lexical`, `semantic`, or `hybrid`. Stored as a
    /// string here and validated at resolution time so an invalid value yields
    /// a clear error rather than a confusing deserialize failure for the whole
    /// config file.
    pub mode: Option<String>,
}

/// Top-level shape of `~/.config/cass/cass.toml`.
///
/// Only the `[search]` table is consumed today. Other tables are ignored so the
/// same file can grow additional sections later without breaking older binaries.
#[derive(Debug, Clone, Default, Deserialize)]
struct CassConfigFile {
    #[serde(default)]
    search: SearchDefaults,
}

/// Errors surfaced while loading the config file. Kept narrow and stringly so
/// callers can fold them into the existing `CliError` surface.
#[derive(Debug)]
pub enum ConfigLoadError {
    /// The file exists but could not be read.
    Read(std::io::Error),
    /// The file exists but is not valid TOML.
    Parse(String),
}

impl std::fmt::Display for ConfigLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigLoadError::Read(e) => write!(f, "failed to read cass config: {e}"),
            ConfigLoadError::Parse(e) => {
                write!(f, "invalid cass config (~/.config/cass/cass.toml): {e}")
            }
        }
    }
}

impl std::error::Error for ConfigLoadError {}

/// Resolve the path to the global cass config file (`cass.toml`), mirroring the
/// XDG resolution used for `sources.toml` so both live side-by-side.
///
/// - Primary: `$XDG_CONFIG_HOME/cass/cass.toml`
/// - Then: platform config dir (e.g. `~/Library/Application Support/cass/` on
///   macOS, `~/.config/cass/` on Linux) when it already exists
/// - Then: `~/.config/cass/cass.toml` when it already exists
/// - Else: the platform path (for documentation / future creation)
pub fn config_path() -> Option<PathBuf> {
    config_path_from_parts(
        dotenvy::var("XDG_CONFIG_HOME").ok().map(PathBuf::from),
        dirs::config_dir(),
        dirs::home_dir(),
    )
}

fn config_path_from_parts(
    xdg_config_home: Option<PathBuf>,
    platform_config_dir: Option<PathBuf>,
    home_dir: Option<PathBuf>,
) -> Option<PathBuf> {
    if let Some(xdg) = xdg_config_home {
        let trimmed = xdg.as_os_str().is_empty();
        if !trimmed {
            return Some(xdg.join("cass").join("cass.toml"));
        }
    }

    let platform_path = platform_config_dir.map(|p| p.join("cass").join("cass.toml"));
    if let Some(ref path) = platform_path
        && path.exists()
    {
        return Some(path.clone());
    }

    if let Some(home) = home_dir {
        let dot_config = home.join(".config").join("cass").join("cass.toml");
        if dot_config.exists() {
            return Some(dot_config);
        }
    }

    platform_path
}

/// Load `[search]` defaults from the config file.
///
/// Returns `Ok(SearchDefaults::default())` when the file is absent (the common
/// case) — only a present-but-broken file is an error, so a missing config is
/// never fatal.
pub fn load_search_defaults() -> Result<SearchDefaults, ConfigLoadError> {
    let Some(path) = config_path() else {
        return Ok(SearchDefaults::default());
    };
    load_search_defaults_from(&path)
}

/// Pure-ish loader against an explicit path (used by `load_search_defaults` and
/// by tests). A non-existent path yields defaults; a present file is read and
/// parsed.
pub fn load_search_defaults_from(
    path: &std::path::Path,
) -> Result<SearchDefaults, ConfigLoadError> {
    if !path.exists() {
        return Ok(SearchDefaults::default());
    }
    let contents = std::fs::read_to_string(path).map_err(ConfigLoadError::Read)?;
    parse_search_defaults(&contents)
}

/// Parse the `[search]` table out of a TOML config string.
pub fn parse_search_defaults(contents: &str) -> Result<SearchDefaults, ConfigLoadError> {
    let file: CassConfigFile =
        toml::from_str(contents).map_err(|e| ConfigLoadError::Parse(e.to_string()))?;
    Ok(file.search)
}

/// Read the timeout environment variable, accepting `CASS_SEARCH_TIMEOUT_MS`
/// (preferred, unambiguous units) and the issue's `CASS_SEARCH_TIMEOUT` as an
/// alias. `_MS` wins when both are set.
pub fn timeout_env() -> Option<String> {
    dotenvy::var("CASS_SEARCH_TIMEOUT_MS")
        .ok()
        .or_else(|| dotenvy::var("CASS_SEARCH_TIMEOUT").ok())
}

/// Read the limit environment variable (`CASS_SEARCH_LIMIT`).
pub fn limit_env() -> Option<String> {
    dotenvy::var("CASS_SEARCH_LIMIT").ok()
}

/// Read the mode environment variable (`CASS_SEARCH_MODE`).
pub fn mode_env() -> Option<String> {
    dotenvy::var("CASS_SEARCH_MODE").ok()
}

/// A single resolution outcome plus which source produced it, so callers can
/// surface a clear error message and (optionally) tell the user where a value
/// came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultSource {
    CliFlag,
    EnvVar,
    ConfigFile,
    BuiltIn,
}

/// Resolve the effective search timeout (ms) with full precedence.
///
/// * `cli` — the value of `--timeout`, if the flag was passed.
/// * `env` — the raw `CASS_SEARCH_TIMEOUT[_MS]` string, if set.
/// * `config` — the `[search].timeout_ms` from the config file, if present.
///
/// A timeout of `0` (from env or config) is normalized to `None` ("no timeout")
/// so a misconfiguration can't make every search fail before it starts; an
/// explicit `--timeout 0` on the CLI is likewise treated as "no timeout".
/// A non-numeric env value is a hard error (the operator clearly meant to set
/// it; silently ignoring would hide the typo).
pub fn resolve_timeout_ms(
    cli: Option<u64>,
    env: Option<&str>,
    config: Option<u64>,
) -> Result<(Option<u64>, DefaultSource), String> {
    if let Some(v) = cli {
        return Ok((normalize_timeout(v), DefaultSource::CliFlag));
    }
    if let Some(raw) = env {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            // An empty env var is treated as "unset" so `CASS_SEARCH_TIMEOUT=`
            // (a common way to clear a value in a shell rc) falls through.
        } else {
            let parsed: u64 = trimmed.parse().map_err(|_| {
                format!(
                    "CASS_SEARCH_TIMEOUT_MS must be a non-negative integer (milliseconds), got {raw:?}"
                )
            })?;
            return Ok((normalize_timeout(parsed), DefaultSource::EnvVar));
        }
    }
    if let Some(v) = config {
        return Ok((normalize_timeout(v), DefaultSource::ConfigFile));
    }
    Ok((None, DefaultSource::BuiltIn))
}

fn normalize_timeout(v: u64) -> Option<u64> {
    if v == 0 { None } else { Some(v) }
}

/// Resolve the effective `--limit` with full precedence.
///
/// The CLI default is `0` ("no limit"), so we cannot distinguish "user passed
/// `--limit 0`" from "user omitted `--limit`" at this layer — the caller passes
/// `cli_was_explicit` (true when the flag appeared on the command line). When
/// the flag was omitted, env then config then the built-in `0` apply.
pub fn resolve_limit(
    cli_value: usize,
    cli_was_explicit: bool,
    env: Option<&str>,
    config: Option<usize>,
) -> Result<(usize, DefaultSource), String> {
    if cli_was_explicit {
        return Ok((cli_value, DefaultSource::CliFlag));
    }
    if let Some(raw) = env {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let parsed: usize = trimmed.parse().map_err(|_| {
                format!("CASS_SEARCH_LIMIT must be a non-negative integer, got {raw:?}")
            })?;
            return Ok((parsed, DefaultSource::EnvVar));
        }
    }
    if let Some(v) = config {
        return Ok((v, DefaultSource::ConfigFile));
    }
    Ok((cli_value, DefaultSource::BuiltIn))
}

/// Resolve the effective `--mode` string with full precedence. Returns the
/// canonical lowercase mode name (`lexical` | `semantic` | `hybrid`) or `None`
/// when nothing is configured (caller falls back to hybrid-preferred).
pub fn resolve_mode(
    cli: Option<&str>,
    env: Option<&str>,
    config: Option<&str>,
) -> Result<(Option<String>, DefaultSource), String> {
    if let Some(m) = cli {
        return Ok((Some(validate_mode(m)?), DefaultSource::CliFlag));
    }
    if let Some(m) = env {
        let trimmed = m.trim();
        if !trimmed.is_empty() {
            return Ok((Some(validate_mode(trimmed)?), DefaultSource::EnvVar));
        }
    }
    if let Some(m) = config {
        let trimmed = m.trim();
        if !trimmed.is_empty() {
            return Ok((Some(validate_mode(trimmed)?), DefaultSource::ConfigFile));
        }
    }
    Ok((None, DefaultSource::BuiltIn))
}

fn validate_mode(value: &str) -> Result<String, String> {
    match value.to_ascii_lowercase().as_str() {
        m @ ("lexical" | "semantic" | "hybrid") => Ok(m.to_string()),
        other => Err(format!(
            "invalid search mode {other:?}; expected one of: lexical, semantic, hybrid"
        )),
    }
}

/// Largest accepted window size for either search window limit.
///
/// The window stage needs both `N` and `N + 1` to be representable as `usize`
/// and as `i64`, so the largest valid value is `i64::MAX - 1`.
const MAX_WINDOW_LIMIT: u64 = (i64::MAX as u64) - 1;

/// Built-in rrf window when no source sets one and reranking is on.
const DEFAULT_RRF_WINDOW: usize = 200;

/// Built-in rerank window when no source sets one and reranking is on.
const DEFAULT_RERANK_WINDOW: usize = 5;

/// Static message for the legacy `limit` migration. It never echoes the value
/// the caller supplied.
const WINDOW_LIMIT_MIGRATION_ERROR: &str = "cass search no longer accepts the legacy limit setting; \
     use --rrf-limit / --rerank-limit on the command line, or CASS_RRF_LIMIT / CASS_RERANK_LIMIT \
     in the environment";

/// Static message for an out-of-range window amount. It never echoes the value
/// the caller supplied.
const WINDOW_AMOUNT_ERROR: &str = "window limit must be a positive decimal integer within range";

/// Static message for `rerank_limit > rrf_limit`.
const WINDOW_K_GT_N_ERROR: &str = "rerank window limit must not exceed the rrf window limit";

/// Static message for an explicit CLI rerank window while reranking is off.
const WINDOW_CLI_K_WHEN_OFF_ERROR: &str =
    "rerank window limit is only accepted when reranking is enabled";

/// Raw, already-read inputs for `cass search` window-limit resolution.
///
/// [`resolve_window_limits`] is pure: it never reads the environment or the
/// filesystem, so the caller supplies the raw strings it already fetched plus
/// the parsed config. The `cli_*` values are `Some` only when the operator
/// passed the flag explicitly, so `Some(0)` means "explicit zero" rather than
/// "omitted".
#[derive(Debug)]
pub struct WindowLimitInputs<'a> {
    /// Whether the rerank stage is enabled for this run.
    pub rerank: bool,
    /// `--rrf-limit`, present only when the flag was passed.
    pub cli_rrf: Option<usize>,
    /// `--rerank-limit`, present only when the flag was passed.
    pub cli_rerank: Option<usize>,
    /// Raw `CASS_RRF_LIMIT`, if set.
    pub env_rrf: Option<&'a str>,
    /// Raw `CASS_RERANK_LIMIT`, if set.
    pub env_rerank: Option<&'a str>,
    /// Raw legacy `CASS_SEARCH_LIMIT`, if set. Any value, including an empty
    /// string, triggers the migration error.
    pub env_legacy_limit: Option<&'a str>,
    /// Parsed `[search]` table from the config file.
    pub config: &'a SearchDefaults,
}

/// A resolved pair of window limits plus their provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedWindowLimits {
    /// Effective rrf candidate-pool window. `0` is the built-in "no explicit
    /// window" sentinel (rerank off, no source configured one); a user-supplied
    /// `0` is always rejected.
    pub rrf_limit: usize,
    pub rrf_source: DefaultSource,
    /// Effective rerank window, present only when reranking is enabled.
    pub rerank_limit: Option<usize>,
    pub rerank_source: Option<DefaultSource>,
}

/// Resolve the `cass search` window limits (`--rrf-limit` / `--rerank-limit`)
/// with the same CLI > env > config > built-in precedence as the other
/// defaults.
///
/// Only the layer that actually wins is validated, so a valid higher layer
/// overrides a zero or malformed lower layer. The legacy `limit` setting (env
/// `env_legacy_limit` or `config.limit`) is always a migration error and cannot
/// be overridden by the new arguments.
///
/// Validation is closed: a window amount must be nonzero, and `N` plus `N + 1`
/// must fit in both `usize` and `i64`. When reranking is enabled the rerank
/// window must be at least `1` and at most the rrf window. Error messages never
/// echo the caller's raw input.
pub fn resolve_window_limits(input: WindowLimitInputs<'_>) -> Result<ResolvedWindowLimits, String> {
    if input.env_legacy_limit.is_some() || input.config.limit.is_some() {
        return Err(WINDOW_LIMIT_MIGRATION_ERROR.to_string());
    }

    // With reranking off only the rrf window is parsed, and an explicit CLI
    // rerank window is rejected outright; env/config rerank values are ignored.
    if !input.rerank && input.cli_rerank.is_some() {
        return Err(WINDOW_CLI_K_WHEN_OFF_ERROR.to_string());
    }

    let rrf_builtin = if input.rerank { DEFAULT_RRF_WINDOW } else { 0 };
    let (rrf_limit, rrf_source) = resolve_window_amount(
        input.cli_rrf,
        input.env_rrf,
        input.config.rrf_limit,
        rrf_builtin,
        WINDOW_AMOUNT_ERROR,
    )?;

    if !input.rerank {
        return Ok(ResolvedWindowLimits {
            rrf_limit,
            rrf_source,
            rerank_limit: None,
            rerank_source: None,
        });
    }

    let (rerank_limit, rerank_source) = resolve_window_amount(
        input.cli_rerank,
        input.env_rerank,
        input.config.rerank_limit,
        DEFAULT_RERANK_WINDOW,
        WINDOW_AMOUNT_ERROR,
    )?;

    if rerank_limit > rrf_limit {
        return Err(WINDOW_K_GT_N_ERROR.to_string());
    }

    Ok(ResolvedWindowLimits {
        rrf_limit,
        rrf_source,
        rerank_limit: Some(rerank_limit),
        rerank_source: Some(rerank_source),
    })
}

/// Select and validate one window amount across the four layers. The built-in
/// value is returned as-is: an implicit `0` for a disabled rerank is the
/// legacy "no explicit window" sentinel, not a user-supplied zero.
fn resolve_window_amount(
    cli: Option<usize>,
    env: Option<&str>,
    config: Option<usize>,
    builtin: usize,
    error: &'static str,
) -> Result<(usize, DefaultSource), String> {
    if let Some(v) = cli {
        return Ok((validate_window_amount(v, error)?, DefaultSource::CliFlag));
    }
    if let Some(raw) = env {
        return Ok((parse_window_env(raw, error)?, DefaultSource::EnvVar));
    }
    if let Some(v) = config {
        return Ok((validate_window_amount(v, error)?, DefaultSource::ConfigFile));
    }
    Ok((builtin, DefaultSource::BuiltIn))
}

/// Accept a window amount only when it is nonzero and `n` and `n + 1` fit in
/// both `usize` and `i64`.
fn validate_window_amount(value: usize, error: &'static str) -> Result<usize, String> {
    let in_range =
        value != 0 && value.checked_add(1).is_some() && (value as u64) <= MAX_WINDOW_LIMIT;
    if in_range {
        Ok(value)
    } else {
        Err(error.to_string())
    }
}

/// Parse a raw env string. After trimming, only ASCII decimal digits are
/// allowed; the value must be positive and within range. The raw input is never
/// echoed in the error.
fn parse_window_env(raw: &str, error: &'static str) -> Result<usize, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(error.to_string());
    }
    let parsed: u64 = trimmed.parse().map_err(|_| error.to_string())?;
    let amount = usize::try_from(parsed).map_err(|_| error.to_string())?;
    validate_window_amount(amount, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_cli_beats_env_and_config() {
        let (v, src) = resolve_timeout_ms(Some(1000), Some("2000"), Some(3000)).unwrap();
        assert_eq!(v, Some(1000));
        assert_eq!(src, DefaultSource::CliFlag);
    }

    #[test]
    fn timeout_env_beats_config_when_no_cli() {
        let (v, src) = resolve_timeout_ms(None, Some("2000"), Some(3000)).unwrap();
        assert_eq!(v, Some(2000));
        assert_eq!(src, DefaultSource::EnvVar);
    }

    #[test]
    fn timeout_config_used_when_no_cli_or_env() {
        let (v, src) = resolve_timeout_ms(None, None, Some(3000)).unwrap();
        assert_eq!(v, Some(3000));
        assert_eq!(src, DefaultSource::ConfigFile);
    }

    #[test]
    fn timeout_builtin_is_none() {
        let (v, src) = resolve_timeout_ms(None, None, None).unwrap();
        assert_eq!(v, None);
        assert_eq!(src, DefaultSource::BuiltIn);
    }

    #[test]
    fn timeout_zero_normalizes_to_none_everywhere() {
        assert_eq!(resolve_timeout_ms(Some(0), None, None).unwrap().0, None);
        assert_eq!(resolve_timeout_ms(None, Some("0"), None).unwrap().0, None);
        assert_eq!(resolve_timeout_ms(None, None, Some(0)).unwrap().0, None);
    }

    #[test]
    fn timeout_empty_env_falls_through_to_config() {
        let (v, src) = resolve_timeout_ms(None, Some("   "), Some(3000)).unwrap();
        assert_eq!(v, Some(3000));
        assert_eq!(src, DefaultSource::ConfigFile);
    }

    #[test]
    fn timeout_non_numeric_env_is_an_error() {
        let err = resolve_timeout_ms(None, Some("soon"), None).unwrap_err();
        assert!(err.contains("CASS_SEARCH_TIMEOUT_MS"), "{err}");
    }

    #[test]
    fn limit_explicit_cli_wins_even_at_zero() {
        let (v, src) = resolve_limit(0, true, Some("200"), Some(300)).unwrap();
        assert_eq!(v, 0);
        assert_eq!(src, DefaultSource::CliFlag);
    }

    #[test]
    fn limit_env_then_config_then_builtin() {
        assert_eq!(
            resolve_limit(0, false, Some("200"), Some(300)).unwrap(),
            (200, DefaultSource::EnvVar)
        );
        assert_eq!(
            resolve_limit(0, false, None, Some(300)).unwrap(),
            (300, DefaultSource::ConfigFile)
        );
        assert_eq!(
            resolve_limit(0, false, None, None).unwrap(),
            (0, DefaultSource::BuiltIn)
        );
    }

    #[test]
    fn limit_non_numeric_env_is_an_error() {
        assert!(resolve_limit(0, false, Some("lots"), None).is_err());
    }

    #[test]
    fn mode_precedence_and_canonicalization() {
        assert_eq!(
            resolve_mode(Some("LEXICAL"), Some("semantic"), Some("hybrid")).unwrap(),
            (Some("lexical".to_string()), DefaultSource::CliFlag)
        );
        assert_eq!(
            resolve_mode(None, Some("Semantic"), Some("hybrid")).unwrap(),
            (Some("semantic".to_string()), DefaultSource::EnvVar)
        );
        assert_eq!(
            resolve_mode(None, None, Some("Hybrid")).unwrap(),
            (Some("hybrid".to_string()), DefaultSource::ConfigFile)
        );
        assert_eq!(
            resolve_mode(None, None, None).unwrap(),
            (None, DefaultSource::BuiltIn)
        );
    }

    #[test]
    fn mode_invalid_value_is_an_error() {
        assert!(resolve_mode(None, Some("fuzzy"), None).is_err());
        assert!(resolve_mode(None, None, Some("vector")).is_err());
    }

    #[test]
    fn parse_full_search_table() {
        let toml = r#"
            [search]
            timeout_ms = 300000
            limit = 200
            mode = "hybrid"
        "#;
        let d = parse_search_defaults(toml).unwrap();
        assert_eq!(d.timeout_ms, Some(300000));
        assert_eq!(d.limit, Some(200));
        assert_eq!(d.mode.as_deref(), Some("hybrid"));
    }

    #[test]
    fn parse_partial_search_table() {
        let toml = "[search]\ntimeout_ms = 5000\n";
        let d = parse_search_defaults(toml).unwrap();
        assert_eq!(d.timeout_ms, Some(5000));
        assert_eq!(d.limit, None);
        assert_eq!(d.mode, None);
    }

    #[test]
    fn parse_empty_or_unrelated_config_is_default() {
        assert_eq!(
            parse_search_defaults("").unwrap(),
            SearchDefaults::default()
        );
        // An unrelated table (e.g. a future section) must not error.
        assert_eq!(
            parse_search_defaults("[other]\nfoo = 1\n").unwrap(),
            SearchDefaults::default()
        );
    }

    #[test]
    fn parse_unknown_keys_in_search_table_are_ignored() {
        let toml = "[search]\ntimeout_ms = 1\nfuture_key = true\n";
        let d = parse_search_defaults(toml).unwrap();
        assert_eq!(d.timeout_ms, Some(1));
    }

    #[test]
    fn parse_broken_toml_is_an_error() {
        assert!(parse_search_defaults("[search\ntimeout_ms = ").is_err());
    }

    #[test]
    fn load_from_missing_path_is_default() {
        let d = load_search_defaults_from(std::path::Path::new(
            "/nonexistent/cass/cass.toml.definitely-not-here",
        ))
        .unwrap();
        assert_eq!(d, SearchDefaults::default());
    }

    #[test]
    fn config_path_prefers_xdg_config_home() {
        let p = config_path_from_parts(
            Some(PathBuf::from("/xdg")),
            Some(PathBuf::from("/platform")),
            Some(PathBuf::from("/home/u")),
        )
        .unwrap();
        assert_eq!(p, PathBuf::from("/xdg/cass/cass.toml"));
    }

    #[test]
    fn config_path_falls_back_to_platform_when_no_files_exist() {
        // Neither platform nor ~/.config file exists -> platform path returned.
        let p = config_path_from_parts(
            None,
            Some(PathBuf::from("/platform")),
            Some(PathBuf::from("/home/definitely-missing")),
        )
        .unwrap();
        assert_eq!(p, PathBuf::from("/platform/cass/cass.toml"));
    }

    // ---- search window limits (P08a) ----

    /// Base `WindowLimitInputs` for a run with reranking off and nothing set;
    /// each test tweaks only the fields it exercises.
    fn base_inputs(config: &SearchDefaults) -> WindowLimitInputs<'_> {
        WindowLimitInputs {
            rerank: false,
            cli_rrf: None,
            cli_rerank: None,
            env_rrf: None,
            env_rerank: None,
            env_legacy_limit: None,
            config,
        }
    }

    #[test]
    fn window_all_defaults_off_is_zero_builtin_without_rerank() {
        let cfg = SearchDefaults::default();
        let r = resolve_window_limits(base_inputs(&cfg)).unwrap();
        assert_eq!(r.rrf_limit, 0);
        assert_eq!(r.rrf_source, DefaultSource::BuiltIn);
        assert_eq!(r.rerank_limit, None);
        assert_eq!(r.rerank_source, None);
    }

    #[test]
    fn window_all_defaults_on_is_200_5_builtin() {
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        let r = resolve_window_limits(i).unwrap();
        assert_eq!(r.rrf_limit, 200);
        assert_eq!(r.rrf_source, DefaultSource::BuiltIn);
        assert_eq!(r.rerank_limit, Some(5));
        assert_eq!(r.rerank_source, Some(DefaultSource::BuiltIn));
    }

    #[test]
    fn window_cli_layer_is_selected() {
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(300);
        i.cli_rerank = Some(7);
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rrf_source), (300, DefaultSource::CliFlag));
        assert_eq!(
            (r.rerank_limit, r.rerank_source),
            (Some(7), Some(DefaultSource::CliFlag))
        );
    }

    #[test]
    fn window_env_layer_is_selected() {
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.env_rrf = Some("300");
        i.env_rerank = Some("7");
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rrf_source), (300, DefaultSource::EnvVar));
        assert_eq!(
            (r.rerank_limit, r.rerank_source),
            (Some(7), Some(DefaultSource::EnvVar))
        );
    }

    #[test]
    fn window_config_layer_is_selected() {
        let cfg = SearchDefaults {
            rrf_limit: Some(300),
            rerank_limit: Some(7),
            ..SearchDefaults::default()
        };
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        let r = resolve_window_limits(i).unwrap();
        assert_eq!(
            (r.rrf_limit, r.rrf_source),
            (300, DefaultSource::ConfigFile)
        );
        assert_eq!(
            (r.rerank_limit, r.rerank_source),
            (Some(7), Some(DefaultSource::ConfigFile))
        );
    }

    #[test]
    fn window_valid_cli_overrides_bad_env_and_config() {
        let cfg = SearchDefaults {
            rrf_limit: Some(0),
            rerank_limit: Some(0),
            ..SearchDefaults::default()
        };
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(300);
        i.cli_rerank = Some(7);
        i.env_rrf = Some("not-a-number");
        i.env_rerank = Some("0");
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rrf_source), (300, DefaultSource::CliFlag));
        assert_eq!(
            (r.rerank_limit, r.rerank_source),
            (Some(7), Some(DefaultSource::CliFlag))
        );
    }

    #[test]
    fn window_valid_env_overrides_bad_config() {
        let cfg = SearchDefaults {
            rrf_limit: Some(0),
            rerank_limit: Some(0),
            ..SearchDefaults::default()
        };
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.env_rrf = Some("300");
        i.env_rerank = Some("7");
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rrf_source), (300, DefaultSource::EnvVar));
        assert_eq!(
            (r.rerank_limit, r.rerank_source),
            (Some(7), Some(DefaultSource::EnvVar))
        );
    }

    #[test]
    fn window_env_trims_outer_whitespace() {
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.env_rrf = Some("  \t 300 \n ");
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rrf_source), (300, DefaultSource::EnvVar));
    }

    #[test]
    fn window_env_rejects_malformed_forms() {
        let cfg = SearchDefaults::default();
        for raw in [
            "",
            "   ",
            "-5",
            "+5",
            "abc",
            "5.0",
            "12x",
            "0x10",
            "9_999",
            // u64 parse overflow
            "99999999999999999999999",
            // parses as u64 but exceeds i64::MAX - 1
            "9223372036854775807",
            "18446744073709551615",
        ] {
            let mut i = base_inputs(&cfg);
            i.env_rrf = Some(raw);
            assert!(
                resolve_window_limits(i).is_err(),
                "env rrf value {raw:?} must be rejected"
            );
        }
    }

    #[test]
    fn window_explicit_zero_rejected_for_rrf_in_every_layer() {
        // CLI
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.cli_rrf = Some(0);
        assert!(resolve_window_limits(i).is_err());
        // env
        let mut i = base_inputs(&cfg);
        i.env_rrf = Some("0");
        assert!(resolve_window_limits(i).is_err());
        // config
        let cfg = SearchDefaults {
            rrf_limit: Some(0),
            ..SearchDefaults::default()
        };
        assert!(resolve_window_limits(base_inputs(&cfg)).is_err());
    }

    #[test]
    fn window_explicit_zero_rejected_for_rerank_when_on() {
        let cfg = SearchDefaults::default();
        // CLI rerank 0
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(200);
        i.cli_rerank = Some(0);
        assert!(resolve_window_limits(i).is_err());
        // env rerank 0
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.env_rrf = Some("200");
        i.env_rerank = Some("0");
        assert!(resolve_window_limits(i).is_err());
        // config rerank 0
        let cfg = SearchDefaults {
            rrf_limit: Some(200),
            rerank_limit: Some(0),
            ..SearchDefaults::default()
        };
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        assert!(resolve_window_limits(i).is_err());
    }

    #[test]
    fn window_on_n4_without_k_is_rejected_not_clamped() {
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(4);
        assert!(resolve_window_limits(i).is_err());
    }

    #[test]
    fn window_on_n4_k4_is_accepted() {
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(4);
        i.cli_rerank = Some(4);
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rerank_limit), (4, Some(4)));
    }

    #[test]
    fn window_on_n5_without_k_uses_default_5() {
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(5);
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rerank_limit), (5, Some(5)));
        assert_eq!(r.rerank_source, Some(DefaultSource::BuiltIn));
    }

    #[test]
    fn window_on_k_greater_than_n_is_rejected() {
        let cfg = SearchDefaults::default();
        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(10);
        i.cli_rerank = Some(11);
        assert!(resolve_window_limits(i).is_err());
    }

    #[test]
    fn window_max_boundary_passes_and_next_value_is_rejected() {
        let max_allowed = (i64::MAX as usize) - 1;
        let cfg = SearchDefaults::default();

        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(max_allowed);
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rerank_limit), (max_allowed, Some(5)));

        let mut i = base_inputs(&cfg);
        i.rerank = true;
        i.cli_rrf = Some(max_allowed + 1);
        assert!(resolve_window_limits(i).is_err());

        let mut i = base_inputs(&cfg);
        i.env_rrf = Some("9223372036854775806");
        assert_eq!(
            resolve_window_limits(i).unwrap().rrf_limit,
            9223372036854775806
        );

        let mut i = base_inputs(&cfg);
        i.env_rrf = Some("9223372036854775807");
        assert!(resolve_window_limits(i).is_err());
    }

    #[test]
    fn window_off_rejects_cli_rerank_even_at_zero() {
        let cfg = SearchDefaults::default();
        for k in [Some(5), Some(0)] {
            let mut i = base_inputs(&cfg);
            i.cli_rerank = k;
            assert!(
                resolve_window_limits(i).is_err(),
                "off cli K={k:?} must be rejected"
            );
        }
    }

    #[test]
    fn window_off_ignores_env_and_config_rerank() {
        let cfg = SearchDefaults {
            rerank_limit: Some(0),
            ..SearchDefaults::default()
        };
        let mut i = base_inputs(&cfg);
        i.cli_rrf = Some(50);
        i.env_rerank = Some("0");
        let r = resolve_window_limits(i).unwrap();
        assert_eq!((r.rrf_limit, r.rrf_source), (50, DefaultSource::CliFlag));
        assert_eq!(r.rerank_limit, None);
        assert_eq!(r.rerank_source, None);

        // A garbage env rerank value is likewise ignored while reranking is off.
        let mut i = base_inputs(&cfg);
        i.env_rerank = Some("not-a-number");
        assert!(resolve_window_limits(i).is_ok());
    }

    #[test]
    fn window_legacy_env_limit_is_a_migration_error_even_with_full_cli() {
        let cfg = SearchDefaults::default();
        for legacy in ["100", "", "   "] {
            let mut i = base_inputs(&cfg);
            i.rerank = true;
            i.cli_rrf = Some(200);
            i.cli_rerank = Some(5);
            i.env_legacy_limit = Some(legacy);
            let err = resolve_window_limits(i).unwrap_err();
            assert!(err.contains("--rrf-limit"), "{err}");
            assert!(err.contains("--rerank-limit"), "{err}");
            assert!(err.contains("CASS_RRF_LIMIT"), "{err}");
            assert!(err.contains("CASS_RERANK_LIMIT"), "{err}");
        }
    }

    #[test]
    fn window_legacy_config_limit_is_a_migration_error_even_at_zero() {
        for legacy in [0usize, 100, usize::MAX] {
            let cfg = SearchDefaults {
                limit: Some(legacy),
                ..SearchDefaults::default()
            };
            let mut i = base_inputs(&cfg);
            i.rerank = true;
            i.cli_rrf = Some(200);
            i.cli_rerank = Some(5);
            let err = resolve_window_limits(i).unwrap_err();
            assert!(err.contains("--rrf-limit"), "{err}");
            assert!(err.contains("--rerank-limit"), "{err}");
            assert!(err.contains("CASS_RRF_LIMIT"), "{err}");
            assert!(err.contains("CASS_RERANK_LIMIT"), "{err}");
        }
    }

    #[test]
    fn window_errors_never_echo_the_raw_input() {
        let cfg = SearchDefaults::default();

        let mut i = base_inputs(&cfg);
        i.env_legacy_limit = Some("SECRET-LEGACY-9931");
        let err = resolve_window_limits(i).unwrap_err();
        assert!(!err.contains("SECRET-LEGACY-9931"), "{err}");
        assert!(!err.contains("9931"), "{err}");

        let mut i = base_inputs(&cfg);
        i.env_rrf = Some("SECRET-ENV-7742");
        let err = resolve_window_limits(i).unwrap_err();
        assert!(!err.contains("SECRET-ENV-7742"), "{err}");
        assert!(!err.contains("7742"), "{err}");
    }

    #[test]
    fn parse_new_window_fields_load_from_toml() {
        let toml = "[search]\nrrf_limit = 200\nrerank_limit = 5\n";
        let d = parse_search_defaults(toml).unwrap();
        assert_eq!(d.rrf_limit, Some(200));
        assert_eq!(d.rerank_limit, Some(5));
        assert_eq!(d.limit, None);
        assert_eq!(d.timeout_ms, None);
        assert_eq!(d.mode, None);
    }
}
