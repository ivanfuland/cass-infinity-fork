//! PR8 C5 — source-root config fields and the authorized sync root.
//!
//! `SourceDefinition` gains `origin_host` (required, no derivation), `readonly`
//! and `mirror_dir`. The last one stops being a decoration on an ssh source: it
//! becomes the mirror root *and* the directory `prepare_local_sync_root`
//! authorizes writes against, so a mirror on a NAS mount is writable without
//! widening the containment predicate.
//!
//! These six tests are the acceptance evidence for AC-1 … AC-5 and AC-7 of the
//! C5 task book. The baseline `--lib sources::` / `--lib indexer::` comparison,
//! the four e2e targets and the `checks.toml [report]` exit code are the AC-6
//! evidence and live in the task report, not here.

use coding_agent_search::indexer::{IndexOptions, build_scan_roots, run_index};
use coding_agent_search::sources::config::{SourceDefinition, SourcesConfig};
use coding_agent_search::sources::sync::{SyncEngine, path_to_safe_dirname};
use coding_agent_search::storage::sqlite::FrankenStorage;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// `SourcesConfig::load()` reads `XDG_CONFIG_HOME` from the process environment
/// and `build_scan_roots` calls it, so the tests that need a config on disk must
/// take turns. Same shape as the crate's own `ENV_LOCK` discipline: the window
/// covers exactly the calls under test and every variable is restored after,
/// including removing one that was previously unset.
static ENV_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` with a private environment rooted at `tmp`.
///
/// `HOME` and `XDG_DATA_HOME` are redirected on purpose: `run_index` scans the
/// agent directories derived from `HOME`, so leaving the real one in place would
/// crawl the operator's actual `~/.claude` / `~/.codex` rather than this test's
/// corpus. `CASS_IGNORE_SOURCES_CONFIG` is cleared for the same reason it is set
/// elsewhere — here the config must be *read*, not short-circuited.
fn with_private_env<T>(config_home: &Path, home: &Path, f: impl FnOnce() -> T) -> T {
    let _guard = ENV_SERIAL.lock().unwrap_or_else(|poison| poison.into_inner());

    let keys = ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "HOME", "CASS_IGNORE_SOURCES_CONFIG"];
    let saved: Vec<(&str, Option<std::ffi::OsString>)> = keys
        .iter()
        .map(|key| (*key, std::env::var_os(key)))
        .collect();

    // SAFETY: the only threads that read these variables are the tests in this
    // binary, and ENV_SERIAL keeps them from overlapping with this window.
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", config_home);
        std::env::set_var("XDG_DATA_HOME", home.join(".local/share"));
        std::env::set_var("HOME", home);
        std::env::remove_var("CASS_IGNORE_SOURCES_CONFIG");
    }

    let out = f();

    for (key, value) in saved {
        // SAFETY: as above; the window ends here.
        unsafe {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    out
}

fn write_sources_config(config_home: &Path, toml: &str) {
    let path = config_home.join("cass/sources.toml");
    std::fs::create_dir_all(path.parent().expect("config dir")).expect("create config dir");
    std::fs::write(&path, toml).expect("write sources.toml");
}

/// `(path, len, mtime)` for every entry under `root`, recursively, sorted.
///
/// mtime is compared exactly, not by a tolerance: the claim under test is that
/// ingest does not touch the root at all, so any difference is a failure.
fn snapshot_tree(root: &Path) -> Vec<(PathBuf, u64, Option<SystemTime>)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64, Option<SystemTime>)>) {
        let mut children: Vec<PathBuf> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| entry.expect("dir entry").path())
            .collect();
        children.sort();

        for child in children {
            let meta = std::fs::symlink_metadata(&child).expect("symlink_metadata");
            let is_dir = meta.is_dir();
            out.push((child.clone(), meta.len(), meta.modified().ok()));
            if is_dir {
                walk(&child, out);
            }
        }
    }

    let mut out = Vec::new();
    walk(root, &mut out);
    out
}

/// AC-1: `origin_host` is required and must match `^[A-Za-z0-9._-]{1,64}$`, and
/// the error names both the field and the source.
#[test]
fn origin_host_required() {
    let mut missing = SourceDefinition::local("laptop");
    missing.origin_host = String::new();
    let message = missing
        .validate()
        .expect_err("a source with no origin_host must not validate")
        .to_string();
    assert!(
        message.contains("origin_host"),
        "error must name the field: {message}"
    );
    assert!(
        message.contains("laptop"),
        "error must name the source: {message}"
    );

    let too_long = "a".repeat(65);
    let mut rejected: Vec<&str> = vec!["bad host", "with@at", "with/slash", "ünicode"];
    rejected.push(&too_long);
    for bad in rejected {
        let mut source = SourceDefinition::local("laptop");
        source.origin_host = bad.to_string();
        let message = source
            .validate()
            .expect_err("a malformed origin_host must not validate")
            .to_string();
        assert!(
            message.contains("origin_host"),
            "error must name the field for {bad:?}: {message}"
        );
        assert!(
            message.contains("laptop"),
            "error must name the source for {bad:?}: {message}"
        );
    }

    // The documented boundary values are accepted.
    let max_len = "a".repeat(64);
    for good in ["local", "ivanmac", "a", max_len.as_str()] {
        let mut source = SourceDefinition::local("laptop");
        source.origin_host = good.to_string();
        assert!(
            source.validate().is_ok(),
            "{good:?} must be a valid origin_host"
        );
    }
}

/// AC-2: two sources registering one normalized path are rejected, and the two
/// spellings differ (`~` versus an absolute path with a trailing separator).
#[test]
fn duplicate_path_rejected() {
    let home = dirs::home_dir().expect("home dir");

    let mut tilde = SourceDefinition::local("laptop");
    tilde.paths = vec!["~/.codex/sessions".to_string()];

    let mut absolute = SourceDefinition::local("desktop");
    absolute.paths = vec![format!("{}/.codex/sessions/", home.display())];

    let config = SourcesConfig {
        sources: vec![tilde, absolute],
        disabled_agents: vec![],
    };

    let message = config
        .validate()
        .expect_err("two sources over one path must not validate")
        .to_string();

    assert!(
        message.contains("laptop") && message.contains("desktop"),
        "error must name both sources: {message}"
    );
    assert!(
        message.contains(".codex/sessions"),
        "error must name the path: {message}"
    );
}

/// AC-3: a `mirror_dir` outside the data dir is authorized, is what `mirror_dir()`
/// returns, leaves `data_dir/remotes/<name>` uncreated, and is the mirror root
/// `build_scan_roots` produces.
#[test]
fn external_mirror_dir_is_authorized_root() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config_home = tmp.path().join("config");
    let home = tmp.path().join("home");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let external = tmp.path().join("external-mirror");

    let mut source = SourceDefinition::ssh("ivanmac", "ivanmac");
    source.paths = vec!["~/.codex/sessions".to_string()];
    source.origin_host = "ivanmac".to_string();
    source.mirror_dir = Some(external.clone());
    source.validate().expect("the source itself must be valid");

    let engine = SyncEngine::new(&data_dir);
    let mirror = engine
        .prepare_mirror_root(&source)
        .expect("an external mirror root must be authorized");
    assert_eq!(mirror, external, "prepare_mirror_root returns the mirror root");
    assert_eq!(engine.mirror_dir(&source), external);
    assert!(external.is_dir(), "the mirror root is created");
    assert!(
        !data_dir.join("remotes").join("ivanmac").exists(),
        "data_dir/remotes/<name> must not be created when mirror_dir is set"
    );

    // build_scan_roots agrees on where the mirror lives. It reads sources.toml
    // through SourcesConfig::load(), so this needs the config on disk.
    let expected_scan_root = external.join(path_to_safe_dirname("~/.codex/sessions"));
    std::fs::create_dir_all(&expected_scan_root).expect("create mirror path");

    write_sources_config(
        &config_home,
        &format!(
            "[[sources]]\nname = \"ivanmac\"\ntype = \"ssh\"\nhost = \"ivanmac\"\norigin_host = \"ivanmac\"\npaths = [\"~/.codex/sessions\"]\nmirror_dir = \"{}\"\n",
            external.display()
        ),
    );

    with_private_env(&config_home, &home, || {
        let storage =
            FrankenStorage::open(&data_dir.join("db.sqlite")).expect("open storage");
        let roots = build_scan_roots(&storage, &data_dir);

        let mirror_root = roots
            .iter()
            .find(|root| root.origin.source_id == "ivanmac")
            .expect("the ssh source must contribute a scan root");
        assert_eq!(
            mirror_root.path, expected_scan_root,
            "the scan root must live under the configured mirror_dir"
        );
        assert!(
            mirror_root.path.starts_with(&external),
            "the scan root must not fall back to data_dir/remotes: {:?}",
            mirror_root.path
        );
        assert!(
            !data_dir.join("remotes").join("ivanmac").exists(),
            "build_scan_roots must not invent data_dir/remotes/<name> either"
        );
    });
}

/// AC-4: a `readonly = true` local root is byte-identical after an index run.
///
/// The mark travels through C3's `ScanRootMeta`, which is also where the
/// configured `origin_host` reaches ingest (C5's transitional list-of-paths
/// side channel was removed in PR8 C6, once both facts had a home on the root
/// metadata). The file-tree comparison is the
/// actual claim: ingest must not create a lock, a watermark sidecar or a
/// `.tmp` under the root -- and the identity assertion below is what keeps the
/// tree comparison from being vacuous, by proving the run really did route
/// this root's session through that metadata.
#[test]
fn readonly_root_untouched() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let config_home = tmp.path().join("config");
    let home = tmp.path().join("home");
    let data_dir = tmp.path().join("data");
    let source_root = tmp.path().join("readonly-source");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    // A real claude_code shape, so the connector actually reads from this root
    // rather than the test passing because nothing was ever scanned.
    let project_dir = source_root.join("projects").join("-test-project");
    std::fs::create_dir_all(&project_dir).expect("create project dir");
    std::fs::copy(
        "tests/fixtures/claude_code_real/projects/-test-project/agent-test123.jsonl",
        project_dir.join("agent-test123.jsonl"),
    )
    .expect("copy claude fixture");

    write_sources_config(
        &config_home,
        &format!(
            "[[sources]]\nname = \"ro-local\"\ntype = \"local\"\norigin_host = \"fixture-ro\"\nreadonly = true\npaths = [\"{}\"]\n",
            source_root.display()
        ),
    );

    let before = snapshot_tree(&source_root);
    assert!(!before.is_empty(), "the fixture must not be empty");

    with_private_env(&config_home, &home, || {
        let db_path = data_dir.join("agent_search.db");
        run_index(
            IndexOptions {
                no_ingest: false,
                full: true,
                force_rebuild: true,
                watch: false,
                watch_once_paths: None,
                db_path: db_path.clone(),
                data_dir: data_dir.clone(),
                semantic: false,
                embedder: "fastembed".to_string(),
                progress: None,
                watch_interval_secs: 30,
            },
            None,
        )
        .expect("the index run must complete");

        // The run really did ingest this root's session — otherwise the
        // tree comparison below would be vacuous.
        let conn = rusqlite::Connection::open(&db_path).expect("open db");
        let ingested: i64 = conn
            .query_row("SELECT COUNT(*) FROM conversations", [], |row| row.get(0))
            .expect("count conversations");
        assert!(
            ingested > 0,
            "the readonly fixture session must have been ingested (got {ingested})"
        );

        // ...and it arrived through this root's `ScanRootMeta`: the configured
        // `origin_host` is what ingest used as the session's identity.
        let identity: String = conn
            .query_row(
                "SELECT identity_host FROM conversations WHERE source_path LIKE ?1",
                [format!("%{}%", source_root.display())],
                |row| row.get(0),
            )
            .expect("the readonly root's session must be in the corpus");
        assert_eq!(
            identity, "fixture-ro",
            "the configured root's origin_host must reach ingest as the identity"
        );
    });

    let after = snapshot_tree(&source_root);
    assert_eq!(
        before, after,
        "a readonly root must be byte-identical (paths, sizes, mtimes) after an index run"
    );
}

/// AC-7: `cass sources add` refuses to run without `--origin-host`, and with it
/// writes a `sources.toml` the real loader accepts.
///
/// The flag is required, not derived, because `origin_host` is what keeps two
/// machines' identically-pathed sessions apart — a guess here would silently
/// merge them. Driven through the real binary so the clap definition, the
/// validation and the config write path are all exercised together.
#[test]
fn sources_add_requires_origin_host() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let home = tmp.path().join("home");
    let data_dir = tmp.path().join("data");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::create_dir_all(&data_dir).expect("create data dir");

    let config_path = home.join(".config/cass/sources.toml");

    // The CLI's plain error is a single "Could not parse arguments" line, so the
    // evidence that the *required* flag is what was missing comes from clap's
    // own usage line: `--origin-host` sits in the required section, outside the
    // `[OPTIONS]` group.
    let help = cass_cmd(&home, &data_dir)
        .args(["sources", "add", "--help"])
        .output()
        .expect("spawn cass sources add --help");
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(
        help_text.contains("--origin-host <HOST> <URL>"),
        "the flag must be part of the required usage line: {help_text}"
    );

    let refused = cass_cmd(&home, &data_dir)
        .args([
            "sources",
            "add",
            "user@laptop.local",
            "--name",
            "laptop",
            "--no-test",
            "--path",
            "~/.claude/projects",
        ])
        .output()
        .expect("spawn cass sources add");
    assert_eq!(
        refused.status.code(),
        Some(2),
        "omitting --origin-host must be a usage error, got {:?}: {}",
        refused.status,
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        !config_path.exists(),
        "a refused add must not leave a sources.toml behind"
    );

    let accepted = cass_cmd(&home, &data_dir)
        .args([
            "sources",
            "add",
            "user@laptop.local",
            "--name",
            "laptop",
            "--origin-host",
            "ivanmac",
            "--no-test",
            "--path",
            "~/.claude/projects",
        ])
        .output()
        .expect("spawn cass sources add");
    assert!(
        accepted.status.success(),
        "add with --origin-host must succeed: {}",
        String::from_utf8_lossy(&accepted.stderr)
    );

    let written = std::fs::read_to_string(&config_path).expect("sources.toml must be written");
    assert!(
        written.contains("origin_host = \"ivanmac\""),
        "the written config must carry the value verbatim: {written}"
    );

    let config = SourcesConfig::load_from(&config_path).expect("the written config must load");
    assert_eq!(config.sources.len(), 1);
    assert_eq!(config.sources[0].origin_host, "ivanmac");
    assert_eq!(config.sources[0].name, "laptop");
}

/// The `cass` binary under test, spawned with a fully private environment.
///
/// `cmd.env` rather than process-global `set_var`: these two tests run in the
/// same binary as the tests that do mutate the environment, and a subprocess
/// gets its own copy, so the two styles cannot interfere.
fn cass_cmd(home: &Path, data_dir: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_cass"));
    cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
    cmd.env("HOME", home);
    cmd.env("XDG_DATA_HOME", home.join(".local/share"));
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd.env("CASS_DATA_DIR", data_dir);
    cmd.env("NO_COLOR", "1");
    // The point of this test is that the config is *read*; a short-circuit left
    // over in the ambient environment would make the assertions meaningless.
    cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
    cmd
}

/// AC-5: a pre-PR8 `sources.toml` is rejected with a migration hint that says
/// what to add, and the same file parses once the field is there.
#[test]
fn legacy_toml_migration_message() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("sources.toml");

    let legacy = "[[sources]]\nname = \"laptop\"\ntype = \"ssh\"\nhost = \"user@laptop.local\"\npaths = [\"~/.claude/projects\"]\n";
    std::fs::write(&path, legacy).expect("write legacy config");

    let message = SourcesConfig::load_from(&path)
        .expect_err("a config with no origin_host must not load")
        .to_string();
    assert!(
        message.contains("origin_host"),
        "the failure must name the missing field: {message}"
    );
    assert!(
        message.contains("[[sources]]") && message.contains("laptop"),
        "the failure must carry an actionable migration hint: {message}"
    );

    let migrated = "[[sources]]\nname = \"laptop\"\ntype = \"ssh\"\nhost = \"user@laptop.local\"\norigin_host = \"laptop\"\npaths = [\"~/.claude/projects\"]\n";
    std::fs::write(&path, migrated).expect("write migrated config");
    let config = SourcesConfig::load_from(&path).expect("the migrated config must load");
    assert_eq!(config.sources.len(), 1);
    assert_eq!(config.sources[0].origin_host, "laptop");
}
