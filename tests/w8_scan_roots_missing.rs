//! PR8 C6 — a configured root that is not there, a `sources.toml` that will not
//! load, and the doctor's three root states.
//!
//! These three tests are the acceptance evidence for AC-1, AC-2 and AC-4 of the
//! C6 task book. Every observation is taken from the real binary, because that
//! is where the four surfaces the task names actually live: the warning line,
//! `cass index --json`, `cass status --json` and `cass sources doctor --json`.
//!
//! The log assertion and the `--json` assertions are deliberately two runs of
//! the same corpus. Robot mode pins the stderr log filter to `error`
//! (`robot_aware_log_directive`, lib.rs), so a single `cass index --json`
//! invocation can never show the `warn!` the first acceptance criterion is
//! about -- and a second run over an already-indexed corpus takes the
//! "nothing changed" path, which does not re-publish the run's stats. Each
//! phase therefore starts from its own empty data directory.

use coding_agent_search::sources::provenance::Source;
use coding_agent_search::storage::sqlite::FrankenStorage;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A real claude_code session, so a scanned root actually ingests something --
/// otherwise every "the HOME root was still scanned" assertion below would pass
/// vacuously.
const CLAUDE_FIXTURE: &str =
    "tests/fixtures/claude_code_real/projects/-test-project/agent-test123.jsonl";

/// One private HOME / config / data-dir triple.
struct Env {
    /// Held for its `Drop`: deleting this deletes the tree the paths point at.
    _tmp: tempfile::TempDir,
    home: PathBuf,
    config_home: PathBuf,
    data_dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let env = Env {
            home: tmp.path().join("home"),
            config_home: tmp.path().join("config"),
            data_dir: tmp.path().join("data"),
            _tmp: tmp,
        };
        std::fs::create_dir_all(&env.home).expect("create home");
        std::fs::create_dir_all(&env.data_dir).expect("create data dir");
        env
    }

    /// A claude_code-shaped session tree under `root`.
    fn write_claude_session(&self, root: &Path, project: &str) {
        let dir = root.join("projects").join(project);
        std::fs::create_dir_all(&dir).expect("create project dir");
        std::fs::copy(CLAUDE_FIXTURE, dir.join("agent-test123.jsonl")).expect("copy fixture");
    }

    fn write_sources_config(&self, toml: &str) {
        let path = self.config_home.join("cass/sources.toml");
        std::fs::create_dir_all(path.parent().expect("config dir")).expect("create config dir");
        std::fs::write(&path, toml).expect("write sources.toml");
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("agent_search.db")
    }

    /// The binary under test with a fully private environment. `cmd.env` rather
    /// than process-global `set_var`: a subprocess gets its own copy, so these
    /// tests cannot leak into the ones that do mutate the environment (and vice
    /// versa).
    fn cass(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cass"));
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", &self.home);
        cmd.env("XDG_DATA_HOME", self.home.join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", &self.config_home);
        cmd.env("CASS_DATA_DIR", &self.data_dir);
        cmd.env("NO_COLOR", "1");
        // Both must be absent for the config to be *read*: one short-circuits
        // it, the other would re-enable the info-level chatter the robot-mode
        // filter pins off.
        cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
        cmd.env_remove("RUST_LOG");
        cmd
    }

    /// Run a subcommand and require it to succeed, returning (stdout, stderr).
    fn run(&self, args: &[&str]) -> (String, String) {
        let out = self
            .cass()
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("spawn cass {args:?}: {e}"));
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        assert!(
            out.status.success(),
            "`cass {args:?}` must succeed, got {:?}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
            out.status
        );
        (stdout, stderr)
    }

    fn run_json(&self, args: &[&str]) -> serde_json::Value {
        let (stdout, stderr) = self.run(args);
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!("`cass {args:?}` did not print JSON ({e})\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}")
        })
    }
}

fn count_conversations_under(db_path: &Path, marker: &str) -> i64 {
    let conn = rusqlite::Connection::open(db_path).expect("open db");
    conn.query_row(
        "SELECT COUNT(*) FROM conversations WHERE source_path LIKE ?1",
        [format!("%{marker}%")],
        |row| row.get(0),
    )
    .expect("count conversations")
}

/// A corpus that ingests from HOME and configures one local root that does not
/// exist. Returns the environment and the missing path.
fn ghost_root_env() -> (Env, PathBuf) {
    let env = Env::new();
    env.write_claude_session(&env.home.join(".claude"), "-home-project");
    let ghost = env.home.join("no-such-root");
    env.write_sources_config(&format!(
        "[[sources]]\nname = \"ghost\"\ntype = \"local\"\norigin_host = \"ghost-host\"\npaths = [\"{}\"]\n",
        ghost.display()
    ));
    (env, ghost)
}

/// AC-1: a configured local root whose path does not exist is named in a
/// single warning, counted in `cass index --json`, and read back by
/// `status --json` -- all while the HOME root is still scanned.
#[test]
fn missing_root_is_counted() {
    // Phase 1: the log line, in human mode.
    let (env, ghost) = ghost_root_env();
    let (_stdout, stderr) = env.run(&["index"]);
    let warns: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("configured scan root does not exist; skipped"))
        .collect();
    assert_eq!(
        warns.len(),
        1,
        "exactly one warning for the one missing root, got {warns:?}\n--- stderr ---\n{stderr}"
    );
    assert!(
        warns[0].contains("ghost"),
        "the warning must name the source: {}",
        warns[0]
    );
    assert!(
        warns[0].contains(&ghost.display().to_string()),
        "the warning must name the path: {}",
        warns[0]
    );

    // Phase 2: the run's own `--json` report, on a fresh data dir.
    let (env, ghost) = ghost_root_env();
    let payload = env.run_json(&["index", "--json"]);
    assert_eq!(
        payload["scan_roots_missing"],
        serde_json::json!(["ghost"]),
        "`cass index --json` must count the missing root: {payload}"
    );
    assert!(
        count_conversations_under(&env.db_path(), "home-project") > 0,
        "the HOME root must still be scanned while the ghost root is skipped"
    );

    // Phase 3: `status --json` reads the same list back out of the `meta` table.
    let status = env.run_json(&["status", "--json"]);
    assert_eq!(
        status["last_index"]["scan_roots_missing"],
        serde_json::json!(["ghost"]),
        "`status --json` must read the list back: {status}"
    );
    assert!(
        status["last_index"]["sources_config_error"].is_null(),
        "a config that loads must not report an error: {status}"
    );
    assert!(!ghost.exists(), "this test's premise is that the root is absent");
}

/// AC-2: `cass sources doctor --json` reports `missing` / `empty` / `present`
/// for each configured root, under a field named `state`, and a local source
/// carries none of the remote-side checks.
#[test]
fn doctor_three_states() {
    let env = Env::new();
    let missing_root = env.home.join("missing-root");
    let empty_root = env.home.join("empty-root");
    std::fs::create_dir_all(&empty_root).expect("create empty root");
    let present_root = env.home.join("present-root");
    env.write_claude_session(&present_root, "-present-project");

    env.write_sources_config(&format!(
        "[[sources]]\nname = \"missing\"\ntype = \"local\"\norigin_host = \"host-a\"\npaths = [\"{missing}\"]\n\n\
         [[sources]]\nname = \"empty\"\ntype = \"local\"\norigin_host = \"host-b\"\npaths = [\"{empty}\"]\n\n\
         [[sources]]\nname = \"present\"\ntype = \"local\"\norigin_host = \"host-c\"\npaths = [\"{present}\"]\n",
        missing = missing_root.display(),
        empty = empty_root.display(),
        present = present_root.display(),
    ));

    let value = env.run_json(&["sources", "doctor", "--json"]);
    let diagnostics = value["diagnostics"]
        .as_array()
        .unwrap_or_else(|| panic!("doctor output must carry diagnostics: {value}"));

    let state_of = |source_id: &str| -> String {
        let entry = diagnostics
            .iter()
            .find(|d| d["source_id"] == source_id)
            .unwrap_or_else(|| panic!("no diagnostics for {source_id}: {value}"));
        let roots = entry["roots"]
            .as_array()
            .unwrap_or_else(|| panic!("{source_id} must list its roots: {entry}"));
        assert_eq!(roots.len(), 1, "{source_id} configures one root: {entry}");
        roots[0]["state"]
            .as_str()
            .unwrap_or_else(|| panic!("{source_id} root must carry `state`: {entry}"))
            .to_string()
    };

    assert_eq!(state_of("missing"), "missing");
    assert_eq!(state_of("empty"), "empty");
    assert_eq!(state_of("present"), "present");

    for source_id in ["missing", "empty", "present"] {
        let entry = diagnostics
            .iter()
            .find(|d| d["source_id"] == source_id)
            .expect("checked above");
        let names: Vec<&str> = entry["checks"]
            .as_array()
            .expect("checks array")
            .iter()
            .filter_map(|check| check["name"].as_str())
            .collect();
        for name in &names {
            assert!(
                !name.starts_with("SSH Connectivity")
                    && !name.starts_with("rsync Available")
                    && !name.starts_with("Remote Path"),
                "a local source must carry no remote-side checks, but {source_id} has {name:?} ({names:?})"
            );
        }
    }
}

/// AC-4: a `sources.toml` that will not load is reported once as an error, is
/// visible in `cass index --json` and `status --json`, makes the doctor say
/// `invalid` (exit 9), still scans the HOME root, and does **not** fall back to
/// the DB-registered sources.
#[test]
fn invalid_config_is_visible() {
    // The config is broken in the one way PR8 C5 made fatal: no `origin_host`.
    let broken_config = |env: &Env| {
        env.write_sources_config(
            "[[sources]]\nname = \"laptop\"\ntype = \"local\"\npaths = [\"/tmp/whatever\"]\n",
        );
    };

    // A DB-registered source the fallback *would* have picked up. Its session
    // must not appear in the corpus: that absence is what makes "no longer
    // silently falls back to the DB-registered sources" a checked claim rather
    // than prose.
    let register_db_source = |env: &Env| {
        let root = env.home.join("db-registered-root");
        env.write_claude_session(&root, "-db-registered-project");
        let storage = FrankenStorage::open(&env.db_path()).expect("open storage");
        let mut source = Source::local();
        source.id = "db-registered".to_string();
        source.config_json = Some(serde_json::json!({
            "paths": [root.display().to_string()],
        }));
        storage.upsert_source(&source).expect("register source");
    };

    // Phase 1: the log line and the corpus, in human mode.
    let env = Env::new();
    env.write_claude_session(&env.home.join(".claude"), "-home-project");
    broken_config(&env);
    register_db_source(&env);

    let (_stdout, stderr) = env.run(&["index"]);
    let errors: Vec<&str> = stderr
        .lines()
        .filter(|line| line.contains("sources config failed to load"))
        .collect();
    assert!(
        !errors.is_empty(),
        "the config failure must be an error line, got:\n{stderr}"
    );
    assert!(
        errors.iter().any(|line| line.contains("origin_host")),
        "the error must carry the loader's own diagnosis, got {errors:?}"
    );
    assert!(
        count_conversations_under(&env.db_path(), "home-project") > 0,
        "the HOME root must still be scanned"
    );
    assert_eq!(
        count_conversations_under(&env.db_path(), "db-registered-project"),
        0,
        "a config that failed to load must not fall back to the DB-registered sources"
    );

    // Phase 2: the run's own `--json` report and the `meta` read-back, on a
    // fresh data dir (same corpus shape).
    let env = Env::new();
    env.write_claude_session(&env.home.join(".claude"), "-home-project");
    broken_config(&env);
    register_db_source(&env);

    let payload = env.run_json(&["index", "--json"]);
    let error_text = payload["sources_config_error"]
        .as_str()
        .unwrap_or_else(|| panic!("`cass index --json` must report the failure: {payload}"));
    assert!(
        error_text.contains("origin_host"),
        "the disclosed error must be the loader's own text: {error_text}"
    );

    let status = env.run_json(&["status", "--json"]);
    let read_back = status["last_index"]["sources_config_error"]
        .as_str()
        .unwrap_or_else(|| panic!("`status --json` must read the failure back: {status}"));
    assert!(
        read_back.contains("origin_host"),
        "the read-back error must be the same text: {read_back}"
    );

    // Phase 3: the doctor says `invalid` and keeps exit code 9.
    let out = env
        .cass()
        .args(["sources", "doctor", "--json"])
        .output()
        .expect("spawn cass sources doctor");
    assert_eq!(
        out.status.code(),
        Some(9),
        "an unreadable config keeps the doctor's exit code 9"
    );
    let doctor: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "doctor must print its structured envelope ({e}): {}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    assert_eq!(doctor["config_state"], "invalid", "doctor envelope: {doctor}");
    assert!(
        doctor["error"]
            .as_str()
            .is_some_and(|text| text.contains("origin_host")),
        "the doctor envelope must carry the reason: {doctor}"
    );
    assert_eq!(doctor["sources"], serde_json::json!([]));
}
