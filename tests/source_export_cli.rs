//! Task17 acceptance tests: `cass sources facts export` (wire v3.1).
//!
//! Reproducible input prerequisites for this batch:
//! - `CASS_T17_INPUT_ROOT` points at the frozen `prepared-inputs` directory
//!   (11 families, each with its DB, fixed TOML copies, materials, profile
//!   materials and independent SQL/literal `gold.json`).
//! - `CASS_T17_CHECKER_ROOT` points at the frozen checker directory
//!   (`check_bundle.py`, `page-identities.json`, expanded cases/links gold).
//! - `CASS_T17_RESULT_ROOT` is a fresh, empty per-run directory.
//! - `CASS_T17_PYTHON` is the absolute Python 3.12 executable.
//!
//! Every case copies its own family DB/materials/fixed files into a new
//! sandbox and rewrites only the physical `fixed_copy_path` in its own copy of
//! the profile FILE. Logical identities, input keys, UUIDs, revisions,
//! receipts and all gold values are kept unchanged. The tests never write the
//! frozen inputs and never generate or update a gold file.

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use coding_agent_search::storage::api::Profile;
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::testing::open_test_writer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

static CASE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static PROCESS_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Frozen input locations
// ---------------------------------------------------------------------------

fn env_path(name: &str) -> PathBuf {
    let value =
        std::env::var(name).unwrap_or_else(|_| panic!("{name} must name the frozen Task17 input"));
    PathBuf::from(value)
}

fn input_root() -> PathBuf {
    env_path("CASS_T17_INPUT_ROOT")
}

fn checker_root() -> PathBuf {
    env_path("CASS_T17_CHECKER_ROOT")
}

fn python_path() -> PathBuf {
    env_path("CASS_T17_PYTHON")
}

fn case_root(label: &str) -> PathBuf {
    let sequence = CASE_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let root =
        env_path("CASS_T17_RESULT_ROOT").join(format!("{label}-{}-{sequence}", std::process::id()));
    fs::create_dir_all(&root).expect("create case sandbox");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("tighten case sandbox");
    root
}

fn sha256_file(path: &Path) -> String {
    let bytes = fs::read(path).expect("read file for digest");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    format!("{:x}", hasher.finalize())
}

fn family_database(family: &str) -> String {
    let index: Value = serde_json::from_slice(
        &fs::read(input_root().join("index.json")).expect("read prepared index"),
    )
    .expect("parse prepared index");
    index["families"]
        .as_array()
        .expect("families")
        .iter()
        .find(|entry| entry["family"] == family)
        .and_then(|entry| entry["database"].as_str())
        .unwrap_or_else(|| panic!("family {family} has no database"))
        .to_string()
}

fn copy_tree(source: &Path, target: &Path) {
    fs::create_dir_all(target).expect("create fixture directory");
    for entry in fs::read_dir(source).expect("read fixture directory") {
        let entry = entry.expect("fixture entry");
        let to = target.join(entry.file_name());
        if entry.file_type().expect("fixture type").is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).expect("copy fixture file");
        }
    }
}

fn write_json(path: &Path, value: &Value) {
    let mut bytes = serde_json::to_vec_pretty(value).expect("serialise fixture json");
    bytes.push(b'\n');
    fs::write(path, bytes).expect("write fixture json");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("tighten fixture json");
}

struct Fixture {
    dir: PathBuf,
    db: PathBuf,
    profile: PathBuf,
}

impl Fixture {
    fn profiles(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.profile).expect("read profile file"))
            .expect("parse profile file")
    }

    fn set_profiles(&self, value: &Value) {
        write_json(&self.profile, value);
    }

    fn fixed(&self, name: &str) -> PathBuf {
        self.dir.join("fixed").join(name)
    }
}

/// Copy one family and rewrite only the physical fixed-copy path in the
/// sandbox profile FILE. Every logical value stays byte-identical.
fn copy_family(family: &str, root: &Path) -> Fixture {
    let source = input_root().join(family);
    let dir = root.join("fixture");
    fs::create_dir_all(&dir).expect("create family sandbox");
    let database = family_database(family);
    let db = dir.join(&database);
    fs::copy(source.join(&database), &db).expect("copy family database");
    copy_tree(&source.join("fixed"), &dir.join("fixed"));
    copy_tree(&source.join("materials"), &dir.join("materials"));
    let profile_source = source.join("profile-materials.json");
    let profile = dir.join("profile-materials.json");
    let mut value: Value =
        serde_json::from_slice(&fs::read(&profile_source).expect("read family profile materials"))
            .expect("parse family profile materials");
    for item in value["profiles"].as_array_mut().expect("profiles array") {
        let original = Path::new(item["fixed_copy_path"].as_str().expect("fixed copy path"));
        let name = original
            .file_name()
            .expect("fixed copy file name")
            .to_os_string();
        item["fixed_copy_path"] = json!(
            dir.join("fixed")
                .join(name)
                .to_str()
                .expect("utf8 sandbox fixed path")
        );
    }
    write_json(&profile, &value);
    Fixture { dir, db, profile }
}

fn family_gold(family: &str) -> Value {
    serde_json::from_slice(
        &fs::read(input_root().join(family).join("gold.json")).expect("read family gold"),
    )
    .expect("parse family gold")
}

// ---------------------------------------------------------------------------
// Command environment
// ---------------------------------------------------------------------------

struct PrivateEnv {
    home: PathBuf,
    xdg_cache: PathBuf,
    xdg_config: PathBuf,
    xdg_data: PathBuf,
    xdg_state: PathBuf,
    tmp: PathBuf,
    cwd: PathBuf,
}

fn private_env(root: &Path) -> PrivateEnv {
    let home = root.join("home");
    let env = PrivateEnv {
        xdg_cache: home.join("cache"),
        xdg_config: home.join("config"),
        xdg_data: home.join("data"),
        xdg_state: home.join("state"),
        home,
        tmp: root.join("tmp"),
        cwd: root.join("cwd"),
    };
    for directory in [
        &env.xdg_cache,
        &env.xdg_config,
        &env.xdg_data,
        &env.xdg_state,
        &env.tmp,
        &env.cwd,
    ] {
        fs::create_dir_all(directory).expect("create private env directory");
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .expect("tighten private env directory");
    }
    let dotenv = env.cwd.join(".env");
    fs::write(&dotenv, b"").expect("write empty .env");
    fs::set_permissions(&dotenv, fs::Permissions::from_mode(0o600)).expect("tighten .env");
    env
}

fn apply_private_env(command: &mut Command, env: &PrivateEnv) {
    command.env_clear();
    command
        .env("HOME", &env.home)
        .env("XDG_CACHE_HOME", &env.xdg_cache)
        .env("XDG_CONFIG_HOME", &env.xdg_config)
        .env("XDG_DATA_HOME", &env.xdg_data)
        .env("XDG_STATE_HOME", &env.xdg_state)
        .env("TMPDIR", &env.tmp)
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C");
    command.current_dir(&env.cwd);
}

fn cli_binary() -> &'static str {
    env!("CARGO_BIN_EXE_cass")
}

fn export_command_with_db(
    fixture: &Fixture,
    db: &Path,
    output: &Path,
    private: &PrivateEnv,
    arguments: &[String],
    extra_env: &[(&str, String)],
) -> Command {
    let mut command = Command::new(cli_binary());
    apply_private_env(&mut command, private);
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command
        .arg("--db")
        .arg(db)
        .args([
            "sources",
            "facts",
            "export",
            "--output",
            output.to_str().expect("utf8 output path"),
            "--profile-materials",
            fixture.profile.to_str().expect("utf8 profile path"),
        ])
        .args(arguments);
    command
}

fn export_command(
    fixture: &Fixture,
    output: &Path,
    private: &PrivateEnv,
    arguments: &[String],
    extra_env: &[(&str, String)],
) -> Command {
    export_command_with_db(fixture, &fixture.db, output, private, arguments, extra_env)
}

// ---------------------------------------------------------------------------
// Recorded child processes
// ---------------------------------------------------------------------------

fn utc_now() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn proc_stat(pid: u32) -> (i32, String) {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).expect("read child stat");
    let rest: Vec<&str> = raw[raw.rfind(')').expect("child comm") + 1..]
        .split_whitespace()
        .collect();
    (rest[2].parse().expect("child pgid"), rest[19].to_string())
}

fn process_meta_dir() -> PathBuf {
    let directory = env_path("CASS_T17_RESULT_ROOT").join("process-meta");
    fs::create_dir_all(&directory).expect("create process meta directory");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
        .expect("tighten process meta directory");
    directory
}

struct RecordedChild {
    child: Child,
    sequence: u64,
    meta_path: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    started_at: String,
    pid: u32,
    pgid: i32,
    start_ticks: String,
    argv: Vec<String>,
    cwd: Option<String>,
    env_keys: Vec<String>,
}

fn spawn_recorded(command: &mut Command) -> RecordedChild {
    let sequence = PROCESS_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    let directory = process_meta_dir();
    let stdout_path = directory.join(format!("{sequence:04}.stdout"));
    let stderr_path = directory.join(format!("{sequence:04}.stderr"));
    let meta_path = directory.join(format!("{sequence:04}.meta.json"));
    let stdout_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stdout_path)
        .expect("create child stdout file");
    let stderr_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stderr_path)
        .expect("create child stderr file");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    command.process_group(0);
    let argv: Vec<String> = std::iter::once(command.get_program().to_string_lossy().into_owned())
        .chain(
            command
                .get_args()
                .map(|argument| argument.to_string_lossy().into_owned()),
        )
        .collect();
    let cwd = command
        .get_current_dir()
        .map(|path| path.to_string_lossy().into_owned());
    let env_keys: Vec<String> = command
        .get_envs()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    let started_at = utc_now();
    let child = command.spawn().expect("spawn recorded child");
    let pid = child.id();
    let (pgid, start_ticks) = proc_stat(pid);
    RecordedChild {
        child,
        sequence,
        meta_path,
        stdout_path,
        stderr_path,
        started_at,
        pid,
        pgid,
        start_ticks,
        argv,
        cwd,
        env_keys,
    }
}

impl RecordedChild {
    fn finish(self, status: std::process::ExitStatus) -> Output {
        let ended_at = utc_now();
        let stdout = fs::read(&self.stdout_path).expect("read child stdout");
        let stderr = fs::read(&self.stderr_path).expect("read child stderr");
        let meta = json!({
            "sequence": self.sequence,
            "argv": self.argv,
            "cwd": self.cwd,
            "env_keys": self.env_keys,
            "pid": self.pid,
            "pgid": self.pgid,
            "proc_start_ticks": self.start_ticks,
            "started_at_utc": self.started_at,
            "ended_at_utc": ended_at,
            "exit_code": status.code(),
            "signal": status.signal(),
            "stdout": self.stdout_path.to_string_lossy(),
            "stderr": self.stderr_path.to_string_lossy(),
        });
        let mut bytes = serde_json::to_vec_pretty(&meta).expect("serialise child meta");
        bytes.push(b'\n');
        fs::write(&self.meta_path, bytes).expect("write child meta");
        Output {
            status,
            stdout,
            stderr,
        }
    }

    fn wait(mut self) -> Output {
        let status = self.child.wait().expect("wait recorded child");
        self.finish(status)
    }
}

fn run(command: &mut Command) -> Output {
    spawn_recorded(command).wait()
}

// ---------------------------------------------------------------------------
// Read-only input database snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
struct DbSnapshot {
    main_sha256: String,
    rows_sha256: String,
    inputs: i64,
    records: i64,
    links: i64,
}

fn snapshot_db(db: &Path) -> DbSnapshot {
    let main_sha256 = sha256_file(db);
    // The frozen AGENTS rule requires every new SQLite read to go through the
    // frankensqlite-compatible storage layer; no rusqlite connection is used.
    let storage =
        FrankenStorage::open_readonly(db).expect("open input database read-only for snapshot");
    let connection = storage.raw();
    let mut canonical = String::new();

    let input_rows = connection
        .query_all_map(
            "SELECT hex(input_key), state, normalizer_id, safety_contract_id, \
             COALESCE(receipt_key, ''), COALESCE(applied_content_generation, ''), \
             hex(expected_records), COALESCE(hex(observed_records), '') \
             FROM source_inputs ORDER BY input_key",
            &[],
            |row| {
                Ok((
                    row.get_typed::<String>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<String>(2)?,
                    row.get_typed::<String>(3)?,
                    row.get_typed::<String>(4)?,
                    row.get_typed::<String>(5)?,
                    row.get_typed::<String>(6)?,
                    row.get_typed::<String>(7)?,
                ))
            },
        )
        .expect("query input snapshot");
    let inputs = input_rows.len() as i64;
    for (key, state, normalizer, safety, receipt, generation, expected, observed) in input_rows {
        canonical.push_str(&format!(
            "input|{key}|{state}|{normalizer}|{safety}|{receipt}|{generation}|{expected}|{observed}\n"
        ));
    }

    let record_rows = connection
        .query_all_map(
            "SELECT hex(i.input_key), hex(r.ordinal), r.record_pointer, \
             hex(r.expected_source_record_sha256), r.frame_state, r.parse_state, \
             r.safety_state, r.retention_state \
             FROM source_records r JOIN source_inputs i ON i.id = r.input_id \
             ORDER BY i.input_key, r.ordinal",
            &[],
            |row| {
                Ok((
                    row.get_typed::<String>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<String>(2)?,
                    row.get_typed::<String>(3)?,
                    row.get_typed::<String>(4)?,
                    row.get_typed::<String>(5)?,
                    row.get_typed::<String>(6)?,
                    row.get_typed::<String>(7)?,
                ))
            },
        )
        .expect("query record snapshot");
    let records = record_rows.len() as i64;
    for (key, ordinal, pointer, expected, frame, parse, safety, retention) in record_rows {
        canonical.push_str(&format!(
            "record|{key}|{ordinal}|{pointer}|{expected}|{frame}|{parse}|{safety}|{retention}\n"
        ));
    }

    let link_rows = connection
        .query_all_map(
            "SELECT hex(i.input_key), COALESCE(l.projection_pointer, ''), \
             COALESCE(CAST(l.message_id AS TEXT), ''), COALESCE(l.authority, ''), \
             hex(l.binding_digest) \
             FROM source_message_links l \
             JOIN source_records r ON r.id = l.record_id \
             JOIN source_inputs i ON i.id = r.input_id \
             ORDER BY i.input_key, r.ordinal, l.id",
            &[],
            |row| {
                Ok((
                    row.get_typed::<String>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<String>(2)?,
                    row.get_typed::<String>(3)?,
                    row.get_typed::<String>(4)?,
                ))
            },
        )
        .expect("query link snapshot");
    let links = link_rows.len() as i64;
    for (key, pointer, message_id, authority, digest) in link_rows {
        canonical.push_str(&format!(
            "link|{key}|{pointer}|{message_id}|{authority}|{digest}\n"
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    DbSnapshot {
        main_sha256,
        rows_sha256: format!("{:x}", hasher.finalize()),
        inputs,
        records,
        links,
    }
}

fn run_with_db_check(command: &mut Command, db: &Path) -> Output {
    if !db.is_file() {
        return run(command);
    }
    let before = snapshot_db(db);
    let output = run(command);
    let after = snapshot_db(db);
    if output.status.success() {
        assert_eq!(
            before, after,
            "successful export must not write its input database"
        );
    }
    output
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn assert_kind(output: &Output, kind: &str) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded; stdout={} stderr={}",
        stdout_text(output),
        stderr_text(output)
    );
    let text = stderr_text(output);
    if let Ok(value) = serde_json::from_str::<Value>(text.trim()) {
        assert_eq!(
            value["error"]["kind"].as_str(),
            Some(kind),
            "unexpected error envelope: {text}"
        );
        assert_eq!(value["error"]["message"].as_str(), Some(kind));
        assert!(value["error"]["hint"].is_null());
    } else {
        assert!(
            text.contains(kind),
            "expected kind {kind}, stderr was: {text}"
        );
    }
}

fn assert_clap_exit(output: &Output) {
    assert_eq!(output.status.code(), Some(2), "expected clap exit 2");
}

fn marker_present(output: &Path) -> bool {
    fs::symlink_metadata(output.join("INCOMPLETE.json")).is_ok()
}

fn index_present(output: &Path) -> bool {
    output.join("index.json").is_file()
}

fn assert_incomplete(output: &Path) {
    assert!(marker_present(output), "INCOMPLETE marker must remain");
    assert!(!index_present(output), "no final index may be published");
}

fn read_index(output: &Path) -> Value {
    serde_json::from_slice(&fs::read(output.join("index.json")).expect("read index"))
        .expect("parse index")
}

fn summary(output: &Path) -> (u64, u64, u64, u64) {
    let index = read_index(output);
    let number = |key: &str| {
        index[key]
            .as_str()
            .expect("decimal string")
            .parse::<u64>()
            .expect("decimal")
    };
    let pages = index["pages"].as_array().expect("pages array").len() as u64;
    (
        pages,
        number("unique_input_count"),
        number("record_count"),
        number("oversized_records"),
    )
}

fn assert_counts(output: &Path, expected: (u64, u64, u64, u64)) {
    assert_eq!(summary(output), expected, "package counts");
}

// ---------------------------------------------------------------------------
// Strict checker invocation
// ---------------------------------------------------------------------------

struct CheckerSpec<'a> {
    family: &'a str,
    scope: &'a str,
    max_records: u64,
    target_bytes: u64,
    input_keys: &'a [String],
    connectors: &'a [String],
    partitions: Option<(&'a str, &'a str)>,
    default_oversized: u64,
}

fn checker_gold(family: &str) -> PathBuf {
    // The dispatch-bound independent SQL/literal gold lives with its family.
    // The checker's bundled expanded golds predate the runtime UUID binding and
    // therefore cannot be the oracle for the bound prepared databases.
    input_root().join(family).join("gold.json")
}

fn check_bundle(bundle: &Path, spec: &CheckerSpec<'_>) {
    let work = bundle.parent().expect("bundle parent").join("checker-env");
    fs::create_dir_all(&work).expect("create checker env");
    let env = private_env(&work);
    let mut command = Command::new(python_path());
    apply_private_env(&mut command, &env);
    command
        .arg(checker_root().join("check_bundle.py"))
        .arg("--gold")
        .arg(checker_gold(spec.family))
        .args(["--scope", spec.scope])
        .args(["--max-records", &spec.max_records.to_string()])
        .args(["--target-bytes", &spec.target_bytes.to_string()])
        .args(["--default-oversized", &spec.default_oversized.to_string()]);
    for key in spec.input_keys {
        command.args(["--input-key", key]);
    }
    for connector in spec.connectors {
        command.args(["--connector", connector]);
    }
    if let Some((fixture, limits)) = spec.partitions {
        command
            .arg("--partitions")
            .arg(checker_root().join("page-identities.json"))
            .args(["--fixture", fixture])
            .args(["--limits", limits]);
    }
    command.arg(bundle);
    let output = run(&mut command);
    assert!(
        output.status.success(),
        "check_bundle rejected {}: stdout={} stderr={}",
        bundle.display(),
        stdout_text(&output),
        stderr_text(&output)
    );
}

fn positive(
    family: &str,
    arguments: &[&str],
    spec: CheckerSpec<'_>,
    expected: (u64, u64, u64, u64),
) {
    let label = format!("{family}-positive");
    let root = case_root(&label);
    let fixture = copy_family(family, &root);
    let output = root.join("out");
    let private = private_env(&root);
    let args: Vec<String> = arguments.iter().map(|value| value.to_string()).collect();
    let result = run_with_db_check(
        &mut export_command(&fixture, &output, &private, &args, &[]),
        &fixture.db,
    );
    assert!(
        result.status.success(),
        "export failed: stdout={} stderr={}",
        stdout_text(&result),
        stderr_text(&result)
    );
    check_bundle(&output, &spec);
    assert_counts(&output, expected);
}

// ---------------------------------------------------------------------------
// e17_01 — complete wire
// ---------------------------------------------------------------------------

#[test]
fn e17_01_complete_wire() {
    let no_such_connector = "__C17_NO_SUCH_CONNECTOR__".to_string();
    let cases = [
        (
            "cases",
            vec!["--scope", "all_source"],
            CheckerSpec {
                family: "cases",
                scope: "all_source",
                max_records: 64,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: None,
                default_oversized: 0,
            },
            (1, 25, 24, 0),
        ),
        (
            "links",
            vec!["--scope", "all_source"],
            CheckerSpec {
                family: "links",
                scope: "all_source",
                max_records: 64,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: None,
                default_oversized: 0,
            },
            (1, 6, 7, 0),
        ),
        (
            "cases",
            vec!["--scope", "analysis", "--max-records", "1"],
            CheckerSpec {
                family: "cases",
                scope: "analysis",
                max_records: 1,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: Some(("cases", "one-record")),
                default_oversized: 0,
            },
            (25, 25, 24, 0),
        ),
        (
            "cases",
            vec!["--scope", "history_unresolved", "--max-records", "2"],
            CheckerSpec {
                family: "cases",
                scope: "history_unresolved",
                max_records: 2,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: Some(("cases", "two-record")),
                default_oversized: 0,
            },
            (13, 25, 0, 0),
        ),
        (
            "cases",
            vec!["--scope", "all_source", "--target-bytes", "1"],
            CheckerSpec {
                family: "cases",
                scope: "all_source",
                max_records: 64,
                target_bytes: 1,
                input_keys: &[],
                connectors: &[],
                partitions: Some(("cases", "one-byte")),
                default_oversized: 0,
            },
            (24, 25, 24, 24),
        ),
        (
            "links",
            vec!["--scope", "analysis", "--max-records", "1"],
            CheckerSpec {
                family: "links",
                scope: "analysis",
                max_records: 1,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: Some(("links", "one-record")),
                default_oversized: 0,
            },
            (5, 4, 4, 0),
        ),
        (
            "links",
            vec!["--scope", "history_unresolved", "--target-bytes", "1"],
            CheckerSpec {
                family: "links",
                scope: "history_unresolved",
                max_records: 64,
                target_bytes: 1,
                input_keys: &[],
                connectors: &[],
                partitions: Some(("links", "one-byte")),
                default_oversized: 0,
            },
            (3, 4, 2, 2),
        ),
        (
            "links",
            vec!["--scope", "all_source", "--max-records", "2"],
            CheckerSpec {
                family: "links",
                scope: "all_source",
                max_records: 2,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: Some(("links", "two-record")),
                default_oversized: 0,
            },
            (4, 6, 7, 0),
        ),
        (
            "large",
            vec!["--scope", "all_source"],
            CheckerSpec {
                family: "large",
                scope: "all_source",
                max_records: 64,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: None,
                default_oversized: 1,
            },
            (1, 1, 1, 1),
        ),
        (
            "cases",
            vec![
                "--scope",
                "all_source",
                "--connectors",
                no_such_connector.as_str(),
            ],
            CheckerSpec {
                family: "cases",
                scope: "all_source",
                max_records: 64,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: std::slice::from_ref(&no_such_connector),
                partitions: None,
                default_oversized: 0,
            },
            (1, 0, 0, 0),
        ),
    ];
    assert_eq!(cases.len(), 10, "e17_01 has ten cells");
    for (family, arguments, spec, expected) in cases {
        let label = format!("e17_01-{}", family);
        let root = case_root(&label);
        let fixture = copy_family(family, &root);
        let output = root.join("out");
        let private = private_env(&root);
        let args: Vec<String> = arguments.into_iter().map(str::to_string).collect();
        let result = run_with_db_check(
            &mut export_command(&fixture, &output, &private, &args, &[]),
            &fixture.db,
        );
        assert!(
            result.status.success(),
            "case {label} failed: stdout={} stderr={}",
            stdout_text(&result),
            stderr_text(&result)
        );
        check_bundle(&output, &spec);
        assert_counts(&output, expected);
    }
}

// ---------------------------------------------------------------------------
// e17_02 — filters and limits
// ---------------------------------------------------------------------------

#[test]
fn e17_02_filter_and_limits() {
    let key_one = "05fb6f41f335caa1f2670db030651c0ab876444911f695d14babe39c04a4c6bf";
    let key_two = "4ec9016a4b5eb9c235730bf846d8ded4f1b852695134e3a892fabf68988303ea";

    positive(
        "links",
        &[],
        CheckerSpec {
            family: "links",
            scope: "analysis",
            max_records: 64,
            target_bytes: 8_388_608,
            input_keys: &[],
            connectors: &[],
            partitions: None,
            default_oversized: 0,
        },
        (1, 4, 4, 0),
    );

    positive(
        "cases",
        &[
            "--scope",
            "all_source",
            "--connectors",
            "codex",
            "--connectors",
            "claude_code",
            "--connectors",
            "codex",
        ],
        CheckerSpec {
            family: "cases",
            scope: "all_source",
            max_records: 64,
            target_bytes: 8_388_608,
            input_keys: &[],
            connectors: &["claude_code".to_string(), "codex".to_string()],
            partitions: None,
            default_oversized: 0,
        },
        (1, 25, 24, 0),
    );

    let repeat_keys = [key_one.to_string(), key_two.to_string()];
    positive(
        "cases",
        &[
            "--scope",
            "all_source",
            "--input-keys",
            key_one,
            "--input-keys",
            key_two,
            "--input-keys",
            key_one,
        ],
        CheckerSpec {
            family: "cases",
            scope: "all_source",
            max_records: 64,
            target_bytes: 8_388_608,
            input_keys: &repeat_keys,
            connectors: &[],
            partitions: None,
            default_oversized: 0,
        },
        (1, 2, 1, 0),
    );

    let raw_connectors = [" claude_code".to_string(), "claude_code,codex".to_string()];
    positive(
        "cases",
        &[
            "--scope",
            "all_source",
            "--connectors",
            " claude_code",
            "--connectors",
            "claude_code,codex",
        ],
        CheckerSpec {
            family: "cases",
            scope: "all_source",
            max_records: 64,
            target_bytes: 8_388_608,
            input_keys: &[],
            connectors: &raw_connectors,
            partitions: None,
            default_oversized: 0,
        },
        (1, 0, 0, 0),
    );

    // Upper-case input key: clap refuses before any output directory exists.
    {
        let root = case_root("e17_02-uppercase");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        let private = private_env(&root);
        let args = vec![
            "--scope".to_string(),
            "all_source".to_string(),
            "--input-keys".to_string(),
            "A".repeat(64),
        ];
        let result = run(&mut export_command(&fixture, &output, &private, &args, &[]));
        assert_clap_exit(&result);
        assert!(!output.exists(), "clap refusal must not create the output");
    }

    // Zero records per page is the reader's fixed invalid_cursor refusal.
    {
        let root = case_root("e17_02-zero");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        let private = private_env(&root);
        let args = vec![
            "--scope".to_string(),
            "all_source".to_string(),
            "--max-records".to_string(),
            "0".to_string(),
        ];
        let result = run_with_db_check(
            &mut export_command(&fixture, &output, &private, &args, &[]),
            &fixture.db,
        );
        assert_kind(&result, "invalid_cursor");
        assert_incomplete(&output);
    }

    // S2 error priority: opening the database comes before any page-limit
    // refusal, so a missing database is `db_error` even with target_bytes 0.
    {
        let root = case_root("e17_02-missing-db");
        let fixture = copy_family("links", &root);
        let missing = root.join("missing.db");
        let private = private_env(&root);

        let normal_out = root.join("missing-normal-out");
        let normal_args = vec!["--scope".to_string(), "all_source".to_string()];
        let normal = run(&mut export_command_with_db(
            &fixture,
            &missing,
            &normal_out,
            &private,
            &normal_args,
            &[],
        ));
        assert_kind(&normal, "db_error");
        assert_incomplete(&normal_out);

        let zero_out = root.join("missing-zero-out");
        let zero_args = vec![
            "--scope".to_string(),
            "all_source".to_string(),
            "--target-bytes".to_string(),
            "0".to_string(),
        ];
        let zero = run(&mut export_command_with_db(
            &fixture,
            &missing,
            &zero_out,
            &private,
            &zero_args,
            &[],
        ));
        assert_kind(&zero, "db_error");
        assert_incomplete(&zero_out);
    }

    // A u64 lexical overflow is refused by clap before output admission.
    {
        let root = case_root("e17_02-overflow");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        let private = private_env(&root);
        let args = vec![
            "--scope".to_string(),
            "all_source".to_string(),
            "--max-records".to_string(),
            "18446744073709551616".to_string(),
        ];
        let result = run(&mut export_command(&fixture, &output, &private, &args, &[]));
        assert_clap_exit(&result);
        assert!(!output.exists());
    }
}

// ---------------------------------------------------------------------------
// e17_03 — profile FILE structure
// ---------------------------------------------------------------------------

fn exported_with_profile(_label: &str, fixture: &Fixture, profile: &Path) -> Output {
    let output = fixture.dir.parent().expect("case parent").join("out");
    let private = private_env(fixture.dir.parent().expect("case parent"));
    let mut command = Command::new(cli_binary());
    apply_private_env(&mut command, &private);
    command.arg("--db").arg(&fixture.db).args([
        "sources",
        "facts",
        "export",
        "--output",
        output.to_str().expect("utf8 output"),
        "--profile-materials",
        profile.to_str().expect("utf8 profile"),
        "--scope",
        "all_source",
        "--json",
    ]);
    let result = run_with_db_check(&mut command, &fixture.db);
    result
}

#[test]
fn e17_03_profile_structure() {
    // 1. FILE missing.
    {
        let root = case_root("e17_03-file-missing");
        let fixture = copy_family("links", &root);
        let missing = root.join("missing.json");
        let result = exported_with_profile("file-missing", &fixture, &missing);
        assert_kind(&result, "source_export_profile_missing");
        assert_incomplete(&root.join("out"));
    }

    // 2. FILE symlink.
    {
        let root = case_root("e17_03-file-symlink");
        let fixture = copy_family("links", &root);
        let link = root.join("link.json");
        symlink(&fixture.profile, &link).expect("profile symlink");
        let result = exported_with_profile("file-symlink", &fixture, &link);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 3. FILE non-UTF8.
    {
        let root = case_root("e17_03-file-nonutf8");
        let fixture = copy_family("links", &root);
        let bad = root.join("nonutf8.json");
        fs::write(&bad, [0xff, 0xfe]).expect("write non-utf8");
        let result = exported_with_profile("file-nonutf8", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 4. Invalid JSON.
    {
        let root = case_root("e17_03-invalid-json");
        let fixture = copy_family("links", &root);
        let bad = root.join("invalid.json");
        fs::write(&bad, b"{").expect("write invalid json");
        let result = exported_with_profile("invalid-json", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 5. Duplicate top-level key.
    {
        let root = case_root("e17_03-duplicate-top-key");
        let fixture = copy_family("links", &root);
        let bad = root.join("duplicate-top.json");
        fs::write(
            &bad,
            br#"{"schema":"cass.source-profile-materials/1","schema":"cass.source-profile-materials/1","profiles":[]}"#,
        )
        .expect("write duplicate top key");
        let result = exported_with_profile("duplicate-top-key", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 6. Unknown top-level key.
    {
        let root = case_root("e17_03-unknown-top-key");
        let fixture = copy_family("links", &root);
        let mut value = fixture.profiles();
        value["extra"] = json!(true);
        let bad = root.join("unknown-top.json");
        write_json(&bad, &value);
        let result = exported_with_profile("unknown-top-key", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 7. Missing item key.
    {
        let root = case_root("e17_03-missing-item-key");
        let fixture = copy_family("links", &root);
        let mut value = fixture.profiles();
        value["profiles"][0]
            .as_object_mut()
            .expect("profile item")
            .remove("fixed_config_sha256");
        let bad = root.join("missing-item.json");
        write_json(&bad, &value);
        let result = exported_with_profile("missing-item-key", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 8. Duplicate item key.
    {
        let root = case_root("e17_03-duplicate-item-key");
        let fixture = copy_family("links", &root);
        let value = fixture.profiles();
        let item = value["profiles"][0].clone();
        let duplicate = item["normalizer_id"].as_str().expect("normalizer id");
        let item_text = serde_json::to_string(&item).expect("item json");
        let body = item_text
            .strip_prefix('{')
            .expect("item object starts with brace");
        let raw = format!(
            "{{\"schema\":\"cass.source-profile-materials/1\",\"profiles\":[{{\"normalizer_id\":\"{duplicate}\",{body}]}}"
        );
        let bad = root.join("duplicate-item.json");
        fs::write(&bad, raw).expect("write duplicate item key");
        let result = exported_with_profile("duplicate-item-key", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 9. Wrong item type.
    {
        let root = case_root("e17_03-wrong-item-type");
        let fixture = copy_family("links", &root);
        let mut value = fixture.profiles();
        value["profiles"][0]["desensitization_enabled"] = json!("true");
        let bad = root.join("wrong-item-type.json");
        write_json(&bad, &value);
        let result = exported_with_profile("wrong-item-type", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 10. Duplicate pair (used).
    {
        let root = case_root("e17_03-duplicate-pair");
        let fixture = copy_family("links", &root);
        let mut value = fixture.profiles();
        let duplicate = value["profiles"][0].clone();
        value["profiles"]
            .as_array_mut()
            .expect("profiles")
            .push(duplicate);
        let bad = root.join("duplicate-pair.json");
        write_json(&bad, &value);
        let result = exported_with_profile("duplicate-pair", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    let synthetic_item = |normalizer: &str, safety: &str| {
        json!({
            "normalizer_id": normalizer,
            "safety_contract_id": safety,
            "fad_pin": "c".repeat(40),
            "mapping_domain": "unsupported-mapping",
            "exclusion_epoch": "unsupported-exclusion",
            "redaction_fingerprint": "unsupported-redaction",
            "code_version": "unsupported-version",
            "config_source_identity": "/C17-original/unused.toml",
            "fixed_copy_path": "/C17-nonexistent/unused.toml",
            "fixed_config_sha256": "d".repeat(64),
            "effective_four_arrays_sha256": "e".repeat(64),
            "desensitization_enabled": true,
        })
    };

    // 11. Duplicate pair that the inputs never reference.
    {
        let root = case_root("e17_03-unused-duplicate-pair");
        let fixture = copy_family("links", &root);
        let mut value = fixture.profiles();
        let first = synthetic_item(&"a".repeat(64), &"b".repeat(64));
        let second = first.clone();
        value["profiles"]
            .as_array_mut()
            .expect("profiles")
            .extend([first, second]);
        let bad = root.join("unused-duplicate.json");
        write_json(&bad, &value);
        let result = exported_with_profile("unused-duplicate-pair", &fixture, &bad);
        assert_kind(&result, "source_export_profile_invalid");
        assert_incomplete(&root.join("out"));
    }

    // 12. Structurally valid, distinct, unreferenced foreign material.
    {
        let root = case_root("e17_03-unused-foreign");
        let mut fixture = copy_family("links", &root);
        let mut value = fixture.profiles();
        value["profiles"]
            .as_array_mut()
            .expect("profiles")
            .push(synthetic_item(&"a".repeat(64), &"b".repeat(64)));
        fixture.set_profiles(&value);
        let output = root.join("out");
        let private = private_env(&root);
        let result = run_with_db_check(
            &mut export_command(
                &fixture,
                &output,
                &private,
                &["--scope".to_string(), "all_source".to_string()],
                &[],
            ),
            &fixture.db,
        );
        assert!(
            result.status.success(),
            "unused foreign material must not block: {}",
            stderr_text(&result)
        );
        check_bundle(
            &output,
            &CheckerSpec {
                family: "links",
                scope: "all_source",
                max_records: 64,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: None,
                default_oversized: 0,
            },
        );

        // S1 opposite side: the same structurally valid, unreferenced item with
        // `desensitization_enabled = false` is refused at FILE structure time.
        let mut false_value = fixture.profiles();
        let mut false_item = synthetic_item(&"f".repeat(64), &"e".repeat(64));
        false_item["desensitization_enabled"] = json!(false);
        false_value["profiles"]
            .as_array_mut()
            .expect("profiles")
            .push(false_item);
        let false_profile = root.join("profile-false.json");
        write_json(&false_profile, &false_value);
        fixture.profile = false_profile;
        let false_output = root.join("false-out");
        let false_result = run(&mut export_command(
            &fixture,
            &false_output,
            &private,
            &["--scope".to_string(), "all_source".to_string()],
            &[],
        ));
        assert_kind(&false_result, "source_export_profile_invalid");
        assert_incomplete(&false_output);
    }
}

// ---------------------------------------------------------------------------
// e17_04 — profile semantics
// ---------------------------------------------------------------------------

fn semantics_case(
    label: &str,
    mutate: impl FnOnce(&mut Fixture, &mut Value),
    family: &str,
    expect_kind: Option<&str>,
) {
    let root = case_root(label);
    let mut fixture = copy_family(family, &root);
    let mut value = fixture.profiles();
    mutate(&mut fixture, &mut value);
    fixture.set_profiles(&value);
    let output = root.join("out");
    let private = private_env(&root);
    let arguments = vec!["--scope".to_string(), "all_source".to_string()];
    let result = run_with_db_check(
        &mut export_command(&fixture, &output, &private, &arguments, &[]),
        &fixture.db,
    );
    if let Some(kind) = expect_kind {
        assert_kind(&result, kind);
        assert_incomplete(&output);
    } else {
        assert!(
            result.status.success(),
            "{label} should complete: {}",
            stderr_text(&result)
        );
        check_bundle(
            &output,
            &CheckerSpec {
                family,
                scope: "all_source",
                max_records: 64,
                target_bytes: 8_388_608,
                input_keys: &[],
                connectors: &[],
                partitions: None,
                default_oversized: 0,
            },
        );
    }
}

fn set_all_profiles(value: &mut Value, field: &str, replacement: Value) {
    for item in value["profiles"].as_array_mut().expect("profiles") {
        item[field] = replacement.clone();
    }
}

#[test]
fn e17_04_profile_semantics() {
    semantics_case(
        "e17_04-pair-missing",
        |_, value| {
            // Remove one referenced pair without creating a duplicate pair.
            value["profiles"][0]["normalizer_id"] = json!("0".repeat(64));
            value["profiles"][0]["safety_contract_id"] = json!("1".repeat(64));
        },
        "links",
        Some("source_export_profile_missing"),
    );

    semantics_case(
        "e17_04-copy-missing",
        |_, value| {
            for item in value["profiles"].as_array_mut().expect("profiles") {
                item["fixed_copy_path"] = json!("/C17-nonexistent/fixed.toml");
            }
        },
        "links",
        Some("source_export_profile_missing"),
    );

    semantics_case(
        "e17_04-copy-symlink",
        |fixture, value| {
            let link = fixture.dir.join("fixed").join("link.toml");
            symlink(fixture.fixed("fixed-A.toml"), &link).expect("fixed symlink");
            for item in value["profiles"].as_array_mut().expect("profiles") {
                item["fixed_copy_path"] = json!(link.to_str().expect("utf8 link"));
            }
        },
        "links",
        Some("source_export_profile_invalid"),
    );

    semantics_case(
        "e17_04-copy-directory",
        |fixture, value| {
            for item in value["profiles"].as_array_mut().expect("profiles") {
                item["fixed_copy_path"] =
                    json!(fixture.dir.join("fixed").to_str().expect("utf8 fixed dir"));
            }
        },
        "links",
        Some("source_export_profile_invalid"),
    );

    semantics_case(
        "e17_04-copy-bad-toml",
        |fixture, value| {
            let bad = fixture.dir.join("fixed").join("bad.toml");
            fs::write(&bad, b"not = [").expect("write bad toml");
            for item in value["profiles"].as_array_mut().expect("profiles") {
                item["fixed_copy_path"] = json!(bad.to_str().expect("utf8 bad"));
            }
        },
        "links",
        Some("source_export_profile_invalid"),
    );

    for (label, field, replacement) in [
        ("e17_04-unsupported-fad-pin", "fad_pin", "0".repeat(40)),
        (
            "e17_04-unsupported-mapping-domain",
            "mapping_domain",
            "cass-source-mapping/9".to_string(),
        ),
        (
            "e17_04-unsupported-exclusion-epoch",
            "exclusion_epoch",
            "cass-source-exclusion/9".to_string(),
        ),
        (
            "e17_04-wrong-redaction-fingerprint",
            "redaction_fingerprint",
            "redact-v1:none".to_string(),
        ),
        (
            "e17_04-wrong-code-version",
            "code_version",
            "cass-source-exclusion/9+redact-v1:none".to_string(),
        ),
    ] {
        let field = field.to_string();
        semantics_case(
            label,
            move |_, value| set_all_profiles(value, &field, json!(replacement)),
            "links",
            Some("source_export_profile_invalid"),
        );
    }

    semantics_case(
        "e17_04-disabled-desensitization",
        |_, value| set_all_profiles(value, "desensitization_enabled", json!(false)),
        "links",
        Some("source_export_profile_invalid"),
    );

    semantics_case(
        "e17_04-changed-valid-toml-bytes",
        |fixture, _| {
            let path = fixture.fixed("fixed-A.toml");
            let original = fs::read_to_string(&path).expect("read fixed A");
            let changed = original.replace("memory_files = []", "memory_files = [\"C17_CHANGED\"]");
            assert_ne!(original, changed, "fixture must contain memory_files = []");
            fs::write(&path, changed).expect("rewrite fixed A");
        },
        "links",
        Some("source_export_profile_mismatch"),
    );

    semantics_case(
        "e17_04-wrong-valid-fixed-sha",
        |_, value| set_all_profiles(value, "fixed_config_sha256", json!("0".repeat(64))),
        "links",
        Some("source_export_profile_mismatch"),
    );

    semantics_case(
        "e17_04-wrong-valid-four-arrays-sha",
        |_, value| {
            set_all_profiles(value, "effective_four_arrays_sha256", json!("0".repeat(64)));
        },
        "links",
        Some("source_export_profile_mismatch"),
    );

    semantics_case(
        "e17_04-wrong-logical-identity",
        |_, value| {
            for item in value["profiles"].as_array_mut().expect("profiles") {
                item["config_source_identity"] = json!("/C17-original/other-private.toml");
            }
        },
        "links",
        Some("source_export_profile_mismatch"),
    );

    semantics_case("e17_04-physical-copy-relocated", |_, _| {}, "links", None);
}

// ---------------------------------------------------------------------------
// e17_05 — per-input effective configuration
// ---------------------------------------------------------------------------

fn control_input_key(family: &str) -> String {
    let gold = family_gold(family);
    gold["expected_all_source"]["inputs"]
        .as_array()
        .expect("inputs")
        .iter()
        .find(|header| {
            header["relative_locator"]
                .as_str()
                .is_some_and(|locator| locator.contains("_CTL_"))
        })
        .and_then(|header| header["input_key"].as_str())
        .unwrap_or_else(|| panic!("{family} has no control input"))
        .to_string()
}

#[test]
fn e17_05_per_input_config() {
    let families = [
        "bad-context-01",
        "bad-context-02",
        "bad-context-03",
        "bad-context-05",
        "bad-context-06",
        "bad-context-07",
    ];
    assert_eq!(families.len(), 6, "e17_05 has six cells");
    for family in families {
        let root = case_root(&format!("e17_05-{family}"));
        let fixture = copy_family(family, &root);
        let control = control_input_key(family);
        let private = private_env(&root);

        // Normal control: the control input alone completes and checks.
        let control_out = root.join("control-out");
        let result = run_with_db_check(
            &mut export_command(
                &fixture,
                &control_out,
                &private,
                &[
                    "--scope".to_string(),
                    "all_source".to_string(),
                    "--input-keys".to_string(),
                    control.clone(),
                ],
                &[],
            ),
            &fixture.db,
        );
        assert!(
            result.status.success(),
            "{family} control failed: {}",
            stderr_text(&result)
        );
        check_bundle(
            &control_out,
            &CheckerSpec {
                family,
                scope: "all_source",
                max_records: 64,
                target_bytes: 8_388_608,
                input_keys: std::slice::from_ref(&control),
                connectors: &[],
                partitions: None,
                default_oversized: 0,
            },
        );

        // Full pair: the second input must reach the per-input material check.
        let full_out = root.join("full-out");
        let result = run_with_db_check(
            &mut export_command(
                &fixture,
                &full_out,
                &private,
                &["--scope".to_string(), "all_source".to_string()],
                &[],
            ),
            &fixture.db,
        );
        assert_kind(&result, "source_export_profile_mismatch");
        assert_incomplete(&full_out);
    }
}

// ---------------------------------------------------------------------------
// e17_06 — output admission
// ---------------------------------------------------------------------------

fn export_to(fixture: &Fixture, output: &Path, root: &Path) -> Output {
    let private = private_env(root);
    run_with_db_check(
        &mut export_command(
            fixture,
            output,
            &private,
            &["--scope".to_string(), "all_source".to_string()],
            &[],
        ),
        &fixture.db,
    )
}

fn default_checker(family: &str) -> CheckerSpec<'_> {
    CheckerSpec {
        family,
        scope: "all_source",
        max_records: 64,
        target_bytes: 8_388_608,
        input_keys: &[],
        connectors: &[],
        partitions: None,
        default_oversized: if family == "large" { 1 } else { 0 },
    }
}

#[test]
fn e17_06_output_admission() {
    // 1. New directory, unknown connector with standard=null.
    {
        let root = case_root("e17_06-new-directory");
        let fixture = copy_family("unsupported", &root);
        let output = root.join("out");
        let result = export_to(&fixture, &output, &root);
        assert!(result.status.success(), "{}", stderr_text(&result));
        check_bundle(&output, &default_checker("unsupported"));
        assert_eq!(summary(&output), (1, 1, 1, 0));
        let mode = fs::metadata(&output)
            .expect("output metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }

    // 2. Existing empty directory: tightened to 0700, parents unchanged.
    {
        let root = case_root("e17_06-existing-empty");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        fs::create_dir(&output).expect("pre-create output");
        fs::set_permissions(&output, fs::Permissions::from_mode(0o755)).expect("pre mode");
        let parent_mode = fs::metadata(&root)
            .expect("root metadata")
            .permissions()
            .mode()
            & 0o777;
        let result = export_to(&fixture, &output, &root);
        assert!(result.status.success(), "{}", stderr_text(&result));
        check_bundle(&output, &default_checker("links"));
        let mode = fs::metadata(&output).expect("mode").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        let after = fs::metadata(&root).expect("root mode").permissions().mode() & 0o777;
        assert_eq!(after, parent_mode, "parent permissions must not change");
    }

    // 3. Non-empty directory: foreign bytes unchanged.
    {
        let root = case_root("e17_06-nonempty");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        fs::create_dir(&output).expect("pre-create output");
        let foreign = output.join("foreign.bin");
        fs::write(&foreign, b"C17_FOREIGN_BYTES").expect("foreign file");
        let result = export_to(&fixture, &output, &root);
        assert_kind(&result, "source_export_output_invalid");
        assert_eq!(
            fs::read(&foreign).expect("foreign bytes"),
            b"C17_FOREIGN_BYTES"
        );
    }

    // 4. Target is a symlink.
    {
        let root = case_root("e17_06-target-symlink");
        let fixture = copy_family("links", &root);
        let real = root.join("real");
        fs::create_dir(&real).expect("real dir");
        let output = root.join("out");
        symlink(&real, &output).expect("target symlink");
        let result = export_to(&fixture, &output, &root);
        assert_kind(&result, "source_export_output_invalid");
    }

    // 5. A parent component is a symlink.
    {
        let root = case_root("e17_06-parent-symlink");
        let fixture = copy_family("links", &root);
        let real = root.join("real-parent");
        fs::create_dir(&real).expect("real parent");
        let link = root.join("link-parent");
        symlink(&real, &link).expect("parent symlink");
        let output = link.join("out");
        let result = export_to(&fixture, &output, &root);
        assert_kind(&result, "source_export_output_invalid");
    }

    // 6. Target is a regular file.
    {
        let root = case_root("e17_06-target-file");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        fs::write(&output, b"C17_NOT_A_DIRECTORY").expect("target file");
        let result = export_to(&fixture, &output, &root);
        assert_kind(&result, "source_export_output_invalid");
        assert_eq!(
            fs::read(&output).expect("target file bytes"),
            b"C17_NOT_A_DIRECTORY"
        );
    }

    // 7. The output path aliases the input database.
    {
        let root = case_root("e17_06-db-alias");
        let fixture = copy_family("links", &root);
        let before = snapshot_db(&fixture.db);
        let result = export_to(&fixture, &fixture.db, &root);
        assert_kind(&result, "source_export_output_invalid");
        assert_eq!(snapshot_db(&fixture.db), before, "database must not change");
    }

    // 8. A pre-existing pages child makes the target non-empty.
    {
        let root = case_root("e17_06-preexisting-pages");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        fs::create_dir(&output).expect("pre-create output");
        fs::create_dir(output.join("pages")).expect("pre-create pages");
        let result = export_to(&fixture, &output, &root);
        assert_kind(&result, "source_export_output_invalid");
    }

    // 9. An owned but unwritable directory is refused at admission.
    {
        let root = case_root("e17_06-unwritable");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        fs::create_dir(&output).expect("pre-create output");
        fs::set_permissions(&output, fs::Permissions::from_mode(0o500)).expect("lock output");
        let result = export_to(&fixture, &output, &root);
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).expect("unlock output");
        assert_kind(&result, "source_export_output_invalid");
    }

    // 10. A real page write fails under a child-only 4 KiB RLIMIT_FSIZE.
    {
        let root = case_root("e17_06-page-write-limit");
        let fixture = copy_family("large", &root);
        {
            let mut guard =
                open_test_writer(&fixture.db, Profile::Production).expect("open fixture writer");
            guard
                .storage()
                .raw()
                .execute_batch("PRAGMA journal_mode = DELETE;")
                .expect("delete journal mode");
            guard.mark_committed();
        }
        let before = snapshot_db(&fixture.db);
        let launcher = root.join("limit-launcher.py");
        fs::write(
            &launcher,
            b"import os, resource, signal, sys\n\
resource.setrlimit(resource.RLIMIT_FSIZE, (4096, 4096))\n\
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)\n\
os.execv(sys.argv[1], sys.argv[1:])\n",
        )
        .expect("write launcher");
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o600)).expect("launcher mode");
        let output = root.join("out");
        let private = private_env(&root);
        let mut command = Command::new(python_path());
        apply_private_env(&mut command, &private);
        command
            .arg(&launcher)
            .arg(cli_binary())
            .arg("--db")
            .arg(&fixture.db)
            .args([
                "sources",
                "facts",
                "export",
                "--output",
                output.to_str().expect("utf8 output"),
                "--profile-materials",
                fixture.profile.to_str().expect("utf8 profile"),
                "--scope",
                "all_source",
                "--json",
            ]);
        let result = run(&mut command);
        assert_kind(&result, "source_export_io_failed");
        assert_incomplete(&output);
        assert_eq!(snapshot_db(&fixture.db), before, "database must not change");
    }
}

// ---------------------------------------------------------------------------
// e17_07 — real interruptions
// ---------------------------------------------------------------------------

fn wait_for_sentinel(path: &Path, child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(metadata) = fs::symlink_metadata(path) {
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "sentinel must be 0600");
            return;
        }
        if let Some(status) = child.try_wait().expect("child status") {
            panic!("child exited before the pause sentinel: {status:?}");
        }
        assert!(
            Instant::now() < deadline,
            "pause sentinel never appeared at {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn e17_07_real_interruptions() {
    let cases = [
        ("page_partial", false),
        ("index_before_publish", false),
        ("index_after_publish", true),
    ];
    assert_eq!(cases.len(), 3, "e17_07 has three cells");
    for (point, index_expected) in cases {
        let root = case_root(&format!("e17_07-{point}"));
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        let sentinel = root.join("pause.sentinel");
        let private = private_env(&root);
        let before = snapshot_db(&fixture.db);
        let mut command = export_command(
            &fixture,
            &output,
            &private,
            &["--scope".to_string(), "all_source".to_string()],
            &[
                ("CASS_SOURCE_EXPORT_PAUSE_AT", point.to_string()),
                (
                    "CASS_SOURCE_EXPORT_PAUSE_SENTINEL",
                    sentinel.to_str().expect("utf8 sentinel").to_string(),
                ),
            ],
        );
        let mut recorded = spawn_recorded(&mut command);
        wait_for_sentinel(&sentinel, &mut recorded.child);
        recorded.child.kill().expect("kill own paused export child");
        let status = recorded.child.wait().expect("wait paused child");
        let _ = recorded.finish(status);
        assert_eq!(status.signal(), Some(9), "child must die by -9");
        assert!(marker_present(&output), "marker must survive the kill");
        assert_eq!(
            index_present(&output),
            index_expected,
            "index presence at {point}"
        );
        assert_eq!(
            snapshot_db(&fixture.db),
            before,
            "interrupted export must not write its input database"
        );

        // A fresh directory still completes normally.
        let control = root.join("control-out");
        let result = run_with_db_check(
            &mut export_command(
                &fixture,
                &control,
                &private,
                &["--scope".to_string(), "all_source".to_string()],
                &[],
            ),
            &fixture.db,
        );
        assert!(
            result.status.success(),
            "normal control after {point} failed: {}",
            stderr_text(&result)
        );
        check_bundle(&control, &default_checker("links"));
    }
}

// ---------------------------------------------------------------------------
// e17_08 — privacy and legacy trace control
// ---------------------------------------------------------------------------

fn assert_absent(text: &str, needles: &[&str], surface: &str) {
    for needle in needles {
        assert!(
            !text.contains(needle),
            "{surface} must not expose {needle:?}"
        );
    }
}

fn trace_lines(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .expect("read trace")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("trace json line"))
        .collect()
}

#[test]
fn e17_08_privacy_and_legacy() {
    // 1. Success runtime surfaces: no canary on stdout/stderr/trace, exact
    // summary keys, hidden trace args, private values kept in the package.
    {
        let root = case_root("e17_08-success-surfaces");
        let fixture = copy_family("links", &root);
        let output = root.join("out");
        let trace = root.join("trace.jsonl");
        let private = private_env(&root);
        let mut command = Command::new(cli_binary());
        apply_private_env(&mut command, &private);
        command
            .env("CASS_TRACE_ID", "C17_TRACE_MARKER")
            .arg("--db")
            .arg(&fixture.db)
            .arg("--trace-file")
            .arg(&trace)
            .args([
                "sources",
                "facts",
                "export",
                "--output",
                output.to_str().expect("utf8 output"),
                "--profile-materials",
                fixture.profile.to_str().expect("utf8 profile"),
                "--scope",
                "all_source",
                "--json",
            ]);
        let result = run_with_db_check(&mut command, &fixture.db);
        assert!(result.status.success(), "{}", stderr_text(&result));
        let stdout = stdout_text(&result);
        let stderr = stderr_text(&result);
        let trace_text = fs::read_to_string(&trace).expect("trace");
        let canaries = [
            "C17_TRACE_MARKER",
            "C17_REQ_MARKER",
            "/C17-private/",
            "C17_PRIVATE_DETAIL",
            "C17_PRIVATE_NATIVE",
            "/C17-original/config-private-A.toml",
            "/C17-original/config-private-B.toml",
            output.to_str().expect("utf8 output"),
            fixture.profile.to_str().expect("utf8 profile"),
        ];
        assert_absent(&stdout, &canaries, "stdout");
        assert_absent(&stderr, &canaries, "stderr");
        assert_absent(&trace_text, &canaries, "trace");

        let payload: Value = serde_json::from_str(&stdout).expect("summary json");
        let keys: BTreeSet<&str> = payload
            .as_object()
            .expect("summary object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            BTreeSet::from([
                "status",
                "page_count",
                "unique_input_count",
                "record_count",
                "oversized_records",
                "index_sha256"
            ])
        );
        assert_eq!(payload["status"], "complete");

        let lines = trace_lines(&trace);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["cmd"], "sources");
        assert_eq!(lines[0]["args"], json!([]));
        assert!(lines[0]["request_id"].is_null());
        assert!(lines[0]["trace_id"].is_null());

        // The private package keeps the original logical identity and the
        // complete private parser context; only the runtime surfaces hide them.
        let index = read_index(&output);
        let identity = index["profiles"][0]["config_source_identity"]
            .as_str()
            .expect("profile identity");
        assert!(identity.starts_with("/C17-original/config-private-"));
        let page: Value = serde_json::from_slice(
            &fs::read(output.join("pages").join("000000000000.json")).expect("read page"),
        )
        .expect("parse page");
        let serialised = serde_json::to_string(&page).expect("page json");
        assert!(serialised.contains("/C17-private/roots/links"));
        check_bundle(&output, &default_checker("links"));
    }

    // 2. Failure runtime surfaces: the fixed kind only, no canary anywhere,
    // marker retained and no success package.
    {
        let root = case_root("e17_08-failure-surfaces");
        let fixture = copy_family("links", &root);
        {
            let path = fixture.fixed("fixed-A.toml");
            let mut bytes = fs::read(&path).expect("read fixed A");
            bytes.extend_from_slice(b"# C17_PRIVATE_DETAIL changed\n");
            fs::write(&path, bytes).expect("mutate fixed A");
        }
        let output = root.join("out");
        let trace = root.join("trace.jsonl");
        let private = private_env(&root);
        let mut command = Command::new(cli_binary());
        apply_private_env(&mut command, &private);
        command
            .env("CASS_TRACE_ID", "C17_TRACE_MARKER")
            .arg("--db")
            .arg(&fixture.db)
            .arg("--trace-file")
            .arg(&trace)
            .args([
                "sources",
                "facts",
                "export",
                "--output",
                output.to_str().expect("utf8 output"),
                "--profile-materials",
                fixture.profile.to_str().expect("utf8 profile"),
                "--scope",
                "all_source",
                "--json",
            ]);
        let result = run_with_db_check(&mut command, &fixture.db);
        assert_kind(&result, "source_export_profile_mismatch");
        assert_incomplete(&output);
        let fixed_path = fixture.fixed("fixed-A.toml");
        let fixed_text = fixed_path.to_str().expect("utf8 fixed");
        let canaries = [
            "C17_TRACE_MARKER",
            "C17_PRIVATE_DETAIL",
            "/C17-private/",
            "/C17-original/config-private-A.toml",
            fixed_text,
        ];
        let stderr = stderr_text(&result);
        let stdout = stdout_text(&result);
        let trace_text = fs::read_to_string(&trace).expect("trace");
        let marker_text = fs::read_to_string(output.join("INCOMPLETE.json")).expect("marker");
        assert_absent(&stderr, &canaries, "stderr");
        assert_absent(&stdout, &canaries, "stdout");
        assert_absent(&trace_text, &canaries, "trace");
        assert_absent(&marker_text, &canaries, "INCOMPLETE.json");
    }

    // 3. Existing non-export command keeps its full trace semantics.
    {
        let root = case_root("e17_08-legacy-trace");
        let fixture = copy_family("links", &root);
        let trace = root.join("legacy-trace.jsonl");
        let before = sha256_file(&fixture.db);
        let private = private_env(&root);
        let mut command = Command::new(cli_binary());
        apply_private_env(&mut command, &private);
        command
            .env("CASS_TRACE_ID", "C17_TRACE_MARKER")
            .arg("--db")
            .arg(&fixture.db)
            .arg("--trace-file")
            .arg(&trace)
            .args([
                "search",
                "C17_LEGACY_QUERY_MARKER",
                "--mode",
                "lexical",
                "--rrf-limit",
                "0",
                "--request-id",
                "C17_REQ_MARKER",
                "--json",
            ]);
        let result = run(&mut command);
        assert_eq!(result.status.code(), Some(2), "usage refusal expected");
        let stderr = stderr_text(&result);
        assert!(stderr.contains("usage"), "stderr was: {stderr}");
        let expected_argv: Vec<String> = std::iter::once(cli_binary().to_string())
            .chain(
                [
                    "--db",
                    fixture.db.to_str().expect("utf8 db"),
                    "--trace-file",
                    trace.to_str().expect("utf8 trace"),
                    "search",
                    "C17_LEGACY_QUERY_MARKER",
                    "--mode",
                    "lexical",
                    "--rrf-limit",
                    "0",
                    "--request-id",
                    "C17_REQ_MARKER",
                    "--json",
                ]
                .into_iter()
                .map(str::to_string),
            )
            .collect();
        let lines = trace_lines(&trace);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["cmd"], "search");
        assert_eq!(
            lines[0]["args"],
            serde_json::to_value(&expected_argv).expect("argv json")
        );
        assert_eq!(lines[0]["request_id"], "C17_REQ_MARKER");
        assert_eq!(lines[0]["trace_id"], "C17_TRACE_MARKER");
        assert_eq!(lines[0]["error"]["kind"], "usage");
        assert_eq!(sha256_file(&fixture.db), before, "database must not change");
    }
}
