//! Task16 · source Replace restore integration tests.
//!
//! Every case drives the real `cass` binary against a real sealed raw mirror
//! and a real SQLite candidate database. The private inputs come from
//! `CASS_T16_INPUT_ROOT`; every run writes its evidence under a fresh
//! `CASS_T16_RESULT_ROOT`. No private absolute path is compiled into this file.
//!
//! The catalogue's 69 integration rows live in the eight functions below; the
//! four private component functions (18 rows) live beside the production
//! helpers in `src/phase3_restore.rs`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use coding_agent_search::raw_mirror::{
    RAW_MIRROR_LOCAL_IDENTITY_HOST, RawMirrorCaptureInput, RawMirrorCaptureRecord,
    RawMirrorSessionIdentity, capture_source_file_with_identity,
};
use coding_agent_search::storage::sqlite::FrankenStorage;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

const CONTEXT_SCHEMA: &str = "cass.restore-source-contexts/1";
const SNAPSHOT_ROOT: &str = "c16-snapshot";
const GENERATION: &str = "c16-generation";
const OTHER_HEX: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

// ---------------------------------------------------------------------------
// Roots and evidence
// ---------------------------------------------------------------------------

fn input_root() -> PathBuf {
    PathBuf::from(
        dotenvy::var("CASS_T16_INPUT_ROOT")
            .expect("CASS_T16_INPUT_ROOT must point at the frozen Task16 inputs"),
    )
}

fn result_root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = dotenvy::var("CASS_T16_RESULT_ROOT")
            .expect("CASS_T16_RESULT_ROOT must be a fresh directory per worker");
        let path = PathBuf::from(root);
        assert!(
            !path.exists(),
            "CASS_T16_RESULT_ROOT must not exist before the run: {}",
            path.display()
        );
        std::fs::create_dir_all(&path).expect("create the result root");
        path
    })
    .clone()
}

struct CaseDir {
    path: PathBuf,
}

impl CaseDir {
    fn new(test: &str, case: &str) -> Self {
        let path = result_root().join(test).join(case);
        assert!(
            !path.exists(),
            "case evidence directory already exists: {}",
            path.display()
        );
        std::fs::create_dir_all(&path).expect("create the case evidence directory");
        Self { path }
    }

    fn write(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.path.join(name), bytes).expect("write case evidence");
    }

    fn write_json(&self, name: &str, value: &serde_json::Value) {
        self.write(
            name,
            &serde_json::to_vec_pretty(value).expect("encode case evidence"),
        );
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn pass(&self) {
        self.write("PASS", b"ok\n");
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn proc_starttime(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let fields: Vec<&str> = stat[close + 2..].split_whitespace().collect();
    fields.get(19).map(|value| (*value).to_string())
}

#[derive(Debug)]
struct RunResult {
    rc: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    meta: serde_json::Value,
}

fn cli_binary() -> PathBuf {
    // M1 pins an immutable CLI copy through the test-only override; ordinary
    // builds use cargo's own binding.
    if let Some(path) = option_env!("CASS_T16_TEST_CLI") {
        PathBuf::from(path)
    } else {
        PathBuf::from(env!("CARGO_BIN_EXE_cass"))
    }
}

struct ChildEnv<'a> {
    home: &'a Path,
    xdg_config: &'a Path,
    xdg_data: &'a Path,
    xdg_cache: &'a Path,
    xdg_state: &'a Path,
    tmpdir: &'a Path,
    cwd: &'a Path,
}

fn spawn_cli(
    label: &str,
    args: &[String],
    envs: &[(&str, &str)],
    env: &ChildEnv<'_>,
) -> (Child, serde_json::Value) {
    use std::os::unix::process::CommandExt as _;

    let mut command = Command::new(cli_binary());
    command
        .args(args)
        .current_dir(env.cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", env.home)
        .env("XDG_CONFIG_HOME", env.xdg_config)
        .env("XDG_DATA_HOME", env.xdg_data)
        .env("XDG_CACHE_HOME", env.xdg_cache)
        .env("XDG_STATE_HOME", env.xdg_state)
        .env("TMPDIR", env.tmpdir)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    // Record the real keys the child will receive (never the values).
    let env_keys: Vec<String> = command
        .get_envs()
        .map(|(key, _)| key.to_string_lossy().into_owned())
        .collect();
    let start = now_rfc3339();
    let child = command.spawn().expect("spawn the cass CLI child");
    let exe = std::fs::read_link(format!("/proc/{}/exe", child.id()))
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let meta = serde_json::json!({
        "label": label,
        "argv": args,
        "cwd": env.cwd,
        "pid": child.id(),
        "pgid": child.id(),
        "proc_starttime": proc_starttime(child.id()),
        "utc_start": start,
        "exe": exe,
        "env_keys": env_keys,
    });
    (child, meta)
}

fn finish_child(mut child: Child, mut meta: serde_json::Value) -> RunResult {
    use std::os::unix::process::ExitStatusExt as _;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_end(&mut stdout);
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_end(&mut stderr);
    }
    let status = child.wait().expect("wait for the cass CLI child");
    meta["utc_end"] = serde_json::json!(now_rfc3339());
    meta["parent_wait_rc"] = serde_json::json!(status.code());
    meta["signal"] = serde_json::json!(status.signal());
    RunResult {
        rc: status.code(),
        stdout,
        stderr,
        meta,
    }
}

fn run_cli(
    case: &CaseDir,
    label: &str,
    args: &[String],
    envs: &[(&str, &str)],
    env: &ChildEnv<'_>,
) -> RunResult {
    let (child, meta) = spawn_cli(label, args, envs, env);
    let result = finish_child(child, meta);
    case.write(&format!("{label}.stdout"), &result.stdout);
    case.write(&format!("{label}.stderr"), &result.stderr);
    case.write_json(&format!("{label}.meta.json"), &result.meta);
    result
}

/// Run at a named pause point, wait for the child's own sentinel, then SIGKILL
/// only that recorded child and wait for it.
fn run_paused_at(
    case: &CaseDir,
    label: &str,
    args: &[String],
    envs: &[(&str, &str)],
    env: &ChildEnv<'_>,
    sentinel: &Path,
    pause: &str,
) -> RunResult {
    let mut all_envs = envs.to_vec();
    let sentinel_text = sentinel.to_string_lossy().into_owned();
    all_envs.push(("CASS_RESTORE_PAUSE_AT", pause));
    all_envs.push(("CASS_RESTORE_PAUSE_SENTINEL", sentinel_text.as_str()));
    let (mut child, meta) = spawn_cli(label, args, &all_envs, env);
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut handshaken = false;
    while Instant::now() < deadline {
        if sentinel.exists() {
            handshaken = true;
            break;
        }
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(handshaken, "{label}: the child never reached {pause}");
    child.kill().expect("SIGKILL the recorded child");
    let result = finish_child(child, meta);
    case.write(&format!("{label}.stdout"), &result.stdout);
    case.write(&format!("{label}.stderr"), &result.stderr);
    case.write_json(&format!("{label}.meta.json"), &result.meta);
    result
}

fn error_json(result: &RunResult) -> serde_json::Value {
    let text = String::from_utf8_lossy(&result.stderr);
    for line in text.lines().rev() {
        let trimmed = line.trim();
        if trimmed.starts_with('{') {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
                return value;
            }
        }
    }
    panic!("the CLI printed no JSON error envelope on stderr: {text}");
}

fn assert_kind(result: &RunResult, expected: &str) {
    let payload = error_json(result);
    assert_eq!(
        payload
            .pointer("/error/kind")
            .and_then(|value| value.as_str())
            .unwrap_or_else(|| panic!("no error.kind in {payload}")),
        expected,
        "unexpected CLI error kind: {payload}"
    );
}

// ---------------------------------------------------------------------------
// World cloning
// ---------------------------------------------------------------------------

struct World {
    tmp: TempDir,
    home: PathBuf,
    xdg_config: PathBuf,
    xdg_data: PathBuf,
    xdg_cache: PathBuf,
    xdg_state: PathBuf,
    tmpdir: PathBuf,
    cwd: PathBuf,
    scratch: PathBuf,
    data: PathBuf,
    db: PathBuf,
    contexts: PathBuf,
    fixed: PathBuf,
}

fn copy_tree(source: &Path, target: &Path) {
    std::fs::create_dir_all(target).expect("create the target directory");
    for entry in std::fs::read_dir(source).expect("read the source directory") {
        let entry = entry.expect("read the source entry");
        let from = entry.path();
        let to = target.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&from, &to);
        } else {
            std::fs::copy(&from, &to).expect("copy the source file");
        }
    }
}

impl World {
    fn from_source(id: &str, extra: bool) -> Self {
        let tmp = TempDir::new().expect("create the world tempdir");
        let home = tmp.path().join("home");
        let xdg_config = tmp.path().join("xdg-config");
        let xdg_data = tmp.path().join("xdg-data");
        let xdg_cache = tmp.path().join("xdg-cache");
        let xdg_state = tmp.path().join("xdg-state");
        let tmpdir = tmp.path().join("tmpdir");
        let cwd = tmp.path().join("cwd");
        let scratch = tmp.path().join("scratch");
        let data = tmp.path().join("data");
        for path in [
            &home,
            &xdg_config,
            &xdg_data,
            &xdg_cache,
            &xdg_state,
            &tmpdir,
            &cwd,
            &scratch,
            &data,
        ] {
            std::fs::create_dir_all(path).expect("create a world directory");
        }
        std::fs::write(cwd.join(".env"), b"").expect("write the empty cwd .env");
        let root = input_root();
        let source = if extra {
            root.join("extra").join(id)
        } else {
            root.join("worlds").join(id)
        };
        copy_tree(&source.join("data"), &data);
        let contexts = if source.join("contexts.local.json").exists() {
            source.join("contexts.local.json")
        } else if source.join("contexts.json").exists() {
            source.join("contexts.json")
        } else {
            root.join("worlds/01-claude_code-jsonl/contexts.json")
        };
        let fixed = if source.join("fixed.toml").exists() {
            source.join("fixed.toml")
        } else {
            root.join("worlds/01-claude_code-jsonl/fixed.toml")
        };
        let db = data.join("agent_search.db");
        Self {
            tmp,
            home,
            xdg_config,
            xdg_data,
            xdg_cache,
            xdg_state,
            tmpdir,
            cwd,
            scratch,
            data,
            db,
            contexts,
            fixed,
        }
    }

    fn native(id: &str) -> Self {
        let directory = match id {
            "claude_code-jsonl" => "01-claude_code-jsonl",
            "claude_code-json_document" => "02-claude_code-json_document",
            "codex-jsonl" => "03-codex-jsonl",
            "codex-json_document" => "04-codex-json_document",
            "codex-jsonl-multi" => "05-codex-jsonl-multi",
            other => panic!("unknown native world {other}"),
        };
        Self::from_source(directory, false)
    }

    fn extra(id: &str) -> Self {
        Self::from_source(id, true)
    }

    /// Clone the Root-verified Openclaw legacy carrier into a fresh case data
    /// directory. The descriptor is data, never an instruction.
    fn legacy_openclaw() -> (Self, serde_json::Value) {
        let descriptor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(input_root().join("legacy-openclaw.json"))
                .expect("read the legacy carrier descriptor"),
        )
        .expect("decode the legacy carrier descriptor");
        let tmp = TempDir::new().expect("create the legacy tempdir");
        let home = tmp.path().join("home");
        let xdg_config = tmp.path().join("xdg-config");
        let xdg_data = tmp.path().join("xdg-data");
        let xdg_cache = tmp.path().join("xdg-cache");
        let xdg_state = tmp.path().join("xdg-state");
        let tmpdir = tmp.path().join("tmpdir");
        let cwd = tmp.path().join("cwd");
        let scratch = tmp.path().join("scratch");
        let data = tmp.path().join("data");
        for path in [
            &home,
            &xdg_config,
            &xdg_data,
            &xdg_cache,
            &xdg_state,
            &tmpdir,
            &cwd,
            &scratch,
            &data,
        ] {
            std::fs::create_dir_all(path).expect("create a legacy world directory");
        }
        std::fs::write(cwd.join(".env"), b"").expect("write the empty cwd .env");
        copy_tree(
            Path::new(descriptor["data_root"].as_str().expect("data_root")),
            &data,
        );
        let db = data.join("agent_search.db");
        (
            Self {
                tmp,
                home,
                xdg_config,
                xdg_data,
                xdg_cache,
                xdg_state,
                tmpdir,
                cwd,
                scratch,
                data,
                db,
                contexts: PathBuf::new(),
                fixed: PathBuf::new(),
            },
            descriptor,
        )
    }

    /// A synthetic-but-real chain: versions are written to a live source and
    /// captured through the production capture entry. The candidate DB is then
    /// built by a real ordinary index of the first version only, so the later
    /// captured versions are exactly what a real restore must replace.
    fn chain(versions: &[Vec<u8>]) -> (Self, Vec<RawMirrorCaptureRecord>) {
        assert!(!versions.is_empty());
        let tmp = TempDir::new().expect("create the chain tempdir");
        let home = tmp.path().join("home");
        let xdg_config = tmp.path().join("xdg-config");
        let xdg_data = tmp.path().join("xdg-data");
        let xdg_cache = tmp.path().join("xdg-cache");
        let xdg_state = tmp.path().join("xdg-state");
        let tmpdir = tmp.path().join("tmpdir");
        let cwd = tmp.path().join("cwd");
        let scratch = tmp.path().join("scratch");
        let data = tmp.path().join("data");
        for path in [
            &home,
            &xdg_config,
            &xdg_data,
            &xdg_cache,
            &xdg_state,
            &tmpdir,
            &cwd,
            &scratch,
            &data,
        ] {
            std::fs::create_dir_all(path).expect("create a chain directory");
        }
        std::fs::write(cwd.join(".env"), b"").expect("write the empty cwd .env");
        let live = home.join(".claude/projects/R16-chain/chain.jsonl");
        let mut captures = Vec::new();
        for (index, bytes) in versions.iter().enumerate() {
            write_source(&live, bytes, 1_700_100_000 + index as u64);
            captures.push(capture(&data, &live));
        }
        // Build the DB from the first version only.
        write_source(&live, &versions[0], 1_700_200_000);
        let db = data.join("agent_search.db");
        let fixed = tmp.path().join("fixed.toml");
        let contexts = tmp.path().join("contexts.json");
        let world = Self {
            tmp,
            home,
            xdg_config,
            xdg_data,
            xdg_cache,
            xdg_state,
            tmpdir,
            cwd,
            scratch,
            data: data.clone(),
            db: db.clone(),
            contexts: PathBuf::new(),
            fixed: PathBuf::new(),
        };
        let index = run_cli(
            &CaseDir::new("chain-index", &format!("chain-{}", captures[0].manifest_id)),
            "index",
            &[
                "index".to_string(),
                "--full".to_string(),
                "--data-dir".to_string(),
                data.to_string_lossy().into_owned(),
                "--db".to_string(),
                db.to_string_lossy().into_owned(),
                "--json".to_string(),
            ],
            &[],
            &world.env(),
        );
        assert_eq!(
            index.rc,
            Some(0),
            "the ordinary index of the first chain version must succeed: {}",
            String::from_utf8_lossy(&index.stderr)
        );
        std::fs::write(
            &fixed,
            "memory_files = []\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n",
        )
        .expect("write the chain fixed config");
        // The real shape: the live source holds the newest version while the DB
        // still holds the first one. The declaration's physical recheck reads it.
        write_source(&live, &versions[versions.len() - 1], 1_700_400_000);
        write_contexts(&contexts, &captures, &live, "R16_T16_CHAIN");
        (
            Self {
                contexts,
                fixed,
                ..world
            },
            captures,
        )
    }

    fn env(&self) -> ChildEnv<'_> {
        ChildEnv {
            home: &self.home,
            xdg_config: &self.xdg_config,
            xdg_data: &self.xdg_data,
            xdg_cache: &self.xdg_cache,
            xdg_state: &self.xdg_state,
            tmpdir: &self.tmpdir,
            cwd: &self.cwd,
        }
    }

    fn journal(&self) -> PathBuf {
        self.tmp.path().join("journal.json")
    }

    fn marker(&self) -> PathBuf {
        self.db.parent().expect("db parent").join("w1-commit-marker.json")
    }
}

fn literal(name: &str) -> Vec<u8> {
    std::fs::read(input_root().join("literals").join(name))
        .unwrap_or_else(|error| panic!("read literal {name}: {error}"))
}

fn codex_v0() -> Vec<u8> {
    literal("claude_code-jsonl-v0.source")
}

fn codex_v1() -> Vec<u8> {
    literal("claude_code-jsonl-v1.source")
}

/// A real longer prefix of the same session: the v1 bytes plus its last record
/// repeated. The byte layer and the message layer both stay a true prefix.
fn codex_v2() -> Vec<u8> {
    let mut bytes = codex_v1();
    let last = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .next_back()
        .expect("v1 carries at least one record")
        .to_vec();
    bytes.extend_from_slice(&last);
    bytes.push(b'\n');
    bytes.extend_from_slice(&last);
    bytes.push(b'\n');
    bytes
}

fn write_source(path: &Path, bytes: &[u8], stamp: u64) {
    std::fs::create_dir_all(path.parent().expect("source parent")).expect("create source parent");
    std::fs::write(path, bytes).expect("write the live source");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open the live source");
    file.set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(stamp))
        .expect("set a unique source mtime");
}

fn capture(data_dir: &Path, live: &Path) -> RawMirrorCaptureRecord {
    capture_source_file_with_identity(
        RawMirrorCaptureInput {
            data_dir,
            provider: "claude",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: live,
            db_links: &[],
        },
        RawMirrorSessionIdentity {
            identity_host: RAW_MIRROR_LOCAL_IDENTITY_HOST,
            external_id: None,
        },
    )
    .expect("capture the chain version into the raw mirror")
}

fn write_contexts(path: &Path, captures: &[RawMirrorCaptureRecord], live: &Path, namespace: &str) {
    let mut inputs: Vec<serde_json::Value> = captures
        .iter()
        .map(|record| {
            serde_json::json!({
                "manifest_id": record.manifest_id,
                "identity_namespace": namespace,
                "connector": "claude_code",
                "scan_root": live.parent().expect("live parent").to_string_lossy(),
                "relative_locator": live.file_name().expect("live name").to_string_lossy(),
                "role": "primary_session_log",
                "origin": {"source_id": "local", "kind": "local", "host": null, "source_version": null},
                "platform": null,
                "workspace_rewrites": [],
            })
        })
        .collect();
    inputs.sort_by(|left, right| {
        left["manifest_id"].as_str().unwrap().as_bytes()
            .cmp(right["manifest_id"].as_str().unwrap().as_bytes())
    });
    let value = serde_json::json!({"schema": CONTEXT_SCHEMA, "inputs": inputs});
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&value).expect("encode contexts"),
    )
    .expect("write the contexts file");
}

// ---------------------------------------------------------------------------
// CLI arguments
// ---------------------------------------------------------------------------

fn plan_args(world: &World, out: Option<&Path>) -> Vec<String> {
    let mut args = vec![
        "mirror-restore".to_string(),
        "--data-dir".to_string(),
        world.data.to_string_lossy().into_owned(),
        "--candidate-db".to_string(),
        world.db.to_string_lossy().into_owned(),
        "--scratch".to_string(),
        world.scratch.to_string_lossy().into_owned(),
        "--snapshot-root".to_string(),
        SNAPSHOT_ROOT.to_string(),
        "--json".to_string(),
        "--source-contexts".to_string(),
        world.contexts.to_string_lossy().into_owned(),
        "--source-safety-config".to_string(),
        world.fixed.to_string_lossy().into_owned(),
    ];
    if let Some(out) = out {
        args.push("--out".into());
        args.push(out.to_string_lossy().into_owned());
    }
    args
}

fn apply_args(world: &World, journal: &Path) -> Vec<String> {
    apply_args_with_snapshot(world, journal, SNAPSHOT_ROOT, GENERATION)
}

fn apply_args_with_snapshot(
    world: &World,
    journal: &Path,
    snapshot_root: &str,
    generation: &str,
) -> Vec<String> {
    let mut args = plan_args(world, None);
    // The snapshot root is this run's identity; two batches over the same file
    // must not share one restore receipt key.
    let root_at = args
        .iter()
        .position(|arg| arg == "--snapshot-root")
        .expect("plan args carry the snapshot root");
    args[root_at + 1] = snapshot_root.to_string();
    args.push("--apply".into());
    args.push("--journal".into());
    args.push(journal.to_string_lossy().into_owned());
    args.push("--generation".into());
    args.push(generation.to_string());
    args
}

fn plan_no_context_args(world: &World, journal: &Path) -> Vec<String> {
    vec![
        "mirror-restore".to_string(),
        "--data-dir".to_string(),
        world.data.to_string_lossy().into_owned(),
        "--candidate-db".to_string(),
        world.db.to_string_lossy().into_owned(),
        "--scratch".to_string(),
        world.scratch.to_string_lossy().into_owned(),
        "--snapshot-root".to_string(),
        SNAPSHOT_ROOT.to_string(),
        "--json".to_string(),
        "--apply".to_string(),
        "--journal".to_string(),
        journal.to_string_lossy().into_owned(),
        "--generation".to_string(),
        GENERATION.to_string(),
    ]
}

/// The legacy path takes no source contexts and no source safety config.
fn legacy_plan_args(world: &World, out: Option<&Path>) -> Vec<String> {
    let mut args = vec![
        "mirror-restore".to_string(),
        "--data-dir".to_string(),
        world.data.to_string_lossy().into_owned(),
        "--candidate-db".to_string(),
        world.db.to_string_lossy().into_owned(),
        "--scratch".to_string(),
        world.scratch.to_string_lossy().into_owned(),
        "--snapshot-root".to_string(),
        SNAPSHOT_ROOT.to_string(),
        "--json".to_string(),
    ];
    if let Some(out) = out {
        args.push("--out".into());
        args.push(out.to_string_lossy().into_owned());
    }
    args
}

fn legacy_apply_args(world: &World, journal: &Path) -> Vec<String> {
    let mut args = legacy_plan_args(world, None);
    args.push("--apply".into());
    args.push("--journal".into());
    args.push(journal.to_string_lossy().into_owned());
    args.push("--generation".into());
    args.push(GENERATION.into());
    args
}

fn recover_args(journal: &Path) -> Vec<String> {
    vec![
        "mirror-restore".to_string(),
        "--recover".to_string(),
        "--journal".to_string(),
        journal.to_string_lossy().into_owned(),
        "--json".to_string(),
    ]
}

fn qualify_args(world: &World, journal: &Path, deep: bool) -> Vec<String> {
    let mut args = vec![
        "mirror-restore".to_string(),
        "--qualify".to_string(),
        "--data-dir".to_string(),
        world.data.to_string_lossy().into_owned(),
        "--candidate-db".to_string(),
        world.db.to_string_lossy().into_owned(),
        "--journal".to_string(),
        journal.to_string_lossy().into_owned(),
        "--json".to_string(),
    ];
    if deep {
        args.push("--deep-verify".into());
    }
    args
}

// ---------------------------------------------------------------------------
// SQL and mirror helpers
// ---------------------------------------------------------------------------

fn open_ro(db: &Path) -> FrankenStorage {
    FrankenStorage::open_readonly(db).expect("open the candidate db readonly")
}

fn sql_rows(db: &Path, sql: &str) -> Vec<Vec<serde_json::Value>> {
    let mut storage = open_ro(db);
    let rows = storage
        .raw()
        .query_all_map(sql, &[], |row| {
            let mut values = Vec::new();
            let mut index = 0;
            while let Ok(value) = row.get_value(index) {
                values.push(typed_value(&value));
                index += 1;
            }
            Ok(values)
        })
        .expect("run the snapshot query");
    storage.close_best_effort_in_place();
    rows
}

fn typed_value(value: &coding_agent_search::storage::api::Value) -> serde_json::Value {
    use coding_agent_search::storage::api::Value;
    match value {
        Value::Null => serde_json::json!({"type": "null"}),
        Value::Integer(number) => serde_json::json!({"type": "integer", "value": number}),
        Value::Real(number) => {
            serde_json::json!({"type": "real", "bits": format!("{:016x}", number.to_bits())})
        }
        Value::Text(text) => serde_json::json!({"type": "text", "value": text}),
        Value::Blob(bytes) => {
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            serde_json::json!({"type": "blob", "hex": hex})
        }
    }
}

fn scalar_i64(db: &Path, sql: &str) -> i64 {
    let rows = sql_rows(db, sql);
    assert_eq!(rows.len(), 1, "a scalar query must return one row");
    rows[0][0]["value"].as_i64().expect("an integer scalar")
}

fn scalar_text(db: &Path, sql: &str) -> String {
    let rows = sql_rows(db, sql);
    assert_eq!(rows.len(), 1, "a scalar query must return one row");
    rows[0][0]["value"].as_str().expect("a text scalar").to_string()
}

fn count(db: &Path, sql: &str) -> i64 {
    scalar_i64(db, sql)
}

fn typed_snapshot(db: &Path) -> serde_json::Value {
    let tables = [
        ("messages", "id"),
        ("conversations", "id"),
        ("agents", "id"),
        ("workspaces", "id"),
        ("source_inputs", "id"),
        ("source_records", "id"),
        ("source_message_links", "id"),
        ("operation_commit_receipt", "idempotency_key"),
        ("meta", "key"),
    ];
    let mut snapshot = serde_json::Map::new();
    for (table, key) in tables {
        snapshot.insert(
            table.to_string(),
            serde_json::json!(sql_rows(
                db,
                &format!("SELECT * FROM {table} ORDER BY {key}")
            )),
        );
    }
    serde_json::Value::Object(snapshot)
}

fn revision(db: &Path) -> String {
    scalar_text(db, "SELECT value FROM meta WHERE key = 'source_facts_revision'")
}

fn generation(db: &Path) -> String {
    scalar_text(
        db,
        "SELECT value FROM meta WHERE key = 'source_content_generation'",
    )
}

fn sqlite_exec(db: &Path, sql: &str) {
    let mut storage = FrankenStorage::open(db).expect("open the candidate db for mutation");
    storage.raw().execute(sql, &[]).expect("apply the mutation");
    storage.close_best_effort_in_place();
}

fn sqlite_exec_params(db: &Path, sql: &str, params: &[coding_agent_search::storage::api::Value]) {
    let mut storage = FrankenStorage::open(db).expect("open the candidate db for mutation");
    storage
        .raw()
        .execute(sql, params)
        .expect("apply the mutation");
    storage.close_best_effort_in_place();
}

fn blake3_file(path: &Path) -> String {
    blake3::hash(&std::fs::read(path).expect("read the file for blake3")).to_hex().to_string()
}

fn db_sha(path: &Path) -> Option<String> {
    std::fs::read(path)
        .ok()
        .map(|bytes| Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect())
}

fn mirror_digest(data: &Path) -> String {
    fn walk(root: &Path, base: &Path, out: &mut Vec<(String, String)>) {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
            .expect("read the mirror directory")
            .map(|entry| entry.expect("read entry").path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let relative = path
                    .strip_prefix(base)
                    .expect("relative mirror path")
                    .to_string_lossy()
                    .into_owned();
                let bytes = std::fs::read(&path).expect("read a mirror file");
                let digest: String = Sha256::digest(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                out.push((relative, digest));
            }
        }
    }
    let mut out = Vec::new();
    walk(&data.join("raw-mirror"), &data.join("raw-mirror"), &mut out);
    serde_json::to_string(&out).expect("encode the mirror digest")
}

fn mirror_file_map(data: &Path) -> std::collections::BTreeMap<String, String> {
    let pairs: Vec<(String, String)> =
        serde_json::from_str(&mirror_digest(data)).expect("decode the mirror digest list");
    pairs.into_iter().collect()
}

fn mirror_manifest_path(data: &Path, manifest_id: &str) -> PathBuf {
    let manifests = data.join("raw-mirror").join("v1").join("manifests");
    std::fs::read_dir(&manifests)
        .expect("read the manifest directory")
        .map(|entry| entry.expect("manifest entry").path())
        .find(|path| path.to_string_lossy().contains(manifest_id))
        .expect("the planned manifest file")
}

fn journal_json(journal: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(journal).expect("read the journal"))
        .expect("decode the journal")
}

fn write_journal(journal: &Path, value: &serde_json::Value) {
    std::fs::write(journal, serde_json::to_vec(value).expect("encode the journal"))
        .expect("write the journal");
}

fn rewind_journal(journal: &Path, state: &str, committed: &[String], published: &[String]) {
    let mut value = journal_json(journal);
    value["state"] = serde_json::json!(state);
    value["committed"] = serde_json::json!(committed);
    value["published"] = serde_json::json!(published);
    write_journal(journal, &value);
}

/// Remove the marker before a fixture-rewound recovery. The journal bytes were
/// rewritten by this test, so the old marker's `journal_digest` describes a file
/// that no longer exists; the product recreates the marker from the journal it
/// itself writes. The C3 verifier still runs unchanged.
fn remove_marker(world: &World) {
    let _ = std::fs::remove_file(world.marker());
}

fn refresh_marker_db_identity(world: &World) {
    let path = world.marker();
    let mut marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read the marker"))
            .expect("decode the marker");
    marker["db_identity"]["sqlite_digest"] = serde_json::json!(blake3_file(&world.db));
    marker["db_identity"]["sqlite_size_bytes"] =
        serde_json::json!(std::fs::metadata(&world.db).expect("stat the db").len());
    std::fs::write(&path, serde_json::to_vec(&marker).expect("encode the marker"))
        .expect("write the marker");
}

fn refresh_marker_identity(world: &World, journal: &Path) {
    refresh_marker_db_identity(world);
    let path = world.marker();
    let mut marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read the marker"))
            .expect("decode the marker");
    marker["journal_digest"] = serde_json::json!(blake3_file(journal));
    std::fs::write(&path, serde_json::to_vec(&marker).expect("encode the marker"))
        .expect("write the marker");
}

fn restore_receipt_detail(db: &Path) -> serde_json::Value {
    let text = scalar_text(
        db,
        "SELECT detail FROM operation_commit_receipt \
         WHERE operation = 'mirror-restore-replace' AND detail IS NOT NULL",
    );
    serde_json::from_str(&text).expect("the restore receipt detail is JSON")
}

fn mutate_restore_detail(db: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let mut detail = restore_receipt_detail(db);
    mutate(&mut detail);
    sqlite_exec_params(
        db,
        "UPDATE operation_commit_receipt SET detail = ?1 \
         WHERE operation = 'mirror-restore-replace'",
        &[coding_agent_search::storage::api::Value::Text(
            serde_json::to_string(&detail).expect("encode the detail"),
        )],
    );
}

fn delete_restore_receipt(db: &Path) {
    sqlite_exec(
        db,
        "DELETE FROM operation_commit_receipt WHERE operation = 'mirror-restore-replace'",
    );
}

fn apply_result(result: &RunResult) -> serde_json::Value {
    assert_eq!(
        result.rc,
        Some(0),
        "apply must succeed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).expect("apply JSON")
}

fn plan_report(case: &CaseDir, world: &World) -> serde_json::Value {
    let out = case.join("plan.json");
    let result = run_cli(case, "plan", &plan_args(world, Some(&out)), &[], &world.env());
    assert_eq!(
        result.rc,
        Some(0),
        "plan must succeed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&std::fs::read(&out).expect("read the plan report"))
        .expect("decode the plan report")
}

fn completed_replace(test: &str, id: &str, world: World) -> (CaseDir, World, PathBuf) {
    let case = CaseDir::new(test, id);
    let journal = world.journal();
    let report = apply_result(&run_cli(
        &case,
        "apply",
        &apply_args(&world, &journal),
        &[],
        &world.env(),
    ));
    assert_eq!(report["replaced"].as_u64(), Some(1), "{id}: one replacement");
    (case, world, journal)
}

// ---------------------------------------------------------------------------
// r16_01 · native replacement through the real CLI
// ---------------------------------------------------------------------------

#[test]
fn r16_01_native_replace() {
    let cases = [
        ("claude_code-jsonl", 2u64, 4u64),
        ("claude_code-json_document", 2, 4),
        ("codex-jsonl", 2, 4),
        ("codex-json_document", 2, 4),
        ("codex-jsonl-multi", 4, 6),
    ];
    for (id, old_messages, new_messages) in cases {
        let case = CaseDir::new("r16_01_native_replace", id);
        let world = World::native(id);
        let old_inputs = sql_rows(
            &world.db,
            "SELECT * FROM source_inputs ORDER BY id",
        );
        let old_input_ids: Vec<i64> = old_inputs
            .iter()
            .map(|row| row[0]["value"].as_i64().unwrap())
            .collect();
        let old_input_filter = old_input_ids
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let old_records = sql_rows(
            &world.db,
            &format!(
                "SELECT * FROM source_records WHERE input_id IN ({old_input_filter}) ORDER BY id"
            ),
        );
        let old_receipts = sql_rows(
            &world.db,
            "SELECT * FROM operation_commit_receipt WHERE operation = 'source_input_activation_v1' ORDER BY id",
        );
        let old_receipt_keys: Vec<String> = old_receipts
            .iter()
            .map(|row| row[1]["value"].as_str().unwrap().to_string())
            .collect();
        let old_receipt_filter = old_receipt_keys
            .iter()
            .map(|key| format!("'{key}'"))
            .collect::<Vec<_>>()
            .join(",");
        let old_links: Vec<(i64, Option<i64>)> = sql_rows(
            &world.db,
            "SELECT id, message_id FROM source_message_links WHERE authority = 'canonical' ORDER BY id",
        )
        .iter()
        .map(|row| {
            (
                row[0]["value"].as_i64().unwrap(),
                row[1].get("value").and_then(|value| value.as_i64()),
            )
        })
        .collect();
        let revision_before = revision(&world.db);
        let mirror_before = mirror_digest(&world.data);

        let report = plan_report(&case, &world);
        assert_eq!(report["replace"].as_u64(), Some(1), "{id}: real plan replace");
        assert_eq!(report["planned_actions"].as_u64(), Some(1));

        // The planned journal itself names the target conversation.
        let journal = world.journal();
        let paused = run_paused_at(
            &case,
            "apply-paused",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
            &case.join("pause.sentinel"),
            "planned",
        );
        assert!(paused.rc.is_none(), "{id}: the planned child was SIGKILLed");
        let journal_value = journal_json(&journal);
        assert_eq!(journal_value["state"], "planned");
        assert_eq!(journal_value["planned"][0]["action"]["kind"], "replace");
        assert_eq!(
            journal_value["planned"][0]["action"]["conversation_id"],
            serde_json::json!(1)
        );
        let planned_id = journal_value["planned"][0]["manifest_id"]
            .as_str()
            .expect("planned manifest id")
            .to_string();
        let planned_manifest_path = mirror_manifest_path(&world.data, &planned_id);
        let planned_manifest_before: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&planned_manifest_path).expect("read the planned manifest"),
        )
        .expect("decode the planned manifest");

        let applied = apply_result(&run_cli(
            &case,
            "recover",
            &recover_args(&journal),
            &[],
            &world.env(),
        ));
        assert_eq!(applied["replaced"].as_u64(), Some(1), "{id}: replaced");
        assert_eq!(applied["restored"].as_u64().unwrap_or(0), 0);
        assert_eq!(applied["deduplicated"].as_u64().unwrap_or(0), 0);
        assert_eq!(applied["source_replayed"].as_u64().unwrap_or(0), 0);
        // The recover output keeps its original shape (no message counters);
        // the actual counts are proved by SQL below.

        // Every old canonical link is historical/NULL; every canonical link
        // points at a real current message.
        assert_eq!(
            count(
                &world.db,
                "SELECT COUNT(*) FROM source_message_links \
                 WHERE authority = 'historical' AND message_id IS NULL",
            ),
            old_links.len() as i64,
            "{id}: every old link was historyized"
        );
        for (link_id, message_id) in &old_links {
            assert!(
                message_id.is_some(),
                "{id}: link {link_id} was canonical before the run"
            );
        }
        assert_eq!(
            sql_rows(
                &world.db,
                "SELECT COUNT(*) FROM source_message_links l \
                 LEFT JOIN messages m ON m.id = l.message_id \
                 WHERE l.authority = 'canonical' AND m.id IS NULL",
            )[0][0]["value"],
            serde_json::json!(0),
            "{id}: no canonical link dangles"
        );
        assert_eq!(count(&world.db, "SELECT COUNT(*) FROM messages"), new_messages as i64);
        assert_eq!(
            count(
                &world.db,
                "SELECT COUNT(*) FROM messages WHERE conversation_id = 1",
            ),
            new_messages as i64
        );
        assert_eq!(revision(&world.db), (revision_before.parse::<u64>().unwrap() + 1).to_string());
        assert_eq!(generation(&world.db), GENERATION);

        // Old immutable evidence is byte-exact.
        assert_eq!(
            sql_rows(
                &world.db,
                &format!("SELECT * FROM source_inputs WHERE id IN ({old_input_filter}) ORDER BY id"),
            ),
            old_inputs,
            "{id}: the old source input rows are unchanged"
        );
        assert_eq!(
            sql_rows(
                &world.db,
                &format!(
                    "SELECT * FROM source_records WHERE input_id IN ({old_input_filter}) ORDER BY id"
                ),
            ),
            old_records,
            "{id}: the old records are unchanged"
        );
        assert_eq!(
            sql_rows(
                &world.db,
                &format!(
                    "SELECT * FROM operation_commit_receipt \
                     WHERE idempotency_key IN ({old_receipt_filter}) ORDER BY id"
                ),
            ),
            old_receipts,
            "{id}: the old activation receipts are unchanged"
        );

        let detail = restore_receipt_detail(&world.db);
        assert_eq!(detail["restore_operation"], "mirror-restore-replace");
        assert_eq!(detail["schema"], "cass.restore-source-receipt/1");
        assert_eq!(
            detail.as_object().expect("detail object").len(),
            8,
            "{id}: the C3 top level has eight keys"
        );

        // A second process: already committed, no message or generation change.
        let gen_after_apply = generation(&world.db);
        let after_db = db_sha(&world.db);
        let again = apply_result(&run_cli(
            &case,
            "recover-again",
            &recover_args(&journal),
            &[],
            &world.env(),
        ));
        assert_eq!(again["already_committed"].as_u64(), Some(1));
        assert_eq!(again["replaced"].as_u64().unwrap_or(0), 0);
        assert_eq!(again["messages_inserted"].as_u64().unwrap_or(0), 0);
        assert_eq!(again["messages_deleted"].as_u64().unwrap_or(0), 0);
        assert_eq!(db_sha(&world.db), after_db, "{id}: no DB write on replay");
        assert_eq!(generation(&world.db), gen_after_apply);

        // Qualification reads the stored evidence and writes nothing.
        refresh_marker_identity(&world, &journal);
        let before_qualify = db_sha(&world.db);
        for (label, deep) in [("qualify", false), ("qualify-deep", true)] {
            let result = run_cli(
                &case,
                label,
                &qualify_args(&world, &journal, deep),
                &[],
                &world.env(),
            );
            assert_eq!(
                result.rc,
                Some(0),
                "{id}: {label}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        assert_eq!(db_sha(&world.db), before_qualify, "{id}: qualify writes nothing");

        // F2: an independent fresh clone performs the real first apply (not a
        // recover) and proves the actual SQL delete/insert counts against the
        // fixture literals.
        let apply_world = World::native(id);
        let apply_report = apply_result(&run_cli(
            &case,
            &format!("{id}-fresh-apply"),
            &apply_args(&apply_world, &apply_world.journal()),
            &[],
            &apply_world.env(),
        ));
        assert_eq!(
            apply_report["messages_deleted"].as_u64(),
            Some(old_messages),
            "{id}: the fresh apply deletes the old prefix"
        );
        assert_eq!(
            apply_report["messages_inserted"].as_u64(),
            Some(new_messages),
            "{id}: the fresh apply inserts the full new version"
        );

        // Only the planned manifest's db_links and self digest may move; every
        // other mirror file stays byte-identical, and inside the planned
        // manifest every other field keeps its exact value.
        let before_pairs: Vec<(String, String)> =
            serde_json::from_str(&mirror_before).expect("decode the pre-run mirror list");
        let before_map: std::collections::BTreeMap<String, String> =
            before_pairs.into_iter().collect();
        let after_map = mirror_file_map(&world.data);
        assert_eq!(
            before_map.keys().collect::<Vec<_>>(),
            after_map.keys().collect::<Vec<_>>(),
            "{id}: the mirror file set is unchanged"
        );
        let changed: Vec<&String> = before_map
            .keys()
            .filter(|key| before_map.get(*key) != after_map.get(*key))
            .collect();
        assert_eq!(
            changed.len(),
            1,
            "{id}: exactly one mirror file changes: {changed:?}"
        );
        let planned_relative = planned_manifest_path
            .strip_prefix(world.data.join("raw-mirror"))
            .expect("planned manifest under raw-mirror")
            .to_string_lossy()
            .into_owned();
        assert_eq!(
            changed[0], &planned_relative,
            "{id}: only the planned manifest changes"
        );
        let planned_manifest_after: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&planned_manifest_path).expect("read the planned manifest"),
        )
        .expect("decode the planned manifest");
        let before_object = planned_manifest_before
            .as_object()
            .expect("planned manifest object");
        let after_object = planned_manifest_after
            .as_object()
            .expect("planned manifest object");
        assert_eq!(
            before_object.keys().collect::<Vec<_>>(),
            after_object.keys().collect::<Vec<_>>(),
            "{id}: the planned manifest key set is unchanged"
        );
        for key in before_object.keys() {
            if key == "db_links" || key == "manifest_blake3" {
                continue;
            }
            assert_eq!(
                before_object[key], after_object[key],
                "{id}: planned manifest field {key} is unchanged"
            );
        }
        assert_ne!(
            before_object["db_links"], after_object["db_links"],
            "{id}: the published link list moved"
        );

        // Persist the real before/after maps and the two planned manifest
        // objects so the reviewer can recompute the exact file/field delta
        // from disk rather than trusting the in-memory assertion.
        case.write_json(
            "mirror-before.json",
            &serde_json::to_value(&before_map).expect("encode the before map"),
        );
        case.write_json(
            "mirror-after.json",
            &serde_json::to_value(&after_map).expect("encode the after map"),
        );
        case.write_json("planned-manifest-before.json", &planned_manifest_before);
        case.write_json("planned-manifest-after.json", &planned_manifest_after);

        case.write_json(
            "expected.json",
            &serde_json::json!({
                "case": id,
                "replaced": 1,
                "messages_deleted": old_messages,
                "messages_inserted": new_messages,
                "restore_operation": "mirror-restore-replace",
                "revision_delta": 1,
            }),
        );
        case.pass();
        eprintln!("R16_CASE test=r16_01_native_replace case={id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r16_02 · history and replay
// ---------------------------------------------------------------------------

fn currency_links(db: &Path, currency: &str) {
    match currency {
        "Current" => {}
        "Historical" => sqlite_exec(
            db,
            "UPDATE source_message_links SET authority = 'historical', message_id = NULL \
             WHERE authority = 'canonical'",
        ),
        "Mixed" => sqlite_exec(
            db,
            "UPDATE source_message_links SET authority = 'historical', message_id = NULL \
             WHERE id = (SELECT MIN(id) FROM source_message_links WHERE authority = 'canonical')",
        ),
        other => panic!("unknown currency {other}"),
    }
}

#[test]
fn r16_02_history_replay() {
    let currencies = [
        ("Current", "Current"),
        ("Current-missing", "Current"),
        ("Historical", "Historical"),
        ("Historical-missing", "Historical"),
        ("Mixed", "Mixed"),
        ("Mixed-missing", "Mixed"),
    ];
    for (id, currency) in currencies {
        let test = "r16_02_history_replay";
        let case = CaseDir::new(test, id);
        let (world, captures) = World::chain(&[codex_v0(), codex_v1()]);
        let _ = captures;
        let journal = world.journal();
        let first = apply_result(&run_cli(
            &case,
            "apply",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
        ));
        assert_eq!(first["replaced"].as_u64(), Some(1), "{id}: completed replace");
        currency_links(&world.db, currency);
        let messages_before = count(&world.db, "SELECT COUNT(*) FROM messages");
        let revision_before = revision(&world.db);
        let links_before = sql_rows(
            &world.db,
            "SELECT * FROM source_message_links ORDER BY id",
        );
        let payload_before = sql_rows(&world.db, "SELECT * FROM source_inputs ORDER BY id");
        let receipts_before = sql_rows(
            &world.db,
            "SELECT * FROM operation_commit_receipt \
             WHERE operation = 'source_input_activation_v1' ORDER BY id",
        );
        refresh_marker_db_identity(&world);

        if id.ends_with("-missing") {
            // Missing restore C3: ordinary source Replay adds only the C3 and
            // the journal generation meta.
            delete_restore_receipt(&world.db);
            rewind_journal(&journal, "planned", &[], &[]);
            remove_marker(&world);
            let before = typed_snapshot(&world.db);
            let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
            assert_eq!(
                result.rc,
                Some(0),
                "{id}: replay must complete: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let report: serde_json::Value =
                serde_json::from_slice(&result.stdout).expect("recover JSON");
            assert_eq!(report["source_replayed"].as_u64(), Some(1));
            assert_eq!(report["replaced"].as_u64().unwrap_or(0), 0);
            assert_eq!(report["messages_inserted"].as_u64().unwrap_or(0), 0);
            assert_eq!(
                count(&world.db, "SELECT COUNT(*) FROM messages"),
                messages_before
            );
            assert_eq!(revision(&world.db), revision_before);
            assert_eq!(
                count(
                    &world.db,
                    "SELECT COUNT(*) FROM operation_commit_receipt \
                     WHERE operation = 'mirror-restore-replace' AND detail IS NOT NULL",
                ),
                1,
                "{id}: exactly one restore C3"
            );
            // Only the new receipt and the generation meta differ.
            let after = typed_snapshot(&world.db);
            let before_obj = before.as_object().unwrap();
            let after_obj = after.as_object().unwrap();
            for table in [
                "messages",
                "conversations",
                "agents",
                "workspaces",
                "source_inputs",
                "source_records",
                "source_message_links",
            ] {
                assert_eq!(before_obj[table], after_obj[table], "{id}: {table} unchanged");
            }
            let before_meta = before_obj["meta"].as_array().unwrap();
            let after_meta = after_obj["meta"].as_array().unwrap();
            let changed: Vec<_> = after_meta
                .iter()
                .filter(|row| !before_meta.contains(row))
                .collect();
            for row in &changed {
                let key = row[0]["value"].as_str().unwrap();
                assert_eq!(
                    key, "source_content_generation",
                    "{id}: only the generation meta may change"
                );
                assert_eq!(row[1]["value"].as_str().unwrap(), GENERATION);
            }
            assert_eq!(serde_json::json!(links_before), after_obj["source_message_links"]);
            assert_eq!(serde_json::json!(payload_before), after_obj["source_inputs"]);
            assert_eq!(receipts_before.len() + 1,
                after_obj["operation_commit_receipt"].as_array().unwrap().len());
        } else {
            // Existing C3: already committed, zero typed change.
            rewind_journal(
                &journal,
                "db-committed",
                &journal_json(&journal)["committed"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_string())
                    .collect::<Vec<_>>(),
                &journal_json(&journal)["published"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_string())
                    .collect::<Vec<_>>(),
            );
            remove_marker(&world);
            let before = typed_snapshot(&world.db);
            let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
            assert_eq!(
                result.rc,
                Some(0),
                "{id}: existing C3 replay must succeed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            let report: serde_json::Value =
                serde_json::from_slice(&result.stdout).expect("recover JSON");
            assert_eq!(report["already_committed"].as_u64(), Some(1));
            assert_eq!(report["replaced"].as_u64().unwrap_or(0), 0);
            assert_eq!(report["messages_inserted"].as_u64().unwrap_or(0), 0);
            assert_eq!(typed_snapshot(&world.db), before, "{id}: no typed change");
            assert_eq!(revision(&world.db), revision_before);
        }
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }

    // The real double replacement: 2 -> 4 -> 6, then the first journal replay.
    {
        let test = "r16_02_history_replay";
        let case = CaseDir::new(test, "real-double-replace-old-receipt");
        let (world, captures) = World::chain(&[codex_v0(), codex_v1(), codex_v2()]);
        // Hide the third version for the first replacement.
        let third = &captures[2];
        let manifest_path = world
            .data
            .join("raw-mirror/v1")
            .join(&third.manifest_relative_path);
        let hidden = world.data.join("hidden-third.json");
        std::fs::rename(&manifest_path, &hidden).expect("hide the third manifest");
        let live = world.home.join(".claude/projects/R16-chain/chain.jsonl");
        write_source(&live, &codex_v1(), 1_700_500_000);
        write_contexts(
            &world.contexts,
            &[captures[0].clone(), captures[1].clone()],
            &live,
            "R16_T16_CHAIN",
        );
        let first_journal = world.tmp.path().join("journal-first.json");
        let first = apply_result(&run_cli(
            &case,
            "apply-first",
            &apply_args(&world, &first_journal),
            &[],
            &world.env(),
        ));
        assert_eq!(first["replaced"].as_u64(), Some(1));
        assert_eq!(first["messages_inserted"].as_u64(), Some(4));
        // The second batch is its own run; the first run's marker must not
        // block it.
        remove_marker(&world);
        std::fs::rename(&hidden, &manifest_path).expect("restore the third manifest");
        write_source(&live, &codex_v2(), 1_700_600_000);
        write_contexts(&world.contexts, &captures, &live, "R16_T16_CHAIN");
        let second_journal = world.tmp.path().join("journal-second.json");
        let second = apply_result(&run_cli(
            &case,
            "apply-second",
            &apply_args_with_snapshot(&world, &second_journal, "c16-snapshot-2", GENERATION),
            &[],
            &world.env(),
        ));
        assert_eq!(second["replaced"].as_u64(), Some(1));
        assert_eq!(second["messages_inserted"].as_u64(), Some(6));
        // Rewind the first journal to db-committed so its old receipt is verified.
        rewind_journal(
            &first_journal,
            "db-committed",
            &journal_json(&first_journal)["committed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            &journal_json(&first_journal)["published"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
        );
        remove_marker(&world);
        let before = typed_snapshot(&world.db);
        let result = run_cli(
            &case,
            "recover-first",
            &recover_args(&first_journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            result.rc,
            Some(0),
            "the old receipt must verify: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("recover JSON");
        assert_eq!(report["already_committed"].as_u64(), Some(1));
        assert_eq!(report["replaced"].as_u64().unwrap_or(0), 0);
        assert_eq!(typed_snapshot(&world.db), before, "no write on old replay");
        case.pass();
        eprintln!("R16_CASE test={test} case=real-double-replace-old-receipt result=pass");
    }


    // Message-id reuse never revives an old link: the old rows keep their ids
    // and stay historical/NULL, while the new canonical links are new rows over
    // real current messages.
    {
        let test = "r16_02_history_replay";
        let case = CaseDir::new(test, "message-id-reuse-does-not-revive");
        let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
        let old_rows: Vec<i64> = sql_rows(
            &world.db,
            "SELECT id FROM source_message_links WHERE authority = 'canonical' ORDER BY id",
        )
        .iter()
        .map(|row| row[0]["value"].as_i64().unwrap())
        .collect();
        let journal = world.journal();
        let report = apply_result(&run_cli(
            &case,
            "apply",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
        ));
        assert_eq!(report["replaced"].as_u64(), Some(1));
        for row_id in &old_rows {
            assert_eq!(
                count(
                    &world.db,
                    &format!(
                        "SELECT COUNT(*) FROM source_message_links \
                         WHERE id = {row_id} AND authority = 'historical' AND message_id IS NULL"
                    ),
                ),
                1,
                "old link row {row_id} must stay historical/NULL"
            );
        }
        assert_eq!(
            count(
                &world.db,
                "SELECT COUNT(*) FROM source_message_links \
                 WHERE authority = 'historical' AND message_id IS NOT NULL",
            ),
            0
        );
        assert_eq!(
            count(
                &world.db,
                "SELECT COUNT(*) FROM source_message_links l \
                 LEFT JOIN messages m ON m.id = l.message_id \
                 WHERE l.authority = 'canonical' AND m.id IS NULL",
            ),
            0
        );
        case.pass();
        eprintln!("R16_CASE test={test} case=message-id-reuse-does-not-revive result=pass");
    }

    // A real SourceNew receipt remains valid after a real newer Replace.
    {
        let test = "r16_02_history_replay";
        let case = CaseDir::new(test, "old-new-receipt-after-real-replace");
        let (world, captures) = World::chain(&[codex_v0()]);
        let empty = world.tmp.path().join("empty.db");
        {
            let mut storage = FrankenStorage::open(&empty).expect("create the empty candidate");
            storage.close_best_effort_in_place();
        }
        let live = world.home.join(".claude/projects/R16-chain/chain.jsonl");
        let world = World { db: empty, ..world };
        let new_journal = world.tmp.path().join("journal-new.json");
        let new_report = apply_result(&run_cli(
            &case,
            "apply-new",
            &apply_args(&world, &new_journal),
            &[],
            &world.env(),
        ));
        assert_eq!(new_report["restored"].as_u64(), Some(1), "real SourceNew");
        write_source(&live, &codex_v1(), 1_700_300_000);
        let second = capture(&world.data, &live);
        write_contexts(
            &world.contexts,
            &[captures[0].clone(), second],
            &live,
            "R16_T16_CHAIN",
        );
        // The newer run is its own batch: drop the New run's marker so the
        // marker gate compares against the journal this run writes.
        remove_marker(&world);
        let replace_journal = world.tmp.path().join("journal-replace.json");
        let replace_report = apply_result(&run_cli(
            &case,
            "apply-replace",
            &apply_args(&world, &replace_journal),
            &[],
            &world.env(),
        ));
        assert_eq!(replace_report["replaced"].as_u64(), Some(1));
        rewind_journal(
            &new_journal,
            "db-committed",
            &journal_json(&new_journal)["committed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            &journal_json(&new_journal)["published"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
        );
        remove_marker(&world);
        let before = typed_snapshot(&world.db);
        let result = run_cli(&case, "recover-old-new", &recover_args(&new_journal), &[], &world.env());
        assert_eq!(
            result.rc,
            Some(0),
            "old New receipt must verify as Historical: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("recover JSON");
        assert_eq!(report["already_committed"].as_u64(), Some(1));
        assert_eq!(report["replaced"].as_u64().unwrap_or(0), 0);
        assert_eq!(typed_snapshot(&world.db), before, "no write on old replay");
        case.pass();
        eprintln!("R16_CASE test={test} case=old-new-receipt-after-real-replace result=pass");
    }

    // -----------------------------------------------------------------------
    // R1 side cases 1-8: target relationship across both C3 arms and all seven
    // journal states, plus the two historical publication controls. The side
    // evidence lives under `r1-side/`; the nine rows above keep their own
    // denominator.
    // -----------------------------------------------------------------------
    let carrier_root = r1_carrier_root();
    for (arm, c3, target, decoy) in [
        ("r16r1-absent-valid", false, 1u64, false),
        ("r16r1-absent-missing", false, 999_999, false),
        ("r16r1-absent-unrelated", false, 2, true),
        ("r16r1-present-valid", true, 1, false),
        ("r16r1-present-missing", true, 999_999, false),
        ("r16r1-present-unrelated", true, 2, true),
    ] {
        let states: &[&str] = if arm.ends_with("-valid") {
            if c3 {
                &["closure-verified"]
            } else {
                &["planned"]
            }
        } else {
            &[
                "planned",
                "db-committed",
                "readiness-invalidated",
                "embeddings-invalidated",
                "analytics-rebuilt",
                "manifest-partial",
                "closure-verified",
            ]
        };
        for state in states {
            let id = format!("{arm}/{state}");
            let label = format!("{arm}-{state}");
            let case = CaseDir::new("r1-side", &label);
            let (world, journal) = r1_clone(
                &case,
                &carrier_root.join("seed"),
                c3,
                target,
                decoy,
                state,
                false,
                false,
            );
            let planned_id = journal_json(&journal)["planned"][0]["manifest_id"]
                .as_str()
                .expect("planned manifest id")
                .to_string();
            let before = typed_snapshot(&world.db);
            let before_mirror = mirror_digest(&world.data);
            let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
            if arm.ends_with("-valid") {
                assert_eq!(
                    result.rc,
                    Some(0),
                    "{id}: the legal arm must succeed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let report: serde_json::Value =
                    serde_json::from_slice(&result.stdout).expect("recover JSON");
                if c3 {
                    assert_eq!(report["already_committed"].as_u64(), Some(1), "{id}");
                } else {
                    assert_eq!(report["source_replayed"].as_u64(), Some(1), "{id}");
                }
                assert_eq!(
                    report["replaced"].as_u64().unwrap_or(0),
                    0,
                    "{id}: no reinstall"
                );
                let links = r1_manifest_links(&world, &planned_id);
                assert!(
                    links.iter().any(|link| *link == Some(1)),
                    "{id}: the proven parent is linked: {links:?}"
                );
                assert!(
                    !links
                        .iter()
                        .any(|link| matches!(link, Some(2) | Some(999_999))),
                    "{id}: no wrong link: {links:?}"
                );
            } else {
                assert_eq!(result.rc, Some(1), "{id}: the bad target must be refused");
                assert_kind(&result, "source_restore_receipt_conflict");
                assert_eq!(typed_snapshot(&world.db), before, "{id}: typed state unchanged");
                assert_eq!(mirror_digest(&world.data), before_mirror, "{id}: mirror unchanged");
            }
            r1_side_pass(
                &id,
                "recover",
                &result,
                &serde_json::json!({
                    "id": id,
                    "arm": arm,
                    "state": state,
                    "expected": if arm.ends_with("-valid") { "rc0/no-reinstall" } else { "rc1/source_restore_receipt_conflict" },
                }),
            );
        }
        if c3 && !arm.ends_with("-valid") {
            for (label, deep) in [("qualify", false), ("qualify-deep", true)] {
                let id = format!("{arm}/{label}");
                let case = CaseDir::new("r1-side", &format!("{arm}-{label}"));
                let (world, journal) = r1_clone(
                    &case,
                    &carrier_root.join("seed"),
                    c3,
                    target,
                    decoy,
                    "closure-verified",
                    false,
                    true,
                );
                refresh_marker_identity(&world, &journal);
                let result = run_cli(
                    &case,
                    label,
                    &qualify_args(&world, &journal, deep),
                    &[],
                    &world.env(),
                );
                assert_eq!(
                    result.rc,
                    Some(1),
                    "{id}: qualification must refuse the wrong target"
                );
                assert_kind(&result, "source_restore_receipt_conflict");
                r1_side_pass(
                    &id,
                    label,
                    &result,
                    &serde_json::json!({"id": id, "arm": arm, "mode": label}),
                );
            }
        }
    }
    for (id, mode) in [
        ("r16r1-historical-parent-absent", "parent-absent"),
        ("r16r1-historical-parent-reused", "parent-reused"),
    ] {
        let case = CaseDir::new("r1-side", id);
        let carrier = carrier_root.join("historical-fk-valid").join(mode);
        let (world, journal) = r1_clone(
            &case,
            &carrier,
            true,
            1,
            false,
            "closure-verified",
            true,
            false,
        );
        let planned_id = journal_json(&journal)["planned"][0]["manifest_id"]
            .as_str()
            .expect("planned manifest id")
            .to_string();
        let before = typed_snapshot(&world.db);
        let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: the legal historical replay must succeed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("recover JSON");
        assert_eq!(report["already_committed"].as_u64(), Some(1), "{id}");
        assert_eq!(
            report["replaced"].as_u64().unwrap_or(0),
            0,
            "{id}: no reinstall"
        );
        assert_eq!(
            report["published_without_backlink"].as_u64(),
            Some(1),
            "{id}: None is counted, not failed"
        );
        assert_eq!(typed_snapshot(&world.db), before, "{id}: no DB write");
        let links = r1_manifest_links(&world, &planned_id);
        assert!(
            links.iter().any(Option::is_none),
            "{id}: the absent/reused parent is linked as None: {links:?}"
        );
        assert!(
            !links
                .iter()
                .any(|link| matches!(link, Some(2) | Some(999_999))),
            "{id}: no wrong link: {links:?}"
        );
        r1_side_pass(
            id,
            "recover",
            &result,
            &serde_json::json!({"id": id, "expected": "already_committed1/None/0"}),
        );
    }
}

// ---------------------------------------------------------------------------
// R1 · carrier cloning and side evidence
// ---------------------------------------------------------------------------

fn r1_carrier_root() -> PathBuf {
    PathBuf::from(
        std::env::var("CASS_T16_R1_SEED_ROOT")
            .expect("CASS_T16_R1_SEED_ROOT must point at Root's target-integrity carrier"),
    )
}

fn r1_clone(
    case: &CaseDir,
    carrier: &Path,
    c3: bool,
    target: u64,
    decoy: bool,
    state: &str,
    keep_bookkeeping: bool,
    keep_marker: bool,
) -> (World, PathBuf) {
    let _ = case;
    let tmp = TempDir::new().expect("create the r1 world tempdir");
    let home = tmp.path().join("home");
    let xdg_config = tmp.path().join("xdg-config");
    let xdg_data = tmp.path().join("xdg-data");
    let xdg_cache = tmp.path().join("xdg-cache");
    let xdg_state = tmp.path().join("xdg-state");
    let tmpdir = tmp.path().join("tmpdir");
    let cwd = tmp.path().join("cwd");
    let scratch = tmp.path().join("scratch");
    let data = tmp.path().join("data");
    for path in [
        &home,
        &xdg_config,
        &xdg_data,
        &xdg_cache,
        &xdg_state,
        &tmpdir,
        &cwd,
        &scratch,
        &data,
    ] {
        std::fs::create_dir_all(path).expect("create an r1 world directory");
    }
    std::fs::write(cwd.join(".env"), b"").expect("write the empty cwd .env");
    copy_tree(&carrier.join("data"), &data);
    copy_tree(&carrier.join("scratch"), &scratch);
    let db = data.join("agent_search.db");
    let journal = tmp.path().join("journal.json");
    let mut value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(carrier.join("journal.json")).expect("read the carrier journal"),
    )
    .expect("decode the carrier journal");
    value["data_dir"] = serde_json::json!(data);
    value["scratch_dir"] = serde_json::json!(scratch);
    value["db_path"] = serde_json::json!(db);
    value["marker_path"] = serde_json::json!(data.join("w1-commit-marker.json"));
    value["state"] = serde_json::json!(state);
    value["planned"][0]["action"]["conversation_id"] = serde_json::json!(target);
    if keep_bookkeeping {
        // The historical carriers keep their committed receipt bookkeeping so
        // the replay accounts `already_committed`, but the publish list is
        // cleared: publication must run again and decide the link under R1.
        value["published"] = serde_json::json!([]);
    } else {
        value["committed"] = serde_json::json!([]);
        value["published"] = serde_json::json!([]);
    }
    std::fs::write(
        &journal,
        serde_json::to_vec(&value).expect("encode the journal"),
    )
    .expect("write the journal");
    if !c3 {
        delete_restore_receipt(&db);
    }
    if decoy {
        sqlite_exec(
            &db,
            "INSERT INTO conversations (id, agent_id, workspace_id, source_id, external_id, \
             title, source_path, started_at, ended_at, approx_tokens, metadata_json, origin_host, \
             identity_host, metadata_bin, last_message_idx, last_message_created_at) \
             SELECT 2, agent_id, workspace_id, source_id, 'ROOT-DECOY-2', title, source_path, \
             started_at, ended_at, approx_tokens, metadata_json, origin_host, identity_host, \
             metadata_bin, last_message_idx, last_message_created_at FROM conversations WHERE id = 1",
        );
    }
    let marker = data.join("w1-commit-marker.json");
    if marker.exists() && !keep_marker {
        std::fs::rename(&marker, data.join("w1-commit-marker.archive"))
            .expect("archive the carrier marker");
    }
    let world = World {
        tmp,
        home,
        xdg_config,
        xdg_data,
        xdg_cache,
        xdg_state,
        tmpdir,
        cwd,
        scratch,
        data,
        db,
        contexts: PathBuf::new(),
        fixed: PathBuf::new(),
    };
    (world, journal)
}

fn r1_manifest_links(world: &World, planned_id: &str) -> Vec<Option<i64>> {
    let manifests = world
        .data
        .join("raw-mirror")
        .join("v1")
        .join("manifests");
    let entry = std::fs::read_dir(&manifests)
        .expect("read the manifest directory")
        .map(|entry| entry.expect("manifest entry").path())
        .find(|path| path.to_string_lossy().contains(planned_id))
        .expect("the planned manifest file");
    let value: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&entry).expect("read the planned manifest"),
    )
    .expect("decode the planned manifest");
    value["db_links"]
        .as_array()
        .map(|links| {
            links
                .iter()
                .map(|link| link["conversation_id"].as_i64())
                .collect()
        })
        .unwrap_or_default()
}

fn r1_side_pass(id: &str, label: &str, result: &RunResult, expected: &serde_json::Value) {
    let dir = result_root().join("r1-side").join(id.replace('/', "_"));
    std::fs::create_dir_all(&dir).expect("create the r1 side evidence directory");
    std::fs::write(
        dir.join("expected.json"),
        serde_json::to_vec(expected).expect("encode the expected side row"),
    )
    .expect("write the expected side row");
    std::fs::write(dir.join(format!("{label}.stdout")), &result.stdout)
        .expect("write the side stdout");
    std::fs::write(dir.join(format!("{label}.stderr")), &result.stderr)
        .expect("write the side stderr");
    std::fs::write(dir.join("PASS"), b"").expect("write the side PASS");
}

// ---------------------------------------------------------------------------
// r16_03 · complete C3 binding mutations
// ---------------------------------------------------------------------------

fn completed_chain(test: &str, id: &str) -> (CaseDir, World, PathBuf) {
    let case = CaseDir::new(test, id);
    let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
    let journal = world.journal();
    let report = apply_result(&run_cli(
        &case,
        "apply",
        &apply_args(&world, &journal),
        &[],
        &world.env(),
    ));
    assert_eq!(report["replaced"].as_u64(), Some(1));
    rewind_journal(
        &journal,
        "db-committed",
        &journal_json(&journal)["committed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        &journal_json(&journal)["published"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
    );
    (case, world, journal)
}

fn mutate_c3(db: &Path, id: &str) {
    match id {
        id if id.starts_with("request/") => {
            let field = id.trim_start_matches("request/").to_string();
            mutate_restore_detail(db, |detail| match field.as_str() {
                "finish" => {
                    detail["source_request"]["finish"][3] =
                        serde_json::json!("999");
                }
                "projection_disposition" => {
                    detail["source_request"]["projection_disposition"] =
                        serde_json::json!("WholeInputRejected");
                }
                "requested_terminal" => {
                    detail["source_request"]["requested_terminal"] =
                        serde_json::json!("Partial");
                }
                other => {
                    detail["source_request"][other] = serde_json::json!(OTHER_HEX);
                }
            });
        }
        id if id.starts_with("detail/") => {
            let field = id.trim_start_matches("detail/").to_string();
            mutate_restore_detail(db, |detail| {
                detail[&field] = serde_json::json!(OTHER_HEX);
            });
        }
        id if id.starts_with("input-row/") => {
            let field = id.trim_start_matches("input-row/");
            let key = restore_receipt_detail(db)["source_request"]["input_key"]
                .as_str()
                .unwrap()
                .to_string();
            let params: Vec<coding_agent_search::storage::api::Value> = match field {
                "byte_len" => vec![
                    coding_agent_search::storage::api::Value::Blob(vec![0u8; 8]),
                    coding_agent_search::storage::api::Value::Blob(hex_to_bytes(&key)),
                ],
                "normalizer_id" | "safety_contract_id" => vec![
                    coding_agent_search::storage::api::Value::Text("other".into()),
                    coding_agent_search::storage::api::Value::Blob(
                        hex_to_bytes(&key),
                    ),
                ],
                _ => vec![coding_agent_search::storage::api::Value::Blob(vec![0xAAu8; 32]),
                          coding_agent_search::storage::api::Value::Blob(hex_to_bytes(&key))],
            };
            if matches!(field, "normalizer_id" | "safety_contract_id") {
                sqlite_exec_params(
                    db,
                    &format!("UPDATE source_inputs SET {field} = ?1 WHERE input_key = ?2"),
                    &params,
                );
            } else {
                sqlite_exec_params(
                    db,
                    &format!("UPDATE source_inputs SET {field} = ?1 WHERE input_key = ?2"),
                    &params,
                );
            }
        }
        "source-input-registration-missing" => {
            let key = restore_receipt_detail(db)["source_request"]["input_key"]
                .as_str()
                .unwrap()
                .to_string();
            sqlite_exec_params(
                db,
                "DELETE FROM source_inputs WHERE input_key = ?1",
                &[coding_agent_search::storage::api::Value::Blob(hex_to_bytes(&key))],
            );
        }
        "activation-row-missing" => {
            let key = restore_receipt_detail(db)["source_receipt_key"]
                .as_str()
                .unwrap()
                .to_string();
            sqlite_exec_params(
                db,
                "DELETE FROM operation_commit_receipt WHERE idempotency_key = ?1",
                &[coding_agent_search::storage::api::Value::Text(key)],
            );
        }
        "activation-detail-corrupt" => {
            let key = restore_receipt_detail(db)["source_receipt_key"]
                .as_str()
                .unwrap()
                .to_string();
            sqlite_exec_params(
                db,
                "UPDATE operation_commit_receipt SET detail = 'x' WHERE idempotency_key = ?1",
                &[coding_agent_search::storage::api::Value::Text(key)],
            );
        }
        "receipt-row/operation" => {
            sqlite_exec(
                db,
                "UPDATE operation_commit_receipt SET operation = 'mirror-restore-new' \
                 WHERE operation = 'mirror-restore-replace'",
            );
        }
        "receipt-row/detail-null-legacy" => {
            sqlite_exec(
                db,
                "UPDATE operation_commit_receipt SET detail = NULL \
                 WHERE operation = 'mirror-restore-replace'",
            );
        }
        other => panic!("no mutation for {other}"),
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len(), 64, "one digest is 32 bytes");
    (0..32)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn r16_03_full_c3_binding() {
    let cases: &[(&str, &str)] = &[
        ("request/input_key", "source_restore_receipt_conflict"),
        ("request/library_identity", "source_restore_receipt_conflict"),
        ("request/normalizer_id", "source_restore_receipt_conflict"),
        ("request/safety_contract_id", "source_restore_receipt_conflict"),
        ("request/expected_manifest_digest", "source_restore_receipt_conflict"),
        ("request/finish", "source_restore_receipt_conflict"),
        ("request/projection_disposition", "source_restore_receipt_conflict"),
        ("request/source_semantic_records_root", "source_restore_receipt_conflict"),
        ("request/claims_root", "source_restore_receipt_conflict"),
        ("request/requested_terminal", "source_restore_receipt_conflict"),
        ("detail/restore_operation", "source_restore_receipt_conflict"),
        ("detail/snapshot_root", "source_restore_receipt_conflict"),
        ("detail/manifest_id", "source_restore_receipt_conflict"),
        ("detail/source_receipt_key", "source_restore_receipt_conflict"),
        ("detail/source_installation_digest", "source_restore_receipt_conflict"),
        ("input-row/context_digest", "source_restore_receipt_conflict"),
        ("input-row/sealed_sha256", "source_restore_receipt_conflict"),
        ("input-row/byte_len", "source_restore_receipt_conflict"),
        ("input-row/normalizer_id", "source_restore_receipt_conflict"),
        ("input-row/safety_contract_id", "source_restore_receipt_conflict"),
        ("source-input-registration-missing", "source_restore_receipt_conflict"),
        ("activation-row-missing", "source_restore_receipt_conflict"),
        ("activation-detail-corrupt", "source_restore_receipt_inconsistent"),
        ("detail/restore_key", "source_restore_receipt_conflict"),
        ("receipt-row/operation", "source_restore_receipt_conflict"),
        ("receipt-row/detail-null-legacy", "source_restore_receipt_conflict"),
    ];
    for (id, expected) in cases {
        let (case, world, journal) = completed_chain("r16_03_full_c3_binding", id);
        mutate_c3(&world.db, id);
        remove_marker(&world);
        let before = typed_snapshot(&world.db);
        let before_mirror = mirror_digest(&world.data);
        let before_journal = std::fs::read(&journal).expect("read the journal");
        let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(result.rc, Some(1), "{id}: the mutation must be refused");
        assert_kind(&result, expected);
        assert_eq!(typed_snapshot(&world.db), before, "{id}: no DB write");
        assert_eq!(mirror_digest(&world.data), before_mirror, "{id}: no mirror write");
        assert_eq!(
            std::fs::read(&journal).expect("read the journal"),
            before_journal,
            "{id}: no journal write"
        );
        case.pass();
        eprintln!("R16_CASE test=r16_03_full_c3_binding case={id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r16_04 · material-first across the seven journal states
// ---------------------------------------------------------------------------

#[test]
fn r16_04_journal_material_first() {
    let states = [
        "planned",
        "db-committed",
        "readiness-invalidated",
        "embeddings-invalidated",
        "analytics-rebuilt",
        "manifest-partial",
        "closure-verified",
    ];
    for state in states {
        for (suffix, bad) in [("valid", false), ("bad-material", true)] {
            let id = format!("{state}-{suffix}");
            let test = "r16_04_journal_material_first";
            let case = CaseDir::new(test, &id);
            let (world, journal) = if state == "planned" {
                let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
                let journal = world.journal();
                run_paused_at(
                    &case,
                    "apply-paused",
                    &apply_args(&world, &journal),
                    &[],
                    &world.env(),
                    &case.join("pause.sentinel"),
                    "planned",
                );
                (world, journal)
            } else {
                let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
                let journal = world.journal();
                apply_result(&run_cli(
                    &case,
                    "apply",
                    &apply_args(&world, &journal),
                    &[],
                    &world.env(),
                ));
                rewind_journal(
                    &journal,
                    state,
                    &journal_json(&journal)["committed"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_str().unwrap().to_string())
                        .collect::<Vec<_>>(),
                    &journal_json(&journal)["published"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_str().unwrap().to_string())
                        .collect::<Vec<_>>(),
                );
                (world, journal)
            };
            if bad {
                let mut value = journal_json(&journal);
                let bad_key: String = Sha256::digest(b"ROOT_R16_BAD")
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                value["planned"][0]["source_binding"]["input_key"] =
                    serde_json::json!(bad_key);
                write_journal(&journal, &value);
            }
            remove_marker(&world);
            let before_db = typed_snapshot(&world.db);
            let before_mirror = mirror_digest(&world.data);
            let before_journal = std::fs::read(&journal).expect("read the journal");
            let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
            if bad {
                assert_eq!(result.rc, Some(1), "{id}: bad material must be refused");
                assert_kind(&result, "source_restore_material_mismatch");
                assert_eq!(typed_snapshot(&world.db), before_db);
                assert_eq!(mirror_digest(&world.data), before_mirror);
                assert_eq!(std::fs::read(&journal).expect("read"), before_journal);
            } else if state == "planned" {
                let report = apply_result(&result);
                assert_eq!(report["replaced"].as_u64(), Some(1), "{id}: real replace");
            } else {
                assert_eq!(
                    result.rc,
                    Some(0),
                    "{id}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                let report: serde_json::Value =
                    serde_json::from_slice(&result.stdout).expect("recover JSON");
                assert_eq!(report["already_committed"].as_u64(), Some(1));
            }
            case.pass();
            eprintln!("R16_CASE test={test} case={id} result=pass");
        }
    }
}

// ---------------------------------------------------------------------------
// r16_05 · atomicity
// ---------------------------------------------------------------------------

fn planned_native(test: &str, id: &str, world: World) -> (CaseDir, World, PathBuf) {
    let case = CaseDir::new(test, id);
    let journal = world.journal();
    run_paused_at(
        &case,
        "apply-paused",
        &apply_args(&world, &journal),
        &[],
        &world.env(),
        &case.join("pause.sentinel"),
        "planned",
    );
    (case, world, journal)
}

fn assert_failed_then_recovered(
    case: &CaseDir,
    world: &World,
    journal: &Path,
    label: &str,
    expected_kind: &str,
) {
    let before = typed_snapshot(&world.db);
    let before_mirror = mirror_digest(&world.data);
    let failed = run_cli(case, label, &recover_args(journal), &[], &world.env());
    assert_eq!(failed.rc, Some(1), "{label}: the injected failure must fire");
    assert_kind(&failed, expected_kind);
    assert_eq!(typed_snapshot(&world.db), before, "{label}: whole transaction rolled back");
    assert_eq!(mirror_digest(&world.data), before_mirror, "{label}: mirror retained");
    let recovered = apply_result(&run_cli(
        case,
        &format!("{label}-recover"),
        &recover_args(journal),
        &[],
        &world.env(),
    ));
    assert_eq!(recovered["replaced"].as_u64(), Some(1), "{label}: replaced once");
    let again = apply_result(&run_cli(
        case,
        &format!("{label}-noop"),
        &recover_args(journal),
        &[],
        &world.env(),
    ));
    assert_eq!(again["already_committed"].as_u64(), Some(1), "{label}: second no-op");
}

#[test]
fn r16_05_atomicity() {
    for (native, id) in [
        ("claude_code-jsonl", "claude_code-jsonl/late-c3-before-insert-trigger"),
        ("claude_code-jsonl", "claude_code-jsonl/postwrite-library-identity-blob"),
        ("claude_code-jsonl", "claude_code-jsonl/inside-source-tx-sigkill"),
        ("codex-jsonl", "codex-jsonl/late-c3-before-insert-trigger"),
        ("codex-jsonl", "codex-jsonl/postwrite-library-identity-blob"),
        ("codex-jsonl", "codex-jsonl/inside-source-tx-sigkill"),
    ] {
        let (case, world, journal) = planned_native("r16_05_atomicity", id, World::native(native));
        if id.ends_with("late-c3-before-insert-trigger") {
            sqlite_exec(
                &world.db,
                "CREATE TRIGGER r16_canary BEFORE INSERT ON operation_commit_receipt \
                 WHEN NEW.operation = 'mirror-restore-replace' \
                 BEGIN SELECT RAISE(ABORT, 'R16_PRIVATE_CANARY'); END",
            );
            let before = typed_snapshot(&world.db);
            let failed = run_cli(&case, "injected", &recover_args(&journal), &[], &world.env());
            assert_eq!(failed.rc, Some(1));
            assert_kind(&failed, "mirror_restore_recover_failed");
            assert_eq!(typed_snapshot(&world.db), before);
            sqlite_exec(&world.db, "DROP TRIGGER r16_canary");
            let recovered = apply_result(&run_cli(
                &case,
                "recover",
                &recover_args(&journal),
                &[],
                &world.env(),
            ));
            assert_eq!(recovered["replaced"].as_u64(), Some(1));
            let again = apply_result(&run_cli(
                &case,
                "recover-noop",
                &recover_args(&journal),
                &[],
                &world.env(),
            ));
            assert_eq!(again["already_committed"].as_u64(), Some(1));
        } else if id.ends_with("postwrite-library-identity-blob") {
            sqlite_exec(
                &world.db,
                "CREATE TRIGGER r16_canary AFTER INSERT ON operation_commit_receipt \
                 WHEN NEW.operation = 'mirror-restore-replace' \
                 BEGIN UPDATE meta SET value = X'FF' WHERE key = 'library_identity'; END",
            );
            // F3: snapshot after the trigger is built and before the failure so
            // the whole typed nine-table state and the mirror can be compared.
            let before = typed_snapshot(&world.db);
            let before_mirror = mirror_digest(&world.data);
            let failed = run_cli(&case, "injected", &recover_args(&journal), &[], &world.env());
            assert_eq!(failed.rc, Some(1));
            assert_kind(&failed, "mirror_restore_recover_failed");
            assert_eq!(typed_snapshot(&world.db), before, "{id}: typed nine tables rolled back");
            assert_eq!(mirror_digest(&world.data), before_mirror, "{id}: mirror retained");
            sqlite_exec(&world.db, "DROP TRIGGER r16_canary");
            let recovered = apply_result(&run_cli(
                &case,
                "recover",
                &recover_args(&journal),
                &[],
                &world.env(),
            ));
            assert_eq!(recovered["replaced"].as_u64(), Some(1));
            let again = apply_result(&run_cli(
                &case,
                "recover-noop",
                &recover_args(&journal),
                &[],
                &world.env(),
            ));
            assert_eq!(again["already_committed"].as_u64(), Some(1));
        } else {
            let before = typed_snapshot(&world.db);
            let killed = run_paused_at(
                &case,
                "apply-sigkill",
                &recover_args(&journal),
                &[],
                &world.env(),
                &case.join("inside.sentinel"),
                "restore-new-inserted-not-receipted",
            );
            assert!(killed.rc.is_none(), "{id}: the child was SIGKILLed");
            assert_eq!(typed_snapshot(&world.db), before, "{id}: no half commit");
            let recovered = apply_result(&run_cli(
                &case,
                "recover",
                &recover_args(&journal),
                &[],
                &world.env(),
            ));
            assert_eq!(recovered["replaced"].as_u64(), Some(1));
            let again = apply_result(&run_cli(
                &case,
                "recover-noop",
                &recover_args(&journal),
                &[],
                &world.env(),
            ));
            assert_eq!(again["already_committed"].as_u64(), Some(1));
        }
        let _ = assert_failed_then_recovered;
        case.pass();
        eprintln!("R16_CASE test=r16_05_atomicity case={id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r16_06 · alias queries
// ---------------------------------------------------------------------------

#[test]
fn r16_06_alias_queries() {
    {
        let test = "r16_06_alias_queries";
        let id = "legacy-raw-agent-only";
        let case = CaseDir::new(test, id);
        let world = World::extra("legacy-raw-only");
        let report = plan_report(&case, &world);
        assert_eq!(report["replace"].as_u64(), Some(1), "{id}: replace parent1");
        let journal = world.journal();
        let applied = apply_result(&run_cli(
            &case,
            "apply",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
        ));
        assert_eq!(applied["replaced"].as_u64(), Some(1));
        assert_eq!(
            count(&world.db, "SELECT COUNT(*) FROM messages WHERE conversation_id = 1"),
            4
        );
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
    {
        let test = "r16_06_alias_queries";
        let id = "canonical-plus-raw-two-candidates";
        let case = CaseDir::new(test, id);
        let world = World::extra("canonical-plus-raw");
        let before_db = db_sha(&world.db);
        let before_mirror = mirror_digest(&world.data);
        let report = plan_report(&case, &world);
        assert_eq!(
            report["hold_multiple_candidates"].as_u64(),
            Some(1),
            "{id}: two candidates hold"
        );
        assert_eq!(report["planned_actions"].as_u64(), Some(0));
        assert_eq!(db_sha(&world.db), before_db, "{id}: plan writes nothing");
        assert_eq!(mirror_digest(&world.data), before_mirror);
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r16_07 · admission, delete, legacy
// ---------------------------------------------------------------------------

#[test]
fn r16_07_admission_delete_legacy() {
    {
        let test = "r16_07_admission_delete_legacy";
        let id = "zero-replace-projection";
        let case = CaseDir::new(test, id);
        let (world, _) = World::chain(&[Vec::new()]);
        let journal = world.journal();
        run_paused_at(
            &case,
            "apply-paused",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
            &case.join("pause.sentinel"),
            "planned",
        );
        let mut value = journal_json(&journal);
        value["planned"][0]["action"] =
            serde_json::json!({"kind": "replace", "conversation_id": 1});
        write_journal(&journal, &value);
        let before = typed_snapshot(&world.db);
        let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_projection_count");
        assert_eq!(typed_snapshot(&world.db), before, "{id}: no DB mutation");
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
    {
        let test = "r16_07_admission_delete_legacy";
        let id = "forget-no-resurrection";
        let case = CaseDir::new(test, id);
        let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
        let journal = world.journal();
        apply_result(&run_cli(
            &case,
            "apply",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
        ));
        let live = world.home.join(".claude/projects/R16-chain/chain.jsonl");
        {
            let mut storage = FrankenStorage::open(&world.db).expect("open for forget");
            storage
                .forget_conversations_by_source_glob(&live.to_string_lossy(), false)
                .expect("forget the source conversations");
            storage.close_best_effort_in_place();
        }
        rewind_journal(
            &journal,
            "db-committed",
            &journal_json(&journal)["committed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            &journal_json(&journal)["published"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
        );
        // The public OriginalGlob forget removes both the canonical rows and
        // the matching source copies. That is the existing deletion contract.
        assert_eq!(count(&world.db, "SELECT COUNT(*) FROM messages"), 0);
        assert_eq!(count(&world.db, "SELECT COUNT(*) FROM conversations"), 0);
        assert_eq!(count(&world.db, "SELECT COUNT(*) FROM source_inputs"), 0);
        assert_eq!(count(&world.db, "SELECT COUNT(*) FROM source_records"), 0);
        assert_eq!(
            count(&world.db, "SELECT COUNT(*) FROM source_message_links"),
            0
        );
        remove_marker(&world);
        let after_forget = typed_snapshot(&world.db);
        let after_mirror = mirror_digest(&world.data);
        let c3_before = count(
            &world.db,
            "SELECT COUNT(*) FROM operation_commit_receipt \
             WHERE operation = 'mirror-restore-replace' AND detail IS NOT NULL",
        );
        let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(result.rc, Some(1), "{id}: the old request must be refused");
        assert_kind(&result, "source_restore_receipt_conflict");
        assert_eq!(
            typed_snapshot(&world.db),
            after_forget,
            "{id}: no typed state changes on the refused request"
        );
        assert_eq!(mirror_digest(&world.data), after_mirror, "{id}: mirror retained");
        assert_eq!(
            count(
                &world.db,
                "SELECT COUNT(*) FROM operation_commit_receipt \
                 WHERE operation = 'mirror-restore-replace' AND detail IS NOT NULL",
            ),
            c3_before,
            "{id}: the refused request writes no new C3"
        );
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
    {
        let test = "r16_07_admission_delete_legacy";
        let id = "purge-sourcefacts-refuses";
        let case = CaseDir::new(test, id);
        let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
        let journal = world.journal();
        apply_result(&run_cli(
            &case,
            "apply",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
        ));
        {
            let mut storage = FrankenStorage::open(&world.db).expect("open for purge");
            storage
                .purge_agent_archive_data("claude_code")
                .expect("purge the codex archive data");
            storage.close_best_effort_in_place();
        }
        rewind_journal(
            &journal,
            "db-committed",
            &journal_json(&journal)["committed"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            &journal_json(&journal)["published"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
        );
        remove_marker(&world);
        let messages = count(&world.db, "SELECT COUNT(*) FROM messages");
        let c3_before = count(
            &world.db,
            "SELECT COUNT(*) FROM operation_commit_receipt \
             WHERE operation = 'mirror-restore-replace' AND detail IS NOT NULL",
        );
        let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_receipt_conflict");
        assert_eq!(
            count(&world.db, "SELECT COUNT(*) FROM messages"),
            messages,
            "{id}: no resurrection"
        );
        assert_eq!(
            count(
                &world.db,
                "SELECT COUNT(*) FROM operation_commit_receipt \
                 WHERE operation = 'mirror-restore-replace' AND detail IS NOT NULL",
            ),
            c3_before,
            "{id}: no fabricated C3"
        );
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
    {
        let test = "r16_07_admission_delete_legacy";
        let id = "legacy-replace-still-original";
        let case = CaseDir::new(test, id);
        // Root-verified real Openclaw legacy carrier: clone it, take no source
        // contexts, and use the original legacy plan/apply/recover path.
        let (world, descriptor) = World::legacy_openclaw();
        let out = case.join("plan.json");
        let plan = run_cli(&case, "plan", &legacy_plan_args(&world, Some(&out)), &[], &world.env());
        assert_eq!(
            plan.rc,
            Some(0),
            "{id}: legacy plan: {}",
            String::from_utf8_lossy(&plan.stderr)
        );
        let plan_report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&out).expect("read the plan report"))
                .expect("decode the plan report");
        assert_eq!(plan_report["replace"].as_u64(), Some(1));
        assert_eq!(plan_report["restore"].as_u64().unwrap_or(0), 0);
        assert_eq!(plan_report["planned_actions"].as_u64(), Some(1));
        assert_eq!(plan_report["holds"].as_u64().unwrap_or(0), 0);
        assert_eq!(plan_report["origin_unmapped"].as_u64().unwrap_or(0), 0);

        let journal = world.journal();
        run_paused_at(
            &case,
            "apply-paused",
            &legacy_apply_args(&world, &journal),
            &[],
            &world.env(),
            &case.join("pause.sentinel"),
            "planned",
        );
        let planned = journal_json(&journal);
        assert_eq!(planned["planned"][0]["action"]["kind"], "replace");
        assert_eq!(
            planned["planned"][0]["action"]["conversation_id"],
            serde_json::json!(1)
        );
        assert_eq!(planned["planned"][0]["source_binding"], serde_json::Value::Null);
        let report = apply_result(&run_cli(
            &case,
            "recover",
            &recover_args(&journal),
            &[],
            &world.env(),
        ));
        assert_eq!(report["replaced"].as_u64(), Some(1));

        // Exact literal messages from the descriptor.
        let expected_messages: Vec<String> = descriptor["new_messages"]
            .as_array()
            .expect("new_messages")
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect();
        let actual_messages: Vec<String> = sql_rows(
            &world.db,
            "SELECT content FROM messages WHERE conversation_id = 1 ORDER BY idx",
        )
        .iter()
        .map(|row| row[0]["value"].as_str().unwrap().to_string())
        .collect();
        assert_eq!(actual_messages, expected_messages, "{id}: exact literal messages");
        assert_eq!(
            count(&world.db, "SELECT COUNT(*) FROM conversations"),
            1
        );
        for table in ["source_inputs", "source_records", "source_message_links"] {
            assert_eq!(
                count(&world.db, &format!("SELECT COUNT(*) FROM {table}")),
                0,
                "{id}: {table} stays empty"
            );
        }
        let key = scalar_text(
            &world.db,
            "SELECT idempotency_key FROM operation_commit_receipt \
             WHERE operation = 'mirror-restore-replace'",
        );
        assert!(
            key.starts_with("mirror-restore-replace:v2:"),
            "{id}: the original legacy key shape"
        );
        assert_eq!(
            count(
                &world.db,
                "SELECT COUNT(*) FROM operation_commit_receipt \
                 WHERE operation = 'mirror-restore-replace' AND detail IS NULL",
            ),
            1,
            "{id}: the legacy receipt keeps its detail NULL"
        );
        assert_eq!(generation(&world.db), GENERATION);
        // The second recover is a no-op with byte-identical DB.
        let before = db_sha(&world.db);
        let again = apply_result(&run_cli(
            &case,
            "recover-again",
            &recover_args(&journal),
            &[],
            &world.env(),
        ));
        assert_eq!(again["already_committed"].as_u64(), Some(1));
        assert_eq!(db_sha(&world.db), before, "{id}: idempotent recover");
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
    {
        let test = "r16_07_admission_delete_legacy";
        let id = "no-old-source-links";
        let case = CaseDir::new(test, id);
        let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
        sqlite_exec(&world.db, "DELETE FROM source_inputs");
        let revision_before = revision(&world.db);
        let journal = world.journal();
        let report = apply_result(&run_cli(
            &case,
            "apply",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
        ));
        assert_eq!(report["replaced"].as_u64(), Some(1));
        assert_eq!(
            count(
                &world.db,
                "SELECT COUNT(*) FROM source_message_links WHERE authority = 'historical'",
            ),
            0,
            "{id}: there were no old canonical links to historyize"
        );
        assert_eq!(
            revision(&world.db),
            (revision_before.parse::<u64>().unwrap() + 1).to_string()
        );
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r16_08 · qualification
// ---------------------------------------------------------------------------

fn new_input_blob(world: &World, journal: &Path) -> PathBuf {
    let view = coding_agent_search::raw_mirror::manifest_views(&world.data)
        .expect("read the mirror views")
        .into_iter()
        .find(|view| {
            view.manifest_id
                == journal_json(journal)["planned"][0]["manifest_id"]
                    .as_str()
                    .unwrap()
        })
        .expect("the planned manifest");
    world
        .data
        .join("raw-mirror/v1")
        .join(&view.blob_relative_path)
}

#[test]
fn r16_08_qualify() {
    {
        let test = "r16_08_qualify";
        let id = "default-readonly-full-c3";
        let case = CaseDir::new(test, id);
        let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
        let journal = world.journal();
        apply_result(&run_cli(
            &case,
            "apply",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
        ));
        refresh_marker_identity(&world, &journal);
        let before = db_sha(&world.db);
        for (label, deep) in [("qualify", false), ("qualify-deep", true)] {
            let result = run_cli(
                &case,
                label,
                &qualify_args(&world, &journal, deep),
                &[],
                &world.env(),
            );
            assert_eq!(
                result.rc,
                Some(0),
                "{id}: {label}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        assert_eq!(db_sha(&world.db), before, "{id}: qualify writes nothing");
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
    {
        let test = "r16_08_qualify";
        let id = "equal-size-source-blob-tamper";
        let case = CaseDir::new(test, id);
        let (world, _) = World::chain(&[codex_v0(), codex_v1()]);
        let journal = world.journal();
        apply_result(&run_cli(
            &case,
            "apply",
            &apply_args(&world, &journal),
            &[],
            &world.env(),
        ));
        let blob = new_input_blob(&world, &journal);
        let mut bytes = std::fs::read(&blob).expect("read the sealed blob");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&blob, &bytes).expect("write the same-length tampered blob");
        refresh_marker_identity(&world, &journal);
        // Each mode keeps its existing layer: normal reaches the source
        // material check, deep hits the earlier mirror blob checksum layer.
        for (label, deep, expected) in [
            ("qualify", false, "source_restore_material_mismatch"),
            ("qualify-deep", true, "mirror_restore_not_qualified"),
        ] {
            let result = run_cli(
                &case,
                label,
                &qualify_args(&world, &journal, deep),
                &[],
                &world.env(),
            );
            assert_eq!(result.rc, Some(1), "{id}: {label} must read the real bytes");
            assert_kind(&result, expected);
            if deep {
                assert!(
                    String::from_utf8_lossy(&result.stderr)
                        .contains("E-MIRROR-BLOB-CHECKSUM-MISMATCH"),
                    "{id}: the deep refusal keeps the real blob checksum clue"
                );
            }
        }
        case.pass();
        eprintln!("R16_CASE test={test} case={id} result=pass");
    }
}
