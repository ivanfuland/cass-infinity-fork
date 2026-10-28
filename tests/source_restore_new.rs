//! Task15 · source New restore integration tests.
//!
//! Every case drives the real `cass` binary against a real sealed raw-mirror
//! and a real SQLite candidate database. Each case writes its own evidence tree
//! under `CASS_T15_RESULT_ROOT`: payload literal, independent expected material,
//! argv/cwd/PID/PGID/starttime/wait rc, stdout, stderr, journal bytes, DB and
//! mirror digests, and a final PASS marker.
//!
//! The independent expected values are computed here from the fixed declaration,
//! literal sealed bytes and the published canonical formulas. Candidate output
//! is never used to construct an expectation.

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

const FAD_PIN: &str = "61f975f3b56f8dabc4ecbe1dae4102c1ea6b16e5";
const MAPPING_DOMAIN: &str = "cass-source-mapping/3";
const EXCLUSION_EPOCH: &str = "cass-source-exclusion/2";
const NORMALIZER_DOMAIN: &str = "cass.source-normalizer/1";
const SAFETY_CONTRACT: &str = "cass.source-safety/1";
const REDACTION_FINGERPRINT: &str =
    "redact-v1:fe8bda3a83e4f2f4fe85f0de5c84428140bfa658b7865706c43877488ec2bb47";
const CODE_VERSION: &str = "cass-source-exclusion/2+redact-v1:fe8bda3a83e4f2f4fe85f0de5c84428140bfa658b7865706c43877488ec2bb47";
const FIXED_SAFETY: &str = "memory_files = []\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n";
const ID_GUARD_FIXED: &str = "memory_files = [\"USER.md\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = [\"exec\"]\n";
const CONTEXT_SCHEMA: &str = "cass.restore-source-contexts/1";

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

fn assets_root() -> PathBuf {
    PathBuf::from(
        dotenvy::var("CASS_T15_INPUT_ROOT")
            .expect("CASS_T15_INPUT_ROOT must point at the frozen assets"),
    )
}

fn result_root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = dotenvy::var("CASS_T15_RESULT_ROOT")
            .expect("CASS_T15_RESULT_ROOT must be set for every Task15 run");
        let path = PathBuf::from(root);
        assert!(
            !path.exists(),
            "CASS_T15_RESULT_ROOT must not exist before the first run: {}",
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
    fn new(root: &Path, test: &str, case: &str) -> Self {
        let path = root.join(test).join(case);
        assert!(
            !path.exists(),
            "case evidence directory already exists (refusing to overwrite): {}",
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
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn proc_starttime(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let close = stat.rfind(')')?;
    let rest = &stat[close + 2..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
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
    // M1: the three phases compile the same test source with a compile-time
    // immutable CLI copy, so the ELF cannot drift to a later target binary.
    // Ordinary builds leave this unset and use cargo's own binding.
    if let Some(path) = option_env!("CASS_T15_TEST_CLI") {
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
    cwd: &'a Path,
}

fn baseline_cli() -> PathBuf {
    PathBuf::from(
        dotenvy::var("CASS_GUARD_BASELINE_CLI")
            .expect("CASS_GUARD_BASELINE_CLI must be set for every ID/body guard run"),
    )
}

fn spawn_cli(
    label: &str,
    args: &[String],
    envs: &[(&str, &str)],
    env: &ChildEnv<'_>,
) -> (Child, serde_json::Value) {
    spawn_cli_binary(&cli_binary(), label, args, envs, env)
}

fn spawn_cli_binary(
    binary: &Path,
    label: &str,
    args: &[String],
    envs: &[(&str, &str)],
    env: &ChildEnv<'_>,
) -> (Child, serde_json::Value) {
    use std::os::unix::process::CommandExt as _;

    let mut command = Command::new(binary);
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
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
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
        "env_keys": envs.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
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
    assert!(
        handshaken,
        "{label}: the child never reached the planned pause point"
    );
    child.kill().expect("SIGKILL the recorded planned child");
    let result = finish_child(child, meta);
    case.write(&format!("{label}.stdout"), &result.stdout);
    case.write(&format!("{label}.stderr"), &result.stderr);
    case.write_json(&format!("{label}.meta.json"), &result.meta);
    result
}

fn run_baseline_cli(
    case: &CaseDir,
    label: &str,
    args: &[String],
    envs: &[(&str, &str)],
    env: &ChildEnv<'_>,
) -> RunResult {
    let (child, meta) = spawn_cli_binary(&baseline_cli(), label, args, envs, env);
    let result = finish_child(child, meta);
    case.write(&format!("{label}.stdout"), &result.stdout);
    case.write(&format!("{label}.stderr"), &result.stderr);
    case.write_json(&format!("{label}.meta.json"), &result.meta);
    result
}

fn run_baseline_paused_at(
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
    let (mut child, meta) = spawn_cli_binary(&baseline_cli(), label, args, &all_envs, env);
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
    assert!(
        handshaken,
        "{label}: the baseline child never reached the planned pause point"
    );
    child.kill().expect("SIGKILL the recorded baseline child");
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
    panic!(
        "the CLI did not print a JSON error envelope on stderr: {}",
        text
    )
}

fn assert_kind(result: &RunResult, expected: &str) {
    let payload = error_json(result);
    let kind = payload
        .pointer("/error/kind")
        .and_then(|value| value.as_str())
        .unwrap_or_else(|| panic!("no error.kind in {payload}"));
    assert_eq!(kind, expected, "unexpected CLI error kind: {payload}");
}

// ---------------------------------------------------------------------------
// Literal payloads (task-14-fixtures-v3, unchanged original bytes)
// ---------------------------------------------------------------------------

struct Payload {
    bytes: &'static [u8],
    sha: &'static str,
}

fn payload(name: &str) -> &'static Payload {
    macro_rules! payload {
        ($bytes:expr, $sha:expr) => {{
            &Payload {
                bytes: $bytes,
                sha: $sha,
            }
        }};
    }
    match name {
        "claude_one" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
"#,
            "6f202da269cbdc40d7ac4b7fc204cf3a119b09e39b6e034face1bf5316686639"
        ),
        "claude_different_one" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C14 different message"}}
"#,
            "2b2f81fc6f265e01c029dbaf86f6398170d66f246015c5f8a6a9098625ce9d79"
        ),
        "claude_document" => payload!(
            br#"{
  "cwd": "/synthetic/c44-project",
  "sessionId": "C44-CLAUDE",
  "version": "2.0.37",
  "messages": [
    {
      "role": "user",
      "content": "C44 question",
      "timestamp": "2026-01-01T00:00:00.000Z"
    },
    {
      "role": "assistant",
      "content": [
        {
          "type": "text",
          "text": "C44 answer"
        }
      ],
      "timestamp": "2026-01-01T00:00:01.000Z"
    }
  ]
}
"#,
            "2fdf8eb31971bfa0603cb64dd6d8f4305c0463504e5447266df72411bb0a2118"
        ),
        "codex_jsonl" => payload!(
            br#"{"timestamp":"2026-01-01T00:00:00.000Z","type":"session_meta","payload":{"id":"C44-CODEX","cwd":"/synthetic/c44-project","cli_version":"0.42.0"}}
{"timestamp":"2026-01-01T00:00:01.000Z","type":"response_item","payload":{"type":"message","id":"C44-U","role":"user","content":[{"type":"input_text","text":"C44 question"}]}}
{"timestamp":"2026-01-01T00:00:02.000Z","type":"response_item","payload":{"type":"message","id":"C44-A","role":"assistant","content":[{"type":"output_text","text":"C44 answer"}]}}
"#,
            "d50dd595f1a3a3111fffc9bdb0eff1059826071ab4164a6fc878b284b7fad3c6"
        ),
        "codex_document" => payload!(
            br#"{
  "session": {
    "id": "C44-CODEX",
    "cwd": "/synthetic/c44-project",
    "cli_version": "0.42.0"
  },
  "items": [
    {
      "type": "message",
      "role": "user",
      "content": [
        {
          "type": "input_text",
          "text": "C44 question"
        }
      ],
      "timestamp": "2026-01-01T00:00:00.000Z"
    },
    {
      "type": "message",
      "role": "assistant",
      "content": [
        {
          "type": "output_text",
          "text": "C44 answer"
        }
      ],
      "timestamp": "2026-01-01T00:00:01.000Z"
    }
  ]
}
"#,
            "b1f4f4c63f2a33b69c518c6fcab467b2d627e8df2843a7c2774f080177a01eec"
        ),
        "claude_empty_document" => payload!(
            b"{\"cwd\":\"/synthetic/c15\",\"sessionId\":\"C15_EMPTY\",\"version\":\"2.0.37\",\"messages\":[]}\n",
            "86d467510e07848f5f27049287e08ad6bc21892aac4d0cc581e3a868b136b0c2"
        ),
        "claude_array_document" => payload!(
            b"[]\n",
            "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"
        ),
        "claude_object_document" => payload!(
            b"{}\n",
            "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356"
        ),
        "codex_empty_document" => payload!(
            b"{\"session\":{\"id\":\"C15_EMPTY\",\"cwd\":\"/synthetic/c15\",\"cli_version\":\"0.42.0\"},\"items\":[]}\n",
            "a268a9f0173d5666685c84ca618e10d342a2b9addd08fd82cfa685a1b79a097b"
        ),
        "claude_empty_jsonl" => payload!(
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ),
        "claude_blank_jsonl" => payload!(
            b"\n \t\n",
            "499874d2d7401738884f105a329bd7f7a1919826deeff536eedfc90db95d3b35"
        ),
        "id_guard_control" => payload!(
            br#"{"type":"assistant","uuid":"G-A","sessionId":"G-S","cwd":"/synthetic/guard","timestamp":"2026-01-01T00:00:01Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"G-DISTINCT","name":"mcp__ccw-control-plane__project_read","input":{"document":"exec"}}]}}
{"type":"user","uuid":"G-U","sessionId":"G-S","cwd":"/synthetic/guard","timestamp":"2026-01-01T00:00:02Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"G-DISTINCT","content":"ID-GUARD-RESTORE-BODY"}]}}
"#,
            "f8d39ae4313a4e7ffc9044a682c7d8878f271c88fefef71b475907fb1d557926"
        ),
        "id_guard_collision" => payload!(
            br#"{"type":"assistant","uuid":"G-A","sessionId":"G-S","cwd":"/synthetic/guard","timestamp":"2026-01-01T00:00:01Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"ID-GUARD-RESTORE-BODY","name":"mcp__ccw-control-plane__project_read","input":{"document":"exec"}}]}}
{"type":"user","uuid":"G-U","sessionId":"G-S","cwd":"/synthetic/guard","timestamp":"2026-01-01T00:00:02Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"ID-GUARD-RESTORE-BODY","content":"ID-GUARD-RESTORE-BODY"}]}}
"#,
            "d6d4d24b46460c15055809e774a039ad5aa933ae91f43c7d5a14ef09e1e4d5dc"
        ),
        other => panic!("unknown literal payload {other}"),
    }
}

// ---------------------------------------------------------------------------
// Canonical formulas (independent of the candidate implementation)
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    out.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn json_string(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn canonical_tuple(items: &[Option<&str>]) -> String {
    let mut out = String::from("[");
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        match item {
            Some(value) => out.push_str(&json_string(value)),
            None => out.push_str("null"),
        }
    }
    out.push(']');
    out
}

fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(number) => number.to_string(),
        serde_json::Value::String(text) => json_string(text),
        serde_json::Value::Array(items) => {
            let mut out = String::from("[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&canonical_json(item));
            }
            out.push(']');
            out
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&json_string(key));
                out.push(':');
                out.push_str(&canonical_json(&map[*key]));
            }
            out.push('}');
            out
        }
    }
}

fn sha256_canonical(value: &serde_json::Value) -> String {
    sha256_hex(canonical_json(value).as_bytes())
}

fn four_arrays_digest() -> String {
    sha256_hex(
        br#"{"injection_only_files":[],"memory_files":[],"project_read_documents":[],"workspace_scoped_files":[]}"#,
    )
}

// ---------------------------------------------------------------------------
// World / fixture
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Spec {
    provider: &'static str,
    source_id: &'static str,
    origin_kind: &'static str,
    origin_host: Option<&'static str>,
    connector: &'static str,
    logical: &'static str,
    payload_name: &'static str,
}

fn native_spec(payload_name: &'static str) -> Spec {
    let (provider, connector, logical) = match payload_name {
        "codex_jsonl" => (
            "codex",
            "codex",
            ".codex/sessions/2026/08/rollout-c29.jsonl",
        ),
        "codex_document" | "codex_empty_document" => {
            ("codex", "codex", ".codex/sessions/2026/08/rollout-c29.json")
        }
        "id_guard_control" | "id_guard_collision" => (
            "claude",
            "claude_code",
            ".claude/projects/C29-ws/C29-session.jsonl",
        ),
        "claude_document"
        | "claude_empty_document"
        | "claude_array_document"
        | "claude_object_document" => (
            "claude",
            "claude_code",
            ".claude/projects/C29-ws/session.json",
        ),
        _ => (
            "claude",
            "claude_code",
            ".claude/projects/C29-ws/C29-session.jsonl",
        ),
    };
    Spec {
        provider,
        source_id: "local",
        origin_kind: "local",
        origin_host: None,
        connector,
        logical,
        payload_name,
    }
}

fn unique_mtime() -> std::time::SystemTime {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let sequence = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + sequence)
}

fn write_source(path: &Path, bytes: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("source parent"))
        .expect("create the source parent");
    std::fs::write(path, bytes).expect("write the live source");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open the live source");
    file.set_modified(unique_mtime())
        .expect("set a unique source mtime");
}

struct Source {
    capture: RawMirrorCaptureRecord,
    live_path: PathBuf,
    declaration: serde_json::Value,
}

struct World {
    tmp: TempDir,
    home: PathBuf,
    xdg_config: PathBuf,
    xdg_data: PathBuf,
    xdg_cache: PathBuf,
    cwd: PathBuf,
    data_dir: PathBuf,
    scratch: PathBuf,
    db: PathBuf,
    fixed: PathBuf,
}

impl World {
    fn new() -> Self {
        let tmp = TempDir::new().expect("create the world tempdir");
        let home = tmp.path().join("home");
        let xdg_config = tmp.path().join("xdg-config");
        let xdg_data = tmp.path().join("xdg-data");
        let xdg_cache = tmp.path().join("xdg-cache");
        let cwd = tmp.path().join("cwd");
        let data_dir = tmp.path().join("cass-data");
        let scratch = tmp.path().join("scratch");
        for path in [
            &home,
            &xdg_config,
            &xdg_data,
            &xdg_cache,
            &cwd,
            &data_dir,
            &scratch,
        ] {
            std::fs::create_dir_all(path).expect("create a world directory");
        }
        std::fs::write(cwd.join(".env"), b"").expect("write the empty cwd .env");
        let fixed = tmp.path().join("fixed-safety.toml");
        std::fs::write(&fixed, FIXED_SAFETY).expect("write the fixed safety copy");
        let db = tmp.path().join("candidate.sqlite");
        {
            let mut storage = FrankenStorage::open(&db).expect("create the candidate database");
            storage.close_best_effort_in_place();
        }
        Self {
            tmp,
            home,
            xdg_config,
            xdg_data,
            xdg_cache,
            cwd,
            data_dir,
            scratch,
            db,
            fixed,
        }
    }

    fn env(&self) -> ChildEnv<'_> {
        ChildEnv {
            home: &self.home,
            xdg_config: &self.xdg_config,
            xdg_data: &self.xdg_data,
            xdg_cache: &self.xdg_cache,
            cwd: &self.cwd,
        }
    }

    fn source(&self, spec: Spec) -> Source {
        let live_path = self.home.join(spec.logical);
        write_source(&live_path, payload(spec.payload_name).bytes);
        let capture = capture_source_file_with_identity(
            RawMirrorCaptureInput {
                data_dir: &self.data_dir,
                provider: spec.provider,
                source_id: spec.source_id,
                origin_kind: spec.origin_kind,
                origin_host: spec.origin_host,
                source_path: &live_path,
                db_links: &[],
            },
            RawMirrorSessionIdentity {
                identity_host: RAW_MIRROR_LOCAL_IDENTITY_HOST,
                external_id: None,
            },
        )
        .expect("capture the fixture into the raw mirror");
        let declaration = declaration_for(&spec, &capture, &live_path);
        Source {
            capture,
            live_path,
            declaration,
        }
    }

    fn write_contexts(&self, sources: &[&Source]) -> (PathBuf, serde_json::Value) {
        let inputs: Vec<serde_json::Value> = sources
            .iter()
            .map(|source| source.declaration.clone())
            .collect();
        self.write_contexts_inputs(inputs)
    }

    fn write_contexts_inputs(
        &self,
        inputs: Vec<serde_json::Value>,
    ) -> (PathBuf, serde_json::Value) {
        let mut inputs = inputs;
        inputs.sort_by(|left, right| {
            left["manifest_id"]
                .as_str()
                .unwrap()
                .as_bytes()
                .cmp(right["manifest_id"].as_str().unwrap().as_bytes())
        });
        let value = serde_json::json!({ "schema": CONTEXT_SCHEMA, "inputs": inputs });
        let path = self.tmp.path().join("contexts.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap())
            .expect("write the contexts file");
        (path, value)
    }

    fn views(&self) -> Vec<coding_agent_search::raw_mirror::RawMirrorManifestView> {
        coding_agent_search::raw_mirror::manifest_views(&self.data_dir)
            .expect("read the manifest views")
    }

    /// Point the candidate at the ordinary index's own database path, so the
    /// ordinary ingest and the restore share one database.
    fn use_index_db(&mut self) {
        self.db = self.data_dir.join("agent_search.db");
        let mut storage =
            FrankenStorage::open(&self.db).expect("create the shared candidate database");
        storage.close_best_effort_in_place();
    }
}

fn declaration_for(
    spec: &Spec,
    capture: &RawMirrorCaptureRecord,
    live_path: &Path,
) -> serde_json::Value {
    let parent = live_path.parent().expect("live parent");
    let name = live_path.file_name().expect("live name");
    serde_json::json!({
        "manifest_id": capture.manifest_id,
        "identity_namespace": "C29_NAMESPACE",
        "connector": spec.connector,
        "scan_root": parent.to_string_lossy(),
        "relative_locator": name.to_string_lossy(),
        "role": "primary_session_log",
        "origin": {
            "source_id": spec.source_id,
            "kind": spec.origin_kind,
            "host": spec.origin_host,
            "source_version": null,
        },
        "platform": null,
        "workspace_rewrites": [],
    })
}

// ---------------------------------------------------------------------------
// Independent expected material
// ---------------------------------------------------------------------------

fn expected_profile(world: &World, explicit_identity: bool) -> serde_json::Value {
    let fixed_path = &world.fixed;
    let (fixed_bytes, published_path) = if explicit_identity {
        (
            std::fs::read(fixed_path).expect("read the fixed safety copy"),
            std::path::absolute(fixed_path)
                .expect("absolute fixed path")
                .to_string_lossy()
                .into_owned(),
        )
    } else {
        let effective = coding_agent_search::sources::config::ExcludedContextPaths {
            memory_files: Vec::new(),
            injection_only_files: Vec::new(),
            workspace_scoped_files: Vec::new(),
            project_read_documents: Vec::new(),
        };
        let bytes = toml::to_string(&effective)
            .expect("serialise the effective rule set")
            .into_bytes();
        let digest = sha256_hex(&bytes);
        let path = world
            .data_dir
            .join("source-configs")
            .join("v1")
            .join(format!("{digest}.toml"));
        (bytes, path.to_string_lossy().into_owned())
    };
    let fixed_sha = sha256_hex(&fixed_bytes);
    let identity = if explicit_identity {
        published_path.clone()
    } else {
        format!("cass.source-config/1:sha256:{fixed_sha}")
    };
    serde_json::json!({
        "config_source_identity": identity,
        "fixed_copy_path": published_path,
        "fixed_config_sha256": fixed_sha,
        "effective_four_arrays_sha256": four_arrays_digest(),
        "code_version": CODE_VERSION,
        "fad_pin": FAD_PIN,
        "mapping_domain": MAPPING_DOMAIN,
        "exclusion_epoch": EXCLUSION_EPOCH,
        "redaction_fingerprint": REDACTION_FINGERPRINT,
        "desensitization_enabled": true,
    })
}

fn effective_config_material(declaration: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema": "cass.source-parser-context/1",
        "connector": declaration["connector"],
        "roots": [{
            "path": declaration["scan_root"],
            "origin": {
                "kind": declaration["origin"]["kind"],
                "host": declaration["origin"]["host"],
                "source_version": declaration["origin"]["source_version"],
            },
            "platform": declaration["platform"],
            "workspace_rewrites": declaration["workspace_rewrites"],
        }],
        "role": declaration["role"],
    })
}

fn parser_context_wire(
    declaration: &serde_json::Value,
    effective_digest: &str,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "cass.source-parser-context/1",
        "connector": declaration["connector"],
        "discovery_roots": [declaration["scan_root"]],
        "since_ts": null,
        "relative_locator": declaration["relative_locator"],
        "role": declaration["role"],
        "origin": {
            "kind": declaration["origin"]["kind"],
            "host": declaration["origin"]["host"],
            "source_version": declaration["origin"]["source_version"],
        },
        "platform": declaration["platform"],
        "workspace_rewrites": declaration["workspace_rewrites"],
        "effective_config_summary": { "effective_digest": effective_digest },
    })
}

fn expected_binding(declaration: &serde_json::Value, payload: &Payload) -> serde_json::Value {
    let effective = effective_config_material(declaration);
    let effective_digest = sha256_canonical(&effective);
    let normalizer_id = sha256_canonical(&serde_json::json!([
        NORMALIZER_DOMAIN,
        FAD_PIN,
        MAPPING_DOMAIN,
        effective_digest,
    ]));
    let safety_contract_id = safety_contract("C29_CONFIG_IDENTITY");
    let context_wire = parser_context_wire(declaration, &effective_digest);
    let context_digest = sha256_canonical(&context_wire);
    let tuple = [
        Some("cass.source-input/2"),
        Some(declaration["identity_namespace"].as_str().unwrap()),
        Some(declaration["origin"]["source_id"].as_str().unwrap()),
        Some(declaration["connector"].as_str().unwrap()),
        Some(declaration["scan_root"].as_str().unwrap()),
        Some(declaration["relative_locator"].as_str().unwrap()),
        Some(declaration["role"].as_str().unwrap()),
        Some(declaration["origin"]["kind"].as_str().unwrap()),
        declaration["origin"]["host"].as_str(),
        declaration["origin"]["source_version"].as_str(),
        declaration["platform"].as_str(),
        Some(context_digest.as_str()),
        Some(payload.sha),
        Some(normalizer_id.as_str()),
        Some(safety_contract_id.as_str()),
    ];
    serde_json::json!({
        "declaration": declaration,
        "context_digest": context_digest,
        "sealed_sha256": payload.sha,
        "byte_len": payload.bytes.len(),
        "normalizer_id": normalizer_id,
        "safety_contract_id": safety_contract_id,
        "input_key": sha256_hex(canonical_tuple(&tuple).as_bytes()),
    })
}

fn safety_contract(config_identity: &str) -> String {
    sha256_canonical(&serde_json::json!([
        SAFETY_CONTRACT,
        EXCLUSION_EPOCH,
        REDACTION_FINGERPRINT,
        config_identity,
        sha256_hex(FIXED_SAFETY.as_bytes()),
        four_arrays_digest(),
        true,
    ]))
}

fn expected_binding_with_identity(
    declaration: &serde_json::Value,
    payload: &Payload,
    profile: &serde_json::Value,
) -> serde_json::Value {
    let mut binding = expected_binding(declaration, payload);
    let identity = profile["config_source_identity"].as_str().unwrap();
    let safety = safety_contract(identity);
    let normalizer = binding["normalizer_id"].as_str().unwrap().to_string();
    let context_digest = binding["context_digest"].as_str().unwrap().to_string();
    let tuple = [
        Some("cass.source-input/2"),
        Some(declaration["identity_namespace"].as_str().unwrap()),
        Some(declaration["origin"]["source_id"].as_str().unwrap()),
        Some(declaration["connector"].as_str().unwrap()),
        Some(declaration["scan_root"].as_str().unwrap()),
        Some(declaration["relative_locator"].as_str().unwrap()),
        Some(declaration["role"].as_str().unwrap()),
        Some(declaration["origin"]["kind"].as_str().unwrap()),
        declaration["origin"]["host"].as_str(),
        declaration["origin"]["source_version"].as_str(),
        declaration["platform"].as_str(),
        Some(context_digest.as_str()),
        Some(payload.sha),
        Some(normalizer.as_str()),
        Some(safety.as_str()),
    ];
    binding["safety_contract_id"] = serde_json::json!(safety);
    binding["input_key"] = serde_json::json!(sha256_hex(canonical_tuple(&tuple).as_bytes()));
    binding
}

// ---------------------------------------------------------------------------
// CLI argument builders and digests
// ---------------------------------------------------------------------------

fn plan_args(
    world: &World,
    contexts: &Path,
    safety: Option<&Path>,
    out: Option<&Path>,
) -> Vec<String> {
    let mut args = vec![
        "mirror-restore".to_string(),
        "--data-dir".to_string(),
        world.data_dir.to_string_lossy().into_owned(),
        "--candidate-db".to_string(),
        world.db.to_string_lossy().into_owned(),
        "--scratch".to_string(),
        world.scratch.to_string_lossy().into_owned(),
        "--snapshot-root".to_string(),
        "c29-snapshot-root".to_string(),
        "--json".to_string(),
        "--source-contexts".to_string(),
        contexts.to_string_lossy().into_owned(),
    ];
    if let Some(safety) = safety {
        args.push("--source-safety-config".into());
        args.push(safety.to_string_lossy().into_owned());
    }
    if let Some(out) = out {
        args.push("--out".into());
        args.push(out.to_string_lossy().into_owned());
    }
    args
}

fn apply_args(
    world: &World,
    contexts: &Path,
    safety: Option<&Path>,
    journal: &Path,
) -> Vec<String> {
    let mut args = plan_args(world, contexts, safety, None);
    args.push("--apply".into());
    args.push("--journal".into());
    args.push(journal.to_string_lossy().into_owned());
    args.push("--generation".into());
    args.push("c29-generation".into());
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

fn db_digest(path: &Path) -> Option<String> {
    std::fs::read(path).ok().map(|bytes| sha256_hex(&bytes))
}

fn mirror_digest(data_dir: &Path) -> String {
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
                let bytes = std::fs::read(&path).expect("read the mirror file");
                out.push((
                    path.strip_prefix(base)
                        .expect("inside the mirror")
                        .to_string_lossy()
                        .into_owned(),
                    sha256_hex(&bytes),
                ));
            }
        }
    }
    let root = data_dir.join("raw-mirror");
    let mut out = Vec::new();
    if root.exists() {
        walk(&root, &root, &mut out);
    }
    out.sort();
    out.into_iter()
        .map(|(path, digest)| format!("{path}={digest}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn journal_json(journal: &Path) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(journal).expect("read the journal"))
        .expect("decode the journal")
}

fn assert_journal_materials(
    journal: &serde_json::Value,
    contexts_value: &serde_json::Value,
    profile: &serde_json::Value,
) {
    assert_eq!(journal["schema_version"], 4, "journal4 version");
    assert_eq!(
        journal["source_contexts"], *contexts_value,
        "source_contexts must be the actual declarations"
    );
    assert_eq!(
        journal["source_contexts_digest"],
        serde_json::json!(sha256_canonical(contexts_value)),
        "the aggregate digest must be recomputed from the material"
    );
    assert_eq!(
        journal["source_profile"], *profile,
        "source_profile mismatch"
    );
}

fn write_default_safety(world: &World, poisoned: bool) {
    let dir = world.xdg_config.join("cass");
    std::fs::create_dir_all(&dir).expect("create the config tier");
    let body = if poisoned {
        "memory_files = [\"C29_UNMATCHED_RULE.md\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n"
    } else {
        FIXED_SAFETY
    };
    std::fs::write(dir.join("excluded_context_paths.toml"), body)
        .expect("write the live rule file");
}

fn assert_untouched(world: &World, before_db: Option<String>, before_mirror: &str) {
    assert_eq!(
        db_digest(&world.db),
        before_db,
        "the candidate DB must not change"
    );
    assert_eq!(
        mirror_digest(&world.data_dir),
        before_mirror,
        "the raw mirror must not change"
    );
}

// ---------------------------------------------------------------------------
// Task15 · shared evidence and SQL helpers
// ---------------------------------------------------------------------------

fn case_evidence(test: &str, case: &str) -> CaseDir {
    let root = result_root();
    CaseDir::new(&root, test, case)
}

fn qualify_args(world: &World, journal: &Path) -> Vec<String> {
    vec![
        "mirror-restore".to_string(),
        "--qualify".to_string(),
        "--data-dir".to_string(),
        world.data_dir.to_string_lossy().into_owned(),
        "--candidate-db".to_string(),
        world.db.to_string_lossy().into_owned(),
        "--journal".to_string(),
        journal.to_string_lossy().into_owned(),
        "--json".to_string(),
    ]
}

fn value_json(value: &coding_agent_search::storage::api::Value) -> serde_json::Value {
    use coding_agent_search::storage::api::Value;
    match value {
        Value::Null => serde_json::Value::Null,
        Value::Integer(number) => serde_json::json!(number),
        Value::Real(number) => serde_json::json!(format!("f64bits:{:016x}", number.to_bits())),
        Value::Text(text) => serde_json::json!(text),
        Value::Blob(bytes) => {
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            serde_json::json!(format!("blob:{hex}"))
        }
    }
}

fn sql_rows(db: &Path, sql: &str) -> Vec<Vec<serde_json::Value>> {
    let mut storage = FrankenStorage::open_readonly(db).expect("open the candidate db readonly");
    let rows = storage
        .raw()
        .query_all_map(sql, &[], |row| {
            let mut values = Vec::new();
            let mut index = 0;
            while let Ok(value) = row.get_value(index) {
                values.push(value_json(&value));
                index += 1;
            }
            Ok(values)
        })
        .expect("run the snapshot query");
    storage.close_best_effort_in_place();
    rows
}

fn sql_scalar_i64(db: &Path, sql: &str) -> i64 {
    let rows = sql_rows(db, sql);
    assert_eq!(rows.len(), 1, "a scalar query must return exactly one row");
    rows[0][0].as_i64().expect("an integer scalar")
}

fn sql_scalar_text(db: &Path, sql: &str) -> String {
    let rows = sql_rows(db, sql);
    assert_eq!(rows.len(), 1, "a scalar query must return exactly one row");
    rows[0][0].as_str().expect("a text scalar").to_string()
}

fn table_count(db: &Path, table: &str) -> i64 {
    sql_scalar_i64(db, &format!("SELECT COUNT(*) FROM {table}"))
}

fn table_count_where(db: &Path, table: &str, predicate: &str) -> i64 {
    sql_scalar_i64(
        db,
        &format!("SELECT COUNT(*) FROM {table} WHERE {predicate}"),
    )
}

fn receipt_detail(db: &Path) -> serde_json::Value {
    let text = sql_scalar_text(
        db,
        "SELECT detail FROM operation_commit_receipt \
         WHERE operation = 'mirror-restore-new' AND state = 'committed'",
    );
    serde_json::from_str(&text).expect("the restore receipt detail is JSON")
}

fn assert_object_keys(value: &serde_json::Value, expected: &[&str]) {
    let object = value.as_object().expect("an object");
    let actual: std::collections::BTreeSet<&String> = object.keys().collect();
    let wanted: std::collections::BTreeSet<String> =
        expected.iter().map(|key| key.to_string()).collect();
    let wanted_refs: std::collections::BTreeSet<&String> = wanted.iter().collect();
    assert_eq!(actual, wanted_refs, "object key set mismatch");
}

// ---------------------------------------------------------------------------
// R1 · typed full-table oracle and field-level mirror snapshots
// ---------------------------------------------------------------------------

/// One SQLite value with an explicit type tag. Blob and real values can never
/// collide with a Text value.
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

fn sql_typed_rows(db: &Path, sql: &str) -> Vec<Vec<serde_json::Value>> {
    let mut storage = FrankenStorage::open_readonly(db).expect("open the candidate db readonly");
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
        .expect("run the typed snapshot query");
    storage.close_best_effort_in_place();
    rows
}

/// Every column of all nine oracle tables, in primary-key order.
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
            serde_json::json!(sql_typed_rows(
                db,
                &format!("SELECT * FROM {table} ORDER BY {key}")
            )),
        );
    }
    serde_json::Value::Object(snapshot)
}

/// The mirror's declared facts, field by field. The caller decides which
/// fields a planned publication may change.
fn mirror_views_snapshot(data_dir: &Path) -> Vec<serde_json::Value> {
    let mut views = coding_agent_search::raw_mirror::manifest_views(data_dir)
        .expect("read the mirror manifest views");
    views.sort_by(|left, right| left.manifest_id.cmp(&right.manifest_id));
    views
        .iter()
        .map(|view| {
            serde_json::json!({
                "manifest_id": view.manifest_id,
                "manifest_relative_path": view.manifest_relative_path,
                "blob_relative_path": view.blob_relative_path,
                "blob_blake3": view.blob_blake3,
                "blob_size_bytes": view.blob_size_bytes,
                "provider": view.provider,
                "source_id": view.source_id,
                "origin_kind": view.origin_kind,
                "origin_host": view.origin_host,
                "original_path": view.original_path,
                "original_path_blake3": view.original_path_blake3,
                "identity_host": view.identity_host,
                "agent": view.agent,
                "external_id": view.external_id,
                "shape_root": view.shape_root,
                "relative_path": view.relative_path,
                "captured_at_ms": view.captured_at_ms,
                "source_size_bytes": view.source_size_bytes,
                "source_mtime_ms": view.source_mtime_ms,
                "db_links": view.db_links.iter().map(|link| serde_json::json!({
                    "conversation_id": link.conversation_id,
                    "message_count": link.message_count,
                    "source_path": link.source_path,
                    "started_at_ms": link.started_at_ms,
                })).collect::<Vec<_>>(),
                "manifest_blake3": view.manifest_blake3,
            })
        })
        .collect()
}

/// The allowed publication changes: only `db_links` and the manifest's own
/// digest. Every other field of every manifest must stay equal.
fn assert_planned_mirror_only(
    before: &[serde_json::Value],
    after: &[serde_json::Value],
    planned_manifest_ids: &[String],
) {
    assert_eq!(before.len(), after.len(), "manifest count changed");
    for (before_view, after_view) in before.iter().zip(after) {
        let manifest_id = before_view["manifest_id"]
            .as_str()
            .expect("manifest id");
        let planned = planned_manifest_ids.iter().any(|id| id == manifest_id);
        let mut before_fields = before_view.as_object().unwrap().clone();
        let mut after_fields = after_view.as_object().unwrap().clone();
        if planned {
            before_fields.remove("db_links");
            before_fields.remove("manifest_blake3");
            after_fields.remove("db_links");
            after_fields.remove("manifest_blake3");
        }
        assert_eq!(
            before_fields, after_fields,
            "{manifest_id}: only a planned manifest's db_links/self-digest may change"
        );
    }
}

fn sha256_file(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("read the file for its digest");
    sha256_hex(&bytes)
}

// ---------------------------------------------------------------------------
// n15_01 · native source New through the real CLI
// ---------------------------------------------------------------------------

#[test]
fn n15_01_native_source_new() {
    let cases = [
        ("claude-jsonl", "claude_one", 1u64, 1u64, 1u64, 1u64),
        ("claude-document", "claude_document", 1, 1, 2, 2),
        ("codex-jsonl", "codex_jsonl", 3, 1, 2, 3),
        ("codex-document", "codex_document", 1, 1, 2, 2),
        ("claude-empty-document", "claude_empty_document", 1, 0, 0, 1),
        ("claude-array-document", "claude_array_document", 1, 0, 0, 1),
        ("claude-object-document", "claude_object_document", 1, 0, 0, 1),
        ("codex-empty-document", "codex_empty_document", 1, 0, 0, 1),
        ("claude-empty-jsonl", "claude_empty_jsonl", 0, 0, 0, 0),
        ("claude-blank-jsonl", "claude_blank_jsonl", 0, 0, 0, 0),
    ];

    // R1: the independent frozen literals drive every success-side expected
    // value. They are never built from candidate output.
    let literals: serde_json::Value = serde_json::from_slice(
        &std::fs::read(assets_root().join("native-literals.json"))
            .expect("read the frozen native literals"),
    )
    .expect("decode the frozen native literals");
    let literal_for = |id: &str| {
        literals["cases"]
            .as_array()
            .expect("literal cases")
            .iter()
            .find(|case| case["case"] == id)
            .expect("a frozen literal for every native case")
    };

    for (id, payload_name, records, conversations, messages, links) in cases {
        let case = case_evidence("n15_01_native_source_new", id);
        let world = World::new();
        let source = world.source(native_spec(payload_name));
        let (contexts, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, true);
        let journal = world.tmp.path().join("journal.json");

        let literal = literal_for(id);
        assert_eq!(
            payload(payload_name).bytes,
            literal["literal"]
                .as_str()
                .expect("literal string")
                .as_bytes(),
            "{id}: the input bytes must be the frozen literal"
        );
        assert_eq!(
            payload(payload_name).sha,
            literal["sha256"].as_str().expect("literal sha"),
            "{id}: the literal SHA"
        );
        let before_db = typed_snapshot(&world.db);
        let before_mirror = mirror_views_snapshot(&world.data_dir);
        let before_source = sha256_file(&source.live_path);

        let args = apply_args(&world, &contexts, Some(&world.fixed), &journal);
        let result = run_cli(&case, "apply", &args, &[], &world.env());
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: apply failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("apply JSON output");
        assert_eq!(report["applied"], serde_json::json!(true), "{id}");
        assert_eq!(
            report["restored"],
            serde_json::json!(conversations),
            "{id}: restored"
        );
        assert_eq!(
            report["messages_inserted"],
            serde_json::json!(messages),
            "{id}: messages_inserted"
        );
        if conversations == 0 {
            assert_eq!(
                report["source_only_completed"],
                serde_json::json!(1),
                "{id}: source_only_completed"
            );
            assert!(
                report.get("source_replayed").is_none(),
                "{id}: a first commit is not a replay"
            );
        } else {
            assert!(
                report.get("source_only_completed").is_none(),
                "{id}: a nonzero input must not claim source-only completion"
            );
        }
        case.write_json("apply.report.json", &report);

        // Close/reopen SQL: every count is read from a fresh read-only handle.
        assert_eq!(table_count(&world.db, "source_inputs"), 1, "{id}: source_inputs");
        assert_eq!(table_count(&world.db, "source_records"), records as i64, "{id}: records");
        assert_eq!(
            table_count(&world.db, "source_message_links"),
            links as i64,
            "{id}: links"
        );
        assert_eq!(
            table_count(&world.db, "conversations"),
            conversations as i64,
            "{id}: conversations"
        );
        assert_eq!(table_count(&world.db, "messages"), messages as i64, "{id}: messages");
        if conversations == 0 {
            assert_eq!(table_count(&world.db, "agents"), 0, "{id}: no fake agent");
            assert_eq!(table_count(&world.db, "workspaces"), 0, "{id}: no fake workspace");
        }
        assert_eq!(
            table_count_where(
                &world.db,
                "source_inputs",
                "state = 'complete' OR state = 'staged'"
            ),
            1,
            "{id}: one source input row"
        );
        let source_state = sql_scalar_text(&world.db, "SELECT state FROM source_inputs");
        assert_eq!(source_state, "complete", "{id}: source state");
        assert_eq!(
            table_count_where(
                &world.db,
                "operation_commit_receipt",
                "operation = 'source_input_activation_v1' AND state = 'committed'"
            ),
            1,
            "{id}: source activation receipt"
        );
        assert_eq!(
            table_count_where(
                &world.db,
                "operation_commit_receipt",
                "operation = 'mirror-restore-new' AND state = 'committed'"
            ),
            1,
            "{id}: restore receipt"
        );
        let detail = receipt_detail(&world.db);
        assert_object_keys(
            &detail,
            &[
                "schema",
                "restore_operation",
                "restore_key",
                "snapshot_root",
                "manifest_id",
                "source_request",
                "source_receipt_key",
                "source_installation_digest",
            ],
        );
        assert_eq!(detail["schema"], serde_json::json!("cass.restore-source-receipt/1"));
        assert_object_keys(
            &detail["source_request"],
            &[
                "input_key",
                "library_identity",
                "normalizer_id",
                "safety_contract_id",
                "expected_manifest_digest",
                "finish",
                "projection_disposition",
                "source_semantic_records_root",
                "claims_root",
                "requested_terminal",
            ],
        );
        assert_eq!(detail["source_request"]["projection_disposition"], serde_json::json!("Ready"));
        assert_eq!(detail["source_request"]["requested_terminal"], serde_json::json!("Complete"));
        assert_eq!(
            detail["source_request"]["finish"].as_array().map(Vec::len),
            Some(9),
            "{id}: finish arity"
        );
        assert_eq!(
            detail["source_request"]["source_semantic_records_root"]
                .as_array()
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            detail["source_request"]["claims_root"].as_array().map(Vec::len),
            Some(2)
        );

        // R1 · independent binding, full typed snapshots and field-level mirror.
        let expected_binding =
            expected_binding_with_identity(&source.declaration, payload(payload_name), &profile);
        let journal_value = journal_json(&journal);
        assert_eq!(
            journal_value["planned"][0]["source_binding"], expected_binding,
            "{id}: the journal binding must equal the independent material"
        );
        let after_db = typed_snapshot(&world.db);
        let after_mirror = mirror_views_snapshot(&world.data_dir);
        case.write_json("db.before.json", &before_db);
        case.write_json("db.after.json", &after_db);
        case.write_json("mirror.before.json", &serde_json::json!(before_mirror));
        case.write_json("mirror.after.json", &serde_json::json!(after_mirror));
        assert_planned_mirror_only(
            &before_mirror,
            &after_mirror,
            &[source.capture.manifest_id.clone()],
        );
        assert_eq!(
            sha256_file(&source.live_path),
            before_source,
            "{id}: the original source bytes must not change"
        );

        // R3: re-read the sealed blob file itself and compare it with the
        // frozen literal, not only with the manifest's declared digest.
        let view = world
            .views()
            .into_iter()
            .find(|view| view.manifest_id == source.capture.manifest_id)
            .expect("the planned manifest view");
        let sealed_blob = world
            .data_dir
            .join("raw-mirror")
            .join("v1")
            .join(&view.blob_relative_path);
        let sealed_bytes = std::fs::read(&sealed_blob).expect("read the sealed blob");
        assert_eq!(
            sealed_bytes,
            payload(payload_name).bytes,
            "{id}: the sealed blob bytes must equal the frozen literal"
        );
        assert_eq!(
            sha256_hex(&sealed_bytes),
            payload(payload_name).sha,
            "{id}: the sealed blob SHA must equal the frozen literal"
        );

        // R3: a nonzero New must carry the real conversation backlink; a zero
        // source keeps the original None fallback and counts it.
        let (expected_backlink, expected_without_backlink) = if conversations == 0 {
            (None, 1)
        } else {
            let conversation_id = sql_scalar_i64(&world.db, "SELECT id FROM conversations");
            (Some(conversation_id), 0)
        };
        assert_eq!(
            view.db_links.first().and_then(|link| link.conversation_id),
            expected_backlink,
            "{id}: the published db_link must name the actual SQL conversation"
        );
        assert_eq!(
            report["published_without_backlink"],
            serde_json::json!(expected_without_backlink),
            "{id}: published_without_backlink"
        );

        // Independent literal message bodies and roles.
        let expected_messages: &[(&str, &str)] = match id {
            "claude-jsonl" => &[("user", "C44 question")],
            "claude-document" | "codex-jsonl" | "codex-document" => {
                &[("user", "C44 question"), ("assistant", "C44 answer")]
            }
            _ => &[],
        };
        let produced: Vec<(String, String)> =
            sql_rows(&world.db, "SELECT role, content FROM messages ORDER BY id")
                .into_iter()
                .map(|row| {
                    (
                        row[0].as_str().expect("message role").to_string(),
                        row[1].as_str().expect("message content").to_string(),
                    )
                })
                .collect();
        assert_eq!(produced.len(), expected_messages.len(), "{id}: message count");
        for (index, ((role, content), (expected_role, expected_content))) in
            produced.iter().zip(expected_messages).enumerate()
        {
            assert_eq!(role, expected_role, "{id}: message {index} role");
            assert_eq!(content, expected_content, "{id}: message {index} content");
        }

        // Source semantics and the current link witness.
        let source_row = sql_rows(
            &world.db,
            "SELECT state, format, lower(hex(expected_records)), \
             lower(hex(expected_blank_lines)) FROM source_inputs",
        );
        assert_eq!(source_row[0][0].as_str(), Some("complete"), "{id}: state");
        let expected_format =
            if source.live_path.extension().and_then(|ext| ext.to_str()) == Some("json") {
                "json_document"
            } else {
                "jsonl"
            };
        assert_eq!(
            source_row[0][1].as_str(),
            Some(expected_format),
            "{id}: format"
        );
        let records_hex: String = records
            .to_be_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            source_row[0][2].as_str(),
            Some(records_hex.as_str()),
            "{id}: expected_records"
        );
        let expected_blank_lines: u64 = if id == "claude-blank-jsonl" { 2 } else { 0 };
        let blank_hex: String = expected_blank_lines
            .to_be_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            source_row[0][3].as_str(),
            Some(blank_hex.as_str()),
            "{id}: expected_blank_lines"
        );
        let link_rows = sql_rows(
            &world.db,
            "SELECT authority, message_id FROM source_message_links ORDER BY id",
        );
        // codex-jsonl carries one standalone session_meta record plus two
        // canonical message links; the other nonzero cases are all canonical;
        // zero documents carry only a standalone record; empty/blank JSONL has
        // no links.
        let expected_standalone = if id == "codex-jsonl" {
            1
        } else if conversations == 0 {
            links
        } else {
            0
        };
        let expected_canonical = links - expected_standalone;
        let standalone = link_rows
            .iter()
            .filter(|row| row[0].as_str() == Some("standalone") && row[1].is_null())
            .count() as u64;
        let canonical = link_rows
            .iter()
            .filter(|row| row[0].as_str() == Some("canonical") && row[1].as_i64().is_some())
            .count() as u64;
        assert_eq!(standalone, expected_standalone, "{id}: standalone links");
        assert_eq!(canonical, expected_canonical, "{id}: canonical links");

        // The restore request must bind the independent binding and literal.
        let request = &detail["source_request"];
        assert_eq!(
            request["input_key"], expected_binding["input_key"],
            "{id}: request input_key"
        );
        assert_eq!(
            request["normalizer_id"], expected_binding["normalizer_id"],
            "{id}: normalizer"
        );
        assert_eq!(
            request["safety_contract_id"], expected_binding["safety_contract_id"],
            "{id}: safety"
        );
        assert_eq!(
            request["finish"][1], expected_binding["sealed_sha256"],
            "{id}: finish digest"
        );
        assert_eq!(
            request["finish"][2],
            serde_json::json!(
                expected_binding["byte_len"]
                    .as_u64()
                    .expect("the binding byte length")
                    .to_string()
            ),
            "{id}: finish bytes"
        );
        assert_eq!(
            request["finish"][3],
            serde_json::json!(records.to_string()),
            "{id}: finish records"
        );
        assert_eq!(
            request["finish"][4],
            serde_json::json!(expected_blank_lines.to_string()),
            "{id}: finish blanks"
        );
        let activation_key = sql_scalar_text(
            &world.db,
            "SELECT idempotency_key FROM operation_commit_receipt \
             WHERE operation = 'source_input_activation_v1'",
        );
        assert_eq!(
            detail["source_receipt_key"],
            serde_json::json!(activation_key),
            "{id}: the restore detail names the stored activation receipt"
        );

        assert_eq!(
            sql_scalar_text(
                &world.db,
                "SELECT value FROM meta WHERE key = 'source_content_generation'"
            ),
            "c29-generation",
            "{id}: generation"
        );

        // The journal keeps the real declarations and profile.
        let journal_value = journal_json(&journal);
        assert_journal_materials(&journal_value, &contexts_value, &profile);
        case.write_json("journal.json", &journal_value);

        // Qualify reads the real marker, journal, DB and mirror.
        let qargs = qualify_args(&world, &journal);
        let qualified = run_cli(&case, "qualify", &qargs, &[], &world.env());
        assert_eq!(
            qualified.rc,
            Some(0),
            "{id}: qualify failed: {}",
            String::from_utf8_lossy(&qualified.stderr)
        );
        let qjson: serde_json::Value =
            serde_json::from_slice(&qualified.stdout).expect("qualify JSON");
        assert_eq!(qjson["qualified"], serde_json::json!(true), "{id}");
        case.write_json("qualify.report.json", &qjson);
        case.write(
            "PASS",
            format!(
                "{id} apply=0 qualify=0 records={records} conversations={conversations} messages={messages} links={links}\n"
            )
            .as_bytes(),
        );
    }
}

// ---------------------------------------------------------------------------
// Task15 · receipt-mutation helpers
// ---------------------------------------------------------------------------

fn blake3_file(path: &Path) -> String {
    let bytes = std::fs::read(path).expect("read the file for a blake3 digest");
    blake3::hash(&bytes).to_hex().to_string()
}

fn completed_claude_document(test: &str, id: &str) -> (CaseDir, World, PathBuf) {
    let case = case_evidence(test, id);
    let world = World::new();
    let source = world.source(native_spec("claude_document"));
    let (contexts, _) = world.write_contexts(&[&source]);
    let journal = world.tmp.path().join("journal.json");
    let args = apply_args(&world, &contexts, Some(&world.fixed), &journal);
    let result = run_cli(&case, "apply", &args, &[], &world.env());
    assert_eq!(
        result.rc,
        Some(0),
        "{id}: the genuine completed source New must apply: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    (case, world, journal)
}

fn rewind_journal(journal: &Path, state: &str, committed: &[String]) {
    let mut value = journal_json(journal);
    value["state"] = serde_json::json!(state);
    value["committed"] = serde_json::json!(committed);
    value["published"] = serde_json::json!([]);
    std::fs::write(journal, serde_json::to_vec(&value).expect("encode the rewound journal"))
        .expect("write the rewound journal");
}

fn sqlite_exec(db: &Path, sql: &str, params: &[coding_agent_search::storage::api::Value]) {
    let mut storage = FrankenStorage::open(db).expect("open the candidate db for mutation");
    storage.raw().execute(sql, params).expect("apply the mutation");
    storage.close_best_effort_in_place();
}

fn mutate_detail(db: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let text = sql_scalar_text(
        db,
        "SELECT detail FROM operation_commit_receipt WHERE operation = 'mirror-restore-new'",
    );
    let mut detail: serde_json::Value = serde_json::from_str(&text).expect("detail is JSON");
    mutate(&mut detail);
    sqlite_exec(
        db,
        "UPDATE operation_commit_receipt SET detail = ?1 WHERE operation = 'mirror-restore-new'",
        &[coding_agent_search::storage::api::Value::Text(
            serde_json::to_string(&detail).expect("encode the mutated detail"),
        )],
    );
}

fn delete_restore_receipt(db: &Path) {
    sqlite_exec(
        db,
        "DELETE FROM operation_commit_receipt WHERE operation = 'mirror-restore-new'",
        &[],
    );
}

fn mutate_activation_hash(db: &Path) {
    sqlite_exec(
        db,
        "UPDATE source_inputs SET activation_request_hash = ?1",
        &[coding_agent_search::storage::api::Value::Blob(vec![0xAA; 32])],
    );
}

/// Refresh only the DB half of the marker identity after an intentional edit.
/// Used before `--recover`, which republishes the journal to its final form.
fn refresh_marker_db_identity(world: &World) {
    let marker_path = world.tmp.path().join("w1-commit-marker.json");
    let mut marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker_path).expect("read the marker"))
            .expect("decode the marker");
    marker["db_identity"]["sqlite_digest"] = serde_json::json!(blake3_file(&world.db));
    marker["db_identity"]["sqlite_size_bytes"] =
        serde_json::json!(std::fs::metadata(&world.db).expect("stat the db").len());
    std::fs::write(
        &marker_path,
        serde_json::to_vec(&marker).expect("encode the marker"),
    )
    .expect("write the marker");
}

/// Refresh both halves for `--qualify`: the journal is already in its final
/// form, so its current file digest is the one the gate will see.
fn refresh_marker_identity(world: &World, journal: &Path) {
    refresh_marker_db_identity(world);
    let marker_path = world.tmp.path().join("w1-commit-marker.json");
    let mut marker: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker_path).expect("read the marker"))
            .expect("decode the marker");
    marker["journal_digest"] = serde_json::json!(blake3_file(journal));
    std::fs::write(
        &marker_path,
        serde_json::to_vec(&marker).expect("encode the marker"),
    )
    .expect("write the marker");
}

// ---------------------------------------------------------------------------
// n15_04 · the four shared-receipt consumers
// ---------------------------------------------------------------------------

#[test]
fn n15_04_shared_receipt_consumers() {
    let mutations: [(&str, &str); 6] = [
        ("valid", "complete"),
        ("detail-null", "source_restore_replan_required"),
        ("detail-unsupported-schema", "source_restore_replan_required"),
        ("detail-restore-key-valid-other", "source_restore_receipt_conflict"),
        ("restore-row-missing", "source_restore_receipt_conflict"),
        ("source-activation-hash-valid-other", "source_restore_receipt_inconsistent"),
    ];
    let consumers = ["planned-db-skip", "post-db-account", "qualify-layer6"];
    // M1-only case selection. Unset means the full frozen 18-case default.
    let selected = dotenvy::var("CASS_T15_N15_04_CASE").ok();

    for consumer in consumers {
        for (mutation, expected) in mutations {
            let id = format!("{consumer}/{mutation}");
            if let Some(selected) = selected.as_ref()
                && &id != selected
            {
                continue;
            }
            let (case, world, journal) = completed_claude_document("n15_04_shared_receipt_consumers", &id);
            let manifest_id = journal_json(&journal)["planned"][0]["manifest_id"]
                .as_str()
                .expect("the planned manifest id")
                .to_string();

            if mutation == "detail-null" {
                sqlite_exec(
                    &world.db,
                    "UPDATE operation_commit_receipt SET detail = NULL WHERE operation = 'mirror-restore-new'",
                    &[],
                );
            } else if mutation == "detail-unsupported-schema" {
                mutate_detail(&world.db, |detail| {
                    detail["schema"] = serde_json::json!("cass.restore-source-receipt/2");
                });
            } else if mutation == "detail-restore-key-valid-other" {
                mutate_detail(&world.db, |detail| {
                    detail["restore_key"] = serde_json::json!("C15_OTHER_VALID_RESTORE_KEY");
                });
            } else if mutation == "restore-row-missing" {
                delete_restore_receipt(&world.db);
            } else if mutation == "source-activation-hash-valid-other" {
                mutate_activation_hash(&world.db);
            }

            match consumer {
                "planned-db-skip" => {
                    let committed = if mutation == "restore-row-missing" {
                        vec![manifest_id.clone()]
                    } else {
                        Vec::new()
                    };
                    // The receipt mutation changes the DB, so the marker from
                    // the first apply is stale. Remove it: the verifier, not a
                    // marker comparison, must decide this case.
                    let _ = std::fs::remove_file(
                        world.tmp.path().join("w1-commit-marker.json"),
                    );
                    rewind_journal(&journal, "planned", &committed);
                    let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
                    if expected == "complete" {
                        assert_eq!(
                            result.rc,
                            Some(0),
                            "{id}: recover must succeed: {}",
                            String::from_utf8_lossy(&result.stderr)
                        );
                        let report: serde_json::Value =
                            serde_json::from_slice(&result.stdout).expect("recover JSON");
                        assert_eq!(report["already_committed"], serde_json::json!(1), "{id}");
                    } else {
                        assert_eq!(result.rc, Some(1), "{id}: must refuse");
                        assert_kind(&result, expected);
                    }
                }
                "post-db-account" => {
                    rewind_journal(&journal, "db-committed", &[manifest_id.clone()]);
                    let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
                    if expected == "complete" {
                        assert_eq!(
                            result.rc,
                            Some(0),
                            "{id}: recover must succeed: {}",
                            String::from_utf8_lossy(&result.stderr)
                        );
                        let report: serde_json::Value =
                            serde_json::from_slice(&result.stdout).expect("recover JSON");
                        assert_eq!(report["already_committed"], serde_json::json!(1), "{id}");
                    } else {
                        assert_eq!(result.rc, Some(1), "{id}: must refuse");
                        assert_kind(&result, expected);
                    }
                }
                "qualify-layer6" => {
                    refresh_marker_identity(&world, &journal);
                    let result = run_cli(
                        &case,
                        "qualify",
                        &qualify_args(&world, &journal),
                        &[],
                        &world.env(),
                    );
                    if expected == "complete" {
                        assert_eq!(
                            result.rc,
                            Some(0),
                            "{id}: qualify must pass: {}",
                            String::from_utf8_lossy(&result.stderr)
                        );
                        let report: serde_json::Value =
                            serde_json::from_slice(&result.stdout).expect("qualify JSON");
                        assert_eq!(report["qualified"], serde_json::json!(true), "{id}");
                    } else {
                        assert_eq!(result.rc, Some(1), "{id}: must refuse");
                        assert_kind(&result, expected);
                    }
                }
                _ => unreachable!(),
            }
            case.write("PASS", format!("{id} expected={expected}\n").as_bytes());
        }
    }
}

// ---------------------------------------------------------------------------
// n15_05 · complete request binding
// ---------------------------------------------------------------------------

#[test]
fn n15_05_complete_request_binding() {
    const OTHER_HEX: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let cases: [(&str, &str); 23] = [
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
    ];

    for (id, expected) in cases {
        let (case, world, journal) =
            completed_claude_document("n15_05_complete_request_binding", id);
        match id {
            "request/input_key" => mutate_detail(&world.db, |detail| {
                detail["source_request"]["input_key"] = serde_json::json!(OTHER_HEX);
            }),
            "request/library_identity" => mutate_detail(&world.db, |detail| {
                detail["source_request"]["library_identity"] = serde_json::json!("other library");
            }),
            "request/normalizer_id" => mutate_detail(&world.db, |detail| {
                detail["source_request"]["normalizer_id"] = serde_json::json!(OTHER_HEX);
            }),
            "request/safety_contract_id" => mutate_detail(&world.db, |detail| {
                detail["source_request"]["safety_contract_id"] = serde_json::json!(OTHER_HEX);
            }),
            "request/expected_manifest_digest" => mutate_detail(&world.db, |detail| {
                detail["source_request"]["expected_manifest_digest"] =
                    serde_json::json!(OTHER_HEX);
            }),
            "request/finish" => mutate_detail(&world.db, |detail| {
                let finish = detail["source_request"]["finish"]
                    .as_array_mut()
                    .expect("finish array");
                finish[3] = serde_json::json!("2");
            }),
            "request/projection_disposition" => mutate_detail(&world.db, |detail| {
                detail["source_request"]["projection_disposition"] =
                    serde_json::json!("WholeInputRejected");
            }),
            "request/source_semantic_records_root" => mutate_detail(&world.db, |detail| {
                let root = detail["source_request"]["source_semantic_records_root"]
                    .as_array_mut()
                    .expect("root array");
                root[0] = serde_json::json!(OTHER_HEX);
            }),
            "request/claims_root" => mutate_detail(&world.db, |detail| {
                let root = detail["source_request"]["claims_root"]
                    .as_array_mut()
                    .expect("root array");
                root[0] = serde_json::json!(OTHER_HEX);
            }),
            "request/requested_terminal" => mutate_detail(&world.db, |detail| {
                detail["source_request"]["requested_terminal"] = serde_json::json!("Partial");
            }),
            "detail/restore_operation" => mutate_detail(&world.db, |detail| {
                detail["restore_operation"] = serde_json::json!("mirror-restore-replace");
            }),
            "detail/snapshot_root" => mutate_detail(&world.db, |detail| {
                detail["snapshot_root"] = serde_json::json!("other-snapshot-root");
            }),
            "detail/manifest_id" => mutate_detail(&world.db, |detail| {
                detail["manifest_id"] = serde_json::json!("other-manifest-id");
            }),
            "detail/source_receipt_key" => mutate_detail(&world.db, |detail| {
                detail["source_receipt_key"] =
                    serde_json::json!(format!("source-input-v1:{OTHER_HEX}"));
            }),
            "detail/source_installation_digest" => mutate_detail(&world.db, |detail| {
                detail["source_installation_digest"] = serde_json::json!(OTHER_HEX);
            }),
            "input-row/context_digest" => sqlite_exec(
                &world.db,
                "UPDATE source_inputs SET context_digest = ?1",
                &[coding_agent_search::storage::api::Value::Blob(vec![0x11; 32])],
            ),
            "input-row/sealed_sha256" => sqlite_exec(
                &world.db,
                "UPDATE source_inputs SET sealed_sha256 = ?1",
                &[coding_agent_search::storage::api::Value::Blob(vec![0x22; 32])],
            ),
            "input-row/byte_len" => sqlite_exec(
                &world.db,
                "UPDATE source_inputs SET byte_len = ?1",
                &[coding_agent_search::storage::api::Value::Blob(
                    999u64.to_be_bytes().to_vec(),
                )],
            ),
            "input-row/normalizer_id" => sqlite_exec(
                &world.db,
                "UPDATE source_inputs SET normalizer_id = ?1",
                &[coding_agent_search::storage::api::Value::Text(
                    OTHER_HEX.to_string(),
                )],
            ),
            "input-row/safety_contract_id" => sqlite_exec(
                &world.db,
                "UPDATE source_inputs SET safety_contract_id = ?1",
                &[coding_agent_search::storage::api::Value::Text(
                    OTHER_HEX.to_string(),
                )],
            ),
            "source-input-registration-missing" => {
                sqlite_exec(&world.db, "DELETE FROM source_message_links", &[]);
                sqlite_exec(&world.db, "DELETE FROM source_records", &[]);
                sqlite_exec(&world.db, "DELETE FROM source_inputs", &[]);
            }
            "activation-row-missing" => {
                sqlite_exec(
                    &world.db,
                    "DELETE FROM operation_commit_receipt \
                     WHERE operation = 'source_input_activation_v1'",
                    &[],
                );
            }
            "activation-detail-corrupt" => {
                sqlite_exec(
                    &world.db,
                    "UPDATE operation_commit_receipt SET detail = 'not-json' \
                     WHERE operation = 'source_input_activation_v1'",
                    &[],
                );
            }
            _ => unreachable!(),
        }

        let before_snapshot = typed_snapshot(&world.db);
        let before_mirror = mirror_views_snapshot(&world.data_dir);
        rewind_journal(&journal, "planned", &[]);
        let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(result.rc, Some(1), "{id}: the run must refuse");
        assert_kind(&result, expected);
        let after_snapshot = typed_snapshot(&world.db);
        case.write_json("db.before-reject.json", &before_snapshot);
        case.write_json("db.after-reject.json", &after_snapshot);
        assert_eq!(
            after_snapshot, before_snapshot,
            "{id}: a refused run must not change any typed row"
        );
        assert_eq!(
            mirror_views_snapshot(&world.data_dir),
            before_mirror,
            "{id}: a refused run must not advance the mirror"
        );
        case.write("PASS", format!("{id} expected={expected}\n").as_bytes());
    }

    // R1-SIDE · the two Root F0 stored-receipt counterexamples, rechecked on
    // the repaired source. These are explicit side columns: they do not
    // replace or renumber the frozen 23 rows above.
    for field in ["semantic_request_digest", "library_identity"] {
        let id = format!("r1-side/stored-{field}");
        let (case, world, journal) = completed_claude_document(
            "n15_05_complete_request_binding",
            &id.replace('/', "-"),
        );
        let normal = run_cli(
            &case,
            "normal-qualify",
            &qualify_args(&world, &journal),
            &[],
            &world.env(),
        );
        assert_eq!(normal.rc, Some(0), "{id}: normal qualify control");

        let original = sql_scalar_text(
            &world.db,
            "SELECT detail FROM operation_commit_receipt \
             WHERE operation = 'source_input_activation_v1'",
        );
        let mut value: serde_json::Value =
            serde_json::from_str(&original).expect("the activation detail is JSON");
        if field == "library_identity" {
            value["library_identity"] = serde_json::json!("r1-other-library");
        } else {
            let previous = value["semantic_request_digest"]
                .as_str()
                .expect("the activation detail carries the digest")
                .to_string();
            let replacement = if previous == "a".repeat(64) {
                "b".repeat(64)
            } else {
                "a".repeat(64)
            };
            value["semantic_request_digest"] = serde_json::json!(replacement);
        }
        let modified = serde_json::to_string(&value).expect("encode the stored corruption");
        coding_agent_search::storage::source_facts::decode_receipt_detail(
            modified.as_bytes(),
        )
        .expect("the stored corruption is still strictly canonical");
        sqlite_exec(
            &world.db,
            "UPDATE operation_commit_receipt SET detail = ?1 \
             WHERE operation = 'source_input_activation_v1'",
            &[coding_agent_search::storage::api::Value::Text(modified)],
        );
        rewind_journal(&journal, "planned", &[]);
        refresh_marker_db_identity(&world);
        let recovered = run_cli(
            &case,
            "recover-corrupt-stored",
            &recover_args(&journal),
            &[],
            &world.env(),
        );
        assert_eq!(recovered.rc, Some(1), "{id}: the run must refuse");
        assert_kind(&recovered, "source_restore_receipt_inconsistent");
        case.write(
            "PASS",
            format!("{id} expected=source_restore_receipt_inconsistent\n").as_bytes(),
        );
    }
}

// ---------------------------------------------------------------------------
// n15_06 · receipt currency (dynamic links only)
// ---------------------------------------------------------------------------

#[test]
fn n15_06_receipt_currency() {
    for currency in ["Current", "Historical", "Mixed"] {
        let id = format!("currency-{currency}");
        let (case, world, journal) =
            completed_claude_document("n15_06_receipt_currency", &id);
        match currency {
            "Current" => {}
            "Historical" => {
                sqlite_exec(
                    &world.db,
                    "UPDATE source_message_links \
                     SET authority = 'historical', message_id = NULL",
                    &[],
                );
            }
            "Mixed" => {
                let ids: Vec<i64> = sql_rows(
                    &world.db,
                    "SELECT id FROM source_message_links WHERE authority = 'canonical' ORDER BY id",
                )
                .into_iter()
                .map(|row| row[0].as_i64().expect("link id"))
                .collect();
                assert_eq!(ids.len(), 2, "the claude document has two canonical links");
                sqlite_exec(
                    &world.db,
                    &format!(
                        "UPDATE source_message_links \
                         SET authority = 'historical', message_id = NULL WHERE id = {}",
                        ids[0]
                    ),
                    &[],
                );
            }
            _ => unreachable!(),
        }

        let before_snapshot = typed_snapshot(&world.db);
        let before_mirror = mirror_views_snapshot(&world.data_dir);

        let manifest_id = journal_json(&journal)["planned"][0]["manifest_id"]
            .as_str()
            .expect("the planned manifest id")
            .to_string();
        // The currency change is an intentional edit of the dynamic link
        // columns. Refresh the marker's DB identity so the marker attests the
        // candidate as it now stands; the journal digest is refreshed only for
        // qualify, after the journal reaches its final form.
        refresh_marker_db_identity(&world);
        rewind_journal(&journal, "db-committed", &[manifest_id]);
        let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: recover must succeed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("recover JSON");
        assert_eq!(report["already_committed"], serde_json::json!(1), "{id}");
        assert!(
            report.get("source_replayed").is_none(),
            "{id}: a genuine restore receipt is not a source replay"
        );

        let after_snapshot = typed_snapshot(&world.db);
        case.write_json("db.before-currency.json", &before_snapshot);
        case.write_json("db.after-currency.json", &after_snapshot);
        assert_eq!(
            after_snapshot, before_snapshot,
            "{id}: all nine typed tables must stay value exact"
        );
        assert_eq!(
            mirror_views_snapshot(&world.data_dir),
            before_mirror,
            "{id}: the mirror must stay field exact"
        );

        refresh_marker_identity(&world, &journal);
        let qualified = run_cli(
            &case,
            "qualify",
            &qualify_args(&world, &journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            qualified.rc,
            Some(0),
            "{id}: qualify must pass: {}",
            String::from_utf8_lossy(&qualified.stderr)
        );
        let qjson: serde_json::Value =
            serde_json::from_slice(&qualified.stdout).expect("qualify JSON");
        assert_eq!(qjson["qualified"], serde_json::json!(true), "{id}");
        case.write("PASS", format!("{id}\n").as_bytes());
    }
}

// ---------------------------------------------------------------------------
// n15_07 · qualify depth and privacy
// ---------------------------------------------------------------------------

fn deep_qualify_args(world: &World, journal: &Path) -> Vec<String> {
    let mut args = qualify_args(world, journal);
    args.push("--deep-verify".to_string());
    args
}

fn text_qualify_args(world: &World, journal: &Path) -> Vec<String> {
    qualify_args(world, journal)
        .into_iter()
        .filter(|arg| arg != "--json")
        .collect()
}

fn run_strace_qualify(
    case: &CaseDir,
    label: &str,
    world: &World,
    journal: &Path,
    deep: bool,
) -> (RunResult, String) {
    use std::os::unix::process::CommandExt as _;
    let log = case.join(&format!("{label}.strace"));
    let mut args = vec![
        "-f".to_string(),
        "-e".to_string(),
        "trace=openat,read".to_string(),
        "-o".to_string(),
        log.to_string_lossy().into_owned(),
        cli_binary().to_string_lossy().into_owned(),
    ];
    args.extend(if deep {
        deep_qualify_args(world, journal)
    } else {
        qualify_args(world, journal)
    });
    let env = world.env();
    let mut command = Command::new("/usr/bin/strace");
    command
        .args(&args)
        .current_dir(env.cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .env("HOME", env.home)
        .env("XDG_CONFIG_HOME", env.xdg_config)
        .env("XDG_DATA_HOME", env.xdg_data)
        .env("XDG_CACHE_HOME", env.xdg_cache)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let start = now_rfc3339();
    let child = command.spawn().expect("spawn strace");
    let pid = child.id();
    let meta = serde_json::json!({
        "label": label,
        "argv": args,
        "pid": pid,
        "pgid": pid,
        "proc_starttime": proc_starttime(pid),
        "utc_start": start,
    });
    let result = finish_child(child, meta);
    case.write(&format!("{label}.stdout"), &result.stdout);
    case.write(&format!("{label}.stderr"), &result.stderr);
    case.write_json(&format!("{label}.meta.json"), &result.meta);
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    (result, log_text)
}

#[test]
fn n15_07_qualify_depth_and_privacy() {
    // 1 · default-normal-readonly
    {
        let id = "default-normal-readonly";
        let (case, world, journal) =
            completed_claude_document("n15_07_qualify_depth_and_privacy", id);
        let before_db = db_digest(&world.db);
        let before_mirror = mirror_digest(&world.data_dir);
        let result = run_cli(
            &case,
            "qualify-default",
            &qualify_args(&world, &journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("qualify JSON");
        assert_eq!(report["qualified"], serde_json::json!(true), "{id}");
        assert_untouched(&world, before_db, &before_mirror);
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // 2 · equal-size-blob-change-default-and-deep
    {
        let id = "equal-size-blob-change-default-and-deep";
        let (case, world, journal) =
            completed_claude_document("n15_07_qualify_depth_and_privacy", id);
        let source = world
            .views()
            .into_iter()
            .find(|view| view.provider == "claude")
            .expect("the claude manifest view");
        let blob = world
            .data_dir
            .join("raw-mirror")
            .join("v1")
            .join(&source.blob_relative_path);
        let original = std::fs::read(&blob).expect("read the sealed blob");
        let mut flipped = original.clone();
        let index = flipped.len() / 2;
        flipped[index] ^= 0x01;
        std::fs::write(&blob, &flipped).expect("flip one blob byte");

        let (default_result, default_log) = run_strace_qualify(
            &case,
            "strace-default",
            &world,
            &journal,
            false,
        );
        assert_eq!(
            default_result.rc,
            Some(0),
            "{id}: default qualify must pass: {}",
            String::from_utf8_lossy(&default_result.stderr)
        );
        let default_report: serde_json::Value =
            serde_json::from_slice(&default_result.stdout).expect("default qualify JSON");
        assert_eq!(default_report["qualified"], serde_json::json!(true));
        assert!(
            !default_log.contains(&blob.to_string_lossy().to_string()),
            "{id}: default qualify must not open or read the blob"
        );

        let (deep_result, deep_log) =
            run_strace_qualify(&case, "strace-deep", &world, &journal, true);
        assert_eq!(deep_result.rc, Some(1), "{id}: deep qualify must reject");
        assert_kind(&deep_result, "mirror_restore_not_qualified");
        let deep_payload = error_json(&deep_result);
        assert!(
            deep_payload
                .pointer("/error/message")
                .and_then(|value| value.as_str())
                .map(|message| message.contains("E-MIRROR-BLOB-CHECKSUM-MISMATCH"))
                .unwrap_or(false),
            "{id}: deep qualifies rejects with the existing blob checksum error: {deep_payload}"
        );
        assert!(
            deep_log.contains(&blob.to_string_lossy().to_string()),
            "{id}: deep qualify must actually open the blob"
        );

        std::fs::write(&blob, &original).expect("restore the sealed blob");
        let (control, _) =
            run_strace_qualify(&case, "strace-deep-control", &world, &journal, true);
        assert_eq!(
            control.rc,
            Some(0),
            "{id}: the normal deep control must pass: {}",
            String::from_utf8_lossy(&control.stderr)
        );
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // 3–5 · the three text short codes
    for (id, expected) in [
        ("text-source_restore_replan_required", "source_restore_replan_required"),
        ("text-source_restore_receipt_conflict", "source_restore_receipt_conflict"),
        ("text-source_restore_receipt_inconsistent", "source_restore_receipt_inconsistent"),
    ] {
        let (case, world, journal) =
            completed_claude_document("n15_07_qualify_depth_and_privacy", id);
        match id {
            "text-source_restore_replan_required" => sqlite_exec(
                &world.db,
                "UPDATE operation_commit_receipt SET detail = NULL \
                 WHERE operation = 'mirror-restore-new'",
                &[],
            ),
            "text-source_restore_receipt_conflict" => mutate_detail(&world.db, |detail| {
                detail["restore_key"] = serde_json::json!("C15_OTHER_VALID_RESTORE_KEY");
            }),
            "text-source_restore_receipt_inconsistent" => mutate_activation_hash(&world.db),
            _ => unreachable!(),
        }
        refresh_marker_identity(&world, &journal);
        let result = run_cli(
            &case,
            "qualify-text",
            &text_qualify_args(&world, &journal),
            &[],
            &world.env(),
        );
        assert_eq!(result.rc, Some(1), "{id}: must refuse");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert_eq!(
            stderr.trim(),
            expected,
            "{id}: the text face prints only the fixed short code"
        );
        case.write("PASS", format!("{id} expected={expected}\n").as_bytes());
    }

    // 6 · qualify-prior-layer-preserved
    {
        let id = "qualify-prior-layer-preserved";
        let (case, world, journal) =
            completed_claude_document("n15_07_qualify_depth_and_privacy", id);
        sqlite_exec(
            &world.db,
            "UPDATE operation_commit_receipt SET detail = NULL \
             WHERE operation = 'mirror-restore-new'",
            &[],
        );
        let marker_path = world.tmp.path().join("w1-commit-marker.json");
        let mut marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&marker_path).expect("read the marker"))
                .expect("decode the marker");
        marker["schema"] = serde_json::json!("bogus.marker.schema");
        std::fs::write(
            &marker_path,
            serde_json::to_vec(&marker).expect("encode the marker"),
        )
        .expect("write the invalid marker");
        let result = run_cli(
            &case,
            "qualify-prior-layer",
            &qualify_args(&world, &journal),
            &[],
            &world.env(),
        );
        assert_eq!(result.rc, Some(1), "{id}: must refuse");
        assert_kind(&result, "mirror_restore_not_qualified");
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // R1-SIDE · the two Root F0 qualify-material counterexamples, rechecked on
    // the repaired source. Explicit side columns, not part of the frozen 6.
    for mode in ["fad-pin", "missing-binding"] {
        let id = format!("r1-side/qualify-{mode}");
        let (case, world, journal) = completed_claude_document(
            "n15_07_qualify_depth_and_privacy",
            &id.replace('/', "-"),
        );
        let normal = run_cli(
            &case,
            "normal-qualify",
            &qualify_args(&world, &journal),
            &[],
            &world.env(),
        );
        assert_eq!(normal.rc, Some(0), "{id}: normal qualify control");

        let mut value = journal_json(&journal);
        if mode == "fad-pin" {
            value["source_profile"]["fad_pin"] = serde_json::json!("f".repeat(40));
        } else {
            value["planned"][0]["source_binding"] = serde_json::Value::Null;
        }
        std::fs::write(
            &journal,
            serde_json::to_vec(&value).expect("encode the edited journal"),
        )
        .expect("write the edited journal");
        refresh_marker_identity(&world, &journal);

        let bad = run_cli(
            &case,
            "edited-qualify",
            &qualify_args(&world, &journal),
            &[],
            &world.env(),
        );
        assert_eq!(bad.rc, Some(1), "{id}: qualify must reject the edited material");
        assert_kind(&bad, "source_restore_material_mismatch");
        let recovered = run_cli(
            &case,
            "edited-recover",
            &recover_args(&journal),
            &[],
            &world.env(),
        );
        assert_eq!(recovered.rc, Some(1), "{id}: recover rejects the same material");
        assert_kind(&recovered, "source_restore_material_mismatch");
        case.write(
            "PASS",
            format!("{id} expected=source_restore_material_mismatch\n").as_bytes(),
        );
    }
}

// ---------------------------------------------------------------------------
// n15_02 · counting, replay, dedup, legacy and mixed
// ---------------------------------------------------------------------------

const OPENCLAW_PAYLOAD: &[u8] = br#"{"type":"session","id":"C15-OPENCLAW","timestamp":"2026-01-01T00:00:00.000Z","cwd":"/synthetic/c15-openclaw"}
{"type":"message","id":"C15-O-U","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"user","content":[{"type":"text","text":"C15 openclaw question"}]}}
{"type":"message","id":"C15-O-A","timestamp":"2026-01-01T00:00:02.000Z","message":{"role":"assistant","content":[{"type":"text","text":"C15 openclaw answer"}]}}
"#;

/// One source whose declaration names the connector's real scan root, so the
/// plan's input key matches the ordinary index's own ingestion.
fn replay_source(world: &World, spec: Spec) -> Source {
    let mut source = world.source(spec.clone());
    let (root, relative) = match spec.connector {
        "claude_code" => {
            let root = world.home.join(".claude/projects");
            let relative = source
                .live_path
                .strip_prefix(&root)
                .expect("the claude source lives under the claude projects root")
                .to_path_buf();
            (root, relative)
        }
        "codex" => {
            let root = world.home.join(".codex/sessions");
            let relative = source
                .live_path
                .strip_prefix(&root)
                .expect("the codex source lives under the codex sessions root")
                .to_path_buf();
            (root, relative)
        }
        other => panic!("no replay declaration for connector {other}"),
    };
    source.declaration = serde_json::json!({
        "manifest_id": source.capture.manifest_id,
        "identity_namespace": "local",
        "connector": spec.connector,
        "scan_root": root.to_string_lossy(),
        "relative_locator": relative.to_string_lossy(),
        "role": "primary_session_log",
        "origin": {
            "source_id": spec.source_id,
            "kind": spec.origin_kind,
            "host": spec.origin_host,
            "source_version": null,
        },
        "platform": null,
        "workspace_rewrites": [],
    });
    source
}

fn capture_openclaw(world: &World) -> RawMirrorCaptureRecord {
    let live = world
        .home
        .join(".openclaw/agents/testagent/sessions/session.jsonl");
    write_source(&live, OPENCLAW_PAYLOAD);
    capture_source_file_with_identity(
        RawMirrorCaptureInput {
            data_dir: &world.data_dir,
            provider: "openclaw/testagent",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &live,
            db_links: &[],
        },
        RawMirrorSessionIdentity {
            identity_host: RAW_MIRROR_LOCAL_IDENTITY_HOST,
            external_id: None,
        },
    )
    .expect("capture the openclaw fixture")
}

fn legacy_apply_args(world: &World, journal: &Path) -> Vec<String> {
    vec![
        "mirror-restore".to_string(),
        "--data-dir".to_string(),
        world.data_dir.to_string_lossy().into_owned(),
        "--candidate-db".to_string(),
        world.db.to_string_lossy().into_owned(),
        "--scratch".to_string(),
        world.scratch.to_string_lossy().into_owned(),
        "--snapshot-root".to_string(),
        "c29-snapshot-root".to_string(),
        "--apply".to_string(),
        "--journal".to_string(),
        journal.to_string_lossy().into_owned(),
        "--generation".to_string(),
        "c29-generation".to_string(),
        "--json".to_string(),
    ]
}

fn ordinary_index(world: &World, id: &str) -> RunResult {
    let args = vec![
        "index".to_string(),
        "--json".to_string(),
        "--data-dir".to_string(),
        world.data_dir.to_string_lossy().into_owned(),
    ];
    let result = run_cli(
        &case_evidence("n15_02_counts_and_legacy", &format!("{id}-index")),
        "index",
        &args,
        &[],
        &world.env(),
    );
    assert_eq!(
        result.rc,
        Some(0),
        "the ordinary index must succeed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    result
}

#[test]
fn n15_02_counts_and_legacy() {
    // 1 · source-only-apply-text
    {
        let id = "source-only-apply-text";
        let case = case_evidence("n15_02_counts_and_legacy", id);
        let world = World::new();
        let source = world.source(native_spec("claude_empty_document"));
        let (contexts, _) = world.write_contexts(&[&source]);
        let journal = world.tmp.path().join("journal.json");
        let mut args = apply_args(&world, &contexts, Some(&world.fixed), &journal);
        args.retain(|arg| arg != "--json");
        let result = run_cli(&case, "apply-text", &args, &[], &world.env());
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let text = String::from_utf8_lossy(&result.stdout);
        assert!(text.contains("source_only_completed=1"), "{id}: {text}");
        assert!(text.contains("restored=0"), "{id}: {text}");
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // 2 · source-only-recover-text
    {
        let id = "source-only-recover-text";
        let case = case_evidence("n15_02_counts_and_legacy", id);
        let world = World::new();
        let source = world.source(native_spec("claude_blank_jsonl"));
        let (contexts, _) = world.write_contexts(&[&source]);
        let journal = world.tmp.path().join("journal.json");
        let sentinel = world.tmp.path().join("planned.sentinel");
        let planned = run_paused_at(
            &case_evidence("n15_02_counts_and_legacy", &format!("{id}-plan")),
            "plan",
            &apply_args(&world, &contexts, Some(&world.fixed), &journal),
            &[],
            &world.env(),
            &sentinel,
            "planned",
        );
        assert_eq!(planned.meta["signal"], serde_json::json!(9), "{id}");
        let mut args = recover_args(&journal);
        args.retain(|arg| arg != "--json");
        let result = run_cli(&case, "recover-text", &args, &[], &world.env());
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let text = String::from_utf8_lossy(&result.stdout);
        assert!(text.contains("source_only_completed=1"), "{id}: {text}");
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // 3–4 · ordinary source replay (real recipe)
    for (id, payload_name) in [
        ("ordinary-complete-source-replay", "claude_one"),
        ("ordinary-zero-source-replay", "claude_empty_document"),
    ] {
        let case = case_evidence("n15_02_counts_and_legacy", id);
        let mut world = World::new();
        world.use_index_db();
        write_default_safety(&world, false);
        let source = replay_source(&world, native_spec(payload_name));
        let (contexts, _) = world.write_contexts(&[&source]);
        let journal = world.tmp.path().join("journal.json");
        let sentinel = world.tmp.path().join("planned.sentinel");
        let planned = run_paused_at(
            &case_evidence("n15_02_counts_and_legacy", &format!("{id}-plan")),
            "plan",
            &apply_args(&world, &contexts, None, &journal),
            &[],
            &world.env(),
            &sentinel,
            "planned",
        );
        assert_eq!(planned.meta["signal"], serde_json::json!(9), "{id}");
        assert_eq!(journal_json(&journal)["state"], serde_json::json!("planned"), "{id}");

        ordinary_index(&world, id);
        assert_eq!(
            sql_scalar_text(&world.db, "SELECT state FROM source_inputs"),
            "complete",
            "{id}: the ordinary index must complete the same input"
        );
        let messages_before = table_count(&world.db, "messages");
        let before_replay = typed_snapshot(&world.db);

        let recovered = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(
            recovered.rc,
            Some(0),
            "{id}: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&recovered.stdout).expect("recover JSON");
        assert_eq!(report["source_replayed"], serde_json::json!(1), "{id}");
        assert!(
            report.get("source_only_completed").is_none(),
            "{id}: a replay is not source-only completion"
        );
        assert_eq!(
            table_count(&world.db, "messages"),
            messages_before,
            "{id}: a source replay inserts no messages"
        );
        let after_replay = typed_snapshot(&world.db);
        case.write_json("db.before-replay.json", &before_replay);
        case.write_json("db.after-replay.json", &after_replay);
        assert_eq!(
            after_replay["messages"], before_replay["messages"],
            "{id}: a replay changes no message row"
        );
        assert_eq!(
            after_replay["conversations"], before_replay["conversations"],
            "{id}: a replay changes no conversation row"
        );
        assert_eq!(
            after_replay["source_inputs"], before_replay["source_inputs"],
            "{id}: a replay keeps the completed source input"
        );
        assert_eq!(
            table_count_where(
                &world.db,
                "operation_commit_receipt",
                "operation = 'mirror-restore-new' AND state = 'committed'"
            ),
            1,
            "{id}: the replay closes the restore receipt"
        );
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // 5 · same-content-existing-conversation-deduplicated
    {
        let id = "same-content-existing-conversation-deduplicated";
        // First build the genuine conversation through the shared kernel, then
        // remove only the source registration and the two receipts. The
        // conversation is now a legacy row with no source evidence, and the
        // second install must content-dedupe against it.
        let (case, world, journal) = completed_claude_document("n15_02_counts_and_legacy", id);
        assert_eq!(table_count(&world.db, "conversations"), 1, "{id}");
        let messages_before = table_count(&world.db, "messages");
        sqlite_exec(&world.db, "DELETE FROM source_message_links", &[]);
        sqlite_exec(&world.db, "DELETE FROM source_records", &[]);
        sqlite_exec(&world.db, "DELETE FROM source_inputs", &[]);
        sqlite_exec(
            &world.db,
            "DELETE FROM operation_commit_receipt \
             WHERE operation IN ('source_input_activation_v1', 'mirror-restore-new')",
            &[],
        );
        // The marker is not evidence in this case: the DB was intentionally
        // reduced to a legacy conversation. Remove the stale marker so the
        // recover writes a fresh one instead of comparing against the pre-edit
        // artifact.
        let _ = std::fs::remove_file(world.tmp.path().join("w1-commit-marker.json"));
        rewind_journal(&journal, "planned", &[]);

        let recovered = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());
        assert_eq!(
            recovered.rc,
            Some(0),
            "{id}: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&recovered.stdout).expect("recover JSON");
        assert_eq!(report["deduplicated"], serde_json::json!(1), "{id}");
        assert_eq!(report["restored"], serde_json::json!(0), "{id}");
        assert_eq!(
            table_count(&world.db, "messages"),
            messages_before,
            "{id}: a content dedup inserts no messages"
        );
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // 6–7 · legacy JSON and text output shapes
    for (id, json) in [
        ("legacy-json-shape-unchanged", true),
        ("legacy-text-shape-unchanged", false),
    ] {
        let case = case_evidence("n15_02_counts_and_legacy", id);
        let world = World::new();
        capture_openclaw(&world);
        let journal = world.tmp.path().join("journal.json");
        let mut args = legacy_apply_args(&world, &journal);
        if !json {
            args.retain(|arg| arg != "--json");
        }
        let result = run_cli(&case, "apply", &args, &[], &world.env());
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: the legacy apply must succeed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        if json {
            let report: serde_json::Value =
                serde_json::from_slice(&result.stdout).expect("legacy apply JSON");
            assert!(report.get("source_only_completed").is_none(), "{id}");
            assert!(report.get("source_replayed").is_none(), "{id}");
            assert_eq!(report["restored"], serde_json::json!(1), "{id}");
        } else {
            let text = String::from_utf8_lossy(&result.stdout);
            assert!(!text.contains("source_only_completed"), "{id}: {text}");
            assert!(!text.contains("source_replayed"), "{id}: {text}");
        }
        assert_eq!(table_count(&world.db, "conversations"), 1, "{id}");
        assert_eq!(
            table_count(&world.db, "source_inputs"),
            0,
            "{id}: legacy has no source rows"
        );
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // 8 · mixed source New and legacy New
    {
        let id = "mixed-source-new-and-legacy-new";
        let case = case_evidence("n15_02_counts_and_legacy", id);
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        capture_openclaw(&world);
        let (contexts, _) = world.write_contexts(&[&source]);
        let journal = world.tmp.path().join("journal.json");
        let result = run_cli(
            &case,
            "apply",
            &apply_args(&world, &contexts, Some(&world.fixed), &journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("apply JSON");
        assert_eq!(report["restored"], serde_json::json!(2), "{id}");
        assert_eq!(table_count(&world.db, "conversations"), 2, "{id}");
        assert_eq!(
            table_count(&world.db, "source_inputs"),
            1,
            "{id}: only the source item"
        );
        case.write("PASS", format!("{id}\n").as_bytes());
    }
}

// ---------------------------------------------------------------------------
// n15_03 · input atomicity
// ---------------------------------------------------------------------------

fn install_late_receipt_trigger(db: &Path) {
    let mut storage = FrankenStorage::open(db).expect("open the candidate db");
    storage
        .raw()
        .execute_batch(
            "CREATE TRIGGER c15_late_restore_receipt \
             BEFORE INSERT ON operation_commit_receipt \
             WHEN NEW.operation = 'mirror-restore-new' \
             BEGIN SELECT RAISE(ABORT, 'C15_PRIVATE_SQL_CANARY'); END;",
        )
        .expect("install the late receipt trigger");
    storage.close_best_effort_in_place();
}

fn drop_late_receipt_trigger(db: &Path) {
    sqlite_exec(db, "DROP TRIGGER c15_late_restore_receipt", &[]);
}

fn assert_no_source_rows(db: &Path) {
    for table in [
        "source_inputs",
        "source_records",
        "source_message_links",
        "conversations",
        "messages",
        "agents",
        "workspaces",
        "operation_commit_receipt",
    ] {
        assert_eq!(
            table_count(db, table),
            0,
            "{table} must be rolled back to zero"
        );
    }
}

fn paused_planned_apply(
    id: &str,
    world: &World,
    contexts: &Path,
    journal: &Path,
    sentinel: &Path,
) -> RunResult {
    run_paused_at(
        &case_evidence("n15_03_input_atomicity", &format!("{id}-plan")),
        "plan",
        &apply_args(world, contexts, Some(&world.fixed), journal),
        &[],
        &world.env(),
        sentinel,
        "planned",
    )
}

#[test]
fn n15_03_input_atomicity() {
    // 1–2 · a real late SQLite failure on the restore receipt insert.
    for (id, payload_name, records, conversations, messages, links) in [
        ("late-receipt-trigger-claude", "claude_one", 1u64, 1u64, 1u64, 1u64),
        ("late-receipt-trigger-codex", "codex_document", 1, 1, 2, 2),
    ] {
        let case = case_evidence("n15_03_input_atomicity", id);
        let world = World::new();
        let source = world.source(native_spec(payload_name));
        let (contexts, _) = world.write_contexts(&[&source]);
        let journal = world.tmp.path().join("journal.json");
        let sentinel = world.tmp.path().join("planned.sentinel");
        let planned = paused_planned_apply(id, &world, &contexts, &journal, &sentinel);
        assert_eq!(planned.meta["signal"], serde_json::json!(9), "{id}: planned pause kill");
        assert_eq!(journal_json(&journal)["state"], serde_json::json!("planned"), "{id}");

        install_late_receipt_trigger(&world.db);
        let before_failure = typed_snapshot(&world.db);
        let before_mirror = mirror_views_snapshot(&world.data_dir);
        let first = run_cli(&case, "recover-triggered", &recover_args(&journal), &[], &world.env());
        assert_eq!(first.rc, Some(1), "{id}: the late trigger must fail the run");
        assert_kind(&first, "mirror_restore_recover_failed");
        let after_failure = typed_snapshot(&world.db);
        case.write_json("db.before-failure.json", &before_failure);
        case.write_json("db.after-failure.json", &after_failure);
        assert_eq!(
            after_failure, before_failure,
            "{id}: the failed restore must roll back every typed row"
        );
        assert_eq!(
            mirror_views_snapshot(&world.data_dir),
            before_mirror,
            "{id}: the failed restore must not advance the mirror"
        );
        assert_no_source_rows(&world.db);
        assert_eq!(
            journal_json(&journal)["state"],
            serde_json::json!("planned"),
            "{id}: the journal must not advance"
        );

        drop_late_receipt_trigger(&world.db);
        let second = run_cli(&case, "recover-clean", &recover_args(&journal), &[], &world.env());
        assert_eq!(
            second.rc,
            Some(0),
            "{id}: the clean fresh recover must succeed: {}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert_eq!(table_count(&world.db, "source_records"), records as i64, "{id}");
        assert_eq!(table_count(&world.db, "source_message_links"), links as i64, "{id}");
        assert_eq!(table_count(&world.db, "conversations"), conversations as i64, "{id}");
        assert_eq!(table_count(&world.db, "messages"), messages as i64, "{id}");
        assert_eq!(
            table_count_where(
                &world.db,
                "operation_commit_receipt",
                "operation = 'mirror-restore-new' AND state = 'committed'"
            ),
            1,
            "{id}: exactly one restore receipt after the clean replay"
        );
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // 3–4 · a real SIGKILL inside the source transaction.
    for (id, payload_name, records, conversations, messages, links) in [
        ("inside-source-tx-kill-claude", "claude_one", 1u64, 1u64, 1u64, 1u64),
        ("inside-source-tx-kill-codex", "codex_document", 1, 1, 2, 2),
    ] {
        let case = case_evidence("n15_03_input_atomicity", id);
        let world = World::new();
        let source = world.source(native_spec(payload_name));
        let (contexts, _) = world.write_contexts(&[&source]);
        let journal = world.tmp.path().join("journal.json");
        let planned_sentinel = world.tmp.path().join("planned.sentinel");
        let planned = paused_planned_apply(id, &world, &contexts, &journal, &planned_sentinel);
        assert_eq!(planned.meta["signal"], serde_json::json!(9), "{id}: planned pause kill");

        let inside_sentinel = world.tmp.path().join("inside.sentinel");
        let before_kill = typed_snapshot(&world.db);
        let before_kill_mirror = mirror_views_snapshot(&world.data_dir);
        let killed = run_paused_at(
            &case,
            "recover-killed",
            &recover_args(&journal),
            &[],
            &world.env(),
            &inside_sentinel,
            "restore-new-inserted-not-receipted",
        );
        assert_eq!(
            killed.meta["signal"],
            serde_json::json!(9),
            "{id}: the source transaction child must be SIGKILLed at its sentinel"
        );
        let after_kill = typed_snapshot(&world.db);
        case.write_json("db.before-kill.json", &before_kill);
        case.write_json("db.after-kill.json", &after_kill);
        assert_eq!(
            after_kill, before_kill,
            "{id}: the killed source transaction must leave no typed row"
        );
        assert_eq!(
            mirror_views_snapshot(&world.data_dir),
            before_kill_mirror,
            "{id}: the killed source transaction must not advance the mirror"
        );
        assert_no_source_rows(&world.db);
        assert_eq!(
            journal_json(&journal)["state"],
            serde_json::json!("planned"),
            "{id}: the journal must not advance"
        );

        let fresh = run_cli(&case, "recover-fresh", &recover_args(&journal), &[], &world.env());
        assert_eq!(
            fresh.rc,
            Some(0),
            "{id}: the fresh process must recover: {}",
            String::from_utf8_lossy(&fresh.stderr)
        );
        assert_eq!(table_count(&world.db, "source_inputs"), 1, "{id}");
        assert_eq!(table_count(&world.db, "source_records"), records as i64, "{id}");
        assert_eq!(table_count(&world.db, "source_message_links"), links as i64, "{id}");
        assert_eq!(table_count(&world.db, "conversations"), conversations as i64, "{id}");
        assert_eq!(table_count(&world.db, "messages"), messages as i64, "{id}");
        assert_eq!(
            table_count_where(
                &world.db,
                "operation_commit_receipt",
                "operation = 'mirror-restore-new' AND state = 'committed'"
            ),
            1,
            "{id}: exactly one restore receipt after the fresh recovery"
        );
        case.write("PASS", format!("{id}\n").as_bytes());
    }

    // R3-SIDE · a real post-write storage read failure must keep the typed
    // StorageError chain and the generic recovery family. The Root pre-fix
    // evidence recorded source_restore_receipt_inconsistent; R3 asserts the
    // repaired end state. This is a side column, not part of the frozen 4.
    {
        let id = "r3-side/postwrite-db-read-error";
        let (case, world, journal) = completed_claude_document(
            "n15_03_input_atomicity",
            "r3-side-postwrite-db-read-error",
        );
        sqlite_exec(
            &world.db,
            "DELETE FROM operation_commit_receipt WHERE operation = 'mirror-restore-new'",
            &[],
        );
        rewind_journal(&journal, "planned", &[]);
        let _ = std::fs::remove_file(world.tmp.path().join("w1-commit-marker.json"));
        sqlite_exec(
            &world.db,
            "CREATE TRIGGER c15_r3_postwrite AFTER INSERT ON operation_commit_receipt \
             WHEN NEW.operation = 'mirror-restore-new' \
             BEGIN UPDATE meta SET value = x'ff' WHERE key = 'library_identity'; END",
            &[],
        );
        let before = typed_snapshot(&world.db);
        let result = run_cli(
            &case,
            "recover-postwrite-db-error",
            &recover_args(&journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            result.rc,
            Some(1),
            "{id}: the post-write read failure must fail the run"
        );
        assert_kind(&result, "mirror_restore_recover_failed");
        let after = typed_snapshot(&world.db);
        case.write_json("db.before-postwrite-error.json", &before);
        case.write_json("db.after-postwrite-error.json", &after);
        assert_eq!(
            after, before,
            "{id}: the failed run must roll back every typed row"
        );
        assert_eq!(
            journal_json(&journal)["state"],
            serde_json::json!("planned"),
            "{id}: the journal must not advance"
        );
        sqlite_exec(&world.db, "DROP TRIGGER c15_r3_postwrite", &[]);
        case.write(
            "PASS",
            format!("{id} expected=mirror_restore_recover_failed\n").as_bytes(),
        );
    }
    {
        let id = "r3-side/postwrite-db-read-error-normal-control";
        let (case, world, journal) = completed_claude_document(
            "n15_03_input_atomicity",
            "r3-side-postwrite-db-normal",
        );
        sqlite_exec(
            &world.db,
            "DELETE FROM operation_commit_receipt WHERE operation = 'mirror-restore-new'",
            &[],
        );
        rewind_journal(&journal, "planned", &[]);
        let _ = std::fs::remove_file(world.tmp.path().join("w1-commit-marker.json"));
        let result = run_cli(
            &case,
            "recover-postwrite-normal",
            &recover_args(&journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            result.rc,
            Some(0),
            "{id}: the normal control must recover: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&result.stdout).expect("recover JSON");
        assert_eq!(report["source_replayed"], serde_json::json!(1), "{id}");
        case.write("PASS", format!("{id}\n").as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Owner ID/body guard · the six frozen restore cases
// ---------------------------------------------------------------------------

fn id_guard_note(failures: &mut Vec<String>, label: &str, ok: bool, detail: String) {
    if !ok {
        failures.push(format!("{label}: {detail}"));
    }
}

/// Build one baseline (accepted 2ed) source New world. A paused apply leaves
/// the journal at `planned`; a full apply writes the complete source and both
/// receipts, which the late-state cases then rewind in the journal only.
fn id_guard_baseline_apply(
    case: &CaseDir,
    world: &World,
    source: &Source,
    label: &str,
    pause_at_planned: bool,
) -> (PathBuf, RunResult) {
    let (contexts, _) = world.write_contexts(&[source]);
    let journal = world.tmp.path().join(format!("{label}-journal.json"));
    if pause_at_planned {
        let sentinel = world.tmp.path().join(format!("{label}-planned.sentinel"));
        let result = run_baseline_paused_at(
            case,
            &format!("{label}-baseline-plan"),
            &apply_args(world, &contexts, Some(&world.fixed), &journal),
            &[],
            &world.env(),
            &sentinel,
            "planned",
        );
        assert_eq!(
            result.meta["signal"],
            serde_json::json!(9),
            "{label}: the planned pause must be SIGKILLed"
        );
        assert_eq!(
            journal_json(&journal)["state"],
            serde_json::json!("planned"),
            "{label}: the paused journal must be planned"
        );
        (journal, result)
    } else {
        let result = run_baseline_cli(
            case,
            &format!("{label}-baseline-apply"),
            &apply_args(world, &contexts, Some(&world.fixed), &journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            result.rc,
            Some(0),
            "{label}: the accepted 2ed baseline must complete the collision: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        (journal, result)
    }
}

#[test]
fn g_id_02_restore_id_body_conflict() {
    let baseline = baseline_cli();
    assert!(
        baseline.is_file(),
        "CASS_GUARD_BASELINE_CLI is not a file: {}",
        baseline.display()
    );
    let mut failures = Vec::new();

    // The planned pair: the baseline pauses before any DB write. The current
    // CLI must apply the normal side and refuse the conflict side before any
    // journal, DB or mirror movement.
    for (side, payload_name) in [
        ("control", "id_guard_control"),
        ("conflict", "id_guard_collision"),
    ] {
        let label = format!("planned-{side}");
        let case = case_evidence("g_id_02_restore_id_body_conflict", &label);
        let world = World::new();
        std::fs::write(&world.fixed, ID_GUARD_FIXED).expect("write the guard fixed copy");
        let source = world.source(native_spec(payload_name));
        let (journal, _) = id_guard_baseline_apply(&case, &world, &source, &label, true);

        let before_db = typed_snapshot(&world.db);
        let before_mirror = mirror_views_snapshot(&world.data_dir);
        let before_journal = std::fs::read(&journal).expect("read the planned journal");
        let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());

        if side == "control" {
            id_guard_note(
                &mut failures,
                &label,
                result.rc == Some(0),
                format!(
                    "the normal side did not recover: rc={:?} stderr={}",
                    result.rc,
                    String::from_utf8_lossy(&result.stderr)
                ),
            );
            id_guard_note(
                &mut failures,
                &label,
                table_count_where(&world.db, "source_inputs", "state = 'complete'") == 1,
                "the normal side did not complete the source".to_string(),
            );
            id_guard_note(
                &mut failures,
                &label,
                table_count(&world.db, "messages") == 2,
                format!("messages={}", table_count(&world.db, "messages")),
            );
            id_guard_note(
                &mut failures,
                &label,
                table_count_where(
                    &world.db,
                    "operation_commit_receipt",
                    "operation = 'mirror-restore-new' AND state = 'committed'",
                ) == 1,
                "the normal side has no committed restore receipt".to_string(),
            );
        } else {
            let text = format!(
                "{}{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
            id_guard_note(
                &mut failures,
                &label,
                result.rc == Some(1),
                format!("rc={:?}", result.rc),
            );
            id_guard_note(
                &mut failures,
                &label,
                text.contains("source_restore_material_mismatch"),
                format!("the fixed material mismatch code is absent; output={text}"),
            );
            id_guard_note(
                &mut failures,
                &label,
                typed_snapshot(&world.db) == before_db,
                "the nine typed tables changed".to_string(),
            );
            id_guard_note(
                &mut failures,
                &label,
                mirror_views_snapshot(&world.data_dir) == before_mirror,
                "the mirror views changed".to_string(),
            );
            id_guard_note(
                &mut failures,
                &label,
                std::fs::read(&journal).expect("read the journal") == before_journal,
                "the planned journal changed".to_string(),
            );
            id_guard_note(
                &mut failures,
                &label,
                table_count(&world.db, "source_inputs") == 0,
                format!("source_inputs={}", table_count(&world.db, "source_inputs")),
            );
        }
    }

    // The late pairs: the baseline really completes the collision (the proven
    // bug), then the journal alone is rewound to the declared late state. The
    // current CLI must still fail the material check on the conflict side and
    // report the normal side as already committed.
    for state in ["db-committed", "closure-verified"] {
        for (side, payload_name) in [
            ("control", "id_guard_control"),
            ("conflict", "id_guard_collision"),
        ] {
            let label = format!("{state}-{side}");
            let case = case_evidence("g_id_02_restore_id_body_conflict", &label);
            let world = World::new();
            std::fs::write(&world.fixed, ID_GUARD_FIXED).expect("write the guard fixed copy");
            let source = world.source(native_spec(payload_name));
            let (journal, _) = id_guard_baseline_apply(&case, &world, &source, &label, false);
            let manifest_id = journal_json(&journal)["planned"][0]["manifest_id"]
                .as_str()
                .expect("the planned manifest id")
                .to_string();
            rewind_journal(&journal, state, &[manifest_id]);

            let before_db = typed_snapshot(&world.db);
            let before_mirror = mirror_views_snapshot(&world.data_dir);
            let before_journal = std::fs::read(&journal).expect("read the rewound journal");
            let result = run_cli(&case, "recover", &recover_args(&journal), &[], &world.env());

            if side == "control" {
                id_guard_note(
                    &mut failures,
                    &label,
                    result.rc == Some(0),
                    format!(
                        "the normal side did not recover: rc={:?} stderr={}",
                        result.rc,
                        String::from_utf8_lossy(&result.stderr)
                    ),
                );
                if let Ok(report) =
                    serde_json::from_slice::<serde_json::Value>(&result.stdout)
                {
                    id_guard_note(
                        &mut failures,
                        &label,
                        report["already_committed"] == serde_json::json!(1),
                        format!("already_committed={}", report["already_committed"]),
                    );
                    id_guard_note(
                        &mut failures,
                        &label,
                        report.get("source_replayed").is_none(),
                        "a genuine restore receipt is not a source replay".to_string(),
                    );
                } else {
                    id_guard_note(
                        &mut failures,
                        &label,
                        false,
                        "the normal side printed no recover JSON".to_string(),
                    );
                }
                id_guard_note(
                    &mut failures,
                    &label,
                    table_count_where(
                        &world.db,
                        "operation_commit_receipt",
                        "operation = 'source_input_activation_v1' AND state = 'committed'",
                    ) == 1,
                    "the source activation receipt is absent".to_string(),
                );
                id_guard_note(
                    &mut failures,
                    &label,
                    table_count_where(
                        &world.db,
                        "operation_commit_receipt",
                        "operation = 'mirror-restore-new' AND state = 'committed'",
                    ) == 1,
                    "the restore receipt is absent".to_string(),
                );
            } else {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&result.stdout),
                    String::from_utf8_lossy(&result.stderr)
                );
                id_guard_note(
                    &mut failures,
                    &label,
                    result.rc == Some(1),
                    format!("rc={:?}", result.rc),
                );
                id_guard_note(
                    &mut failures,
                    &label,
                    text.contains("source_restore_material_mismatch"),
                    format!("the fixed material mismatch code is absent; output={text}"),
                );
                id_guard_note(
                    &mut failures,
                    &label,
                    typed_snapshot(&world.db) == before_db,
                    "the nine typed tables changed".to_string(),
                );
                id_guard_note(
                    &mut failures,
                    &label,
                    mirror_views_snapshot(&world.data_dir) == before_mirror,
                    "the mirror views changed".to_string(),
                );
                id_guard_note(
                    &mut failures,
                    &label,
                    std::fs::read(&journal).expect("read the journal") == before_journal,
                    "the rewound journal changed".to_string(),
                );
            }
        }
    }

    assert!(
        failures.is_empty(),
        "the six frozen restore ID/body cases failed:\n{}",
        failures.join("\n")
    );
}
