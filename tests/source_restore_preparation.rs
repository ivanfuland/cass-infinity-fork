//! Task29 · sealed restore-preparation integration tests.
//!
//! Every case drives the real `cass` binary against a real sealed raw-mirror
//! and a real SQLite candidate database. Each case writes its own evidence tree
//! under `CASS_T29_RESULT_ROOT`: payload literal, independent expected material,
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
const MAPPING_DOMAIN: &str = "cass-source-mapping/2";
const EXCLUSION_EPOCH: &str = "cass-source-exclusion/1";
const NORMALIZER_DOMAIN: &str = "cass.source-normalizer/1";
const SAFETY_CONTRACT: &str = "cass.source-safety/1";
const REDACTION_FINGERPRINT: &str =
    "redact-v1:fe8bda3a83e4f2f4fe85f0de5c84428140bfa658b7865706c43877488ec2bb47";
const CODE_VERSION: &str = "cass-source-exclusion/1+redact-v1:fe8bda3a83e4f2f4fe85f0de5c84428140bfa658b7865706c43877488ec2bb47";
const FIXED_SAFETY: &str = "memory_files = []\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n";
const CONTEXT_SCHEMA: &str = "cass.restore-source-contexts/1";

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

fn result_root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::var("CASS_T29_RESULT_ROOT")
            .expect("CASS_T29_RESULT_ROOT must be set for every Task29 run");
        let path = PathBuf::from(root);
        assert!(
            !path.exists(),
            "CASS_T29_RESULT_ROOT must not exist before the first run: {}",
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
    PathBuf::from(env!("CARGO_BIN_EXE_cass"))
}

fn cli_digest() -> String {
    sha256_hex(&std::fs::read(cli_binary()).expect("read the compiled CLI binary"))
}

struct ChildEnv<'a> {
    home: &'a Path,
    xdg_config: &'a Path,
    xdg_data: &'a Path,
    xdg_cache: &'a Path,
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

fn run_paused(
    case: &CaseDir,
    label: &str,
    args: &[String],
    envs: &[(&str, &str)],
    env: &ChildEnv<'_>,
    sentinel: &Path,
) -> RunResult {
    let mut all_envs = envs.to_vec();
    let sentinel_text = sentinel.to_string_lossy().into_owned();
    all_envs.push(("CASS_RESTORE_PAUSE_AT", "planned"));
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
        "codex_document" => ("codex", "codex", ".codex/sessions/2026/08/rollout-c29.json"),
        "claude_document" => (
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

fn sql_count(db: &Path, sql: &str) -> i64 {
    let mut storage = FrankenStorage::open_readonly(db).expect("open the candidate db readonly");
    let count = storage
        .raw()
        .query_row_map(sql, &[], |row| row.get_typed(0))
        .expect("count the rows");
    storage.close_best_effort_in_place();
    count
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
    assert_eq!(journal["committed"], serde_json::json!([]));
    assert_eq!(journal["published"], serde_json::json!([]));
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

fn blob_path(world: &World, capture: &RawMirrorCaptureRecord) -> PathBuf {
    let view = world
        .views()
        .into_iter()
        .find(|view| view.manifest_id == capture.manifest_id)
        .expect("the source manifest view");
    world
        .data_dir
        .join("raw-mirror")
        .join("v1")
        .join(&view.blob_relative_path)
}

// ---------------------------------------------------------------------------
// p29_01 · sealed material and fixed-copy identity through the real CLI
// ---------------------------------------------------------------------------

#[test]
fn p29_01_cli_sealed_and_fixed() {
    let root = result_root();
    let cases: [(&str, &str, &str, &str); 8] = [
        ("claude-jsonl", "claude_one", "default", "none"),
        ("claude-document", "claude_document", "default", "none"),
        ("codex-jsonl", "codex_jsonl", "default", "none"),
        ("codex-document", "codex_document", "default", "none"),
        ("live-replaced", "claude_one", "default", "replace-live"),
        ("live-deleted", "codex_jsonl", "default", "delete-live"),
        (
            "default-copy-relocated",
            "claude_one",
            "default",
            "relocate",
        ),
        (
            "explicit-copy-relocated",
            "codex_jsonl",
            "explicit",
            "relocate",
        ),
    ];
    for (case_id, payload_name, identity_mode, after) in cases {
        let case_dir = CaseDir::new(&root, "p29_01_cli_sealed_and_fixed", case_id);
        let world = World::new();
        let explicit = identity_mode == "explicit";
        if !explicit {
            write_default_safety(&world, false);
        }
        let source = world.source(native_spec(payload_name));
        let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, explicit);
        let expected =
            expected_binding_with_identity(&source.declaration, payload(payload_name), &profile);
        let journal_path = world.tmp.path().join("restore-journal.json");
        let safety = explicit.then_some(world.fixed.as_path());
        let before_db = db_digest(&world.db);
        let before_mirror = mirror_digest(&world.data_dir);

        let paused = run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(&world, &contexts_path, safety, &journal_path),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        assert!(paused.rc.is_none(), "the planned pause child is SIGKILLed");
        let planned = journal_json(&journal_path);
        assert_eq!(planned["state"], "planned");
        assert_journal_materials(&planned, &contexts_value, &profile);
        assert_eq!(planned["planned"].as_array().unwrap().len(), 1);
        assert_eq!(
            planned["planned"][0]["manifest_id"],
            source.capture.manifest_id
        );
        assert_eq!(
            planned["planned"][0]["source_binding"], expected,
            "{case_id}: the journal binding must equal the independent material"
        );
        case_dir.write(
            "journal.planned.json",
            &std::fs::read(&journal_path).unwrap(),
        );
        case_dir.write("payload.bin", payload(payload_name).bytes);
        assert_untouched(&world, before_db.clone(), &before_mirror);

        let mut recover_journal = planned.clone();
        let mut journal_to_recover = journal_path.clone();
        match after {
            "none" => {}
            "replace-live" => {
                std::fs::write(&source.live_path, payload("claude_different_one").bytes)
                    .expect("replace the live source bytes");
            }
            "delete-live" => {
                std::fs::remove_file(&source.live_path).expect("remove the live source");
            }
            "relocate" => {
                let fixed_copy = PathBuf::from(
                    planned["source_profile"]["fixed_copy_path"]
                        .as_str()
                        .expect("the journal names the fixed copy"),
                );
                let relocated = world.tmp.path().join("c29-relocated-fixed-safety.toml");
                std::fs::rename(&fixed_copy, &relocated).expect("move the fixed copy");
                recover_journal["source_profile"]["fixed_copy_path"] =
                    serde_json::json!(relocated.to_string_lossy());
                journal_to_recover = world.tmp.path().join("restore-journal-relocated.json");
                std::fs::write(
                    &journal_to_recover,
                    serde_json::to_vec_pretty(&recover_journal).unwrap(),
                )
                .expect("write the relocated journal");
                case_dir.write(
                    "fixed-copy.relocated.txt",
                    relocated.to_string_lossy().as_bytes(),
                );
            }
            other => panic!("unhandled after-capture action {other}"),
        }
        // The live source and the original contexts file are gone by now for
        // the live cases; recovery must work from the sealed material alone.
        if after != "none" {
            let _ = std::fs::remove_file(&contexts_path);
        }
        let recover = run_cli(
            &case_dir,
            "recover",
            &recover_args(&journal_to_recover),
            &[],
            &world.env(),
        );
        assert_eq!(
            recover.rc,
            Some(0),
            "{case_id}: recover must complete: {}",
            String::from_utf8_lossy(&recover.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&recover.stdout).expect("recover JSON");
        let restored = report["restored"].as_u64().unwrap_or(0);
        let source_only = report["source_only_completed"].as_u64().unwrap_or(0);
        assert_eq!(
            restored + source_only,
            1,
            "{case_id}: the item lands in exactly one outcome cell"
        );
        assert_eq!(
            sql_count(&world.db, "SELECT COUNT(*) FROM source_inputs"),
            1,
            "{case_id}: one source input"
        );
        assert_eq!(
            sql_count(
                &world.db,
                "SELECT COUNT(*) FROM operation_commit_receipt \
                 WHERE operation = 'source_input_activation_v1' AND state = 'committed'"
            ),
            1,
            "{case_id}: the source activation receipt"
        );
        assert_eq!(
            sql_count(
                &world.db,
                "SELECT COUNT(*) FROM operation_commit_receipt \
                 WHERE operation = 'mirror-restore-new' AND state = 'committed'"
            ),
            1,
            "{case_id}: the restore receipt"
        );
        case_dir.write(
            "journal.recover.json",
            &std::fs::read(&journal_to_recover).unwrap(),
        );
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({
                "case": case_id,
                "payload": payload_name,
                "payload_sha256": payload(payload_name).sha,
                "payload_byte_len": payload(payload_name).bytes.len(),
                "identity_mode": identity_mode,
                "after_capture": after,
                "expected_kind": "complete",
                "profile": profile,
                "contexts": contexts_value,
                "binding": expected,
                "cli_path": cli_binary().to_string_lossy(),
                "cli_sha256": cli_digest(),
                "db_before": before_db,
                "db_after_planned": db_digest(&world.db),
                "mirror_before": before_mirror,
                "mirror_after_planned": mirror_digest(&world.data_dir),
            }),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!("R29_CASE test=p29_01_cli_sealed_and_fixed case={case_id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// p29_02 · binding and material refusal through the real CLI
// ---------------------------------------------------------------------------

const P29_02_CASES: [&str; 10] = [
    "binding-context_digest",
    "binding-sealed_sha256",
    "binding-byte_len",
    "binding-normalizer_id",
    "binding-safety_contract_id",
    "binding-input_key",
    "blob-truncated",
    "blob-equal-length-corrupt",
    "fixed-copy-missing",
    "fixed-copy-changed",
];

#[test]
fn p29_02_cli_binding_and_material_refusal() {
    let root = result_root();
    let filter = std::env::var("CASS_T29_CASE_FILTER")
        .ok()
        .filter(|value| !value.is_empty());
    if let Some(filter) = &filter {
        assert!(
            P29_02_CASES.contains(&filter.as_str()),
            "unknown CASS_T29_CASE_FILTER value {filter}"
        );
    }
    let wrong = sha256_hex(b"C29_WRONG");
    for case_id in P29_02_CASES {
        if let Some(filter) = &filter {
            if case_id != filter {
                continue;
            }
        }
        let case_dir = CaseDir::new(&root, "p29_02_cli_binding_and_material_refusal", case_id);
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, true);
        let expected =
            expected_binding_with_identity(&source.declaration, payload("claude_one"), &profile);
        let base_journal = world.tmp.path().join("base-journal.json");
        let before_planned_db = db_digest(&world.db);
        let before_planned_mirror = mirror_digest(&world.data_dir);
        let paused = run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(&world, &contexts_path, Some(&world.fixed), &base_journal),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        assert!(paused.rc.is_none(), "the planned pause child is SIGKILLed");
        let base = journal_json(&base_journal);
        assert_journal_materials(&base, &contexts_value, &profile);
        assert_eq!(base["planned"][0]["source_binding"], expected);
        assert_untouched(&world, before_planned_db.clone(), &before_planned_mirror);
        case_dir.write("journal.base.json", &std::fs::read(&base_journal).unwrap());
        case_dir.write("payload.bin", payload("claude_one").bytes);

        let mut mutated = base.clone();
        let mut journal_to_recover = base_journal.clone();
        match case_id {
            "binding-context_digest" => {
                mutated["planned"][0]["source_binding"]["context_digest"] =
                    serde_json::json!(wrong);
            }
            "binding-sealed_sha256" => {
                mutated["planned"][0]["source_binding"]["sealed_sha256"] = serde_json::json!(wrong);
            }
            "binding-byte_len" => {
                let length = mutated["planned"][0]["source_binding"]["byte_len"]
                    .as_u64()
                    .expect("byte_len");
                mutated["planned"][0]["source_binding"]["byte_len"] = serde_json::json!(length + 1);
            }
            "binding-normalizer_id" => {
                mutated["planned"][0]["source_binding"]["normalizer_id"] = serde_json::json!(wrong);
            }
            "binding-safety_contract_id" => {
                mutated["planned"][0]["source_binding"]["safety_contract_id"] =
                    serde_json::json!(wrong);
            }
            "binding-input_key" => {
                mutated["planned"][0]["source_binding"]["input_key"] = serde_json::json!(wrong);
            }
            "blob-truncated" => {
                let blob = blob_path(&world, &source.capture);
                let mut bytes = std::fs::read(&blob).expect("read the sealed blob");
                bytes.truncate(bytes.len().saturating_sub(1));
                std::fs::write(&blob, bytes).expect("truncate the sealed blob");
            }
            "blob-equal-length-corrupt" => {
                let blob = blob_path(&world, &source.capture);
                let mut bytes = std::fs::read(&blob).expect("read the sealed blob");
                bytes[0] ^= 0xff;
                std::fs::write(&blob, bytes).expect("corrupt the sealed blob");
            }
            "fixed-copy-missing" => {
                std::fs::rename(
                    &world.fixed,
                    world.tmp.path().join("c29-fixed-safety-moved.toml"),
                )
                .expect("move the fixed copy away");
            }
            "fixed-copy-changed" => {
                std::fs::write(
                    &world.fixed,
                    "memory_files = [\"C29_CHANGED_RULE.md\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n",
                )
                .expect("change the fixed copy bytes");
            }
            other => panic!("unhandled material refusal case {other}"),
        }
        if mutated != base {
            journal_to_recover = world.tmp.path().join("journal.mutated.json");
            std::fs::write(
                &journal_to_recover,
                serde_json::to_vec_pretty(&mutated).unwrap(),
            )
            .expect("write the mutated journal");
            case_dir.write(
                "journal.mutated.json",
                &std::fs::read(&journal_to_recover).unwrap(),
            );
        } else {
            case_dir.write(
                "journal.mutated.json",
                b"unchanged; the material file changed\n",
            );
        }
        let before_recover_db = db_digest(&world.db);
        let before_recover_mirror = mirror_digest(&world.data_dir);
        let recover = run_cli(
            &case_dir,
            "recover",
            &recover_args(&journal_to_recover),
            &[],
            &world.env(),
        );
        assert_eq!(recover.rc, Some(1), "{case_id}: recover must fail closed");
        assert_kind(&recover, "source_restore_material_mismatch");
        assert_untouched(&world, before_recover_db.clone(), &before_recover_mirror);
        assert_eq!(
            journal_json(&journal_to_recover)["state"],
            "planned",
            "{case_id}: the journal must not advance"
        );
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({
                "case": case_id,
                "expected_kind": "source_restore_material_mismatch",
                "wrong_value": wrong,
                "profile": profile,
                "contexts": contexts_value,
                "binding": expected,
                "cli_path": cli_binary().to_string_lossy(),
                "cli_sha256": cli_digest(),
                "db_before_recover": before_recover_db,
                "mirror_before_recover": before_recover_mirror,
            }),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!(
            "R29_CASE test=p29_02_cli_binding_and_material_refusal case={case_id} result=pass"
        );
    }
}
