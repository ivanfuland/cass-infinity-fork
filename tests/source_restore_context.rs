//! Task14 · source-aware restore-context integration tests.
//!
//! Every case drives the real `cass` binary against a real sealed raw-mirror and
//! a real SQLite candidate database. Each case writes its own evidence tree
//! under `CASS_T14_RESULT_ROOT` (case argv/cwd/PID/PGID/start time/wait rc,
//! stdout, stderr, journal bytes, DB and mirror digests, independent expected).
//!
//! The independent expected values are computed here from the fixed declaration,
//! literal sealed bytes and the published canonical formulas. Candidate output
//! is never used to construct an expectation.

use std::collections::BTreeMap;
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
const EXCLUSION_EPOCH: &str = "cass-source-exclusion/1";
/// The epoch the current producer writes (Task10). Kept apart from
/// [`EXCLUSION_EPOCH`], which the fixed v1 calibration vector above still
/// names.
const CURRENT_EXCLUSION_EPOCH: &str = "cass-source-exclusion/2";
const NORMALIZER_DOMAIN: &str = "cass.source-normalizer/1";
const SAFETY_CONTRACT: &str = "cass.source-safety/1";
const REDACTION_FINGERPRINT: &str =
    "redact-v1:fe8bda3a83e4f2f4fe85f0de5c84428140bfa658b7865706c43877488ec2bb47";
const CURRENT_CODE_VERSION: &str = "cass-source-exclusion/2+redact-v1:fe8bda3a83e4f2f4fe85f0de5c84428140bfa658b7865706c43877488ec2bb47";
const FIXED_SAFETY: &str = "memory_files = []\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n";
const CONTEXT_SCHEMA: &str = "cass.restore-source-contexts/1";

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

fn result_root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let root = std::env::var("CASS_T14_RESULT_ROOT")
            .expect("CASS_T14_RESULT_ROOT must be set for every Task14 run");
        let path = PathBuf::from(root);
        assert!(
            !path.exists(),
            "CASS_T14_RESULT_ROOT must not exist before the first run: {}",
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
    // The field after comm is state (field 3); starttime is field 22.
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
    case: &CaseDir,
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
    let meta = serde_json::json!({
        "label": label,
        "argv": args,
        "cwd": env.cwd,
        "pid": child.id(),
        "pgid": child.id(),
        "proc_starttime": proc_starttime(child.id()),
        "utc_start": start,
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
    let (child, meta) = spawn_cli(case, label, args, envs, env);
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
    let (mut child, meta) = spawn_cli(case, label, args, &all_envs, env);
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
// Literal payloads (controller-fixed, task-14-fixtures-v3)
// ---------------------------------------------------------------------------

struct Payload {
    bytes: &'static [u8],
    sha: &'static str,
    records: u64,
    messages: u64,
    parse_failed: u64,
}

fn payload(name: &str) -> &'static Payload {
    macro_rules! payload {
        ($bytes:expr, $sha:expr, $records:expr, $messages:expr, $failed:expr) => {{
            &Payload {
                bytes: $bytes,
                sha: $sha,
                records: $records,
                messages: $messages,
                parse_failed: $failed,
            }
        }};
    }
    match name {
        "claude_one" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
"#,
            "6f202da269cbdc40d7ac4b7fc204cf3a119b09e39b6e034face1bf5316686639",
            1,
            1,
            0
        ),
        "claude_two" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
{"type":"assistant","uuid":"C44-A","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"text","text":"C44 answer"}],"model":"C44-model"}}
"#,
            "c675f87354f7cb219f991070431b98408c8ec841d8dfcc8cf69cca3af100e8fb",
            2,
            2,
            0
        ),
        "claude_three" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
{"type":"assistant","uuid":"C44-A","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"text","text":"C44 answer"}],"model":"C44-model"}}
{"type":"user","uuid":"C14-U3","timestamp":"2026-01-01T00:00:02.000Z","message":{"role":"user","content":"C14 third message"}}
"#,
            "b8d2f95539c4d4c76f75a693dc21ae56e62b09d32302868b0d8eafe5b341d28a",
            3,
            3,
            0
        ),
        "claude_reordered_one" => payload!(
            br#"{"message":{"role":"user","content":"C44 question"},"timestamp":"2026-01-01T00:00:00.000Z","uuid":"C44-U","type":"user"}
"#,
            "f2dac9bee63a920e2c576e79ca385e83337bd70cdec37cb36d49eff0e5ec48b5",
            1,
            1,
            0
        ),
        "claude_different_one" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C14 different message"}}
"#,
            "2b2f81fc6f265e01c029dbaf86f6398170d66f246015c5f8a6a9098625ce9d79",
            1,
            1,
            0
        ),
        "claude_no_lf_one" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}"#,
            "96968d7ad96138b93b2c243665fb05e3dc5a69a743355240d116c1cbfff0ef1a",
            1,
            1,
            0
        ),
        "empty_jsonl" => payload!(
            b"",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            0,
            0,
            0
        ),
        "array_zero" => payload!(
            b"[]\n",
            "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570",
            1,
            0,
            0
        ),
        "object_zero" => payload!(
            b"{}\n",
            "ca3d163bab055381827226140568f3bef7eaac187cebd76878e0b63e9e442356",
            1,
            0,
            0
        ),
        "zero_prefix" => payload!(
            b"[]\n{}\n",
            "fa1ab896c1df8845e1d03e3c34533776e45902123a4df060b4ddd2ce54df65eb",
            2,
            0,
            0
        ),
        "zero_no_lf" => payload!(
            b"[]",
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            1,
            0,
            0
        ),
        "bad_unterminated_tail" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
{"type":"#,
            "a519b04c7476c04b2cc9adf7d2f675a4a1dd3df8f07a89bb1e074ed61fdac5f0",
            2,
            1,
            1
        ),
        "claude_parse_failed" => payload!(
            br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
{"type":"assistant","uuid":"C44-A","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"assistant","content":[{"type":"text","text":"C44 answer"}],"model":"C44-model"}}
{C44_BAD_JSON}
"#,
            "effcc439599d87c1c49b885f4470e0bfa4e981cc0b3790cc9aecb3e859b79b25",
            3,
            2,
            1
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
            "2fdf8eb31971bfa0603cb64dd6d8f4305c0463504e5447266df72411bb0a2118",
            1,
            2,
            0
        ),
        "codex_jsonl" => payload!(
            br#"{"timestamp":"2026-01-01T00:00:00.000Z","type":"session_meta","payload":{"id":"C44-CODEX","cwd":"/synthetic/c44-project","cli_version":"0.42.0"}}
{"timestamp":"2026-01-01T00:00:01.000Z","type":"response_item","payload":{"type":"message","id":"C44-U","role":"user","content":[{"type":"input_text","text":"C44 question"}]}}
{"timestamp":"2026-01-01T00:00:02.000Z","type":"response_item","payload":{"type":"message","id":"C44-A","role":"assistant","content":[{"type":"output_text","text":"C44 answer"}]}}
"#,
            "d50dd595f1a3a3111fffc9bdb0eff1059826071ab4164a6fc878b284b7fad3c6",
            3,
            2,
            0
        ),
        "legacy_openclaw" => payload!(
            br#"{"type":"session","id":"s1","timestamp":"2026-02-01T16:00:00.000Z","cwd":"/synthetic/openclaw"}
{"type":"message","id":"m1","timestamp":"2026-02-01T16:00:01.000Z","message":{"role":"user","content":[{"type":"text","text":"C14_LEGACY_TEXT"}]}}
"#,
            "c14-legacy-openclaw-fixture-sha256-not-frozen",
            2,
            1,
            0
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
            "b1f4f4c63f2a33b69c518c6fcab467b2d627e8df2843a7c2774f080177a01eec",
            1,
            2,
            0
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

/// Independently calibrated synthetic material formula.
///
/// These values exercise the same canonical config/normalizer/context/safety/
/// identity formulas the runtime uses, on a self-contained synthetic vector.
/// The expected digests were reproduced independently from the stdlib SHA/JSON
/// equations; nothing is read back from a candidate run, and the runtime
/// old-material identity is untouched.
fn assert_synthetic_material_formula() {
    let scan_root = "/synthetic/source-restore/array-zero/.claude/projects";
    let declaration = serde_json::json!({
        "manifest_id": "frozen-array_zero",
        "identity_namespace": "local",
        "connector": "claude_code",
        "scan_root": scan_root,
        "relative_locator": "c14/session.jsonl",
        "role": "primary_session_log",
        "origin": {"source_id":"local","kind":"local","host":null,"source_version":null},
        "platform": null,
        "workspace_rewrites": []
    });
    let effective = effective_config_material(&declaration);
    let effective_digest = sha256_canonical(&effective);
    assert_eq!(
        effective_digest, "361a9fa862c1bb03b47f9cfa9ff19cde7dfe0540ebf6d63c2c54f0ea60b33cf8",
        "synthetic effective_config_digest"
    );
    let normalizer = sha256_canonical(&serde_json::json!([
        NORMALIZER_DOMAIN,
        FAD_PIN,
        "cass-source-mapping/2",
        effective_digest,
    ]));
    assert_eq!(
        normalizer, "ec1d6deaf860c3d44a5f36ff807d834acd97f27ccc93e49a8dcfa6037f2515aa",
        "synthetic normalizer_id"
    );
    let wire = parser_context_wire(&declaration, &effective_digest);
    assert_eq!(
        sha256_canonical(&wire),
        "c28fb1e8f6b4af0c1c42eb939c80828aaaf6e310ae236a7fdaf9044965f4dad9",
        "synthetic context_digest"
    );
    let safety = sha256_canonical(&serde_json::json!([
        SAFETY_CONTRACT,
        EXCLUSION_EPOCH,
        REDACTION_FINGERPRINT,
        "/synthetic/source-restore/array-zero/fixed.toml",
        "9ee6b90930f70c85446de56cc5475f77ecfcfb923408d706cf43da7634ba02fa",
        "ea8895d8b90a2b60ed5e31867e5e4c965f07e70b7e321a231d3dd9af16565a08",
        true,
    ]));
    assert_eq!(
        safety, "ba22433ba88eb5a5ad296bee0021eccb27075369b2db77c1d8c6370ce4f0f376",
        "synthetic safety_contract_id"
    );
    let tuple = [
        Some("cass.source-input/2"),
        Some("local"),
        Some("local"),
        Some("claude_code"),
        Some(scan_root),
        Some("c14/session.jsonl"),
        Some("primary_session_log"),
        Some("local"),
        None,
        None,
        None,
        Some("c28fb1e8f6b4af0c1c42eb939c80828aaaf6e310ae236a7fdaf9044965f4dad9"),
        Some("37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570"),
        Some("ec1d6deaf860c3d44a5f36ff807d834acd97f27ccc93e49a8dcfa6037f2515aa"),
        Some("ba22433ba88eb5a5ad296bee0021eccb27075369b2db77c1d8c6370ce4f0f376"),
    ];
    assert_eq!(
        sha256_hex(canonical_tuple(&tuple).as_bytes()),
        "809ae8e2ac1659cc06d472d4111a0c9a25fdbb57edbfa2cb0f0b87b1542275d6",
        "synthetic input_key"
    );
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
    /// Connector-shaped logical path relative to HOME.
    logical: &'static str,
    payload_name: &'static str,
}

fn unique_mtime() -> std::time::SystemTime {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let sequence = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + sequence)
}

/// Write one fixture source and give it a unique mtime.
///
/// The raw-mirror blob cache keys on the source's path, size and mtime. Two
/// different payloads of the same size written inside one mtime tick can make
/// the second capture reuse the first blob (and therefore the same manifest),
/// which turns a two-position fixture into an ambiguous single identity.
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
    payload_name: &'static str,
    spec: Spec,
}

struct World {
    tmp: TempDir,
    home: PathBuf,
    xdg_config: PathBuf,
    xdg_data: PathBuf,
    xdg_cache: PathBuf,
    xdg_state: PathBuf,
    tmpdir: PathBuf,
    cwd: PathBuf,
    index_data: PathBuf,
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
        let xdg_state = tmp.path().join("xdg-state");
        let tmpdir = tmp.path().join("tmpdir");
        let cwd = tmp.path().join("cwd");
        let index_data = tmp.path().join("index-data");
        let data_dir = tmp.path().join("cass-data");
        let scratch = tmp.path().join("scratch");
        for path in [
            &home,
            &xdg_config,
            &xdg_data,
            &xdg_cache,
            &xdg_state,
            &tmpdir,
            &cwd,
            &index_data,
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
            xdg_state,
            tmpdir,
            cwd,
            index_data,
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
            xdg_state: &self.xdg_state,
            tmpdir: &self.tmpdir,
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
            payload_name: spec.payload_name,
            spec,
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

    /// Capture the named payload again at the same logical path. A different
    /// payload or a different origin kind produces a distinct manifest, which
    /// is a second position in the same identity group.
    fn source_variant(&self, spec: &Spec, payload_name: &'static str) -> Source {
        let live_path = self.home.join(spec.logical);
        write_source(&live_path, payload(payload_name).bytes);
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
        let declaration = declaration_for(spec, &capture, &live_path);
        Source {
            capture,
            live_path,
            declaration,
            payload_name,
            spec: Spec {
                provider: spec.provider,
                source_id: spec.source_id,
                origin_kind: spec.origin_kind,
                origin_host: spec.origin_host,
                connector: spec.connector,
                logical: spec.logical,
                payload_name,
            },
        }
    }

    fn rewrite_manifest_times(
        &self,
        capture: &RawMirrorCaptureRecord,
        captured_at_ms: i64,
        source_mtime_ms: i64,
    ) {
        let path = self
            .data_dir
            .join("raw-mirror")
            .join("v1")
            .join(&capture.manifest_relative_path);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("read the manifest"))
                .expect("decode the manifest");
        manifest["captured_at_ms"] = serde_json::json!(captured_at_ms);
        manifest["source_mtime_ms"] = serde_json::json!(source_mtime_ms);
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap())
            .expect("write the manifest times");
        let digest = coding_agent_search::raw_mirror::recompute_manifest_blake3(
            &self.data_dir,
            &capture.manifest_relative_path,
        )
        .expect("recompute the manifest self digest");
        manifest["manifest_blake3"] = serde_json::json!(digest);
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap())
            .expect("write the manifest digest");
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
        "identity_namespace": "C14_NAMESPACE",
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
        // The default mode publishes the serialised effective rule set under
        // `data_dir/source-configs/v1/<sha>.toml`; this is that exact encoding.
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
        "code_version": CURRENT_CODE_VERSION,
        "fad_pin": FAD_PIN,
        "mapping_domain": MAPPING_DOMAIN,
        "exclusion_epoch": CURRENT_EXCLUSION_EPOCH,
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
    let config_identity = "C14_CONFIG_IDENTITY";
    // The safety identity embeds the real config identity; callers replace it
    // with the identity the run actually uses (explicit path or content).
    let safety_contract_id = safety_contract(config_identity);
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
        CURRENT_EXCLUSION_EPOCH,
        REDACTION_FINGERPRINT,
        config_identity,
        sha256_hex(FIXED_SAFETY.as_bytes()),
        four_arrays_digest(),
        true,
    ]))
}

/// The `safety_contract_id` for one expected binding must match the profile's
/// `config_source_identity`. The helper above uses a placeholder for the first
/// pass; this rewrites it for the concrete identity.
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

fn expected_contexts_value(sources: &[&Source]) -> serde_json::Value {
    let mut inputs: Vec<serde_json::Value> = sources
        .iter()
        .map(|source| source.declaration.clone())
        .collect();
    inputs.sort_by(|left, right| {
        left["manifest_id"]
            .as_str()
            .unwrap()
            .as_bytes()
            .cmp(right["manifest_id"].as_str().unwrap().as_bytes())
    });
    serde_json::json!({ "schema": CONTEXT_SCHEMA, "inputs": inputs })
}

// ---------------------------------------------------------------------------
// CLI argument builders
// ---------------------------------------------------------------------------

fn plan_args(
    world: &World,
    contexts: Option<&Path>,
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
        "c14-snapshot-root".to_string(),
        "--json".to_string(),
    ];
    if let Some(contexts) = contexts {
        args.push("--source-contexts".into());
        args.push(contexts.to_string_lossy().into_owned());
    }
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
    contexts: Option<&Path>,
    safety: Option<&Path>,
    journal: &Path,
) -> Vec<String> {
    let mut args = plan_args(world, contexts, safety, None);
    args.push("--apply".into());
    args.push("--journal".into());
    args.push(journal.to_string_lossy().into_owned());
    args.push("--generation".into());
    args.push("c14-generation".into());
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

fn sql_count(db: &Path, sql: &str) -> i64 {
    let mut storage = FrankenStorage::open_readonly(db).expect("open the candidate db readonly");
    let count = storage
        .raw()
        .query_row_map(sql, &[], |row| row.get_typed(0))
        .expect("count the rows");
    storage.close_best_effort_in_place();
    count
}

/// Task15: a legal source New item completes; the exact counts were already
/// asserted by the native and zero tables, so this checks the terminal shape.
fn assert_source_new_completes(
    case_dir: &CaseDir,
    world: &World,
    journal_path: &Path,
    id: &str,
) {
    let recover = run_cli(
        case_dir,
        "recover",
        &recover_args(journal_path),
        &[],
        &world.env(),
    );
    assert_eq!(
        recover.rc,
        Some(0),
        "{id}: recover must complete: {}",
        String::from_utf8_lossy(&recover.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&recover.stdout).expect("recover JSON");
    let restored = report["restored"].as_u64().unwrap_or(0);
    let source_only = report["source_only_completed"].as_u64().unwrap_or(0);
    assert_eq!(
        restored + source_only,
        1,
        "{id}: the item lands in exactly one outcome cell"
    );
    assert_eq!(
        sql_count(&world.db, "SELECT COUNT(*) FROM source_inputs"),
        1,
        "{id}: one source input"
    );
    assert_eq!(
        sql_count(
            &world.db,
            "SELECT COUNT(*) FROM operation_commit_receipt \
             WHERE operation = 'source_input_activation_v1' AND state = 'committed'"
        ),
        1,
        "{id}: the source activation receipt"
    );
    assert_eq!(
        sql_count(
            &world.db,
            "SELECT COUNT(*) FROM operation_commit_receipt \
             WHERE operation = 'mirror-restore-new' AND state = 'committed'"
        ),
        1,
        "{id}: the restore receipt"
    );
    assert_eq!(
        journal_json(journal_path)["state"],
        serde_json::json!("closure-verified"),
        "{id}: terminal journal"
    );
}

/// Task15 terminal state for a legal source New planned item: the recover
/// completes it in one transaction and writes both receipts.
fn assert_source_new_completed(
    case_dir: &CaseDir,
    world: &World,
    journal_path: &Path,
    id: &str,
    records: u64,
    messages: u64,
) {
    assert_source_new_completes(case_dir, world, journal_path, id);
    assert_eq!(
        sql_count(&world.db, "SELECT COUNT(*) FROM source_records"),
        records as i64,
        "{id}: source records"
    );
    assert_eq!(
        sql_count(&world.db, "SELECT COUNT(*) FROM conversations"),
        if messages == 0 { 0 } else { 1 },
        "{id}: conversations"
    );
    assert_eq!(
        sql_count(&world.db, "SELECT COUNT(*) FROM messages"),
        messages as i64,
        "{id}: messages"
    );
}

fn assert_journal_materials(
    journal: &serde_json::Value,
    contexts_value: &serde_json::Value,
    profile: &serde_json::Value,
) {
    assert_eq!(journal["schema_version"], 4, "journal4 version");
    assert_eq!(
        journal["source_contexts"], *contexts_value,
        "source_contexts must be the actual P-union-S declarations"
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
    assert!(
        journal["analytics_now_ms"].is_i64(),
        "analytics_now_ms is a number"
    );
    assert_eq!(journal["committed"], serde_json::json!([]));
    assert_eq!(journal["published"], serde_json::json!([]));
}

// ---------------------------------------------------------------------------
// Case tables
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct NativeCase {
    id: &'static str,
    payload: &'static str,
    records: u64,
    messages: u64,
    kind: &'static str,
    valid: bool,
}

const NATIVE_CASES: &[NativeCase] = &[
    NativeCase {
        id: "native-claude_one",
        payload: "claude_one",
        records: 1,
        messages: 1,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-claude_two",
        payload: "claude_two",
        records: 2,
        messages: 2,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-claude_three",
        payload: "claude_three",
        records: 3,
        messages: 3,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-claude_reordered_one",
        payload: "claude_reordered_one",
        records: 1,
        messages: 1,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-claude_different_one",
        payload: "claude_different_one",
        records: 1,
        messages: 1,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-claude_no_lf_one",
        payload: "claude_no_lf_one",
        records: 1,
        messages: 1,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-empty_jsonl",
        payload: "empty_jsonl",
        records: 0,
        messages: 0,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-array_zero",
        payload: "array_zero",
        records: 1,
        messages: 0,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-object_zero",
        payload: "object_zero",
        records: 1,
        messages: 0,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-zero_prefix",
        payload: "zero_prefix",
        records: 2,
        messages: 0,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-zero_no_lf",
        payload: "zero_no_lf",
        records: 1,
        messages: 0,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-bad_unterminated_tail",
        payload: "bad_unterminated_tail",
        records: 2,
        messages: 1,
        kind: "source_restore_material_mismatch",
        valid: false,
    },
    NativeCase {
        id: "native-claude_parse_failed",
        payload: "claude_parse_failed",
        records: 3,
        messages: 2,
        kind: "source_restore_material_mismatch",
        valid: false,
    },
    NativeCase {
        id: "native-claude_document",
        payload: "claude_document",
        records: 1,
        messages: 2,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-codex_jsonl",
        payload: "codex_jsonl",
        records: 3,
        messages: 2,
        kind: "complete",
        valid: true,
    },
    NativeCase {
        id: "native-codex_document",
        payload: "codex_document",
        records: 1,
        messages: 2,
        kind: "complete",
        valid: true,
    },
];

fn native_spec(payload_name: &'static str) -> Spec {
    let (provider, connector, logical) = match payload_name {
        "codex_jsonl" => (
            "codex",
            "codex",
            ".codex/sessions/2026/08/rollout-c14.jsonl",
        ),
        "codex_document" => ("codex", "codex", ".codex/sessions/2026/08/rollout-c14.json"),
        "claude_document" => (
            "claude",
            "claude_code",
            ".claude/projects/C14-ws/session.json",
        ),
        _ => (
            "claude",
            "claude_code",
            ".claude/projects/C14-ws/C14-session.jsonl",
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

// ---------------------------------------------------------------------------
// r14_01 · native formats and zero-message sources
// ---------------------------------------------------------------------------

#[test]
fn r14_01_native_formats_and_zero() {
    assert_synthetic_material_formula();
    let root = result_root();
    for case in NATIVE_CASES {
        let case_dir = CaseDir::new(&root, "r14_01_native_formats_and_zero", case.id);
        let world = World::new();
        let source = world.source(native_spec(case.payload));
        let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, true);
        let journal_path = world.tmp.path().join("restore-journal.json");
        let sentinel = case_dir.join("pause.sentinel");

        if case.valid {
            let before_db = db_digest(&world.db);
            let before_mirror = mirror_digest(&world.data_dir);
            let args = apply_args(
                &world,
                Some(&contexts_path),
                Some(&world.fixed),
                &journal_path,
            );
            let paused = run_paused(
                &case_dir,
                "apply-paused",
                &args,
                &[],
                &world.env(),
                &sentinel,
            );
            assert!(paused.rc.is_none(), "the planned pause child is SIGKILLed");
            let journal = journal_json(&journal_path);
            case_dir.write(
                "journal.planned.json",
                &std::fs::read(&journal_path).unwrap(),
            );
            assert_eq!(journal["state"], "planned");
            assert_journal_materials(&journal, &contexts_value, &profile);
            let planned = journal["planned"].as_array().expect("planned array");
            assert_eq!(planned.len(), 1, "{case:?}: one planned item");
            let expected_binding = expected_binding_with_identity(
                &source.declaration,
                payload(case.payload),
                &profile,
            );
            assert_eq!(planned[0]["manifest_id"], source.capture.manifest_id);
            assert_eq!(planned[0]["action"]["kind"], "restore-new");
            assert_eq!(planned[0]["source_binding"], expected_binding);
            assert_eq!(
                db_digest(&world.db),
                before_db,
                "planned must not write the DB"
            );
            assert_eq!(
                mirror_digest(&world.data_dir),
                before_mirror,
                "planned must not write the mirror"
            );

            assert_source_new_completed(
                &case_dir,
                &world,
                &journal_path,
                case.id,
                case.records,
                case.messages,
            );
        } else {
            let args = plan_args(&world, Some(&contexts_path), Some(&world.fixed), None);
            let planned = run_cli(&case_dir, "plan", &args, &[], &world.env());
            assert_eq!(planned.rc, Some(1), "bad payload must be refused");
            assert_kind(&planned, case.kind);
            assert!(!journal_path.exists(), "a refused plan writes no journal");
        }

        let expected = serde_json::json!({
            "case": case.id,
            "payload": case.payload,
            "expected_records": case.records,
            "expected_messages": case.messages,
            "expected_kind": case.kind,
            "valid_before_install": case.valid,
            "manifest_id": source.capture.manifest_id,
            "profile": profile,
            "binding": if case.valid { expected_binding_with_identity(&source.declaration, payload(case.payload), &profile) } else { serde_json::Value::Null },
        });
        case_dir.write_json("expected.json", &expected);
        case_dir.write("PASS", b"ok\n");
        eprintln!(
            "R14_CASE test=r14_01_native_formats_and_zero case={} result=pass",
            case.id
        );
    }
}

// ---------------------------------------------------------------------------
// r14_02 · frozen material restart
// ---------------------------------------------------------------------------

fn write_default_safety(world: &World, poisoned: bool) {
    let dir = world.xdg_config.join("cass");
    std::fs::create_dir_all(&dir).expect("create the config tier");
    let body = if poisoned {
        "memory_files = [\"C14_UNMATCHED_RULE_B.md\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n"
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

#[derive(Clone, Copy, Debug)]
struct RestartCase {
    id: &'static str,
    mode: &'static str,
    condition: &'static str,
    kind: &'static str,
}

const RESTART_CASES: &[RestartCase] = &[
    RestartCase {
        id: "default-content-valid",
        mode: "default-content",
        condition: "valid",
        kind: "complete",
    },
    RestartCase {
        id: "default-content-fixed-copy-missing",
        mode: "default-content",
        condition: "fixed-copy-missing",
        kind: "source_restore_material_mismatch",
    },
    RestartCase {
        id: "default-content-fixed-copy-content-changed",
        mode: "default-content",
        condition: "fixed-copy-content-changed",
        kind: "source_restore_material_mismatch",
    },
    RestartCase {
        id: "explicit-path-valid",
        mode: "explicit-path",
        condition: "valid",
        kind: "complete",
    },
    RestartCase {
        id: "explicit-path-fixed-copy-missing",
        mode: "explicit-path",
        condition: "fixed-copy-missing",
        kind: "source_restore_material_mismatch",
    },
    RestartCase {
        id: "explicit-path-fixed-copy-content-changed",
        mode: "explicit-path",
        condition: "fixed-copy-content-changed",
        kind: "source_restore_material_mismatch",
    },
];

#[test]
fn r14_02_frozen_material_restart() {
    assert_synthetic_material_formula();
    let root = result_root();
    for case in RESTART_CASES {
        let case_dir = CaseDir::new(&root, "r14_02_frozen_material_restart", case.id);
        let world = World::new();
        if case.mode == "default-content" {
            write_default_safety(&world, false);
        }
        let source = world.source(native_spec("claude_one"));
        let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
        let explicit = case.mode == "explicit-path";
        let safety = explicit.then_some(world.fixed.as_path());
        let profile = expected_profile(&world, explicit);
        let journal_path = world.tmp.path().join("restore-journal.json");
        let before_db = db_digest(&world.db);
        let before_mirror = mirror_digest(&world.data_dir);

        let args = apply_args(&world, Some(&contexts_path), safety, &journal_path);
        run_paused(
            &case_dir,
            "apply-paused",
            &args,
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let journal = journal_json(&journal_path);
        assert_journal_materials(&journal, &contexts_value, &profile);
        assert_eq!(journal["state"], "planned");
        case_dir.write(
            "journal.planned.json",
            &std::fs::read(&journal_path).unwrap(),
        );

        // Planned sentinel reached: end the child, delete the original contexts
        // and the live source, then mutate only what this case names.
        std::fs::remove_file(&contexts_path).expect("delete the original contexts");
        std::fs::remove_file(&source.live_path).expect("delete the live source");
        let fixed_copy = PathBuf::from(
            journal["source_profile"]["fixed_copy_path"]
                .as_str()
                .expect("the journal names the fixed copy"),
        );
        case_dir.write("fixed-copy.path", fixed_copy.to_string_lossy().as_bytes());
        match (case.mode, case.condition) {
            ("default-content", "valid") => {
                // Poison the live discovery tier: recovery must not rediscover.
                write_default_safety(&world, true);
            }
            ("default-content", "fixed-copy-missing") | ("explicit-path", "fixed-copy-missing") => {
                std::fs::remove_file(&fixed_copy).expect("remove the fixed copy");
            }
            ("default-content", "fixed-copy-content-changed")
            | ("explicit-path", "fixed-copy-content-changed") => {
                std::fs::write(
                    &fixed_copy,
                    "memory_files = [\"C14_CHANGED_RULE.md\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n",
                )
                .expect("change the fixed copy bytes");
            }
            ("explicit-path", "valid") => {
                // The explicit file *is* the fixed copy; it must stay.
                assert!(fixed_copy.exists());
            }
            other => panic!("unexpected restart case {other:?}"),
        }

        if case.condition == "valid" {
            assert_source_new_completed(&case_dir, &world, &journal_path, case.id, 1, 1);
        } else {
            let recover = run_cli(
                &case_dir,
                "recover",
                &recover_args(&journal_path),
                &[],
                &world.env(),
            );
            assert_eq!(recover.rc, Some(1), "recover must fail closed");
            assert_kind(&recover, case.kind);
            assert_untouched(&world, before_db.clone(), &before_mirror);
            assert_eq!(journal_json(&journal_path)["state"], "planned");
        }

        case_dir.write_json(
            "expected.json",
            &serde_json::json!({
                "case": case.id,
                "mode": case.mode,
                "condition": case.condition,
                "expected_kind": case.kind,
                "profile": profile,
                "contexts": contexts_value,
            }),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!(
            "R14_CASE test=r14_02_frozen_material_restart case={} result=pass",
            case.id
        );
    }
}

// ---------------------------------------------------------------------------
// r14_03 · participation set, access order and short-circuit
// ---------------------------------------------------------------------------

fn declaration_with(
    source: &Source,
    namespace: Option<&str>,
    locator: Option<&str>,
) -> serde_json::Value {
    let mut declaration = source.declaration.clone();
    if let Some(namespace) = namespace {
        declaration["identity_namespace"] = serde_json::json!(namespace);
    }
    if let Some(locator) = locator {
        declaration["relative_locator"] = serde_json::json!(locator);
    }
    declaration
}

fn plan_error(case_dir: &CaseDir, world: &World, contexts: &Path, label: &str) -> RunResult {
    let args = plan_args(world, Some(contexts), Some(&world.fixed), None);
    let result = run_cli(case_dir, label, &args, &[], &world.env());
    case_dir.write(
        "journal.does-not-exist",
        if world.tmp.path().join("restore-journal.json").exists() {
            b"unexpected journal"
        } else {
            b"no journal"
        },
    );
    result
}

fn plan_ok(case_dir: &CaseDir, world: &World, contexts: &Path, label: &str) -> serde_json::Value {
    let out = case_dir.join("plan-report.json");
    let args = plan_args(world, Some(contexts), Some(&world.fixed), Some(&out));
    let result = run_cli(case_dir, label, &args, &[], &world.env());
    assert_eq!(result.rc, Some(0), "plan must succeed: {result:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&result.stdout).expect("plan JSON on stdout");
    value
}

fn group_order(world: &World) -> Vec<coding_agent_search::raw_mirror::RawMirrorManifestView> {
    world.views()
}

#[test]
fn r14_03_participation_and_order() {
    assert_synthetic_material_formula();
    let root = result_root();

    // singleton-missing: the singleton has no declaration; S is still checked.
    {
        let case_dir = CaseDir::new(&root, "r14_03_participation_and_order", "singleton-missing");
        let world = World::new();
        let _source = world.source(native_spec("claude_one"));
        let (contexts, _) = world.write_contexts_inputs(Vec::new());
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_context_invalid");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"source_restore_context_invalid","P":[],"S":[]}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // participant-nonwinner-missing: only the longer winner is declared; the
    // non-winner participant is accessed by the pair callback and refuses.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_03_participation_and_order",
            "participant-nonwinner-missing",
        );
        let world = World::new();
        let mut spec = native_spec("claude_one");
        spec.logical = ".claude/projects/C14-ws/version.jsonl";
        let one = world.source_variant(&spec, "claude_one");
        let two = world.source_variant(&spec, "claude_two");
        let views = group_order(&world);
        let longer = views
            .iter()
            .max_by_key(|view| view.source_size_bytes)
            .expect("two views");
        let winner = if longer.manifest_id == one.capture.manifest_id {
            &one
        } else {
            &two
        };
        let (contexts, _) = world.write_contexts(&[winner]);
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_context_invalid");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"source_restore_context_invalid"}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // early-hold-third: three raw-prefix positions at one path. The first two
    // (manifest-id order) get an inverted mtime so the first pair HOLDs before
    // the third position is ever accessed.
    for (case_id, third_declaration) in [
        ("early-hold-third-missing", None),
        ("early-hold-third-semantic-bad", Some("wrong.jsonl")),
        ("early-hold-third-valid-unused", Some("session.jsonl")),
    ] {
        let case_dir = CaseDir::new(&root, "r14_03_participation_and_order", case_id);
        let world = World::new();
        let mut spec = native_spec("claude_one");
        spec.logical = ".claude/projects/C14-ws/early.jsonl";
        let one = world.source_variant(&spec, "claude_one");
        let two = world.source_variant(&spec, "claude_two");
        let three = world.source_variant(&spec, "claude_three");
        let by_id: BTreeMap<String, &Source> = [
            (one.capture.manifest_id.clone(), &one),
            (two.capture.manifest_id.clone(), &two),
            (three.capture.manifest_id.clone(), &three),
        ]
        .into_iter()
        .collect();
        let order: Vec<&Source> = world
            .views()
            .iter()
            .map(|view| *by_id.get(&view.manifest_id).expect("captured source"))
            .collect();
        let first = order[0];
        let second = order[1];
        let third = order[2];
        let (short, long) = if payload(first.payload_name).bytes.len()
            <= payload(second.payload_name).bytes.len()
        {
            (first, second)
        } else {
            (second, first)
        };
        world.rewrite_manifest_times(&short.capture, 1000, 2000);
        world.rewrite_manifest_times(&long.capture, 1000, 1000);
        let mut inputs = vec![
            declaration_with(first, None, None),
            declaration_with(second, None, None),
        ];
        if let Some(locator) = third_declaration {
            inputs.push(declaration_with(third, None, Some(locator)));
        }
        let (contexts, _) = world.write_contexts_inputs(inputs);
        let summary = plan_ok(&case_dir, &world, &contexts, "plan");
        assert_eq!(
            summary["holds_by_reason"]["version-time-conflict"], 1,
            "{case_id}: the first pair must HOLD on the time inversion"
        );
        let versions = summary["source_versions"]
            .as_array()
            .expect("source_versions present");
        assert_eq!(
            versions.len(),
            2,
            "{case_id}: the third position is never visited"
        );
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"plan-hold","P":[0,1],"S":[],"version_ids": versions.iter().map(|v| v["manifest_id"].clone()).collect::<Vec<_>>()}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // unknown-id: a declaration that does not name a discovered manifest.
    {
        let case_dir = CaseDir::new(&root, "r14_03_participation_and_order", "unknown-id");
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let mut unknown = source.declaration.clone();
        unknown["manifest_id"] = serde_json::json!("c14-unknown-manifest");
        let (contexts, _) = world.write_contexts_inputs(vec![source.declaration.clone(), unknown]);
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_context_invalid");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"source_restore_context_invalid"}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // nonfirst-id: a known openclaw manifest declared for the first batch.
    {
        let case_dir = CaseDir::new(&root, "r14_03_participation_and_order", "nonfirst-id");
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let mut openclaw_spec = native_spec("codex_jsonl");
        openclaw_spec.provider = "openclaw";
        openclaw_spec.connector = "claude_code";
        openclaw_spec.logical = ".openclaw/agents/c14.jsonl";
        let openclaw = world.source_variant(&openclaw_spec, "codex_jsonl");
        let (contexts, _) = world.write_contexts_inputs(vec![
            source.declaration.clone(),
            openclaw.declaration.clone(),
        ]);
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_context_invalid");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"source_restore_context_invalid"}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // unused-id-duplicate: the same known ID twice.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_03_participation_and_order",
            "unused-id-duplicate",
        );
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let (contexts, _) = world
            .write_contexts_inputs(vec![source.declaration.clone(), source.declaration.clone()]);
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_context_ambiguous");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"source_restore_context_ambiguous"}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // sameblob-two-identities-valid: identical bytes under local and ssh.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_03_participation_and_order",
            "sameblob-two-identities-valid",
        );
        let world = World::new();
        let mut local = native_spec("claude_one");
        local.logical = ".claude/projects/C14-ws/same.jsonl";
        let first = world.source_variant(&local, "claude_one");
        let mut ssh = local;
        ssh.origin_kind = "ssh";
        let second = world.source_variant(&ssh, "claude_one");
        let (contexts, contexts_value) = world.write_contexts(&[&first, &second]);
        let profile = expected_profile(&world, true);
        let journal = world.tmp.path().join("restore-journal.json");
        let before_db = db_digest(&world.db);
        let before_mirror = mirror_digest(&world.data_dir);
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(&world, Some(&contexts), Some(&world.fixed), &journal),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let value = journal_json(&journal);
        assert_journal_materials(&value, &contexts_value, &profile);
        let by_id: BTreeMap<String, &Source> = [
            (first.capture.manifest_id.clone(), &first),
            (second.capture.manifest_id.clone(), &second),
        ]
        .into_iter()
        .collect();
        let order: Vec<&Source> = world
            .views()
            .iter()
            .map(|view| *by_id.get(&view.manifest_id).expect("captured source"))
            .collect();
        let planned = value["planned"].as_array().expect("planned");
        assert_eq!(planned.len(), 1);
        let winner = order[0];
        assert_eq!(
            planned[0]["manifest_id"].as_str().unwrap(),
            winner.capture.manifest_id,
            "equal class keeps the first position"
        );
        let expected =
            expected_binding_with_identity(&winner.declaration, payload("claude_one"), &profile);
        assert_eq!(planned[0]["source_binding"], expected);
        assert_eq!(
            db_digest(&world.db),
            before_db,
            "the planned pause must not write the DB"
        );
        assert_eq!(
            mirror_digest(&world.data_dir),
            before_mirror,
            "the planned pause must not write the mirror"
        );
        assert_source_new_completed(
            &case_dir,
            &world,
            &journal,
            "sameblob-two-identities-valid",
            1,
            1,
        );
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"complete","P":[0,1],"S":[0]}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // sameblob-second-missing: only the first position is declared.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_03_participation_and_order",
            "sameblob-second-missing",
        );
        let world = World::new();
        let mut local = native_spec("claude_one");
        local.logical = ".claude/projects/C14-ws/same.jsonl";
        let first = world.source_variant(&local, "claude_one");
        let mut ssh = local;
        ssh.origin_kind = "ssh";
        let second = world.source_variant(&ssh, "claude_one");
        let order: Vec<&Source> = {
            let by_id: BTreeMap<String, &Source> = [
                (first.capture.manifest_id.clone(), &first),
                (second.capture.manifest_id.clone(), &second),
            ]
            .into_iter()
            .collect();
            world
                .views()
                .iter()
                .map(|view| *by_id.get(&view.manifest_id).unwrap())
                .collect()
        };
        let (contexts, _) = world.write_contexts(&[order[0]]);
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_context_invalid");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"source_restore_context_invalid"}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // sameblob-second-bad-binding: a clean but wrong locator is a material
    // mismatch, not a structural ContextInvalid.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_03_participation_and_order",
            "sameblob-second-bad-binding",
        );
        let world = World::new();
        let mut local = native_spec("claude_one");
        local.logical = ".claude/projects/C14-ws/same.jsonl";
        let first = world.source_variant(&local, "claude_one");
        let mut ssh = local;
        ssh.origin_kind = "ssh";
        let second = world.source_variant(&ssh, "claude_one");
        let order: Vec<&Source> = {
            let by_id: BTreeMap<String, &Source> = [
                (first.capture.manifest_id.clone(), &first),
                (second.capture.manifest_id.clone(), &second),
            ]
            .into_iter()
            .collect();
            world
                .views()
                .iter()
                .map(|view| *by_id.get(&view.manifest_id).unwrap())
                .collect()
        };
        let (contexts, _) = world.write_contexts_inputs(vec![
            declaration_with(order[0], None, None),
            declaration_with(order[1], None, Some("wrong.jsonl")),
        ]);
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_material_mismatch");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"source_restore_material_mismatch"}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // left-semantic-error-before-right-parse-error: the first position's
    // declaration fails before the second position's bad payload is reached.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_03_participation_and_order",
            "left-semantic-error-before-right-parse-error",
        );
        let world = World::new();
        let mut spec = native_spec("claude_one");
        spec.logical = ".claude/projects/C14-ws/left.jsonl";
        let tail = world.source_variant(&spec, "bad_unterminated_tail");
        let bad = world.source_variant(&spec, "claude_parse_failed");
        let by_id: BTreeMap<String, &Source> = [
            (tail.capture.manifest_id.clone(), &tail),
            (bad.capture.manifest_id.clone(), &bad),
        ]
        .into_iter()
        .collect();
        let order: Vec<&Source> = world
            .views()
            .iter()
            .map(|v| *by_id.get(&v.manifest_id).unwrap())
            .collect();
        let inputs = vec![
            declaration_with(order[0], Some("   "), None),
            declaration_with(order[1], None, None),
        ];
        case_dir.write_json(
            "group-order.json",
            &serde_json::json!({
                "order": order.iter().map(|s| s.capture.manifest_id.clone()).collect::<Vec<_>>(),
                "payloads": order.iter().map(|s| s.payload_name).collect::<Vec<_>>(),
                "identities": world.views().iter().map(|view| serde_json::json!({
                    "provider": view.provider,
                    "source_id": view.source_id,
                    "origin_kind": view.origin_kind,
                    "origin_host": view.origin_host,
                    "original_path": view.original_path,
                })).collect::<Vec<_>>(),
                "inputs": inputs,
            }),
        );
        let (contexts, _) = world.write_contexts_inputs(inputs);
        case_dir.write("contexts.json", &std::fs::read(&contexts).unwrap());
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_context_invalid");
        case_dir.write_json("expected.json", &serde_json::json!({"kind":"source_restore_context_invalid","reason":"44 step1 before the second position"}));
        case_dir.write("PASS", b"ok\n");
    }

    // left-parse-error-before-right-semantic-error: the first position's bad
    // payload is admitted-failed before the second declaration is touched.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_03_participation_and_order",
            "left-parse-error-before-right-semantic-error",
        );
        let world = World::new();
        let mut spec = native_spec("claude_one");
        spec.logical = ".claude/projects/C14-ws/left.jsonl";
        let tail = world.source_variant(&spec, "bad_unterminated_tail");
        let bad = world.source_variant(&spec, "claude_parse_failed");
        let by_id: BTreeMap<String, &Source> = [
            (tail.capture.manifest_id.clone(), &tail),
            (bad.capture.manifest_id.clone(), &bad),
        ]
        .into_iter()
        .collect();
        let order: Vec<&Source> = world
            .views()
            .iter()
            .map(|v| *by_id.get(&v.manifest_id).unwrap())
            .collect();
        let (contexts, _) = world.write_contexts_inputs(vec![
            declaration_with(order[0], None, None),
            declaration_with(order[1], Some("   "), None),
        ]);
        let result = plan_error(&case_dir, &world, &contexts, "plan");
        assert_eq!(result.rc, Some(1));
        assert_kind(&result, "source_restore_material_mismatch");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"kind":"source_restore_material_mismatch"}),
        );
        case_dir.write("PASS", b"ok\n");
    }

    // sameblob-and-sametime HOLD: both same-blob IDs and the long version are
    // named by real manifest IDs, not by blob hashes or counts.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_03_participation_and_order",
            "sameblob-and-sametime-HOLD-identity-evidence",
        );
        let mut attempt = 0;
        loop {
            attempt += 1;
            assert!(
                attempt <= 40,
                "could not make the two short manifests sort first"
            );
            let world = World::new();
            let mut local = native_spec("claude_one");
            local.logical = ".claude/projects/C14-ws/same.jsonl";
            let first = world.source_variant(&local, "claude_one");
            let mut ssh = local.clone();
            ssh.origin_kind = "ssh";
            let second = world.source_variant(&ssh, "claude_one");
            let long = world.source_variant(&local, "claude_two");
            let short_ids = [
                first.capture.manifest_id.clone(),
                second.capture.manifest_id.clone(),
            ];
            let mut ids: Vec<(String, u64)> = world
                .views()
                .iter()
                .map(|view| (view.manifest_id.clone(), view.source_size_bytes))
                .collect();
            ids.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
            if !(ids[0].1 == 121 && ids[1].1 == 121) {
                continue;
            }
            let by_id: BTreeMap<String, &Source> = [
                (first.capture.manifest_id.clone(), &first),
                (second.capture.manifest_id.clone(), &second),
                (long.capture.manifest_id.clone(), &long),
            ]
            .into_iter()
            .collect();
            let order: Vec<&Source> = world
                .views()
                .iter()
                .map(|v| *by_id.get(&v.manifest_id).unwrap())
                .collect();
            // Equal recorded capture/source times for the two short IDs;
            // short mtime 2000 > long mtime 1000 creates the prefix conflict.
            for short_id in &short_ids {
                let source = by_id.get(short_id).unwrap();
                world.rewrite_manifest_times(&source.capture, 1000, 2000);
            }
            world.rewrite_manifest_times(&long.capture, 1000, 1000);
            let inputs: Vec<serde_json::Value> = order
                .iter()
                .map(|source| declaration_with(source, None, None))
                .collect();
            let (contexts, _) = world.write_contexts_inputs(inputs);
            let out = case_dir.join("plan-report.json");
            let summary = plan_ok(&case_dir, &world, &contexts, "plan");
            let versions = summary["source_versions"]
                .as_array()
                .expect("source_versions");
            assert_eq!(versions.len(), 3);
            let reported: Vec<String> = versions
                .iter()
                .map(|value| value["manifest_id"].as_str().unwrap().to_string())
                .collect();
            let expected_ids: Vec<String> = order
                .iter()
                .map(|s| s.capture.manifest_id.clone())
                .collect();
            assert_eq!(reported, expected_ids);
            let lengths: Vec<u64> = versions
                .iter()
                .map(|value| value["full_byte_len"].as_u64().unwrap())
                .collect();
            assert_eq!(lengths, vec![121, 121, 295]);
            let holds: serde_json::Value = serde_json::from_slice(
                &std::fs::read(out.with_extension("holds.json")).expect("holds ledger"),
            )
            .expect("decode holds ledger");
            let row = &holds[0];
            assert_eq!(row["reason"], "version-time-conflict");
            let ids_in_hold: Vec<String> = row["source_manifest_ids"]
                .as_array()
                .expect("source_manifest_ids")
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                ids_in_hold, expected_ids,
                "all three real IDs in version order"
            );
            case_dir.write_json(
                "expected.json",
                &serde_json::json!({"kind":"plan-hold","P":[0,1,2],"S":[],"source_manifest_ids": expected_ids}),
            );
            case_dir.write("PASS", b"ok\n");
            break;
        }
    }
    eprintln!("R14_CASE test=r14_03_participation_and_order result=pass");
}

// ---------------------------------------------------------------------------
// r14_04 · full sealed bytes, prepared relations and SQL scope
// ---------------------------------------------------------------------------

const RICH_INVOCATION: &[u8] = br#"{"type":"assistant","uuid":"C14_CALL","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"assistant","model":"C14_MODEL","content":[{"type":"text","text":"C14 working"},{"type":"tool_use","id":"C14_TOOL","name":"Read","input":{"file_path":"/synthetic/c14-data.txt"}}]}}
{"type":"user","uuid":"C14_RESULT","timestamp":"2026-01-01T00:00:01.000Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"C14_TOOL","content":"C14 tool output"}]}}
"#;
const RICH_PREFIX: &[u8] = br#"{"type":"assistant","uuid":"C14_CALL","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"assistant","model":"C14_MODEL","content":[{"type":"text","text":"C14 working"},{"type":"tool_use","id":"C14_TOOL","name":"Read","input":{"file_path":"/synthetic/c14-data.txt"}}]}}
"#;

fn capture_payload(world: &World, spec: &Spec, bytes: &[u8]) -> Source {
    let live_path = world.home.join(spec.logical);
    write_source(&live_path, bytes);
    let capture = capture_source_file_with_identity(
        RawMirrorCaptureInput {
            data_dir: &world.data_dir,
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
    let declaration = declaration_for(spec, &capture, &live_path);
    Source {
        capture,
        live_path,
        declaration,
        payload_name: "runtime",
        spec: spec.clone(),
    }
}

fn two_position_world(
    path: &'static str,
    first: &'static str,
    second: &'static str,
    second_kind: &'static str,
) -> (World, Source, Source) {
    let world = World::new();
    let mut one = native_spec(first);
    one.logical = path;
    let a = world.source_variant(&one, first);
    let mut other = one;
    other.origin_kind = second_kind;
    let b = world.source_variant(&other, second);
    (world, a, b)
}

fn order_sources<'a>(world: &World, sources: &[&'a Source]) -> Vec<&'a Source> {
    let by_id: BTreeMap<String, &Source> = sources
        .iter()
        .map(|source| (source.capture.manifest_id.clone(), *source))
        .collect();
    world
        .views()
        .iter()
        .map(|view| *by_id.get(&view.manifest_id).expect("captured source"))
        .collect()
}

fn run_relation_valid(case_dir: &CaseDir, world: &World, sources: &[&Source], winner: &Source) {
    let (contexts, contexts_value) = world.write_contexts(sources);
    let profile = expected_profile(world, true);
    let journal = world.tmp.path().join("restore-journal.json");
    let before_db = db_digest(&world.db);
    let before_mirror = mirror_digest(&world.data_dir);
    run_paused(
        case_dir,
        "apply-paused",
        &apply_args(world, Some(&contexts), Some(&world.fixed), &journal),
        &[],
        &world.env(),
        &case_dir.join("pause.sentinel"),
    );
    let value = journal_json(&journal);
    assert_journal_materials(&value, &contexts_value, &profile);
    let planned = value["planned"].as_array().expect("planned");
    assert_eq!(planned.len(), 1);
    assert_eq!(
        planned[0]["manifest_id"].as_str().unwrap(),
        winner.capture.manifest_id
    );
    assert_eq!(
        planned[0]["source_binding"],
        expected_binding_with_identity(&winner.declaration, payload(winner.payload_name), &profile,)
    );
    assert_eq!(
        db_digest(&world.db),
        before_db,
        "the planned pause must not write the DB"
    );
    assert_eq!(
        mirror_digest(&world.data_dir),
        before_mirror,
        "the planned pause must not write the mirror"
    );
    assert_source_new_completes(case_dir, world, &journal, "relation-valid");
    case_dir.write_json(
        "expected.json",
        &serde_json::json!({"kind":"complete","winner": winner.capture.manifest_id,"profile": profile,"contexts": contexts_value}),
    );
    case_dir.write("PASS", b"ok\n");
}

fn run_relation_hold(case_dir: &CaseDir, world: &World, sources: &[&Source], reason: &str) {
    let (contexts, _) = world.write_contexts(sources);
    let summary = plan_ok(case_dir, world, &contexts, "plan");
    assert_eq!(
        summary["holds_by_reason"][reason], 1,
        "expected exactly one {reason} HOLD: {summary}"
    );
    let versions = summary["source_versions"]
        .as_array()
        .expect("source_versions");
    assert_eq!(
        versions.len(),
        sources.len(),
        "each compared position is visited"
    );
    case_dir.write_json(
        "expected.json",
        &serde_json::json!({"kind":"plan-hold","reason": reason,"positions": sources.len()}),
    );
    case_dir.write("PASS", b"ok\n");
}

#[test]
fn r14_04_full_bytes_and_prepared_relations() {
    assert_synthetic_material_formula();
    let root = result_root();

    // same-fullbytes: identical bytes under local and ssh are one Equal class;
    // the first position is the winner.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_04_full_bytes_and_prepared_relations",
            "same-fullbytes",
        );
        let (world, a, b) = two_position_world(
            ".claude/projects/C14-ws/rel.jsonl",
            "claude_one",
            "claude_one",
            "ssh",
        );
        let order = order_sources(&world, &[&a, &b]);
        run_relation_valid(&case_dir, &world, &[&a, &b], order[0]);
    }
    // byte-prefix: one is a true byte prefix of two; the longer wins.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_04_full_bytes_and_prepared_relations",
            "byte-prefix",
        );
        let (world, a, b) = two_position_world(
            ".claude/projects/C14-ws/rel.jsonl",
            "claude_one",
            "claude_two",
            "local",
        );
        let longer = if a.payload_name == "claude_two" {
            &a
        } else {
            &b
        };
        run_relation_valid(&case_dir, &world, &[&a, &b], longer);
    }
    // different-keys-same-messages: bytes differ, prepared messages are Equal.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_04_full_bytes_and_prepared_relations",
            "different-keys-same-messages",
        );
        let (world, a, b) = two_position_world(
            ".claude/projects/C14-ws/rel.jsonl",
            "claude_one",
            "claude_reordered_one",
            "local",
        );
        let order = order_sources(&world, &[&a, &b]);
        run_relation_valid(&case_dir, &world, &[&a, &b], order[0]);
    }
    // message-divergence: MessageSequence divergence HOLDs.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_04_full_bytes_and_prepared_relations",
            "message-divergence",
        );
        let (world, a, b) = two_position_world(
            ".claude/projects/C14-ws/rel.jsonl",
            "claude_one",
            "claude_different_one",
            "local",
        );
        run_relation_hold(&case_dir, &world, &[&a, &b], "version-diverged");
    }
    // zero-byte-prefix: empty bytes are a true prefix of []\n.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_04_full_bytes_and_prepared_relations",
            "zero-byte-prefix",
        );
        let (world, a, b) = two_position_world(
            ".claude/projects/C14-ws/rel.jsonl",
            "empty_jsonl",
            "array_zero",
            "local",
        );
        let longer = if a.payload_name == "array_zero" {
            &a
        } else {
            &b
        };
        run_relation_valid(&case_dir, &world, &[&a, &b], longer);
    }
    // zero-without-byte-relation: []\n vs {}\n, both zero messages -> Diverged/Bytes.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_04_full_bytes_and_prepared_relations",
            "zero-without-byte-relation",
        );
        let (world, a, b) = two_position_world(
            ".claude/projects/C14-ws/rel.jsonl",
            "array_zero",
            "object_zero",
            "local",
        );
        run_relation_hold(&case_dir, &world, &[&a, &b], "version-diverged");
    }
    // zero-to-one: empty prefix of a one-message source.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_04_full_bytes_and_prepared_relations",
            "zero-to-one",
        );
        let (world, a, b) = two_position_world(
            ".claude/projects/C14-ws/rel.jsonl",
            "empty_jsonl",
            "claude_one",
            "local",
        );
        let longer = if a.payload_name == "claude_one" {
            &a
        } else {
            &b
        };
        run_relation_valid(&case_dir, &world, &[&a, &b], longer);
    }
    // full-no-final-lf: the sealed 120-byte no-LF form is a true prefix of the
    // 121-byte LF-terminated form.
    {
        let case_dir = CaseDir::new(
            &root,
            "r14_04_full_bytes_and_prepared_relations",
            "full-no-final-lf",
        );
        let (world, a, b) = two_position_world(
            ".claude/projects/C14-ws/rel.jsonl",
            "claude_no_lf_one",
            "claude_one",
            "local",
        );
        let longer = if a.payload_name == "claude_one" {
            &a
        } else {
            &b
        };
        run_relation_valid(&case_dir, &world, &[&a, &b], longer);
    }
    eprintln!("R14_CASE test=r14_04_full_bytes_and_prepared_relations relations result=pass");

    // SQL candidate cases: the candidate DB is produced by the accepted
    // ordinary index over the same logical source path.
    struct SqlCase {
        id: &'static str,
        indexed_bytes: &'static [u8],
        expected_reason: Option<&'static str>,
        expected_action: &'static str,
    }
    let sql_cases = [
        SqlCase {
            id: "sql-candidate-equal-with-source-invocations",
            indexed_bytes: RICH_INVOCATION,
            expected_reason: None,
            expected_action: "skip",
        },
        SqlCase {
            id: "sql-candidate-prefix-with-source-invocations",
            indexed_bytes: RICH_PREFIX,
            expected_reason: None,
            expected_action: "replace",
        },
        SqlCase {
            id: "sql-candidate-message-divergence",
            indexed_bytes: payload("claude_different_one").bytes,
            expected_reason: Some("candidate-diverged"),
            expected_action: "hold",
        },
    ];
    for case in sql_cases {
        let case_dir = CaseDir::new(&root, "r14_04_full_bytes_and_prepared_relations", case.id);
        let world = World::new();
        let spec = Spec {
            // The ordinary indexer captures Claude conversations under the DB
            // agent slug, so the restore mirror must use the same spelling for
            // the candidate lookup to bind.
            provider: "claude_code",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            connector: "claude_code",
            logical: ".claude/projects/C14-ws/rich.jsonl",
            payload_name: "runtime",
        };
        // 1. accepted ordinary index of the candidate bytes at the same path.
        let live = world.home.join(spec.logical);
        write_source(&live, case.indexed_bytes);
        let index_args = vec![
            "index".to_string(),
            "--full".to_string(),
            "--data-dir".to_string(),
            world.index_data.to_string_lossy().into_owned(),
            "--db".to_string(),
            world.db.to_string_lossy().into_owned(),
            "--json".to_string(),
        ];
        let indexed = run_cli(&case_dir, "ordinary-index", &index_args, &[], &world.env());
        assert_eq!(
            indexed.rc,
            Some(0),
            "the ordinary index must succeed: {indexed:?}"
        );
        // 2. close that process, then write the full source and capture it.
        write_source(&live, RICH_INVOCATION);
        let source = capture_payload(&world, &spec, RICH_INVOCATION);
        let (contexts, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, true);
        if case.id == "sql-candidate-prefix-with-source-invocations" {
            let journal = world.tmp.path().join("restore-journal.json");
            run_paused(
                &case_dir,
                "apply-paused",
                &apply_args(&world, Some(&contexts), Some(&world.fixed), &journal),
                &[],
                &world.env(),
                &case_dir.join("pause.sentinel"),
            );
            let value = journal_json(&journal);
            assert_journal_materials(&value, &contexts_value, &profile);
            let planned = value["planned"].as_array().expect("planned");
            assert_eq!(planned.len(), 1);
            assert_eq!(planned[0]["action"]["kind"], "replace");
            let recover = run_cli(
                &case_dir,
                "recover",
                &recover_args(&journal),
                &[],
                &world.env(),
            );
            assert_eq!(
                recover.rc,
                Some(0),
                "the legal source Replace must complete: {}",
                String::from_utf8_lossy(&recover.stderr)
            );
            let report: serde_json::Value =
                serde_json::from_slice(&recover.stdout).expect("recover JSON");
            assert_eq!(report["replaced"].as_u64(), Some(1));
            assert_eq!(
                sql_count(
                    &world.db,
                    "SELECT COUNT(*) FROM operation_commit_receipt \
                     WHERE operation = 'mirror-restore-replace' AND detail IS NOT NULL"
                ),
                1,
                "the complete replace C3"
            );
        } else if let Some(reason) = case.expected_reason {
            let summary = plan_ok(&case_dir, &world, &contexts, "plan");
            assert_eq!(summary["holds_by_reason"][reason], 1, "{summary}");
            // F6: a source-versus-SQL HOLD names the real winner manifest ID
            // and never invents a candidate manifest ID.
            let out = case_dir.join("plan-report.json");
            let holds: serde_json::Value = serde_json::from_slice(
                &std::fs::read(out.with_extension("holds.json")).expect("holds ledger"),
            )
            .expect("decode holds ledger");
            assert_eq!(holds.as_array().expect("holds").len(), 1, "{holds}");
            let row = &holds[0];
            assert_eq!(row["reason"], *reason);
            let ids: Vec<String> = row["source_manifest_ids"]
                .as_array()
                .expect("source_manifest_ids must be present for a source HOLD")
                .iter()
                .map(|value| value.as_str().unwrap().to_string())
                .collect();
            assert_eq!(
                ids,
                vec![source.capture.manifest_id.clone()],
                "only the real winner manifest ID may appear"
            );
            let versions = summary["source_versions"]
                .as_array()
                .expect("source_versions");
            assert_eq!(versions.len(), 1, "{summary}");
            assert_eq!(versions[0]["manifest_id"], row["source_manifest_ids"][0]);
        } else {
            let summary = plan_ok(&case_dir, &world, &contexts, "plan");
            assert_eq!(
                summary["skip"], 1,
                "the SQL candidate equals the source: {summary}"
            );
            assert_eq!(summary["planned_actions"], 0);
        }
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({
                "case": case.id,
                "expected_action": case.expected_action,
                "expected_reason": case.expected_reason,
                "source_sha256": sha256_hex(RICH_INVOCATION),
                "profile": profile,
                "contexts": contexts_value,
            }),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!(
            "R14_CASE test=r14_04_full_bytes_and_prepared_relations case={} result=pass",
            case.id
        );
    }
}

// ---------------------------------------------------------------------------
// r14_05 · journal4 strict wire
// ---------------------------------------------------------------------------

fn duplicate_root_member(text: &str, member: &str, value: &serde_json::Value) -> String {
    let addition = format!("\"{member}\":{}", serde_json::to_string(value).unwrap());
    let mut out = text.trim_end().to_string();
    assert!(out.ends_with('}'), "journal root is an object");
    out.pop();
    out.push(',');
    out.push_str(&addition);
    out.push('}');
    out
}

fn duplicate_member_inside(text: &str, object: &str, addition: &str) -> String {
    let count = text.match_indices(object).count();
    assert_eq!(count, 1, "the nested object must occur exactly once");
    let index = text.find(object).expect("nested object present");
    let mut replaced = object.to_string();
    replaced.pop();
    replaced.push(',');
    replaced.push_str(addition);
    replaced.push('}');
    let mut out = String::new();
    out.push_str(&text[..index]);
    out.push_str(&replaced);
    out.push_str(&text[index + object.len()..]);
    out
}

const STRICT_CASES: &[&str] = &[
    "root-missing-source_contexts",
    "root-missing-source_contexts_digest",
    "root-missing-source_profile",
    "planned-missing-source_binding",
    "profile-missing-config_source_identity",
    "profile-missing-fixed_copy_path",
    "profile-missing-fixed_config_sha256",
    "profile-missing-effective_four_arrays_sha256",
    "profile-missing-code_version",
    "profile-missing-fad_pin",
    "profile-missing-mapping_domain",
    "profile-missing-exclusion_epoch",
    "profile-missing-redaction_fingerprint",
    "profile-missing-desensitization_enabled",
    "binding-missing-declaration",
    "binding-missing-context_digest",
    "binding-missing-sealed_sha256",
    "binding-missing-byte_len",
    "binding-missing-normalizer_id",
    "binding-missing-safety_contract_id",
    "binding-missing-input_key",
    "root-null-one",
    "root-null-all-source",
    "root-duplicate-new-key",
    "profile-unknown",
    "profile-duplicate",
    "binding-unknown",
    "binding-duplicate",
    "binding-null-source",
    "binding-byte-len-negative",
    "binding-byte-len-overflow",
    "binding-byte-len-string",
    "binding-declaration-format",
    "contexts-unknown",
    "contexts-duplicate-key",
    "contexts-duplicate-id",
    "contexts-missing-platform",
    "contexts-missing-host",
    "contexts-missing-version",
    "version-1-first",
    "version-3-first",
    "version-unknown-first",
    "analytics-old-default-exception",
    "nullable-platform-host-version",
    "rewrite-agents-omitted",
    "rewrite-agents-null",
];

#[test]
fn r14_05_strict_journal_wire() {
    assert_synthetic_material_formula();
    let root = result_root();
    for case_id in STRICT_CASES {
        let case_dir = CaseDir::new(&root, "r14_05_strict_journal_wire", case_id);
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, true);
        let base_journal = world.tmp.path().join("base-journal.json");
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(
                &world,
                Some(&contexts_path),
                Some(&world.fixed),
                &base_journal,
            ),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let base_bytes = std::fs::read(&base_journal).expect("read the base journal");
        let base: serde_json::Value = serde_json::from_slice(&base_bytes).expect("decode base");
        assert_journal_materials(&base, &contexts_value, &profile);
        case_dir.write("journal.base.json", &base_bytes);

        let mut value = base.clone();
        let mut raw_text: Option<String> = None;
        let expected_kind: &str;
        // Task15: the three legal wire spellings now install instead of
        // stopping at the old install_unavailable boundary.
        let mut completes = false;
        let expects_schema_message = matches!(
            *case_id,
            "version-1-first" | "version-3-first" | "version-unknown-first"
        );
        let mut recompute_binding = false;
        match *case_id {
            "root-missing-source_contexts" => {
                value.as_object_mut().unwrap().remove("source_contexts");
                expected_kind = "source_restore_material_mismatch";
            }
            "root-missing-source_contexts_digest" => {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove("source_contexts_digest");
                expected_kind = "source_restore_material_mismatch";
            }
            "root-missing-source_profile" => {
                value.as_object_mut().unwrap().remove("source_profile");
                expected_kind = "source_restore_material_mismatch";
            }
            "planned-missing-source_binding" => {
                value["planned"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("source_binding");
                expected_kind = "source_restore_material_mismatch";
            }
            id if id.starts_with("profile-missing-") => {
                let member = id.trim_start_matches("profile-missing-");
                value["source_profile"]
                    .as_object_mut()
                    .unwrap()
                    .remove(member);
                expected_kind = "source_restore_material_mismatch";
            }
            id if id.starts_with("binding-missing-") => {
                let member = id.trim_start_matches("binding-missing-");
                value["planned"][0]["source_binding"]
                    .as_object_mut()
                    .unwrap()
                    .remove(member);
                expected_kind = "source_restore_material_mismatch";
            }
            "root-null-one" => {
                value["source_contexts"] = serde_json::Value::Null;
                expected_kind = "source_restore_material_mismatch";
            }
            "root-null-all-source" => {
                value["source_contexts"] = serde_json::Value::Null;
                value["source_contexts_digest"] = serde_json::Value::Null;
                value["source_profile"] = serde_json::Value::Null;
                expected_kind = "source_restore_material_mismatch";
            }
            "root-duplicate-new-key" => {
                let text = serde_json::to_string(&value).unwrap();
                raw_text = Some(duplicate_root_member(
                    &text,
                    "source_profile",
                    &value["source_profile"],
                ));
                expected_kind = "source_restore_material_mismatch";
            }
            "profile-unknown" => {
                value["source_profile"]["c14_unknown_member"] = serde_json::json!(true);
                expected_kind = "source_restore_material_mismatch";
            }
            "profile-duplicate" => {
                let text = serde_json::to_string(&value).unwrap();
                let profile_text = serde_json::to_string(&value["source_profile"]).unwrap();
                raw_text = Some(duplicate_member_inside(
                    &text,
                    &profile_text,
                    "\"config_source_identity\":\"c14-duplicate\"",
                ));
                expected_kind = "source_restore_material_mismatch";
            }
            "binding-unknown" => {
                value["planned"][0]["source_binding"]["c14_unknown_member"] =
                    serde_json::json!(true);
                expected_kind = "source_restore_material_mismatch";
            }
            "binding-duplicate" => {
                let text = serde_json::to_string(&value).unwrap();
                let binding_text =
                    serde_json::to_string(&value["planned"][0]["source_binding"]).unwrap();
                raw_text = Some(duplicate_member_inside(
                    &text,
                    &binding_text,
                    "\"input_key\":\"c14-duplicate\"",
                ));
                expected_kind = "source_restore_material_mismatch";
            }
            "binding-null-source" => {
                value["planned"][0]["source_binding"] = serde_json::Value::Null;
                expected_kind = "source_restore_material_mismatch";
            }
            "binding-byte-len-negative" => {
                value["planned"][0]["source_binding"]["byte_len"] = serde_json::json!(-1);
                expected_kind = "source_restore_material_mismatch";
            }
            "binding-byte-len-overflow" => {
                let text = serde_json::to_string(&value).unwrap();
                let current = value["planned"][0]["source_binding"]["byte_len"].to_string();
                let replaced = text.replacen(
                    &format!("\"byte_len\":{current}"),
                    "\"byte_len\":18446744073709551616",
                    1,
                );
                assert_ne!(replaced, text, "the overflow literal must be inserted");
                raw_text = Some(replaced);
                expected_kind = "source_restore_material_mismatch";
            }
            "binding-byte-len-string" => {
                value["planned"][0]["source_binding"]["byte_len"] = serde_json::json!("1");
                expected_kind = "source_restore_material_mismatch";
            }
            "binding-declaration-format" => {
                value["planned"][0]["source_binding"]["declaration"]["origin"]
                    .as_object_mut()
                    .unwrap()
                    .remove("host");
                expected_kind = "source_restore_material_mismatch";
            }
            "contexts-unknown" => {
                value["source_contexts"]["inputs"][0]["c14_unknown_member"] =
                    serde_json::json!(true);
                expected_kind = "source_restore_context_invalid";
            }
            "contexts-duplicate-key" => {
                let text = serde_json::to_string(&value).unwrap();
                let contexts_text = serde_json::to_string(&value["source_contexts"]).unwrap();
                raw_text = Some(duplicate_member_inside(
                    &text,
                    &contexts_text,
                    &format!("\"schema\":{}", serde_json::json!(CONTEXT_SCHEMA)),
                ));
                expected_kind = "source_restore_context_invalid";
            }
            "contexts-duplicate-id" => {
                let first = value["source_contexts"]["inputs"][0].clone();
                value["source_contexts"]["inputs"]
                    .as_array_mut()
                    .unwrap()
                    .push(first);
                expected_kind = "source_restore_context_ambiguous";
            }
            "contexts-missing-platform" => {
                value["source_contexts"]["inputs"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("platform");
                expected_kind = "source_restore_context_invalid";
            }
            "contexts-missing-host" => {
                value["source_contexts"]["inputs"][0]["origin"]
                    .as_object_mut()
                    .unwrap()
                    .remove("host");
                expected_kind = "source_restore_context_invalid";
            }
            "contexts-missing-version" => {
                value["source_contexts"]["inputs"][0]["origin"]
                    .as_object_mut()
                    .unwrap()
                    .remove("source_version");
                expected_kind = "source_restore_context_invalid";
            }
            "version-1-first" => {
                value["schema_version"] = serde_json::json!(1);
                expected_kind = "mirror_restore_recover_failed";
            }
            "version-3-first" => {
                value["schema_version"] = serde_json::json!(3);
                expected_kind = "mirror_restore_recover_failed";
            }
            "version-unknown-first" => {
                value["schema_version"] = serde_json::json!(999);
                expected_kind = "mirror_restore_recover_failed";
            }
            "analytics-old-default-exception" => {
                value.as_object_mut().unwrap().remove("analytics_now_ms");
                expected_kind = "complete";
                completes = true;
            }
            "nullable-platform-host-version" => {
                value["source_contexts"]["inputs"][0]["platform"] = serde_json::Value::Null;
                value["source_contexts"]["inputs"][0]["origin"]["host"] = serde_json::Value::Null;
                value["source_contexts"]["inputs"][0]["origin"]["source_version"] =
                    serde_json::Value::Null;
                value["planned"][0]["source_binding"]["declaration"] =
                    value["source_contexts"]["inputs"][0].clone();
                recompute_binding = true;
                expected_kind = "complete";
                completes = true;
            }
            "rewrite-agents-omitted" | "rewrite-agents-null" => {
                // Both the missing and null input spellings normalize to the
                // same typed declaration, which omits `agents` on the wire.
                let rewrite = serde_json::json!({
                    "from": "/synthetic/from",
                    "to": "/synthetic/to",
                });
                value["source_contexts"]["inputs"][0]["workspace_rewrites"] =
                    serde_json::json!([rewrite]);
                value["planned"][0]["source_binding"]["declaration"] =
                    value["source_contexts"]["inputs"][0].clone();
                recompute_binding = true;
                expected_kind = "complete";
                completes = true;
            }
            other => panic!("unhandled strict journal case {other}"),
        }

        if recompute_binding {
            let declaration = value["source_contexts"]["inputs"][0].clone();
            let binding =
                expected_binding_with_identity(&declaration, payload("claude_one"), &profile);
            value["planned"][0]["source_binding"] = binding;
            let contexts = value["source_contexts"].clone();
            value["source_contexts_digest"] = serde_json::json!(sha256_canonical(&contexts));
        }

        let bytes = match raw_text {
            Some(text) => text.into_bytes(),
            None => serde_json::to_vec_pretty(&value).expect("encode the mutated journal"),
        };
        let mutated_path = case_dir.join("journal.mutated.json");
        std::fs::write(&mutated_path, &bytes).expect("write the mutated journal");
        if completes {
            assert_source_new_completes(&case_dir, &world, &mutated_path, case_id);
        } else {
            let recover = run_cli(
                &case_dir,
                "recover",
                &recover_args(&mutated_path),
                &[],
                &world.env(),
            );
            assert_eq!(recover.rc, Some(1), "{case_id}: recover must fail closed");
            assert_kind(&recover, expected_kind);
            if expects_schema_message {
                assert!(
                    String::from_utf8_lossy(&recover.stderr)
                        .contains("E-JOURNAL-SCHEMA-MISMATCH"),
                    "{case_id}: the version refusal must name E-JOURNAL-SCHEMA-MISMATCH"
                );
            }
        }
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "expected_kind": expected_kind, "version_gate": expects_schema_message}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!("R14_CASE test=r14_05_strict_journal_wire case={case_id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r14_06 · recomputed material from valid-looking encodings
// ---------------------------------------------------------------------------

const WRONG_SHA: &str = "60025c43da8600b44d3526b2dfb4035c2716159fe871f5a0efa897e6671977c2";

#[test]
fn r14_06_recomputed_material_bindings() {
    assert_synthetic_material_formula();
    let root = result_root();
    let cases = [
        "binding-valid-hex-wrong-context_digest",
        "binding-valid-hex-wrong-sealed_sha256",
        "binding-valid-hex-wrong-normalizer_id",
        "binding-valid-hex-wrong-safety_contract_id",
        "binding-valid-hex-wrong-input_key",
        "profile-material-wrong-config_source_identity",
        "profile-material-wrong-fixed_config_sha256",
        "profile-material-wrong-effective_four_arrays_sha256",
        "profile-material-wrong-code_version",
        "profile-material-wrong-fad_pin",
        "profile-material-wrong-mapping_domain",
        "profile-material-wrong-exclusion_epoch",
        "profile-material-wrong-redaction_fingerprint",
        "profile-material-wrong-desensitization_enabled",
        "aggregate-wrong-digest",
        "binding-byte-len-wrong",
        "cross-input-binding",
    ];
    let wrong = sha256_hex(b"C14_WRONG");
    for case_id in cases {
        let case_dir = CaseDir::new(&root, "r14_06_recomputed_material_bindings", case_id);
        let world = World::new();
        let cross_input = case_id == "cross-input-binding";
        let mut sources = Vec::new();
        let source_a = world.source_variant(
            &Spec {
                provider: "claude_code",
                source_id: "local",
                origin_kind: "local",
                origin_host: None,
                connector: "claude_code",
                logical: ".claude/projects/C14-ws/a.jsonl",
                payload_name: "claude_one",
            },
            "claude_one",
        );
        sources.push(source_a);
        if cross_input {
            sources.push(world.source_variant(
                &Spec {
                    provider: "claude_code",
                    source_id: "local",
                    origin_kind: "local",
                    origin_host: None,
                    connector: "claude_code",
                    logical: ".claude/projects/C14-ws/b.jsonl",
                    payload_name: "claude_one",
                },
                "claude_one",
            ));
        }
        let refs: Vec<&Source> = sources.iter().collect();
        let (contexts_path, contexts_value) = world.write_contexts(&refs);
        let profile = expected_profile(&world, true);
        let base_journal = world.tmp.path().join("base-journal.json");
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(
                &world,
                Some(&contexts_path),
                Some(&world.fixed),
                &base_journal,
            ),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let base: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&base_journal).unwrap()).unwrap();
        assert_journal_materials(&base, &contexts_value, &profile);
        let mut value = base.clone();
        match case_id {
            "binding-valid-hex-wrong-context_digest" => {
                value["planned"][0]["source_binding"]["context_digest"] = serde_json::json!(wrong);
            }
            "binding-valid-hex-wrong-sealed_sha256" => {
                value["planned"][0]["source_binding"]["sealed_sha256"] = serde_json::json!(wrong);
            }
            "binding-valid-hex-wrong-normalizer_id" => {
                value["planned"][0]["source_binding"]["normalizer_id"] = serde_json::json!(wrong);
            }
            "binding-valid-hex-wrong-safety_contract_id" => {
                value["planned"][0]["source_binding"]["safety_contract_id"] =
                    serde_json::json!(wrong);
            }
            "binding-valid-hex-wrong-input_key" => {
                value["planned"][0]["source_binding"]["input_key"] = serde_json::json!(wrong);
            }
            "profile-material-wrong-config_source_identity" => {
                value["source_profile"]["config_source_identity"] =
                    serde_json::json!(format!("content:sha256:{WRONG_SHA}"));
            }
            "profile-material-wrong-fixed_config_sha256" => {
                value["source_profile"]["fixed_config_sha256"] = serde_json::json!(WRONG_SHA);
            }
            "profile-material-wrong-effective_four_arrays_sha256" => {
                value["source_profile"]["effective_four_arrays_sha256"] =
                    serde_json::json!(WRONG_SHA);
            }
            "profile-material-wrong-code_version" => {
                value["source_profile"]["code_version"] =
                    serde_json::json!(format!("cass-source-exclusion/1+redact-v1:{WRONG_SHA}"));
            }
            "profile-material-wrong-fad_pin" => {
                value["source_profile"]["fad_pin"] =
                    serde_json::json!("0000000000000000000000000000000000000000");
            }
            "profile-material-wrong-mapping_domain" => {
                value["source_profile"]["mapping_domain"] =
                    serde_json::json!("cass-source-mapping/999");
            }
            "profile-material-wrong-exclusion_epoch" => {
                value["source_profile"]["exclusion_epoch"] =
                    serde_json::json!("cass-source-exclusion/999");
            }
            "profile-material-wrong-redaction_fingerprint" => {
                value["source_profile"]["redaction_fingerprint"] =
                    serde_json::json!(format!("redact-v1:{WRONG_SHA}"));
            }
            "profile-material-wrong-desensitization_enabled" => {
                value["source_profile"]["desensitization_enabled"] = serde_json::json!(false);
            }
            "aggregate-wrong-digest" => {
                value["source_contexts_digest"] = serde_json::json!(wrong);
            }
            "binding-byte-len-wrong" => {
                let length = value["planned"][0]["source_binding"]["byte_len"]
                    .as_u64()
                    .unwrap();
                value["planned"][0]["source_binding"]["byte_len"] = serde_json::json!(length + 1);
            }
            "cross-input-binding" => {
                let second = value["planned"][1]["source_binding"].clone();
                value["planned"][0]["source_binding"] = second;
            }
            other => panic!("unhandled recomputed material case {other}"),
        }
        let mutated = case_dir.join("journal.mutated.json");
        std::fs::write(&mutated, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        case_dir.write("journal.base.json", &std::fs::read(&base_journal).unwrap());
        let recover = run_cli(
            &case_dir,
            "recover",
            &recover_args(&mutated),
            &[],
            &world.env(),
        );
        assert_eq!(recover.rc, Some(1), "{case_id}: recover must fail closed");
        assert_kind(&recover, "source_restore_material_mismatch");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "expected_kind": "source_restore_material_mismatch", "wrong_sha": wrong}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!("R14_CASE test=r14_06_recomputed_material_bindings case={case_id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r14_07 · material validation precedes every state
// ---------------------------------------------------------------------------

#[test]
fn r14_07_all_seven_states_material_first() {
    assert_synthetic_material_formula();
    let root = result_root();
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
        for side in ["valid", "tampered"] {
            let case_id = format!("{state}-{side}");
            let case_dir = CaseDir::new(&root, "r14_07_all_seven_states_material_first", &case_id);
            let world = World::new();
            let source = world.source(native_spec("claude_one"));
            let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
            let profile = expected_profile(&world, true);
            let base_journal = world.tmp.path().join("base-journal.json");
            let before_db = db_digest(&world.db);
            let before_mirror = mirror_digest(&world.data_dir);
            run_paused(
                &case_dir,
                "apply-paused",
                &apply_args(
                    &world,
                    Some(&contexts_path),
                    Some(&world.fixed),
                    &base_journal,
                ),
                &[],
                &world.env(),
                &case_dir.join("pause.sentinel"),
            );
            let mut value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&base_journal).unwrap()).unwrap();
            assert_journal_materials(&value, &contexts_value, &profile);
            value["state"] = serde_json::json!(state);
            let mut completes = false;
            let expected_kind;
            if side == "tampered" {
                value["planned"][0]["source_binding"]["input_key"] =
                    serde_json::json!(sha256_hex(b"C14_WRONG"));
                expected_kind = "source_restore_material_mismatch";
            } else if state == "planned" {
                // The one genuine first planned state installs.
                expected_kind = "complete";
                completes = true;
            } else {
                // Every other state is synthetic: it claims progress with no
                // real restore receipt, which is a conflict, never a redo.
                expected_kind = "source_restore_receipt_conflict";
            }
            let mutated = case_dir.join("journal.state.json");
            std::fs::write(&mutated, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            if completes {
                assert_source_new_completes(&case_dir, &world, &mutated, &case_id);
            } else {
                let recover = run_cli(
                    &case_dir,
                    "recover",
                    &recover_args(&mutated),
                    &[],
                    &world.env(),
                );
                assert_eq!(recover.rc, Some(1), "{case_id}: recover must fail closed");
                assert_kind(&recover, expected_kind);
                assert_untouched(&world, before_db, &before_mirror);
            }
            case_dir.write_json(
                "expected.json",
                &serde_json::json!({"case": case_id, "state": state, "side": side, "expected_kind": expected_kind}),
            );
            case_dir.write("PASS", b"ok\n");
            eprintln!(
                "R14_CASE test=r14_07_all_seven_states_material_first case={case_id} result=pass"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// r14_08 · CLI conflicts and the legacy front end
// ---------------------------------------------------------------------------

fn openclaw_spec() -> Spec {
    Spec {
        provider: "openclaw/main",
        source_id: "local",
        origin_kind: "local",
        origin_host: None,
        connector: "claude_code",
        logical: ".openclaw/agents/main/sessions/c14.jsonl",
        payload_name: "legacy_openclaw",
    }
}

fn conversation_count(path: &Path) -> i64 {
    let mut storage = FrankenStorage::open_readonly(path).expect("open the candidate database");
    let count = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| {
            row.get_typed(0)
        })
        .expect("count conversations");
    storage.close_best_effort_in_place();
    count
}

#[test]
fn r14_08_cli_and_legacy() {
    assert_synthetic_material_formula();
    let root = result_root();

    // Four parser-level conflicts. Each must fail with the clap usage code 2.
    for (case_id, extra) in [
        (
            "contexts-with-recover",
            vec!["--recover", "--source-contexts"],
        ),
        (
            "safety-with-recover",
            vec!["--recover", "--source-safety-config"],
        ),
        (
            "contexts-with-qualify",
            vec!["--qualify", "--source-contexts"],
        ),
        (
            "safety-with-qualify",
            vec!["--qualify", "--source-safety-config"],
        ),
    ] {
        let case_dir = CaseDir::new(&root, "r14_08_cli_and_legacy", case_id);
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let (contexts_path, _) = world.write_contexts(&[&source]);
        let journal = world.tmp.path().join("journal.json");
        let mut args = vec![
            "mirror-restore".to_string(),
            "--candidate-db".to_string(),
            world.db.to_string_lossy().into_owned(),
            "--data-dir".to_string(),
            world.data_dir.to_string_lossy().into_owned(),
            "--journal".to_string(),
            journal.to_string_lossy().into_owned(),
            "--json".to_string(),
        ];
        for option in &extra {
            args.push((*option).to_string());
            if *option == "--source-contexts" {
                args.push(contexts_path.to_string_lossy().into_owned());
            } else if *option == "--source-safety-config" {
                args.push(world.fixed.to_string_lossy().into_owned());
            }
        }
        let result = run_cli(&case_dir, "clap", &args, &[], &world.env());
        assert_eq!(result.rc, Some(2), "{case_id}: clap conflict must exit 2");
        assert!(!journal.exists(), "a parse-level refusal writes no journal");
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "kind": "clap-conflict", "exit_code": 2}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!("R14_CASE test=r14_08_cli_and_legacy case={case_id} result=pass");
    }

    // legacy-only-valid: an openclaw source keeps the original front end and
    // performs a real restore with no source materials and no configuration
    // discovery.
    {
        let case_id = "legacy-only-valid";
        let case_dir = CaseDir::new(&root, "r14_08_cli_and_legacy", case_id);
        let world = World::new();
        // A poisoned discovery tier: the legacy plan must not read it.
        write_default_safety(&world, true);
        let source = world.source(openclaw_spec());
        let args = apply_args(&world, None, None, &case_dir.join("legacy-journal.json"));
        let result = run_cli(&case_dir, "apply", &args, &[], &world.env());
        assert_eq!(
            result.rc,
            Some(0),
            "legacy restore must succeed: {result:?}"
        );
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).expect("apply JSON");
        assert_eq!(report["restored"], 1);
        assert_eq!(conversation_count(&world.db), 1);
        assert!(
            !world.data_dir.join("source-configs").exists(),
            "legacy-only planning must not publish a source configuration"
        );
        let journal: serde_json::Value =
            serde_json::from_slice(&std::fs::read(case_dir.join("legacy-journal.json")).unwrap())
                .unwrap();
        assert!(journal["source_contexts"].is_null());
        assert!(journal["source_profile"].is_null());
        assert!(journal["planned"][0]["source_binding"].is_null());
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "kind": "original legacy success", "restored": 1}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!("R14_CASE test=r14_08_cli_and_legacy case={case_id} result=pass");
        let _ = source;
    }

    // legacy-plan-with-source-HOLD-participants: the journal records the P
    // materials but only the legacy item is planned. A deleted P-only blob must
    // not be reopened by recovery.
    {
        let case_id = "legacy-plan-with-source-HOLD-participants";
        let case_dir = CaseDir::new(&root, "r14_08_cli_and_legacy", case_id);
        let world = World::new();
        let mut early = native_spec("claude_one");
        early.logical = ".claude/projects/C14-ws/early.jsonl";
        early.provider = "claude_code";
        let one = world.source_variant(&early, "claude_one");
        let two = world.source_variant(&early, "claude_two");
        let three = world.source_variant(&early, "claude_three");
        let by_id: BTreeMap<String, &Source> = [
            (one.capture.manifest_id.clone(), &one),
            (two.capture.manifest_id.clone(), &two),
            (three.capture.manifest_id.clone(), &three),
        ]
        .into_iter()
        .collect();
        let order: Vec<&Source> = world
            .views()
            .iter()
            .map(|v| *by_id.get(&v.manifest_id).unwrap())
            .collect();
        let (short, long) = if payload(order[0].payload_name).bytes.len()
            <= payload(order[1].payload_name).bytes.len()
        {
            (order[0], order[1])
        } else {
            (order[1], order[0])
        };
        world.rewrite_manifest_times(&short.capture, 1000, 2000);
        world.rewrite_manifest_times(&long.capture, 1000, 1000);
        let (contexts_path, contexts_value) = world.write_contexts(&[order[0], order[1]]);
        let legacy = world.source(openclaw_spec());
        let profile = expected_profile(&world, true);
        let journal = case_dir.join("mixed-journal.json");
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(&world, Some(&contexts_path), Some(&world.fixed), &journal),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&journal).unwrap()).unwrap();
        assert_eq!(value["planned"].as_array().unwrap().len(), 1);
        assert_eq!(
            value["planned"][0]["manifest_id"].as_str().unwrap(),
            legacy.capture.manifest_id
        );
        assert!(value["planned"][0]["source_binding"].is_null());
        assert_eq!(value["source_contexts"], contexts_value);
        assert_eq!(value["source_profile"], profile);
        // Delete a blob that only P touched. Recovery must never reopen it.
        let p_only = value["source_contexts"]["inputs"][0]["manifest_id"]
            .as_str()
            .unwrap()
            .to_string();
        let view = world
            .views()
            .into_iter()
            .find(|view| view.manifest_id == *p_only)
            .expect("the P manifest view");
        let blob = world
            .data_dir
            .join("raw-mirror")
            .join("v1")
            .join(&view.blob_relative_path);
        std::fs::remove_file(&blob).expect("delete the P-only blob");
        assert!(!blob.exists());
        let recover = run_cli(
            &case_dir,
            "recover",
            &recover_args(&journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            recover.rc,
            Some(0),
            "legacy recovery must not reopen P blobs: {recover:?}"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&recover.stdout).expect("recover JSON");
        assert_eq!(report["restored"], 1);
        assert_eq!(conversation_count(&world.db), 1);
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "kind": "legacy success plus source HOLD P evidence", "restored": 1, "deleted_p_blob": blob.to_string_lossy()}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!("R14_CASE test=r14_08_cli_and_legacy case={case_id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r14_11 · all-null source materials must still reopen planned manifests
// ---------------------------------------------------------------------------

fn null_source_materials(value: &mut serde_json::Value) {
    value["source_contexts"] = serde_json::Value::Null;
    value["source_contexts_digest"] = serde_json::Value::Null;
    value["source_profile"] = serde_json::Value::Null;
    for item in value["planned"].as_array_mut().expect("planned items") {
        item["source_binding"] = serde_json::Value::Null;
    }
}

fn recover_and_expect(
    case_dir: &CaseDir,
    world: &World,
    journal: &Path,
    before_db: Option<String>,
    before_mirror: &str,
    expected_kind: &str,
) {
    let before_bytes = std::fs::read(journal).expect("read the mutated journal");
    let recover = run_cli(
        case_dir,
        "recover",
        &recover_args(journal),
        &[],
        &world.env(),
    );
    assert_eq!(recover.rc, Some(1), "recover must fail closed");
    assert_kind(&recover, expected_kind);
    assert_untouched(world, before_db, before_mirror);
    assert_eq!(
        std::fs::read(journal).expect("read back the journal"),
        before_bytes,
        "a refused recovery must not rewrite the journal"
    );
}

#[test]
fn r14_11_all_null_material_provider_guard() {
    assert_synthetic_material_formula();
    let root = result_root();
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
        let case_id = format!("all-null-default-{state}");
        let case_dir = CaseDir::new(&root, "r14_11_all_null_material_provider_guard", &case_id);
        let world = World::new();
        write_default_safety(&world, false);
        let source = world.source(native_spec("claude_one"));
        let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, false);
        let base_journal = world.tmp.path().join("base-journal.json");
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(&world, Some(&contexts_path), None, &base_journal),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let base_bytes = std::fs::read(&base_journal).expect("read the base journal");
        let base: serde_json::Value = serde_json::from_slice(&base_bytes).expect("decode base");
        assert_journal_materials(&base, &contexts_value, &profile);
        case_dir.write("journal.base.json", &base_bytes);

        let mut value = base.clone();
        value["state"] = serde_json::json!(state);
        null_source_materials(&mut value);
        let mutated = case_dir.join("journal.all-null.json");
        std::fs::write(&mutated, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let before_db = db_digest(&world.db);
        let before_mirror = mirror_digest(&world.data_dir);
        recover_and_expect(
            &case_dir,
            &world,
            &mutated,
            before_db,
            &before_mirror,
            "source_restore_material_mismatch",
        );
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "state": state, "materials": "all-null", "expected_kind": "source_restore_material_mismatch"}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!(
            "R14_CASE test=r14_11_all_null_material_provider_guard case={case_id} result=pass"
        );
    }

    // Explicit path identity: the same all-null journal must be rejected before
    // any DB or receipt branch.
    {
        let case_id = "all-null-explicit-planned";
        let case_dir = CaseDir::new(&root, "r14_11_all_null_material_provider_guard", case_id);
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, true);
        let base_journal = world.tmp.path().join("base-journal.json");
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(
                &world,
                Some(&contexts_path),
                Some(&world.fixed),
                &base_journal,
            ),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let base_bytes = std::fs::read(&base_journal).expect("read the base journal");
        let base: serde_json::Value = serde_json::from_slice(&base_bytes).expect("decode base");
        assert_journal_materials(&base, &contexts_value, &profile);
        let mut value = base.clone();
        null_source_materials(&mut value);
        let mutated = case_dir.join("journal.all-null.json");
        std::fs::write(&mutated, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let before_db = db_digest(&world.db);
        let before_mirror = mirror_digest(&world.data_dir);
        recover_and_expect(
            &case_dir,
            &world,
            &mutated,
            before_db,
            &before_mirror,
            "source_restore_material_mismatch",
        );
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "materials": "all-null", "identity": "explicit-path", "expected_kind": "source_restore_material_mismatch"}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!(
            "R14_CASE test=r14_11_all_null_material_provider_guard case={case_id} result=pass"
        );
    }

    // A mixed journal with one legal legacy planned item and one first-batch
    // planned item: all materials null must reject before the legacy install.
    {
        let case_id = "all-null-mixed-planned";
        let case_dir = CaseDir::new(&root, "r14_11_all_null_material_provider_guard", case_id);
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let (contexts_path, _) = world.write_contexts(&[&source]);
        let legacy = world.source(openclaw_spec());
        let base_journal = world.tmp.path().join("base-journal.json");
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(
                &world,
                Some(&contexts_path),
                Some(&world.fixed),
                &base_journal,
            ),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let base_bytes = std::fs::read(&base_journal).expect("read the base journal");
        let base: serde_json::Value = serde_json::from_slice(&base_bytes).expect("decode base");
        let planned = base["planned"].as_array().expect("planned");
        assert_eq!(
            planned.len(),
            2,
            "one first-batch and one legacy planned item"
        );
        let first_batch = planned
            .iter()
            .find(|item| item["manifest_id"] == serde_json::json!(source.capture.manifest_id))
            .expect("the first-batch item is planned");
        assert!(
            !first_batch["source_binding"].is_null(),
            "the first-batch item carries its binding"
        );
        let legacy_item = planned
            .iter()
            .find(|item| item["manifest_id"] == serde_json::json!(legacy.capture.manifest_id))
            .expect("the legacy item is planned");
        assert!(
            legacy_item["source_binding"].is_null(),
            "the legacy item keeps a null binding"
        );
        case_dir.write("journal.base.json", &base_bytes);

        let mut value = base.clone();
        null_source_materials(&mut value);
        let mutated = case_dir.join("journal.all-null.json");
        std::fs::write(&mutated, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let before_db = db_digest(&world.db);
        let before_mirror = mirror_digest(&world.data_dir);
        recover_and_expect(
            &case_dir,
            &world,
            &mutated,
            before_db,
            &before_mirror,
            "source_restore_material_mismatch",
        );
        assert_eq!(
            conversation_count(&world.db),
            0,
            "the legacy item must not be installed after the refused validation"
        );
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "planned": ["first-batch", "legacy"], "materials": "all-null", "expected_kind": "source_restore_material_mismatch"}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!(
            "R14_CASE test=r14_11_all_null_material_provider_guard case={case_id} result=pass"
        );
    }

    // True all-legacy control: null materials and null bindings must still
    // restore through the original path.
    {
        let case_id = "all-null-legacy-control";
        let case_dir = CaseDir::new(&root, "r14_11_all_null_material_provider_guard", case_id);
        let world = World::new();
        let _legacy = world.source(openclaw_spec());
        let base_journal = case_dir.join("legacy-journal.json");
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(&world, None, None, &base_journal),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let base_bytes = std::fs::read(&base_journal).expect("read the legacy journal");
        let base: serde_json::Value = serde_json::from_slice(&base_bytes).expect("decode base");
        assert!(base["source_contexts"].is_null());
        assert!(base["source_contexts_digest"].is_null());
        assert!(base["source_profile"].is_null());
        assert!(
            base["planned"]
                .as_array()
                .unwrap()
                .iter()
                .all(|item| item["source_binding"].is_null())
        );
        let recover = run_cli(
            &case_dir,
            "recover",
            &recover_args(&base_journal),
            &[],
            &world.env(),
        );
        assert_eq!(
            recover.rc,
            Some(0),
            "a true all-legacy recovery must succeed: {recover:?}"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&recover.stdout).expect("recover JSON");
        assert_eq!(report["restored"], 1);
        assert_eq!(conversation_count(&world.db), 1);
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "kind": "original legacy success", "restored": 1}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!(
            "R14_CASE test=r14_11_all_null_material_provider_guard case={case_id} result=pass"
        );
    }
}

// ---------------------------------------------------------------------------
// r14_12 · old wire field errors keep their original classification
// ---------------------------------------------------------------------------

#[test]
fn r14_12_old_wire_error_boundary() {
    assert_synthetic_material_formula();
    let root = result_root();
    let cases = [
        "old-state-type",
        "old-operation-id-type",
        "old-holds-count-type",
        "old-planned-type",
        "old-planned-action-type",
        "old-committed-type",
        "old-missing-required",
        "old-analytics-default-control",
    ];
    for case_id in cases {
        let case_dir = CaseDir::new(&root, "r14_12_old_wire_error_boundary", case_id);
        let world = World::new();
        let source = world.source(native_spec("claude_one"));
        let (contexts_path, contexts_value) = world.write_contexts(&[&source]);
        let profile = expected_profile(&world, true);
        let base_journal = world.tmp.path().join("base-journal.json");
        run_paused(
            &case_dir,
            "apply-paused",
            &apply_args(
                &world,
                Some(&contexts_path),
                Some(&world.fixed),
                &base_journal,
            ),
            &[],
            &world.env(),
            &case_dir.join("pause.sentinel"),
        );
        let base_bytes = std::fs::read(&base_journal).expect("read the base journal");
        let base: serde_json::Value = serde_json::from_slice(&base_bytes).expect("decode base");
        assert_journal_materials(&base, &contexts_value, &profile);
        case_dir.write("journal.base.json", &base_bytes);

        let mut value = base.clone();
        let expected_kind = match case_id {
            "old-state-type" => {
                value["state"] = serde_json::json!(123);
                "mirror_restore_recover_failed"
            }
            "old-operation-id-type" => {
                value["operation_id"] = serde_json::json!(123);
                "mirror_restore_recover_failed"
            }
            "old-holds-count-type" => {
                value["holds_count"] = serde_json::json!("bad");
                "mirror_restore_recover_failed"
            }
            "old-planned-type" => {
                value["planned"] = serde_json::json!({});
                "mirror_restore_recover_failed"
            }
            "old-planned-action-type" => {
                value["planned"][0]["action"] = serde_json::json!(123);
                "mirror_restore_recover_failed"
            }
            "old-committed-type" => {
                value["committed"] = serde_json::json!(123);
                "mirror_restore_recover_failed"
            }
            "old-missing-required" => {
                value.as_object_mut().unwrap().remove("operation_id");
                "mirror_restore_recover_failed"
            }
            "old-analytics-default-control" => {
                value.as_object_mut().unwrap().remove("analytics_now_ms");
                "complete"
            }
            other => panic!("unhandled old wire case {other}"),
        };
        let mutated = case_dir.join("journal.mutated.json");
        std::fs::write(&mutated, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        if case_id == "old-analytics-default-control" {
            assert_source_new_completes(&case_dir, &world, &mutated, case_id);
        } else {
            let before_db = db_digest(&world.db);
            let before_mirror = mirror_digest(&world.data_dir);
            recover_and_expect(
                &case_dir,
                &world,
                &mutated,
                before_db,
                &before_mirror,
                expected_kind,
            );
            assert_eq!(conversation_count(&world.db), 0);
        }
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "expected_kind": expected_kind}),
        );
        case_dir.write("PASS", b"ok\n");
        eprintln!("R14_CASE test=r14_12_old_wire_error_boundary case={case_id} result=pass");
    }
}

// ---------------------------------------------------------------------------
// r14_14 · candidate identity and pre-callback blob admission
// ---------------------------------------------------------------------------

fn strip_final_lf(name: &str) -> Vec<u8> {
    let mut bytes = payload(name).bytes.to_vec();
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    bytes
}

fn capture_with_mtime(world: &World, spec: &Spec, bytes: &[u8], mtime_ms: i64) -> Source {
    let live_path = world.home.join(spec.logical);
    std::fs::create_dir_all(live_path.parent().expect("live parent"))
        .expect("create the live parent");
    std::fs::write(&live_path, bytes).expect("write the live source");
    let stamp = std::time::UNIX_EPOCH + std::time::Duration::from_millis(mtime_ms as u64);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&live_path)
        .expect("open the live source");
    file.set_modified(stamp).expect("set the source mtime");
    let capture = capture_source_file_with_identity(
        RawMirrorCaptureInput {
            data_dir: &world.data_dir,
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
    let declaration = declaration_for(spec, &capture, &live_path);
    Source {
        capture,
        live_path,
        declaration,
        payload_name: "runtime",
        spec: Spec {
            provider: spec.provider,
            source_id: spec.source_id,
            origin_kind: spec.origin_kind,
            origin_host: spec.origin_host,
            connector: spec.connector,
            logical: spec.logical,
            payload_name: "runtime",
        },
    }
}

/// Three no-final-LF versions of one, two and three messages with mtimes set
/// strictly reverse to their byte lengths. Views are returned in manifest-ID
/// order, which is the planner's position order; the third position is the
/// one left unvisited by the first-pair time-conflict HOLD.
fn three_position_world(case_id: &str) -> (World, Vec<Source>, PathBuf, serde_json::Value) {
    let world = World::new();
    let spec = Spec {
        provider: "claude_code",
        source_id: "local",
        origin_kind: "local",
        origin_host: None,
        connector: "claude_code",
        logical: ".claude/projects/C14-ws/three.jsonl",
        payload_name: "runtime",
    };
    let one = strip_final_lf("claude_one");
    let two = strip_final_lf("claude_two");
    let three = strip_final_lf("claude_three");
    let sources = vec![
        capture_with_mtime(&world, &spec, &one, 1_700_000_003_000),
        capture_with_mtime(&world, &spec, &two, 1_700_000_002_000),
        capture_with_mtime(&world, &spec, &three, 1_700_000_001_000),
    ];
    let mut ordered: Vec<(String, Source)> = sources
        .into_iter()
        .map(|source| (source.capture.manifest_id.clone(), source))
        .collect();
    ordered.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let sources: Vec<Source> = ordered.into_iter().map(|(_, source)| source).collect();
    let view_ids: Vec<String> = world
        .views()
        .iter()
        .map(|view| view.manifest_id.clone())
        .collect();
    let source_ids: Vec<String> = sources
        .iter()
        .map(|source| source.capture.manifest_id.clone())
        .collect();
    assert_eq!(
        view_ids, source_ids,
        "{case_id}: planner position order must equal manifest-ID order"
    );
    let (contexts, contexts_value) = world.write_contexts(&[&sources[0], &sources[1]]);
    (world, sources, contexts, contexts_value)
}

fn third_blob_path(world: &World, third: &Source) -> PathBuf {
    let view = world
        .views()
        .into_iter()
        .find(|view| view.manifest_id == third.capture.manifest_id)
        .expect("the third manifest view");
    world
        .data_dir
        .join("raw-mirror")
        .join("v1")
        .join(&view.blob_relative_path)
}

fn duplicate_conversations(world: &World, additional: usize) {
    use coding_agent_search::storage::sqlite::FrankenStorage;
    let mut storage = FrankenStorage::open(&world.db).expect("open the candidate database");
    let original: i64 = storage
        .raw()
        .query_row_map("SELECT MIN(id) FROM conversations", &[], |row| {
            row.get_typed(0)
        })
        .expect("the indexed conversation");
    for _ in 0..additional {
        let sql = format!(
            "INSERT INTO conversations (agent_id, workspace_id, source_id, external_id, title, \
             source_path, started_at, ended_at, approx_tokens, metadata_json, origin_host, \
             identity_host, metadata_bin, total_input_tokens, total_output_tokens, \
             total_cache_read_tokens, total_cache_creation_tokens, grand_total_tokens, \
             estimated_cost_usd, primary_model, api_call_count, tool_call_count, \
             user_message_count, assistant_message_count, last_message_idx, \
             last_message_created_at) SELECT agent_id, workspace_id, source_id, NULL, title, \
             source_path, started_at, ended_at, approx_tokens, metadata_json, origin_host, \
             identity_host, metadata_bin, total_input_tokens, total_output_tokens, \
             total_cache_read_tokens, total_cache_creation_tokens, grand_total_tokens, \
             estimated_cost_usd, primary_model, api_call_count, tool_call_count, \
             user_message_count, assistant_message_count, last_message_idx, \
             last_message_created_at FROM conversations WHERE id = {original}"
        );
        storage
            .raw()
            .execute(&sql, &[])
            .expect("duplicate a conversation");
        let new_id: i64 = storage
            .raw()
            .query_row_map("SELECT MAX(id) FROM conversations", &[], |row| {
                row.get_typed(0)
            })
            .expect("the duplicated conversation");
        let sql = format!(
            "INSERT INTO messages (conversation_id, idx, role, author, created_at, content, \
             extra_json, extra_bin, excluded) SELECT {new_id}, idx, role, author, created_at, \
             content, extra_json, extra_bin, excluded FROM messages WHERE conversation_id = {original}"
        );
        storage.raw().execute(&sql, &[]).expect("copy the messages");
    }
    storage.close_best_effort_in_place();
}

fn plan_holds(
    case_dir: &CaseDir,
    world: &World,
    contexts: &Path,
) -> (serde_json::Value, serde_json::Value) {
    let summary = plan_ok(case_dir, world, contexts, "plan");
    let out = case_dir.join("plan-report.json");
    let holds: serde_json::Value = serde_json::from_slice(
        &std::fs::read(out.with_extension("holds.json")).expect("holds ledger"),
    )
    .expect("decode holds ledger");
    (summary, holds)
}

fn index_rich_candidate(case_dir: &CaseDir, world: &World, spec: &Spec) {
    let live = world.home.join(spec.logical);
    write_source(&live, RICH_INVOCATION);
    let index_args = vec![
        "index".to_string(),
        "--full".to_string(),
        "--data-dir".to_string(),
        world.index_data.to_string_lossy().into_owned(),
        "--db".to_string(),
        world.db.to_string_lossy().into_owned(),
        "--json".to_string(),
    ];
    let indexed = run_cli(case_dir, "ordinary-index", &index_args, &[], &world.env());
    assert_eq!(
        indexed.rc,
        Some(0),
        "the ordinary index must succeed: {indexed:?}"
    );
}

#[test]
fn r14_14_candidate_identity_and_blob_admission() {
    assert_synthetic_material_formula();
    let root = result_root();
    let mut failures: Vec<String> = Vec::new();

    // Each case runs to completion even when an earlier one fails, so one R2
    // run exposes both the F6 and F5 red sides instead of stopping at the
    // first panic.
    macro_rules! run_case {
        ($id:expr, $body:block) => {{
            let id: &str = $id;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $body));
            match outcome {
                Ok(()) => eprintln!(
                    "R14_CASE test=r14_14_candidate_identity_and_blob_admission case={id} result=pass"
                ),
                Err(_) => {
                    failures.push(id.to_string());
                    eprintln!(
                        "R14_CASE test=r14_14_candidate_identity_and_blob_admission case={id} result=fail"
                    );
                }
            }
        }};
    }

    // ── SQL multiple candidates: no source ID may be attached to SQL rows ──
    for (case_id, extra_candidates) in [
        ("sql-two-candidates-no-source-id", 1usize),
        ("sql-three-candidates-no-source-id", 2usize),
    ] {
        run_case!(case_id, {
            let case_dir = CaseDir::new(
                &root,
                "r14_14_candidate_identity_and_blob_admission",
                case_id,
            );
            let world = World::new();
            let spec = Spec {
                provider: "claude_code",
                source_id: "local",
                origin_kind: "local",
                origin_host: None,
                connector: "claude_code",
                logical: ".claude/projects/C14-ws/rich.jsonl",
                payload_name: "runtime",
            };
            index_rich_candidate(&case_dir, &world, &spec);
            duplicate_conversations(&world, extra_candidates);
            let source = capture_payload(&world, &spec, RICH_INVOCATION);
            let (contexts, _) = world.write_contexts(&[&source]);
            let before_db = db_digest(&world.db);
            let before_mirror = mirror_digest(&world.data_dir);
            let (summary, holds) = plan_holds(&case_dir, &world, &contexts);
            assert_eq!(
                summary["candidate_versions_seen"],
                serde_json::json!(1 + extra_candidates),
                "{summary}"
            );
            assert_eq!(
                summary["holds_by_reason"]["multiple-candidates"], 1,
                "{summary}"
            );
            assert_eq!(summary["planned_actions"], 0, "{summary}");
            let row = &holds[0];
            assert_eq!(row["reason"], "multiple-candidates");
            assert_eq!(row["evidence_kind"], "versions");
            assert!(
                row.get("source_manifest_ids").is_none(),
                "SQL-only candidates must not carry a source manifest ID: {row}"
            );
            let versions = summary["source_versions"]
                .as_array()
                .expect("the real source winner keeps its source_versions entry");
            assert_eq!(versions.len(), 1, "{summary}");
            assert_eq!(versions[0]["manifest_id"], source.capture.manifest_id);
            assert_untouched(&world, before_db, &before_mirror);
            case_dir.write_json(
                "expected.json",
                &serde_json::json!({"case": case_id, "candidates": 1 + extra_candidates, "reason": "multiple-candidates", "source_manifest_ids": null}),
            );
            case_dir.write("PASS", b"ok\n");
        });
    }

    // ── Single SQL candidate that is a superset: winner side gets the ID ──
    run_case!("sql-single-superset-winner-id", {
        let case_id = "sql-single-superset-winner-id";
        let case_dir = CaseDir::new(
            &root,
            "r14_14_candidate_identity_and_blob_admission",
            case_id,
        );
        let world = World::new();
        let spec = Spec {
            provider: "claude_code",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            connector: "claude_code",
            logical: ".claude/projects/C14-ws/rich.jsonl",
            payload_name: "runtime",
        };
        index_rich_candidate(&case_dir, &world, &spec);
        let source = capture_payload(&world, &spec, RICH_PREFIX);
        let (contexts, _) = world.write_contexts(&[&source]);
        let before_db = db_digest(&world.db);
        let before_mirror = mirror_digest(&world.data_dir);
        let (summary, holds) = plan_holds(&case_dir, &world, &contexts);
        assert_eq!(summary["candidate_versions_seen"], 1, "{summary}");
        assert_eq!(
            summary["holds_by_reason"]["candidate-superset"], 1,
            "{summary}"
        );
        assert_eq!(summary["planned_actions"], 0, "{summary}");
        let row = &holds[0];
        assert_eq!(row["reason"], "candidate-superset");
        let ids: Vec<String> = row["source_manifest_ids"]
            .as_array()
            .expect("the real winner must carry its ID")
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids, vec![source.capture.manifest_id.clone()]);
        assert_untouched(&world, before_db, &before_mirror);
        case_dir.write_json(
            "expected.json",
            &serde_json::json!({"case": case_id, "candidates": 1, "reason": "candidate-superset", "source_manifest_ids": ids}),
        );
        case_dir.write("PASS", b"ok\n");
    });

    // ── Unvisited third position: blob admission decides before 41 ──
    for case_id in [
        "unvisited-third-missing-blob",
        "unvisited-third-corrupt-blob",
        "unvisited-third-symlink-blob",
    ] {
        run_case!(case_id, {
            let case_dir = CaseDir::new(
                &root,
                "r14_14_candidate_identity_and_blob_admission",
                case_id,
            );
            let (world, sources, contexts, _) = three_position_world(case_id);
            let blob = third_blob_path(&world, &sources[2]);
            let private_target = world.tmp.path().join("c14-third-private.bin");
            let expected_reasons: &[&str];
            match case_id {
                "unvisited-third-missing-blob" => {
                    std::fs::rename(&blob, world.tmp.path().join("c14-third-moved.bin"))
                        .expect("move the third blob away");
                    expected_reasons = &["manifest-reference-missing"];
                }
                "unvisited-third-corrupt-blob" => {
                    let mut bytes = std::fs::read(&blob).expect("read the third blob");
                    bytes[0] ^= 0xff;
                    std::fs::write(&blob, &bytes).expect("corrupt the third blob");
                    expected_reasons = &["payload-hash-mismatch"];
                }
                "unvisited-third-symlink-blob" => {
                    // Same sealed bytes, only the physical location changes: the
                    // path guard itself must reject the non-regular blob path,
                    // not a repeated hash-corruption case.
                    let original = world.tmp.path().join("c14-third-original.bin");
                    std::fs::rename(&blob, &original).expect("move the third blob aside");
                    let bytes = std::fs::read(&original).expect("read the moved third blob");
                    std::fs::write(&private_target, &bytes).expect("write the private target");
                    std::os::unix::fs::symlink(&private_target, &blob)
                        .expect("symlink the blob path");
                    expected_reasons = &["payload-hash-mismatch"];
                }
                other => panic!("unhandled blob case {other}"),
            }
            let private_before = std::fs::read(&private_target).ok();
            let before_db = db_digest(&world.db);
            let before_mirror = mirror_digest(&world.data_dir);
            let (summary, holds) = plan_holds(&case_dir, &world, &contexts);
            let reason = holds[0]["reason"].as_str().expect("hold reason");
            assert!(
                expected_reasons.contains(&reason),
                "{case_id}: unexpected HOLD reason {reason}: {holds}"
            );
            let expected_evidence_kind = if case_id == "unvisited-third-missing-blob" {
                // The existing ReferenceMissing emitter carries an (empty) version list.
                "versions"
            } else {
                // PayloadHashMismatch / Unreadable use the InputUnreadable evidence.
                "input-unreadable"
            };
            assert_eq!(
                holds[0]["evidence_kind"], expected_evidence_kind,
                "{case_id}: the legacy blob-admission emitter keeps its existing evidence kind"
            );
            assert!(
                summary.get("source_versions").is_none(),
                "{case_id}: a bad group must not report source_versions: {summary}"
            );
            assert_eq!(summary["planned_actions"], 0, "{summary}");
            assert_eq!(summary["candidate_versions_seen"], 0, "{summary}");
            assert_untouched(&world, before_db, &before_mirror);
            if case_id == "unvisited-third-symlink-blob" {
                assert_eq!(
                    std::fs::read(&private_target).ok(),
                    private_before,
                    "the private symlink target must not change"
                );
            }
            case_dir.write_json(
                "expected.json",
                &serde_json::json!({"case": case_id, "reason": reason, "evidence_kind": expected_evidence_kind, "source_versions": null}),
            );
            case_dir.write("PASS", b"ok\n");
        });
    }

    assert!(failures.is_empty(), "r14_14 failing cases: {failures:?}");
}
