//! Task09 acceptance tests: one restore journal consumes the rule epoch that
//! its own fixed profile names.
//!
//! Every fixture here is synthetic and self-contained. A real `claude_code` and
//! a real `codex` session are captured into a real raw mirror, a schema-4
//! *planned* journal is written by hand from independently computed material
//! (declarations, profile, seven-field bindings), and the real `cass` binary
//! restores into a fresh isolated candidate database. The profile declares
//! `cass-source-exclusion/2`; the restore must therefore judge and clear the
//! recall bodies with the v2 rules while the producer default stays at `/1`.
//!
//! No expected value is read back from the candidate: the envelopes, the
//! bindings and the profile are built from the literals in this file, and every
//! post-restore fact is read from a fresh read-only SQL handle or from the real
//! `sources facts export` package.
//!
//! Evidence trees are written only when `CASS_MCP_T09_RESULT_ROOT` points at a
//! directory the runner created for this round; the world itself always lives
//! in its own `TempDir`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine as _;
use coding_agent_search::indexer::exclusion::{ExcludedMarker, ExclusionReason};
use coding_agent_search::indexer::redact_secrets::redaction_algorithm_fingerprint;
use coding_agent_search::raw_mirror::{
    RAW_MIRROR_LOCAL_IDENTITY_HOST, RawMirrorCaptureInput, RawMirrorCaptureRecord,
    RawMirrorSessionIdentity, capture_source_file_with_identity,
};
use coding_agent_search::storage::api::Value;
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Frozen identity material
// ---------------------------------------------------------------------------

const FAD_PIN: &str = "61f975f3b56f8dabc4ecbe1dae4102c1ea6b16e5";
const MAPPING_DOMAIN: &str = "cass-source-mapping/2";
const NORMALIZER_DOMAIN: &str = "cass.source-normalizer/1";
const SAFETY_CONTRACT: &str = "cass.source-safety/1";
const EPOCH_V2: &str = "cass-source-exclusion/2";
const CONTEXT_SCHEMA: &str = "cass.restore-source-contexts/1";
const NAMESPACE: &str = "MCP_T09_NAMESPACE";

/// The fixed copy both epochs share: all four arrays explicitly empty.
const FIXED_TOML: &str = "memory_files = []\ninjection_only_files = []\n\
workspace_scoped_files = []\nproject_read_documents = []\n";

// ---------------------------------------------------------------------------
// Independent canonical JSON
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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

fn canonical_json(value: &Json) -> String {
    match value {
        Json::Null => "null".to_string(),
        Json::Bool(value) => value.to_string(),
        Json::Number(number) => number.to_string(),
        Json::String(text) => json_string(text),
        Json::Array(items) => {
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
        Json::Object(map) => {
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

fn sha256_canonical(value: &Json) -> String {
    sha256_hex(canonical_json(value).as_bytes())
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

fn fingerprint() -> String {
    redaction_algorithm_fingerprint()
}

fn code_version_v2() -> String {
    format!("{EPOCH_V2}+{}", fingerprint())
}

fn four_arrays_digest() -> String {
    sha256_hex(
        br#"{"injection_only_files":[],"memory_files":[],"project_read_documents":[],"workspace_scoped_files":[]}"#,
    )
}

// ---------------------------------------------------------------------------
// Fixture bodies: one legal C04 envelope, reused by every recall result
// ---------------------------------------------------------------------------

/// The frozen search result the recall envelope carries. Only its own
/// `source_id`/`source_path`/`line_number` contribute source metadata.
const RECALL_JSON: &str = "{\"hits\":[{\"content\":\"we picked per-feature worktrees\",\
\"line_number\":7,\"source_id\":\"local\",\"source_path\":\"/synthetic/t09/prior.jsonl\"}]}";

fn xml_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            ch => out.push(ch),
        }
    }
    out
}

fn recall_wrapper() -> String {
    format!(
        "<cass_recall version=\"1\" tool=\"cass_search\">{}</cass_recall>",
        xml_escape(RECALL_JSON)
    )
}

/// The frozen Codex application result: one completed read-only command whose
/// whole output is the one C04 envelope.
fn codex_application() -> String {
    let value = json!({
        "chunk_id": "t09-chunk",
        "exit_code": 0,
        "output": recall_wrapper(),
        "wall_time_seconds": 0.25,
    });
    serde_json::to_string(&value).expect("the application result encodes")
}

/// The frozen C07 input: one `text(await tools.exec_command(J));` literal whose
/// `J.cmd` is exactly one CASS read command.
fn codex_expression() -> String {
    let input = json!({"cmd": "cass search \"worktree decision\" --recall"});
    format!("text(await tools.exec_command({input}));")
}

/// A real `claude_code` session: one ordinary user turn, one legal native MCP
/// recall, one direct `Bash` CLI recall, one ordinary same-named tool whose
/// plain output must stay, and a closing assistant turn.
fn claude_session() -> Vec<u8> {
    let lines = vec![
        json!({
            "type": "user",
            "timestamp": "2026-01-02T00:00:00.000Z",
            "uuid": "t09-claude-u1",
            "message": {
                "role": "user",
                "content": "T09 claude user prose stays: search my prior sessions"
            }
        }),
        json!({
            "type": "assistant",
            "timestamp": "2026-01-02T00:00:01.000Z",
            "uuid": "t09-claude-a1",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Searching with the cass MCP."},
                    {
                        "type": "tool_use",
                        "id": "toolu_t09_mcp",
                        "name": "mcp__cass-mcp__cass_search",
                        "input": {"query": "worktree decision"}
                    }
                ]
            }
        }),
        json!({
            "type": "user",
            "timestamp": "2026-01-02T00:00:02.000Z",
            "uuid": "t09-claude-u2",
            "message": {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_t09_mcp", "content": recall_wrapper()}
                ]
            }
        }),
        json!({
            "type": "assistant",
            "timestamp": "2026-01-02T00:00:03.000Z",
            "uuid": "t09-claude-a2",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "Now the same query through one direct CLI call."},
                    {
                        "type": "tool_use",
                        "id": "toolu_t09_cli",
                        "name": "Bash",
                        "input": {"command": "cass search \"worktree decision\" --recall"}
                    }
                ]
            }
        }),
        json!({
            "type": "user",
            "timestamp": "2026-01-02T00:00:04.000Z",
            "uuid": "t09-claude-u3",
            "message": {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_t09_cli", "content": recall_wrapper()}
                ]
            }
        }),
        json!({
            "type": "assistant",
            "timestamp": "2026-01-02T00:00:05.000Z",
            "uuid": "t09-claude-a3",
            "message": {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "One ordinary tool that merely shares the name."},
                    {
                        "type": "tool_use",
                        "id": "toolu_t09_plain",
                        "name": "cass_search",
                        "input": {"query": "ordinary"}
                    }
                ]
            }
        }),
        json!({
            "type": "user",
            "timestamp": "2026-01-02T00:00:06.000Z",
            "uuid": "t09-claude-u4",
            "message": {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_t09_plain", "content": "T09 ordinary same-named tool output stays"}
                ]
            }
        }),
        json!({
            "type": "assistant",
            "timestamp": "2026-01-02T00:00:07.000Z",
            "uuid": "t09-claude-a4",
            "message": {
                "role": "assistant",
                "content": "T09 claude closing answer stays"
            }
        }),
    ];
    jsonl_bytes(lines)
}

/// A real `codex` rollout: one session header, one ordinary user turn, the
/// frozen single-call `exec` wrapper, its result and a closing assistant turn.
fn codex_session() -> Vec<u8> {
    let lines = vec![
        json!({
            "timestamp": "2026-01-02T00:00:00.000Z",
            "type": "session_meta",
            "payload": {"id": "T09-CODEX", "cwd": "/synthetic/t09", "cli_version": "0.42.0"}
        }),
        json!({
            "timestamp": "2026-01-02T00:00:01.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": "t09-codex-u1",
                "role": "user",
                "content": [{"type": "input_text", "text": "T09 codex user prose stays"}]
            }
        }),
        json!({
            "timestamp": "2026-01-02T00:00:02.000Z",
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "name": "exec",
                "input": codex_expression(),
                "call_id": "t09-call"
            }
        }),
        json!({
            "timestamp": "2026-01-02T00:00:03.000Z",
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "t09-call",
                "output": [{"type": "input_text", "text": codex_application()}]
            }
        }),
        json!({
            "timestamp": "2026-01-02T00:00:04.000Z",
            "type": "response_item",
            "payload": {
                "type": "message",
                "id": "t09-codex-a1",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "T09 codex closing answer stays"}]
            }
        }),
    ];
    jsonl_bytes(lines)
}

fn jsonl_bytes(lines: Vec<Json>) -> Vec<u8> {
    let mut out = Vec::new();
    for line in lines {
        out.extend_from_slice(
            serde_json::to_string(&line)
                .expect("a fixture line")
                .as_bytes(),
        );
        out.push(b'\n');
    }
    out
}

/// The ordinary rows every fixture keeps, exactly as the literals spell them.
const CLAUDE_KEPT: [&str; 3] = [
    "T09 claude user prose stays: search my prior sessions",
    "T09 ordinary same-named tool output stays",
    "T09 claude closing answer stays",
];

const CODEX_KEPT: [&str; 2] = [
    "T09 codex user prose stays",
    "T09 codex closing answer stays",
];

// ---------------------------------------------------------------------------
// World: one isolated candidate, mirror, home and command environment
// ---------------------------------------------------------------------------

struct World {
    root: TempDir,
    home: PathBuf,
    xdg_config: PathBuf,
    xdg_data: PathBuf,
    xdg_cache: PathBuf,
    cwd: PathBuf,
    tmp: PathBuf,
    data_dir: PathBuf,
    scratch: PathBuf,
    db: PathBuf,
    fixed: PathBuf,
}

impl World {
    fn new() -> Self {
        let root = TempDir::new().expect("create the world tempdir");
        let home = root.path().join("home");
        let xdg_config = root.path().join("xdg-config");
        let xdg_data = root.path().join("xdg-data");
        let xdg_cache = root.path().join("xdg-cache");
        let cwd = root.path().join("cwd");
        let tmp = root.path().join("tmp");
        let data_dir = root.path().join("cass-data");
        let scratch = root.path().join("scratch");
        for path in [
            &home,
            &xdg_config,
            &xdg_data,
            &xdg_cache,
            &cwd,
            &tmp,
            &data_dir,
            &scratch,
        ] {
            fs::create_dir_all(path).expect("create a world directory");
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .expect("tighten a world directory");
        }
        fs::write(cwd.join(".env"), b"").expect("write the empty cwd .env");
        let fixed = root.path().join("fixed-safety.toml");
        fs::write(&fixed, FIXED_TOML).expect("write the fixed safety copy");
        let db = root.path().join("candidate.sqlite");
        {
            let mut storage = FrankenStorage::open(&db).expect("create the candidate database");
            storage.close_best_effort_in_place();
        }
        Self {
            root,
            home,
            xdg_config,
            xdg_data,
            xdg_cache,
            cwd,
            tmp,
            data_dir,
            scratch,
            db,
            fixed,
        }
    }

    fn command(&self, args: &[String]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_cass"));
        command.env_clear();
        command
            .env("HOME", &self.home)
            .env("XDG_CACHE_HOME", &self.xdg_cache)
            .env("XDG_CONFIG_HOME", &self.xdg_config)
            .env("XDG_DATA_HOME", &self.xdg_data)
            .env("XDG_STATE_HOME", self.home.join("state"))
            .env("TMPDIR", &self.tmp)
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C");
        command.current_dir(&self.cwd);
        command.args(args);
        command
    }

    fn recover(&self, journal: &Path) -> Output {
        self.command(&[
            "mirror-restore".to_string(),
            "--recover".to_string(),
            "--journal".to_string(),
            journal.to_string_lossy().into_owned(),
            "--json".to_string(),
        ])
        .output()
        .expect("run the recover CLI")
    }

    fn export(&self, out: &Path, materials: &Path) -> Output {
        self.command(&[
            "--db".to_string(),
            self.db.to_string_lossy().into_owned(),
            "sources".to_string(),
            "facts".to_string(),
            "export".to_string(),
            "--output".to_string(),
            out.to_string_lossy().into_owned(),
            "--profile-materials".to_string(),
            materials.to_string_lossy().into_owned(),
            "--scope".to_string(),
            "all_source".to_string(),
            "--json".to_string(),
        ])
        .output()
        .expect("run the export CLI")
    }
}

struct Source {
    capture: RawMirrorCaptureRecord,
    live_path: PathBuf,
    bytes: Vec<u8>,
    declaration: Json,
}

fn capture_source(
    world: &World,
    file_name: &str,
    provider: &str,
    connector: &str,
    source_id: &str,
    bytes: &[u8],
) -> Source {
    let live_path = world.home.join(file_name);
    fs::write(&live_path, bytes).expect("write the live source");
    let capture = capture_source_file_with_identity(
        RawMirrorCaptureInput {
            data_dir: &world.data_dir,
            provider,
            source_id,
            origin_kind: "local",
            origin_host: None,
            source_path: &live_path,
            db_links: &[],
        },
        RawMirrorSessionIdentity {
            identity_host: RAW_MIRROR_LOCAL_IDENTITY_HOST,
            external_id: None,
        },
    )
    .expect("capture the fixture into the raw mirror");
    let declaration = json!({
        "manifest_id": capture.manifest_id,
        "identity_namespace": NAMESPACE,
        "connector": connector,
        "scan_root": live_path.parent().expect("live parent").to_string_lossy(),
        "relative_locator": live_path.file_name().expect("live name").to_string_lossy(),
        "role": "primary_session_log",
        "origin": {
            "source_id": source_id,
            "kind": "local",
            "host": null,
            "source_version": null,
        },
        "platform": null,
        "workspace_rewrites": [],
    });
    Source {
        capture,
        live_path,
        bytes: bytes.to_vec(),
        declaration,
    }
}

// ---------------------------------------------------------------------------
// Independently computed journal material
// ---------------------------------------------------------------------------

fn effective_material(declaration: &Json) -> Json {
    json!({
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

fn parser_context_wire(declaration: &Json, effective_digest: &str) -> Json {
    json!({
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
        "effective_config_summary": {"effective_digest": effective_digest},
    })
}

fn fixed_path_text(world: &World) -> String {
    std::path::absolute(&world.fixed)
        .expect("absolute fixed path")
        .to_string_lossy()
        .into_owned()
}

/// The v2 profile the journal names: ten keys, epoch `/2`, and the complete v2
/// code version built from the real redaction fingerprint.
fn profile_v2(world: &World) -> Json {
    let fixed_path = fixed_path_text(world);
    json!({
        "config_source_identity": fixed_path,
        "fixed_copy_path": fixed_path,
        "fixed_config_sha256": sha256_hex(FIXED_TOML.as_bytes()),
        "effective_four_arrays_sha256": four_arrays_digest(),
        "code_version": code_version_v2(),
        "fad_pin": FAD_PIN,
        "mapping_domain": MAPPING_DOMAIN,
        "exclusion_epoch": EPOCH_V2,
        "redaction_fingerprint": fingerprint(),
        "desensitization_enabled": true,
    })
}

fn safety_contract(profile: &Json) -> String {
    sha256_canonical(&json!([
        SAFETY_CONTRACT,
        EPOCH_V2,
        fingerprint(),
        profile["config_source_identity"],
        profile["fixed_config_sha256"],
        profile["effective_four_arrays_sha256"],
        true,
    ]))
}

fn binding(declaration: &Json, sealed_sha: &str, byte_len: u64, profile: &Json) -> Json {
    let effective = effective_material(declaration);
    let effective_digest = sha256_canonical(&effective);
    let normalizer_id = sha256_canonical(&json!([
        NORMALIZER_DOMAIN,
        FAD_PIN,
        MAPPING_DOMAIN,
        effective_digest,
    ]));
    let safety_contract_id = safety_contract(profile);
    let context_digest = sha256_canonical(&parser_context_wire(declaration, &effective_digest));
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
        Some(sealed_sha),
        Some(normalizer_id.as_str()),
        Some(safety_contract_id.as_str()),
    ];
    json!({
        "declaration": declaration,
        "context_digest": context_digest,
        "sealed_sha256": sealed_sha,
        "byte_len": byte_len,
        "normalizer_id": normalizer_id,
        "safety_contract_id": safety_contract_id,
        "input_key": sha256_hex(canonical_tuple(&tuple).as_bytes()),
    })
}

struct Materials {
    contexts: Json,
    contexts_digest: String,
    profile: Json,
    bindings: Vec<Json>,
}

fn materials(world: &World, sources: &[&Source]) -> Materials {
    let profile = profile_v2(world);
    let mut declarations: Vec<Json> = sources
        .iter()
        .map(|source| source.declaration.clone())
        .collect();
    declarations.sort_by(|left, right| {
        left["manifest_id"]
            .as_str()
            .unwrap()
            .as_bytes()
            .cmp(right["manifest_id"].as_str().unwrap().as_bytes())
    });
    let contexts = json!({"schema": CONTEXT_SCHEMA, "inputs": declarations});
    let contexts_digest = sha256_canonical(&contexts);
    let bindings = sources
        .iter()
        .map(|source| {
            binding(
                &source.declaration,
                &sha256_hex(&source.bytes),
                source.bytes.len() as u64,
                &profile,
            )
        })
        .collect();
    Materials {
        contexts,
        contexts_digest,
        profile,
        bindings,
    }
}

fn journal_value(world: &World, materials: &Materials) -> Json {
    let planned: Vec<Json> = materials
        .bindings
        .iter()
        .map(|binding| {
            json!({
                "manifest_id": binding["declaration"]["manifest_id"],
                "action": {"kind": "restore-new"},
                "source_binding": binding,
            })
        })
        .collect();
    json!({
        "schema_version": 4,
        "operation_id": "mcp-t09-restore",
        "state": "planned",
        "data_dir": world.data_dir.to_string_lossy(),
        "scratch_dir": world.scratch.to_string_lossy(),
        "db_path": world.db.to_string_lossy(),
        "marker_path": world.scratch.join("w1-commit-marker.json").to_string_lossy(),
        "snapshot_root": "mcp-t09-snapshot",
        "generation": "mcp-t09-generation",
        "planned": planned,
        "holds_count": 0,
        "origin_unmapped_count": 0,
        "committed": [],
        "published": [],
        "analytics_now_ms": 1_760_000_000_000i64,
        "source_contexts": materials.contexts,
        "source_contexts_digest": materials.contexts_digest,
        "source_profile": materials.profile,
    })
}

fn write_journal(world: &World, value: &Json, name: &str) -> PathBuf {
    let path = world.tmp.join(name);
    let mut bytes = serde_json::to_vec_pretty(value).expect("the journal encodes");
    bytes.push(b'\n');
    fs::write(&path, bytes).expect("write the planned journal");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("tighten the journal");
    path
}

// ---------------------------------------------------------------------------
// Read-only inspection
// ---------------------------------------------------------------------------

fn value_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Integer(number) => json!(number),
        Value::Real(number) => json!(format!("f64bits:{:016x}", number.to_bits())),
        Value::Text(text) => json!(text),
        Value::Blob(bytes) => {
            let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            json!(format!("blob:{hex}"))
        }
    }
}

fn sql_rows(db: &Path, sql: &str) -> Vec<Vec<Json>> {
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
        .expect("run the read-only query");
    storage.close_best_effort_in_place();
    rows
}

fn sql_scalar_i64(db: &Path, sql: &str) -> i64 {
    let rows = sql_rows(db, sql);
    assert_eq!(rows.len(), 1, "a scalar query returns exactly one row");
    rows[0][0].as_i64().expect("an integer scalar")
}

fn sql_scalar_text(db: &Path, sql: &str) -> String {
    let rows = sql_rows(db, sql);
    assert_eq!(rows.len(), 1, "a scalar query returns exactly one row");
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

fn counts(db: &Path) -> Json {
    let tables = [
        "messages",
        "conversations",
        "agents",
        "workspaces",
        "source_inputs",
        "source_records",
        "source_message_links",
        "operation_commit_receipt",
        "meta",
    ];
    let mut snapshot = serde_json::Map::new();
    for table in tables {
        snapshot.insert(table.to_string(), json!(table_count(db, table)));
    }
    Json::Object(snapshot)
}

struct MessageRow {
    idx: i64,
    role: String,
    content: String,
    excluded: Option<ExcludedMarker>,
}

fn message_rows(db: &Path) -> Vec<MessageRow> {
    sql_rows(
        db,
        "SELECT idx, role, content, json(excluded) FROM messages ORDER BY id",
    )
    .into_iter()
    .map(|row| MessageRow {
        idx: row[0].as_i64().expect("message idx"),
        role: row[1].as_str().expect("message role").to_string(),
        content: row[2].as_str().expect("message content").to_string(),
        excluded: row[3]
            .as_str()
            .map(|text| ExcludedMarker::from_json_str(text).expect("a well-formed marker")),
    })
    .collect()
}

/// Every stored safe record payload as lowercase hex, without the `blob:`
/// prefix [`value_json`] adds. The payload is msgpack, so a string is stored as
/// its raw UTF-8 bytes.
fn safe_payload_hex(db: &Path) -> Vec<String> {
    sql_rows(
        db,
        "SELECT lower(hex(payload_bin)) FROM source_records ORDER BY id",
    )
    .into_iter()
    .map(|row| match row[0].as_str() {
        Some(text) => text.strip_prefix("blob:").unwrap_or(text).to_string(),
        None => String::new(),
    })
    .collect()
}

fn hex_of(text: &str) -> String {
    text.as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn file_sha256(path: &Path) -> String {
    sha256_hex(&fs::read(path).expect("read the file for its digest"))
}

fn mirror_blob_path(world: &World, manifest_id: &str) -> PathBuf {
    let views = coding_agent_search::raw_mirror::manifest_views(&world.data_dir)
        .expect("read the mirror manifest views");
    let view = views
        .iter()
        .find(|view| view.manifest_id == manifest_id)
        .expect("the planned manifest view");
    world
        .data_dir
        .join("raw-mirror")
        .join("v1")
        .join(&view.blob_relative_path)
}

fn error_kind(output: &Output) -> String {
    let text = String::from_utf8_lossy(&output.stderr);
    let value: Json = serde_json::from_str(&text)
        .unwrap_or_else(|_| panic!("the refusal envelope is not JSON: {text}"));
    value
        .pointer("/error/kind")
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("no error.kind in {value}"))
        .to_string()
}

// ---------------------------------------------------------------------------
// Evidence (only when the runner names a fresh round directory)
// ---------------------------------------------------------------------------

fn evidence_directory(case: &str) -> Option<PathBuf> {
    let root = std::env::var_os("CASS_MCP_T09_RESULT_ROOT").map(PathBuf::from)?;
    let directory = root.join(case);
    fs::create_dir_all(&directory).expect("create the evidence directory");
    Some(directory)
}

fn write_evidence(case: &str, name: &str, bytes: &[u8]) {
    let Some(directory) = evidence_directory(case) else {
        return;
    };
    fs::write(directory.join(name), bytes).expect("write the evidence file");
}

fn write_evidence_json(case: &str, name: &str, value: &Json) {
    write_evidence(
        case,
        name,
        &serde_json::to_vec_pretty(value).expect("encode the evidence"),
    );
}

// ---------------------------------------------------------------------------
// One self-contained v2 material set
// ---------------------------------------------------------------------------

struct Setup {
    world: World,
    claude: Source,
    codex: Source,
    materials: Materials,
}

fn setup() -> Setup {
    let world = World::new();
    let claude = capture_source(
        &world,
        "claude-session.jsonl",
        "claude",
        "claude_code",
        "local",
        &claude_session(),
    );
    let codex = capture_source(
        &world,
        "codex-rollout.jsonl",
        "codex",
        "codex",
        "local",
        &codex_session(),
    );
    let materials = materials(&world, &[&claude, &codex]);
    Setup {
        world,
        claude,
        codex,
        materials,
    }
}

fn sealed_blobs(setup: &Setup) -> Vec<(String, String)> {
    [&setup.claude, &setup.codex]
        .iter()
        .map(|source| {
            let path = mirror_blob_path(&setup.world, &source.capture.manifest_id);
            (source.capture.manifest_id.clone(), file_sha256(&path))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// 09-AC1: a non-empty v2 material really restores, cleans and exports
// ---------------------------------------------------------------------------

#[test]
fn mcp_restore_v2_nonempty_cli_recover_and_export() {
    let setup = setup();
    let world = &setup.world;
    let journal = journal_value(world, &setup.materials);
    write_evidence_json("restore-v2", "journal.planned.json", &journal);
    let journal_path = write_journal(world, &journal, "journal.json");

    let before_counts = counts(&world.db);
    let before_journal = fs::read(&journal_path).expect("read the planned journal");
    let before_blobs = sealed_blobs(&setup);
    let before_live: Vec<String> = [&setup.claude, &setup.codex]
        .iter()
        .map(|source| file_sha256(&source.live_path))
        .collect();

    let output = world.recover(&journal_path);
    write_evidence("restore-v2", "recover.stdout", &output.stdout);
    write_evidence("restore-v2", "recover.stderr", &output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "the v2 restore must succeed, stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Json = serde_json::from_slice(&output.stdout).expect("the recover report is JSON");
    write_evidence_json("restore-v2", "recover.report.json", &report);
    assert_eq!(report["recovered"], json!(true));
    assert_eq!(
        report["restored"],
        json!(2),
        "two non-empty inputs restored"
    );
    assert_eq!(report["replaced"], json!(0));
    assert_eq!(report["already_committed"], json!(0));
    assert_eq!(report["published"], json!(2));

    // The journal really advanced, and the commit marker exists.
    let after_journal: Json =
        serde_json::from_slice(&fs::read(&journal_path).expect("read the journal back"))
            .expect("the journal is JSON");
    write_evidence_json("restore-v2", "journal.finished.json", &after_journal);
    assert_eq!(after_journal["state"], json!("closure-verified"));
    let committed: Vec<&str> = after_journal["committed"]
        .as_array()
        .expect("committed array")
        .iter()
        .filter_map(Json::as_str)
        .collect();
    for source in [&setup.claude, &setup.codex] {
        assert!(
            committed.contains(&source.capture.manifest_id.as_str()),
            "the journal records {} as committed",
            source.capture.manifest_id
        );
    }
    assert!(world.scratch.join("w1-commit-marker.json").is_file());

    // Closed/reopened SQL: every count comes from a fresh read-only handle.
    assert_eq!(table_count(&world.db, "source_inputs"), 2);
    assert_eq!(
        table_count_where(&world.db, "source_inputs", "state = 'complete'"),
        2
    );
    assert_eq!(table_count(&world.db, "conversations"), 2);
    // A content array is split per block: each Claude `[text, tool_use]` line
    // is a prose row plus a tool_call row, so eight lines project eleven rows;
    // the codex rollout projects its user, exec call, result and answer.
    assert_eq!(
        table_count(&world.db, "messages"),
        15,
        "11 claude + 4 codex"
    );
    assert_eq!(
        table_count(&world.db, "source_records"),
        13,
        "8 claude + 5 codex"
    );
    assert_eq!(
        table_count_where(
            &world.db,
            "source_message_links",
            "authority = 'canonical' AND message_id IS NOT NULL"
        ),
        15,
        "every projected message has its own canonical link"
    );
    assert_eq!(
        table_count_where(
            &world.db,
            "operation_commit_receipt",
            "operation = 'source_input_activation_v1' AND state = 'committed'"
        ),
        2,
        "each input carries its own activation receipt"
    );
    assert_eq!(
        table_count_where(
            &world.db,
            "operation_commit_receipt",
            "operation = 'mirror-restore-new' AND state = 'committed'"
        ),
        2,
        "each restored input carries its own restore receipt"
    );
    assert_eq!(
        sql_scalar_text(
            &world.db,
            "SELECT value FROM meta WHERE key = 'source_content_generation'"
        ),
        "mcp-t09-generation"
    );

    // The three recall rows are cleared with marker 2 and the real source
    // metadata; every ordinary row keeps its exact literal.
    let rows = message_rows(&world.db);
    write_evidence_json(
        "restore-v2",
        "messages.rows.json",
        &json!({
            "rows": rows
                .iter()
                .map(|row| {
                    json!({
                        "idx": row.idx,
                        "role": row.role,
                        "content": row.content,
                        "excluded": row.excluded.as_ref().map(|marker| json!({
                            "rule_version": marker.rule_version,
                            "reason": marker.reason,
                            "sha256": marker.sha256,
                            "bytes": marker.bytes,
                            "event_key": marker.raw.event_key,
                            "blocks": marker.raw.blocks,
                            "tool_name": marker.anchor.tool_name,
                            "tool_call_id": marker.anchor.tool_call_id,
                            "sessions": marker.src.as_ref().map(|src| src.sessions.clone()),
                            "hits": marker.src.as_ref().map(|src| src.hits.clone()),
                        })),
                    })
                })
                .collect::<Vec<_>>()
        }),
    );
    write_evidence_json(
        "restore-v2",
        "conversations.rows.json",
        &json!(sql_rows(
            &world.db,
            "SELECT c.id, a.slug, c.source_id, c.source_path, c.external_id, \
             c.origin_host, c.identity_host \
             FROM conversations c JOIN agents a ON a.id = c.agent_id ORDER BY c.id"
        )),
    );
    {
        // The mirror's own declared facts, field by field. The sealed blobs
        // themselves are compared byte for byte further down.
        let views = coding_agent_search::raw_mirror::manifest_views(&world.data_dir)
            .expect("read the manifest views");
        write_evidence_json(
            "restore-v2",
            "manifest.views.json",
            &json!(
                views
                    .iter()
                    .map(|view| json!({
                        "manifest_id": view.manifest_id,
                        "provider": view.provider,
                        "agent": view.agent,
                        "source_id": view.source_id,
                        "original_path": view.original_path,
                        "origin_kind": view.origin_kind,
                        "origin_host": view.origin_host,
                        "identity_host": view.identity_host,
                        "external_id": view.external_id,
                        "shape_root": view.shape_root,
                        "blob_blake3": view.blob_blake3,
                        "blob_size_bytes": view.blob_size_bytes,
                        "manifest_blake3": view.manifest_blake3,
                        "db_links": view.db_links.iter().map(|link| json!({
                            "conversation_id": link.conversation_id,
                            "source_path": link.source_path,
                        })).collect::<Vec<_>>(),
                    }))
                    .collect::<Vec<_>>()
            ),
        );

        // A nonzero New publishes exactly one backlink, and it names the
        // conversation this run restored under the manifest's own path. The
        // expected id comes from the candidate's conversation rows, not from
        // the publication lookup.
        let conversation_for = |path: &str| -> i64 {
            let rows = sql_rows(&world.db, "SELECT id, source_path FROM conversations");
            let matches: Vec<i64> = rows
                .iter()
                .filter(|row| row[1].as_str() == Some(path))
                .filter_map(|row| row[0].as_i64())
                .collect();
            assert_eq!(matches.len(), 1, "one conversation for {path}");
            matches[0]
        };
        assert_eq!(report["published_without_backlink"], json!(0));
        assert_eq!(views.len(), 2);
        for view in &views {
            let expected_id = conversation_for(&view.original_path);
            assert_eq!(
                view.db_links.len(),
                1,
                "one backlink for {}",
                view.manifest_id
            );
            assert_eq!(view.db_links[0].conversation_id, Some(expected_id));
            assert_eq!(
                view.db_links[0].source_path.as_deref(),
                Some(view.original_path.as_str())
            );
        }
    }
    let excluded: Vec<&MessageRow> = rows.iter().filter(|row| row.excluded.is_some()).collect();
    assert_eq!(
        excluded.len(),
        3,
        "exactly the three recall results are excluded"
    );
    let wrapper = recall_wrapper();
    let codex_body = codex_application();
    let expected: [(&str, &str, &str, &str); 3] = [
        (
            "mcp__cass-mcp__cass_search",
            "toolu_t09_mcp",
            "t09-claude-u2",
            wrapper.as_str(),
        ),
        ("Bash", "toolu_t09_cli", "t09-claude-u3", wrapper.as_str()),
        ("exec", "t09-call", "line:4", codex_body.as_str()),
    ];
    for (tool_name, call_id, event_key, body) in expected {
        let row = excluded
            .iter()
            .find(|row| {
                row.excluded
                    .as_ref()
                    .and_then(|marker| marker.anchor.tool_call_id.as_deref())
                    == Some(call_id)
            })
            .unwrap_or_else(|| panic!("no excluded row for {call_id}"));
        let marker = row.excluded.as_ref().expect("checked above");
        assert_eq!(marker.rule_version, 2, "{call_id}: v2 marker");
        assert_eq!(marker.reason, ExclusionReason::CassRecall);
        assert_eq!(marker.anchor.tool_name.as_deref(), Some(tool_name));
        assert_eq!(marker.raw.event_key, event_key);
        assert_eq!(
            marker.raw.blocks,
            vec![0],
            "{call_id}: the one result block"
        );
        assert_eq!(
            marker.sha256,
            sha256_hex(body.as_bytes()),
            "{call_id}: body digest"
        );
        assert_eq!(marker.bytes, body.len() as u64, "{call_id}: body length");
        assert!(marker.parse_error.is_none(), "{call_id}: source parsed");
        let src = marker
            .src
            .as_ref()
            .unwrap_or_else(|| panic!("{call_id}: source"));
        assert_eq!(src.sessions, vec!["/synthetic/t09/prior.jsonl".to_string()]);
        assert_eq!(src.hits.len(), 1);
        assert_eq!(src.hits[0].source_id, "local");
        assert_eq!(src.hits[0].line_number, Some(7));
        assert_eq!(row.content, "", "{call_id}: the body is cleared");
        assert_eq!(row.role, "tool_result");
    }

    for kept in CLAUDE_KEPT.iter().chain(CODEX_KEPT.iter()) {
        let row = rows
            .iter()
            .find(|row| row.content == *kept)
            .unwrap_or_else(|| panic!("the ordinary row {kept:?} is missing"));
        assert!(
            row.excluded.is_none(),
            "the ordinary row {kept:?} is not excluded"
        );
    }
    assert!(
        !rows.iter().any(|row| row.content.contains("cass_recall")),
        "no recall envelope survives in the candidate body"
    );

    // The stored safe payload keeps no copy of either cleared body and still
    // carries the ordinary text.
    let payloads = safe_payload_hex(&world.db);
    assert_eq!(payloads.len(), 13);
    let wrapper_hex = hex_of(&wrapper);
    let codex_hex = hex_of(&codex_body);
    let redacted_hex = hex_of("[REDACTED]");
    for payload in &payloads {
        assert!(
            !payload.contains(&wrapper_hex),
            "a safe payload still carries the recall envelope"
        );
        assert!(
            !payload.contains(&codex_hex),
            "a safe payload still carries the codex application text"
        );
    }
    assert!(
        payloads
            .iter()
            .any(|payload| payload.contains(&redacted_hex)),
        "the cleared copies are replaced by the placeholder"
    );
    assert!(
        payloads
            .iter()
            .any(|payload| payload.contains(&hex_of(CLAUDE_KEPT[0]))),
        "the ordinary Claude prose survives in the safe payload"
    );
    assert!(
        payloads
            .iter()
            .any(|payload| payload.contains(&hex_of(CODEX_KEPT[0]))),
        "the ordinary Codex prose survives in the safe payload"
    );

    // The sealed raw mirror and the live sources are byte-identical.
    assert_eq!(
        sealed_blobs(&setup),
        before_blobs,
        "the sealed blobs are unchanged"
    );
    for (source, before) in [&setup.claude, &setup.codex].iter().zip(before_live) {
        assert_eq!(
            file_sha256(&source.live_path),
            before,
            "the live source is unchanged"
        );
    }
    assert_ne!(
        before_counts["messages"],
        counts(&world.db)["messages"],
        "the restore really wrote messages"
    );

    // The real export must reproduce each input's own v2 identity.
    let materials_path = world.tmp.join("profile-materials.json");
    let entries: Vec<Json> = setup
        .materials
        .bindings
        .iter()
        .map(|binding| {
            json!({
                "normalizer_id": binding["normalizer_id"],
                "safety_contract_id": binding["safety_contract_id"],
                "fad_pin": FAD_PIN,
                "mapping_domain": MAPPING_DOMAIN,
                "exclusion_epoch": EPOCH_V2,
                "redaction_fingerprint": fingerprint(),
                "code_version": code_version_v2(),
                "config_source_identity": setup.materials.profile["config_source_identity"],
                "fixed_copy_path": fixed_path_text(world),
                "fixed_config_sha256": setup.materials.profile["fixed_config_sha256"],
                "effective_four_arrays_sha256": setup.materials.profile["effective_four_arrays_sha256"],
                "desensitization_enabled": true,
            })
        })
        .collect();
    let mut bytes = serde_json::to_vec_pretty(&json!({
        "schema": "cass.source-profile-materials/1",
        "profiles": entries,
    }))
    .expect("encode the profile materials");
    bytes.push(b'\n');
    fs::write(&materials_path, bytes).expect("write the profile materials");
    fs::set_permissions(&materials_path, fs::Permissions::from_mode(0o600))
        .expect("tighten the profile materials");

    let export_dir = world.root.path().join("export");
    let export = world.export(&export_dir, &materials_path);
    write_evidence("restore-v2", "export.stdout", &export.stdout);
    write_evidence("restore-v2", "export.stderr", &export.stderr);
    assert!(
        export.status.success(),
        "the export must succeed, stderr={}",
        String::from_utf8_lossy(&export.stderr)
    );
    let summary: Json = serde_json::from_slice(&export.stdout).expect("the export summary");
    assert_eq!(summary["status"], json!("complete"));
    assert_eq!(summary["unique_input_count"], json!("2"));
    assert_eq!(summary["record_count"], json!("13"));
    assert!(!export_dir.join("INCOMPLETE.json").exists());

    let index: Json =
        serde_json::from_slice(&fs::read(export_dir.join("index.json")).expect("read the index"))
            .expect("the index is JSON");
    write_evidence_json("restore-v2", "export.index.json", &index);
    assert_eq!(index["schema"], json!("cass.source-export/2"));
    assert_eq!(index["role"], json!("candidate"));
    assert_eq!(index["surface"], json!("cass_safe_facts"));

    let profiles = index["profiles"].as_array().expect("profile index");
    assert_eq!(
        profiles.len(),
        2,
        "one profile entry per normalizer identity"
    );
    for profile in profiles {
        assert_eq!(profile["exclusion_epoch"], json!(EPOCH_V2));
        assert_eq!(profile["code_version"], json!(code_version_v2()));
        assert_eq!(
            profile["config_source_identity"],
            setup.materials.profile["config_source_identity"]
        );
        assert_eq!(
            profile["fixed_config_sha256"],
            setup.materials.profile["fixed_config_sha256"]
        );
        assert_eq!(
            profile["effective_four_arrays_sha256"],
            setup.materials.profile["effective_four_arrays_sha256"]
        );
        assert_eq!(profile["desensitization_enabled"], json!(true));
        assert_eq!(profile["redaction_fingerprint"], json!(fingerprint()));
        assert_eq!(profile["fad_pin"], json!(FAD_PIN));
        assert_eq!(profile["mapping_domain"], json!(MAPPING_DOMAIN));
        let relative = profile["relative_path"]
            .as_str()
            .expect("the copied profile path");
        let copied = fs::read(export_dir.join(relative)).expect("read the copied fixed copy");
        assert_eq!(
            copied,
            FIXED_TOML.as_bytes(),
            "the fixed copy is published verbatim"
        );
    }

    let mut exported_inputs: Vec<Json> = Vec::new();
    let mut exported_records: Vec<Json> = Vec::new();
    for page in index["pages"].as_array().expect("pages") {
        let path = export_dir.join(page["path"].as_str().expect("page path"));
        let wrapper: Json = serde_json::from_slice(&fs::read(&path).expect("read the page"))
            .expect("the page is JSON");
        for input in wrapper["page"]["inputs"].as_array().expect("page inputs") {
            exported_inputs.push(input.clone());
        }
        for record in wrapper["page"]["records"].as_array().expect("page records") {
            exported_records.push(record.clone());
        }
    }
    assert_eq!(exported_inputs.len(), 2);
    assert_eq!(exported_records.len(), 13);
    // The exporter owns its own order, so every input is matched by the key the
    // binding names, never by position.
    for binding in &setup.materials.bindings {
        let input_key = binding["input_key"].as_str().expect("the binding key");
        let matches: Vec<&Json> = exported_inputs
            .iter()
            .filter(|input| input["input_key"].as_str() == Some(input_key))
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "exactly one exported input carries {input_key}"
        );
        let input = matches[0];
        assert_eq!(
            input["source_id"],
            binding["declaration"]["origin"]["source_id"]
        );
        assert_eq!(input["normalizer_id"], binding["normalizer_id"]);
        assert_eq!(input["safety_contract_id"], binding["safety_contract_id"]);
        assert_eq!(input["state"], json!("complete"));
        assert!(
            input["receipt_key"].as_str().is_some(),
            "an activated input carries a receipt"
        );
        assert!(
            input["activation_request_hash"].as_str().is_some(),
            "an activated input records its activation request"
        );
        let manifest = input["expected_manifest"]
            .as_array()
            .expect("manifest array");
        assert_eq!(manifest.len(), 15, "the frozen header length");
        assert_eq!(manifest[10], json!(code_version_v2()), "code_version");
        assert_eq!(
            manifest[12], setup.materials.profile["config_source_identity"],
            "config identity"
        );
        assert_eq!(manifest[13], setup.materials.profile["fixed_config_sha256"]);
        assert_eq!(
            manifest[14],
            setup.materials.profile["effective_four_arrays_sha256"]
        );
    }

    // The exported safe payloads carry the cleared copies neither, and keep the
    // ordinary text. The exporter publishes the record payload as msgpack
    // bytes in base64.
    for record in &exported_records {
        let Some(text) = record["payload_base64"].as_str() else {
            continue;
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text)
            .expect("the payload is base64");
        let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(
            !hex.contains(&wrapper_hex),
            "the exported payload still carries the recall envelope"
        );
        assert!(
            !hex.contains(&codex_hex),
            "the exported payload still carries the codex application text"
        );
    }
    let exported_payloads: Vec<String> = exported_records
        .iter()
        .filter_map(|record| record["payload_base64"].as_str())
        .map(|text| {
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .expect("the payload is base64")
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        })
        .collect();
    assert!(
        exported_payloads
            .iter()
            .any(|payload| payload.contains(&hex_of(CLAUDE_KEPT[0]))),
        "the exported payload keeps the ordinary Claude prose"
    );
    assert!(
        exported_payloads
            .iter()
            .any(|payload| payload.contains(&hex_of(CODEX_KEPT[0]))),
        "the exported payload keeps the ordinary Codex prose"
    );

    write_evidence_json("restore-v2", "counts.after.json", &counts(&world.db));
    write_evidence(
        "restore-v2",
        "PASS",
        b"recovered=2 messages=15 records=13 export=complete\n",
    );
}

// ---------------------------------------------------------------------------
// 09-AC2: every single-fact material mutation is refused before any write
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Mutation {
    RemoveProfileKey,
    MissingRootSourceProfile,
    UnknownCodeVersion,
    EpochMismatch,
    RedactionFingerprint,
    MissingFixedCopy,
    ChangedCopyBytes,
    ChangedFixedHash,
    ChangedArraysHash,
}

fn mutate(world: &World, journal: &mut Json, mutation: Mutation) {
    match mutation {
        Mutation::RemoveProfileKey => {
            // One key inside the profile object: the rest of the profile, the
            // contexts, their digest and every planned binding stay as they are.
            journal["source_profile"]
                .as_object_mut()
                .expect("the profile is an object")
                .remove("exclusion_epoch")
                .expect("the key is present before removal");
        }
        Mutation::MissingRootSourceProfile => {
            // The journal's own `source_profile` member is absent, while the
            // contexts, their digest and every planned binding stay intact.
            journal
                .as_object_mut()
                .expect("the journal is an object")
                .remove("source_profile")
                .expect("the member is present before removal");
        }
        Mutation::UnknownCodeVersion => {
            journal["source_profile"]["code_version"] =
                json!(format!("cass-source-exclusion/3+{}", fingerprint()));
        }
        Mutation::EpochMismatch => {
            journal["source_profile"]["exclusion_epoch"] = json!("cass-source-exclusion/1");
        }
        Mutation::RedactionFingerprint => {
            journal["source_profile"]["redaction_fingerprint"] =
                json!(format!("redact-v0:{}", fingerprint()));
        }
        Mutation::MissingFixedCopy => {
            fs::remove_file(&world.fixed).expect("remove the fixed copy");
        }
        Mutation::ChangedCopyBytes => {
            let mut bytes = fs::read(&world.fixed).expect("read the fixed copy");
            bytes.extend_from_slice(b"\n# a different copy of the same rules\n");
            fs::write(&world.fixed, bytes).expect("write the changed fixed copy");
        }
        Mutation::ChangedFixedHash => {
            journal["source_profile"]["fixed_config_sha256"] = json!("0".repeat(64));
        }
        Mutation::ChangedArraysHash => {
            journal["source_profile"]["effective_four_arrays_sha256"] = json!("1".repeat(64));
        }
    }
}

#[test]
fn mcp_restore_rule_epochs_reject_bad_v2_material_without_writes() {
    let cases = [
        ("remove-profile-key", Mutation::RemoveProfileKey),
        (
            "missing-root-source-profile",
            Mutation::MissingRootSourceProfile,
        ),
        ("unknown-code-version", Mutation::UnknownCodeVersion),
        ("epoch-code-version-mismatch", Mutation::EpochMismatch),
        ("redaction-fingerprint", Mutation::RedactionFingerprint),
        ("missing-fixed-copy", Mutation::MissingFixedCopy),
        ("changed-copy-bytes", Mutation::ChangedCopyBytes),
        ("changed-fixed-hash", Mutation::ChangedFixedHash),
        ("changed-arrays-hash", Mutation::ChangedArraysHash),
    ];
    for (case, mutation) in cases {
        let setup = setup();
        let world = &setup.world;
        let mut journal = journal_value(world, &setup.materials);
        let before_counts = counts(&world.db);
        let before_blobs = sealed_blobs(&setup);
        mutate(world, &mut journal, mutation);
        // The exact material the CLI is about to refuse, so the position of
        // each mutation is auditable instead of inferred from the case name.
        write_evidence_json(case, "journal.mutated.json", &journal);
        let journal_path = write_journal(world, &journal, "journal.json");
        let before_journal = fs::read(&journal_path).expect("read the planned journal");

        let output = world.recover(&journal_path);
        write_evidence(case, "recover.stdout", &output.stdout);
        write_evidence(case, "recover.stderr", &output.stderr);
        assert!(
            output.status.code() != Some(0),
            "{case}: the mutated material must be refused"
        );
        assert_eq!(
            error_kind(&output),
            "source_restore_material_mismatch",
            "{case}: the existing material refusal keeps its own kind"
        );
        assert_eq!(
            counts(&world.db),
            before_counts,
            "{case}: a refused material writes no candidate row"
        );
        assert_eq!(
            fs::read(&journal_path).expect("read the journal back"),
            before_journal,
            "{case}: no false progress is recorded in the journal"
        );
        assert_eq!(
            sealed_blobs(&setup),
            before_blobs,
            "{case}: the sealed mirror is untouched"
        );
        assert!(
            !world.scratch.join("w1-commit-marker.json").exists(),
            "{case}: no commit marker is written"
        );
        write_evidence(
            case,
            "PASS",
            b"refused=source_restore_material_mismatch writes=0\n",
        );
    }
}
