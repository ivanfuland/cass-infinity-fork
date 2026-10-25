//! Ticket 03 (`cass-alien-fresh-ingest`): Pi default incremental behaviour over
//! the three valid root shapes, plus the explicit missing-root diagnostic.
//!
//! Every observation comes from the real CLI. A case is one private HOME tree
//! (or one configured root) plus one private data directory, and it drives the
//! same session file through six stages: full ingest, a quiet incremental run,
//! one appended round, another quiet run, one appended round with a mismatched
//! tool-call id, and a last quiet run. The stage expectations are frozen in
//! `tests/fixtures/alien_pi_incremental/stages.json`; the input bytes and their
//! sha256 are frozen in `manifest.json`.
//!
//! ## Why the age wait is where it is
//!
//! The pinned connector skips a file when `mtime < since_ts - 1_000`
//! (`franken_agent_detection` `connectors/utils.rs::file_modified_since`), and
//! the connector-level `since_ts` is the *previous* run's recorded scan time
//! (`connector_local_scan_since_ts_from_state`). A file written just before run
//! N therefore still passes run N+1's threshold, and run N+1 would rescan it.
//! So the file is made at least 1,150 ms old **before each run whose file was
//! just written**. That keeps run N's own scan inclusive of its new bytes (its
//! threshold comes from run N-1) and makes run N+1 see the file as stale. The
//! three quiet stages write nothing, so their age only grows.

use coding_agent_search::storage::api::Conn;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const STAGES_JSON: &str = include_str!("fixtures/alien_pi_incremental/stages.json");
const MANIFEST_JSON: &str = include_str!("fixtures/alien_pi_incremental/manifest.json");

/// The one path every stage writes, relative to whatever root the case uses.
const CANONICAL_RELATIVE: &str =
    ".pi/agent/sessions/--synthetic-alien--/2026-10-24T00-00-00_stage-session.jsonl";
const SESSION_FILE_NAME: &str = "2026-10-24T00-00-00_stage-session.jsonl";
/// The session header's own id, which the connector prefers as `external_id`.
const SESSION_EXTERNAL_ID: &str = "synthetic-stage-session";
const CONFIG_SOURCE_NAME: &str = "synthetic-pi-config";
const CONFIG_ORIGIN_HOST: &str = "synthetic-config-host";
const ORDINARY_USER: &str = "ordinary synthetic user";
const ORDINARY_FINAL: &str = "ordinary synthetic answer";

/// `since_ts - 1_000` is the connector's threshold, so this is 150 ms of slack.
const REQUIRED_AGE_MS: i128 = 1_150;

/// The stages that write bytes; every other stage reuses the previous bytes.
const WRITTEN_STAGES: [&str; 3] = ["S0", "S2", "S4"];

// ============================================================================
// Frozen inputs
// ============================================================================

#[derive(Clone, Debug)]
struct StageExpect {
    id: String,
    action: String,
    db_messages: u64,
    db_recall_excluded: u64,
    uncovered: BTreeMap<String, u64>,
}

#[derive(Clone, Debug)]
struct StageInput {
    file_name: String,
    sha256: String,
    messages: Option<u64>,
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alien_pi_incremental")
}

fn u64_map(value: &Value) -> BTreeMap<String, u64> {
    value
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value.as_u64().unwrap_or_else(|| panic!("{key}: u64")),
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

fn stage_expectations() -> Vec<StageExpect> {
    let stages: Value = serde_json::from_str(STAGES_JSON).expect("stages.json is JSON");
    assert_eq!(
        stages["schema"].as_str(),
        Some("cass-alien-pi-stages/1"),
        "stages.json schema"
    );
    let list = stages["stages"]
        .as_array()
        .expect("stages.json stages array")
        .iter()
        .map(|stage| {
            let uncovered = u64_map(&stage["uncovered_by_reason"]);
            let total: u64 = uncovered.values().copied().sum();
            assert_eq!(
                stage["uncovered_total"].as_u64(),
                Some(total),
                "{}: the frozen total equals its frozen map",
                stage["id"]
            );
            StageExpect {
                id: stage["id"].as_str().expect("stage id").to_string(),
                action: stage["action"].as_str().expect("stage action").to_string(),
                db_messages: stage["db_messages"].as_u64().expect("db_messages"),
                db_recall_excluded: stage["db_recall_excluded"]
                    .as_u64()
                    .expect("db_recall_excluded"),
                uncovered,
            }
        })
        .collect::<Vec<_>>();
    let ids: Vec<&str> = list.iter().map(|stage| stage.id.as_str()).collect();
    assert_eq!(ids, ["S0", "S1", "S2", "S3", "S4", "S5"], "stage roster");
    list
}

fn stage_inputs() -> BTreeMap<String, StageInput> {
    let manifest: Value = serde_json::from_str(MANIFEST_JSON).expect("manifest.json is JSON");
    assert_eq!(
        manifest["schema"].as_str(),
        Some("cass-alien-pi-stage-inputs/1"),
        "manifest.json schema"
    );
    assert_eq!(
        manifest["canonical_target_relative_path"].as_str(),
        Some(CANONICAL_RELATIVE),
        "the fixture contract and this file must name the same relative path"
    );
    manifest["inputs"]
        .as_array()
        .expect("manifest inputs array")
        .iter()
        .map(|input| {
            let stage = input["stage"].as_str().expect("input stage").to_string();
            let file_name = Path::new(input["file"].as_str().expect("input file"))
                .file_name()
                .expect("input file name")
                .to_string_lossy()
                .into_owned();
            (
                stage,
                StageInput {
                    file_name,
                    sha256: input["sha256"].as_str().expect("input sha256").to_string(),
                    messages: input["messages"].as_u64(),
                },
            )
        })
        .collect()
}

/// The frozen bytes for a writing stage, checked against the manifest hash.
///
/// The manifest records the path the fixtures were authored under
/// (`fixtures/pi-stages/...`); this ticket delivers them next to this test, so
/// only the file name is taken from it. The sha256 is what binds the two.
fn frozen_bytes(inputs: &BTreeMap<String, StageInput>, stage: &str) -> Vec<u8> {
    let input = inputs
        .get(stage)
        .unwrap_or_else(|| panic!("no frozen input for {stage}"));
    let path = fixture_dir().join(&input.file_name);
    let bytes = fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    assert_eq!(
        sha256_hex(&bytes),
        input.sha256,
        "{stage}: the fixture bytes are the frozen input"
    );
    if let Some(messages) = input.messages {
        assert_eq!(
            session_records(&bytes).len() as u64,
            messages,
            "{stage}: the frozen input holds the declared message count"
        );
    }
    bytes
}

// ============================================================================
// Small helpers
// ============================================================================

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn unix_ns(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH)
        .expect("clock is after the epoch")
        .as_nanos()
}

fn file_mtime_ns(path: &Path) -> u128 {
    unix_ns(
        fs::metadata(path)
            .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()))
            .modified()
            .unwrap_or_else(|err| panic!("mtime {}: {err}", path.display())),
    )
}

/// Age of the session file in milliseconds; a future mtime reads as zero.
fn file_age_ms(path: &Path) -> i128 {
    let mtime = file_mtime_ns(path);
    let now = unix_ns(SystemTime::now());
    let age_ns = now.saturating_sub(mtime);
    i128::try_from(age_ns / 1_000_000).unwrap_or(i128::MAX)
}

/// Block until the session file is old enough for the next run's threshold to
/// skip it; returns how long this call actually waited.
fn wait_until_old_enough(path: &Path) -> u128 {
    let start = Instant::now();
    loop {
        let age = file_age_ms(path);
        if age >= REQUIRED_AGE_MS {
            return start.elapsed().as_millis();
        }
        let remaining = (REQUIRED_AGE_MS - age).max(1);
        std::thread::sleep(Duration::from_millis(
            u64::try_from(remaining).unwrap_or(1) + 2,
        ));
    }
}

/// The candidate CLI. `CASS_ALIEN_TEST_CASS_BIN` exists only for the frozen
/// pre-fix red and is never consulted by any other path in this file.
fn cass_bin() -> PathBuf {
    match std::env::var_os("CASS_ALIEN_TEST_CASS_BIN") {
        Some(path) => {
            let path = PathBuf::from(path);
            assert!(
                path.is_file(),
                "CASS_ALIEN_TEST_CASS_BIN must name an existing CLI: {}",
                path.display()
            );
            path
        }
        None => PathBuf::from(env!("CARGO_BIN_EXE_cass")),
    }
}

fn claim_artifact_dir(parent: &Path, label: &str) -> PathBuf {
    let mut attempt = 0u32;
    loop {
        let name = if attempt == 0 {
            label.to_string()
        } else {
            format!("{label}-r{}", attempt + 1)
        };
        let candidate = parent.join(name);
        match fs::create_dir(&candidate) {
            Ok(()) => return candidate,
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                attempt += 1;
                assert!(
                    attempt < 1000,
                    "cannot claim an artifact directory for {label}"
                );
            }
            Err(err) => panic!(
                "cannot create artifact directory {}: {err}",
                candidate.display()
            ),
        }
    }
}

fn write_json(path: &Path, value: &Value) {
    let mut file =
        fs::File::create(path).unwrap_or_else(|err| panic!("create {}: {err}", path.display()));
    file.write_all(&serde_json::to_vec_pretty(value).expect("JSON serializes"))
        .unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
}

fn display_path(path: &Path) -> String {
    path.display().to_string()
}

/// `/proc/<pid>/stat` field 22 (starttime, clock ticks since boot).
fn proc_start_ticks(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    rest.split_whitespace().nth(19)?.parse().ok()
}

// ============================================================================
// Case environment
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootKind {
    /// `$HOME/.pi/agent/sessions/...` -- the default agent home.
    DefaultHome,
    /// `PI_CODING_AGENT_DIR` points outside any `.pi/agent` shaped path.
    AgentDirOverride,
    /// An explicit `sources.toml` root holding the canonical relative path.
    ConfiguredRoot,
    /// An explicit `sources.toml` root whose path does not exist.
    ConfiguredMissingRoot,
}

impl RootKind {
    const fn label(self) -> &'static str {
        match self {
            Self::DefaultHome => "default-home",
            Self::AgentDirOverride => "agent-dir-override",
            Self::ConfiguredRoot => "configured-root",
            Self::ConfiguredMissingRoot => "configured-missing-root",
        }
    }

    const fn token(self) -> &'static str {
        match self {
            Self::DefaultHome => "default_home",
            Self::AgentDirOverride => "agent_dir_override",
            Self::ConfiguredRoot => "configured_root",
            Self::ConfiguredMissingRoot => "configured_missing_root",
        }
    }
}

/// One private HOME / config / data-dir set, kept on disk as evidence.
struct CaseEnv {
    kind: RootKind,
    /// Kept (never dropped) so the case tree survives as evidence.
    root: PathBuf,
    home: PathBuf,
    config_home: PathBuf,
    cache_home: PathBuf,
    data_home: PathBuf,
    tmp: PathBuf,
    cwd: PathBuf,
    data_dir: PathBuf,
    /// The session file the stages write, or the missing root's path.
    source_path: PathBuf,
    /// The root named in `sources.toml`, for the configured kinds.
    configured_root: Option<PathBuf>,
    /// The agent home handed to `PI_CODING_AGENT_DIR`, if any.
    agent_home: Option<PathBuf>,
    artifact_dir: PathBuf,
}

impl CaseEnv {
    fn new(kind: RootKind) -> Self {
        let temp = tempfile::Builder::new()
            .prefix("cass-t03-")
            .tempdir()
            .expect("case tempdir");
        // Kept on purpose: deleting it would delete the evidence this test
        // writes into `case.json`.
        let root = temp.keep();
        let home = root.join("home");
        let config_home = root.join("config");
        let cache_home = root.join("cache");
        let data_home = root.join("xdg-data");
        let tmp = root.join("tmp");
        let cwd = root.join("cwd");
        let data_dir = root.join("data");
        for dir in [&config_home, &cache_home, &data_home, &tmp, &cwd, &data_dir] {
            fs::create_dir_all(dir).expect("create case directory");
        }

        let (source_path, configured_root, agent_home) = match kind {
            RootKind::DefaultHome => {
                let home_dir = home.join(".pi/agent");
                fs::create_dir_all(&home_dir).expect("create default agent home");
                (
                    home_dir
                        .join("sessions/--synthetic-alien--")
                        .join(SESSION_FILE_NAME),
                    None,
                    None,
                )
            }
            RootKind::AgentDirOverride => {
                // Deliberately outside every `.pi/agent` / `.omp/agent` /
                // `pi-agent` shaped name: the override is the only thing that
                // points the connector here, so a scratch copy that loses the
                // override has no fallback shape to be recognised by.
                let agent_home = root.join("custom-agent-home");
                fs::create_dir_all(agent_home.join("sessions/--synthetic-alien--"))
                    .expect("create override agent home");
                (
                    agent_home
                        .join("sessions/--synthetic-alien--")
                        .join(SESSION_FILE_NAME),
                    None,
                    Some(agent_home),
                )
            }
            RootKind::ConfiguredRoot => {
                let configured = root.join("configured-root");
                fs::create_dir_all(&configured).expect("create configured root");
                (configured.join(CANONICAL_RELATIVE), Some(configured), None)
            }
            RootKind::ConfiguredMissingRoot => {
                let configured = root.join("absent-root");
                (configured.clone(), Some(configured), None)
            }
        };
        if kind != RootKind::ConfiguredMissingRoot {
            fs::create_dir_all(source_path.parent().expect("source parent"))
                .expect("create source directory");
        }

        if let Some(configured) = &configured_root {
            let config_path = config_home.join("cass/sources.toml");
            fs::create_dir_all(config_path.parent().expect("config parent"))
                .expect("create config dir");
            fs::write(
                &config_path,
                format!(
                    "[[sources]]\nname = \"{CONFIG_SOURCE_NAME}\"\ntype = \"local\"\norigin_host = \"{CONFIG_ORIGIN_HOST}\"\npaths = [\"{}\"]\n",
                    display_path(configured)
                ),
            )
            .expect("write sources.toml");
        }

        let artifact_parent = match std::env::var_os("CASS_ALIEN_TEST_ARTIFACT_ROOT") {
            Some(root) => {
                let root = PathBuf::from(root);
                fs::create_dir_all(&root).expect("create artifact root");
                root
            }
            None => {
                let fallback = root.join("artifacts");
                fs::create_dir_all(&fallback).expect("create fallback artifact root");
                fallback
            }
        };
        let artifact_dir = claim_artifact_dir(&artifact_parent, kind.label());

        let case = Self {
            kind,
            home,
            config_home,
            cache_home,
            data_home,
            tmp,
            cwd,
            data_dir,
            source_path,
            configured_root,
            agent_home,
            artifact_dir,
            root,
        };

        // The override case only means something if no ancestor of the real
        // source or data tree can be matched by the connector's shape rules.
        if kind == RootKind::AgentDirOverride {
            let text = display_path(&case.root);
            for token in [".pi/agent", ".omp/agent", "pi-agent"] {
                assert!(
                    !text.contains(token),
                    "the override case root must not carry {token}: {text}"
                );
            }
        }
        write_json(
            &case.artifact_dir.join("case.json"),
            &json!({
                "record": "cass_alien_pi_incremental_case",
                "label": kind.label(),
                "root_kind": kind.token(),
                "root": display_path(&case.root),
                "home": display_path(&case.home),
                "config_home": display_path(&case.config_home),
                "data_dir": display_path(&case.data_dir),
                "source_path": display_path(&case.source_path),
                "configured_root": case.configured_root.as_deref().map(display_path),
                "agent_home": case.agent_home.as_deref().map(display_path),
                "cass_bin": display_path(&cass_bin()),
            }),
        );
        case
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("agent_search.db")
    }

    /// A fully private environment. `env_clear` plus an explicit whitelist is
    /// what makes a stray `PI_*` or `CASS_*` variable on the host unable to
    /// change the outcome.
    fn cass(&self) -> Command {
        let mut cmd = Command::new(cass_bin());
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_CACHE_HOME", &self.cache_home)
            .env("TMPDIR", &self.tmp)
            // Keep the case offline and deterministic: the update checker would
            // otherwise be the only thing in this run that could touch the
            // network.
            .env("CASS_SKIP_UPDATE", "1")
            .current_dir(&self.cwd);
        if let Some(agent_home) = &self.agent_home {
            cmd.env("PI_CODING_AGENT_DIR", agent_home);
        }
        cmd
    }

    fn env_snapshot(&self) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("PATH".into(), "/usr/bin:/bin".into());
        env.insert("LANG".into(), "C.UTF-8".into());
        env.insert("HOME".into(), display_path(&self.home));
        env.insert("XDG_DATA_HOME".into(), display_path(&self.data_home));
        env.insert("XDG_CONFIG_HOME".into(), display_path(&self.config_home));
        env.insert("XDG_CACHE_HOME".into(), display_path(&self.cache_home));
        env.insert("TMPDIR".into(), display_path(&self.tmp));
        env.insert("CASS_SKIP_UPDATE".into(), "1".into());
        if let Some(agent_home) = &self.agent_home {
            env.insert("PI_CODING_AGENT_DIR".into(), display_path(agent_home));
        }
        env
    }
}

// ============================================================================
// Database read-back
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
struct RowView {
    idx: i64,
    role: String,
    content: String,
    excluded: Option<Value>,
    extra: Value,
}

#[derive(Debug)]
struct MirrorFacts {
    blob_relative_path: String,
    blob_blake3: String,
    blob_size_bytes: u64,
    blob_bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct DbState {
    present: bool,
    conversations: i64,
    source_paths: Vec<String>,
    external_ids: Vec<String>,
    metadata: Value,
    rows: Vec<RowView>,
}

impl DbState {
    fn excluded(&self) -> u64 {
        self.rows
            .iter()
            .filter(|row| row.excluded.is_some())
            .count() as u64
    }

    fn roles(&self) -> Vec<String> {
        self.rows.iter().map(|row| row.role.clone()).collect()
    }

    fn summary(&self) -> Value {
        json!({
            "present": self.present,
            "conversations": self.conversations,
            "source_paths": self.source_paths,
            "external_ids": self.external_ids,
            "messages": self.rows.len(),
            "recall_excluded": self.excluded(),
            "roles": self.roles(),
        })
    }
}

fn decode_json_or_msgpack(
    json_column: Option<String>,
    bin_column: Option<Vec<u8>>,
    what: &str,
) -> Value {
    if let Some(text) = json_column.as_deref().filter(|text| !text.is_empty()) {
        return serde_json::from_str(text)
            .unwrap_or_else(|err| panic!("{what}: JSON column is not JSON: {err}"));
    }
    if let Some(bytes) = bin_column.filter(|bytes| !bytes.is_empty()) {
        return rmp_serde::from_slice(&bytes)
            .unwrap_or_else(|err| panic!("{what}: msgpack column is not decodable: {err}"));
    }
    Value::Null
}

/// Read the whole case database. An absent file is a legitimate observation
/// (the missing-root case), so this never panics on it.
fn read_db(db_path: &Path, label: &str) -> DbState {
    if !db_path.is_file() {
        return DbState::default();
    }
    let conn = Conn::open_read(db_path)
        .unwrap_or_else(|err| panic!("{label}: open {}: {err}", db_path.display()));
    let conversations: i64 = conn
        .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| {
            row.get_typed(0)
        })
        .expect("count conversations");
    let mut state = DbState {
        present: true,
        conversations,
        ..DbState::default()
    };
    if conversations == 0 {
        return state;
    }

    let identities = conn
        .query_all_map(
            "SELECT source_path, external_id FROM conversations ORDER BY id",
            &[],
            |row| {
                Ok((
                    row.get_typed::<Option<String>>(0)?,
                    row.get_typed::<Option<String>>(1)?,
                ))
            },
        )
        .expect("read conversation identities");
    for (source_path, external_id) in identities {
        state.source_paths.push(source_path.unwrap_or_default());
        state.external_ids.push(external_id.unwrap_or_default());
    }

    let metadata: (Option<String>, Option<Vec<u8>>) = conn
        .query_row_map(
            "SELECT metadata_json, metadata_bin FROM conversations LIMIT 1",
            &[],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("read conversation metadata");
    state.metadata = decode_json_or_msgpack(metadata.0, metadata.1, label);

    let raw = conn
        .query_all_map(
            "SELECT m.idx, m.role, m.content, json(m.excluded), m.extra_json, m.extra_bin \
             FROM messages m JOIN conversations c ON c.id = m.conversation_id \
             ORDER BY m.idx",
            &[],
            |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<String>(2)?,
                    row.get_typed::<Option<String>>(3)?,
                    row.get_typed::<Option<String>>(4)?,
                    row.get_typed::<Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .expect("read message rows");
    state.rows = raw
        .into_iter()
        .map(
            |(idx, role, content, excluded, extra_json, extra_bin)| RowView {
                idx,
                role,
                content,
                excluded: excluded.map(|text| {
                    serde_json::from_str(&text)
                        .unwrap_or_else(|err| panic!("{label}: excluded marker is not JSON: {err}"))
                }),
                extra: decode_json_or_msgpack(extra_json, extra_bin, label),
            },
        )
        .collect();
    state
}

/// Read a capture blob by the path a marker or the conversation metadata names.
fn read_mirror_blob(data_dir: &Path, blob_relative_path: &str, label: &str) -> Vec<u8> {
    let path = data_dir
        .join("raw-mirror")
        .join("v1")
        .join(blob_relative_path);
    fs::read(&path)
        .unwrap_or_else(|err| panic!("{label}: read mirror blob {}: {err}", path.display()))
}

/// The conversation's own capture record. A full run inserts the conversation
/// and records this round's blob; a later merge round appends to the same row
/// and leaves the conversation metadata alone, so this stays the FIRST
/// capture's blob (each new marker names its own round's blob instead). The
/// facts here are self-consistency only -- the byte-for-byte comparison
/// against a stage file lives in `assert_rows`, where the round is known.
fn mirror_facts(data_dir: &Path, metadata: &Value, label: &str) -> MirrorFacts {
    let raw_mirror = &metadata["cass"]["raw_mirror"];
    let blob_relative_path = raw_mirror["blob_relative_path"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: raw mirror blob path missing: {metadata}"))
        .to_string();
    let expected_blake3 = raw_mirror["blob_blake3"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: raw mirror blake3 missing: {metadata}"))
        .to_string();
    let expected_size = raw_mirror["blob_size_bytes"]
        .as_u64()
        .unwrap_or_else(|| panic!("{label}: raw mirror size missing: {metadata}"));

    let blob_bytes = read_mirror_blob(data_dir, &blob_relative_path, label);
    assert_eq!(
        blake3_hex(&blob_bytes),
        expected_blake3,
        "{label}: captured blob blake3 must match the recorded metadata"
    );
    assert_eq!(
        blob_bytes.len() as u64,
        expected_size,
        "{label}: captured blob size must match the recorded metadata"
    );
    MirrorFacts {
        blob_relative_path,
        blob_blake3: blake3_hex(&blob_bytes),
        blob_size_bytes: blob_bytes.len() as u64,
        blob_bytes,
    }
}

/// A written round's own capture, proved without relying on excluded markers.
/// The last written stage adds no new marker and the conversation metadata
/// still names the first capture, so neither can show that round's capture.
/// The private raw-mirror tree can: every capture lands there as a blob named
/// by its blake3, whatever the round did to the conversation row.
#[derive(Debug)]
struct RoundCapture {
    stage: String,
    blob_relative_path: String,
    blob_sha256: String,
    blob_blake3: String,
    blob_size_bytes: u64,
    matching_blobs: Vec<String>,
}

impl RoundCapture {
    fn to_json(&self) -> Value {
        json!({
            "stage": self.stage,
            "blob_relative_path": self.blob_relative_path,
            "blob_sha256": self.blob_sha256,
            "blob_blake3": self.blob_blake3,
            "blob_size_bytes": self.blob_size_bytes,
            "matching_blobs": self.matching_blobs,
        })
    }
}

/// Every blob under the private raw mirror, as `(path relative to v1, bytes)`.
fn raw_mirror_blobs(data_dir: &Path) -> Vec<(String, Vec<u8>)> {
    let root = data_dir.join("raw-mirror").join("v1");
    let mut out = Vec::new();
    let mut stack = vec![root.join("blobs")];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries {
            let path = entry.expect("read a raw-mirror entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if !path.is_file() {
                continue;
            }
            let bytes = fs::read(&path)
                .unwrap_or_else(|err| panic!("read raw-mirror blob {}: {err}", path.display()));
            let relative = path
                .strip_prefix(&root)
                .unwrap_or_else(|err| panic!("blob {} is under v1: {err}", path.display()))
                .to_string_lossy()
                .into_owned();
            out.push((relative, bytes));
        }
    }
    out.sort();
    out
}

/// AC2: this round's complete capture is on disk, byte-equal to the frozen
/// stage bytes and named by its blake3.
fn round_capture_proof(data_dir: &Path, stage: &str, bytes: &[u8]) -> RoundCapture {
    let expected_sha256 = sha256_hex(bytes);
    let expected_blake3 = blake3_hex(bytes);
    let matching_blobs: Vec<String> = raw_mirror_blobs(data_dir)
        .into_iter()
        .filter(|(_, blob_bytes)| blob_bytes == bytes)
        .map(|(relative, _)| relative)
        .collect();
    assert!(
        !matching_blobs.is_empty(),
        "{stage}: the round's complete capture blob is on disk (sha256 {expected_sha256}, {} bytes)",
        bytes.len()
    );
    let expected_name = format!("{expected_blake3}.raw");
    for relative in &matching_blobs {
        let name = relative.rsplit('/').next().unwrap_or(relative);
        assert_eq!(
            name, expected_name,
            "{stage}: the capture blob {relative} is named by the round's blake3"
        );
    }
    let blob_relative_path = matching_blobs[0].clone();
    let blob_bytes = read_mirror_blob(data_dir, &blob_relative_path, stage);
    assert_eq!(
        blob_bytes, bytes,
        "{stage}: the recorded capture blob is the round's bytes"
    );
    RoundCapture {
        stage: stage.to_string(),
        blob_relative_path,
        blob_sha256: expected_sha256,
        blob_blake3: expected_blake3,
        blob_size_bytes: bytes.len() as u64,
        matching_blobs,
    }
}

// ============================================================================
// One CLI run
// ============================================================================

#[derive(Debug)]
struct StageRun {
    stage: String,
    argv: Vec<String>,
    env: BTreeMap<String, String>,
    pid: u32,
    start_ticks: Option<u64>,
    started_unix_ns: u128,
    finished_unix_ns: u128,
    waited_ms: u128,
    age_at_start_ms: Option<i128>,
    source_present: bool,
    source_sha256: Option<String>,
    source_mtime_ns: Option<u128>,
    exit_code: Option<i32>,
    stdout: Value,
    stderr: String,
    db: DbState,
    data_dir: PathBuf,
    mirror: Option<MirrorFacts>,
    artifact_dir: PathBuf,
}

impl StageRun {
    fn label(&self) -> String {
        format!("{}[{}]", self.stage, display_path(&self.artifact_dir))
    }

    fn record(&self) -> Value {
        json!({
            "stage": self.stage,
            "argv": self.argv,
            "env": self.env,
            "pid": self.pid,
            "proc_start_ticks": self.start_ticks,
            "started_unix_ns": self.started_unix_ns.to_string(),
            "finished_unix_ns": self.finished_unix_ns.to_string(),
            "waited_ms": self.waited_ms.to_string(),
            "age_at_start_ms": self.age_at_start_ms.map(|age| age.to_string()),
            "source_present": self.source_present,
            "source_sha256": self.source_sha256,
            "source_mtime_ns": self.source_mtime_ns.map(|mtime| mtime.to_string()),
            "exit_code": self.exit_code,
            "stdout_messages": self.stdout["messages"],
            "stdout_conversations": self.stdout["conversations"],
            "stdout_recall_uncovered_total": self.stdout["recall_uncovered_total"],
            "stdout_recall_uncovered_by_reason": self.stdout["recall_uncovered_by_reason"],
            "scan_roots_missing": self.stdout["scan_roots_missing"],
            "sources_config_error": self.stdout["sources_config_error"],
            "db": self.db.summary(),
            "mirror": self.mirror.as_ref().map(|mirror| json!({
                "blob_relative_path": mirror.blob_relative_path,
                "blob_blake3": mirror.blob_blake3,
                "blob_size_bytes": mirror.blob_size_bytes,
                "blob_sha256": sha256_hex(&mirror.blob_bytes),
            })),
            "artifact_dir": display_path(&self.artifact_dir),
        })
    }
}

/// Run one stage through the real CLI and write every observation to disk
/// before any assertion looks at it.
fn run_stage(
    case: &CaseEnv,
    stage: &str,
    full: bool,
    current_bytes: &[u8],
    waited_ms: u128,
) -> StageRun {
    let label = format!("{} {stage}", case.kind.label());
    let evidence = case.artifact_dir.join(stage);
    fs::create_dir_all(&evidence).expect("create stage evidence dir");

    let source_present = case.source_path.is_file();
    let (source_sha256, source_mtime_ns, age_at_start_ms) = if source_present {
        let expected_sha = sha256_hex(current_bytes);
        let on_disk =
            fs::read(&case.source_path).unwrap_or_else(|err| panic!("{label}: read source: {err}"));
        assert_eq!(
            sha256_hex(&on_disk),
            expected_sha,
            "{label}: the session file on disk must be the stage's bytes"
        );
        (
            Some(expected_sha),
            Some(file_mtime_ns(&case.source_path)),
            Some(file_age_ms(&case.source_path)),
        )
    } else {
        assert!(
            current_bytes.is_empty(),
            "{label}: a stage without a source file cannot carry bytes"
        );
        (None, None, None)
    };

    let mut argv: Vec<String> = vec!["-v".into(), "index".into()];
    if full {
        argv.push("--full".into());
    }
    argv.push("--data-dir".into());
    argv.push(display_path(&case.data_dir));
    argv.push("--json".into());
    argv.push("--robot-trace-ingest".into());

    let env = case.env_snapshot();
    let mut cmd = case.cass();
    cmd.args(&argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let started_unix_ns = unix_ns(SystemTime::now());
    let child = cmd
        .spawn()
        .unwrap_or_else(|err| panic!("{label}: spawn cass: {err}"));
    let pid = child.id();
    let start_ticks = proc_start_ticks(pid);
    let output = child
        .wait_with_output()
        .unwrap_or_else(|err| panic!("{label}: wait for cass: {err}"));
    let finished_unix_ns = unix_ns(SystemTime::now());

    write_json(
        &evidence.join("argv.json"),
        &json!({
            "argv": argv,
            "cass_bin": display_path(&cass_bin()),
            "cwd": display_path(&case.cwd),
            "full": full,
        }),
    );
    write_json(&evidence.join("env.json"), &json!(env));
    write_json(
        &evidence.join("identity.json"),
        &json!({ "pid": pid, "proc_start_ticks": start_ticks }),
    );
    write_json(
        &evidence.join("timing.json"),
        &json!({
            "started_unix_ns": started_unix_ns.to_string(),
            "finished_unix_ns": finished_unix_ns.to_string(),
            "waited_ms": waited_ms.to_string(),
            "age_at_start_ms": age_at_start_ms.map(|age| age.to_string()),
        }),
    );
    write_json(
        &evidence.join("source.json"),
        &json!({
            "path": display_path(&case.source_path),
            "present": source_present,
            "sha256": source_sha256,
            "mtime_ns": source_mtime_ns.map(|mtime| mtime.to_string()),
            "bytes": current_bytes.len(),
        }),
    );
    fs::write(evidence.join("stdout.json"), &output.stdout).expect("write stdout");
    fs::write(evidence.join("stderr.log"), &output.stderr).expect("write stderr");
    fs::write(
        evidence.join("exit_code"),
        format!("{:?}\n", output.status.code()),
    )
    .expect("write exit code");

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let stdout = serde_json::from_slice::<Value>(&output.stdout).unwrap_or(Value::Null);
    let db = read_db(&case.db_path(), &label);
    write_json(&evidence.join("db.json"), &db.summary());
    write_json(
        &evidence.join("rows.json"),
        &serde_json::to_value(&db.rows).expect("rows are serializable"),
    );
    let mirror = if db.conversations == 1 {
        Some(mirror_facts(&case.data_dir, &db.metadata, &label))
    } else {
        None
    };

    StageRun {
        stage: stage.to_string(),
        argv,
        env,
        pid,
        start_ticks,
        started_unix_ns,
        finished_unix_ns,
        waited_ms,
        age_at_start_ms,
        source_present,
        source_sha256,
        source_mtime_ns,
        exit_code: output.status.code(),
        stdout,
        stderr,
        db,
        data_dir: case.data_dir.clone(),
        mirror,
        artifact_dir: evidence,
    }
}

// ============================================================================
// Frozen cleanup rules (shared with the T02 evidence)
// ============================================================================

/// The `message` records of a Pi session file, in file order.
fn session_records(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|value| value.get("type").and_then(Value::as_str) == Some("message"))
        .collect()
}

/// The 1-based physical line of each canonical message record.
fn physical_lines(bytes: &[u8]) -> Vec<u64> {
    String::from_utf8_lossy(bytes)
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .filter(|(_, line)| {
            serde_json::from_str::<Value>(line)
                .map(|value| value.get("type").and_then(Value::as_str) == Some("message"))
                .unwrap_or(false)
        })
        .map(|(index, _)| index as u64 + 1)
        .collect()
}

fn flatten_text_body(record: &Value) -> String {
    let content = record.pointer("/message/content");
    match content {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|block| match block.get("type").and_then(Value::as_str) {
                Some("text") => block
                    .get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                Some("thinking") => block
                    .get("thinking")
                    .and_then(Value::as_str)
                    .map(|text| format!("[Thinking] {text}")),
                Some("toolCall") => {
                    let name = block
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    let args = block
                        .get("arguments")
                        .and_then(Value::as_object)
                        .map(|map| {
                            map.iter()
                                .filter_map(|(key, value)| {
                                    value.as_str().map(|value| format!("{key}={value}"))
                                })
                                .take(3)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .unwrap_or_default();
                    Some(if args.is_empty() {
                        format!("[Tool: {name}]")
                    } else {
                        format!("[Tool: {name}] {args}")
                    })
                }
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn body_block_indices(record: &Value) -> Vec<u64> {
    match record.pointer("/message/content") {
        Some(Value::String(_)) => vec![0],
        Some(Value::Array(blocks)) => blocks
            .iter()
            .enumerate()
            .filter(|(_, block)| block.get("type").and_then(Value::as_str) == Some("text"))
            .map(|(index, _)| index as u64)
            .collect(),
        _ => Vec::new(),
    }
}

fn body_leaves(record: &Value) -> Vec<String> {
    match record.pointer("/message/content") {
        Some(Value::String(text)) => vec![text.clone()],
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter(|block| block.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|block| block.get("text").and_then(Value::as_str))
            .filter(|text| !text.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

fn field_after<'a>(line: &'a str, marker: &str) -> &'a str {
    let start = line
        .find(marker)
        .unwrap_or_else(|| panic!("field {marker} missing in: {line}"))
        + marker.len();
    line[start..].split_whitespace().next().unwrap_or_default()
}

// ============================================================================
// Judgments
// ============================================================================

/// AC2: the CLI stdout, `indexing_stats`, the stderr `completed` event and the
/// Pi `scan_session` line agree in every stage; a quiet stage rescans nothing.
///
/// `outcome` is the `scan_session` outcome this stage must report: the first
/// full run creates the conversation (`inserted`), and every later ingesting
/// run re-reads the whole file and appends to the same row (`merged`). A
/// `skipped_duplicate` here would mean the stage's new bytes were dropped.
fn assert_round_surface(
    run: &StageRun,
    expect: &StageExpect,
    ingesting: bool,
    expected_outcome: &str,
) {
    let label = run.label();
    let total: u64 = expect.uncovered.values().copied().sum();
    let stdout = &run.stdout;

    assert_eq!(
        stdout["recall_uncovered_total"].as_u64(),
        Some(total),
        "{label}: stdout recall_uncovered_total"
    );
    assert_eq!(
        u64_map(&stdout["recall_uncovered_by_reason"]),
        expect.uncovered,
        "{label}: stdout recall_uncovered_by_reason"
    );
    assert_eq!(
        stdout["indexing_stats"]["recall_uncovered_total"].as_u64(),
        Some(total),
        "{label}: indexing_stats total"
    );
    assert_eq!(
        u64_map(&stdout["indexing_stats"]["recall_uncovered_by_reason"]),
        expect.uncovered,
        "{label}: indexing_stats by reason"
    );
    assert_eq!(
        stdout["scan_roots_missing"],
        json!([]),
        "{label}: a valid root is never counted as missing"
    );
    assert!(
        stdout["sources_config_error"].is_null(),
        "{label}: a config that loads reports no error: {stdout}"
    );

    let events: Vec<Value> = run
        .stderr
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect();
    let completed = events
        .iter()
        .find(|event| event["event"].as_str() == Some("completed"))
        .unwrap_or_else(|| panic!("{label}: stderr has no completed event"));
    assert_eq!(
        completed["recall_uncovered_total"].as_u64(),
        Some(total),
        "{label}: completed event total"
    );
    assert_eq!(
        u64_map(&completed["recall_uncovered_by_reason"]),
        expect.uncovered,
        "{label}: completed event by reason"
    );

    let pi_lines: Vec<&str> = run
        .stderr
        .lines()
        .filter(|line| line.contains("scan_session") && line.contains("agent=pi_agent"))
        .collect();
    if ingesting {
        assert_eq!(
            pi_lines.len(),
            1,
            "{label}: exactly one Pi scan_session line for the one ingested file; stderr:\n{}",
            run.stderr
        );
        let line = pi_lines[0];
        for old_field in ["external_id=", "bytes=", "outcome="] {
            assert!(
                line.contains(old_field),
                "{label}: the Pi scan_session line keeps the old field {old_field}: {line}"
            );
        }
        let actual_outcome = field_after(line, "outcome=").trim_matches('"');
        assert_eq!(
            actual_outcome, expected_outcome,
            "{label}: an ingested file reports the frozen outcome: {line}"
        );
        assert_eq!(
            field_after(line, "recall_uncovered_total=")
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("{label}: scan_session total is a u64: {line}")),
            total,
            "{label}: scan_session per-case total equals the round JSON"
        );
        let map: BTreeMap<String, u64> =
            serde_json::from_str(field_after(line, "recall_uncovered_by_reason=")).unwrap_or_else(
                |err| panic!("{label}: scan_session by-reason is not JSON ({err}): {line}"),
            );
        assert_eq!(
            map, expect.uncovered,
            "{label}: scan_session per-case map equals the round JSON"
        );
        assert!(
            stdout["messages"].as_u64().unwrap_or(0) > 0,
            "{label}: an ingesting round reports the messages it wrote: {stdout}"
        );
    } else {
        assert!(
            pi_lines.is_empty(),
            "{label}: a quiet round must not rescan the unchanged file: {pi_lines:?}"
        );
        assert_eq!(
            stdout["messages"].as_u64(),
            Some(0),
            "{label}: a quiet round writes no messages"
        );
        assert_eq!(
            stdout["conversations"].as_u64(),
            Some(0),
            "{label}: a quiet round ingests no conversation"
        );
    }
}

/// AC1 and AC3: the database holds the frozen per-stage totals and every row
/// keeps the wiped-or-preserved shape the cleanup rules require.
///
/// `initial_bytes` is the first (full-run) stage file. A full run records the
/// captured blob on the conversation; a merge run appends to the same row and
/// leaves that metadata alone, so the conversation's blob stays the first
/// capture. Each marker carries its own round's blob, which is why the marker
/// check below reads the blob the marker names rather than the conversation's.
fn assert_rows(
    run: &StageRun,
    expect: &StageExpect,
    bytes: &[u8],
    initial_bytes: &[u8],
    first_round: bool,
) {
    let label = run.label();
    let records = session_records(bytes);
    let lines = physical_lines(bytes);
    assert_eq!(
        records.len() as u64,
        expect.db_messages,
        "{label}: the stage's file holds the frozen message count"
    );
    assert_eq!(
        lines.len(),
        records.len(),
        "{label}: one physical line per message"
    );
    assert_eq!(
        run.db.rows.len() as u64,
        expect.db_messages,
        "{label}: the database holds the frozen message count"
    );
    assert_eq!(
        run.db.excluded(),
        expect.db_recall_excluded,
        "{label}: excluded row count"
    );
    for (position, row) in run.db.rows.iter().enumerate() {
        assert_eq!(
            row.idx, position as i64,
            "{label}: row indexes are dense and ordered"
        );
    }

    for row in &run.db.rows {
        let idx = usize::try_from(row.idx).unwrap_or_else(|_| panic!("{label}: negative row idx"));
        let record = records
            .get(idx)
            .unwrap_or_else(|| panic!("{label}: row idx {idx} has no source record"));
        match &row.excluded {
            Some(marker) => assert_positive_row(
                label.as_str(),
                &run.data_dir,
                row,
                record,
                marker,
                lines[idx],
            ),
            None => assert_negative_row(label.as_str(), row, record),
        }
    }

    let mirror = run
        .mirror
        .as_ref()
        .unwrap_or_else(|| panic!("{label}: a positive stage must carry a raw mirror"));
    assert_eq!(
        mirror.blob_blake3,
        blake3_hex(&mirror.blob_bytes),
        "{label}: the conversation mirror blob is the bytes on disk"
    );
    assert_eq!(
        mirror.blob_size_bytes,
        mirror.blob_bytes.len() as u64,
        "{label}: the conversation mirror blob size is the bytes on disk"
    );
    let expected_blob = if first_round { bytes } else { initial_bytes };
    assert_eq!(
        mirror.blob_bytes,
        expected_blob,
        "{label}: the conversation keeps its first capture's blob ({} bytes expected)",
        expected_blob.len()
    );

    assert_eq!(
        run.db.rows.first().map(|row| row.role.as_str()),
        Some("user"),
        "{label}: the first stored row is the ordinary user message"
    );
    assert_eq!(
        run.db.rows.last().map(|row| row.role.as_str()),
        Some("assistant"),
        "{label}: the last stored row is the final answer"
    );
    let user = run
        .db
        .rows
        .iter()
        .find(|row| row.role == "user")
        .unwrap_or_else(|| panic!("{label}: fixture has no user row"));
    assert_eq!(
        user.content, ORDINARY_USER,
        "{label}: the ordinary user body is unchanged"
    );
    assert_eq!(
        run.db.rows.last().expect("at least one row").content,
        ORDINARY_FINAL,
        "{label}: the ordinary final answer is unchanged"
    );
}

fn assert_positive_row(
    label: &str,
    data_dir: &Path,
    row: &RowView,
    record: &Value,
    marker: &Value,
    line: u64,
) {
    assert_eq!(
        row.content, "",
        "{label}: an excluded row's body is cleared: row {}",
        row.idx
    );
    assert_eq!(
        marker["reason"].as_str(),
        Some("cass_recall"),
        "{label}: excluded reason at row {}",
        row.idx
    );
    assert_eq!(
        marker["rule_version"].as_u64(),
        Some(2),
        "{label}: v2 rule version at row {}",
        row.idx
    );

    let body = flatten_text_body(record);
    let sha256 = marker["sha256"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: marker sha256 missing at row {}", row.idx));
    assert_eq!(sha256.len(), 64, "{label}: marker sha256 is hex64");
    assert_eq!(
        sha256,
        sha256_hex(body.as_bytes()),
        "{label}: the marker hashes the cleared body at row {}",
        row.idx
    );
    assert_eq!(
        marker["bytes"].as_u64(),
        Some(body.len() as u64),
        "{label}: the marker records the cleared body length at row {}",
        row.idx
    );
    assert_eq!(
        marker["fingerprint_blake3"].as_str(),
        Some(blake3_hex(body.as_bytes()).as_str()),
        "{label}: the marker records the body blake3 at row {}",
        row.idx
    );

    // Each marker names the blob captured on ITS round. On a merge round that
    // is a new blob, not the one the conversation metadata still carries. Read
    // the named blob and prove it really contains this row.
    let blob_relative_path = marker["raw"]["blob"]
        .as_str()
        .unwrap_or_else(|| panic!("{label}: marker names no captured blob at row {}", row.idx));
    assert!(
        !blob_relative_path.is_empty(),
        "{label}: the marker names a non-empty captured blob at row {}",
        row.idx
    );
    let blob_bytes = read_mirror_blob(data_dir, blob_relative_path, label);
    let blob_records = session_records(&blob_bytes);
    let blob_lines = physical_lines(&blob_bytes);
    assert_eq!(
        blob_records.get(row.idx as usize),
        Some(record),
        "{label}: the marker's blob holds this row's original record at row {} ({blob_relative_path})",
        row.idx
    );
    assert_eq!(
        blob_lines.get(row.idx as usize).copied(),
        Some(line),
        "{label}: the marker's blob holds this row's physical line at row {} ({blob_relative_path})",
        row.idx
    );
    assert_eq!(
        marker["raw"]["idx"].as_u64(),
        Some(row.idx as u64),
        "{label}: the marker records the canonical index at row {}",
        row.idx
    );
    assert_eq!(
        marker["raw"]["event_key"].as_str(),
        Some(format!("pi:line:{line}").as_str()),
        "{label}: the marker names the physical event line at row {}",
        row.idx
    );
    assert_eq!(
        marker["raw"]["blocks"],
        json!(body_block_indices(record)),
        "{label}: the marker keeps the original body block indices at row {}",
        row.idx
    );

    assert_eq!(
        marker["anchor"]["tool_call_id"].as_str(),
        record
            .pointer("/message/toolCallId")
            .and_then(Value::as_str),
        "{label}: the anchor keeps the real binding id at row {}",
        row.idx
    );
    assert_eq!(
        marker["anchor"]["tool_name"].as_str(),
        record.pointer("/message/toolName").and_then(Value::as_str),
        "{label}: the anchor keeps the real binding name at row {}",
        row.idx
    );
    assert!(
        marker["parse_error"].is_null(),
        "{label}: a healthy fixture body has no parse error at row {}",
        row.idx
    );
    assert!(
        marker["src"].is_object(),
        "{label}: a healthy excluded body carries its extracted source at row {}: {marker}",
        row.idx
    );

    // The whole extra is decoded back: the body keeps its slot as the shared
    // placeholder, every other field and array index stays, and no original
    // body leaf survives anywhere in the record.
    let original = &record["message"];
    let actual = &row.extra["message"];
    let placeholder = json!({
        "redacted": true,
        "sha256": sha256,
        "bytes": body.len() as u64,
    });
    match (original.get("content"), actual.get("content")) {
        (Some(Value::String(_)), Some(Value::Object(_))) => assert_eq!(
            actual["content"], placeholder,
            "{label}: a string body becomes the placeholder at row {}",
            row.idx
        ),
        (Some(Value::Array(original_blocks)), Some(Value::Array(actual_blocks))) => {
            assert_eq!(
                original_blocks.len(),
                actual_blocks.len(),
                "{label}: every content block index is retained at row {}",
                row.idx
            );
            for (index, (original_block, actual_block)) in
                original_blocks.iter().zip(actual_blocks).enumerate()
            {
                if original_block.get("type").and_then(Value::as_str) == Some("text") {
                    assert_eq!(
                        actual_block["text"], placeholder,
                        "{label}: text block {index} becomes the placeholder at row {}",
                        row.idx
                    );
                    let mut expected_block = original_block.clone();
                    expected_block["text"] = placeholder.clone();
                    assert_eq!(
                        actual_block, &expected_block,
                        "{label}: text block {index} keeps its other keys at row {}",
                        row.idx
                    );
                } else {
                    assert_eq!(
                        actual_block, original_block,
                        "{label}: non-text block {index} is untouched at row {}",
                        row.idx
                    );
                }
            }
        }
        (Some(original_content), Some(actual_content)) => assert_eq!(
            actual_content, original_content,
            "{label}: body shape at row {}",
            row.idx
        ),
        _ => panic!("{label}: row {} has no content slot", row.idx),
    }
    for (key, value) in original
        .as_object()
        .unwrap_or_else(|| panic!("{label}: record message is an object"))
    {
        if key == "content" {
            continue;
        }
        assert_eq!(
            actual.get(key.as_str()),
            Some(value),
            "{label}: metadata field {key} is retained at row {}",
            row.idx
        );
    }
    for (key, value) in row
        .extra
        .as_object()
        .unwrap_or_else(|| panic!("{label}: extra is an object"))
    {
        if key == "message" {
            continue;
        }
        assert_eq!(
            Some(value),
            record.get(key.as_str()),
            "{label}: record field {key} is retained at row {}",
            row.idx
        );
    }
    let decoded = serde_json::to_string(&row.extra).expect("extra serializes");
    for leaf in body_leaves(record) {
        assert!(
            !decoded.contains(&leaf),
            "{label}: the cleared body leaf does not survive in the decoded extra at row {}",
            row.idx
        );
    }
}

fn assert_negative_row(label: &str, row: &RowView, record: &Value) {
    assert_eq!(
        row.extra, *record,
        "{label}: a preserved row keeps its whole raw record at row {}",
        row.idx
    );
    assert_eq!(
        row.content,
        flatten_text_body(record),
        "{label}: a preserved row keeps its flattened body verbatim at row {}",
        row.idx
    );
}

// ============================================================================
// The three valid-root cases
// ============================================================================

fn drive_valid_root(kind: RootKind) {
    let case = CaseEnv::new(kind);
    let inputs = stage_inputs();
    let stages = stage_expectations();
    let mut current: Vec<u8> = Vec::new();
    let mut initial_bytes: Vec<u8> = Vec::new();
    let mut source_mtime_ns: Option<u128> = None;
    let mut previous_finished_ns: Option<u128> = None;
    let mut stage_records: Vec<Value> = Vec::new();

    for (index, expect) in stages.iter().enumerate() {
        let written = WRITTEN_STAGES.contains(&expect.id.as_str());
        let mut waited_ms = 0u128;
        if written {
            let frozen = frozen_bytes(&inputs, &expect.id);
            if index == 0 {
                // The first stage creates the file.
                fs::write(&case.source_path, &frozen).expect("create the stage session");
            } else {
                // Later stages append only the new suffix. Read what is on disk,
                // prove the frozen stage extends it as a prefix, and append the
                // rest through an append-mode handle.
                let on_disk = fs::read(&case.source_path).unwrap_or_else(|err| {
                    panic!("{} {}: read the source: {err}", kind.label(), expect.id)
                });
                assert_eq!(
                    on_disk,
                    current,
                    "{} {}: the file on disk still holds the previous stage's complete source",
                    kind.label(),
                    expect.id
                );
                assert!(
                    frozen.starts_with(&on_disk),
                    "{} {}: the frozen stage extends the previous complete source as a prefix",
                    kind.label(),
                    expect.id
                );
                let suffix = &frozen[on_disk.len()..];
                assert!(
                    !suffix.is_empty(),
                    "{} {}: an appended stage adds at least one byte",
                    kind.label(),
                    expect.id
                );
                let mut handle = fs::OpenOptions::new()
                    .append(true)
                    .open(&case.source_path)
                    .unwrap_or_else(|err| {
                        panic!("{} {}: open for append: {err}", kind.label(), expect.id)
                    });
                handle.write_all(suffix).unwrap_or_else(|err| {
                    panic!("{} {}: append the suffix: {err}", kind.label(), expect.id)
                });
                handle.flush().unwrap_or_else(|err| {
                    panic!("{} {}: flush the append: {err}", kind.label(), expect.id)
                });
                handle.sync_all().unwrap_or_else(|err| {
                    panic!("{} {}: sync the append: {err}", kind.label(), expect.id)
                });
                drop(handle);
                let appended = fs::read(&case.source_path).unwrap_or_else(|err| {
                    panic!(
                        "{} {}: read back the source: {err}",
                        kind.label(),
                        expect.id
                    )
                });
                assert_eq!(
                    appended,
                    frozen,
                    "{} {}: appending the suffix produces exactly the frozen stage bytes",
                    kind.label(),
                    expect.id
                );
                let appended_mtime = file_mtime_ns(&case.source_path);
                let finished = previous_finished_ns.unwrap_or_else(|| {
                    panic!(
                        "{} {}: an appended stage follows a finished round",
                        kind.label(),
                        expect.id
                    )
                });
                assert!(
                    appended_mtime > finished,
                    "{} {}: the append mtime is strictly later than the previous round's CLI finish (mtime={appended_mtime}, finished={finished})",
                    kind.label(),
                    expect.id
                );
            }
            current = frozen;
            source_mtime_ns = Some(file_mtime_ns(&case.source_path));
            // Only a freshly written file needs this: the run right after the
            // write still sees its own bytes (its threshold comes from the
            // previous run), and the following run must see it as stale.
            waited_ms = wait_until_old_enough(&case.source_path);
        } else if index > 0 {
            // A quiet stage writes nothing: the source bytes and their mtime
            // must be exactly what the previous stage left.
            let on_disk = fs::read(&case.source_path).unwrap_or_else(|err| {
                panic!("{} {}: read the source: {err}", kind.label(), expect.id)
            });
            assert_eq!(
                sha256_hex(&on_disk),
                sha256_hex(&current),
                "{} {}: a quiet stage leaves the source bytes unchanged",
                kind.label(),
                expect.id
            );
            assert_eq!(
                Some(file_mtime_ns(&case.source_path)),
                source_mtime_ns,
                "{} {}: a quiet stage leaves the source mtime unchanged",
                kind.label(),
                expect.id
            );
        }
        if index == 0 {
            initial_bytes = current.clone();
        }
        assert!(
            !current.is_empty(),
            "{}: the first stage must write the frozen bytes",
            kind.label()
        );

        let run = run_stage(&case, &expect.id, index == 0, &current, waited_ms);
        // Evidence first, then the assertions: a red run still leaves its files.
        write_json(&run.artifact_dir.join("assert.json"), &run.record());

        assert_eq!(
            run.exit_code,
            Some(0),
            "{} {}: `cass index` must succeed (rc={:?}); parsed stdout: {}\nstderr tail:\n{}",
            kind.label(),
            expect.id,
            run.exit_code,
            run.stdout,
            run.stderr
                .lines()
                .rev()
                .take(12)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert_eq!(
            run.stdout["success"],
            json!(true),
            "{} {}: the CLI reports success",
            kind.label(),
            expect.id
        );

        assert_eq!(
            run.db.conversations,
            1,
            "{} {}: exactly one conversation in an isolated root",
            kind.label(),
            expect.id
        );
        assert_eq!(
            run.db.source_paths,
            vec![display_path(&case.source_path)],
            "{} {}: the conversation keeps the first parse's source path",
            kind.label(),
            expect.id
        );
        assert_eq!(
            run.db.external_ids,
            vec![SESSION_EXTERNAL_ID.to_string()],
            "{} {}: the conversation keeps the session id as external id",
            kind.label(),
            expect.id
        );

        assert_round_surface(
            &run,
            expect,
            written,
            if index == 0 { "inserted" } else { "merged" },
        );
        assert_rows(&run, expect, &current, &initial_bytes, index == 0);
        // A written round captures this round's complete file; a quiet round
        // captures nothing and keeps the previous round's proof.
        let capture = if written {
            let proof = round_capture_proof(&run.data_dir, &expect.id, &current);
            write_json(&run.artifact_dir.join("capture.json"), &proof.to_json());
            Some(proof)
        } else {
            None
        };
        previous_finished_ns = Some(run.finished_unix_ns);

        stage_records.push(json!({
            "stage": expect.id,
            "action": expect.action,
            "written": written,
            "waited_ms": waited_ms.to_string(),
            "source_sha256": sha256_hex(&current),
            "source_mtime_ns": source_mtime_ns.map(|mtime| mtime.to_string()),
            "run": run.record(),
            "round_capture": capture.map(|proof| proof.to_json()),
        }));
    }

    write_json(
        &case.artifact_dir.join("summary.json"),
        &json!({
            "record": "cass_alien_pi_incremental_summary",
            "label": kind.label(),
            "root_kind": kind.token(),
            "root": display_path(&case.root),
            "source_path": display_path(&case.source_path),
            "data_dir": display_path(&case.data_dir),
            "db": display_path(&case.db_path()),
            "final_source_sha256": sha256_hex(&current),
            "stages": stage_records,
        }),
    );
}

/// AC1: the default `$HOME/.pi/agent` root survives six stages of full, quiet
/// and appended incremental runs.
#[test]
fn alien_pi_incremental_default_home() {
    drive_valid_root(RootKind::DefaultHome);
}

/// AC1: a root pinned by `PI_CODING_AGENT_DIR`, whose path carries none of the
/// connector's shape markers, still ingests and stays incremental.
#[test]
fn alien_pi_incremental_agent_dir_override() {
    drive_valid_root(RootKind::AgentDirOverride);
}

/// AC1: an explicit `sources.toml` root holding the canonical relative path
/// ingests and stays incremental, with no HOME-side copy in play.
#[test]
fn alien_pi_incremental_configured_root() {
    drive_valid_root(RootKind::ConfiguredRoot);
}

/// AC3: an explicitly configured root that does not exist is counted once,
/// named in the warning with its source and absolute path, and produces no
/// conversation.
#[test]
fn alien_pi_incremental_configured_missing_root() {
    let case = CaseEnv::new(RootKind::ConfiguredMissingRoot);
    assert!(
        !case.source_path.exists(),
        "the case premise is that the configured root is absent: {}",
        case.source_path.display()
    );

    let run = run_stage(&case, "M0", true, &[], 0);
    write_json(&case.artifact_dir.join("assert.json"), &run.record());

    assert_eq!(
        run.exit_code,
        Some(0),
        "missing root: a missing configured root is a diagnostic, not a failure; stdout: {}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert_eq!(
        run.stdout["success"],
        json!(true),
        "missing root: the CLI still reports success: {}",
        run.stdout
    );
    assert_eq!(
        run.stdout["scan_roots_missing"],
        json!([CONFIG_SOURCE_NAME]),
        "missing root: `cass index --json` counts exactly the one configured root: {}",
        run.stdout
    );
    assert!(
        run.stdout["sources_config_error"].is_null(),
        "missing root: a config that loads reports no error: {}",
        run.stdout
    );
    assert_eq!(
        run.stdout["indexing_stats"]["total_conversations"].as_u64(),
        Some(0),
        "missing root: nothing is ingested"
    );

    let missing = display_path(&case.source_path);
    let warns: Vec<&str> = run
        .stderr
        .lines()
        .filter(|line| line.contains("configured scan root does not exist; skipped"))
        .collect();
    assert!(
        !warns.is_empty(),
        "missing root: the run must warn about the skipped root; stderr:\n{}",
        run.stderr
    );
    assert!(
        warns
            .iter()
            .any(|line| line.contains(CONFIG_SOURCE_NAME) && line.contains(&missing)),
        "missing root: the warning names the source and the absolute path, got {warns:?}"
    );

    assert_eq!(
        run.db.conversations,
        0,
        "missing root: the database holds no conversation: {}",
        run.db.summary()
    );
    assert_eq!(
        run.db.rows.len(),
        0,
        "missing root: the database holds no message rows"
    );

    write_json(
        &case.artifact_dir.join("summary.json"),
        &json!({
            "record": "cass_alien_pi_incremental_summary",
            "label": RootKind::ConfiguredMissingRoot.label(),
            "root_kind": RootKind::ConfiguredMissingRoot.token(),
            "root": display_path(&case.root),
            "missing_path": missing,
            "warning_lines": warns,
            "stages": [run.record()],
        }),
    );
}
