//! Real CLI coverage for explicit Pi watch-once paths and per-run diagnostics.

use coding_agent_search::storage::api::Conn;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const RELATIVE: &str =
    ".pi/agent/sessions/--synthetic-alien--/2026-10-24T00-00-00_stage-session.jsonl";

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn ns(time: SystemTime) -> u128 {
    time.duration_since(UNIX_EPOCH).unwrap().as_nanos()
}

fn fixture(stage: &str) -> Vec<u8> {
    let directory =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alien_pi_watch_once");
    let manifest: Value =
        serde_json::from_slice(&fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    let input = manifest["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|input| input["stage"] == stage)
        .unwrap();
    let bytes = fs::read(directory.join(format!("{stage}.jsonl"))).unwrap();
    assert_eq!(sha256(&bytes), input["sha256"].as_str().unwrap());
    bytes
}

fn expected(stage: &str) -> Value {
    let stages: Value =
        serde_json::from_str(include_str!("fixtures/alien_pi_watch_once/stages.json")).unwrap();
    stages["stages"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == stage)
        .unwrap()
        .clone()
}

fn decode_extra(text: Option<String>, binary: Option<Vec<u8>>) -> Value {
    if let Some(text) = text {
        serde_json::from_str(&text).unwrap()
    } else if let Some(binary) = binary {
        rmp_serde::from_slice(&binary).unwrap()
    } else {
        Value::Null
    }
}

fn db_snapshot(data: &Path, source: &Path, stage: &str) -> Value {
    let conn = Conn::open_read(&data.join("agent_search.db")).unwrap();
    let count: i64 = conn
        .query_row_map("SELECT count(*) FROM conversations", &[], |r| {
            r.get_typed(0)
        })
        .unwrap();
    assert_eq!(count, 1);
    let identity: (String, String) = conn
        .query_row_map(
            "SELECT external_id, source_path FROM conversations",
            &[],
            |r| Ok((r.get_typed(0)?, r.get_typed(1)?)),
        )
        .unwrap();
    assert_eq!(identity.0, "synthetic-stage-session");
    assert_eq!(identity.1, source.to_string_lossy());
    let rows = conn
        .query_all_map(
            "SELECT idx, role, content, json(excluded), extra_json, extra_bin \
             FROM messages ORDER BY idx",
            &[],
            |r| {
                Ok((
                    r.get_typed::<i64>(0)?,
                    r.get_typed::<String>(1)?,
                    r.get_typed::<String>(2)?,
                    r.get_typed::<Option<String>>(3)?,
                    r.get_typed::<Option<String>>(4)?,
                    r.get_typed::<Option<Vec<u8>>>(5)?,
                ))
            },
        )
        .unwrap();
    let want = expected(stage);
    assert!(!rows.is_empty());
    assert_eq!(rows.len() as u64, want["db_messages"].as_u64().unwrap());
    let mut excluded = 0;
    let mut observations = Vec::new();
    for (position, (idx, role, body, marker, text, binary)) in rows.into_iter().enumerate() {
        assert_eq!(idx, position as i64);
        let extra = decode_extra(text, binary);
        let encoded = extra.to_string();
        let marker: Option<Value> = marker.map(|text| serde_json::from_str(&text).unwrap());
        if matches!(idx, 2 | 6) {
            excluded += 1;
            let mark = marker.as_ref().expect("proved recall remains excluded");
            assert_eq!(mark["reason"], "cass_recall");
            assert_eq!(mark["rule_version"], 2);
            assert_eq!(role, "tool");
            for text in [&body, &encoded] {
                assert!(!text.contains("<cass_recall "));
                assert!(!text.contains("synthetic recalled body"));
            }
        } else {
            assert!(marker.is_none());
            match idx {
                0 | 4 => assert_eq!(body, "ordinary synthetic user"),
                3 | 7 | 10 => assert_eq!(body, "ordinary synthetic answer"),
                9 => {
                    for text in [&body, &encoded] {
                        assert!(text.contains("<cass_recall "));
                        assert!(text.contains("synthetic recalled body"));
                    }
                }
                _ => {}
            }
        }
        observations.push(json!({"idx": idx, "role": role, "body": body,
            "excluded": marker, "extra": extra}));
    }
    assert_eq!(excluded, want["db_recall_excluded"].as_u64().unwrap());
    json!({"conversations": count, "external_id": identity.0, "source_path": identity.1,
        "messages": observations.len(), "excluded": excluded, "rows": observations})
}

fn field<'a>(line: &'a str, name: &str) -> &'a str {
    line.split_once(name)
        .unwrap()
        .1
        .split_whitespace()
        .next()
        .unwrap()
}

struct Case {
    root: PathBuf,
    source: PathBuf,
    last_finished: Option<SystemTime>,
    last_bytes: Vec<u8>,
    last_mtime: Option<SystemTime>,
    rounds: Vec<Value>,
}

impl Case {
    fn new(label: &str) -> Self {
        let mut builder = tempfile::Builder::new();
        let prefix = format!("cass-pi-watch-once-{label}-");
        builder.prefix(&prefix);
        let temporary = if let Some(parent) = std::env::var_os("CASS_ALIEN_TEST_ARTIFACT_ROOT") {
            fs::create_dir_all(&parent).unwrap();
            builder.tempdir_in(parent).unwrap()
        } else {
            builder.tempdir().unwrap()
        };
        // Successful and failed runs both leave inspectable CLI/DB evidence.
        let root = temporary.keep();
        for directory in ["home", "config", "cache", "xdg", "cwd"] {
            fs::create_dir(root.join(directory)).unwrap();
        }
        let source = root.join("home").join(RELATIVE);
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        Self {
            root,
            source,
            last_finished: None,
            last_bytes: Vec::new(),
            last_mtime: None,
            rounds: Vec::new(),
        }
    }

    fn round(&mut self, stage: &str, action: &str) {
        let bytes = fixture(stage);
        match action {
            "create" => fs::write(&self.source, &bytes).unwrap(),
            "append" => {
                let old = fs::read(&self.source).unwrap();
                assert_eq!(old, self.last_bytes);
                assert!(bytes.starts_with(&old) && bytes.len() > old.len());
                let mut file = OpenOptions::new().append(true).open(&self.source).unwrap();
                file.write_all(&bytes[old.len()..]).unwrap();
                file.flush().unwrap();
                file.sync_all().unwrap();
            }
            "quiet" | "touch" => {
                assert_eq!(fs::read(&self.source).unwrap(), self.last_bytes);
                assert_eq!(self.last_bytes, bytes);
                assert_eq!(
                    fs::metadata(&self.source).unwrap().modified().unwrap(),
                    self.last_mtime.unwrap()
                );
            }
            _ => panic!("unknown action {action}"),
        }
        if matches!(action, "append" | "touch") {
            let previous = self.last_finished.unwrap();
            let timestamp = SystemTime::now().max(previous + Duration::from_millis(2));
            File::options()
                .write(true)
                .open(&self.source)
                .unwrap()
                .set_times(FileTimes::new().set_modified(timestamp))
                .unwrap();
            assert!(fs::metadata(&self.source).unwrap().modified().unwrap() > previous);
        }
        assert_eq!(fs::read(&self.source).unwrap(), bytes);
        let mtime = fs::metadata(&self.source).unwrap().modified().unwrap();
        let label = format!("{}-{stage}-{action}", self.rounds.len());
        let stdout = self.root.join(format!("{label}.stdout"));
        let stderr = self.root.join(format!("{label}.stderr"));
        let executable = std::env::var_os("CASS_ALIEN_TEST_CASS_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_cass")));
        let mut args = vec!["-v".to_string(), "index".to_string()];
        if action == "create" {
            args.push("--full".to_string());
        } else {
            args.extend([
                "--watch-once".to_string(),
                self.source.display().to_string(),
            ]);
        }
        args.extend([
            "--data-dir".to_string(),
            self.root.join("data").display().to_string(),
            "--json".to_string(),
            "--robot-trace-ingest".to_string(),
        ]);
        let mut child = Command::new(&executable)
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("HOME", self.root.join("home"))
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("XDG_DATA_HOME", self.root.join("xdg"))
            .env("TMPDIR", &self.root)
            .env("CASS_SKIP_UPDATE", "1")
            .current_dir(self.root.join("cwd"))
            .stdout(Stdio::from(File::create(&stdout).unwrap()))
            .stderr(Stdio::from(File::create(&stderr).unwrap()))
            .spawn()
            .unwrap();
        let pid = child.id();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
        let start_ticks = stat
            .split_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .nth(19)
            .unwrap();
        write_json(
            &self.root.join(format!("{label}.process.json")),
            &json!({"pid": pid, "start_ticks": start_ticks, "argv": args,
                "exe": fs::read_link(format!("/proc/{pid}/exe")).ok(),
                "requested_executable": executable}),
        );
        let status = child.wait().unwrap();
        let finished = SystemTime::now();
        write_json(
            &self.root.join(format!("{label}.exit.json")),
            &json!({"exit_code": status.code(), "finished_ns": ns(finished)}),
        );
        assert!(
            status.success(),
            "{}: {}",
            self.root.display(),
            fs::read_to_string(&stderr).unwrap()
        );
        let payload: Value = serde_json::from_slice(&fs::read(&stdout).unwrap()).unwrap();
        let logs = fs::read_to_string(&stderr).unwrap();
        let completed = logs
            .lines()
            .filter_map(|s| serde_json::from_str::<Value>(s).ok())
            .find(|v| v["event"] == "completed")
            .expect("real completed event");
        let traces: Vec<_> = logs
            .lines()
            .filter(|line| line.contains("scan_session") && line.contains("agent=pi_agent"))
            .collect();
        assert_eq!(traces.len(), usize::from(action != "quiet"));
        let want = expected(stage);
        for trace in &traces {
            assert_eq!(
                field(trace, "recall_uncovered_total=")
                    .parse::<u64>()
                    .unwrap(),
                want["uncovered_total"].as_u64().unwrap()
            );
            assert_eq!(
                serde_json::from_str::<Value>(field(trace, "recall_uncovered_by_reason=")).unwrap(),
                want["uncovered_by_reason"]
            );
        }
        let snapshot = db_snapshot(&self.root.join("data"), &self.source, stage);
        write_json(&self.root.join(format!("{label}.db.json")), &snapshot);
        let blobs: Vec<_> = walkdir::WalkDir::new(self.root.join("data/raw-mirror/v1/blobs"))
            .into_iter()
            .map(Result::unwrap)
            .filter(|entry| entry.file_type().is_file())
            .filter(|entry| fs::read(entry.path()).unwrap() == bytes)
            .map(|entry| entry.into_path())
            .collect();
        assert!(
            !blobs.is_empty(),
            "{stage}: current source bytes must be captured"
        );
        for blob in &blobs {
            assert_eq!(
                blob.file_name().unwrap().to_string_lossy(),
                format!("{}.raw", blake3::hash(&bytes).to_hex())
            );
        }
        assert_eq!(fs::read(&self.source).unwrap(), bytes);
        self.rounds
            .push(json!({"stage": stage, "action": action, "pid": pid,
            "argv": args, "exit_code": status.code(), "finished_ns": ns(finished),
            "previous_finished_ns": self.last_finished.map(ns), "source_mtime_ns": ns(mtime),
            "source_sha256": sha256(&bytes), "current_raw_blobs": blobs,
            "expected_uncovered": want["uncovered_by_reason"], "result": payload,
            "completed": completed, "pi_trace": traces, "db": snapshot}));
        write_json(
            &self.root.join("summary.json"),
            &json!({"rounds": self.rounds}),
        );
        for surface in [&payload, &payload["indexing_stats"], &completed] {
            assert_eq!(
                surface["recall_uncovered_by_reason"],
                want["uncovered_by_reason"],
                "{} {label}: per-run reason map",
                self.root.display()
            );
            assert_eq!(
                surface["recall_uncovered_total"],
                want["uncovered_total"],
                "{} {label}: per-run total",
                self.root.display()
            );
        }
        self.last_bytes = bytes;
        self.last_mtime = Some(mtime);
        self.last_finished = Some(finished);
    }
}

#[test]
fn alien_pi_watch_once_valid_append() {
    let mut case = Case::new("valid");
    case.round("S0", "create");
    case.round("S2", "append");
}

#[test]
fn alien_pi_watch_once_repeat() {
    let mut case = Case::new("repeat");
    case.round("S0", "create");
    case.round("S2", "append");
    case.round("S2", "quiet");
}

#[test]
fn alien_pi_watch_once_unpaired_repeat() {
    let mut case = Case::new("unpaired");
    case.round("S0", "create");
    case.round("S2", "append");
    case.round("S4", "append");
    case.round("S4", "touch");
}
