//! Resident Pi CLI coverage for callback diagnostics and exact process teardown.

#![cfg(target_os = "linux")]

use coding_agent_search::storage::api::Conn;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Instant;
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
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/alien_pi_resident");
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
        serde_json::from_str(include_str!("fixtures/alien_pi_resident/stages.json")).unwrap();
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

fn process_start(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    Some(
        stat.split_once(") ")?
            .1
            .split_whitespace()
            .nth(19)?
            .to_string(),
    )
}

fn pi_traces(log: &str) -> Vec<String> {
    log.lines()
        .filter(|line| line.contains("scan_session") && line.contains("agent=pi_agent"))
        .map(str::to_owned)
        .collect()
}

struct Watcher {
    root: PathBuf,
    source: PathBuf,
    child: Option<Child>,
    pid: u32,
    start: String,
    executable: PathBuf,
    stages: Vec<Value>,
}

impl Watcher {
    fn new(label: &str) -> Self {
        let mut builder = tempfile::Builder::new();
        let prefix = format!("cass-pi-resident-{label}-");
        builder.prefix(&prefix);
        let temporary = if let Some(parent) = std::env::var_os("CASS_ALIEN_TEST_ARTIFACT_ROOT") {
            fs::create_dir_all(&parent).unwrap();
            builder.tempdir_in(parent).unwrap()
        } else {
            builder.tempdir().unwrap()
        };
        let root = temporary.keep();
        for name in ["home", "config", "cache", "xdg", "cwd"] {
            fs::create_dir(root.join(name)).unwrap();
        }
        let configured = root.join("configured-root");
        let source = configured.join(RELATIVE);
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, fixture("S0")).unwrap();
        fs::create_dir(root.join("config/cass")).unwrap();
        fs::write(root.join("config/cass/sources.toml"), format!(
            "[[sources]]\nname=\"synthetic-pi-watch\"\ntype=\"local\"\norigin_host=\"synthetic-watch-host\"\npaths=[{}]\n",
            json!(configured))).unwrap();
        let executable = PathBuf::from(env!("CARGO_BIN_EXE_cass"));
        let args = vec![
            "-v".to_string(),
            "index".to_string(),
            "--watch".to_string(),
            "--watch-interval".to_string(),
            "1".to_string(),
            "--data-dir".to_string(),
            root.join("data").display().to_string(),
            "--json".to_string(),
            "--robot-trace-ingest".to_string(),
        ];
        let child = Command::new(&executable)
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LANG", "C.UTF-8")
            .env("HOME", root.join("home"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_CACHE_HOME", root.join("cache"))
            .env("XDG_DATA_HOME", root.join("xdg"))
            .env("TMPDIR", &root)
            .env("CASS_SKIP_UPDATE", "1")
            .current_dir(root.join("cwd"))
            .stdout(Stdio::from(
                File::create(root.join("watch.stdout")).unwrap(),
            ))
            .stderr(Stdio::from(
                File::create(root.join("watch.stderr")).unwrap(),
            ))
            .spawn()
            .unwrap();
        let pid = child.id();
        let mut result = Self {
            root,
            source,
            child: Some(child),
            pid,
            start: String::new(),
            executable,
            stages: Vec::new(),
        };
        result.start = process_start(pid).expect("spawned watch process identity");
        let actual = fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        assert_eq!(actual, fs::canonicalize(&result.executable).unwrap());
        write_json(
            &result.root.join("identity.json"),
            &json!({"pid": pid,
            "start_ticks": result.start, "exe": actual, "argv": args,
            "environment_keys": ["PATH", "LANG", "HOME", "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR", "CASS_SKIP_UPDATE"]}),
        );
        result
    }

    fn logs(&self) -> String {
        fs::read_to_string(self.root.join("watch.stderr")).unwrap()
    }

    fn wait<T>(&mut self, label: &str, mut observe: impl FnMut(&Self) -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "{}: watcher exited while waiting for {label}",
                self.root.display()
            );
            assert_eq!(
                process_start(self.pid).as_deref(),
                Some(self.start.as_str())
            );
            if let Some(value) = observe(self) {
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "{}: {label} observation deadline",
                self.root.display()
            );
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    fn idle(&mut self, after_ns: u128, reasons: &Value) -> Value {
        let event = self.wait("fresh idle progress", |watch| {
            watch
                .logs()
                .lines()
                .rev()
                .filter_map(|s| serde_json::from_str::<Value>(s).ok())
                .find(|event| {
                    event["phase_code"] == 0
                        && event["ts_ms"]
                            .as_u64()
                            .is_some_and(|ms| u128::from(ms) * 1_000_000 > after_ns)
                })
        });
        assert_eq!(
            &event["recall_uncovered_by_reason"],
            reasons,
            "{}: live per-callback reason map",
            self.root.display()
        );
        let total: u64 = reasons
            .as_object()
            .unwrap()
            .values()
            .map(|n| n.as_u64().unwrap())
            .sum();
        assert_eq!(
            event["recall_uncovered_total"],
            total,
            "{}: live per-callback total",
            self.root.display()
        );
        event
    }

    fn stage(&mut self, stage: &str) {
        let before = pi_traces(&self.logs()).len();
        let bytes = fixture(stage);
        if stage != "S0" {
            let current = fs::read(&self.source).unwrap();
            assert!(bytes.starts_with(&current) && bytes.len() > current.len());
            let mut file = OpenOptions::new().append(true).open(&self.source).unwrap();
            file.write_all(&bytes[current.len()..]).unwrap();
            file.flush().unwrap();
            file.sync_all().unwrap();
        }
        let want = expected(stage);
        let db_time =
            self.wait("database endpoint", |watch| {
                if stage == "S0"
                    && !watch.logs().contains(&format!(
                        "watching {}",
                        watch.root.join("configured-root").display()
                    ))
                {
                    return None;
                }
                let connection = Conn::open_read(&watch.root.join("data/agent_search.db")).ok()?;
                let counts: (i64, i64, i64) = connection.query_row_map(
                "SELECT (SELECT count(*) FROM conversations), (SELECT count(*) FROM messages), \
                 (SELECT count(*) FROM messages WHERE excluded IS NOT NULL)", &[],
                |r| Ok((r.get_typed(0)?, r.get_typed(1)?, r.get_typed(2)?))).ok()?;
                (counts
                    == (
                        1,
                        want["db_messages"].as_i64().unwrap(),
                        want["db_recall_excluded"].as_i64().unwrap(),
                    ))
                    .then(|| ns(SystemTime::now()))
            });
        let idle = self.idle(db_time, &want["uncovered_by_reason"]);
        let traces = pi_traces(&self.logs());
        // The initial scan may finish before its spawn receipt is saved.
        let new_traces = if stage == "S0" {
            &traces[..]
        } else {
            &traces[before..]
        };
        assert_eq!(new_traces.len(), 1, "{stage}: single declared Pi root");
        let expected_total = want["uncovered_total"].as_u64().unwrap();
        assert!(new_traces[0].contains(&format!("recall_uncovered_total={expected_total}")));
        assert!(new_traces[0].contains(&format!(
            "recall_uncovered_by_reason={}",
            want["uncovered_by_reason"]
        )));
        let database = db_snapshot(&self.root.join("data"), &self.source, stage);
        let blobs: Vec<_> = walkdir::WalkDir::new(self.root.join("data/raw-mirror/v1/blobs"))
            .into_iter()
            .map(Result::unwrap)
            .filter(|e| e.file_type().is_file())
            .filter(|e| fs::read(e.path()).unwrap() == bytes)
            .map(|e| e.into_path())
            .collect();
        assert!(!blobs.is_empty());
        assert_eq!(fs::read(&self.source).unwrap(), bytes);
        self.stages.push(
            json!({"stage": stage, "pid": self.pid, "start_ticks": self.start,
            "db_observed_ns": db_time, "fresh_idle": idle, "pi_trace": new_traces,
            "source_sha256": sha256(&bytes), "raw_blobs": blobs, "db": database}),
        );
        write_json(
            &self.root.join("summary.json"),
            &json!({"stages": self.stages}),
        );
    }

    fn empty_cycle(&mut self, create: bool) {
        let old = self.logs();
        let old_scans = old.matches("watch_scan").count();
        let old_pi = pi_traces(&old).len();
        let path = self
            .source
            .parent()
            .unwrap()
            .join("2026-10-24T00-00-01_empty-session.jsonl");
        if create {
            fs::write(
                &path,
                format!(
                    "{}\n",
                    json!({"type":"session", "version":3,
                "id":"synthetic-empty-session", "timestamp":"2026-10-24T00:00:01Z",
                "cwd":"/synthetic/project"})
                ),
            )
            .unwrap();
        } else {
            let previous = fs::metadata(&path).unwrap().modified().unwrap();
            let modified = SystemTime::now().max(previous + Duration::from_millis(2));
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(FileTimes::new().set_modified(modified))
                .unwrap();
        }
        let observed = self.wait("new native file-event callback", |watch| {
            (watch.logs().matches("watch_scan").count() > old_scans).then(|| ns(SystemTime::now()))
        });
        let reasons = if create {
            json!({"unpaired_result":1})
        } else {
            json!({})
        };
        let idle = self.idle(observed, &reasons);
        let pi = pi_traces(&self.logs());
        let added = &pi[old_pi..];
        assert_eq!(added.len(), usize::from(create));
        let database = db_snapshot(&self.root.join("data"), &self.source, "S4");
        assert_eq!(fs::read(&self.source).unwrap(), fixture("S4"));
        self.stages
            .push(json!({"empty_cycle": if create { 1 } else { 2 },
            "pid": self.pid, "start_ticks": self.start, "callback_observed_ns": observed,
            "fresh_idle": idle, "new_pi_trace": added, "db": database}));
        write_json(
            &self.root.join("summary.json"),
            &json!({"stages": self.stages}),
        );
    }

    fn finish(&mut self, strict: bool) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let result = (|| -> Result<Value, String> {
            if child.try_wait().map_err(|e| e.to_string())?.is_none() {
                if process_start(self.pid).as_deref() != Some(self.start.as_str())
                    || fs::read_link(format!("/proc/{}/exe", self.pid)).ok()
                        != fs::canonicalize(&self.executable).ok()
                {
                    return Err("watch process identity changed; no signal sent".into());
                }
                let status = Command::new("/usr/bin/kill")
                    .args(["-INT", &self.pid.to_string()])
                    .status()
                    .map_err(|e| e.to_string())?;
                if !status.success() {
                    return Err("exact watcher SIGINT failed".into());
                }
            }
            let status = child.wait().map_err(|e| e.to_string())?;
            let absent = !Path::new(&format!("/proc/{}", self.pid)).exists();
            Ok(
                json!({"pid": self.pid, "start_ticks": self.start, "signal": status.signal(),
                "exit_code": status.code(), "process_absent": absent, "strict_teardown": strict}),
            )
        })();
        write_json(&self.root.join("cleanup.json"), &json!({"result": result}));
        if strict {
            let value = result.expect("exact watcher cleanup");
            assert_eq!(value["signal"], 2);
            assert_eq!(value["process_absent"], true);
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.finish(false);
    }
}

#[test]
fn alien_pi_resident_valid_append() {
    let mut watch = Watcher::new("valid");
    watch.stage("S0");
    watch.stage("S2");
    watch.idle(ns(SystemTime::now()), &json!({}));
    watch.finish(true);
}

#[test]
fn alien_pi_resident_unpaired_append() {
    let mut watch = Watcher::new("unpaired");
    watch.stage("S0");
    watch.stage("S2");
    watch.stage("S4");
    watch.empty_cycle(true);
    watch.empty_cycle(false);
    watch.finish(true);
}
