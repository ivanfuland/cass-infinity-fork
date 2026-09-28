//! PR10 task 02 — an interrupted SSH mirror must not publish a half file.
//!
//! The mirror root is a scan root: whatever sits there under a session's real
//! name is read by a connector on the next index. So a transfer that dies
//! half way must leave the *old* complete file exactly as it was, or leave no
//! file at all — never a truncated file under the session's real name.
//!
//! The transfer under test is the one `SyncEngine` runs: these tests take the
//! transfer flags from [`RSYNC_TRANSFER_FLAGS`], the same list the GNU and WSL
//! transports hand to `rsync`, and add only `--bwlimit` — the instrument that
//! widens the interruption window far enough to interrupt inside it. The
//! remote endpoint is replaced by a local staging directory, so no SSH
//! connection is ever made; everything else about the transfer is the real
//! flag vector running against the real destination layout
//! (`prepare_mirror_root` + `mirror_path_under`, not a hand-built directory).
//!
//! Interruption is a `SIGTERM` to the transfer's whole process group, and the
//! group is polled until it is gone before anything on disk is read. `rsync`
//! forks a receiver and a generator, and the receiver is the process that
//! decides what happens to the in-progress file; signalling only the parent
//! would leave the decision to a race.
//!
//! The connector instrument is the codex connector from the real registry.
//! Its `rollout-*.jsonl` discovery matches the session the mirror publishes,
//! and does not match `rsync`'s parked `.rollout-….XXXXXX` temp name — both
//! halves of that are asserted rather than assumed.
//!
//! The file is Linux-only. Every measurement here comes from running GNU
//! `rsync` on a local filesystem under `SIGTERM`; macOS ships openrsync, whose
//! option set and interruption handling are a different implementation that
//! this task has no evidence about. Claiming the same result there by running
//! the same commands would be an assumption, so the file says where it stands
//! instead.

#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use coding_agent_search::connectors::{Connector, ScanContext, ScanRoot, get_connector_factories};
use coding_agent_search::sources::config::SourceDefinition;
use coding_agent_search::sources::sync::{RSYNC_TRANSFER_FLAGS, SyncEngine, mirror_path_under};
use coding_agent_search::storage::sqlite::FrankenStorage;

/// The in-tree codex session fixture: 1 conversation / 3 messages, so an
/// ingest that found the session and one that found nothing are distinguishable
/// by count.
const CODEX_FIXTURE: &str = "codex_real/sessions/2025/11/25/rollout-test.jsonl";

/// Where a mirrored codex home keeps its rollouts, relative to the mirror root.
const SESSION_REL: &str = "sessions/2025/11/25/rollout-test.jsonl";

/// The size of the transferred session. Large enough that the throttle below
/// leaves seconds of transfer to interrupt inside.
const PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// One generated assistant turn of the payload, in bytes.
///
/// Turns are made large rather than numerous on purpose: a few hundred fat
/// turns fill the same 4 MiB as tens of thousands of thin ones, so a run scans
/// and ingests a small conversation instead of a huge one.
///
/// It does not make the archive's message-row count agree with the
/// connector's. For this payload the connector reports 258 messages while the
/// archive written by the same run holds 132 rows; the difference is not
/// localized here, is not caused by this task's change, and is outside its
/// scope. The end-to-end test below therefore pins the archive's
/// *conversation* count exactly and its message count only as non-zero, rather
/// than comparing two instruments whose disagreement nobody has explained.
const TURN_LINE_BYTES: usize = 16 * 1024;

/// KiB/s, the control-plane baseline's throttle. `rsync --bwlimit` is in
/// KiB/s, so the 4 MiB payload takes about a minute of wall clock.
const THROTTLE_KIB_PER_SEC: u32 = 64;

/// How long a single wait may take before the test gives up and reports.
const WAIT_LIMIT: Duration = Duration::from_secs(60);

fn fixture_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative)
}

/// `len` characters of deterministic high-entropy text.
///
/// `-z` is part of the transfer flags, and it throttles the stream that
/// actually crosses the wire: a run of one repeated character compresses to
/// nothing, so `--bwlimit` would have almost no stream to slow down and the
/// transfer would finish before it could be interrupted. A base64 alphabet
/// keeps the text valid inside a JSON string and leaves deflate little to
/// work with.
fn filler(len: usize, seed: u64) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut state = seed | 1;
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        // xorshift64*, so the payload is the same bytes on every run.
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let value = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.push(char::from(ALPHABET[((value >> 33) % 64) as usize]));
    }
    out
}

/// One generated `response_item` assistant turn, exactly `budget` bytes
/// including its newline, so the payload lands on [`PAYLOAD_BYTES`] exactly.
fn generated_turn_line(budget: usize, turn: usize) -> String {
    const PREFIX: &str = r#"{"timestamp":"2025-09-30T15:43:05.000Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"text","text":""#;
    // Closes the text string, the content object, the content array, the
    // payload object and the root object.
    const SUFFIX: &str = "\"}]}}\n";
    assert!(
        budget > PREFIX.len() + SUFFIX.len(),
        "a generated turn needs room for its own JSON, got {budget} bytes"
    );
    let mut line = String::with_capacity(budget);
    line.push_str(PREFIX);
    line.push_str(&filler(
        budget - PREFIX.len() - SUFFIX.len(),
        0x9E37_79B9_7F4A_7C15 ^ (turn as u64),
    ));
    line.push_str(SUFFIX);
    line
}

/// The transferred session: this repository's codex fixture, followed by
/// generated assistant turns up to exactly [`PAYLOAD_BYTES`].
///
/// The size is what makes the transfer interruptible; the codex shape is what
/// makes the same bytes a session the connector has to find once the retry
/// completes. Returns the bytes and the number of generated turns, so a caller
/// can predict the conversation's message count.
fn session_payload() -> (Vec<u8>, usize) {
    let mut out = std::fs::read(fixture_path(CODEX_FIXTURE)).expect("read the codex fixture");
    assert!(
        out.ends_with(b"\n"),
        "the fixture must end on a line boundary or the generated turns would weld onto it"
    );
    let room = PAYLOAD_BYTES - out.len();
    let turns = room / TURN_LINE_BYTES;
    let leftover = room % TURN_LINE_BYTES;
    assert!(
        turns >= 1,
        "the payload must hold at least one generated turn"
    );
    for turn in 0..turns {
        // The first turn absorbs the remainder, so the payload lands on the
        // byte rather than overshooting by a fraction of a line.
        let budget = TURN_LINE_BYTES + if turn == 0 { leftover } else { 0 };
        out.extend_from_slice(generated_turn_line(budget, turn).as_bytes());
    }
    assert_eq!(
        out.len(),
        PAYLOAD_BYTES,
        "the payload must be exactly the declared size"
    );
    (out, turns)
}

/// The source definition the tests' `sources.toml` describes.
fn ssh_source(name: &str, path: &str) -> SourceDefinition {
    let mut source = SourceDefinition::ssh(name, name);
    source.paths = vec![path.to_string()];
    source.origin_host = name.to_string();
    source
}

fn ssh_source_toml(name: &str, path: &str) -> String {
    format!(
        "[[sources]]\nname = \"{name}\"\ntype = \"ssh\"\nhost = \"{name}\"\norigin_host = \"{name}\"\npaths = [\"{path}\"]\n"
    )
}

/// One isolated machine: a private staging directory to transfer *from*, and
/// the mirror directory the production write side would transfer *into*.
struct Mirror {
    /// Held for its `Drop`: deleting this deletes the whole tree.
    _tmp: tempfile::TempDir,
    home: PathBuf,
    config_home: PathBuf,
    data_dir: PathBuf,
    stage: PathBuf,
    scan_root: PathBuf,
    remote_path: String,
    name: String,
}

impl Mirror {
    fn new(name: &str, remote_path: &str) -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let home = tmp.path().join("home");
        let config_home = tmp.path().join("config");
        let data_dir = tmp.path().join("data");
        let stage = tmp.path().join("stage");
        for dir in [&home, &data_dir, &stage] {
            std::fs::create_dir_all(dir).expect("create the isolated directory");
        }

        // The destination is named by the production write side, not by the
        // test: `prepare_mirror_root` authorizes the configured root and
        // `mirror_path_under` names the per-path directory under it.
        let engine = SyncEngine::new(&data_dir);
        let mirror_root = engine
            .prepare_mirror_root(&ssh_source(name, remote_path))
            .expect("the configured mirror root must be authorized");
        let scan_root = mirror_path_under(&mirror_root, remote_path);
        std::fs::create_dir_all(&scan_root).expect("create the mirror directory");

        let config_path = config_home.join("cass/sources.toml");
        std::fs::create_dir_all(config_path.parent().expect("config dir"))
            .expect("create config dir");
        std::fs::write(&config_path, ssh_source_toml(name, remote_path))
            .expect("write sources.toml");

        Self {
            _tmp: tmp,
            home,
            config_home,
            data_dir,
            stage,
            scan_root,
            remote_path: remote_path.to_string(),
            name: name.to_string(),
        }
    }

    fn root(&self) -> &Path {
        self._tmp.path()
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("agent_search.db")
    }

    fn target(&self) -> PathBuf {
        self.scan_root.join(SESSION_REL)
    }

    /// Write `bytes` at the codex session shape under `dir`.
    fn place_session(dir: &Path, bytes: &[u8]) -> PathBuf {
        let dest = dir.join(SESSION_REL);
        std::fs::create_dir_all(dest.parent().expect("parent")).expect("create the session dir");
        std::fs::write(&dest, bytes).expect("write the session");
        dest
    }

    /// The transfer's flag vector, exactly as the transports build it, with
    /// the pull's operands pointed at the staging directory and the mirror.
    fn transfer_command(&self, label: &str, throttle: bool) -> Command {
        let log = std::fs::File::create(self.root().join(format!("{label}.log")))
            .expect("create the transfer log");
        let mut cmd = Command::new("rsync");
        cmd.args(RSYNC_TRANSFER_FLAGS);
        if throttle {
            cmd.arg(format!("--bwlimit={THROTTLE_KIB_PER_SEC}"));
        }
        cmd.args(["--timeout", "600"]);
        // `--` before the operands, matching `run_rsync_command`. The trailing
        // slash on the source means "the directory's contents".
        cmd.arg("--");
        cmd.arg(format!("{}/", self.stage.display()));
        cmd.arg(format!("{}/", self.scan_root.display()));
        // The transfer gets its own process group so the interrupt below can
        // reach every process rsync forks, and only those.
        cmd.stdout(Stdio::from(log.try_clone().expect("clone the log handle")));
        cmd.stderr(Stdio::from(log));
        cmd.process_group(0);
        cmd
    }

    /// `cass index --json` against this machine's data dir and config.
    fn index_json(&self) -> (i32, Option<serde_json::Value>, String) {
        let data_dir = self.data_dir.display().to_string();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cass"));
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", &self.home);
        cmd.env("XDG_DATA_HOME", self.home.join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", &self.config_home);
        cmd.env_remove("CASS_DATA_DIR");
        cmd.env("NO_COLOR", "1");
        cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
        cmd.env_remove("RUST_LOG");
        cmd.env_remove("CLAUDE_CONFIG_DIR");
        cmd.env_remove("CODEX_HOME");
        cmd.args(["index", "--json", "--data-dir", &data_dir]);
        let out = cmd.output().expect("spawn cass index --json");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        (
            out.status.code().unwrap_or(-1),
            serde_json::from_str::<serde_json::Value>(&stdout).ok(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    /// The `sources.toml` this machine was built from, for failure messages.
    fn sources_toml(&self) -> String {
        ssh_source_toml(&self.name, &self.remote_path)
    }
}

/// Every regular file under `root`, with its size.
///
/// Symlinks are neither followed nor reported. `DirEntry::metadata` follows
/// them, so the kind comes from `file_type` — which describes the entry itself
/// — and a symlink falls through both arms below.
fn regular_files_under(root: &Path) -> BTreeMap<PathBuf, u64> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if file_type.is_file() {
                let Ok(meta) = entry.metadata() else { continue };
                out.insert(entry.path(), meta.len());
            }
        }
    }
    out
}

/// A rendering of `files` for failure messages: path relative to `root` and
/// size.
fn describe_files(root: &Path, files: &BTreeMap<PathBuf, u64>) -> String {
    if files.is_empty() {
        return "(no files)".to_string();
    }
    files
        .iter()
        .map(|(path, size)| {
            format!(
                "{} ({size} bytes)",
                path.strip_prefix(root).unwrap_or(path).display()
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn log_tail(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Is any process left in the given process group?
fn group_alive(pgid: u32) -> bool {
    Command::new("kill")
        .args(["-0", "--", &format!("-{pgid}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// What the mirror root holds, by path and size.
type Files = BTreeMap<PathBuf, u64>;

/// Everything under the mirror root right now.
fn snapshot(mirror: &Mirror) -> Files {
    regular_files_under(&mirror.scan_root)
}

/// The one file this transfer is growing, named from what the snapshot shows
/// against the one taken before the transfer started: a file that was not
/// there, or one whose size has moved, and that carries payload.
///
/// This is the transfer's *real* parked temp file — `rsync` writes it beside
/// the destination and renames it into place only on completion — so a caller
/// can hand the live window to the connector instead of inventing a file whose
/// name merely looks like one.
fn growing_file(now: &Files, before: &Files) -> Option<(PathBuf, u64)> {
    let mut grown = now
        .iter()
        .filter(|(path, size)| **size > 0 && before.get(*path) != Some(*size))
        .map(|(path, size)| (path.clone(), *size));
    let first = grown.next();
    assert!(
        grown.next().is_none(),
        "one transfer grows one file; more than one means the snapshot is not what it claims"
    );
    first
}

/// [`growing_file`], for a caller that has already waited for it to exist.
fn require_growing_file(now: &Files, before: &Files) -> (PathBuf, u64) {
    growing_file(now, before).unwrap_or_else(|| {
        panic!(
            "the transfer must be growing a file by now, but the mirror root holds: {}",
            describe_files_of(now)
        )
    })
}

/// [`describe_files`] for a snapshot whose root is not at hand.
fn describe_files_of(files: &Files) -> String {
    if files.is_empty() {
        return "(no files)".to_string();
    }
    files
        .iter()
        .map(|(path, size)| format!("{} ({size} bytes)", path.display()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Wait until *this* transfer has written payload, so the interrupt lands
/// inside the transfer rather than before it.
///
/// "Something is on disk" is the wrong question: the mirror root may already
/// hold a complete session when the transfer starts, and that file would
/// satisfy the test's condition before `rsync` has done anything — which is
/// how an interrupt ends up landing in the file-list phase and proving
/// nothing. The comparison is therefore against the snapshot taken before the
/// transfer was spawned: a file that appeared, or one whose size moved.
///
/// Returns what is on disk at that moment.
fn wait_for_bytes_in_flight(
    mirror: &Mirror,
    before: &Files,
    child: &mut Child,
    log: &Path,
) -> Files {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let now = snapshot(mirror);
        if growing_file(&now, before).is_some() {
            return now;
        }
        if let Some(status) = child.try_wait().expect("poll the transfer") {
            panic!(
                "the transfer exited ({status}) before any bytes reached the mirror root\n--- {} ---\n{}",
                log.display(),
                log_tail(log)
            );
        }
        assert!(
            Instant::now() < deadline,
            "no bytes reached the mirror root within {:?}\n--- {} ---\n{}",
            WAIT_LIMIT,
            log.display(),
            log_tail(log)
        );
        thread::sleep(Duration::from_millis(25));
    }
}

/// `SIGTERM` the transfer's process group and return once every process in it
/// is gone, so nothing is still deciding what to do with the in-progress file
/// when the caller reads the directory.
fn interrupt_and_settle(child: &mut Child, log: &Path) {
    let pgid = child.id();
    let signalled = Command::new("kill")
        .args(["-TERM", "--", &format!("-{pgid}")])
        .status()
        .expect("signal the transfer's process group");
    assert!(
        signalled.success(),
        "the transfer's process group must still exist when it is signalled\n--- {} ---\n{}",
        log.display(),
        log_tail(log)
    );
    let status = child.wait().expect("reap the transfer");
    assert!(
        !status.success(),
        "an interrupted transfer cannot report success ({status})\n--- {} ---\n{}",
        log.display(),
        log_tail(log)
    );

    let deadline = Instant::now() + WAIT_LIMIT;
    while group_alive(pgid) {
        assert!(
            Instant::now() < deadline,
            "the transfer's process group is still alive {:?} after SIGTERM\n--- {} ---\n{}",
            WAIT_LIMIT,
            log.display(),
            log_tail(log)
        );
        thread::sleep(Duration::from_millis(25));
    }
}

/// Run the same transfer without the throttle and require it to succeed.
fn transfer_to_completion(mirror: &Mirror, label: &str) -> BTreeMap<PathBuf, u64> {
    let log = mirror.root().join(format!("{label}.log"));
    let out = mirror
        .transfer_command(label, false)
        .output()
        .expect("run the transfer to completion");
    assert!(
        out.status.success(),
        "the retried transfer must succeed, got {}\n--- {} ---\n{}",
        out.status,
        log.display(),
        log_tail(&log)
    );
    regular_files_under(&mirror.scan_root)
}

/// The codex connector, taken from the registry the indexer uses.
fn codex_connector() -> Box<dyn Connector + Send> {
    get_connector_factories()
        .into_iter()
        .find(|(name, _)| *name == "codex")
        .map(|(_, make)| make())
        .expect("the codex connector must be in the registry")
}

fn scan_context(mirror: &Mirror) -> ScanContext {
    ScanContext::with_roots(
        mirror.data_dir.clone(),
        vec![ScanRoot::local(mirror.scan_root.clone())],
        None,
    )
}

/// What the codex connector would read under the mirror root on the next index.
fn discovered_paths(mirror: &Mirror) -> Vec<PathBuf> {
    codex_connector()
        .discover_source_files(&scan_context(mirror))
        .expect("codex discovery must not fail")
        .into_iter()
        .map(|file| file.source_path)
        .collect()
}

/// `(conversations, messages)` the codex connector parses out of the mirror.
fn parsed_counts(mirror: &Mirror) -> (usize, usize) {
    let conversations = codex_connector()
        .scan(&scan_context(mirror))
        .expect("codex scan must not fail");
    (
        conversations.len(),
        conversations.iter().map(|c| c.messages.len()).sum(),
    )
}

/// `(conversations, messages)` in the archive a `cass index` wrote.
fn archive_counts(db_path: &Path) -> (usize, usize) {
    let storage = FrankenStorage::open(db_path).expect("open storage");
    let counts = (
        storage
            .total_conversation_count()
            .expect("conversation count"),
        storage.total_message_count().expect("message count"),
    );
    storage
        .close_without_checkpoint()
        .expect("close storage without checkpoint");
    counts
}

/// Start the throttled transfer the interruption tests race against.
fn start_throttled_transfer(mirror: &Mirror, label: &str) -> (Child, PathBuf) {
    let log = mirror.root().join(format!("{label}.log"));
    let child = mirror
        .transfer_command(label, true)
        .spawn()
        .expect("spawn the throttled transfer");
    (child, log)
}

/// P1 (fresh target): a transfer interrupted before it completes publishes no
/// file at the session's real name.
///
/// The failing baseline is `--partial`: `rsync` renames its in-progress temp
/// onto the destination name when it is interrupted, so the mirror ends up
/// holding a truncated file where a session belongs.
#[test]
fn interrupted_first_transfer_publishes_no_target_file() {
    let mirror = Mirror::new("laptop", "~/.codex");
    let (payload, _) = session_payload();
    Mirror::place_session(&mirror.stage, &payload);
    let before = snapshot(&mirror);

    let (mut child, log) = start_throttled_transfer(&mirror, "interrupted");
    let in_flight = wait_for_bytes_in_flight(&mirror, &before, &mut child, &log);
    let (parked, parked_len) = require_growing_file(&in_flight, &before);
    assert_ne!(
        parked,
        mirror.target(),
        "the transfer must be writing to its parked temp file, not to the session's real name, \
         when it is interrupted"
    );
    assert!(
        !mirror.target().exists(),
        "the session's real name must not exist while the transfer is running: {}",
        mirror.target().display()
    );
    assert!(
        parked_len > 0,
        "the fragment must carry payload before it is interrupted: {}",
        parked.display()
    );
    interrupt_and_settle(&mut child, &log);

    let after = regular_files_under(&mirror.scan_root);
    assert!(
        after.is_empty(),
        "an interrupted transfer must publish nothing under the mirror root, found {}",
        describe_files(&mirror.scan_root, &after)
    );
    assert!(
        !mirror.target().exists(),
        "the session's real name must not exist after an interrupted first transfer: {}",
        mirror.target().display()
    );
}

/// P1 (existing target): a transfer interrupted while overwriting a complete
/// file leaves that file exactly as it was.
#[test]
fn interrupted_overwrite_preserves_the_previous_complete_file() {
    let mirror = Mirror::new("laptop", "~/.codex");
    let previous = std::fs::read(fixture_path(CODEX_FIXTURE)).expect("read the codex fixture");
    let target = Mirror::place_session(&mirror.scan_root, &previous);
    let published = std::fs::read(&target).expect("read the published session");

    let (payload, _) = session_payload();
    Mirror::place_session(&mirror.stage, &payload);
    let before = snapshot(&mirror);

    let (mut child, log) = start_throttled_transfer(&mirror, "interrupted-overwrite");
    let in_flight = wait_for_bytes_in_flight(&mirror, &before, &mut child, &log);
    let (parked, _) = require_growing_file(&in_flight, &before);
    assert_ne!(
        parked, target,
        "the transfer must be overwriting through a parked temp file, not in place"
    );
    assert_eq!(
        std::fs::read(&target).expect("read the published session mid-transfer"),
        published,
        "the previous complete file must still be its own bytes while the overwrite runs"
    );
    interrupt_and_settle(&mut child, &log);

    let after = std::fs::read(&target).unwrap_or_else(|e| {
        panic!("the published session must survive an interrupted overwrite: {e}")
    });
    assert_eq!(
        after,
        published,
        "an interrupted overwrite must leave the previous complete file byte for byte \
         (was {} bytes, now {} bytes)",
        published.len(),
        after.len()
    );

    let remaining = regular_files_under(&mirror.scan_root);
    assert_eq!(
        remaining.keys().collect::<Vec<_>>(),
        vec![&target],
        "the only file the mirror may hold is the previous complete session, found {}",
        describe_files(&mirror.scan_root, &remaining)
    );
}

/// P2 (live window and after): the connector sees no session, neither in
/// `rsync`'s parked temp fragment while the transfer is still running nor at
/// the session's real name once it has been interrupted.
///
/// The window half is taken against the fragment the transfer is really
/// writing — named from the in-flight snapshot — not against a file this test
/// wrote to look like one.
#[test]
fn interrupted_transfer_is_invisible_to_the_connector() {
    let mirror = Mirror::new("laptop", "~/.codex");
    let (payload, _) = session_payload();
    Mirror::place_session(&mirror.stage, &payload);
    let before = snapshot(&mirror);

    let (mut child, log) = start_throttled_transfer(&mirror, "interrupted-discovery");
    let in_flight = wait_for_bytes_in_flight(&mirror, &before, &mut child, &log);
    let (parked, parked_len) = require_growing_file(&in_flight, &before);
    assert_eq!(
        parked.parent(),
        mirror.target().parent(),
        "rsync parks its temp file beside the destination, so the fragment under test has to be \
         in the destination's own directory: {}",
        parked.display()
    );
    assert_ne!(
        parked,
        mirror.target(),
        "the growing file must be the parked temp, not the session's real name"
    );
    assert!(
        !mirror.target().exists(),
        "the session's real name must not exist while its transfer is still running: {}",
        mirror.target().display()
    );

    // Why the fragment is harmless, stated over the fragment itself rather
    // than assumed: rsync parks it as `.<destination name>.XXXXXX`, and the
    // codex connector's rollout rule needs a name that *starts* with
    // `rollout-`. The observed name is in the message either way.
    let parked_name = parked
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_else(|| panic!("the parked fragment has no name: {}", parked.display()));
    let target_name = mirror
        .target()
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the session's real name is not empty")
        .to_string();
    assert!(
        parked_name.starts_with(&format!(".{target_name}.")),
        "rsync's parked temp file is `.{target_name}.XXXXXX`; observed `{parked_name}` \
         ({parked_len} bytes)"
    );
    assert!(
        !parked_name.starts_with("rollout-"),
        "the connector's rollout rule cannot match `{parked_name}`, which is why the live \
         fragment is invisible while a truncated file at `{target_name}` would not be"
    );

    // The live window, handed to the connector that the indexer itself uses.
    let discovered_mid_transfer = discovered_paths(&mirror);
    assert!(
        !discovered_mid_transfer.contains(&parked),
        "the connector must not treat rsync's parked temp fragment as a session, but it \
         discovered {discovered_mid_transfer:?} including {} ({parked_len} bytes)",
        parked.display()
    );
    assert!(
        discovered_mid_transfer.is_empty(),
        "mid-transfer the mirror root holds only the parked fragment, so the connector must \
         discover nothing, found {discovered_mid_transfer:?}"
    );
    assert_eq!(
        parsed_counts(&mirror),
        (0, 0),
        "the connector must not present a half-transferred session as a complete one"
    );

    interrupt_and_settle(&mut child, &log);

    let discovered = discovered_paths(&mirror);
    assert!(
        discovered.is_empty(),
        "the connector must discover no session under an interrupted mirror root, found {discovered:?} \
         (mirror root holds: {})",
        describe_files(&mirror.scan_root, &regular_files_under(&mirror.scan_root))
    );

    let (conversations, messages) = parsed_counts(&mirror);
    assert_eq!(
        (conversations, messages),
        (0, 0),
        "the connector must parse no conversation out of an interrupted mirror root"
    );
}

/// P2 (second half) and P4: retrying the same transfer after the interruption
/// publishes the complete session, the connector finds it, and `cass index`
/// ingests it.
#[test]
fn retry_after_interruption_publishes_a_complete_discoverable_session() {
    let mirror = Mirror::new("laptop", "~/.codex");
    let (payload, turns) = session_payload();
    let staged = Mirror::place_session(&mirror.stage, &payload);
    let before = snapshot(&mirror);

    let (mut child, log) = start_throttled_transfer(&mirror, "interrupted-then-retried");
    let in_flight = wait_for_bytes_in_flight(&mirror, &before, &mut child, &log);
    let (parked, _) = require_growing_file(&in_flight, &before);
    assert_ne!(
        parked,
        mirror.target(),
        "the retried transfer must also park its fragment beside the destination"
    );
    interrupt_and_settle(&mut child, &log);
    assert!(
        regular_files_under(&mirror.scan_root).is_empty(),
        "the interruption must leave nothing behind before the retry starts"
    );

    let after = transfer_to_completion(&mirror, "retry");
    assert_eq!(
        after.keys().collect::<Vec<_>>(),
        vec![&mirror.target()],
        "a completed retry must leave exactly the published session, found {}",
        describe_files(&mirror.scan_root, &after)
    );

    let transferred = std::fs::read(&mirror.target()).expect("read the published session");
    assert_eq!(
        transferred.len(),
        PAYLOAD_BYTES,
        "the retried transfer must publish the whole file"
    );
    assert_eq!(
        std::fs::read(&staged).expect("read the staged session"),
        transferred,
        "the published session must equal the staged one byte for byte"
    );

    let discovered = discovered_paths(&mirror);
    assert_eq!(
        discovered,
        vec![mirror.target()],
        "the connector must discover the published session at its own name"
    );

    let parsed = parsed_counts(&mirror);
    assert_eq!(
        parsed,
        (1, 3 + turns),
        "the published session must parse as the fixture's conversation plus {turns} generated turns"
    );

    let (code, payload_json, stderr) = mirror.index_json();
    let payload_json = payload_json.unwrap_or_else(|| {
        panic!("`cass index --json` must print one JSON object\n--- stderr ---\n{stderr}")
    });
    assert_eq!(
        code,
        0,
        "`cass index --json` must succeed over the mirror root\n--- stdout ---\n{payload_json}\n--- stderr ---\n{stderr}\n--- sources.toml ---\n{}",
        mirror.sources_toml()
    );
    assert_eq!(
        payload_json["conversations"], 1,
        "the index run must report the published session's conversation: {payload_json}"
    );

    // The completed file is in the archive, not merely on disk: one
    // conversation, with messages.
    //
    // The archive's own row count is deliberately not compared against the
    // connector's tally. `cass index --json`'s `messages` is the scan's count
    // (258 for this payload), while `SELECT COUNT(*) FROM messages` on the
    // archive that same run wrote is 132 -- the ingest path stores fewer
    // message rows than the connector emits, a property of that path which
    // predates this change and is outside this task's scope. It is the same
    // archive for the same bytes either way, so it is reported, not asserted
    // on. See the task report.
    let archived = archive_counts(&mirror.db_path());
    assert_eq!(
        archived.0, 1,
        "the archive must hold the published session's conversation: {payload_json}"
    );
    assert!(
        archived.1 > 0,
        "the archive must hold the published session's messages: {payload_json}"
    );
}

/// P3: the transfer flags carry no bare `--partial` (nor `--inplace`), still
/// carry the rest, and the construction sites cannot reintroduce either as a
/// literal of their own.
#[test]
fn transfer_flags_carry_no_partial_and_no_inplace() {
    for flag in ["-avz", "--links", "--safe-links", "--stats"] {
        assert!(
            RSYNC_TRANSFER_FLAGS.contains(&flag),
            "{flag} must still be passed to rsync: {RSYNC_TRANSFER_FLAGS:?}"
        );
    }
    for flag in ["--partial", "--partial-dir", "--inplace", "--delete"] {
        assert!(
            !RSYNC_TRANSFER_FLAGS.contains(&flag),
            "{flag} must not be passed to rsync: {RSYNC_TRANSFER_FLAGS:?}"
        );
    }

    // Both transports take this list, so the flag vector above is the whole
    // story — unless a construction site grows a literal of its own again.
    let source = include_str!("../src/sources/sync.rs");
    for literal in [
        "\"--partial\"",
        "\"--partial-dir\"",
        "\"--inplace\"",
        "\"--delete\"",
    ] {
        assert!(
            !source.contains(literal),
            "src/sources/sync.rs must not spell {literal} at a construction site"
        );
    }
}
