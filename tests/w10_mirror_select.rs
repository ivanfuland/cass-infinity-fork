//! PR10 task 03 — an ssh mirror root re-reads exactly what its per-file
//! records say changed.
//!
//! Before this task a configured `type = "ssh"` root kept no watermark at all:
//! every `cass index` handed the connector every file under the mirror, because
//! the files carry the *far* machine's mtimes and a watermark comparison cannot
//! tell a fresh transfer from history already read. The root now keeps the same
//! `(root_id, connector)` watermark and `scan_file_state` rows a local root
//! does, and the comparison is the mirror's own: no record, a recorded `size`
//! that differs, or a recorded `mtime` that differs (spec hard constraint 9).
//!
//! Every observation here comes from the real binary (`cass index --json`, its
//! per-run connector statistics, the exit code and the database it wrote) plus
//! the crate's own storage layer read back independently. Both scan paths are
//! exercised through `Command::env`, never `set_var`, so nothing is
//! process-global and `cargo test`'s default parallelism is reproducible
//! without a serialization lock: each test owns its own `TempDir`, HOME,
//! config root, data dir and database.
//!
//! Scope boundary, stated so the report can be read honestly: this file proves
//! which files a mirror hands to the connector and that they land. It does not
//! cover the absent-path transaction (task 04), the rsync publication
//! guarantee (task 02) or the `cass sync` entry point (tasks 05/06).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use coding_agent_search::sources::config::SourceDefinition;
use coding_agent_search::sources::provenance::Source;
use coding_agent_search::sources::sync::{SyncEngine, mirror_path_under, path_to_safe_dirname};
use coding_agent_search::storage::api::Value;
use coding_agent_search::storage::sqlite::FrankenStorage;

/// The in-tree claude_code fixture: 1 conversation / 2 messages, so a pass
/// that ingested it and a pass that did not are distinguishable by count.
const CLAUDE_FIXTURE: &str = "claude_code_real/projects/-test-project/agent-test123.jsonl";

/// The remote path the configured source mirrors. The fixture lands under the
/// mirror directory at the same relative shape `w8_watermarks` uses, so the
/// connector discovers it from the mirror root rather than from a path the
/// test invented.
const REMOTE_PATH: &str = "~/.claude/projects";

const SOURCE_NAME: &str = "laptop";

/// The id of the source registered in the database for the fallback case. It is
/// deliberately *not* [`SOURCE_NAME`]: the fallback is keyed off the DB row's
/// id, and reusing the configured name would make the two derivations look
/// alike in the assertions.
const FALLBACK_SOURCE_ID: &str = "db-registered-laptop";

/// The two spells a same-size rewrite swaps between: the fixture's own word
/// and a replacement of the same length.
const ORIGINAL_KEYWORD: &str = "smartedgar";
const REWRITTEN_KEYWORD: &str = "bravoagent";

/// Run `body` once per scan path: the streaming producer (the default) and the
/// batch path (`CASS_STREAMING_INDEX=0`). The two must follow the same
/// per-root rules, so a rule implemented on only one of them fails here.
fn for_each_scan_path(mut body: impl FnMut(bool)) {
    for streaming in [true, false] {
        body(streaming);
    }
}

fn fixture_bytes() -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(CLAUDE_FIXTURE),
    )
    .expect("read the claude_code fixture")
}

/// Write the in-tree claude_code fixture at `<root>/<relative>`.
fn write_claude_session(root: &Path, relative: &str) {
    let dest = root.join(relative);
    std::fs::create_dir_all(dest.parent().expect("fixture parent")).expect("create fixture dir");
    std::fs::write(&dest, fixture_bytes()).expect("write claude fixture");
}

/// Set a file's mtime, so a test can present history whose timestamp predates
/// every watermark without waiting for the clock.
fn set_mtime(path: &Path, mtime: SystemTime) {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for mtime");
    file.set_modified(mtime).expect("set mtime");
}

/// One private HOME / config / data-dir triple, and the scan path its runs use.
struct Env {
    /// Held for its `Drop`: deleting this deletes the tree the paths point at.
    _tmp: tempfile::TempDir,
    home: PathBuf,
    config_home: PathBuf,
    data_dir: PathBuf,
    streaming: bool,
}

impl Env {
    fn new(streaming: bool) -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let env = Env {
            home: tmp.path().join("home"),
            config_home: tmp.path().join("config"),
            data_dir: tmp.path().join("data"),
            streaming,
            _tmp: tmp,
        };
        std::fs::create_dir_all(&env.home).expect("create home");
        std::fs::create_dir_all(&env.data_dir).expect("create data dir");
        env
    }

    fn root(&self) -> &Path {
        self._tmp.path()
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir.join("agent_search.db")
    }

    /// The `sources.toml` describing one ssh mirror of [`REMOTE_PATH`].
    /// `full_scan` picks the whole-root contract instead of the incremental
    /// one this task delivers.
    fn write_sources_config(&self, full_scan: bool) {
        let path = self.config_home.join("cass/sources.toml");
        std::fs::create_dir_all(path.parent().expect("config dir")).expect("create config dir");
        let full_scan_line = if full_scan { "full_scan = true\n" } else { "" };
        std::fs::write(
            &path,
            format!(
                "[[sources]]\nname = \"{SOURCE_NAME}\"\ntype = \"ssh\"\nhost = \"{SOURCE_NAME}\"\n\
                 origin_host = \"{SOURCE_NAME}\"\npaths = [\"{REMOTE_PATH}\"]\n{full_scan_line}"
            ),
        )
        .expect("write sources.toml");
    }

    /// The mirror directory the **write side** would publish this source into,
    /// obtained through the production entry points: `prepare_mirror_root`
    /// authorizes and creates the configured mirror root, and `mirror_path_under`
    /// names the per-path directory under it (PR10 task 01's single derivation).
    fn prepare_mirror(&self, data_dir: &Path) -> PathBuf {
        let mut source = SourceDefinition::ssh(SOURCE_NAME, SOURCE_NAME);
        source.paths = vec![REMOTE_PATH.to_string()];
        source.origin_host = SOURCE_NAME.to_string();
        let engine = SyncEngine::new(data_dir);
        let mirror_root = engine
            .prepare_mirror_root(&source)
            .expect("the configured mirror root must be authorized");
        let mirrored = mirror_path_under(&mirror_root, REMOTE_PATH);
        assert_eq!(
            mirrored,
            data_dir
                .join("remotes")
                .join(SOURCE_NAME)
                .join("mirror")
                .join(path_to_safe_dirname(REMOTE_PATH)),
            "the write side must name the mirror directory after the raw configured path"
        );
        mirrored
    }

    /// The binary under test with a fully private environment. `cmd.env` rather
    /// than process-global `set_var`: a subprocess gets its own copy, so these
    /// tests cannot leak into anything else in this process.
    fn cass(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cass"));
        cmd.env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1");
        cmd.env("HOME", &self.home);
        cmd.env("XDG_DATA_HOME", self.home.join(".local/share"));
        cmd.env("XDG_CONFIG_HOME", &self.config_home);
        cmd.env_remove("CASS_DATA_DIR");
        cmd.env("NO_COLOR", "1");
        // Both must be absent for `sources.toml` to be read: one short-circuits
        // it, the other would re-enable info-level chatter.
        cmd.env_remove("CASS_IGNORE_SOURCES_CONFIG");
        cmd.env_remove("RUST_LOG");
        cmd.env_remove("CLAUDE_CONFIG_DIR");
        cmd.env_remove("CODEX_HOME");
        if self.streaming {
            cmd.env_remove("CASS_STREAMING_INDEX");
        } else {
            cmd.env("CASS_STREAMING_INDEX", "0");
        }
        cmd
    }

    /// `cass index --json` against `data_dir`, which may be a symlinked or
    /// relative spelling of the same tree. `cwd` is the child's working
    /// directory, needed only when `data_dir` is relative — this process's own
    /// working directory is never moved. Returns the exit code, the stdout JSON
    /// object (`None` when stdout was not one) and stderr.
    fn index_json_in(
        &self,
        data_dir: &Path,
        cwd: Option<&Path>,
    ) -> (i32, Option<serde_json::Value>, String) {
        let mut cmd = self.cass();
        cmd.args([
            "index",
            "--json",
            "--data-dir",
            &data_dir.display().to_string(),
        ]);
        if let Some(cwd) = cwd {
            cmd.current_dir(cwd);
        }
        let out = cmd.output().expect("spawn cass index --json");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        (
            out.status.code().unwrap_or(-1),
            serde_json::from_str::<serde_json::Value>(&stdout).ok(),
            stderr,
        )
    }

    /// Run `cass index --json` and require success, returning the payload.
    fn index_ok_in(&self, data_dir: &Path, cwd: Option<&Path>) -> serde_json::Value {
        let (code, payload, stderr) = self.index_json_in(data_dir, cwd);
        assert_eq!(
            code, 0,
            "`cass index --json` must succeed, got {code}\n--- stdout ---\n{payload:?}\n--- stderr ---\n{stderr}"
        );
        payload.expect("a successful `index --json` prints one JSON object")
    }

    fn index_ok(&self) -> serde_json::Value {
        self.index_ok_in(&self.data_dir, None)
    }
}

/// Conversations this run handed to ingest, summed over the per-connector
/// breakdown.
///
/// The payload's top-level `conversations` is the *archive* count on the paths
/// whose totals were recorded exactly; `indexing_stats.connectors` is what this
/// run's own scan produced, which is what "how many files did the mirror hand
/// over" has to be read from.
fn parsed_this_run(payload: &serde_json::Value) -> u64 {
    payload["indexing_stats"]["connectors"]
        .as_array()
        .map(|connectors| {
            connectors
                .iter()
                .filter_map(|connector| connector["conversations"].as_u64())
                .sum()
        })
        .unwrap_or(0)
}

fn db_scalar(db_path: &Path, sql: &str) -> i64 {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_row_map(sql, &[], |row| row.get_typed(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

/// Every row of a one-column projection, joined — used to compare a whole
/// table before/after without depending on row order.
fn table_rows(db_path: &Path, sql: &str) -> Vec<String> {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_all_map(sql, &[], |row| row.get_typed::<String>(0))
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

/// [`table_rows`] with a `root_id` prefix bound to `?1`.
fn root_rows(db_path: &Path, sql: &str, root_prefix: &str) -> Vec<String> {
    let storage = FrankenStorage::open_readonly(db_path).expect("open corpus read-only");
    storage
        .raw()
        .query_all_map(sql, &[Value::from(format!("{root_prefix}%"))], |row| {
            row.get_typed::<String>(0)
        })
        .unwrap_or_else(|e| panic!("query {sql:?}: {e}"))
}

const CONVERSATIONS: &str = "SELECT COUNT(*) FROM conversations";
const MESSAGES: &str = "SELECT COUNT(*) FROM messages";

/// One root's own watermark and file-state rows. Both are read by `root_id`
/// prefix so the same projection can ask about the incremental mirror root and
/// about the root kinds that must not have rows at all.
const ROOT_WATERMARK_ROWS: &str = "SELECT root_id || '|' || connector || '|' || last_scan_ts \
     FROM scan_watermarks WHERE root_id LIKE ?1 ORDER BY root_id, connector";
const ROOT_FILE_STATE_ROWS: &str = "SELECT root_id || '|' || connector || '|' || relative_path \
     || '|' || size || '|' || mtime FROM scan_file_state WHERE root_id LIKE ?1 \
     ORDER BY root_id, connector, relative_path";

/// The `relative_path` the tests put the in-tree fixture at, inside the mirror
/// root.
const SESSION_RELATIVE: &str = "projects/-pr10/agent-alpha.jsonl";

/// `(size, mtime_ms)` of a file on disk, the pair `file_scan_stamp` reads.
fn fs_stamp(path: &Path) -> (i64, i64) {
    let metadata = std::fs::metadata(path).expect("fixture metadata");
    let mtime = metadata
        .modified()
        .expect("fixture mtime")
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("mtime after epoch")
        .as_millis();
    (
        i64::try_from(metadata.len()).expect("fixture size"),
        i64::try_from(mtime).expect("fixture mtime ms"),
    )
}

/// The `mtime` the mirror root recorded for `relative`, or `None` when no
/// record exists for it. Read from `scan_file_state` directly: the record is
/// the thing the next run's comparison runs on, so it is the end-to-end
/// evidence that a pass actually read that file.
fn recorded_mtime(db_path: &Path, relative: &str) -> Option<i64> {
    root_rows(
        db_path,
        ROOT_FILE_STATE_ROWS,
        &format!("cfg:{SOURCE_NAME}:"),
    )
    .into_iter()
    .find_map(|row| {
        let fields: Vec<&str> = row.split('|').collect();
        if fields.get(2) != Some(&relative) {
            return None;
        }
        fields.get(4)?.parse::<i64>().ok()
    })
}

/// The mirror directory the **DB-registered fallback** in
/// `build_scan_roots_with_meta` derives for a remote source with no
/// `config_json.paths`: `<data_dir>/remotes/<id>/mirror` (`src/indexer/mod.rs`,
/// the "Remote mirror directory" arm of the fallback).
///
/// Derived here rather than through `SyncEngine::prepare_mirror_root`: that
/// writer is the *explicit-config* path and would be circular evidence for a
/// case whose whole subject is that the fallback finds the directory by itself.
fn fallback_mirror_dir(data_dir: &Path, source_id: &str) -> PathBuf {
    data_dir.join("remotes").join(source_id).join("mirror")
}

/// Register one remote source in `data_dir`'s archive the way the registry
/// holds it once the first ingest has run.
///
/// Deliberately **no `config_json`**, and that is a finding rather than a
/// shortcut. With `config_json.paths` present the first pass derives
/// `<mirror>/<safe dirname>` and the second derives `<mirror>`: ingesting a
/// session whose `source_id` is new upserts a placeholder `Source` with
/// `config_json: None` (`src/storage/sqlite.rs`, the `known_sources` arm), and
/// `upsert_source`'s `ON CONFLICT ... DO UPDATE SET config_json =
/// excluded.config_json` lets that NULL overwrite the registered paths. The
/// root changes between passes, claude's `external_id_root` changes with it,
/// and the second pass dies on `E-MANIFEST-SESSION-KEY-CONFLICT` from
/// `raw_mirror`'s session-key merge. Reported to the control plane; fixing it
/// would change product scan rules, which this task does not own.
fn register_fallback_source(data_dir: &Path, source_id: &str) {
    let db_path = data_dir.join("agent_search.db");
    let storage = FrankenStorage::open(&db_path).expect("open the archive to register a source");
    storage
        .upsert_source(&Source::remote(source_id, source_id))
        .expect("register the remote source");
    storage.close().expect("close the archive");
}

// ---------------------------------------------------------------------------
// S1 — the mirror's own records decide what is handed to the connector
// ---------------------------------------------------------------------------

/// A second pass over an unchanged mirror parses nothing and leaves the archive
/// exactly as it was, while the root keeps the watermark and file state that
/// made the pass a no-op.
#[test]
fn unchanged_mirror_second_pass_parses_nothing() {
    for_each_scan_path(|streaming| {
        let env = Env::new(streaming);
        env.write_sources_config(false);
        let mirror = env.prepare_mirror(&env.data_dir);
        write_claude_session(&mirror, SESSION_RELATIVE);

        let first = env.index_ok();
        let parsed_first = parsed_this_run(&first);
        assert!(
            parsed_first >= 1,
            "the first pass has no watermark, so it must read the whole mirror: {first}"
        );
        let conversations = db_scalar(&env.db_path(), CONVERSATIONS);
        let messages = db_scalar(&env.db_path(), MESSAGES);
        assert_eq!(
            conversations, 1,
            "the mirrored session must be ingested exactly once: {first}"
        );
        assert!(messages > 0, "the mirrored session must bring messages");

        let watermarks = root_rows(
            &env.db_path(),
            ROOT_WATERMARK_ROWS,
            &format!("cfg:{SOURCE_NAME}:"),
        );
        let states = root_rows(
            &env.db_path(),
            ROOT_FILE_STATE_ROWS,
            &format!("cfg:{SOURCE_NAME}:"),
        );
        assert!(
            !watermarks.is_empty(),
            "an explicit ssh mirror root must keep a per-root watermark, got none"
        );
        assert!(
            !states.is_empty(),
            "the pass that read the mirror must record its per-file state, got none"
        );

        let second = env.index_ok();
        assert_eq!(
            parsed_this_run(&second),
            0,
            "nothing changed, so the second pass must hand over no file: {second}"
        );
        assert_eq!(
            db_scalar(&env.db_path(), CONVERSATIONS),
            conversations,
            "a no-op pass must not add a conversation"
        );
        assert_eq!(
            db_scalar(&env.db_path(), MESSAGES),
            messages,
            "a no-op pass must not add a message"
        );
        assert_eq!(
            root_rows(
                &env.db_path(),
                ROOT_FILE_STATE_ROWS,
                &format!("cfg:{SOURCE_NAME}:")
            ),
            states,
            "a clean pass with nothing to re-read must not rewrite the file state"
        );
    });
}

/// A file that arrives with an mtime older than the root's watermark is still
/// new here: a mirror can always receive the far machine's old history, which
/// is exactly what a `mtime > watermark` comparison would drop.
#[test]
fn late_mirror_file_with_an_old_mtime_is_ingested() {
    for_each_scan_path(|streaming| {
        let env = Env::new(streaming);
        env.write_sources_config(false);
        let mirror = env.prepare_mirror(&env.data_dir);
        write_claude_session(&mirror, SESSION_RELATIVE);
        let first = env.index_ok();
        let parsed_first = parsed_this_run(&first);
        assert!(
            parsed_first >= 1,
            "the first pass must read the mirror: {first}"
        );

        let late = mirror.join("projects/-pr10/agent-late.jsonl");
        write_claude_session(&mirror, "projects/-pr10/agent-late.jsonl");
        set_mtime(&late, SystemTime::now() - Duration::from_secs(7_200));

        let second = env.index_ok();
        assert_eq!(
            parsed_this_run(&second),
            parsed_first,
            "exactly one file's worth of work must come back: {second}"
        );
        assert_eq!(
            db_scalar(&env.db_path(), CONVERSATIONS),
            2,
            "the late file must be ingested: {second}"
        );
    });
}

/// A file rewritten in place with the **same size** and an earlier mtime is
/// handed to the connector again, and the mirror's record moves to the mtime it
/// just read. `size` and `mtime > watermark` both miss this file; only
/// comparing the recorded mtime catches it.
///
/// What is deliberately *not* asserted here: the archive's message text. An
/// existing `idx` wins over the incoming body at the same `idx`
/// (`storage/sqlite.rs`'s merge loop records that as an index collision and
/// moves on), so an in-place content edit is not rewritten by the incremental
/// merge. That is ingest semantics this task does not own — the claim here is
/// the scan's, and the claim about the file new to the mirror is the one that
/// carries the end-to-end ingest evidence.
#[test]
fn same_size_older_mtime_rewrite_is_reparsed() {
    for_each_scan_path(|streaming| {
        let env = Env::new(streaming);
        env.write_sources_config(false);
        let mirror = env.prepare_mirror(&env.data_dir);
        let session = mirror.join(SESSION_RELATIVE);
        write_claude_session(&mirror, SESSION_RELATIVE);

        let first = env.index_ok();
        let parsed_first = parsed_this_run(&first);
        assert!(
            parsed_first >= 1,
            "the first pass must read the mirror: {first}"
        );
        let (original_size, original_mtime) = fs_stamp(&session);
        assert_eq!(
            recorded_mtime(&env.db_path(), SESSION_RELATIVE),
            Some(original_mtime),
            "the first pass must record the mtime it read: {first}"
        );

        let original_text =
            String::from_utf8(std::fs::read(&session).expect("read the fixture copy"))
                .expect("the fixture is UTF-8");
        assert!(
            original_text.contains(ORIGINAL_KEYWORD),
            "the fixture must carry {ORIGINAL_KEYWORD} for this rewrite to mean anything"
        );
        let rewritten = original_text.replace(ORIGINAL_KEYWORD, REWRITTEN_KEYWORD);
        assert_eq!(
            rewritten.len(),
            original_text.len(),
            "the rewrite must keep the byte length identical, or it proves nothing about the size branch"
        );
        std::fs::write(&session, &rewritten).expect("rewrite the fixture copy");
        set_mtime(&session, SystemTime::now() - Duration::from_secs(7_200));

        let (rewritten_size, rewritten_mtime) = fs_stamp(&session);
        assert_eq!(
            rewritten_size, original_size,
            "the size must really be unchanged, or the mirror would re-read it for the wrong reason"
        );
        assert!(
            rewritten_mtime < original_mtime,
            "the mtime must really have moved backwards ({rewritten_mtime} vs {original_mtime})"
        );

        let second = env.index_ok();
        assert_eq!(
            parsed_this_run(&second),
            parsed_first,
            "a same-size, earlier-mtime rewrite must be handed over again: {second}"
        );
        assert_eq!(
            db_scalar(&env.db_path(), CONVERSATIONS),
            1,
            "the rewritten session keeps its identity, so it must not duplicate: {second}"
        );
        assert_eq!(
            recorded_mtime(&env.db_path(), SESSION_RELATIVE),
            Some(rewritten_mtime),
            "the record must move to the mtime this pass read, which is the whole point of \
             comparing it"
        );
    });
}

// ---------------------------------------------------------------------------
// S2 — the other root kinds keep their own rules
// ---------------------------------------------------------------------------

/// A `full_scan` source keeps reading the whole root every run and keeps no
/// per-root watermark, exactly as before this task.
#[test]
fn full_scan_mirror_still_reads_the_whole_root_every_run() {
    for_each_scan_path(|streaming| {
        let env = Env::new(streaming);
        env.write_sources_config(true);
        let mirror = env.prepare_mirror(&env.data_dir);
        write_claude_session(&mirror, SESSION_RELATIVE);

        let first = env.index_ok();
        let parsed_first = parsed_this_run(&first);
        assert!(
            parsed_first >= 1,
            "the first pass must read the mirror: {first}"
        );
        assert!(
            root_rows(
                &env.db_path(),
                ROOT_WATERMARK_ROWS,
                &format!("cfg:{SOURCE_NAME}:")
            )
            .is_empty(),
            "a full_scan source must not keep a per-root watermark"
        );

        // Nothing changed on disk, so an incremental root would do nothing.
        let second = env.index_ok();
        assert_eq!(
            parsed_this_run(&second),
            parsed_first,
            "a full_scan source re-reads every file on every run: {second}"
        );
        assert!(
            root_rows(
                &env.db_path(),
                ROOT_WATERMARK_ROWS,
                &format!("cfg:{SOURCE_NAME}:")
            )
            .is_empty(),
            "a full_scan source must not start keeping watermarks either"
        );
    });
}

/// The DB-registered mirror fallback keeps the baseline full-root scan and
/// keeps **no** per-root watermark or file state at all: its root carries no
/// `ScanRootMeta`, so `build_connector_root_plans` never builds a plan for it
/// and the comparison this task changed is never reached. Hard constraint 9
/// leaves that path alone on purpose — a source has to be configured in
/// `sources.toml` to get the incremental treatment.
///
/// The evidence is the passes themselves, not the absence of rows: an
/// unchanged second run still hands the file over, which is what a full-root
/// scan looks like from the outside. See [`register_fallback_source`] for why
/// the registry row carries no `config_json.paths`.
#[test]
fn db_registered_mirror_fallback_still_full_scans_and_keeps_no_watermark() {
    for_each_scan_path(|streaming| {
        let env = Env::new(streaming);
        // No `sources.toml` at all: `SourcesConfig::load` sees an empty config
        // and the builder falls through to the registry in the archive.
        register_fallback_source(&env.data_dir, FALLBACK_SOURCE_ID);

        let mirror = fallback_mirror_dir(&env.data_dir, FALLBACK_SOURCE_ID);
        write_claude_session(&mirror, SESSION_RELATIVE);

        let first = env.index_ok();
        let parsed_first = parsed_this_run(&first);
        assert!(
            parsed_first >= 1,
            "the fallback root must be scanned from its own mirror directory: {first}"
        );
        let conversations = db_scalar(&env.db_path(), CONVERSATIONS);
        let messages = db_scalar(&env.db_path(), MESSAGES);
        assert_eq!(
            conversations, 1,
            "the fallback mirror's session must be ingested exactly once: {first}"
        );

        let root_prefix = format!("cfg:{FALLBACK_SOURCE_ID}:");
        let first_watermarks = root_rows(&env.db_path(), ROOT_WATERMARK_ROWS, &root_prefix);
        let first_states = root_rows(&env.db_path(), ROOT_FILE_STATE_ROWS, &root_prefix);
        println!(
            "db-fallback pass 1 (streaming={streaming}): parsed_this_run={parsed_first} \
             conversations={conversations} messages={messages} \
             watermark_rows={first_watermarks:?} file_state_rows={first_states:?}"
        );
        assert!(
            first_watermarks.is_empty(),
            "a DB-registered fallback root must not keep a per-root watermark"
        );
        assert!(
            first_states.is_empty(),
            "a DB-registered fallback root must not record per-file state either"
        );

        // Nothing changed on disk: an incremental root would hand nothing over.
        let second = env.index_ok();
        let second_watermarks = root_rows(&env.db_path(), ROOT_WATERMARK_ROWS, &root_prefix);
        let second_states = root_rows(&env.db_path(), ROOT_FILE_STATE_ROWS, &root_prefix);
        println!(
            "db-fallback pass 2 (streaming={streaming}): parsed_this_run={} \
             conversations={} messages={} watermark_rows={second_watermarks:?} \
             file_state_rows={second_states:?}",
            parsed_this_run(&second),
            db_scalar(&env.db_path(), CONVERSATIONS),
            db_scalar(&env.db_path(), MESSAGES),
        );
        assert!(
            parsed_this_run(&second) > 0,
            "the fallback is re-read in full on every run, not skipped: {second}"
        );
        assert_eq!(
            parsed_this_run(&second),
            parsed_first,
            "the whole root is read again, so the same files come back: {second}"
        );
        assert_eq!(
            db_scalar(&env.db_path(), CONVERSATIONS),
            conversations,
            "re-reading must not duplicate a session: {second}"
        );
        assert_eq!(
            db_scalar(&env.db_path(), MESSAGES),
            messages,
            "re-reading must not duplicate a message: {second}"
        );
        assert!(
            second_watermarks.is_empty(),
            "a second full scan must not start keeping watermarks either"
        );
        assert!(
            second_states.is_empty(),
            "a second full scan must not start recording per-file state either"
        );
    });
}

// ---------------------------------------------------------------------------
// S3 — the path spellings keep the state the comparison depends on
// ---------------------------------------------------------------------------

/// The `--data-dir` spellings this platform can exercise, as
/// `(spelling the CLI receives, the child's working directory, the tree it
/// resolves to)`.
///
/// The **relative** spelling runs on every platform and carries the claim by
/// itself: a pass through a spelled data dir still leaves the file state the
/// next pass compares against.
///
/// The **symlink** spelling is Unix-only. On Windows a directory symlink needs
/// a privilege (or developer mode) the CI runner is not guaranteed to have, and
/// `std::os::unix` does not exist there at all — so on Windows this case
/// contributes the relative spelling and nothing else, rather than failing to
/// build or skipping the target.
fn data_dir_spellings(env: &Env) -> Vec<(PathBuf, PathBuf, PathBuf)> {
    let relative = PathBuf::from("relative-data");
    let absolute = env.root().join(&relative);
    std::fs::create_dir_all(&absolute).expect("create relative data dir");

    #[cfg(unix)]
    let symlinked = {
        let link = env.root().join("data-link");
        std::os::unix::fs::symlink(&env.data_dir, &link).expect("create data dir symlink");
        vec![(link, env.root().to_path_buf(), env.data_dir.clone())]
    };
    #[cfg(not(unix))]
    let symlinked: Vec<(PathBuf, PathBuf, PathBuf)> = Vec::new();

    // Built without a `mut` binding: on Windows `symlinked` is the empty
    // vector above, and a `mut` that no platform mutates would itself be the
    // warning this split exists to avoid.
    std::iter::once((relative, env.root().to_path_buf(), absolute))
        .chain(symlinked)
        .collect()
}

/// A relative `--data-dir` — and, where the platform has one, a symlink to the
/// same tree — keeps a non-empty file state on the first pass, and still
/// re-reads a late file with an old mtime afterwards. The failure this rules
/// out is a pass that reports success while the watermark moved and no file
/// state was written — the shape that silently drops every later file.
#[test]
fn relative_and_symlinked_data_dirs_keep_the_incremental_state() {
    for_each_scan_path(|streaming| {
        let env = Env::new(streaming);
        env.write_sources_config(false);

        // Each spelling owns a *different* data dir, so the iterations cannot
        // observe each other.
        for (as_seen_by_cli, cwd, real) in data_dir_spellings(&env) {
            let db = real.join("agent_search.db");
            let mirror = env.prepare_mirror(&real);
            write_claude_session(&mirror, SESSION_RELATIVE);

            let first = env.index_ok_in(&as_seen_by_cli, Some(&cwd));
            let parsed_first = parsed_this_run(&first);
            assert!(
                parsed_first >= 1,
                "the first pass through {as_seen_by_cli:?} must read the mirror: {first}"
            );
            let states = root_rows(&db, ROOT_FILE_STATE_ROWS, &format!("cfg:{SOURCE_NAME}:"));
            assert!(
                !states.is_empty(),
                "a successful pass that advanced a watermark must leave file state behind, \
                 got none"
            );
            let keyed: Vec<&str> = states
                .iter()
                .filter_map(|row| row.split('|').nth(2))
                .collect();
            assert!(
                keyed.contains(&SESSION_RELATIVE),
                "the file state must be keyed by the path inside the scanned root, got {states:?}"
            );

            // The late file goes into the same tree through its real spelling.
            let late = mirror.join("projects/-pr10/agent-late.jsonl");
            write_claude_session(&mirror, "projects/-pr10/agent-late.jsonl");
            set_mtime(&late, SystemTime::now() - Duration::from_secs(10_800));

            let second = env.index_ok_in(&as_seen_by_cli, Some(&cwd));
            assert_eq!(
                parsed_this_run(&second),
                parsed_first,
                "the late file must come back through {as_seen_by_cli:?}: {second}"
            );
            assert_eq!(
                db_scalar(&db, CONVERSATIONS),
                2,
                "the late file must be ingested through {as_seen_by_cli:?}: {second}"
            );
        }
    });
}
