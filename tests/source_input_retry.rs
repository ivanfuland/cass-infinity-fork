//! SRC05B-09C acceptance at the real entry point: what the whole-input retry
//! does when the run is driven through the `cass index` binary.
//!
//! The classified-fault matrix -- one typed `Busy`, one typed out-of-memory,
//! `Locked`, the two writer modes, and the shared budget -- is exercised over
//! real SQLite transactions in `src/indexer/source_ingest.rs`'s own test
//! module, because naming a *typed* class and carrying it onto the dedicated
//! writer thread are both test-only seams. What is left here is what only the
//! process boundary can show: the retry budget under the existing fault
//! environment, and that a durable commit whose derivation is pending is not
//! retried at all.
//!
//! The fixtures are synthetic and neutral. No real session, path or secret
//! appears in this file.

use std::path::PathBuf;
use std::process::Command;

/// A private root holding a HOME, a data directory and the fixed safety copy.
struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home")).expect("mkdir home");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        std::fs::write(
            root.path().join("fixed-safety.toml"),
            include_bytes!("../config/excluded_context_paths.toml"),
        )
        .expect("write fixed safety copy");
        Self { root }
    }

    /// Point every source-discovery environment at this fixture, so an
    /// inherited value on the test host cannot make a process scan real
    /// history.
    fn isolate<'a>(&self, cmd: &'a mut Command) -> &'a mut Command {
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.home().join(".config"))
            .env("CODEX_HOME", self.home().join(".codex"))
            .env("CASS_AIDER_DATA_ROOT", self.home().join(".aider"))
            .env("PI_SESSIONS_DIR", self.home().join(".pi"))
            .env("PI_CODING_AGENT_DIR", self.home().join(".pi"))
            .env("GOOSE_PATH_ROOT", self.home().join(".goose"))
            .env("HERMES_HOME", self.home().join(".hermes"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn db(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn fixed_copy(&self) -> PathBuf {
        self.root.path().join("fixed-safety.toml")
    }

    fn write_claude_session(&self, name: &str, lines: &[serde_json::Value]) -> PathBuf {
        let dir = self.home().join(".claude/projects").join(name);
        std::fs::create_dir_all(&dir).expect("mkdir claude project");
        let path = dir.join("session.jsonl");
        let body: String = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&path, body).expect("write claude session");
        path
    }

    /// Run one `cass index` over this fixture.
    ///
    /// Deliberately *not* `--json`: robot mode pins the log filter to `error`,
    /// so the retry's own informative lines would be dropped and a case that
    /// counts them could not tell a real retry from a missing log. Human mode
    /// keeps the INFO/WARN stream, which is where the attempt count is
    /// readable.
    fn run_index_env(&self, envs: &[(&str, &str)]) -> std::process::Output {
        let copy = self.fixed_copy();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_cass"));
        cmd.args([
            "index",
            "--data-dir",
            self.data_dir().to_str().unwrap(),
            "--source-safety-config",
            copy.to_str().unwrap(),
        ]);
        for (key, value) in envs {
            cmd.env(key, value);
        }
        self.isolate(&mut cmd);
        cmd.output().expect("spawn cass index")
    }

    fn logs(output: &std::process::Output) -> String {
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    fn open_db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open_with_flags(self.db(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open the database read-only")
    }
}

/// How many times `needle` occurs in `haystack`.
fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

/// A count of rows, or 0 when the table was never created (a run that failed
/// before its first write).
fn count_rows(db: &rusqlite::Connection, table: &str, where_clause: &str) -> i64 {
    let sql = format!("SELECT COUNT(*) FROM {table} WHERE {where_clause}");
    match db.query_row(&sql, [], |row| row.get::<_, i64>(0)) {
        Ok(count) => count,
        Err(_) => 0,
    }
}

fn claude_session(uuid: &str, question: &str, answer: &str) -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "parentUuid": null,
            "cwd": "/synthetic/project",
            "sessionId": uuid,
            "version": "2.0.37",
            "type": "user",
            "message": {"role": "user", "content": question},
            "uuid": format!("{uuid}-user"),
            "timestamp": "2026-01-01T00:00:00.000Z"
        }),
        serde_json::json!({
            "parentUuid": format!("{uuid}-user"),
            "cwd": "/synthetic/project",
            "sessionId": uuid,
            "version": "2.0.37",
            "type": "assistant",
            "message": {
                "model": "claude-opus-4",
                "role": "assistant",
                "content": [{"type": "text", "text": answer}]
            },
            "uuid": format!("{uuid}-assistant"),
            "timestamp": "2026-01-01T00:00:01.000Z"
        }),
    ]
}

/// One dispatch line is written per attempt, so counting them counts the real
/// attempts rather than the configured budget.
const DISPATCH: &str = "source_input_dispatch";
const BUSY_FAILED: &str = "a typed Busy failed this whole-input attempt";

/// B: the busy budget is the configured one, the exhaustion stops the run, and
/// the root's progress does not move.
///
/// Every attempt reaches the named point, so the budget is spent and then
/// exhausted. Two configured retries means three attempts in total.
#[test]
fn b_the_busy_budget_is_the_configured_count_and_exhaustion_holds_progress() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-retry-b",
        &claude_session(
            "sess-retry-b",
            "synthetic budget question",
            "synthetic budget answer",
        ),
    );

    let output = fixture.run_index_env(&[
        ("CASS_SRC05B07_FAIL_AT", "busy"),
        ("CASS_INDEXER_BEGIN_CONCURRENT_RETRIES", "2"),
    ]);
    let logs = Fixture::logs(&output);

    assert_ne!(
        output.status.code(),
        Some(0),
        "a spent busy budget stops the run; logs={logs}"
    );
    assert_eq!(
        count_occurrences(&logs, DISPATCH),
        3,
        "the attempt count is the first try plus the configured two retries; logs={logs}"
    );
    assert_eq!(
        count_occurrences(&logs, BUSY_FAILED),
        3,
        "every one of those attempts met the persistent typed busy, so the log's own \
         count matches the attempts rather than the budget; logs={logs}"
    );

    // The JSON-side reporting of this same exhausted-budget path -- the
    // outcome survives as a transient failure with `"retryable": true` rather
    // than as corruption -- is covered by
    // `source_input_ingest.rs::i2_a_busy_write_is_reported_as_transient_and_the_whole_input_retries`,
    // which drives this exact fault through `--json` and so reads the report
    // instead of the log.

    let db = fixture.open_db();
    assert_eq!(
        count_rows(&db, "source_inputs", "state = 'complete'"),
        0,
        "an unfinished input completes nothing"
    );
    assert_eq!(
        count_rows(&db, "operation_commit_receipt", "state = 'committed'"),
        0,
        "and writes no receipt"
    );
    assert_eq!(
        count_rows(&db, "messages", "1 = 1"),
        0,
        "and no canonical message, so no failed attempt half-committed"
    );

    // Without the fault the same root commits, exactly once. This is also the
    // progress check: had the failed run advanced this root's file state, the
    // later run would skip the file and complete nothing.
    let retried = fixture.run_index_env(&[]);
    assert_eq!(
        retried.status.code(),
        Some(0),
        "the whole input retries cleanly; logs={}",
        Fixture::logs(&retried)
    );
    let db = fixture.open_db();
    assert_eq!(
        count_rows(&db, "source_inputs", "state = 'complete'"),
        1,
        "the later run completes the input exactly once"
    );
    assert_eq!(
        count_rows(&db, "messages", "1 = 1"),
        2,
        "and lands the session's two messages"
    );
}

/// E: a durable commit whose derivation fails is not a failed input, so it is
/// not retried -- and the receipt stays single.
#[test]
fn e_a_post_commit_derivation_failure_is_not_retried() {
    let fixture = Fixture::new();
    fixture.write_claude_session(
        "proj-retry-e",
        &claude_session(
            "sess-retry-e",
            "synthetic pending question",
            "synthetic pending answer",
        ),
    );

    let output = fixture.run_index_env(&[("CASS_SRC05B07_FAIL_AT", "postcommit")]);
    let logs = Fixture::logs(&output);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a durable commit with a pending derivation is not a failed run; logs={logs}"
    );
    assert_eq!(
        count_occurrences(&logs, DISPATCH),
        1,
        "the commit is durable, so it is attempted once and never retried; logs={logs}"
    );
    assert_eq!(
        count_occurrences(&logs, BUSY_FAILED),
        0,
        "no retry class applies to a pending derivation; logs={logs}"
    );

    let db = fixture.open_db();
    assert_eq!(
        count_rows(&db, "source_inputs", "state = 'complete'"),
        1,
        "the input is complete because its commit is durable"
    );
    assert_eq!(
        count_rows(&db, "operation_commit_receipt", "state = 'committed'"),
        1,
        "exactly one receipt"
    );
    assert_eq!(
        count_rows(&db, "messages", "1 = 1"),
        2,
        "the canonical rows are durable"
    );

    // A later run must not install a second receipt or duplicate the rows.
    let again = fixture.run_index_env(&[]);
    assert_eq!(
        again.status.code(),
        Some(0),
        "the later run succeeds; logs={}",
        Fixture::logs(&again)
    );
    let db = fixture.open_db();
    assert_eq!(
        count_rows(&db, "operation_commit_receipt", "state = 'committed'"),
        1,
        "the receipt is still single"
    );
    assert_eq!(
        count_rows(&db, "messages", "1 = 1"),
        2,
        "and the canonical rows were not duplicated"
    );
}
