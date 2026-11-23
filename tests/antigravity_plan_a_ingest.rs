//! Seam 2 end-to-end integration tests for Antigravity CLI (`agy 1.5.14` + `1.0.7`)
//! on CASS Plan A (`raw-mirror` capture -> scratch reparse -> `blob_events_from_blob`
//! -> `recall_v2` cleaning + R2 context-file exclusion + `reports_recall_uncovered`
//! + `--watch-once` single-file symmetry).
//!
//! Every test drives the real `cass` binary over an isolated temporary HOME,
//! data directory, and config directory, using strictly synthetic fixtures.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use coding_agent_search::recall_output::{self, RecallTool};
use coding_agent_search::storage::api::{Conn, OpenOptions};
use serde_json::{Value, json};

fn cass_bin() -> String {
    std::env::var("CARGO_BIN_EXE_cass")
        .ok()
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_cass").to_string())
}

struct AgyFixture {
    root: tempfile::TempDir,
}

impl AgyFixture {
    fn new() -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        std::fs::create_dir_all(root.path().join("home/.gemini/antigravity-cli/brain"))
            .expect("mkdir agy brain");
        std::fs::create_dir_all(root.path().join("data")).expect("mkdir data");
        std::fs::create_dir_all(root.path().join("config")).expect("mkdir config");
        Self { root }
    }

    fn home(&self) -> PathBuf {
        self.root.path().join("home")
    }

    fn agy_root(&self) -> PathBuf {
        self.home().join(".gemini/antigravity-cli")
    }

    fn config_home(&self) -> PathBuf {
        self.root.path().join("config")
    }

    fn data_dir(&self) -> PathBuf {
        self.root.path().join("data")
    }

    fn db_path(&self) -> PathBuf {
        self.data_dir().join("agent_search.db")
    }

    fn write_session(&self, uuid: &str, filename: &str, bom: bool, records: &[Value]) -> PathBuf {
        let path = self
            .agy_root()
            .join("brain")
            .join(uuid)
            .join(".system_generated/logs")
            .join(filename);
        std::fs::create_dir_all(path.parent().expect("logs parent")).expect("mkdir logs");
        let mut body = if bom {
            String::from("\u{feff}")
        } else {
            String::new()
        };
        for rec in records {
            body.push_str(&serde_json::to_string(rec).expect("encode jsonl record"));
            body.push('\n');
        }
        std::fs::write(&path, body.as_bytes()).expect("write transcript");
        path
    }

    fn write_summary_db(&self, rows: &[(&str, &str, &str, &str, &str, i64)]) {
        let db_path = self.agy_root().join("conversation_summaries.db");
        let conn = rusqlite::Connection::open(&db_path).expect("create synthetic summary db");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS conversation_summaries (
                conversation_id TEXT PRIMARY KEY,
                title TEXT NOT NULL DEFAULT '',
                workspace_uris TEXT NOT NULL DEFAULT '[]',
                parent_conversation_id TEXT NOT NULL DEFAULT '',
                agent_name TEXT NOT NULL DEFAULT '',
                nesting_depth INTEGER NOT NULL DEFAULT 0
            );",
        )
        .expect("create conversation_summaries table");
        for (id, title, uris, parent, agent, depth) in rows {
            conn.execute(
                "INSERT OR REPLACE INTO conversation_summaries \
                 (conversation_id, title, workspace_uris, parent_conversation_id, agent_name, nesting_depth) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, title, uris, parent, agent, depth],
            )
            .expect("insert summary row");
        }
    }

    fn run_index(&self, extra_args: &[&str]) -> Output {
        let mut cmd = Command::new(cass_bin());
        cmd.env("HOME", self.home())
            .env("XDG_DATA_HOME", self.home().join(".local/share"))
            .env("XDG_CONFIG_HOME", self.config_home())
            .env("XDG_CACHE_HOME", self.home().join(".cache"))
            .env("XDG_STATE_HOME", self.home().join(".state"))
            .env("CASS_DATA_DIR", self.data_dir())
            .env("CASS_ANTIGRAVITY_DATA_ROOT", self.agy_root())
            .env("CASS_INLINE_ANALYTICS_UPDATES", "1")
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("NO_COLOR", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .env_remove("CODEX_HOME")
            .env_remove("CASS_IGNORE_SOURCES_CONFIG")
            .env_remove("CASS_TEST_WATCH_PATHS")
            .env_remove("CASS_API_CONFIG")
            .env_remove("RUST_LOG");
        cmd.args(["index", "--data-dir"]).arg(self.data_dir());
        cmd.args(extra_args).arg("--json");
        cmd.output().expect("spawn cass index")
    }

    fn open_db(&self) -> Conn {
        Conn::open_read_with(
            &self.db_path(),
            OpenOptions {
                busy_timeout: Duration::from_secs(30),
            },
        )
        .expect("open cass sqlite read-only")
    }
}

fn decode_extra(text: Option<String>, binary: Option<Vec<u8>>) -> Value {
    if let Some(text) = text {
        serde_json::from_str(&text).expect("decode extra_json")
    } else if let Some(binary) = binary {
        rmp_serde::from_slice(&binary).expect("decode extra_bin")
    } else {
        Value::Null
    }
}

fn c04_search(secret_marker: &str) -> String {
    let val = json!({
        "hits": [{
            "source_id": "local",
            "source_path": "/synthetic/agy/hit.jsonl",
            "line_number": 7,
            "content": secret_marker
        }]
    });
    recall_output::encode(RecallTool::Search, &val).expect("encode c04 search")
}

fn c04_expand(secret_marker: &str) -> String {
    let val = json!([
        {"line": 6, "role": "user", "is_target": false, "content": "context before"},
        {"line": 7, "role": "assistant", "is_target": true, "content": secret_marker}
    ]);
    recall_output::encode(RecallTool::Expand, &val).expect("encode c04 expand")
}

#[test]
fn antigravity_plan_a_ingest_reparse_recall_v2_r2_and_metadata_preservation() {
    const SECRET_DISPATCH_MCP: &str = "AGY_SECRET_CALL_MCP_TOOL_RECALL";
    const SECRET_DIRECT_MCP: &str = "AGY_SECRET_DIRECT_MCP_EXPAND";
    const SECRET_BARE_C04: &str = "AGY_SECRET_BARE_C04_FRAMED";
    const SECRET_CLI_1514: &str = "AGY_SECRET_RUN_COMMAND_1514";
    const SECRET_CLI_107: &str = "AGY_SECRET_LEGACY_107_COMMAND";
    const SECRET_R2_READ_FILE: &str = "AGY_SECRET_R2_CLAUDE_SYSTEM_READ";
    const SECRET_R2_SHELL_CAT: &str = "AGY_SECRET_R2_CLAUDE_SYSTEM_CAT";
    const KEEP_WEBFETCH: &str = "AGY_KEEP_WEBFETCH_OUTPUT";
    const KEEP_ORDINARY_SHELL: &str = "AGY_KEEP_ORDINARY_SHELL_OUTPUT";
    const KEEP_ORDINARY_FILE: &str = "AGY_KEEP_ORDINARY_SOURCE_FILE";
    const KEEP_SUBAGENT_NOTICE: &str = "AGY_KEEP_SUBAGENT_COMPLETION_NOTICE";
    const KEEP_CHECKPOINT: &str = "AGY_KEEP_COMPACTION_CHECKPOINT";
    const KEEP_ERROR_TEXT: &str = "AGY_KEEP_ERROR_MESSAGE_BODY";
    const DROP_PREINVOCATION: &str = "AGY_DROP_PREINVOCATION_SENTINEL";
    const DROP_REMINDER: &str = "AGY_DROP_REMINDER_SENTINEL";

    let fixture = AgyFixture::new();
    let main_uuid = "1111aaaa-2222-3333-4444-555566667777";
    let sub_uuid = "2222bbbb-2222-3333-4444-555566668888";

    fixture.write_summary_db(&[
        (
            main_uuid,
            "Synthetic DB Main Title",
            "[\"file:///run/user/1000/antigravity-overlays/ov1\",\"file:///tmp/synthetic-agy-ws\"]",
            "",
            "",
            0,
        ),
        (
            sub_uuid,
            "Synthetic Subagent Title",
            "[\"file:///tmp/synthetic-agy-ws\"]",
            main_uuid,
            "Research Helper",
            1,
        ),
    ]);

    // Main session WITH UTF-8 BOM: exercises all recall_v2 channels, R2 reads,
    // negative controls, boilerplate filtering, ERROR_MESSAGE, CHECKPOINT, and 1.0.7 compat.
    let main_records = vec![
        json!({
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2026-11-22T10:00:00Z",
            "content": "<USER_REQUEST>\nVerify Antigravity Plan A ingest\n</USER_REQUEST>"
        }),
        json!({
            "step_index": 1,
            "source": "SYSTEM_SDK",
            "type": "SYSTEM_MESSAGE",
            "created_at": "2026-11-22T10:00:01Z",
            "content": format!(
                "The following system message was injected by a PreInvocation hook:\n\
                 <agent-contract-source id=\"global:USER.md\">{DROP_PREINVOCATION}</agent-contract-source>"
            )
        }),
        // Turn 1: lazy call_mcp_tool(cass-mcp) + direct mcp__cass-mcp__cass_expand + bare cass_search
        //         + negative control call_mcp_tool(webfetch) in parallel with interleaved Reminder.
        json!({
            "step_index": 2,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-22T10:00:02Z",
            "model": "gemini-4-neon-xhigh",
            "input_tokens": 1200,
            "cache_read_tokens": 600,
            "output_tokens": 180,
            "thinking": "Running cass recalls and webfetch",
            "tool_calls": [
                {
                    "name": "call_mcp_tool",
                    "args": {
                        "ServerName": "cass-mcp",
                        "ToolName": "cass_search",
                        "Arguments": {"query": "alpha"}
                    }
                },
                {
                    "name": "mcp__cass-mcp__cass_expand",
                    "args": {"source_id": "local", "source_path": "/synthetic/agy/hit.jsonl", "message_id": 7}
                },
                {
                    "name": "cass_search",
                    "args": {"query": "bare-framed"}
                },
                {
                    "name": "call_mcp_tool",
                    "args": {
                        "ServerName": "webfetch",
                        "ToolName": "cass_search",
                        "Arguments": {"url": "https://example.invalid"}
                    }
                }
            ]
        }),
        json!({
            "step_index": 3,
            "source": "SYSTEM",
            "type": "SYSTEM_MESSAGE",
            "created_at": "2026-11-22T10:00:03Z",
            "content": format!(
                "The following is a <SYSTEM_MESSAGE>.\n<SYSTEM_MESSAGE>\nReminder: work efficiently. {DROP_REMINDER}\n</SYSTEM_MESSAGE>"
            )
        }),
        json!({
            "step_index": 4,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:04Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:03Z\nCompleted At: 2026-11-22T10:00:04Z\n{}",
                c04_search(SECRET_DISPATCH_MCP)
            )
        }),
        json!({
            "step_index": 5,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:05Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:04Z\nCompleted At: 2026-11-22T10:00:05Z\n{}",
                c04_expand(SECRET_DIRECT_MCP)
            )
        }),
        json!({
            "step_index": 6,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:06Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:05Z\nCompleted At: 2026-11-22T10:00:06Z\n{}",
                c04_search(SECRET_BARE_C04)
            )
        }),
        json!({
            "step_index": 7,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:07Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:06Z\nCompleted At: 2026-11-22T10:00:07Z\n{KEEP_WEBFETCH}"
            )
        }),
        // Turn 2: run_command CLI recall (double agy 1.5.14 header) + ordinary run_command
        //         + R2 read_file(Path) + R2 run_command(cat) + ordinary read_file(Path)
        json!({
            "step_index": 8,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-22T10:00:08Z",
            "model": "gemini-4-neon-xhigh",
            "tool_calls": [
                {"name": "run_command", "args": {"CommandLine": "cass search beta --robot"}},
                {"name": "run_command", "args": {"CommandLine": "echo hello"}},
                {"name": "read_file", "args": {"Path": "/tmp/synthetic-proj/claude-system.md"}},
                {"name": "run_command", "args": {"CommandLine": "cat /tmp/synthetic-proj/claude-system.md"}},
                {"name": "read_file", "args": {"Path": "/tmp/synthetic-proj/src/lib.rs"}}
            ]
        }),
        json!({
            "step_index": 9,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:09Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:08Z\nCompleted At: 2026-11-22T10:00:09Z\n\
                 Created At: 2026-11-22T10:00:08Z\nCompleted At: 2026-11-22T10:00:09Z\n\
                 Command exited with code 0.\n\nCommand output:\n{}",
                c04_search(SECRET_CLI_1514)
            )
        }),
        json!({
            "step_index": 10,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:10Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:09Z\nCompleted At: 2026-11-22T10:00:10Z\n\
                 Command exited with code 0.\n\nCommand output:\n{KEEP_ORDINARY_SHELL}"
            )
        }),
        json!({
            "step_index": 11,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:11Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:10Z\nCompleted At: 2026-11-22T10:00:11Z\n{SECRET_R2_READ_FILE}"
            )
        }),
        json!({
            "step_index": 12,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:12Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:11Z\nCompleted At: 2026-11-22T10:00:12Z\n\
                 Command exited with code 0.\n\nCommand output:\n{SECRET_R2_SHELL_CAT}"
            )
        }),
        json!({
            "step_index": 13,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T10:00:13Z",
            "content": format!(
                "Created At: 2026-11-22T10:00:12Z\nCompleted At: 2026-11-22T10:00:13Z\n{KEEP_ORDINARY_FILE}"
            )
        }),
        // Legacy 1.0.7 RUN_COMMAND using lowercase `command` key -> CLI recall excluded!
        json!({
            "step_index": 14,
            "source": "MODEL",
            "type": "RUN_COMMAND",
            "created_at": "2026-11-22T10:00:14Z",
            "tool_calls": [{"name": "run_command", "id": "legacy_cli_1", "arguments": {"command": "cass search gamma --robot"}}],
            "content": c04_search(SECRET_CLI_107)
        }),
        // Meaningful system notice, CHECKPOINT, and ERROR_MESSAGE (error-only) must survive.
        json!({
            "step_index": 15,
            "source": "SYSTEM",
            "type": "SYSTEM_MESSAGE",
            "created_at": "2026-11-22T10:00:15Z",
            "content": KEEP_SUBAGENT_NOTICE
        }),
        json!({
            "step_index": 16,
            "source": "SYSTEM",
            "type": "CHECKPOINT",
            "created_at": "2026-11-22T10:00:16Z",
            "content": KEEP_CHECKPOINT
        }),
        json!({
            "step_index": 17,
            "source": "SYSTEM_SDK",
            "type": "ERROR_MESSAGE",
            "created_at": "2026-11-22T10:00:17Z",
            "error": KEEP_ERROR_TEXT
        }),
        json!({
            "step_index": 18,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-22T10:00:18Z",
            "model": "gemini-4-neon-xhigh",
            "input_tokens": 2000,
            "output_tokens": 90,
            "content": "Done verifying."
        }),
    ];
    fixture.write_session(main_uuid, "transcript_full.jsonl", true, &main_records);

    // Subagent standalone session
    fixture.write_session(
        sub_uuid,
        "transcript_full.jsonl",
        false,
        &[
            json!({
                "step_index": 0,
                "source": "USER_EXPLICIT",
                "type": "USER_INPUT",
                "created_at": "2026-11-22T10:01:00Z",
                "content": "<USER_REQUEST>\nSubagent task prompt\n</USER_REQUEST>"
            }),
            json!({
                "step_index": 1,
                "source": "MODEL",
                "type": "PLANNER_RESPONSE",
                "created_at": "2026-11-22T10:01:01Z",
                "model": "gemini-4-carbon-high",
                "content": "Subagent finished."
            }),
        ],
    );

    let output = fixture.run_index(&["--full"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "cass index failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("parse index json");
    assert_eq!(report["success"], json!(true), "report={report}");
    assert_eq!(
        report["indexing_stats"]["event_align_failed"],
        json!(0),
        "BOM + 6-role alignment must have zero failures: {report}"
    );
    assert_eq!(
        report["recall_uncovered_total"],
        json!(0),
        "all 5 recall calls are covered: {report}"
    );

    let db = fixture.open_db();

    // 1. Verify DB workspace/title/title_source/subagent metadata survived scratch reparse!
    let conv_rows: Vec<(String, Option<String>, Option<String>, Option<String>, Option<Vec<u8>>)> = db
        .query_all_map(
            "SELECT c.external_id, c.title, w.path, c.metadata_json, c.metadata_bin \
             FROM conversations c LEFT JOIN workspaces w ON w.id = c.workspace_id \
             JOIN agents a ON a.id = c.agent_id WHERE a.slug = 'antigravity' ORDER BY c.external_id",
            &[],
            |r| {
                Ok((
                    r.get_typed(0)?,
                    r.get_typed(1).ok(),
                    r.get_typed(2).ok(),
                    r.get_typed(3).ok(),
                    r.get_typed(4).ok(),
                ))
            },
        )
        .expect("query conversations");
    assert_eq!(conv_rows.len(), 2, "main + subagent sessions must be indexed");

    let main_row = conv_rows.iter().find(|r| r.0 == main_uuid).expect("main conv");
    assert_eq!(main_row.1.as_deref(), Some("Synthetic DB Main Title"));
    assert_eq!(main_row.2.as_deref(), Some("/tmp/synthetic-agy-ws"));
    let main_meta = decode_extra(main_row.3.clone(), main_row.4.clone());
    assert_eq!(main_meta["title_source"], json!("summary_db"));

    let sub_row = conv_rows.iter().find(|r| r.0 == sub_uuid).expect("sub conv");
    assert_eq!(sub_row.1.as_deref(), Some("Synthetic Subagent Title"));
    assert_eq!(sub_row.2.as_deref(), Some("/tmp/synthetic-agy-ws"));
    let sub_meta = decode_extra(sub_row.3.clone(), sub_row.4.clone());
    assert_eq!(sub_meta["title_source"], json!("summary_db"));
    assert_eq!(sub_meta["parent_conversation_id"], json!(main_uuid));
    assert_eq!(sub_meta["agent_name"], json!("Research Helper"));
    assert_eq!(sub_meta["nesting_depth"], json!(1));

    // 2. Verify all 7 excluded rows (5 cass_recall + 2 R2 context_file_read) have ZERO residue
    //    in BOTH content and decoded extra_json/extra_bin.
    let excluded_rows: Vec<(String, String, Option<String>, Option<Vec<u8>>)> = db
        .query_all_map(
            "SELECT json(m.excluded), m.content, m.extra_json, m.extra_bin \
             FROM messages m WHERE m.excluded IS NOT NULL ORDER BY m.id",
            &[],
            |r| Ok((r.get_typed(0)?, r.get_typed(1)?, r.get_typed(2).ok(), r.get_typed(3).ok())),
        )
        .expect("query excluded rows");
    assert_eq!(
        excluded_rows.len(),
        7,
        "expected 5 cass_recall + 2 context_file_read exclusions"
    );

    let all_msg_rows: Vec<(String, Option<String>, Option<Vec<u8>>)> = db
        .query_all_map(
            "SELECT content, extra_json, extra_bin FROM messages ORDER BY id",
            &[],
            |r| Ok((r.get_typed(0)?, r.get_typed(1).ok(), r.get_typed(2).ok())),
        )
        .expect("query all messages");

    for forbidden in [
        SECRET_DISPATCH_MCP,
        SECRET_DIRECT_MCP,
        SECRET_BARE_C04,
        SECRET_CLI_1514,
        SECRET_CLI_107,
        SECRET_R2_READ_FILE,
        SECRET_R2_SHELL_CAT,
        DROP_PREINVOCATION,
        DROP_REMINDER,
    ] {
        for (content, extra_json, extra_bin) in &all_msg_rows {
            assert!(
                !content.contains(forbidden),
                "forbidden marker {forbidden} leaked into message content: {content}"
            );
            let extra = decode_extra(extra_json.clone(), extra_bin.clone());
            assert!(
                !extra.to_string().contains(forbidden),
                "forbidden marker {forbidden} leaked into decoded extra: {extra}"
            );
        }
    }

    // 3. Verify negative controls & non-boilerplate system/checkpoint/error survived intact.
    let joined_content = all_msg_rows
        .iter()
        .map(|(c, _, _)| c.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    for kept in [
        KEEP_WEBFETCH,
        KEEP_ORDINARY_SHELL,
        KEEP_ORDINARY_FILE,
        KEEP_SUBAGENT_NOTICE,
        KEEP_CHECKPOINT,
        KEEP_ERROR_TEXT,
    ] {
        assert!(
            joined_content.contains(kept),
            "expected preserved content {kept} to survive ingest"
        );
    }

    // 4. Verify token_usage records non-unknown gemini model for antigravity.
    let models: Vec<String> = db
        .query_all_map(
            "SELECT DISTINCT model_name FROM token_usage WHERE model_name IS NOT NULL",
            &[],
            |r| r.get_typed(0),
        )
        .unwrap_or_default();
    assert!(
        models.iter().any(|m| m.starts_with("gemini-4-")),
        "expected real gemini-4-* model in token_usage, got {models:?}"
    );
}

#[test]
fn antigravity_unpaired_mismatch_blocks_cross_step_fallback_and_reports_uncovered_batch_and_watch_once() {
    const ORDINARY_MISMATCH_STAYS: &str = "AGY_ORDINARY_MISMATCH_RESULT_MUST_STAY";
    const CROSS_STEP_ORDINARY_STAYS: &str = "AGY_CROSS_STEP_ORDINARY_MUST_STAY";
    const UNPAIRED_RECALL_BODY: &str = "AGY_UNPAIRED_RECALL_STAYS_AND_COUNTS";

    let fixture = AgyFixture::new();
    let uuid = "3333cccc-2222-3333-4444-555566669999";

    let records = vec![
        json!({
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2026-11-22T11:00:00Z",
            "content": "<USER_REQUEST>\nTest mismatch fail-closed pairing\n</USER_REQUEST>"
        }),
        // Turn 1: N=1 call (cass-mcp) vs M=2 GENERIC results -> all explicitly unpaired!
        // Without B3 sentinels, `PairingContext::build`'s `unpaired.len() == 1` would falsely
        // pair the 1 call with the 1st GENERIC (deleting ORDINARY_MISMATCH_STAYS!).
        json!({
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-22T11:00:01Z",
            "model": "gemini-4-carbon-high",
            "tool_calls": [{
                "name": "call_mcp_tool",
                "args": {"ServerName": "cass-mcp", "ToolName": "cass_search", "Arguments": {"query": "mismatch"}}
            }]
        }),
        json!({
            "step_index": 2,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T11:00:02Z",
            "content": format!("Created At: 2026-11-22T11:00:01Z\n{ORDINARY_MISMATCH_STAYS}")
        }),
        json!({
            "step_index": 3,
            "source": "MODEL",
            "type": "GENERIC",
            "created_at": "2026-11-22T11:00:03Z",
            "content": format!(
                "Created At: 2026-11-22T11:00:02Z\n{}",
                c04_search(UNPAIRED_RECALL_BODY)
            )
        }),
        // Turn 2 (no USER_INPUT between Turn 2 & Turn 3): 1 unpaired call (0 GENERIC)
        // followed by a legacy unpaired tool_result -> must NOT cross-step pair!
        json!({
            "step_index": 4,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-22T11:00:04Z",
            "model": "gemini-4-carbon-high",
            "tool_calls": [{
                "name": "call_mcp_tool",
                "args": {"ServerName": "cass-mcp", "ToolName": "cass_search", "Arguments": {"query": "orphan-call"}}
            }]
        }),
        json!({
            "step_index": 5,
            "source": "MODEL",
            "type": "VIEW_FILE",
            "created_at": "2026-11-22T11:00:05Z",
            "content": CROSS_STEP_ORDINARY_STAYS
        }),
    ];

    // Write BOTH transcript_full.jsonl and transcript.jsonl so we can also test
    // `--watch-once` passing explicit `transcript.jsonl` with sibling `transcript_full.jsonl` (B5)!
    fixture.write_session(uuid, "transcript_full.jsonl", false, &records);
    let compact_path = fixture.write_session(uuid, "transcript.jsonl", false, &records);

    // 1. Batch `cass index --full`: verify 0 exclusions, both ordinary outputs kept,
    //    and `recall_uncovered_by_reason["unpaired_result"] == 1`.
    let batch_out = fixture.run_index(&["--full"]);
    assert_eq!(
        batch_out.status.code(),
        Some(0),
        "batch index failed: stderr={}",
        String::from_utf8_lossy(&batch_out.stderr)
    );
    let batch_report: Value = serde_json::from_slice(&batch_out.stdout).expect("batch json");
    assert_eq!(batch_report["success"], json!(true));
    assert_eq!(
        batch_report["recall_uncovered_by_reason"]["unpaired_result"],
        json!(1),
        "batch must report unpaired_result=1: {batch_report}"
    );
    assert_eq!(batch_report["indexing_stats"]["event_align_failed"], json!(0));

    let db = fixture.open_db();
    let excluded_count: i64 = db
        .query_row_map("SELECT COUNT(*) FROM messages WHERE excluded IS NOT NULL", &[], |r| {
            r.get_typed(0)
        })
        .expect("count excluded");
    assert_eq!(
        excluded_count, 0,
        "mismatched and cross-step unpaired results must NEVER be falsely excluded"
    );
    let bodies: Vec<String> = db
        .query_all_map("SELECT content FROM messages", &[], |r| r.get_typed(0))
        .expect("query contents");
    assert!(bodies.iter().any(|b| b.contains(ORDINARY_MISMATCH_STAYS)));
    assert!(bodies.iter().any(|b| b.contains(CROSS_STEP_ORDINARY_STAYS)));
    assert!(bodies.iter().any(|b| b.contains(UNPAIRED_RECALL_BODY)));
    drop(db);

    // 2. Resident/explicit `--watch-once` targeting `transcript.jsonl` with sibling `transcript_full.jsonl`
    //    in a fresh data_dir: proves B5 single-file scan/discover symmetry, C4.2 `--watch-once` hint,
    //    and `reports_recall_uncovered("antigravity")` on the watch-once path.
    let watch_fixture = AgyFixture::new();
    let _ = watch_fixture.write_session(uuid, "transcript_full.jsonl", false, &records);
    let watch_compact = watch_fixture.write_session(uuid, "transcript.jsonl", false, &records);
    let watch_arg = watch_compact.to_string_lossy().into_owned();
    let watch_out = watch_fixture.run_index(&["--watch-once", watch_arg.as_str()]);
    assert_eq!(
        watch_out.status.code(),
        Some(0),
        "watch-once failed: stderr={}",
        String::from_utf8_lossy(&watch_out.stderr)
    );
    let watch_report: Value = serde_json::from_slice(&watch_out.stdout).expect("watch json");
    assert_eq!(watch_report["success"], json!(true), "watch={watch_report}");
    assert_eq!(
        watch_report["recall_uncovered_by_reason"]["unpaired_result"],
        json!(1),
        "watch-once must report unpaired_result=1: {watch_report}"
    );
    assert_eq!(watch_report["indexing_stats"]["event_align_failed"], json!(0));
    let _ = Path::new(&compact_path);
}

#[test]
fn antigravity_configured_sources_toml_dual_file_index_and_watch_once() {
    // CASS-R2-B1 regression: a `sources.toml`-configured root containing a real
    // agy 1.5.14 dual-file session (both `transcript_full.jsonl` and
    // `transcript.jsonl`) with all 4 default-allowlisted connectors enabled
    // (`antigravity`, `claude_code`, `codex`, `pi_agent`) must:
    //  1) succeed on `cass index --full` with 0 `source_ownership_unresolved`,
    //     indexing 1 `antigravity` conversation and 0 `claude` conversations;
    //  2) succeed on `cass index --watch-once <compact transcript.jsonl>` with
    //     0 watch rejections and route cleanly to `antigravity`.
    let fixture = AgyFixture::new();
    let uuid = "4444dddd-2222-3333-4444-555566660000";

    // Place the configured root OUTSIDE `$HOME/.gemini/antigravity-cli` so it
    // exercises strictly the `sources.toml` shared-root ownership path.
    let shared_root = fixture.root.path().join("mirror/.gemini/antigravity-cli");
    let logs_dir = shared_root
        .join("brain")
        .join(uuid)
        .join(".system_generated/logs");
    std::fs::create_dir_all(&logs_dir).expect("mkdir mirror logs");

    let full_records = [
        json!({
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2026-11-22T12:00:00Z",
            "content": "Configured root dual-file session"
        }),
        json!({
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-22T12:00:01Z",
            "model": "gemini-4-neon-high",
            "content": "FULL_MIRROR_ANSWER_SENTINEL"
        }),
    ];
    let compact_records = [
        json!({
            "step_index": 0,
            "source": "USER_EXPLICIT",
            "type": "USER_INPUT",
            "created_at": "2026-11-22T12:00:00Z",
            "content": "Configured root dual-file session"
        }),
        json!({
            "step_index": 1,
            "source": "MODEL",
            "type": "PLANNER_RESPONSE",
            "created_at": "2026-11-22T12:00:01Z",
            "model": "gemini-4-neon-high",
            "content": "COMPACT_WATCH_ONCE_SENTINEL"
        }),
    ];
    let encode_jsonl = |recs: &[Value]| -> String {
        let mut s = String::new();
        for r in recs {
            s.push_str(&serde_json::to_string(r).unwrap());
            s.push('\n');
        }
        s
    };
    let full_path = logs_dir.join("transcript_full.jsonl");
    let compact_path = logs_dir.join("transcript.jsonl");
    std::fs::write(&full_path, encode_jsonl(&full_records)).expect("write full");
    std::fs::write(&compact_path, encode_jsonl(&compact_records)).expect("write compact");

    // Write sources.toml enabling all 4 default allowlisted connectors.
    let cass_cfg_dir = fixture.config_home().join("cass");
    std::fs::create_dir_all(&cass_cfg_dir).expect("mkdir config/cass");
    let sources_toml = format!(
        r#"disabled_agents = [
  "aider", "amp", "chatgpt", "clawdbot", "cline", "copilot", "copilot_cli",
  "crush", "cursor", "factory", "gemini", "hermes", "kimi", "openclaw",
  "opencode", "openhands", "qwen", "vibe"
]

[[sources]]
name = "local-agy"
type = "local"
origin_host = "local"
paths = [{:?}]
"#,
        shared_root.to_string_lossy()
    );
    std::fs::write(cass_cfg_dir.join("sources.toml"), sources_toml).expect("write sources.toml");

    // 1. Full batch index over configured dual-file root must succeed (exit 0).
    let mut cmd = Command::new(cass_bin());
    cmd.env("HOME", fixture.home())
        .env("XDG_DATA_HOME", fixture.home().join(".local/share"))
        .env("XDG_CONFIG_HOME", fixture.config_home())
        .env("XDG_CACHE_HOME", fixture.home().join(".cache"))
        .env("XDG_STATE_HOME", fixture.home().join(".state"))
        .env("CASS_DATA_DIR", fixture.data_dir())
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("NO_COLOR", "1")
        .env_remove("CASS_ANTIGRAVITY_DATA_ROOT")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("CASS_IGNORE_SOURCES_CONFIG")
        .env_remove("CASS_API_CONFIG")
        .env_remove("RUST_LOG")
        .args(["index", "--full", "--data-dir"])
        .arg(fixture.data_dir())
        .arg("--json");
    let batch_out = cmd.output().expect("spawn configured-root cass index");
    let batch_stderr = String::from_utf8_lossy(&batch_out.stderr);
    assert_eq!(
        batch_out.status.code(),
        Some(0),
        "configured-root dual-file cass index must succeed: stderr={batch_stderr}"
    );
    assert!(
        !batch_stderr.contains("source_ownership_unresolved"),
        "must not emit source_ownership_unresolved: stderr={batch_stderr}"
    );
    let batch_report: Value = serde_json::from_slice(&batch_out.stdout).expect("batch json");
    assert_eq!(batch_report["success"], json!(true), "report={batch_report}");
    assert!(
        batch_report["sources_config_error"].is_null(),
        "sources.toml must load cleanly: {batch_report}"
    );

    let db = fixture.open_db();
    let slug_counts: Vec<(String, i64)> = db
        .query_all_map(
            "SELECT a.slug, COUNT(*) FROM conversations c JOIN agents a ON a.id = c.agent_id GROUP BY a.slug ORDER BY a.slug",
            &[],
            |r| Ok((r.get_typed(0)?, r.get_typed(1)?)),
        )
        .expect("query agent counts");
    assert_eq!(
        slug_counts,
        vec![("antigravity".to_string(), 1)],
        "only antigravity must own the configured dual-file session, never claude"
    );
    let contents: Vec<String> = db
        .query_all_map("SELECT content FROM messages", &[], |r| r.get_typed(0))
        .expect("query contents");
    assert!(
        contents.iter().any(|c| c.contains("FULL_MIRROR_ANSWER_SENTINEL")),
        "batch scan must read primary transcript_full.jsonl: {contents:?}"
    );
    drop(db);

    // 2. Explicit `--watch-once` targeting compact `transcript.jsonl` under the same
    //    configured root in a fresh data_dir must exit 0 and ingest cleanly under antigravity.
    let watch_data = fixture.root.path().join("watch-data");
    std::fs::create_dir_all(&watch_data).expect("mkdir watch-data");
    let mut wcmd = Command::new(cass_bin());
    wcmd.env("HOME", fixture.home())
        .env("XDG_DATA_HOME", fixture.home().join(".local/share"))
        .env("XDG_CONFIG_HOME", fixture.config_home())
        .env("XDG_CACHE_HOME", fixture.home().join(".cache"))
        .env("XDG_STATE_HOME", fixture.home().join(".state"))
        .env("CASS_DATA_DIR", &watch_data)
        .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
        .env("NO_COLOR", "1")
        .env_remove("CASS_ANTIGRAVITY_DATA_ROOT")
        .env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("CODEX_HOME")
        .env_remove("CASS_IGNORE_SOURCES_CONFIG")
        .env_remove("CASS_API_CONFIG")
        .env_remove("RUST_LOG")
        .args(["index", "--data-dir"])
        .arg(&watch_data)
        .arg("--watch-once")
        .arg(&compact_path)
        .arg("--json");
    let watch_out = wcmd.output().expect("spawn configured-root watch-once");
    let watch_stderr = String::from_utf8_lossy(&watch_out.stderr);
    assert_eq!(
        watch_out.status.code(),
        Some(0),
        "configured-root watch-once on transcript.jsonl must succeed: stderr={watch_stderr}"
    );
    assert!(
        !watch_stderr.contains("source_ownership_unresolved"),
        "watch-once must not emit source_ownership_unresolved: stderr={watch_stderr}"
    );
    let watch_report: Value = serde_json::from_slice(&watch_out.stdout).expect("watch json");
    assert_eq!(watch_report["success"], json!(true), "watch={watch_report}");

    let wdb = Conn::open_read_with(
        &watch_data.join("agent_search.db"),
        OpenOptions {
            busy_timeout: Duration::from_secs(30),
        },
    )
    .expect("open watch db");
    let w_contents: Vec<String> = wdb
        .query_all_map("SELECT content FROM messages", &[], |r| r.get_typed(0))
        .expect("query watch contents");
    assert!(
        w_contents.iter().any(|c| c.contains("COMPACT_WATCH_ONCE_SENTINEL")),
        "explicit --watch-once on transcript.jsonl must read that exact file: {w_contents:?}"
    );
}
