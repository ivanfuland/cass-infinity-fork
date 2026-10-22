//! CLI time-filter contract for the read-only MCP entry (04).
//!
//! An explicit `--since`/`--until` value that cannot be parsed must be a usage
//! error on search, sessions and timeline. It must never be folded into the
//! default window and it must not be masked by a missing database or model.
//! The commands keep their previously accepted syntax and their defaults.
//!
//! The fixture is a real current-schema database built by `FrankenStorage`
//! with fixed conversation/message timestamps. Every case spawns the actual
//! `cass` binary with its own HOME/XDG/CASS_DATA_DIR so assertions exercise
//! the production wiring, not a test-only helper.

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::recall_output::{RecallTool, decode};
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Output};

/// 2025-10-01T00:00:00Z
const T_OLD_MS: i64 = 1_759_276_800_000;
/// 2025-10-10T00:00:00Z
const T_IN_MS: i64 = 1_760_054_400_000;
/// 2025-10-25T00:00:00Z
const T_LATE_MS: i64 = 1_761_350_400_000;

struct Fixture {
    home: tempfile::TempDir,
    db: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().unwrap();
        let db = home.path().join("agent_search.db");
        let storage = FrankenStorage::open(&db).unwrap();

        let version = storage
            .raw()
            .query_all_map("PRAGMA user_version", &[], |row| row.get_typed::<i64>(0))
            .unwrap();
        assert_eq!(version, vec![9], "fixture must be the current schema");

        let agent = storage
            .ensure_agent(&Agent {
                id: None,
                slug: "codex".into(),
                name: "Codex".into(),
                version: None,
                kind: AgentKind::Cli,
            })
            .unwrap();
        let workspace = storage.ensure_workspace(home.path(), None).unwrap();

        for (slug, started_at) in [("old", T_OLD_MS), ("inside", T_IN_MS), ("late", T_LATE_MS)] {
            let source = home.path().join(format!("{slug}-session.jsonl"));
            let body = format!("strictneedle {slug} message body");
            storage
                .insert_conversation_tree(
                    agent,
                    Some(workspace),
                    &Conversation {
                        id: None,
                        agent_slug: "codex".into(),
                        workspace: Some(home.path().into()),
                        external_id: Some(format!("strict-time-{slug}")),
                        title: Some(format!("strictneedle {slug}")),
                        source_path: source,
                        started_at: Some(started_at),
                        ended_at: Some(started_at),
                        approx_tokens: None,
                        metadata_json: json!({}),
                        source_id: "local".into(),
                        origin_host: None,
                        messages: vec![Message {
                            id: None,
                            idx: 0,
                            role: MessageRole::User,
                            author: None,
                            created_at: Some(started_at),
                            content: body,
                            extra_json: json!({}),
                            snippets: vec![],
                            excluded: None,
                        }],
                    },
                )
                .unwrap();
        }
        drop(storage);
        Self { home, db }
    }

    fn command_for(&self, db: &std::path::Path) -> Command {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cass"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("CASS_") {
                cmd.env_remove(key);
            }
        }
        cmd.current_dir(self.home.path())
            .env("HOME", self.home.path())
            .env("XDG_DATA_HOME", self.home.path().join("xdg"))
            .env("XDG_CONFIG_HOME", self.home.path().join("config"))
            .env("CASS_DATA_DIR", self.home.path())
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("TZ", "UTC")
            .arg("--db")
            .arg(db);
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = self.command_for(&self.db);
        cmd.args(args);
        cmd.output().unwrap()
    }

    /// Same isolation, but pointed at a database path that does not exist.
    fn run_missing_db(&self, args: &[&str]) -> Output {
        let mut cmd = self.command_for(&self.home.path().join("absent").join("absent.db"));
        cmd.args(args);
        cmd.output().unwrap()
    }
}

fn assert_usage_error(output: &Output, flag: &str) {
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit 2, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "usage errors must keep stdout empty, got: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let envelope: Value = serde_json::from_str(stderr.trim())
        .unwrap_or_else(|e| panic!("stderr is not a JSON error envelope ({e}): {stderr}"));
    assert_eq!(envelope["error"]["code"], 2, "stderr: {stderr}");
    assert_eq!(envelope["error"]["kind"], "usage", "stderr: {stderr}");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap()
            .contains(flag),
        "error should name {flag}: {stderr}"
    );
}

fn json_ok(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "expected success, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON ({e}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn search_hits(value: &Value) -> &Vec<Value> {
    value["hits"].as_array().expect("hits array")
}

fn hit_ids(value: &Value) -> Vec<i64> {
    let mut ids: Vec<i64> = search_hits(value)
        .iter()
        .map(|hit| {
            hit["message_id"]
                .as_i64()
                .unwrap_or_else(|| panic!("hit without message_id: {hit}"))
        })
        .collect();
    ids.sort_unstable();
    ids
}

/// 04-AC1: every explicit unparseable time is `2/usage` on a real schema-9
/// database, including when it is combined with `--today`, and a missing
/// database cannot mask it.
#[test]
fn explicit_invalid_time_is_rejected_on_a_valid_database() {
    let fixture = Fixture::new();
    let cases: &[(&[&str], &str)] = &[
        (
            &[
                "search",
                "strictneedle",
                "--mode",
                "lexical",
                "--since",
                "not-a-date",
                "--json",
            ],
            "--since",
        ),
        (
            &[
                "search",
                "strictneedle",
                "--mode",
                "lexical",
                "--until",
                "not-a-date",
                "--json",
            ],
            "--until",
        ),
        (&["sessions", "--since", "not-a-date", "--json"], "--since"),
        (&["timeline", "--since", "not-a-date", "--json"], "--since"),
        (&["timeline", "--until", "not-a-date", "--json"], "--until"),
        (
            &[
                "search",
                "strictneedle",
                "--mode",
                "lexical",
                "--since",
                "2026-13-45",
                "--json",
            ],
            "--since",
        ),
        (&["sessions", "--since", "   ", "--json"], "--since"),
        (&["timeline", "--until", "2026-02-30", "--json"], "--until"),
        (
            &[
                "search",
                "strictneedle",
                "--mode",
                "lexical",
                "--today",
                "--since",
                "not-a-date",
                "--json",
            ],
            "--since",
        ),
        (
            &["timeline", "--today", "--since", "not-a-date", "--json"],
            "--since",
        ),
        (
            &["timeline", "--today", "--until", "not-a-date", "--json"],
            "--until",
        ),
    ];

    for (args, flag) in cases {
        let label = format!("{args:?}");
        let output = fixture.run(args);
        assert_usage_error(&output, flag);
        eprintln!("valid-db case rejected: {label}");
    }
}

/// 04-AC1 (priority): with no database at all, an explicit bad time must
/// still win over `missing-db`/`missing-index`.
#[test]
fn explicit_invalid_time_wins_over_a_missing_database() {
    let fixture = Fixture::new();
    let cases: &[(&[&str], &str)] = &[
        (
            &[
                "search",
                "strictneedle",
                "--mode",
                "lexical",
                "--since",
                "not-a-date",
                "--json",
            ],
            "--since",
        ),
        (
            &[
                "search",
                "strictneedle",
                "--mode",
                "lexical",
                "--until",
                "not-a-date",
                "--json",
            ],
            "--until",
        ),
        (&["sessions", "--since", "not-a-date", "--json"], "--since"),
        (&["timeline", "--since", "not-a-date", "--json"], "--since"),
        (&["timeline", "--until", "not-a-date", "--json"], "--until"),
    ];

    for (args, flag) in cases {
        let output = fixture.run_missing_db(args);
        assert_usage_error(&output, flag);
        eprintln!("missing-db case rejected: {args:?}");
    }
}

/// 04-AC2: omitted times keep their defaults, and every previously legal
/// syntax still works on all three commands.
#[test]
fn legal_legacy_syntax_and_defaults_are_preserved() {
    let fixture = Fixture::new();

    // search: no time flags -> all fixture messages.
    let all = fixture.run(&["search", "strictneedle", "--mode", "lexical", "--json"]);
    let all = json_ok(&all);
    assert_eq!(search_hits(&all).len(), 3, "default search window: {all}");

    // search: date-only (local midnight, TZ=UTC for the child).
    let dated = fixture.run(&[
        "search",
        "strictneedle",
        "--mode",
        "lexical",
        "--since",
        "2025-10-09",
        "--until",
        "2025-10-11",
        "--json",
    ]);
    let dated = json_ok(&dated);
    assert_eq!(hit_ids(&dated).len(), 1, "date-only window: {dated}");
    assert_eq!(dated["hits"][0]["created_at"], T_IN_MS);

    // search: the naive `YYYY-MM-DDTHH:MM:SS` form this parser has always taken.
    let naive = fixture.run(&[
        "search",
        "strictneedle",
        "--mode",
        "lexical",
        "--since",
        "2025-10-09T00:00:00",
        "--json",
    ]);
    let naive = json_ok(&naive);
    assert_eq!(hit_ids(&naive).len(), 2, "naive datetime window: {naive}");

    // search: relative syntax remains legal (and simply selects nothing here).
    for since in ["-7d", "7d", "today", "yesterday", "-24h"] {
        let output = fixture.run(&[
            "search",
            "strictneedle",
            "--mode",
            "lexical",
            "--since",
            since,
            "--json",
        ]);
        let value = json_ok(&output);
        assert!(value["hits"].is_array(), "--since {since}: {value}");
    }

    // search: the single recall envelope still decodes with a time window.
    let recall = fixture.run(&[
        "search",
        "strictneedle",
        "--mode",
        "lexical",
        "--since",
        "2025-10-09",
        "--until",
        "2025-10-11",
        "--recall",
    ]);
    assert!(
        recall.status.success(),
        "recall failed: {}",
        String::from_utf8_lossy(&recall.stderr)
    );
    let decoded = decode(
        std::str::from_utf8(&recall.stdout).unwrap(),
        RecallTool::Search,
    )
    .expect("recall envelope");
    assert_eq!(search_hits(&decoded).len(), 1, "recall window: {decoded}");

    // sessions: no filter -> all three; legal date and relative forms filter.
    let sessions = json_ok(&fixture.run(&["sessions", "--json"]));
    assert_eq!(
        sessions["sessions"].as_array().unwrap().len(),
        3,
        "default sessions: {sessions}"
    );
    let since = json_ok(&fixture.run(&["sessions", "--since", "2025-10-05", "--json"]));
    assert_eq!(
        since["sessions"].as_array().unwrap().len(),
        2,
        "sessions --since date: {since}"
    );
    let relative = json_ok(&fixture.run(&["sessions", "--since", "-7d", "--json"]));
    assert_eq!(
        relative["sessions"].as_array().unwrap().len(),
        0,
        "sessions --since -7d: {relative}"
    );

    // sessions still has no --until: the flag stays unknown.
    let unknown = fixture.run(&["sessions", "--until", "2025-10-05", "--json"]);
    assert!(
        !unknown.status.success(),
        "sessions must not grow an --until flag"
    );

    // timeline: omitted times mean the seven days before "now".
    let default = json_ok(&fixture.run(&["timeline", "--json"]));
    let start = default["range"]["start"].as_i64().unwrap();
    let end = default["range"]["end"].as_i64().unwrap();
    assert_eq!(
        end - start,
        7 * 24 * 60 * 60 * 1000,
        "default timeline window: {default}"
    );

    // timeline: explicit RFC3339 window and relative syntax still work.
    let explicit = json_ok(&fixture.run(&[
        "timeline",
        "--since",
        "2025-10-05T00:00:00Z",
        "--until",
        "2025-10-15T00:00:00Z",
        "--json",
    ]));
    assert_eq!(explicit["total_sessions"], 1, "explicit window: {explicit}");
    assert_eq!(
        explicit["range"]["start"].as_i64().unwrap(),
        T_IN_MS - 5 * 86_400_000
    );
    assert_eq!(
        explicit["range"]["end"].as_i64().unwrap(),
        T_IN_MS + 5 * 86_400_000
    );

    for since in ["-7d", "7d", "today", "yesterday", "-24h"] {
        let output = fixture.run(&["timeline", "--since", since, "--json"]);
        let value = json_ok(&output);
        assert!(value["range"]["start"].is_i64(), "--since {since}: {value}");
    }

    // timeline: `--today` keeps its original priority over explicit values.
    let today = json_ok(&fixture.run(&[
        "timeline",
        "--today",
        "--until",
        "2025-10-15T00:00:00Z",
        "--json",
    ]));
    let today_start = today["range"]["start"].as_i64().unwrap();
    assert_eq!(today_start % 86_400_000, 0, "--today window: {today}");
}

/// 04-AC3: inverted effective windows are rejected, and two offset spellings
/// of one absolute window return the same data and the same echo range.
#[test]
fn inverted_ranges_are_rejected_and_offsets_share_one_absolute_window() {
    let fixture = Fixture::new();

    let inverted_search = fixture.run(&[
        "search",
        "strictneedle",
        "--mode",
        "lexical",
        "--since",
        "2025-10-25T00:00:00Z",
        "--until",
        "2025-10-05T00:00:00Z",
        "--json",
    ]);
    assert_usage_error(&inverted_search, "--since");

    let inverted_timeline = fixture.run(&[
        "timeline",
        "--since",
        "2025-10-25T00:00:00Z",
        "--until",
        "2025-10-05T00:00:00Z",
        "--json",
    ]);
    assert_usage_error(&inverted_timeline, "--since");

    let utc = json_ok(&fixture.run(&[
        "search",
        "strictneedle",
        "--mode",
        "lexical",
        "--since",
        "2025-10-05T00:00:00Z",
        "--until",
        "2025-10-15T00:00:00Z",
        "--json",
    ]));
    let offset = json_ok(&fixture.run(&[
        "search",
        "strictneedle",
        "--mode",
        "lexical",
        "--since",
        "2025-10-04T19:00:00-05:00",
        "--until",
        "2025-10-14T19:00:00-05:00",
        "--json",
    ]));
    assert_eq!(hit_ids(&utc), hit_ids(&offset), "same absolute window");
    assert_eq!(hit_ids(&utc).len(), 1, "window selects the inside message");

    let utc_timeline = json_ok(&fixture.run(&[
        "timeline",
        "--since",
        "2025-10-05T00:00:00Z",
        "--until",
        "2025-10-15T00:00:00Z",
        "--json",
    ]));
    let offset_timeline = json_ok(&fixture.run(&[
        "timeline",
        "--since",
        "2025-10-04T19:00:00-05:00",
        "--until",
        "2025-10-14T19:00:00-05:00",
        "--json",
    ]));
    assert_eq!(utc_timeline["range"], offset_timeline["range"]);
    assert_eq!(
        utc_timeline["total_sessions"], offset_timeline["total_sessions"],
        "offset spelling must not change the selected sessions"
    );
    assert_eq!(utc_timeline["total_sessions"], 1);
}
