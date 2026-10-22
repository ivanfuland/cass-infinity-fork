//! 03 — precise expand of one indexed message by message ID.
//!
//! These tests drive the real `cass` binary against a synthetic, isolated
//! database. They lock four behaviours:
//!
//! 1. Each of two consecutive hits expands to its own stored body even when
//!    the original session file carries metadata lines and blank lines that
//!    shift the physical line numbers.
//! 2. The stored body is returned whether the original file exists, was
//!    rewritten, or is gone. The source file is never consulted.
//! 3. Unknown IDs, a wrong source/path and a stale content digest are
//!    rejected with exit 3 and distinct kinds, and stdout stays empty.
//! 4. Every context value (0, normal, larger than the session, `usize::MAX`)
//!    yields exactly one target with a clamped window, while integers that
//!    do not fit the CLI types are rejected before the database is read.
//!    The legacy `--line` mode no longer overflows on `--context usize::MAX`.

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::recall_output::{decode, RecallTool};
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const BODIES: [&str; 6] = [
    "alpha context one",
    "beta context two",
    "gamma target three",
    "delta target four",
    "epsilon recall echo",
    "zeta context six",
];

const EXCLUDED_IDX: usize = 4;

/// The synthetic session file deliberately does not mirror the database:
/// it starts with a metadata record and a blank line, so a physical line
/// lookup cannot accidentally agree with the stored message index.
const SOURCE_FILE_ORIGINAL: &str = concat!(
    "{\"type\":\"summary\",\"summary\":\"fixture metadata\"}\n",
    "\n",
    "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"file copy only\"}}\n",
    "{\"type\":\"assistant\",\"message\":{\"role\":\"assistant\",\"content\":\"other file copy\"}}\n",
);

struct Fixture {
    home: tempfile::TempDir,
    db: PathBuf,
    source: PathBuf,
    ids: Vec<i64>,
}

impl Fixture {
    fn new() -> Self {
        let home = tempfile::tempdir().expect("tempdir");
        let db = home.path().join("agent_search.db");
        let source = home.path().join("precise-session.jsonl");
        let storage = FrankenStorage::open(&db).expect("open storage");
        let agent = storage
            .ensure_agent(&Agent {
                id: None,
                slug: "codex".into(),
                name: "Codex".into(),
                version: None,
                kind: AgentKind::Cli,
            })
            .expect("ensure agent");
        let workspace = storage.ensure_workspace(home.path(), None).expect("workspace");
        let messages = BODIES
            .iter()
            .enumerate()
            .map(|(idx, body)| Message {
                id: None,
                idx: idx as i64,
                role: if idx % 2 == 0 {
                    MessageRole::User
                } else {
                    MessageRole::Assistant
                },
                author: None,
                created_at: Some(1_761_000_000_000 + idx as i64),
                content: (*body).into(),
                extra_json: json!({}),
                snippets: vec![],
                excluded: if idx == EXCLUDED_IDX {
                    use coding_agent_search::indexer::exclusion::{
                        ExcludedMarker, ExclusionReason, RawRef,
                    };
                    Some(ExcludedMarker {
                        reason: ExclusionReason::CassRecall,
                        rule_version: 1,
                        bytes: 0,
                        sha256: hex::encode(Sha256::digest(b"")),
                        fingerprint_blake3: blake3::hash(b"").to_hex().to_string(),
                        anchor: Default::default(),
                        src: None,
                        parse_error: None,
                        raw: RawRef {
                            blob: "blobs/fixture.raw".into(),
                            idx: idx as u32,
                            event_key: "fixture".into(),
                            blocks: vec![],
                        },
                    })
                } else {
                    None
                },
            })
            .collect();
        storage
            .insert_conversation_tree(
                agent,
                Some(workspace),
                &Conversation {
                    id: None,
                    agent_slug: "codex".into(),
                    workspace: Some(home.path().into()),
                    external_id: Some("precise-expand-fixture".into()),
                    title: Some("precise expand fixture".into()),
                    source_path: source.clone(),
                    started_at: Some(1_761_000_000_000),
                    ended_at: Some(1_761_000_000_000),
                    approx_tokens: None,
                    metadata_json: json!({}),
                    source_id: "local".into(),
                    origin_host: None,
                    messages,
                },
            )
            .expect("insert conversation");
        let ids = storage
            .raw()
            .query_all_map("SELECT id FROM messages ORDER BY idx", &[], |row| {
                row.get_typed::<i64>(0)
            })
            .expect("message ids");
        drop(storage);
        fs::write(&source, SOURCE_FILE_ORIGINAL).expect("write source file");
        Self {
            home,
            db,
            source,
            ids,
        }
    }

    fn source_str(&self) -> &str {
        self.source.to_str().expect("utf-8 source path")
    }

    fn db_str(&self) -> &str {
        self.db.to_str().expect("utf-8 db path")
    }

    /// Run `cass expand` in message-ID mode with an isolated HOME/XDG.
    fn expand_id(
        &self,
        id: i64,
        sha: &str,
        source: &str,
        path: &str,
        context: &str,
        extra: &[&str],
    ) -> Outcome {
        let message_id = id.to_string();
        let mut args = vec![
            "--color=never",
            "--db",
            self.db_str(),
            "expand",
            path,
            "--source",
            source,
            "--message-id",
            message_id.as_str(),
            "--expected-content-sha256",
            sha,
            "--context",
            context,
        ];
        args.extend_from_slice(extra);
        self.run(&args)
    }

    fn run(&self, args: &[&str]) -> Outcome {
        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("cass"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("CASS_") {
                cmd.env_remove(key);
            }
        }
        cmd.current_dir(self.home.path())
            .env("HOME", self.home.path())
            .env("XDG_DATA_HOME", self.home.path().join("xdg-data"))
            .env("XDG_CONFIG_HOME", self.home.path().join("xdg-config"))
            .env("XDG_CACHE_HOME", self.home.path().join("xdg-cache"))
            .env("CASS_DATA_DIR", self.home.path())
            .env("CASS_IGNORE_SOURCES_CONFIG", "1")
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .args(args);
        let output = cmd.output().expect("run cass");
        Outcome {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

struct Outcome {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn sha_hex(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

fn assert_success(outcome: &Outcome, label: &str) -> Value {
    assert_eq!(
        outcome.code,
        Some(0),
        "[{label}] expected success\nstdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        outcome.stderr.trim().is_empty(),
        "[{label}] success must not write diagnostics to stderr: {}",
        outcome.stderr
    );
    serde_json::from_str(&outcome.stdout)
        .unwrap_or_else(|err| panic!("[{label}] stdout is not JSON: {err}\n{}", outcome.stdout))
}

fn assert_error(outcome: &Outcome, label: &str, expected_code: i32, expected_kind: &str) {
    assert_eq!(
        outcome.code,
        Some(expected_code),
        "[{label}] expected exit {expected_code}\nstdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        outcome.stdout.trim().is_empty(),
        "[{label}] error case must not write to stdout: {}",
        outcome.stdout
    );
    let parsed: Value = serde_json::from_str(outcome.stderr.trim()).unwrap_or_else(|err| {
        panic!(
            "[{label}] stderr is not a JSON error envelope: {err}\n{}",
            outcome.stderr
        )
    });
    let error = parsed.get("error").unwrap_or_else(|| {
        panic!("[{label}] missing error object in envelope: {parsed}");
    });
    assert_eq!(
        error.get("kind").and_then(Value::as_str),
        Some(expected_kind),
        "[{label}] wrong kind: {error}"
    );
    assert_eq!(
        error.get("retryable").and_then(Value::as_bool),
        Some(false),
        "[{label}] wrong retryable: {error}"
    );
}

fn targets(messages: &[Value]) -> Vec<&Value> {
    messages
        .iter()
        .filter(|message| message["is_target"] == Value::Bool(true))
        .collect()
}

fn lines_of(messages: &[Value]) -> Vec<i64> {
    messages
        .iter()
        .map(|message| message["line"].as_i64().expect("line number"))
        .collect()
}

fn contents_of(messages: &[Value]) -> Vec<String> {
    messages
        .iter()
        .map(|message| {
            message["content"]
                .as_str()
                .expect("content string")
                .to_string()
        })
        .collect()
}

#[test]
fn consecutive_hits_expand_to_their_own_indexed_body() {
    let fixture = Fixture::new();
    let first = fixture.expand_id(
        fixture.ids[2],
        &sha_hex(BODIES[2]),
        "local",
        fixture.source_str(),
        "0",
        &["--json"],
    );
    let first = assert_success(&first, "first hit");
    let first_messages = first.as_array().expect("array shape");
    assert_eq!(first_messages.len(), 1, "context 0 must return one message");
    assert_eq!(first_messages[0]["content"], BODIES[2]);
    assert_eq!(first_messages[0]["line"], json!(3));
    assert_eq!(first_messages[0]["role"], "user");
    assert_eq!(targets(first_messages).len(), 1);
    // The ordinary JSON shape is unchanged from the line-based entry point.
    let mut keys: Vec<&str> = first_messages[0]
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, vec!["content", "is_target", "line", "role"]);

    // The source file's physical target line (3) still differs from the
    // second hit's stored index line (4); each hit keeps its own body.
    let second = fixture.expand_id(
        fixture.ids[3],
        &sha_hex(BODIES[3]),
        "local",
        fixture.source_str(),
        "0",
        &["--json"],
    );
    let second = assert_success(&second, "second hit");
    let second_messages = second.as_array().expect("array shape");
    assert_eq!(second_messages.len(), 1);
    assert_eq!(second_messages[0]["content"], BODIES[3]);
    assert_eq!(second_messages[0]["line"], json!(4));
    assert_eq!(targets(second_messages).len(), 1);
}

#[test]
fn indexed_content_is_returned_when_the_source_file_exists_changes_or_disappears() {
    let fixture = Fixture::new();
    let mut observed = Vec::new();
    for variant in 0..3 {
        match variant {
            0 => {
                fs::write(&fixture.source, SOURCE_FILE_ORIGINAL).expect("restore source file");
            }
            1 => {
                fs::write(
                    &fixture.source,
                    "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"rewritten\"}}\n",
                )
                .expect("rewrite source file");
            }
            _ => {
                fs::remove_file(&fixture.source).expect("remove source file");
            }
        }
        let outcome = fixture.expand_id(
            fixture.ids[2],
            &sha_hex(BODIES[2]),
            "local",
            fixture.source_str(),
            "0",
            &["--json"],
        );
        let parsed = assert_success(&outcome, &format!("source file variant {variant}"));
        let messages = parsed.as_array().expect("array shape");
        assert_eq!(messages.len(), 1);
        observed.push(messages[0]["content"].as_str().unwrap().to_string());
    }
    assert_eq!(observed, vec![BODIES[2].to_string(); 3]);
    assert!(
        !fixture.source.exists(),
        "the third variant must still succeed with no source file"
    );
}

#[test]
fn unknown_sources_stale_digests_and_excluded_rows_are_rejected() {
    let fixture = Fixture::new();
    let json_flag = ["--json"];

    let missing = fixture.expand_id(
        fixture.ids[2] + 10_000,
        &sha_hex(BODIES[2]),
        "local",
        fixture.source_str(),
        "3",
        &json_flag,
    );
    assert_error(&missing, "unknown id", 3, "message_not_found");

    let wrong_source = fixture.expand_id(
        fixture.ids[2],
        &sha_hex(BODIES[2]),
        "work-laptop",
        fixture.source_str(),
        "3",
        &json_flag,
    );
    assert_error(&wrong_source, "wrong source", 3, "source_mismatch");

    let other_path = fixture.home.path().join("another-session.jsonl");
    let other_path = other_path.to_str().expect("utf-8 path");
    let wrong_path = fixture.expand_id(
        fixture.ids[2],
        &sha_hex(BODIES[2]),
        "local",
        other_path,
        "3",
        &json_flag,
    );
    assert_error(&wrong_path, "wrong path", 3, "source_mismatch");

    let stale = fixture.expand_id(
        fixture.ids[2],
        &sha_hex(BODIES[3]),
        "local",
        fixture.source_str(),
        "3",
        &json_flag,
    );
    assert_error(&stale, "stale digest", 3, "stale_reference");

    // A removed row ID can be reused by a different body; the digest still
    // anchors the caller to the content it saw.
    let reused = fixture.expand_id(
        fixture.ids[3],
        &sha_hex(BODIES[2]),
        "local",
        fixture.source_str(),
        "3",
        &json_flag,
    );
    assert_error(&reused, "id reuse with another body", 3, "stale_reference");

    let excluded = fixture.expand_id(
        fixture.ids[EXCLUDED_IDX],
        &sha_hex(BODIES[EXCLUDED_IDX]),
        "local",
        fixture.source_str(),
        "3",
        &json_flag,
    );
    assert_error(&excluded, "excluded row", 3, "message_not_found");

    // The same error through the recall channel must not leak a partial XML
    // wrapper to stdout.
    let recall_error = fixture.expand_id(
        fixture.ids[2] + 10_000,
        &sha_hex(BODIES[2]),
        "local",
        fixture.source_str(),
        "3",
        &["--recall"],
    );
    assert_error(&recall_error, "recall unknown id", 3, "message_not_found");
    assert!(
        !recall_error.stdout.contains("cass_recall"),
        "no half XML on stdout: {}",
        recall_error.stdout
    );
}

#[test]
fn every_context_value_clamps_and_keeps_exactly_one_target() {
    let fixture = Fixture::new();
    // Stored idx 4 is excluded, so its line (5) is absent from every window.
    let cases: [(&str, Vec<i64>); 4] = [
        ("0", vec![3]),
        ("1", vec![2, 3, 4]),
        ("100", vec![1, 2, 3, 4, 6]),
        ("18446744073709551615", vec![1, 2, 3, 4, 6]),
    ];
    for (context, expected_lines) in cases {
        let outcome = fixture.expand_id(
            fixture.ids[2],
            &sha_hex(BODIES[2]),
            "local",
            fixture.source_str(),
            context,
            &["--json"],
        );
        let parsed = assert_success(&outcome, &format!("context {context}"));
        let messages = parsed.as_array().expect("array shape");
        assert_eq!(
            messages.len(),
            expected_lines.len(),
            "context {context} window size: {}",
            parsed
        );
        let target_rows = targets(messages);
        assert_eq!(target_rows.len(), 1, "context {context} target count");
        assert_eq!(target_rows[0]["content"], BODIES[2]);
        assert_eq!(target_rows[0]["line"], json!(3));
        // Windows follow stored idx order and clamp to the session bounds.
        assert_eq!(lines_of(messages), expected_lines);
        let bodies = contents_of(messages);
        assert!(
            !bodies.contains(&BODIES[EXCLUDED_IDX].to_string()),
            "excluded content must never enter the context: {bodies:?}"
        );
    }
}

#[test]
fn invalid_integers_and_digests_fail_before_the_database_is_opened() {
    let fixture = Fixture::new();
    let missing_db = fixture.home.path().join("does-not-exist.db");
    let missing_db = missing_db.to_str().expect("utf-8 path");
    let json_flag = ["--json"];

    let expand_with = |message_id: &str, sha: &str, context: &str, extra: &[&str]| {
        let mut args = vec![
            "--color=never",
            "--db",
            missing_db,
            "expand",
            fixture.source_str(),
            "--source",
            "local",
            "--message-id",
            message_id,
            "--expected-content-sha256",
            sha,
            "--context",
            context,
        ];
        args.extend_from_slice(extra);
        fixture.run(&args)
    };

    let ok_sha = sha_hex(BODIES[2]);
    for (label, message_id, context) in [
        ("id zero", "0", "3"),
        ("id negative", "-1", "3"),
        ("id above i64", "9223372036854775808", "3"),
        ("context above usize", "1", "18446744073709551616"),
        ("context negative", "1", "-1"),
    ] {
        let outcome = expand_with(message_id, &ok_sha, context, &json_flag);
        assert_error(&outcome, label, 2, "usage");
    }

    let short_digest = expand_with("1", "abc", "3", &json_flag);
    assert_error(&short_digest, "digest short", 2, "usage");

    let extra_digest = format!("{ok_sha}aa");
    let extra_digest = expand_with("1", &extra_digest, "3", &json_flag);
    assert_error(&extra_digest, "digest extra", 2, "usage");

    let non_hex = "z".repeat(64);
    let non_hex = expand_with("1", &non_hex, "3", &json_flag);
    assert_error(&non_hex, "digest non-hex", 2, "usage");

    // Missing dependency arguments and the line/message-id conflict are also
    // rejected as usage before any database read.
    let missing_sha = fixture.run(&[
        "--color=never",
        "--db",
        missing_db,
        "expand",
        fixture.source_str(),
        "--source",
        "local",
        "--message-id",
        "1",
        "--json",
    ]);
    assert_error(&missing_sha, "missing digest", 2, "usage");

    let missing_source = fixture.run(&[
        "--color=never",
        "--db",
        missing_db,
        "expand",
        fixture.source_str(),
        "--message-id",
        "1",
        "--expected-content-sha256",
        ok_sha.as_str(),
        "--json",
    ]);
    assert_error(&missing_source, "missing source", 2, "usage");

    let conflict = fixture.run(&[
        "--color=never",
        "--db",
        missing_db,
        "expand",
        fixture.source_str(),
        "--line",
        "1",
        "--message-id",
        "1",
        "--source",
        "local",
        "--expected-content-sha256",
        ok_sha.as_str(),
        "--json",
    ]);
    assert_error(&conflict, "line and message id", 2, "usage");

    let neither = fixture.run(&[
        "--color=never",
        "--db",
        missing_db,
        "expand",
        fixture.source_str(),
        "--json",
    ]);
    assert_error(&neither, "neither locator", 2, "usage");
}

#[test]
fn legacy_line_mode_with_max_context_no_longer_overflows() {
    let fixture = Fixture::new();
    let file = fixture.home.path().join("legacy-lines.jsonl");
    fs::write(
        &file,
        "{\"role\":\"user\",\"content\":\"legacy one\"}\n\
         {\"role\":\"assistant\",\"content\":\"legacy two\"}\n\
         {\"role\":\"user\",\"content\":\"legacy three\"}\n",
    )
    .expect("write legacy fixture");
    let file = file.to_str().expect("utf-8 path");
    let outcome = fixture.run(&[
        "--color=never",
        "--db",
        fixture.db_str(),
        "expand",
        file,
        "--line",
        "3",
        "--context",
        "18446744073709551615",
        "--json",
    ]);
    let parsed = assert_success(&outcome, "legacy max context");
    let messages = parsed.as_array().expect("array shape");
    assert_eq!(messages.len(), 3, "the whole session must be selected");
    assert_eq!(targets(messages).len(), 1);
    assert_eq!(targets(messages)[0]["line"], json!(3));
    assert_eq!(targets(messages)[0]["content"], "legacy three");
}

#[test]
fn recall_wraps_message_id_expand_exactly_once() {
    let fixture = Fixture::new();
    let outcome = fixture.expand_id(
        fixture.ids[2],
        &sha_hex(BODIES[2]),
        "local",
        fixture.source_str(),
        "0",
        &["--recall"],
    );
    assert_eq!(
        outcome.code,
        Some(0),
        "recall expand failed\nstdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );
    assert!(
        outcome.stdout.trim_start().starts_with("<cass_recall"),
        "recall output must start with one root element: {}",
        outcome.stdout
    );
    assert_eq!(
        outcome.stdout.matches("<cass_recall").count(),
        1,
        "exactly one recall wrapper: {}",
        outcome.stdout
    );
    let decoded = decode(outcome.stdout.trim(), RecallTool::Expand).expect("decode recall");
    let messages = decoded.as_array().expect("array shape");
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0]["content"], BODIES[2]);
    assert_eq!(targets(messages).len(), 1);
}
