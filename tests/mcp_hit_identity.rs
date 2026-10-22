use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::recall_output::{RecallTool, decode};
use coding_agent_search::search::query::{SearchHit, resolve_recall_hit_identities};
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

struct Fixture {
    home: tempfile::TempDir,
    db: PathBuf,
    source: PathBuf,
    ids: Vec<i64>,
}

impl Fixture {
    fn new(bodies: &[&str], excluded: bool) -> Self {
        let home = tempfile::tempdir().unwrap();
        let db = home.path().join("agent_search.db");
        let source = home.path().join("identity-session.jsonl");
        let storage = FrankenStorage::open(&db).unwrap();
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
        let messages = bodies
            .iter()
            .enumerate()
            .map(|(idx, body)| Message {
                id: None,
                idx: idx as i64,
                role: MessageRole::User,
                author: None,
                created_at: Some(1_761_000_000_000 + idx as i64),
                content: (*body).into(),
                extra_json: json!({}),
                snippets: vec![],
                excluded: if excluded {
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
                    external_id: Some("identity-fixture".into()),
                    title: Some("identityneedle".into()),
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
            .unwrap();
        let ids = storage
            .raw()
            .query_all_map("SELECT id FROM messages ORDER BY idx", &[], |row| {
                row.get_typed::<i64>(0)
            })
            .unwrap();
        assert_eq!(
            ids.len(),
            bodies.len(),
            "fixture must retain all distinct message events"
        );
        drop(storage);
        Self {
            home,
            db,
            source,
            ids,
        }
    }

    fn hit(&self, body: &str, id: Option<i64>) -> SearchHit {
        serde_json::from_value(json!({
            "title":"identityneedle", "snippet":body, "content":body, "score":1.0,
            "source_path":self.source, "agent":"codex", "workspace":self.home.path(),
            "created_at":null, "line_number":999, "source_id":"local", "message_id":id
        }))
        .unwrap()
    }

    fn cli(&self, recall: bool, max_content: Option<&str>) -> Value {
        self.cli_with_tokens(recall, max_content, None)
    }

    fn cli_with_tokens(
        &self,
        recall: bool,
        max_content: Option<&str>,
        max_tokens: Option<&str>,
    ) -> Value {
        let mut cmd = std::process::Command::new(assert_cmd::cargo::cargo_bin!("cass"));
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
            .arg("--db")
            .arg(&self.db)
            .args(["search", "identityneedle", "--mode", "lexical"])
            .arg(if recall { "--recall" } else { "--json" });
        if let Some(max) = max_content {
            cmd.args(["--max-content-length", max]);
        }
        if let Some(tokens) = max_tokens {
            cmd.args(["--max-tokens", tokens]);
        }
        let output = cmd.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        if recall {
            decode(
                std::str::from_utf8(&output.stdout).unwrap(),
                RecallTool::Search,
            )
            .unwrap()
        } else {
            serde_json::from_slice(&output.stdout).unwrap()
        }
    }
}

#[test]
fn real_recall_hashes_full_utf8_before_display_cropping() {
    let body = format!(
        "  identityneedle e\u{301} & </cass_recall> 中文\n{}  ",
        "long body ".repeat(60)
    );
    let fixture = Fixture::new(&[&body], false);
    let full = fixture.cli(true, None);
    let cropped = fixture.cli(true, Some("8"));
    let normal = fixture.cli(false, None);
    let expected = hex::encode(Sha256::digest(body.as_bytes()));
    for output in [&full, &cropped] {
        let hit = &output["hits"][0];
        assert_eq!(hit["message_id"], fixture.ids[0]);
        assert_eq!(hit["source_id"], "local");
        assert_eq!(hit["source_path"], fixture.source.to_str().unwrap());
        assert_eq!(hit["line_number"], 1);
        assert_eq!(hit["content_sha256"], expected);
        assert_eq!(hit["content_sha256"].as_str().unwrap().len(), 64);
    }
    assert!(cropped["hits"][0]["content"].as_str().unwrap().len() < body.len());
    assert!(normal["hits"][0].get("content_sha256").is_none());
    assert_eq!(normal["hits"][0]["content"], body);
}

#[test]
fn missing_id_requires_unique_complete_body_and_never_guesses_the_line() {
    let fixture = Fixture::new(&["unique identityneedle"], false);
    let hit = fixture.hit("unique identityneedle", None);
    let identity = resolve_recall_hit_identities(&fixture.db, &[hit]).unwrap();
    assert_eq!(identity[0].message_id, fixture.ids[0]);
    assert_eq!(identity[0].line_number, 1);
    assert_eq!(
        identity[0].content_sha256,
        hex::encode(Sha256::digest(b"unique identityneedle"))
    );

    let duplicate = Fixture::new(&["same identityneedle", "same identityneedle"], false);
    let mut hit = duplicate.hit("same identityneedle", None);
    hit.line_number = Some(1);
    let error: coding_agent_search::CliError = resolve_recall_hit_identities(&duplicate.db, &[hit])
        .unwrap_err()
        .into();
    assert_eq!(error.code, 9);
    assert_eq!(error.kind, "identity_unavailable");
    // A genuine ID resolves the second row even when the display line is wrong.
    let hit = duplicate.hit("same identityneedle", Some(duplicate.ids[1]));
    let identity = resolve_recall_hit_identities(&duplicate.db, &[hit]).unwrap();
    assert_eq!(identity[0].message_id, duplicate.ids[1]);
    assert_eq!(identity[0].line_number, 2);
}

#[test]
fn stale_body_source_path_and_unknown_ids_are_rejected() {
    let fixture = Fixture::new(&["identityneedle original"], false);
    let mut hits = vec![fixture.hit("identityneedle changed", Some(fixture.ids[0]))];
    hits.push(fixture.hit("identityneedle original", Some(i64::MAX)));
    let mut wrong_source = fixture.hit("identityneedle original", Some(fixture.ids[0]));
    wrong_source.source_id = "another-source".into();
    hits.push(wrong_source);
    let mut wrong_path = fixture.hit("identityneedle original", Some(fixture.ids[0]));
    wrong_path.source_path = "another-session.jsonl".into();
    hits.push(wrong_path);
    for hit in hits {
        let error: coding_agent_search::CliError =
            resolve_recall_hit_identities(&fixture.db, &[hit])
                .unwrap_err()
                .into();
        assert_eq!((error.code, error.kind), (9, "identity_unavailable"));
    }
}

#[test]
fn excluded_messages_are_not_valid_recall_identities() {
    let fixture = Fixture::new(&[""], true);
    let hit = fixture.hit("", Some(fixture.ids[0]));
    let error: coding_agent_search::CliError = resolve_recall_hit_identities(&fixture.db, &[hit])
        .unwrap_err()
        .into();
    assert_eq!((error.code, error.kind), (9, "identity_unavailable"));
}

#[test]
fn token_budget_clamps_a_prefix_without_losing_message_identity() {
    let first = "identityneedle first message body with extra words";
    let second = "identityneedle second message body with extra words";
    let fixture = Fixture::new(&[first, second], false);
    let full = fixture.cli(true, None);
    assert_eq!(full["hits"].as_array().unwrap().len(), 2);
    let small = fixture.cli_with_tokens(true, None, Some("1"));
    let hits = small["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0]["message_id"], full["hits"][0]["message_id"]);
    assert_eq!(hits[0]["content_sha256"], full["hits"][0]["content_sha256"]);
    assert_eq!(small["_meta"]["hits_clamped"], true);
}
