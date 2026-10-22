//! Ticket 20: a successful recall must not hide a requested model path that
//! was never realized.
//!
//! Every case runs the real `cass` binary against a synthetic schema-9 archive
//! and a loopback HTTP fixture owned by this test. The fixture only counts
//! connections: each case here is refused (or degrades) before any model
//! request, so the expected count is zero. No production data, model service or
//! API configuration is touched.

use coding_agent_search::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
use coding_agent_search::recall_output::{RecallTool, decode};
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::{Value, json};
use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

const HIT_QUERY: &str = "t20needle";
const EMPTY_QUERY: &str = "t20absentliteralfixture";

/// A loopback listener that counts connections and never serves a usable reply.
///
/// Every assertion in this file expects zero connections; a non-zero count means
/// the command reached the model stage it should not have reached.
struct Loopback {
    port: u16,
    requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Loopback {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback fixture");
        let port = listener
            .local_addr()
            .expect("loopback fixture address")
            .port();
        listener
            .set_nonblocking(true)
            .expect("non-blocking loopback fixture");
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let counted = Arc::clone(&requests);
        let halted = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !halted.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        counted.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
                        let mut buffer = [0u8; 2048];
                        let _ = stream.read(&mut buffer);
                        let _ = stream.write_all(
                            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                    }
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            requests,
            stop,
            handle: Some(handle),
        }
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// A synthetic schema-9 archive plus an isolated home and a loopback model API
/// configuration. Every test owns its own directories.
struct Fixture {
    _root: tempfile::TempDir,
    home: PathBuf,
    data: PathBuf,
    db: PathBuf,
    api_config: PathBuf,
    loopback: Loopback,
}

impl Fixture {
    /// Five distinct matchable messages: enough for a two-wide rerank page to
    /// leave a real continuation cursor behind.
    fn standard() -> Self {
        Self::new(
            &[
                "t20needle alpha message body",
                "t20needle beta message body",
                "t20needle gamma message body",
                "t20needle delta message body",
                "t20needle epsilon message body",
            ],
            false,
        )
    }

    /// `excluded` marks every seeded message as recall-excluded. The lexical
    /// search does not itself filter those rows; only the recall identity
    /// projection does, which is how one fixture can exercise both failures.
    fn new(bodies: &[&str], excluded: bool) -> Self {
        let root = tempfile::tempdir().expect("temp root");
        let home = root.path().join("home");
        let data = root.path().join("data");
        let config_dir = root.path().join("config");
        for dir in [&home, &data, &config_dir] {
            std::fs::create_dir_all(dir).expect("create fixture directory");
        }
        let db = data.join("agent_search.db");
        let source = home.join("t20-session.jsonl");
        seed_archive(&db, &source, bodies, excluded);

        let loopback = Loopback::start();
        let api_config = config_dir.join("model-api.toml");
        std::fs::write(
            &api_config,
            format!(
                "version = 1\n\
                 default_embedding = \"fixture-embedding\"\n\
                 default_rerank = \"fixture-rerank\"\n\
                 [profiles.fixture-embedding]\n\
                 kind = \"embedding\"\n\
                 protocol = \"openai-embeddings-v1\"\n\
                 endpoint = \"http://127.0.0.1:{port}/embeddings\"\n\
                 scope = \"loopback\"\n\
                 model = \"fixture/embedding\"\n\
                 model_revision = \"fixture-1\"\n\
                 normalization = \"l2\"\n\
                 [profiles.fixture-rerank]\n\
                 kind = \"rerank\"\n\
                 protocol = \"rerank-json-v1\"\n\
                 endpoint = \"http://127.0.0.1:{port}/rerank\"\n\
                 scope = \"loopback\"\n\
                 model = \"fixture/rerank\"\n\
                 model_revision = \"fixture-1\"\n",
                port = loopback.port
            ),
        )
        .expect("write loopback model API configuration");

        Self {
            _root: root,
            home,
            data,
            db,
            api_config,
            loopback,
        }
    }

    /// Run with the loopback API configuration attached.
    fn run(&self, args: &[&str]) -> Output {
        let mut command = self.command();
        command.arg("--api-config").arg(&self.api_config);
        self.push_subcommand(&mut command, args);
        command.output().expect("run cass")
    }

    /// Run with no model configuration at all.
    fn run_without_api(&self, args: &[&str]) -> Output {
        let mut command = self.command();
        self.push_subcommand(&mut command, args);
        command.output().expect("run cass")
    }

    /// `--data-dir` belongs to the search subcommand, so it goes after it.
    fn push_subcommand(&self, command: &mut std::process::Command, args: &[&str]) {
        let (subcommand, rest) = args.split_first().expect("a subcommand is required");
        command
            .arg(subcommand)
            .arg("--data-dir")
            .arg(&self.data)
            .args(rest);
    }

    fn command(&self) -> std::process::Command {
        let mut command = std::process::Command::new(assert_cmd::cargo::cargo_bin!("cass"));
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", self.home.join("xdg-data"))
            .env("XDG_CONFIG_HOME", self.home.join("xdg-config"))
            .env("CASS_DATA_DIR", &self.data)
            .current_dir(&self.home)
            .arg("--db")
            .arg(&self.db);
        command
    }
}

fn seed_archive(db: &Path, source: &Path, bodies: &[&str], excluded: bool) {
    let storage = FrankenStorage::open(db).expect("open synthetic archive");
    let agent = storage
        .ensure_agent(&Agent {
            id: None,
            slug: "codex".into(),
            name: "Codex".into(),
            version: None,
            kind: AgentKind::Cli,
        })
        .expect("ensure agent");
    let workspace = storage
        .ensure_workspace(source.parent().expect("source parent"), None)
        .expect("ensure workspace");
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
            // The lexical search does not itself filter excluded rows; only the
            // recall identity projection does. An excluded row is therefore how
            // this fixture proves the model check runs before that projection.
            excluded: excluded.then(|| excluded_marker(idx)),
        })
        .collect();
    storage
        .insert_conversation_tree(
            agent,
            Some(workspace),
            &Conversation {
                id: None,
                agent_slug: "codex".into(),
                workspace: Some(source.parent().expect("source parent").into()),
                external_id: Some("t20-fixture".into()),
                title: Some("t20needle fixture".into()),
                source_path: source.to_path_buf(),
                started_at: Some(1_761_000_000_000),
                ended_at: Some(1_761_000_000_000),
                approx_tokens: None,
                metadata_json: json!({}),
                source_id: "local".into(),
                origin_host: None,
                messages,
            },
        )
        .expect("insert conversation tree");

    let conversations: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| {
            row.get_typed(0)
        })
        .expect("count conversations");
    let indexed: i64 = storage
        .raw()
        .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| {
            row.get_typed(0)
        })
        .expect("count messages");
    assert_eq!(conversations, 1, "fixture must store one conversation");
    assert_eq!(
        indexed,
        bodies.len() as i64,
        "fixture must store every message"
    );
    storage.close().expect("close synthetic archive");
}

/// The marker the recall exclusion path recognizes. The digests are real
/// digests of the empty body: the writer validates their shape even though the
/// identity projection only asks whether `messages.excluded` is non-null.
fn excluded_marker(idx: usize) -> coding_agent_search::indexer::exclusion::ExcludedMarker {
    use coding_agent_search::indexer::exclusion::{ExcludedMarker, ExclusionReason, RawRef};
    use sha2::{Digest, Sha256};
    ExcludedMarker {
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
    }
}

fn refused(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(9),
        "recall must exit 9; stderr: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "a refused recall must not publish a success wrapper; stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("\"kind\":\"model_unavailable\""),
        "refusal must carry model_unavailable; stderr: {stderr}"
    );
    stderr
}

fn json_success(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(0),
        "ordinary JSON must stay successful; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("ordinary JSON payload")
}

fn recall_success(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(0),
        "recall must stay successful; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout.clone()).expect("recall stdout is UTF-8");
    decode(&text, RecallTool::Search).expect("one valid cass_recall wrapper")
}

#[test]
fn hybrid_degradation_is_refused_on_positive_and_empty_hits() {
    let fixture = Fixture::standard();

    let positive_json = json_success(&fixture.run(&[
        "search",
        HIT_QUERY,
        "--mode",
        "hybrid",
        "--json",
        "--robot-meta",
    ]));
    assert_eq!(positive_json["count"], 5, "fixture must match every message");
    assert_eq!(positive_json["_meta"]["search_mode"], "lexical");
    assert_eq!(positive_json["_meta"]["requested_search_mode"], "hybrid");
    assert_eq!(positive_json["_meta"]["mode_defaulted"], false);
    assert_eq!(positive_json["_meta"]["fallback_tier"], "lexical");
    assert_eq!(positive_json["_meta"]["semantic_degraded"], false);

    let positive_recall = fixture.run(&["search", HIT_QUERY, "--mode", "hybrid", "--recall"]);
    refused(&positive_recall);

    let empty_json = json_success(&fixture.run(&[
        "search",
        EMPTY_QUERY,
        "--mode",
        "hybrid",
        "--json",
        "--robot-meta",
    ]));
    assert_eq!(empty_json["count"], 0);
    assert_eq!(empty_json["_meta"]["requested_search_mode"], "hybrid");
    assert_eq!(empty_json["_meta"]["fallback_tier"], "lexical");

    let empty_recall = fixture.run(&["search", EMPTY_QUERY, "--mode", "hybrid", "--recall"]);
    refused(&empty_recall);

    assert_eq!(
        fixture.loopback.requests(),
        0,
        "a known degradation must be refused before any model request"
    );
}

#[test]
fn unapplied_rerank_is_refused_on_first_page_and_cursor() {
    let fixture = Fixture::standard();
    let page = [
        "search",
        HIT_QUERY,
        "--mode",
        "lexical",
        "--rerank",
        "--rrf-limit",
        "200",
        "--rerank-limit",
        "2",
    ];

    let mut json_args: Vec<&str> = page.to_vec();
    json_args.push("--json");
    let first_json = json_success(&fixture.run(&json_args));
    assert_eq!(first_json["count"], 2);
    assert_eq!(first_json["rerank_requested"], true);
    assert_eq!(first_json["rerank_applied"], false);
    assert_eq!(
        first_json["_meta"]["rerank"]["failure_reason"],
        "input_identity_mismatch"
    );
    let cursor = first_json["_meta"]["next_cursor"]
        .as_str()
        .expect("two-wide page over five hits must leave a real continuation cursor")
        .to_string();

    let mut recall_args: Vec<&str> = page.to_vec();
    recall_args.push("--recall");
    refused(&fixture.run(&recall_args));

    let mut cursor_recall: Vec<&str> = recall_args.clone();
    cursor_recall.push("--cursor");
    cursor_recall.push(&cursor);
    refused(&fixture.run(&cursor_recall));

    let mut cursor_json: Vec<&str> = json_args.clone();
    cursor_json.push("--cursor");
    cursor_json.push(&cursor);
    let continued = json_success(&fixture.run(&cursor_json));
    assert_eq!(continued["rerank_requested"], true);
    assert_eq!(continued["rerank_applied"], false);
    assert_eq!(continued["count"], 2);

    assert_eq!(
        fixture.loopback.requests(),
        0,
        "neither page may send a rerank request"
    );
}

#[test]
fn legal_empty_result_with_requested_rerank_is_not_refused() {
    let fixture = Fixture::standard();
    let page = [
        "search",
        EMPTY_QUERY,
        "--mode",
        "lexical",
        "--rerank",
        "--rrf-limit",
        "200",
        "--rerank-limit",
        "2",
    ];

    let mut json_args: Vec<&str> = page.to_vec();
    json_args.push("--json");
    let empty_json = json_success(&fixture.run(&json_args));
    assert_eq!(empty_json["count"], 0);
    assert_eq!(empty_json["rerank_requested"], true);
    assert_eq!(empty_json["rerank_applied"], false);
    assert_eq!(empty_json["_meta"]["rerank"]["failure_reason"], Value::Null);

    let mut recall_args: Vec<&str> = page.to_vec();
    recall_args.push("--recall");
    let empty_recall = recall_success(&fixture.run(&recall_args));
    assert_eq!(
        empty_recall["hits"].as_array().expect("hits array").len(),
        0,
        "a legal empty result keeps its single empty-hits wrapper"
    );

    assert_eq!(
        fixture.loopback.requests(),
        0,
        "zero candidates must not trigger a rerank request"
    );
}

#[test]
fn explicit_lexical_needs_no_model_and_keeps_both_hit_shapes() {
    let fixture = Fixture::standard();

    let positive_json = json_success(&fixture.run_without_api(&[
        "search",
        HIT_QUERY,
        "--mode",
        "lexical",
        "--json",
    ]));
    assert_eq!(positive_json["count"], 5);
    let positive_recall = recall_success(&fixture.run_without_api(&[
        "search",
        HIT_QUERY,
        "--mode",
        "lexical",
        "--recall",
    ]));
    assert_eq!(positive_recall["hits"].as_array().expect("hits").len(), 5);

    let empty_json = json_success(&fixture.run_without_api(&[
        "search",
        EMPTY_QUERY,
        "--mode",
        "lexical",
        "--json",
    ]));
    assert_eq!(empty_json["count"], 0);
    let empty_recall = recall_success(&fixture.run_without_api(&[
        "search",
        EMPTY_QUERY,
        "--mode",
        "lexical",
        "--recall",
    ]));
    assert_eq!(empty_recall["hits"].as_array().expect("hits").len(), 0);

    assert_eq!(
        fixture.loopback.requests(),
        0,
        "explicit lexical search must not require a model"
    );
}

#[test]
fn defaulted_mode_degrades_without_refusal() {
    let fixture = Fixture::standard();

    let json = json_success(&fixture.run(&["search", HIT_QUERY, "--json", "--robot-meta"]));
    assert_eq!(json["_meta"]["mode_defaulted"], true);
    assert_eq!(json["_meta"]["requested_search_mode"], "hybrid");
    assert_eq!(json["_meta"]["search_mode"], "lexical");
    assert_eq!(json["_meta"]["fallback_tier"], "lexical");
    assert_eq!(json["count"], 5);

    let recalled = recall_success(&fixture.run(&["search", HIT_QUERY, "--recall"]));
    assert_eq!(recalled["_meta"]["mode_defaulted"], true);
    assert_eq!(recalled["hits"].as_array().expect("hits").len(), 5);

    assert_eq!(
        fixture.loopback.requests(),
        0,
        "the default-mode degradation happens before any model request"
    );
}

#[test]
fn unrelated_errors_keep_their_original_code_and_kind() {
    let fixture = Fixture::standard();

    let bad_time = fixture.run_without_api(&[
        "search",
        HIT_QUERY,
        "--mode",
        "lexical",
        "--since",
        "2026-13-45T99:99:99",
        "--json",
    ]);
    let bad_time_stderr = String::from_utf8_lossy(&bad_time.stderr);
    assert_eq!(
        bad_time.status.code(),
        Some(2),
        "unparseable explicit time stays usage; stderr: {bad_time_stderr}"
    );
    assert!(
        bad_time_stderr.contains("\"kind\":\"usage\""),
        "stderr: {bad_time_stderr}"
    );
    assert!(!bad_time_stderr.contains("model_unavailable"));

    let missing_config = fixture.run_without_api(&[
        "search",
        HIT_QUERY,
        "--mode",
        "hybrid",
        "--api-config",
        "/nonexistent/t20-missing-model-api.toml",
        "--json",
    ]);
    let missing_stderr = String::from_utf8_lossy(&missing_config.stderr);
    assert_eq!(
        missing_config.status.code(),
        Some(2),
        "a missing model API configuration keeps its configuration code; stderr: {missing_stderr}"
    );
    assert!(
        missing_stderr.contains("\"kind\":\"ModelApiConfiguration\""),
        "stderr: {missing_stderr}"
    );
    assert!(!missing_stderr.contains("model_unavailable"));
}

/// The real guard must run before the recall identity projection: this fixture
/// stores an excluded message (so the identity lookup refuses it) while an
/// explicit hybrid request still degrades. The model refusal must win.
#[test]
fn model_refusal_precedes_the_recall_identity_projection() {
    let fixture = Fixture::new(&["t20needle excluded message body"], true);

    let lexical = fixture.run(&["search", HIT_QUERY, "--mode", "lexical", "--recall"]);
    let lexical_stderr = String::from_utf8_lossy(&lexical.stderr);
    assert_eq!(
        lexical.status.code(),
        Some(9),
        "the fixture must make identity resolution fail; stderr: {lexical_stderr}"
    );
    assert!(
        lexical_stderr.contains("\"kind\":\"identity_unavailable\""),
        "stderr: {lexical_stderr}"
    );

    let hybrid = fixture.run(&["search", HIT_QUERY, "--mode", "hybrid", "--recall"]);
    let hybrid_stderr = refused(&hybrid);
    assert!(
        !hybrid_stderr.contains("identity_unavailable"),
        "the model refusal must not be masked by an identity error; stderr: {hybrid_stderr}"
    );
}
