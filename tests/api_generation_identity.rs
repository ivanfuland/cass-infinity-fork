//! API02C: the real-SQLite contract of the pure-primary API generation record.
//!
//! Every test here runs against a real database built by the production schema
//! entry point (`FrankenStorage::open`), writes through a real caller
//! transaction, and re-reads through the same store. Nothing stubs the store,
//! the transaction or the codec: the seams the ticket asks for are "real
//! database row and meta records", "real rollback" and "a real second process".
//!
//! The corpus is synthetic and public: a fixed synthetic model id, a fixed
//! synthetic revision and endpoints that are never contacted. No private
//! corpus, no real credential and no real endpoint is involved.

use std::path::{Path, PathBuf};

use coding_agent_search::search::model_api::{
    ApiConfig, EndpointConfigIdentity, RepresentationRecord, ValidatedProfile,
};
use coding_agent_search::storage::api::{Conn, StorageError, Tx, TxMode, Value};
use coding_agent_search::storage::api_generation::{
    ApiGenerationError, ApiGenerationErrorCode, ApiGenerationProvenance,
    VerifiedPrimaryGeneration, create_api_generation, open_api_generation, provenance_meta_key,
    representation_meta_key,
};
use coding_agent_search::storage::schema;
use coding_agent_search::storage::sqlite::FrankenStorage;
use serde_json::json;

const EMBED_MODEL: &str = "example/synthetic-embed";
const EMBED_REVISION: &str = "rev-synthetic-1";
const ENDPOINT_A: &str = "http://127.0.0.1:9100/v1/embeddings";
const ENDPOINT_B: &str = "http://127.0.0.1:9200/v1/embeddings";
const HTTPS_LOOPBACK_ENDPOINT: &str = "https://127.0.0.1:9300/v1/embeddings";
const CLOUD_ENDPOINT: &str = "https://cloud.example.invalid/v1/embeddings";

/// A synthetic secret. It must never reach a stored record or a rendered
/// rejection.
const SYNTHETIC_SECRET: &str = "SYNTHETIC_SECRET_9f3a1c7d";
const CREDENTIAL_ENV: &str = "API02C_SYNTHETIC_TOKEN";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn scratch() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create scratch dir");
    let path = dir.path().join("agent_search.db");
    (dir, path)
}

/// One profile block, at the given protocol and scope.
///
/// `extra` supplies every optional field, `normalization` included, so no line
/// is ever written twice and TOML's own duplicate-key refusal never fires by
/// accident.
fn profile_toml(
    id: &str,
    protocol: &str,
    endpoint: &str,
    scope: &str,
    model: &str,
    revision: &str,
    extra: &[&str],
) -> String {
    let mut text = format!(
        "version = 1\n\
         [profiles.{id}]\n\
         kind = \"embedding\"\n\
         protocol = \"{protocol}\"\n\
         endpoint = \"{endpoint}\"\n\
         scope = \"{scope}\"\n\
         model = \"{model}\"\n\
         model_revision = \"{revision}\"\n"
    );
    for line in extra {
        text.push_str(line);
        text.push('\n');
    }
    text
}

/// A loopback OpenAI-embeddings profile document, normalized with L2.
fn embedding_toml(id: &str, endpoint: &str, model: &str, revision: &str, extra: &[&str]) -> String {
    let mut lines: Vec<&str> = vec![r#"normalization = "l2""#];
    lines.extend_from_slice(extra);
    profile_toml(
        id,
        "openai-embeddings-v1",
        endpoint,
        "loopback",
        model,
        revision,
        &lines,
    )
}

fn parse_profile(id: &str, text: &str) -> ValidatedProfile {
    let config = ApiConfig::parse_toml(text).expect("parse the api configuration");
    config.profile(id).expect("the profile is present").clone()
}

fn profile_for(
    id: &str,
    endpoint: &str,
    model: &str,
    revision: &str,
    extra: &[&str],
) -> ValidatedProfile {
    parse_profile(id, &embedding_toml(id, endpoint, model, revision, extra))
}

/// One real store on a fresh scratch database.
struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    storage: FrankenStorage,
}

impl Fixture {
    fn new() -> Fixture {
        let (dir, path) = scratch();
        let storage = FrankenStorage::open(&path).expect("open the production storage");
        Fixture {
            _dir: dir,
            path,
            storage,
        }
    }

    fn conn(&self) -> &Conn {
        self.storage.raw()
    }

    /// Create one generation inside a real caller transaction.
    fn create(&self, profile: &ValidatedProfile, dim: u64, fingerprint: &[u8]) -> i64 {
        self.conn()
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                create_api_generation(tx, profile, dim, fingerprint, 1_000)
                    .map_err(|error| StorageError::from(error))
            })
            .expect("create the api generation")
    }

    fn open(
        &self,
        generation_id: i64,
        profile: &ValidatedProfile,
    ) -> Result<VerifiedPrimaryGeneration, ApiGenerationError> {
        let conn = self.conn();
        let tx = conn.transaction().expect("open a read transaction");
        open_api_generation(&tx, generation_id, profile)
    }

    fn reopen_error(&self, generation_id: i64, profile: &ValidatedProfile) -> ApiGenerationError {
        self.open(generation_id, profile)
            .expect_err("reopening this generation must fail")
    }
}

fn count(conn: &Conn, table: &str) -> i64 {
    conn.query_row_map(&format!("SELECT COUNT(*) FROM {table}"), &[], |row| {
        row.get_typed::<i64>(0)
    })
    .expect("count rows")
}

fn count_in(tx: &Tx, table: &str) -> i64 {
    tx.query_row_map(&format!("SELECT COUNT(*) FROM {table}"), &[], |row| {
        row.get_typed::<i64>(0)
    })
    .expect("count rows in the transaction")
}

fn meta_value(conn: &Conn, key: &str) -> Option<String> {
    conn.query_opt_map(
        "SELECT value FROM meta WHERE key = ?1",
        &[Value::Text(key.to_string())],
        |row| row.get_typed::<String>(0),
    )
    .expect("read a meta value")
}

fn set_meta(conn: &Conn, key: &str, value: &str) {
    let changed = conn
        .execute(
            "UPDATE meta SET value = ?1 WHERE key = ?2",
            &[Value::Text(value.to_string()), Value::Text(key.to_string())],
        )
        .expect("update a meta value");
    assert_eq!(changed, 1, "the meta key {key} must exist");
}

fn delete_meta(conn: &Conn, key: &str) {
    let changed = conn
        .execute(
            "DELETE FROM meta WHERE key = ?1",
            &[Value::Text(key.to_string())],
        )
        .expect("delete a meta value");
    assert_eq!(changed, 1, "the meta key {key} must exist");
}

/// A hand edit of one top-level provenance key.
fn tamper_top(text: &str, key: &str, new: serde_json::Value) -> String {
    let mut value: serde_json::Value = serde_json::from_str(text).expect("parse the provenance");
    value[key] = new;
    serde_json::to_string(&value).expect("serialize the provenance")
}

/// A hand edit of one key inside the first contributor.
fn tamper_first_contributor(text: &str, key: &str, new: serde_json::Value) -> String {
    let mut value: serde_json::Value = serde_json::from_str(text).expect("parse the provenance");
    value["contributors"][0][key] = new;
    serde_json::to_string(&value).expect("serialize the provenance")
}

/// Replace the contributor's explicit null header with raw JSON text.
///
/// The text is spliced in without parsing, so a header whose numbers no `f64`
/// can hold — `1e400`, a 400-digit integer — is exercised exactly as bytes.
fn replace_header(provenance: &str, header_json: &str) -> String {
    let replaced = provenance.replace(
        "\"compatibility_evidence_header\":null",
        &format!("\"compatibility_evidence_header\":{header_json}"),
    );
    assert_ne!(replaced, provenance, "the null header must be present");
    replaced
}

/// Assert that neither rendering of `error` carries `needle`.
fn assert_renders_without(error: &ApiGenerationError, needle: &str, label: &str) {
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(
            !rendered.contains(needle),
            "{label} leaked the secret through: {rendered}"
        );
    }
}

// ---------------------------------------------------------------------------
// The child process: a second process opening the same database
// ---------------------------------------------------------------------------

const CHILD_ENV_DB: &str = "API02C_CHILD_DB";
const CHILD_ENV_PROFILE_ID: &str = "API02C_CHILD_PROFILE_ID";
const CHILD_ENV_PROFILE_TOML: &str = "API02C_CHILD_PROFILE_TOML";
const CHILD_ENV_GENERATION: &str = "API02C_CHILD_GENERATION";
const CHILD_SENTINEL: &str = "API02C_CHILD_RESULT ";

/// The child entry. It is a no-op when the parent did not hand it a database, so
/// running it on its own claims nothing.
///
/// The credential variable is present in this child's environment (the parent
/// sets it on the command), which is what makes a successful run evidence that
/// no credential *value* is read.
#[test]
#[ignore]
fn api02c_child_reopen_helper() {
    let (Ok(db), Ok(id), Ok(toml)) = (
        std::env::var(CHILD_ENV_DB),
        std::env::var(CHILD_ENV_PROFILE_ID),
        std::env::var(CHILD_ENV_PROFILE_TOML),
    ) else {
        return;
    };
    let generation_id: i64 = std::env::var(CHILD_ENV_GENERATION)
        .expect("the child generation id")
        .parse()
        .expect("a numeric child generation id");
    let profile = parse_profile(&id, &toml);

    let storage = FrankenStorage::open(Path::new(&db)).expect("the child opens the same database");
    let summary = {
        let conn = storage.raw();
        let tx = conn.transaction().expect("the child opens a read transaction");
        let verified = open_api_generation(&tx, generation_id, &profile)
            .expect("the child must reopen the committed generation");
        format!(
            "{{\"generation_id\":{},\"descriptor_sha256\":\"{}\"}}",
            verified.generation_id(),
            verified.descriptor_sha256()
        )
    };
    storage.close().expect("the child closes the storage");
    println!("{CHILD_SENTINEL}{summary}");
}

/// Run the child entry against `path` and return its decoded summary line.
fn run_child(path: &Path, profile_id: &str, toml: &str, generation_id: i64) -> serde_json::Value {
    let output = std::process::Command::new(std::env::current_exe().expect("the test executable"))
        .args([
            "--exact",
            "api02c_child_reopen_helper",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV_DB, path)
        .env(CHILD_ENV_PROFILE_ID, profile_id)
        .env(CHILD_ENV_PROFILE_TOML, toml)
        .env(CHILD_ENV_GENERATION, generation_id.to_string())
        .env(CREDENTIAL_ENV, SYNTHETIC_SECRET)
        .output()
        .expect("spawn the child reopen helper");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let line = stdout
        .lines()
        .find_map(|line| {
            line.split_once(CHILD_SENTINEL)
                .map(|(_, json)| json.to_string())
        })
        .unwrap_or_else(|| {
            panic!(
                "the child printed no {CHILD_SENTINEL} line (status {:?})\n\
                 --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}",
                output.status
            )
        });
    serde_json::from_str(&line).expect("the child summary is JSON")
}

// ---------------------------------------------------------------------------
// Acceptance 1: create, read back in one transaction, reopen in a new process
// ---------------------------------------------------------------------------

#[test]
fn a_generation_is_created_and_read_back_as_one_space() {
    let fixture = Fixture::new();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);

    let generation_id = {
        let conn = fixture.conn();
        let tx = conn.transaction().expect("open the caller transaction");

        let generation_id = create_api_generation(&tx, &profile, 1024, b"fingerprint-one", 1_000)
            .expect("create the generation");

        // The row, the representation record and the provenance record agree.
        let (embedder_id, dim) = tx
            .query_row_map(
                "SELECT embedder_id, dim FROM embedding_generations WHERE id = ?1",
                &[Value::Integer(generation_id)],
                |row| Ok((row.get_typed::<String>(0)?, row.get_typed::<i64>(1)?)),
            )
            .expect("read the generation row");
        assert_eq!(dim, 1024);
        assert!(embedder_id.starts_with("api:"), "got {embedder_id}");

        let representation = tx
            .query_opt_map(
                "SELECT value FROM meta WHERE key = ?1",
                &[Value::Text(representation_meta_key(generation_id))],
                |row| row.get_typed::<String>(0),
            )
            .expect("read the representation record")
            .expect("the representation record is present");
        let record = RepresentationRecord::decode(representation.as_bytes())
            .expect("the representation record decodes");
        assert_eq!(record.generation_id(), generation_id);
        assert_eq!(record.embedder_id(), embedder_id);
        assert_eq!(record.descriptor().effective_dimension(), 1024);

        let provenance_text = tx
            .query_opt_map(
                "SELECT value FROM meta WHERE key = ?1",
                &[Value::Text(provenance_meta_key(generation_id))],
                |row| row.get_typed::<String>(0),
            )
            .expect("read the provenance record")
            .expect("the provenance record is present");
        let provenance = ApiGenerationProvenance::decode(provenance_text.as_bytes())
            .expect("the provenance record decodes");
        assert_eq!(provenance.generation_id(), generation_id);
        assert_eq!(provenance.descriptor_sha256(), record.descriptor_sha256());
        assert_eq!(provenance.contributors().len(), 1);
        let contributor = &provenance.contributors()[0];
        assert_eq!(contributor.model(), EMBED_MODEL);
        assert_eq!(contributor.model_revision(), EMBED_REVISION);
        assert!(!contributor.has_compatibility_evidence_header());
        assert!(contributor.compatibility_evidence_sha256().is_none());
        assert!(contributor.provider_only().is_none());

        // The reopen helper agrees, from inside the very same transaction.
        let verified = open_api_generation(&tx, generation_id, &profile)
            .expect("the generation verifies in the writing transaction");
        assert_eq!(verified.generation_id(), generation_id);
        assert_eq!(verified.descriptor_sha256(), record.descriptor_sha256());
        assert_eq!(verified.primary_contributor().expect("pure primary").model(), EMBED_MODEL);

        tx.commit().expect("commit the caller transaction");
        generation_id
    };

    let toml = embedding_toml("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    fixture.storage.close().expect("close the parent storage");

    let summary = run_child(&fixture.path, "p1", &toml, generation_id);
    assert_eq!(summary["generation_id"].as_i64(), Some(generation_id));
    assert_eq!(
        summary["descriptor_sha256"].as_str().map(str::len),
        Some(64),
        "the child must report a real descriptor digest: {summary}"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 2: no half generation survives any injected failure
// ---------------------------------------------------------------------------

#[test]
fn a_failed_create_never_commits_half_a_generation() {
    let fixture = Fixture::new();
    let conn = fixture.conn();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);

    // An older, active generation that every failure must leave untouched.
    let legacy_id = conn
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::create_embedding_generation(
                tx,
                "legacy-embedder",
                1024,
                3,
                1,
                b"legacy-fingerprint",
                1,
            )
        })
        .expect("create the legacy generation");
    conn.execute(
        "UPDATE embedding_generations SET is_active = 1, activated_at = 2 WHERE id = ?1",
        &[Value::Integer(legacy_id)],
    )
    .expect("activate the legacy generation");
    let legacy_fingerprint: Vec<u8> = conn
        .query_row_map(
            "SELECT fingerprint FROM embedding_generations WHERE id = ?1",
            &[Value::Integer(legacy_id)],
            |row| row.get_typed::<Vec<u8>>(0),
        )
        .expect("read the legacy fingerprint");

    let generations_before = count(conn, "embedding_generations");
    let metas_before = count(conn, "meta");
    assert_eq!(generations_before, 1);

    // (a) the representation record write fails, so no meta lands at all;
    // (b) the provenance record write fails, so only the first meta lands.
    for (pattern, expected_new_metas) in [
        ("api_representation:%", 0_i64),
        ("api_generation_provenance:%", 1_i64),
    ] {
        conn.execute_batch(&format!(
            "CREATE TRIGGER api02c_block BEFORE INSERT ON meta \
             WHEN NEW.key LIKE '{pattern}' \
             BEGIN SELECT RAISE(ABORT, 'api02c injected meta failure'); END;"
        ))
        .expect("install the blocking trigger");

        let tx = conn.transaction().expect("open the caller transaction");
        let error = create_api_generation(&tx, &profile, 1024, b"fp-injected", 5)
            .expect_err("the injected failure must abort the create");
        assert_eq!(
            error.code(),
            ApiGenerationErrorCode::Storage,
            "a store failure must stay a store failure for {pattern}"
        );
        // The helper's writes are visible *inside* this transaction and only
        // there: the transaction is still the caller's to roll back.
        assert_eq!(
            count_in(&tx, "embedding_generations"),
            generations_before + 1
        );
        assert_eq!(count_in(&tx, "meta"), metas_before + expected_new_metas);
        drop(tx); // rolls back

        conn.execute_batch("DROP TRIGGER api02c_block;")
            .expect("drop the blocking trigger");
        assert_eq!(
            count(conn, "embedding_generations"),
            generations_before,
            "no generation may survive the rollback for {pattern}"
        );
        assert_eq!(
            count(conn, "meta"),
            metas_before,
            "no meta record may survive the rollback for {pattern}"
        );
    }

    // (c) the caller's own next step fails after a successful create.
    {
        let tx = conn.transaction().expect("open the caller transaction");
        create_api_generation(&tx, &profile, 1024, b"fp-caller", 7)
            .expect("the create itself succeeds");
        // The schema refuses a second instance id, so the caller's own next
        // statement fails and the caller rolls the transaction back.
        tx.execute(
            "INSERT INTO meta(key, value) VALUES ('vector_domain_instance_id', 'replacement')",
            &[],
        )
        .expect_err("the schema guard must refuse a second instance id");
        drop(tx); // rolls back
        assert_eq!(
            count(conn, "embedding_generations"),
            generations_before,
            "an internally committed generation would have survived the caller's rollback"
        );
        assert_eq!(count(conn, "meta"), metas_before);
    }

    // The older active generation is exactly as it was.
    let active: Option<i64> = conn
        .query_opt_map(
            "SELECT id FROM embedding_generations WHERE is_active = 1",
            &[],
            |row| row.get_typed(0),
        )
        .expect("read the active generation");
    assert_eq!(active, Some(legacy_id));
    let fingerprint_after: Vec<u8> = conn
        .query_row_map(
            "SELECT fingerprint FROM embedding_generations WHERE id = ?1",
            &[Value::Integer(legacy_id)],
            |row| row.get_typed::<Vec<u8>>(0),
        )
        .expect("read the legacy fingerprint again");
    assert_eq!(fingerprint_after, legacy_fingerprint);
}

// ---------------------------------------------------------------------------
// Acceptance 3: a tampered record never reopens
// ---------------------------------------------------------------------------

#[test]
fn a_tampered_record_never_reopens() {
    let fixture = Fixture::new();
    let conn = fixture.conn();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);

    // Control: the untouched generation verifies.
    let good = fixture.create(&profile, 1024, b"fp-good");
    assert!(fixture.open(good, &profile).is_ok());

    // The representation record is missing.
    let missing_representation = fixture.create(&profile, 1024, b"fp-missing-representation");
    delete_meta(conn, &representation_meta_key(missing_representation));
    assert_eq!(
        fixture
            .reopen_error(missing_representation, &profile)
            .code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // The provenance record is missing.
    let missing_provenance = fixture.create(&profile, 1024, b"fp-missing-provenance");
    delete_meta(conn, &provenance_meta_key(missing_provenance));
    assert_eq!(
        fixture.reopen_error(missing_provenance, &profile).code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // The representation record's own digest no longer matches its descriptor.
    let bad_digest = fixture.create(&profile, 1024, b"fp-bad-digest");
    let representation =
        meta_value(conn, &representation_meta_key(bad_digest)).expect("a record");
    let record = RepresentationRecord::decode(representation.as_bytes())
        .expect("the record decodes before tampering");
    let tampered = representation.replace(record.descriptor_sha256(), &"ab".repeat(32));
    assert_ne!(tampered, representation);
    set_meta(conn, &representation_meta_key(bad_digest), &tampered);
    assert_eq!(
        fixture.reopen_error(bad_digest, &profile).code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // The provenance names a different generation.
    let bad_generation = fixture.create(&profile, 1024, b"fp-bad-generation");
    let provenance = meta_value(conn, &provenance_meta_key(bad_generation)).expect("provenance");
    set_meta(
        conn,
        &provenance_meta_key(bad_generation),
        &tamper_top(&provenance, "generation_id", json!(bad_generation + 1)),
    );
    assert_eq!(
        fixture.reopen_error(bad_generation, &profile).code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // The provenance names a different descriptor digest.
    let bad_cross = fixture.create(&profile, 1024, b"fp-bad-cross");
    let provenance = meta_value(conn, &provenance_meta_key(bad_cross)).expect("provenance");
    set_meta(
        conn,
        &provenance_meta_key(bad_cross),
        &tamper_top(&provenance, "descriptor_sha256", json!("cd".repeat(32))),
    );
    assert_eq!(
        fixture.reopen_error(bad_cross, &profile).code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // A row's embedder id disagrees with its own record.
    let bad_embedder = fixture.create(&profile, 1024, b"fp-bad-embedder");
    conn.execute(
        "UPDATE embedding_generations SET embedder_id = ?1 WHERE id = ?2",
        &[
            Value::Text(format!("api:{}", "0".repeat(64))),
            Value::Integer(bad_embedder),
        ],
    )
    .expect("tamper the embedder id");
    assert_eq!(
        fixture.reopen_error(bad_embedder, &profile).code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // A row's pipeline version disagrees with its own record.
    let bad_version = fixture.create(&profile, 1024, b"fp-bad-version");
    conn.execute(
        "UPDATE embedding_generations SET canonicalize_version = canonicalize_version + 1 \
         WHERE id = ?1",
        &[Value::Integer(bad_version)],
    )
    .expect("tamper the pipeline version");
    assert_eq!(
        fixture.reopen_error(bad_version, &profile).code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // A row's dimension disagrees with its own record.
    let bad_dim = fixture.create(&profile, 1024, b"fp-bad-dim");
    conn.execute(
        "UPDATE embedding_generations SET dim = 768 WHERE id = ?1",
        &[Value::Integer(bad_dim)],
    )
    .expect("tamper the dimension");
    assert_eq!(
        fixture.reopen_error(bad_dim, &profile).code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // A source field inside the provenance disagrees with the descriptor.
    let bad_source = fixture.create(&profile, 1024, b"fp-bad-source");
    let provenance = meta_value(conn, &provenance_meta_key(bad_source)).expect("provenance");
    set_meta(
        conn,
        &provenance_meta_key(bad_source),
        &tamper_first_contributor(&provenance, "model", json!("example/other-model")),
    );
    assert_eq!(
        fixture.reopen_error(bad_source, &profile).code(),
        ApiGenerationErrorCode::InvalidRecord
    );

    // The control is still the only one that reopens.
    assert!(fixture.open(good, &profile).is_ok());
}

/// Two records rebuilt to be self-consistent, yet describing a space the running
/// profile does not: the refusal is a classification, not a repair.
#[test]
fn a_self_consistent_record_for_another_space_is_an_identity_mismatch() {
    let fixture = Fixture::new();
    let original = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let other = profile_for("p1", ENDPOINT_A, "example/other-model", EMBED_REVISION, &[]);

    let generation_id = fixture.create(&original, 1024, b"fp-other-space");
    assert!(fixture.open(generation_id, &original).is_ok());
    assert_eq!(
        fixture.reopen_error(generation_id, &other).code(),
        ApiGenerationErrorCode::IdentityMismatch
    );
    // Refusing it changed nothing on disk.
    assert!(fixture.open(generation_id, &original).is_ok());
}

// ---------------------------------------------------------------------------
// T01-A1: call settings are recorded, not admitted
// ---------------------------------------------------------------------------

/// A generation created with one set of call settings opens unchanged under
/// another: only the declared vector space and the pinned provider decide
/// admission.
///
/// Every case is a real `ApiConfig` profile whose call-configuration digest
/// differs from the base profile's. The stored representation and provenance
/// records must stay byte-for-byte identical across every case.
#[test]
fn call_settings_can_change_without_rewriting_generation_identity() {
    let fixture = Fixture::new();
    let conn = fixture.conn();
    let base = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let generation_id = fixture.create(&base, 1024, b"fp-call-settings");
    assert!(fixture.open(generation_id, &base).is_ok());

    let before_representation = meta_value(conn, &representation_meta_key(generation_id));
    let before_provenance = meta_value(conn, &provenance_meta_key(generation_id));
    assert!(before_representation.is_some(), "the record must exist");
    assert!(before_provenance.is_some(), "the record must exist");
    let before_descriptor_sha256 = RepresentationRecord::decode(
        before_representation
            .as_ref()
            .expect("the record must exist")
            .as_bytes(),
    )
    .expect("the representation record decodes")
    .descriptor_sha256()
    .to_string();

    let base_call_digest = EndpointConfigIdentity::from_profile(&base)
        .expect("the base profile has a call identity")
        .sha256();

    let credential_env = format!("api_key_env = \"{CREDENTIAL_ENV}\"");
    let aliases = r#"response_model_aliases = ["alias-a", "alias-b"]"#;
    let cases: Vec<(&str, ValidatedProfile)> = vec![
        (
            "endpoint",
            profile_for("p1", ENDPOINT_B, EMBED_MODEL, EMBED_REVISION, &[]),
        ),
        (
            "timeout_ms",
            profile_for(
                "p1",
                ENDPOINT_A,
                EMBED_MODEL,
                EMBED_REVISION,
                &["timeout_ms = 125000"],
            ),
        ),
        (
            "connect_timeout_ms",
            profile_for(
                "p1",
                ENDPOINT_A,
                EMBED_MODEL,
                EMBED_REVISION,
                &["connect_timeout_ms = 30000"],
            ),
        ),
        (
            "api_key_env",
            profile_for(
                "p1",
                ENDPOINT_A,
                EMBED_MODEL,
                EMBED_REVISION,
                &[credential_env.as_str()],
            ),
        ),
        (
            "max_response_bytes",
            profile_for(
                "p1",
                ENDPOINT_A,
                EMBED_MODEL,
                EMBED_REVISION,
                &["max_response_bytes = 1048576"],
            ),
        ),
        (
            "models_endpoint",
            profile_for(
                "p1",
                ENDPOINT_A,
                EMBED_MODEL,
                EMBED_REVISION,
                &[r#"models_endpoint = "http://127.0.0.1:9100/v1/models""#],
            ),
        ),
        (
            "send_model",
            profile_for(
                "p1",
                ENDPOINT_A,
                EMBED_MODEL,
                EMBED_REVISION,
                &["send_model = false"],
            ),
        ),
        (
            "response_model_aliases",
            profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[aliases]),
        ),
        (
            "all of the above together",
            profile_for(
                "p1",
                ENDPOINT_B,
                EMBED_MODEL,
                EMBED_REVISION,
                &[
                    "timeout_ms = 125000",
                    "connect_timeout_ms = 30000",
                    credential_env.as_str(),
                    "max_response_bytes = 1048576",
                    r#"models_endpoint = "http://127.0.0.1:9200/v1/models""#,
                    "send_model = false",
                    aliases,
                ],
            ),
        ),
    ];

    for (label, profile) in &cases {
        let changed = EndpointConfigIdentity::from_profile(profile)
            .expect("the changed profile has a call identity")
            .sha256();
        assert_ne!(
            changed, base_call_digest,
            "{label} must really move the call configuration"
        );

        let verified = fixture
            .open(generation_id, profile)
            .unwrap_or_else(|error| panic!("{label} must still open the generation: {error}"));
        assert_eq!(verified.generation_id(), generation_id, "{label}");
        assert_eq!(
            verified.descriptor_sha256(),
            before_descriptor_sha256.as_str(),
            "{label} must not change the descriptor digest"
        );
        assert_eq!(
            meta_value(conn, &representation_meta_key(generation_id)),
            before_representation,
            "{label} must not rewrite the representation record"
        );
        assert_eq!(
            meta_value(conn, &provenance_meta_key(generation_id)),
            before_provenance,
            "{label} must not rewrite the provenance record"
        );
    }

    // Scope is a call setting too. Give it its own record on an HTTPS endpoint
    // so the only difference between the two profiles is `scope` itself.
    let https_loopback = parse_profile(
        "p1",
        &profile_toml(
            "p1",
            "openai-embeddings-v1",
            HTTPS_LOOPBACK_ENDPOINT,
            "loopback",
            EMBED_MODEL,
            EMBED_REVISION,
            &[r#"normalization = "l2""#],
        ),
    );
    let scope_generation = fixture.create(&https_loopback, 1024, b"fp-scope");
    let scope_before_representation = meta_value(conn, &representation_meta_key(scope_generation));
    let scope_before_provenance = meta_value(conn, &provenance_meta_key(scope_generation));
    let remote_scope = parse_profile(
        "p1",
        &profile_toml(
            "p1",
            "openai-embeddings-v1",
            HTTPS_LOOPBACK_ENDPOINT,
            "remote",
            EMBED_MODEL,
            EMBED_REVISION,
            &[r#"normalization = "l2""#],
        ),
    );
    assert_ne!(
        EndpointConfigIdentity::from_profile(&remote_scope)
            .expect("the remote profile has a call identity")
            .sha256(),
        EndpointConfigIdentity::from_profile(&https_loopback)
            .expect("the loopback profile has a call identity")
            .sha256(),
        "scope must really move the call configuration"
    );
    let verified = fixture
        .open(scope_generation, &remote_scope)
        .expect("a scope change must still open the generation");
    assert_eq!(verified.generation_id(), scope_generation);
    assert_eq!(
        meta_value(conn, &representation_meta_key(scope_generation)),
        scope_before_representation,
        "scope must not rewrite the representation record"
    );
    assert_eq!(
        meta_value(conn, &provenance_meta_key(scope_generation)),
        scope_before_provenance,
        "scope must not rewrite the provenance record"
    );

    // No case created a second space for the same declaration.
    assert_eq!(count(conn, "embedding_generations"), 2);
    assert!(fixture.open(generation_id, &base).is_ok());
}

// ---------------------------------------------------------------------------
// Acceptance 4: configuration drift is classified, not guessed
// ---------------------------------------------------------------------------

#[test]
fn configuration_drift_is_classified_not_guessed() {
    let fixture = Fixture::new();
    let conn = fixture.conn();
    let base = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let generation_id = fixture.create(&base, 1024, b"fp-drift");

    // Same width, different model.
    let other_model = profile_for("p1", ENDPOINT_A, "example/other-model", EMBED_REVISION, &[]);
    assert_eq!(
        fixture.reopen_error(generation_id, &other_model).code(),
        ApiGenerationErrorCode::IdentityMismatch
    );

    // Same width, same model, different query prefix.
    let prefixed = profile_for(
        "p1",
        ENDPOINT_A,
        EMBED_MODEL,
        EMBED_REVISION,
        &["query_prefix = \"lookup: \""],
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &prefixed).code(),
        ApiGenerationErrorCode::IdentityMismatch
    );

    // Same width, same model, a different declared revision.
    let other_revision = profile_for("p1", ENDPOINT_A, EMBED_MODEL, "rev-synthetic-2", &[]);
    assert_eq!(
        fixture.reopen_error(generation_id, &other_revision).code(),
        ApiGenerationErrorCode::IdentityMismatch
    );

    // Same width, same model, different document prefix.
    let document_prefixed = profile_for(
        "p1",
        ENDPOINT_A,
        EMBED_MODEL,
        EMBED_REVISION,
        &["document_prefix = \"passage: \""],
    );
    assert_eq!(
        fixture
            .reopen_error(generation_id, &document_prefixed)
            .code(),
        ApiGenerationErrorCode::IdentityMismatch
    );

    // Same width, same model, a different protocol family.
    let other_protocol = parse_profile(
        "p1",
        &profile_toml(
            "p1",
            "openrouter-embeddings-v1",
            ENDPOINT_A,
            "loopback",
            EMBED_MODEL,
            EMBED_REVISION,
            &[r#"normalization = "l2""#],
        ),
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &other_protocol).code(),
        ApiGenerationErrorCode::IdentityMismatch
    );

    // An explicit request dimension equal to the archived effective dimension:
    // the profile is legal, but the stored declaration has no request dimension.
    let requesting = profile_for(
        "p1",
        ENDPOINT_A,
        EMBED_MODEL,
        EMBED_REVISION,
        &["request_dimensions = 1024"],
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &requesting).code(),
        ApiGenerationErrorCode::IdentityMismatch
    );

    // Same width, different normalization.
    let unnormalized = parse_profile(
        "p1",
        &profile_toml(
            "p1",
            "openai-embeddings-v1",
            ENDPOINT_A,
            "loopback",
            EMBED_MODEL,
            EMBED_REVISION,
            &[r#"normalization = "none""#],
        ),
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &unnormalized).code(),
        ApiGenerationErrorCode::IdentityMismatch
    );

    // A relocation moves only the call configuration. The declared space is
    // unchanged, so the generation opens and neither record is rewritten.
    let before_representation = meta_value(conn, &representation_meta_key(generation_id));
    let before_provenance = meta_value(conn, &provenance_meta_key(generation_id));
    let relocated = profile_for("p1", ENDPOINT_B, EMBED_MODEL, EMBED_REVISION, &[]);
    let verified = fixture
        .open(generation_id, &relocated)
        .expect("a relocated call configuration must still open the declared space");
    assert_eq!(verified.generation_id(), generation_id);

    // The accepted relocation left the row and both records byte-for-byte
    // intact.
    assert_eq!(
        meta_value(conn, &representation_meta_key(generation_id)),
        before_representation
    );
    assert_eq!(
        meta_value(conn, &provenance_meta_key(generation_id)),
        before_provenance
    );
    assert_eq!(count(conn, "embedding_generations"), 1);
}

/// A pinned provider is the other call-side fact that needs re-admission, and it
/// too leaves the record alone.
#[test]
fn a_changed_pinned_provider_needs_re_admission() {
    let fixture = Fixture::new();
    let providerless = parse_profile(
        "p1",
        &profile_toml(
            "p1",
            "openrouter-embeddings-v1",
            CLOUD_ENDPOINT,
            "remote",
            EMBED_MODEL,
            EMBED_REVISION,
            &[r#"normalization = "l2""#],
        ),
    );
    let pinned = parse_profile(
        "p1",
        &profile_toml(
            "p1",
            "openrouter-embeddings-v1",
            CLOUD_ENDPOINT,
            "remote",
            EMBED_MODEL,
            EMBED_REVISION,
            &[r#"normalization = "l2""#, r#"provider_only = "vendor-a""#],
        ),
    );

    let generation_id = fixture.create(&providerless, 1024, b"fp-provider");
    assert!(fixture.open(generation_id, &providerless).is_ok());
    let error = fixture.reopen_error(generation_id, &pinned);
    assert_eq!(error.code(), ApiGenerationErrorCode::CompatibilityRequired);
    assert_eq!(error.field(), Some("provider_only"));

    // Both records are still exactly what they were.
    assert!(fixture.open(generation_id, &providerless).is_ok());
    assert_eq!(count(fixture.conn(), "embedding_generations"), 1);
}

/// Only the credential variable's *name* enters the stored digest, so no
/// credential value is read and none can be invalidated by rotating one.
#[test]
fn a_credential_value_is_never_read_or_stored() {
    let fixture = Fixture::new();
    let conn = fixture.conn();
    // The variable is deliberately absent from this process.
    assert!(std::env::var(CREDENTIAL_ENV).is_err());
    let key_line = format!("api_key_env = \"{CREDENTIAL_ENV}\"");
    let profile = profile_for(
        "p1",
        ENDPOINT_A,
        EMBED_MODEL,
        EMBED_REVISION,
        &[key_line.as_str()],
    );
    let generation_id = fixture.create(&profile, 1024, b"fp-credential");

    // The variable is unset here and the record still verifies.
    assert!(fixture.open(generation_id, &profile).is_ok());

    // No credential value reached either stored record.
    for key in [
        representation_meta_key(generation_id),
        provenance_meta_key(generation_id),
    ] {
        let stored = meta_value(conn, &key).expect("a stored record");
        assert!(!stored.contains(SYNTHETIC_SECRET), "{key} leaked a credential");
        assert!(
            !stored.contains(CREDENTIAL_ENV),
            "{key} stored a credential source"
        );
    }

    // A second process whose environment *does* hold the secret still verifies.
    let toml = embedding_toml(
        "p1",
        ENDPOINT_A,
        EMBED_MODEL,
        EMBED_REVISION,
        &[key_line.as_str()],
    );
    fixture.storage.close().expect("close the parent storage");
    let summary = run_child(&fixture.path, "p1", &toml, generation_id);
    assert_eq!(summary["generation_id"].as_i64(), Some(generation_id));
}

// ---------------------------------------------------------------------------
// Acceptance 5: only the pure-primary shape is admitted
// ---------------------------------------------------------------------------

#[test]
fn non_primary_shapes_are_refused_with_closed_codes() {
    let fixture = Fixture::new();
    let conn = fixture.conn();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let generation_id = fixture.create(&profile, 1024, b"fp-shapes");
    let provenance = meta_value(conn, &provenance_meta_key(generation_id)).expect("provenance");

    // Two contributors.
    let mut two: serde_json::Value = serde_json::from_str(&provenance).expect("parse");
    let first = two["contributors"][0].clone();
    two["contributors"]
        .as_array_mut()
        .expect("an array")
        .push(first);
    set_meta(
        conn,
        &provenance_meta_key(generation_id),
        &serde_json::to_string(&two).expect("serialize"),
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &profile).code(),
        ApiGenerationErrorCode::UnsupportedContributors
    );

    // One contributor that carries an evidence header.
    set_meta(
        conn,
        &provenance_meta_key(generation_id),
        &tamper_first_contributor(
            &provenance,
            "compatibility_evidence_header",
            json!("cass.api-compatibility/1"),
        ),
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &profile).code(),
        ApiGenerationErrorCode::CompatibilityRequired
    );

    // One contributor that carries an evidence digest.
    set_meta(
        conn,
        &provenance_meta_key(generation_id),
        &tamper_first_contributor(
            &provenance,
            "compatibility_evidence_sha256",
            json!("ef".repeat(32)),
        ),
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &profile).code(),
        ApiGenerationErrorCode::CompatibilityRequired
    );

    // Zero contributors.
    set_meta(
        conn,
        &provenance_meta_key(generation_id),
        &tamper_top(&provenance, "contributors", json!([])),
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &profile).code(),
        ApiGenerationErrorCode::InvalidProvenance
    );

    // The legal pure-primary record still reopens.
    set_meta(conn, &provenance_meta_key(generation_id), &provenance);
    assert!(fixture.open(generation_id, &profile).is_ok());
}

/// A compatibility-evidence header is structured evidence, not a string this
/// ticket may freeze. Any legal non-null JSON header is therefore *present and
/// not admitted here*, which is `CompatibilityRequired` -- never a claim that
/// the record is corrupt, and never a rewrite of its bytes.
#[test]
fn a_structured_compatibility_header_is_pending_admission_not_corruption() {
    let fixture = Fixture::new();
    let conn = fixture.conn();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let generation_id = fixture.create(&profile, 1024, b"fp-header");
    let provenance = meta_value(conn, &provenance_meta_key(generation_id)).expect("provenance");

    let object_header = tamper_first_contributor(
        &provenance,
        "compatibility_evidence_header",
        json!({
            "version": 1,
            "primary": {
                "endpoint_config_sha256": "a".repeat(64),
                "descriptor_sha256": "b".repeat(64),
            },
            "fallback": { "endpoint_config_sha256": "c".repeat(64) },
            "weights_tokenizer_pooling": ["operator_declared", "l2"],
            "conclusion": "equivalent",
        }),
    );

    // The codec reads a structured header as legal JSON, not as a malformed
    // field, and the refusal is the admission one.
    let decoded = ApiGenerationProvenance::decode(object_header.as_bytes())
        .expect("a structured header must still be legal JSON");
    assert!(
        decoded.contributors()[0].has_compatibility_evidence_header(),
        "the header must be read as present"
    );
    assert_eq!(
        decoded
            .single_primary_contributor()
            .expect_err("a header-bearing contributor is not admitted")
            .code(),
        ApiGenerationErrorCode::CompatibilityRequired
    );

    // Every legal non-null JSON shape carries the same meaning.
    for (label, header) in [
        ("a nested object", json!({"version": 1, "nested": {"a": [1, {"b": null}]}})),
        ("an array", json!([1, {"nested": true}])),
        ("a number", json!(7)),
        ("a boolean", json!(true)),
    ] {
        let text = tamper_first_contributor(&provenance, "compatibility_evidence_header", header);
        let decoded = ApiGenerationProvenance::decode(text.as_bytes())
            .unwrap_or_else(|error| panic!("{label} must be legal JSON, got {error}"));
        assert_eq!(
            decoded
                .single_primary_contributor()
                .expect_err("not admitted")
                .code(),
            ApiGenerationErrorCode::CompatibilityRequired,
            "{label}"
        );
    }

    // Through a real reopen, the structured header is refused as pending
    // admission and neither record nor row changes.
    let representation_before = meta_value(conn, &representation_meta_key(generation_id));
    set_meta(
        conn,
        &provenance_meta_key(generation_id),
        object_header.as_str(),
    );
    let error = fixture.reopen_error(generation_id, &profile);
    assert_eq!(error.code(), ApiGenerationErrorCode::CompatibilityRequired);
    assert_eq!(error.field(), Some("compatibility_evidence_header"));
    assert_eq!(
        meta_value(conn, &provenance_meta_key(generation_id)),
        Some(object_header.clone()),
        "the refused bytes must be left exactly as they were"
    );
    assert_eq!(
        meta_value(conn, &representation_meta_key(generation_id)),
        representation_before
    );
    assert_eq!(count(conn, "embedding_generations"), 1);
    // A header-bearing record never yields a verified generation.
    assert!(fixture.open(generation_id, &profile).is_err());

    // Bad JSON is still a malformed record, not a pending one.
    let broken = provenance.replace(
        "\"compatibility_evidence_header\":null",
        "\"compatibility_evidence_header\":{",
    );
    assert_eq!(
        ApiGenerationProvenance::decode(broken.as_bytes())
            .expect_err("broken JSON must be refused")
            .code(),
        ApiGenerationErrorCode::InvalidProvenance
    );

    // The explicit-null control still passes, and so does the stored record.
    set_meta(conn, &provenance_meta_key(generation_id), &provenance);
    assert!(fixture.open(generation_id, &profile).is_ok());
}

/// A header this build cannot hold must still read as *present*, not as a
/// corrupt record. Its numbers are part of the evidence this ticket may not
/// interpret, so the decoder records presence and materializes nothing.
#[test]
fn a_header_this_build_cannot_hold_is_present_not_corruption() {
    let fixture = Fixture::new();
    let conn = fixture.conn();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let generation_id = fixture.create(&profile, 1024, b"fp-big-header");
    let provenance = meta_value(conn, &provenance_meta_key(generation_id)).expect("provenance");

    let huge_integer = "9".repeat(400);
    let cases: Vec<(&str, String)> = vec![
        (
            "a nested float that overflows f64",
            r#"{"version":1,"nested":{"future_value":1e400}}"#.to_string(),
        ),
        (
            "a nested integer larger than u64 and than f64",
            format!(r#"{{"huge":{huge_integer}}}"#),
        ),
        (
            "an integer larger than u64 but representable as f64",
            r#"{"big":18446744073709551616}"#.to_string(),
        ),
        (
            "an array holding both",
            format!(r#"[1e400,{huge_integer},{{"ok":true}}]"#),
        ),
        (
            "a plain object",
            r#"{"version":1,"conclusion":"equivalent"}"#.to_string(),
        ),
        ("a string", r#""cass.api-compatibility/1""#.to_string()),
    ];

    for (label, header) in &cases {
        let text = replace_header(&provenance, header);
        let decoded = ApiGenerationProvenance::decode(text.as_bytes())
            .unwrap_or_else(|error| panic!("{label} must be legal JSON, got {error}"));
        assert!(
            decoded.contributors()[0].has_compatibility_evidence_header(),
            "{label} must be read as present"
        );
        assert_eq!(
            decoded
                .single_primary_contributor()
                .expect_err("not admitted")
                .code(),
            ApiGenerationErrorCode::CompatibilityRequired,
            "{label}"
        );
        // A record that carries evidence is never re-encoded without it.
        assert_eq!(
            decoded
                .canonical_bytes()
                .expect_err("a header this build cannot hold must not be dropped")
                .code(),
            ApiGenerationErrorCode::CompatibilityRequired,
            "{label}"
        );
    }

    // Through a real reopen the boundary is the same, and nothing changes.
    let structured = replace_header(&provenance, r#"{"version":1,"nested":{"future_value":1e400}}"#);
    let representation_before = meta_value(conn, &representation_meta_key(generation_id));
    set_meta(conn, &provenance_meta_key(generation_id), &structured);
    let error = fixture.reopen_error(generation_id, &profile);
    assert_eq!(error.code(), ApiGenerationErrorCode::CompatibilityRequired);
    assert_eq!(error.field(), Some("compatibility_evidence_header"));
    assert_eq!(
        meta_value(conn, &provenance_meta_key(generation_id)),
        Some(structured.clone()),
        "the refused bytes must be left exactly as they were"
    );
    assert_eq!(
        meta_value(conn, &representation_meta_key(generation_id)),
        representation_before
    );
    assert_eq!(count(conn, "embedding_generations"), 1);
    assert!(fixture.open(generation_id, &profile).is_err());

    // A present header cannot mask a structural defect.
    let duplicated = replace_header(
        &provenance.replace("\"model\":", "\"model\":\"dup\",\"model\":"),
        r#"{"version":1}"#,
    );
    assert_eq!(
        ApiGenerationProvenance::decode(duplicated.as_bytes())
            .expect_err("a duplicated contributor key must still be refused")
            .code(),
        ApiGenerationErrorCode::InvalidProvenance
    );

    // Bad JSON stays a structural refusal, with or without a header.
    assert_eq!(
        ApiGenerationProvenance::decode(replace_header(&provenance, "{").as_bytes())
            .expect_err("broken JSON must be refused")
            .code(),
        ApiGenerationErrorCode::InvalidProvenance
    );

    // The explicit null still verifies.
    set_meta(conn, &provenance_meta_key(generation_id), &provenance);
    assert!(fixture.open(generation_id, &profile).is_ok());
}

#[test]
fn a_malformed_provenance_is_refused_structurally() {
    let fixture = Fixture::new();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let generation_id = fixture.create(&profile, 1024, b"fp-malformed");
    let provenance =
        meta_value(fixture.conn(), &provenance_meta_key(generation_id)).expect("provenance");

    let cases: Vec<(&str, String, ApiGenerationErrorCode)> = vec![
        (
            "a future version",
            tamper_top(&provenance, "version", json!(2)),
            ApiGenerationErrorCode::UnsupportedVersion,
        ),
        (
            "an unknown top-level key",
            provenance.replace("\"version\":1", "\"version\":1,\"extra\":1"),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "a missing top-level key",
            provenance.replace(&format!("\"generation_id\":{generation_id},"), ""),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "a duplicated key",
            provenance.replace(
                "\"generation_id\":",
                "\"generation_id\":1,\"generation_id\":",
            ),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "a decimal where an integer belongs",
            provenance.replace("\"version\":1", "\"version\":1.0"),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "trailing data",
            format!("{provenance}[]"),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "a mistyped contributor field",
            tamper_first_contributor(&provenance, "model", json!(7)),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "an unknown normalization",
            tamper_first_contributor(&provenance, "normalization", json!("cosine")),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "an unknown protocol",
            tamper_first_contributor(&provenance, "protocol", json!("openai-embeddings-v9")),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "a rerank protocol on an embedding contributor",
            tamper_first_contributor(&provenance, "protocol", json!("rerank-json-v1")),
            ApiGenerationErrorCode::WrongKind,
        ),
        (
            "a malformed endpoint digest",
            tamper_first_contributor(
                &provenance,
                "endpoint_config_sha256",
                json!("not-a-digest"),
            ),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
        (
            "an absent compatibility field",
            provenance.replace("\"compatibility_evidence_header\":null,", ""),
            ApiGenerationErrorCode::InvalidProvenance,
        ),
    ];

    for (label, text, expected) in cases {
        let error = ApiGenerationProvenance::decode(text.as_bytes())
            .expect_err(&format!("{label} must be refused by the codec"));
        assert_eq!(error.code(), expected, "{label}");
    }

    // And the same class of bytes is refused through a real reopen.
    set_meta(
        fixture.conn(),
        &provenance_meta_key(generation_id),
        &tamper_top(&provenance, "version", json!(2)),
    );
    assert_eq!(
        fixture.reopen_error(generation_id, &profile).code(),
        ApiGenerationErrorCode::UnsupportedVersion
    );
}

/// A rendered rejection carries a code, never the bytes it refused.
#[test]
fn a_rejection_never_echoes_the_record_it_refused() {
    let fixture = Fixture::new();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let generation_id = fixture.create(&profile, 1024, b"fp-echo");
    let provenance =
        meta_value(fixture.conn(), &provenance_meta_key(generation_id)).expect("provenance");

    // Refused while decoding: the codec must not quote what it rejected.
    let codec_cases = [
        (
            "the secret as an unknown normalization",
            tamper_first_contributor(&provenance, "normalization", json!(SYNTHETIC_SECRET)),
        ),
        (
            "the secret as a malformed endpoint digest",
            tamper_first_contributor(
                &provenance,
                "endpoint_config_sha256",
                json!(SYNTHETIC_SECRET),
            ),
        ),
        (
            "the secret as a malformed descriptor digest",
            tamper_top(&provenance, "descriptor_sha256", json!(SYNTHETIC_SECRET)),
        ),
        (
            "the secret as a malformed evidence digest",
            tamper_first_contributor(
                &provenance,
                "compatibility_evidence_sha256",
                json!(SYNTHETIC_SECRET),
            ),
        ),
    ];
    for (label, text) in codec_cases {
        let error = ApiGenerationProvenance::decode(text.as_bytes())
            .expect_err(&format!("{label} must be refused"));
        assert_renders_without(&error, SYNTHETIC_SECRET, label);
    }

    // Refused at reopen: the secret sits in a field the codec accepts.
    set_meta(
        fixture.conn(),
        &provenance_meta_key(generation_id),
        &tamper_first_contributor(&provenance, "provider_only", json!(SYNTHETIC_SECRET)),
    );
    let error = fixture.reopen_error(generation_id, &profile);
    assert_eq!(error.code(), ApiGenerationErrorCode::CompatibilityRequired);
    assert_renders_without(&error, SYNTHETIC_SECRET, "a changed pinned provider");
}

// ---------------------------------------------------------------------------
// Acceptance 6: a hand-written gold
// ---------------------------------------------------------------------------

/// The canonical bytes of one provenance record, written out by hand.
///
/// The golden digest below was computed from this exact byte string with an
/// external tool (`sha256sum`), not by the code under test. The document keeps
/// both compatibility fields as explicit nulls, an empty document prefix, a
/// non-empty query prefix and no provider.
const GOLD_PROVENANCE_JSON: &str = r#"{"contributors":[{"compatibility_evidence_header":null,"compatibility_evidence_sha256":null,"document_prefix":"","endpoint_config_sha256":"1111111111111111111111111111111111111111111111111111111111111111","model":"example/gold-model","model_revision":"rev-gold","normalization":"none","protocol":"openai-embeddings-v1","provider_only":null,"query_prefix":"q:"}],"descriptor_sha256":"2222222222222222222222222222222222222222222222222222222222222222","generation_id":7,"version":1}"#;

/// SHA-256 of [`GOLD_PROVENANCE_JSON`], computed externally.
const GOLD_PROVENANCE_SHA256: &str =
    "0477ae867ee100b20d48b002a20a47baffd1bcffa63c86976b6f10f05b531539";

#[test]
fn a_hand_written_provenance_record_round_trips_to_the_gold() {
    let provenance = ApiGenerationProvenance::decode(GOLD_PROVENANCE_JSON.as_bytes())
        .expect("the gold record decodes");
    assert_eq!(
        provenance
            .canonical_bytes()
            .expect("a pure-primary record encodes")
            .as_slice(),
        GOLD_PROVENANCE_JSON.as_bytes()
    );
    assert_eq!(
        provenance.sha256().expect("a pure-primary record hashes"),
        GOLD_PROVENANCE_SHA256
    );
    assert_eq!(provenance.generation_id(), 7);
    assert_eq!(provenance.version(), 1);
    assert_eq!(provenance.meta_key(), "api_generation_provenance:v1:7");
    assert_eq!(provenance.descriptor_sha256(), "2".repeat(64));
    assert_eq!(provenance.contributors().len(), 1);

    let contributor = provenance.single_primary_contributor().expect("pure primary");
    assert_eq!(contributor.model(), "example/gold-model");
    assert_eq!(contributor.model_revision(), "rev-gold");
    assert_eq!(contributor.document_prefix(), "");
    assert_eq!(contributor.query_prefix(), "q:");
    assert_eq!(contributor.endpoint_config_sha256(), "1".repeat(64));
    assert!(contributor.provider_only().is_none());
    assert!(!contributor.has_compatibility_evidence_header());
    assert!(contributor.compatibility_evidence_sha256().is_none());
}

/// A record the create helper writes is the golden shape: the same key order,
/// the same field set and the same escaping rules.
#[test]
fn the_stored_records_re_encode_to_their_own_bytes() {
    let fixture = Fixture::new();
    let profile = profile_for("p1", ENDPOINT_A, EMBED_MODEL, EMBED_REVISION, &[]);
    let generation_id = fixture.create(&profile, 1024, b"fp-reencode");

    let stored =
        meta_value(fixture.conn(), &provenance_meta_key(generation_id)).expect("provenance");
    let provenance = ApiGenerationProvenance::decode(stored.as_bytes()).expect("decode");
    assert_eq!(
        provenance
            .canonical_bytes()
            .expect("a pure-primary record encodes")
            .as_slice(),
        stored.as_bytes()
    );
    assert_eq!(provenance.sha256().expect("hashes").len(), 64);
    assert_eq!(
        provenance.meta_key(),
        format!("api_generation_provenance:v1:{generation_id}")
    );

    let stored =
        meta_value(fixture.conn(), &representation_meta_key(generation_id)).expect("record");
    let record = RepresentationRecord::decode(stored.as_bytes()).expect("decode");
    assert_eq!(record.canonical_bytes().as_slice(), stored.as_bytes());
    assert_eq!(
        record.meta_key(),
        format!("api_representation:v1:{generation_id}")
    );
}
