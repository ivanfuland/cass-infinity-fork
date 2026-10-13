//! Candidate inventory and independently pinned expected-input binding.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::storage::api::params;

use super::canonicalize::CANONICALIZE_PIPELINE_VERSION;
use super::chunking::CHUNKING_POLICY_VERSION;
use super::regression_chunks::export_chunks;
use super::regression_inventory::export_messages;
use super::regression_io::{RegressionIoContext, validate_private_run_root};
use super::regression_layout::export_order_and_layout;

const BINDING_SCHEMA: &str = "cass.regression-input.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationBinding {
    pub(crate) generation_id: i64,
    pub(crate) embedder_id: String,
    pub(crate) dim: i64,
    pub(crate) fingerprint: String,
    pub(crate) canonicalize_version: u32,
    pub(crate) chunking_policy_version: u32,
    pub(crate) byte_order: String,
    pub(crate) vector_revision: i64,
    pub(crate) audit_status: String,
    pub(crate) vector_domain_instance_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InputBinding {
    pub(crate) schema: String,
    pub(crate) schema_version: i64,
    pub(crate) database_sha256: String,
    pub(crate) wal_bytes: u64,
    /// Hash of the independently supplied source-content manifest file.
    /// The original source files are verified by the frozen-input producer.
    pub(crate) source_manifest_sha256: String,
    pub(crate) message_text_sha256: String,
    pub(crate) chunk_text_sha256: String,
    pub(crate) retrieval_order_sha256: String,
    pub(crate) retrieval_layout_sha256: String,
    pub(crate) lexical_statistics_sha256: String,
    pub(crate) message_count: u64,
    pub(crate) conversation_count: u64,
    pub(crate) chunk_count: u64,
    pub(crate) canonicalize_version: u32,
    pub(crate) chunking_policy_version: u32,
    pub(crate) statistics_policy: String,
    pub(crate) statistics_encoding: String,
    pub(crate) consumed_domains: Vec<String>,
    pub(crate) generation: GenerationBinding,
}

impl InputBinding {
    fn canonicalize(&mut self) -> Result<()> {
        if self.schema != BINDING_SCHEMA
            || self.schema_version != 8
            || self.wal_bytes != 0
            || self.canonicalize_version != CANONICALIZE_PIPELINE_VERSION
            || self.chunking_policy_version != CHUNKING_POLICY_VERSION
            || self.statistics_policy != "regression-fresh-v1"
            || self.statistics_encoding != "lexical-stats-v1"
            || self.consumed_domains != consumed_domains()
        {
            bail!("INPUT_BINDING_POLICY_MISMATCH");
        }
        for value in [
            &mut self.database_sha256,
            &mut self.source_manifest_sha256,
            &mut self.message_text_sha256,
            &mut self.chunk_text_sha256,
            &mut self.retrieval_order_sha256,
            &mut self.retrieval_layout_sha256,
            &mut self.lexical_statistics_sha256,
        ] {
            *value = hex::encode(digest32(value)?);
        }
        let generation = &mut self.generation;
        if generation.generation_id < 0
            || generation.dim <= 0
            || generation.vector_revision < 0
            || generation.embedder_id.is_empty()
            || generation.canonicalize_version != CANONICALIZE_PIPELINE_VERSION
            || generation.chunking_policy_version != CHUNKING_POLICY_VERSION
            || !matches!(generation.byte_order.as_str(), "le" | "be")
            || !matches!(
                generation.audit_status.as_str(),
                "passed" | "pending" | "failed"
            )
            || generation.vector_domain_instance_id.len() != 32
        {
            bail!("GENERATION_BINDING_INVALID");
        }
        if generation.fingerprint.is_empty() {
            bail!("GENERATION_BINDING_INVALID");
        }
        generation.fingerprint = hex::encode(
            hex::decode(&generation.fingerprint).context("GENERATION_BINDING_INVALID")?,
        );
        generation.vector_domain_instance_id = hex::encode(
            hex::decode(&generation.vector_domain_instance_id)
                .context("GENERATION_BINDING_INVALID")?,
        );
        Ok(())
    }
}

fn consumed_domains() -> Vec<String> {
    vec![
        "sqlite:lex_docs/fts_lex".into(),
        "sqlite:active-generation/message_chunks/vec-mirrors".into(),
    ]
}

fn digest32(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        bail!("BINDING_DIGEST_INVALID");
    }
    hex::decode(value)
        .context("BINDING_DIGEST_INVALID")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("BINDING_DIGEST_INVALID"))
}

fn regular_file(path: &Path) -> Result<File> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("BINDING_FILE_NOT_REGULAR");
    }
    File::open(path).map_err(Into::into)
}

fn file_digest(path: &Path) -> Result<String> {
    let mut input = regular_file(path)?;
    let before = input.metadata()?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .context("BINDING_FILE_SIZE_OVERFLOW")?;
    }
    let after = input.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if !path_after.is_file() || path_after.file_type().is_symlink() {
        bail!("BINDING_FILE_CHANGED");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if after.dev() != path_after.dev() || after.ino() != path_after.ino() {
            bail!("BINDING_FILE_CHANGED");
        }
    }
    if size != before.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || after.len() != path_after.len()
        || after.modified()? != path_after.modified()?
    {
        bail!("BINDING_FILE_CHANGED");
    }
    Ok(hex::encode(hash.finalize()))
}

pub(crate) fn verify_source_manifest(path: &Path, expected_sha256: &str) -> Result<()> {
    if file_digest(path)? != expected_sha256 {
        bail!("BINDING_SOURCE_CHANGED");
    }
    Ok(())
}

/// Load the expected bytes and verify their external pin before parsing them.
/// Expected files cannot be generated inside this run's output directory.
pub(crate) fn load_expected(
    path: &Path,
    pinned_sha256: &str,
    context: &RegressionIoContext,
) -> Result<InputBinding> {
    if path
        .canonicalize()?
        .starts_with(context.run_root().canonicalize()?)
    {
        bail!("EXTERNAL_EXPECTED_BINDING_REQUIRED");
    }
    let expected_sha = digest32(pinned_sha256)?;
    let mut input = regular_file(path)?;
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    if Sha256::digest(&bytes).as_slice() != expected_sha {
        bail!("EXPECTED_BINDING_FILE_DIGEST_MISMATCH");
    }
    let mut expected: InputBinding =
        serde_json::from_slice(&bytes).context("EXPECTED_BINDING_INVALID")?;
    expected.canonicalize()?;
    Ok(expected)
}

fn capture_generation(context: &RegressionIoContext) -> Result<GenerationBinding> {
    let source = context.connection()?;
    let generations=source.query_all_map("SELECT id,embedder_id,dim,fingerprint,canonicalize_version,chunking_policy_version,byte_order,vector_revision,audit_status FROM embedding_generations WHERE is_active=1 LIMIT 2",&[],|r|Ok(GenerationBinding{
        generation_id:r.get_typed(0)?,embedder_id:r.get_typed(1)?,dim:r.get_typed(2)?,fingerprint:hex::encode(r.get_typed::<Vec<u8>>(3)?),canonicalize_version:r.get_typed(4)?,chunking_policy_version:r.get_typed(5)?,byte_order:r.get_typed(6)?,vector_revision:r.get_typed(7)?,audit_status:r.get_typed(8)?,vector_domain_instance_id:String::new(),
    }))?;
    let mut generation = match generations.as_slice() {
        [g] => g.clone(),
        [] => bail!("NO_ACTIVE_GENERATION"),
        _ => bail!("AMBIGUOUS_ACTIVE_GENERATION"),
    };
    generation.vector_domain_instance_id = source.query_row_map(
        "SELECT value FROM meta WHERE key=?1",
        &params!["vector_domain_instance_id"],
        |r| r.get_typed(0),
    )?;
    generation.vector_domain_instance_id = hex::encode(
        hex::decode(&generation.vector_domain_instance_id).context("GENERATION_BINDING_INVALID")?,
    );
    context.verify_input()?;
    Ok(generation)
}

pub(crate) struct VerifiedSearch {
    pub(crate) client: super::query::SearchClient,
    pub(crate) binding: InputBinding,
    pub(crate) expected_file_sha256: String,
}

/// Expected approval is a separate input. All identity and maintenance checks
/// finish before constructing a client that can select retrieval candidates.
pub(crate) fn open_verified_search(
    context: std::sync::Arc<RegressionIoContext>,
    expected_path: &Path,
    expected_file_sha256: &str,
    source_manifest: &Path,
) -> Result<VerifiedSearch> {
    let expected = load_expected(expected_path, expected_file_sha256, &context)?;
    context.admit_index_run()?;
    context.verify_database_digest(&digest32(&expected.database_sha256)?)?;
    if file_digest(source_manifest)? != expected.source_manifest_sha256 {
        bail!("EXPECTED_SOURCE_MANIFEST_MISMATCH");
    }
    activate_prepared_search(context, &expected, expected_file_sha256, source_manifest)
}

/// The input runner has already verified the external pins and initial physical
/// database hash. Keep the inventory's own strong checks and all admission gates.
pub(crate) fn activate_prepared_search(
    context: std::sync::Arc<RegressionIoContext>,
    expected: &InputBinding,
    expected_file_sha256: &str,
    source_manifest: &Path,
) -> Result<VerifiedSearch> {
    context.verify_input()?;
    verify_source_manifest(source_manifest, &expected.source_manifest_sha256)?;
    let actual = inspect_input(&context, source_manifest)?;
    verify_expected(expected, &actual)?;
    validate_search_admission(&context, &actual)?;
    let client =
        super::query::SearchClient::open_for_regression(context.run_root(), context.clone())?;
    Ok(VerifiedSearch {
        client,
        binding: actual,
        expected_file_sha256: hex::encode(digest32(expected_file_sha256)?),
    })
}

/// Strong aggregate end check. Equal physical bytes prove the initial inventory
/// still applies; no inventory is independently exported a second time.
pub(crate) fn verify_aggregate_end(
    context: &RegressionIoContext,
    binding: &InputBinding,
    source_manifest: &Path,
) -> Result<()> {
    context.verify_database_digest(&digest32(&binding.database_sha256)?)?;
    verify_source_manifest(source_manifest, &binding.source_manifest_sha256)?;
    if capture_generation(context)? != binding.generation {
        bail!("AGGREGATE_GENERATION_CHANGED");
    }
    if binding.canonicalize_version != CANONICALIZE_PIPELINE_VERSION
        || binding.chunking_policy_version != CHUNKING_POLICY_VERSION
        || binding.statistics_policy != "regression-fresh-v1"
        || binding.statistics_encoding != "lexical-stats-v1"
        || binding.consumed_domains != consumed_domains()
    {
        bail!("AGGREGATE_POLICY_CHANGED");
    }
    context.verify_input()?;
    Ok(())
}

fn validate_search_admission(context: &RegressionIoContext, binding: &InputBinding) -> Result<()> {
    if binding.message_count == 0 {
        bail!("EMPTY_MESSAGE_CORPUS");
    }
    if binding.generation.audit_status != "passed" {
        bail!("GENERATION_REQUIRES_RECOVERY");
    }
    let source = context.connection()?;
    if !matches!(
        crate::storage::sqlite::lex_domain_rebuild_marker_status(&source)?,
        crate::storage::sqlite::LexDomainRebuildMarkerState::Completed { .. }
    ) {
        bail!("LEXICAL_DOMAIN_REQUIRES_RECOVERY");
    }
    source
        .query_opt_map("SELECT rowid FROM fts_lex LIMIT 1", &[], |r| {
            r.get_typed::<i64>(0)
        })
        .context("LEXICAL_DOMAIN_UNAVAILABLE")?;
    let vectors = crate::storage::vector_domain::count_vec0_rows_for_generation(
        &source,
        binding.generation.generation_id,
    )
    .context("VECTOR_DOMAIN_REQUIRES_RECOVERY")?;
    if u64::try_from(vectors)? != binding.chunk_count {
        bail!("VECTOR_DOMAIN_REQUIRES_RECOVERY");
    }
    crate::storage::vector_domain::check_int8_layout(
        &source,
        binding.generation.generation_id,
        binding.generation.dim,
    )
    .context("VECTOR_DOMAIN_REQUIRES_RECOVERY")?;
    context.verify_input()?;
    Ok(())
}

/// Produces an observed candidate. It does not register expected identity or
/// grant quality/admission approval. No model or retrieval request occurs here.
pub(crate) fn inspect_input(
    context: &RegressionIoContext,
    source_manifest: &Path,
) -> Result<InputBinding> {
    if source_manifest
        .canonicalize()?
        .starts_with(context.run_root().canonicalize()?)
    {
        bail!("EXTERNAL_SOURCE_MANIFEST_REQUIRED");
    }
    let source_manifest_sha256 = file_digest(source_manifest)?;
    let database_sha256 = hex::encode(context.database_digest()?);
    let generation = capture_generation(context)?;
    let messages = export_messages(context)?;
    let chunks = export_chunks(context)?;
    if generation.generation_id != chunks.generation_id {
        bail!("ACTIVE_GENERATION_CHANGED");
    }
    let ordering = export_order_and_layout(context)?;
    let lexical_statistics_sha256 = context.lexical_statistics_digest()?;
    let mut actual = InputBinding {
        schema: BINDING_SCHEMA.into(),
        schema_version: 8,
        database_sha256: database_sha256.clone(),
        wal_bytes: 0,
        source_manifest_sha256,
        message_text_sha256: messages.sha256,
        chunk_text_sha256: chunks.sha256,
        retrieval_order_sha256: ordering.order_sha256,
        retrieval_layout_sha256: ordering.layout_sha256,
        lexical_statistics_sha256,
        message_count: messages.message_count,
        conversation_count: messages.conversation_count,
        chunk_count: chunks.chunk_count,
        canonicalize_version: CANONICALIZE_PIPELINE_VERSION,
        chunking_policy_version: CHUNKING_POLICY_VERSION,
        statistics_policy: "regression-fresh-v1".into(),
        statistics_encoding: "lexical-stats-v1".into(),
        consumed_domains: consumed_domains(),
        generation,
    };
    actual.canonicalize()?;
    context.verify_database_digest(&digest32(&database_sha256)?)?;
    if capture_generation(context)? != actual.generation
        || file_digest(source_manifest)? != actual.source_manifest_sha256
    {
        bail!("BINDING_SOURCE_CHANGED");
    }
    validate_private_run_root(context.run_root())?;
    let mut output = tempfile::NamedTempFile::new_in(context.run_root())?;
    serde_json::to_writer_pretty(&mut output, &actual)?;
    output.write_all(b"\n")?;
    output.as_file().sync_all()?;
    output.persist_noclobber(context.run_root().join("input-binding-candidate.json"))?;
    Ok(actual)
}

/// Identity equality is necessary for a run, and is not an index correctness
/// certificate. Vector availability and readonly maintenance admission are
/// checked separately before search.
pub(crate) fn verify_expected(expected: &InputBinding, actual: &InputBinding) -> Result<()> {
    let mut expected = expected.clone();
    expected.canonicalize()?;
    let mut actual = actual.clone();
    actual.canonicalize()?;
    if expected != actual {
        bail!("EXPECTED_INPUT_BINDING_MISMATCH");
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use crate::storage::api::{Conn, Profile};

    fn fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let (root, db, run) = super::super::regression_chunks::tests::fixture("", "");
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        writer.execute_batch("ALTER TABLE embedding_generations ADD COLUMN embedder_id TEXT DEFAULT 'synthetic-embedder'; ALTER TABLE embedding_generations ADD COLUMN dim INTEGER DEFAULT 2; ALTER TABLE embedding_generations ADD COLUMN fingerprint BLOB DEFAULT X'010203'; ALTER TABLE embedding_generations ADD COLUMN canonicalize_version INTEGER DEFAULT 3; ALTER TABLE embedding_generations ADD COLUMN chunking_policy_version INTEGER DEFAULT 1; ALTER TABLE embedding_generations ADD COLUMN byte_order TEXT DEFAULT 'le'; ALTER TABLE embedding_generations ADD COLUMN vector_revision INTEGER DEFAULT 0; ALTER TABLE embedding_generations ADD COLUMN audit_status TEXT DEFAULT 'passed'; CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT); INSERT INTO meta VALUES('vector_domain_instance_id','0123456789abcdef0123456789abcdef'); PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;").unwrap();
        drop(writer);
        let manifest = root.path().join("source-manifest.txt");
        fs::write(&manifest, b"synthetic source-content manifest\n").unwrap();
        (root, db, run, manifest)
    }

    #[test]
    fn inspection_publishes_observed_candidate_and_rechecks_physical_input() {
        let (_root, db, run, manifest) = fixture();
        let before = fs::read(&db).unwrap();
        let context = RegressionIoContext::open(&db, &run).unwrap();
        let actual = inspect_input(&context, &manifest).unwrap();
        assert_eq!(actual.message_count, 1);
        assert_eq!(actual.chunk_count, 1);
        assert_eq!(
            actual.source_manifest_sha256,
            hex::encode(Sha256::digest(fs::read(&manifest).unwrap()))
        );
        assert_eq!(actual.database_sha256, hex::encode(Sha256::digest(&before)));
        assert_eq!(fs::read(&db).unwrap(), before);
        let saved: InputBinding =
            serde_json::from_slice(&fs::read(run.join("input-binding-candidate.json")).unwrap())
                .unwrap();
        assert_eq!(saved, actual);
    }

    #[test]
    fn externally_pinned_expected_file_is_loaded_before_identity_comparison() {
        let (root, db, run, manifest) = fixture();
        let context = RegressionIoContext::open(&db, &run).unwrap();
        let actual = inspect_input(&context, &manifest).unwrap();
        // Synthetic test expected is explicitly created in a separate caller
        // location. The product inspector only publishes the observed candidate.
        let expected_path = root.path().join("caller-expected.json");
        let bytes = serde_json::to_vec(&actual).unwrap();
        fs::write(&expected_path, &bytes).unwrap();
        let pin = hex::encode(Sha256::digest(&bytes));
        let expected = load_expected(&expected_path, &pin, &context).unwrap();
        verify_expected(&expected, &actual).unwrap();
        assert!(
            load_expected(&expected_path, &"00".repeat(32), &context)
                .unwrap_err()
                .to_string()
                .contains("EXPECTED_BINDING_FILE_DIGEST_MISMATCH")
        );
        assert!(
            load_expected(&run.join("input-binding-candidate.json"), &pin, &context)
                .unwrap_err()
                .to_string()
                .contains("EXTERNAL_EXPECTED_BINDING_REQUIRED")
        );
        let mut changed = actual.clone();
        changed.retrieval_layout_sha256 = "00".repeat(32);
        assert!(verify_expected(&expected, &changed).is_err());
    }

    #[test]
    fn changed_counts_policies_generation_and_each_digest_refuse_the_binding() {
        let (_root, db, run, manifest) = fixture();
        let context = RegressionIoContext::open(&db, &run).unwrap();
        let actual = inspect_input(&context, &manifest).unwrap();
        let value = serde_json::to_value(&actual).unwrap();
        for field in [
            "database_sha256",
            "source_manifest_sha256",
            "message_text_sha256",
            "chunk_text_sha256",
            "retrieval_order_sha256",
            "retrieval_layout_sha256",
            "lexical_statistics_sha256",
        ] {
            let mut changed = value.clone();
            changed[field] = serde_json::Value::String("00".repeat(32));
            let changed: InputBinding = serde_json::from_value(changed).unwrap();
            assert!(verify_expected(&changed, &actual).is_err(), "{field}");
        }
        for field in [
            "message_count",
            "conversation_count",
            "chunk_count",
            "schema_version",
            "canonicalize_version",
            "chunking_policy_version",
            "wal_bytes",
        ] {
            let mut changed = value.clone();
            changed[field] = serde_json::Value::from(999);
            let changed: InputBinding = serde_json::from_value(changed).unwrap();
            assert!(verify_expected(&changed, &actual).is_err(), "{field}");
        }
        let mut changed = actual.clone();
        changed.generation.vector_revision += 1;
        assert!(verify_expected(&changed, &actual).is_err());
        let mut changed = actual.clone();
        changed.generation.audit_status = "pending".into();
        assert!(verify_expected(&changed, &actual).is_err());
    }

    #[test]
    fn equivalent_hex_case_is_not_a_text_identity_change() {
        let (_root, db, run, manifest) = fixture();
        let context = RegressionIoContext::open(&db, &run).unwrap();
        let actual = inspect_input(&context, &manifest).unwrap();
        let mut expected = actual.clone();
        expected.database_sha256.make_ascii_uppercase();
        expected
            .generation
            .vector_domain_instance_id
            .make_ascii_uppercase();
        verify_expected(&expected, &actual).unwrap();
    }

    pub(crate) fn searchable_fixture() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        searchable_fixture_with_count(1)
    }

    pub(crate) fn searchable_fixture_with_count(
        count: usize,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        searchable_fixture_with_embedding(count, "synthetic-embedder", 2)
    }

    /// A searchable fixture whose active vector generation is produced through
    /// the real model-API catch-up path against the endpoint named by
    /// `config_path`. Local inference is retired, so a semantic regression run
    /// can only bind to a generation this path created (the API descriptor's
    /// `embedder_id` is `api:<sha256>`, which no hand-written row can match).
    ///
    /// The caller must have the configured endpoint serving embeddings for both
    /// the probe sentinels and the fixture's documents.
    pub(crate) fn searchable_fixture_with_api_embedding(
        count: usize,
        config_path: &Path,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        api_embedding_fixture(count, config_path, false)
    }

    /// Like [`searchable_fixture_with_api_embedding`], but every message carries
    /// a body long enough that one rerank window is a strict subset of the full
    /// content, so neighbour pages and slot binding stay observable.
    pub(crate) fn searchable_long_fixture_with_api_embedding(
        count: usize,
        config_path: &Path,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        api_embedding_fixture(count, config_path, true)
    }

    fn api_embedding_fixture(
        count: usize,
        config_path: &Path,
        long: bool,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        use crate::connectors::{NormalizedConversation, NormalizedMessage};
        use crate::search::model_api::config::ProfileKind;
        use crate::search::model_api::runtime;
        use crate::storage::sqlite::FrankenStorage;
        use crate::search::model_api::{ApiClient, EnvCredentialResolver, PrimaryEmbeddingCall};
        use crate::indexer::db_vector_catchup::{probe_api_backfill, run_api_primary_catchup_backfill};

        let conversation = NormalizedConversation {
            agent_slug: "codex".into(),
            external_id: Some("synthetic-session".into()),
            title: Some("retrieval".into()),
            workspace: None,
            source_path: "synthetic.jsonl".into(),
            started_at: Some(10),
            ended_at: None,
            metadata: serde_json::json!({}),
            messages: vec![NormalizedMessage {
                idx: 0,
                role: "user".into(),
                author: None,
                created_at: Some(20),
                content: if long {
                    format!("retrieval 初始锚点。\n{}", "后续中文合成段落 ".repeat(8000))
                } else {
                    "Investigate retrieval ranking and compare the evidence from both runs.".into()
                },
                extra: serde_json::json!({}),
                snippets: vec![],
                invocations: vec![],
            }],
        };
        let conversations: Vec<_> = (0..count)
            .map(|index| {
                let mut item = conversation.clone();
                if count > 1 {
                    item.external_id = Some(format!("synthetic-session-{index}"));
                    item.source_path = format!("synthetic-{index}.jsonl").into();
                    item.messages[0]
                        .content
                        .push_str(&format!(" Synthetic case {index}."));
                }
                item
            })
            .collect();
        let (root, original) =
            super::super::query::tests::seed_conversations_for_search_client(&conversations)
                .unwrap();
        let input = root.path().join("input");
        fs::create_dir(&input).unwrap();
        let db = input.join("agent_search.db");
        fs::rename(original, &db).unwrap();
        let storage = FrankenStorage::open(&db).unwrap();
        storage.rebuild_lex_domain_from_db(None).unwrap();

        let config =
            runtime::load_config(Some(config_path), |key| std::env::var_os(key)).unwrap();
        let id = config
            .default_profile_id(ProfileKind::Embedding)
            .expect("config must name a default embedding profile")
            .to_string();
        let profile = runtime::profile_by_id(&config, &id).unwrap();
        let client = ApiClient::new(config.clone(), Box::new(EnvCredentialResolver));
        let call = PrimaryEmbeddingCall::new(client, profile.clone(), true).unwrap();
        let probe = probe_api_backfill(&storage, &call)
            .unwrap_or_else(|error| panic!("api probe for the regression fixture: {error}"));
        run_api_primary_catchup_backfill(&storage, 64, &call, &profile, &probe, 42)
            .unwrap_or_else(|error| panic!("api catch-up for the regression fixture: {error}"));

        storage
            .raw()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .unwrap();
        drop(storage);
        let run = root.path().join("run");
        fs::create_dir(&run).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let manifest = root.path().join("source-manifest.txt");
        fs::write(&manifest, b"synthetic source-content manifest\n").unwrap();
        (root, db, run, manifest)
    }

    pub(crate) fn searchable_fixture_with_embedding(
        count: usize,
        embedder_id: &str,
        dimension: usize,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        use crate::connectors::{NormalizedConversation, NormalizedMessage};
        use crate::storage::sqlite::FrankenStorage;
        let conversation = NormalizedConversation {
            agent_slug: "codex".into(),
            external_id: Some("synthetic-session".into()),
            title: Some("retrieval".into()),
            workspace: None,
            source_path: "synthetic.jsonl".into(),
            started_at: Some(10),
            ended_at: None,
            metadata: serde_json::json!({}),
            messages: vec![NormalizedMessage {
                idx: 0,
                role: "user".into(),
                author: None,
                created_at: Some(20),
                content: "Investigate retrieval ranking and compare the evidence from both runs."
                    .into(),
                extra: serde_json::json!({}),
                snippets: vec![],
                invocations: vec![],
            }],
        };
        let conversations: Vec<_> = (0..count)
            .map(|index| {
                let mut item = conversation.clone();
                if count > 1 {
                    item.external_id = Some(format!("synthetic-session-{index}"));
                    item.source_path = format!("synthetic-{index}.jsonl").into();
                    item.messages[0]
                        .content
                        .push_str(&format!(" Synthetic case {index}."));
                }
                item
            })
            .collect();
        let (root, original) =
            super::super::query::tests::seed_conversations_for_search_client(&conversations)
                .unwrap();
        let input = root.path().join("input");
        fs::create_dir(&input).unwrap();
        let db = input.join("agent_search.db");
        fs::rename(original, &db).unwrap();
        let storage = FrankenStorage::open(&db).unwrap();
        storage.rebuild_lex_domain_from_db(None).unwrap();
        drop(storage);
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        let messages: Vec<(i64, i64, String)> = writer
            .query_all_map(
                "SELECT id,conversation_id,content FROM messages ORDER BY id",
                &[],
                |r| Ok((r.get_typed(0)?, r.get_typed(1)?, r.get_typed(2)?)),
            )
            .unwrap();
        let mut vector = vec![0.0; dimension];
        vector[0] = 1.0;
        let embedding = crate::storage::schema::f32_vector_to_le_blob(&vector);
        let generation = writer.with_tx_no_replay(crate::storage::api::TxMode::Immediate, |tx| {
            let id = crate::storage::schema::create_embedding_generation(tx,embedder_id,dimension as i64,3,1,&[1,2,3],10)?;
            for (mid, cid, content) in &messages {
                for chunk in super::super::eligibility::expected_chunks(*mid, *cid, "user", content) {
                    tx.execute("INSERT INTO message_chunks(generation_id,message_id,conversation_id,chunk_idx,byte_start,byte_end,content_hash,embedding,norm,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,1,10)",
                        &params![id,*mid,*cid,i64::from(chunk.chunk_idx),chunk.byte_start as i64,chunk.byte_end as i64,chunk.content_hash.clone(),embedding.clone()])?;
                }
            }
            tx.execute("UPDATE embedding_generations SET is_active=1,audit_status='passed' WHERE id=?1",&params![id])?;
            Ok(id)
        }).unwrap();
        crate::storage::vector_domain::rebuild_vec0_table_for_generation(
            &writer,
            generation,
            dimension as i64,
        )
        .unwrap();
        writer
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .unwrap();
        drop(writer);
        let run = root.path().join("run");
        fs::create_dir(&run).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let manifest = root.path().join("source-manifest.txt");
        fs::write(&manifest, b"synthetic source-content manifest\n").unwrap();
        (root, db, run, manifest)
    }

    pub(crate) fn prepare_expected(
        root: &Path,
        db: &Path,
        manifest: &Path,
    ) -> (std::path::PathBuf, String) {
        use std::os::unix::fs::PermissionsExt;
        let inspection = root.join("inspection");
        fs::create_dir(&inspection).unwrap();
        fs::set_permissions(&inspection, fs::Permissions::from_mode(0o700)).unwrap();
        let context = RegressionIoContext::open(db, &inspection).unwrap();
        let actual = inspect_input(&context, manifest).unwrap();
        let path = root.join("external-expected.json");
        let bytes = serde_json::to_vec(&actual).unwrap();
        fs::write(&path, &bytes).unwrap();
        (path, hex::encode(Sha256::digest(bytes)))
    }

    #[test]
    fn verified_search_reads_real_fts_and_checks_expected_before_candidates() {
        let (root, db, run, manifest) = searchable_fixture();
        let (expected, pin) = prepare_expected(root.path(), &db, &manifest);
        let context = std::sync::Arc::new(RegressionIoContext::open(&db, &run).unwrap());
        assert!(
            open_verified_search(context.clone(), &expected, &"00".repeat(32), &manifest)
                .err()
                .unwrap()
                .to_string()
                .contains("EXPECTED_BINDING_FILE_DIGEST_MISMATCH")
        );
        assert!(fs::read_dir(&run).unwrap().next().is_none());
        let verified = open_verified_search(context, &expected, &pin, &manifest).unwrap();
        assert_eq!(verified.expected_file_sha256, pin);
        assert_eq!(verified.binding.message_count, 1);
        let hits = verified
            .client
            .search(
                "retrieval",
                super::super::query::SearchFilters::default(),
                10,
                0,
                super::super::query::FieldMask::FULL,
            )
            .unwrap();
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn readonly_index_guard_refuses_active_stale_and_replaced_records() {
        use fs2::FileExt;
        let (_root, db, run, _manifest) = fixture();
        let path = db.parent().unwrap().join("index-run.lock");
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.try_lock_exclusive().unwrap();
        let context = RegressionIoContext::open(&db, &run).unwrap();
        assert!(context.admit_index_run().is_err());
        file.unlock().unwrap();
        fs::write(&path, b"pid=123\nmode=index\n").unwrap();
        assert!(
            context
                .admit_index_run()
                .unwrap_err()
                .to_string()
                .contains("INDEX_RUN_STATE_REQUIRES_RECOVERY")
        );
        assert_eq!(fs::read(&path).unwrap(), b"pid=123\nmode=index\n");
        file.set_len(0).unwrap();
        context.admit_index_run().unwrap();
        assert!(file.try_lock_exclusive().is_err());
        fs::rename(&path, path.with_extension("old")).unwrap();
        File::create(&path).unwrap();
        assert!(context.verify_input().is_err());
    }

    #[test]
    fn verified_search_refuses_recovery_state_and_changed_physical_database() {
        let (root, db, run, manifest) = searchable_fixture();
        let (expected, pin) = prepare_expected(root.path(), &db, &manifest);
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        writer
            .execute(
                "UPDATE meta SET value='building' WHERE key='lex_domain_rebuild_state'",
                &[],
            )
            .unwrap();
        writer
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .unwrap();
        drop(writer);
        let context = std::sync::Arc::new(RegressionIoContext::open(&db, &run).unwrap());
        assert!(
            open_verified_search(context, &expected, &pin, &manifest)
                .err()
                .unwrap()
                .to_string()
                .contains("regression_database_digest_mismatch")
        );
        assert!(fs::read_dir(&run).unwrap().next().is_none());
    }

    #[test]
    fn verified_search_readonly_child() -> Result<()> {
        let Some(db) = std::env::var_os("CASS_VERIFIED_DB") else {
            return Ok(());
        };
        let run = std::env::var_os("CASS_VERIFIED_RUN").unwrap();
        let manifest = std::env::var_os("CASS_VERIFIED_MANIFEST").unwrap();
        let expected = std::env::var_os("CASS_VERIFIED_EXPECTED").unwrap();
        let pin = std::env::var("CASS_VERIFIED_PIN").unwrap();
        let context =
            std::sync::Arc::new(RegressionIoContext::open(Path::new(&db), Path::new(&run))?);
        let verified = open_verified_search(
            context.clone(),
            Path::new(&expected),
            &pin,
            Path::new(&manifest),
        )?;
        let filters = super::super::query::SearchFilters::default();
        assert_eq!(
            verified
                .client
                .search(
                    "retrieval",
                    filters.clone(),
                    10,
                    0,
                    super::super::query::FieldMask::FULL
                )?
                .len(),
            1
        );
        let hits = verified.client.search(
            "retrieval",
            filters.clone(),
            10,
            0,
            super::super::query::FieldMask::FULL,
        )?;
        let documents = super::super::rerank::context::build_documents_for_regression(
            &context,
            "retrieval",
            &hits,
        )?;
        assert_eq!(documents.len(), hits.len());
        assert!(!documents[0].is_empty());
        let stamp = super::super::rerank::window::capture_index_stamp_for_regression(&context)?;
        assert_eq!(stamp.schema_version, 8);
        assert!(stamp.wal.is_none());
        assert_eq!(
            stamp.vector.as_ref().unwrap().generation_id,
            verified.binding.generation.generation_id
        );
        let (vectors, _) =
            verified
                .client
                .search_vector_candidates(&[1.0, 0.0], &filters, None, 1)?;
        assert_eq!(vectors.len(), 1);
        let fast = verified
            .client
            .with_vector_search_mode(super::super::query::VectorSearchMode::Fast);
        let (vectors, meta) = fast.search_vector_candidates(&[1.0, 0.0], &filters, None, 1)?;
        assert_eq!(vectors.len(), 1);
        assert!(meta.approximate);
        println!("VERIFIED_FTS_EXACT_FAST_READONLY_SEARCH");
        Ok(())
    }

    #[test]
    fn verified_fts_exact_and_eight_shard_fast_search_work_on_os_readonly_input() {
        let (root, db, run, manifest) = searchable_fixture();
        let (expected, pin) = prepare_expected(root.path(), &db, &manifest);
        let before = fs::read(&db).unwrap();
        let output = std::process::Command::new("/usr/bin/bwrap")
            .args(["--ro-bind", "/", "/", "--bind"])
            .arg(&run)
            .arg(&run)
            .args(["--unshare-net", "--proc", "/proc", "--dev", "/dev"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "search::regression_binding::tests::verified_search_readonly_child",
                "--nocapture",
            ])
            .env("CASS_VERIFIED_DB", &db)
            .env("CASS_VERIFIED_RUN", &run)
            .env("CASS_VERIFIED_MANIFEST", &manifest)
            .env("CASS_VERIFIED_EXPECTED", &expected)
            .env("CASS_VERIFIED_PIN", &pin)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("VERIFIED_FTS_EXACT_FAST_READONLY_SEARCH")
        );
        assert_eq!(fs::read(&db).unwrap(), before);
    }

    #[test]
    fn empty_message_archive_cannot_receive_verified_search_admission() {
        let (root, db, run, manifest) = searchable_fixture();
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        writer
            .execute_batch(
                "DELETE FROM messages; DELETE FROM lex_docs; DELETE FROM message_chunks;",
            )
            .unwrap();
        let generation: i64 = writer
            .query_row_map(
                "SELECT id FROM embedding_generations WHERE is_active=1",
                &[],
                |r| r.get_typed(0),
            )
            .unwrap();
        crate::storage::vector_domain::rebuild_vec0_table_for_generation(&writer, generation, 2)
            .unwrap();
        writer.execute_batch("UPDATE embedding_generations SET audit_status='passed'; UPDATE meta SET value='completed:1:0' WHERE key='lex_domain_rebuild_state'; PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;").unwrap();
        drop(writer);
        let (expected, pin) = prepare_expected(root.path(), &db, &manifest);
        let context = std::sync::Arc::new(RegressionIoContext::open(&db, &run).unwrap());
        assert!(
            open_verified_search(context, &expected, &pin, &manifest)
                .err()
                .unwrap()
                .to_string()
                .contains("EMPTY_MESSAGE_CORPUS")
        );
    }

    #[test]
    fn cli_fixture_export() {
        let Some(marker) = std::env::var_os("CASS_INPUT_CLI_FIXTURE_MARKER") else {
            return;
        };
        let count = std::env::var("CASS_INPUT_CLI_FIXTURE_COUNT")
            .ok()
            .map(|v| v.parse().unwrap())
            .unwrap_or(1);
        let (root, db, run, manifest) =
            if std::env::var_os("CASS_INPUT_CLI_FIXTURE_INFINITY").is_some() {
                searchable_fixture_with_embedding(count, "BAAI/bge-m3", 1024)
            } else {
                searchable_fixture_with_count(count)
            };
        let (expected, pin) = prepare_expected(root.path(), &db, &manifest);
        let retained_root = root.keep();
        let value = serde_json::json!({"root":retained_root,"database":db,"run_root":run,"source_manifest":manifest,"expected_binding":expected,"expected_sha256":pin});
        fs::write(marker, serde_json::to_vec(&value).unwrap()).unwrap();
        println!("RETAINED_SYNTHETIC_CLI_FIXTURE_READY");
    }

    #[test]
    fn binding_readonly_child() -> Result<()> {
        let Some(db) = std::env::var_os("CASS_BINDING_DB") else {
            return Ok(());
        };
        let run = std::env::var_os("CASS_BINDING_RUN").unwrap();
        let manifest = std::env::var_os("CASS_BINDING_SOURCE_MANIFEST").unwrap();
        let context = RegressionIoContext::open(Path::new(&db), Path::new(&run))?;
        inspect_input(&context, Path::new(&manifest))?;
        println!("INPUT_BINDING_READONLY_VERIFIED");
        Ok(())
    }

    #[test]
    fn complete_binding_inspection_works_on_os_readonly_input() {
        let (_root, db, run, manifest) = fixture();
        let before = fs::read(&db).unwrap();
        let output = std::process::Command::new("/usr/bin/bwrap")
            .args(["--ro-bind", "/", "/", "--bind"])
            .arg(&run)
            .arg(&run)
            .args(["--unshare-net", "--proc", "/proc", "--dev", "/dev"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "search::regression_binding::tests::binding_readonly_child",
                "--nocapture",
            ])
            .env("CASS_BINDING_DB", &db)
            .env("CASS_BINDING_RUN", &run)
            .env("CASS_BINDING_SOURCE_MANIFEST", &manifest)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("INPUT_BINDING_READONLY_VERIFIED")
        );
        assert_eq!(fs::read(&db).unwrap(), before);
    }
}
