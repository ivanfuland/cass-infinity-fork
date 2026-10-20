//! Task10 acceptance tests: the public raw source-facts reader and the frozen
//! standard DTOs.
//!
//! Every fixture is synthetic and self-contained: inputs are verified through
//! the existing public `VerifiedSourceInput` path, records are staged through
//! the existing public primitives, and every expected value in this file is
//! hand-written from the frozen contract or an independent computation. No
//! expected value is produced by the reader under test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use coding_agent_search::sources::config::ExcludedContextPaths;
use coding_agent_search::storage::api::{Conn, Profile, Tx, TxMode, Value};
use coding_agent_search::storage::source_codec::decode_safe_source;
use coding_agent_search::storage::source_facts::{
    AttemptHistory, CandidateFact, ClaimLinkInstall, ClaimMappingState, DiagnosticsEnvelope,
    EvidenceKind, ExtraStorageKind, FactStatus, FactUnit, FactValue, FactValueKind, FieldFact,
    FramingScan, InstallationClass, LinkEvidence, MergeFingerprint, MessageFacts, OriginalBinding,
    OriginalBindingOutcome, OriginalInstallation, ParseState, ProjectionDisposition,
    RawSourceFactsPage, RecordMappingState, ReplayRejectReason, SafeDiagnostic, SafetyState,
    Sha256Digest, SourceActivationRequest, SourceClaim, SourceFactsFilter, SourceFactsPageLimits,
    SourceFactsReadError, SourceFactsReadErrorCode, SourceFactsReader, SourceFactsRecord,
    SourceFactsScope, SourceFormat, SourceInputDeclaration, SourceSafetyConfig, StandardFacts,
    TerminalState, ToolFact, UnprocessedRangesEnvelope, UsageSnapshot, VerifiedFinish,
    VerifiedSourceInput, VerifiedStagedRecord, activate_source_input_in_tx, binding_digest,
    context_digest, decode_expected_manifest_header, encode_link_evidence,
    install_source_links_in_tx, semantic_request_digest, source_a_roots_in_tx,
    stage_source_records_in_tx, u64_be8,
};
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::testing::open_test_writer;
use franken_agent_detection::LosslessSourceValue;
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

const SCHEMA7_DDL: &str = include_str!("fixtures/source_legacy_reader/schema7_legacy.sql");
const SCHEMA8_DDL: &str = include_str!("fixtures/source_legacy_reader/schema8_legacy.sql");

const INPUT_HEADER_SNAPSHOT_DOMAIN: &str = "cass.source-input-header-snapshot/1";
const INPUT_SNAPSHOT_COLUMNS: [&str; 31] = [
    "input_key",
    "identity_tuple_bin",
    "source_id",
    "identity_namespace",
    "connector",
    "origin_host",
    "origin_source_version",
    "role_bin",
    "platform_bin",
    "root_id_bin",
    "relative_locator_bin",
    "discovery_bin",
    "parser_context_bin",
    "context_digest",
    "sealed_ref_bin",
    "sealed_sha256",
    "byte_len",
    "format",
    "expected_manifest_bin",
    "normalizer_id",
    "safety_contract_id",
    "state",
    "expected_records",
    "expected_blank_lines",
    "observed_records",
    "observed_blank_lines",
    "unprocessed_ranges_bin",
    "attempt_history_bin",
    "activation_request_hash",
    "receipt_key",
    "applied_content_generation",
];

/// Fixed synthetic source IDs. Their page order is fixed by the SHA-256 of the
/// input identity keys, not by this list's order; the list is kept in the
/// frozen fixture order only so the inputs are easy to compare.
const CATALOG_IDS: [&str; 66] = [
    "C10_EMPTY_437",
    "C10_EMPTY_97",
    "C10_EMPTY_104",
    "C10_EMPTY_587",
    "C10_EMPTY_232",
    "C10_EMPTY_80",
    "C10_EMPTY_356",
    "C10_EMPTY_719",
    "C10_EMPTY_650",
    "C10_EMPTY_10",
    "C10_EMPTY_667",
    "C10_EMPTY_320",
    "C10_EMPTY_159",
    "C10_EMPTY_450",
    "C10_EMPTY_252",
    "C10_EMPTY_775",
    "C10_EMPTY_538",
    "C10_EMPTY_46",
    "C10_EMPTY_762",
    "C10_EMPTY_780",
    "C10_EMPTY_2",
    "C10_EMPTY_315",
    "C10_EMPTY_544",
    "C10_EMPTY_620",
    "C10_EMPTY_231",
    "C10_EMPTY_358",
    "C10_EMPTY_384",
    "C10_EMPTY_115",
    "C10_EMPTY_657",
    "C10_EMPTY_593",
    "C10_EMPTY_532",
    "C10_EMPTY_741",
    "C10_EMPTY_533",
    "C10_EMPTY_654",
    "C10_EMPTY_290",
    "C10_EMPTY_325",
    "C10_EMPTY_135",
    "C10_EMPTY_420",
    "C10_EMPTY_102",
    "C10_EMPTY_429",
    "C10_EMPTY_665",
    "C10_EMPTY_223",
    "C10_EMPTY_150",
    "C10_EMPTY_383",
    "C10_EMPTY_681",
    "C10_EMPTY_770",
    "C10_EMPTY_653",
    "C10_EMPTY_529",
    "C10_EMPTY_133",
    "C10_EMPTY_200",
    "C10_EMPTY_313",
    "C10_EMPTY_596",
    "C10_EMPTY_13",
    "C10_EMPTY_268",
    "C10_EMPTY_235",
    "C10_EMPTY_634",
    "C10_EMPTY_206",
    "C10_EMPTY_303",
    "C10_EMPTY_101",
    "C10_EMPTY_248",
    "C10_EMPTY_294",
    "C10_EMPTY_520",
    "C10_EMPTY_300",
    "C10_DENSE",
    "C10_EMPTY_0",
    "C10_EMPTY_1",
];

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn db_path(tag: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(format!("{tag}.db"));
    (dir, path)
}

fn safety() -> SourceSafetyConfig {
    SourceSafetyConfig {
        code_version: "c10-fixture/1".into(),
        desensitization_enabled: true,
        config_source_identity: "C10_FIXED".into(),
        fixed_config_bytes: b"memory_files = []\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n".to_vec(),
        effective_four_arrays: ExcludedContextPaths {
            memory_files: vec![],
            injection_only_files: vec![],
            workspace_scoped_files: vec![],
            project_read_documents: vec![],
        },
    }
}

fn context_value() -> LosslessSourceValue {
    LosslessSourceValue::parse(br#"{"fixture":"C10"}"#).expect("fixed context")
}

fn verified_with(
    id: &str,
    sealed: &[u8],
    normalizer: &str,
    safety_contract: &str,
) -> VerifiedSourceInput {
    let context = context_value();
    let context_hex = coding_agent_search::storage::source_facts::context_digest(&context)
        .expect("context digest")
        .hex();
    let payload_hex = Sha256Digest::of(sealed).hex();
    let locator = format!("{id}.jsonl");
    let tuple = vec![
        Some("cass.source-input/2".into()),
        Some("C10_NAMESPACE".into()),
        Some(id.into()),
        Some("claude_code".into()),
        Some("/synthetic/c10".into()),
        Some(locator.clone()),
        Some("primary_session_log".into()),
        Some("local".into()),
        None,
        None,
        None,
        Some(context_hex),
        Some(payload_hex),
        Some(normalizer.into()),
        Some(safety_contract.into()),
    ];
    let declaration = SourceInputDeclaration {
        identity_tuple: tuple,
        identity_namespace: "C10_NAMESPACE".into(),
        source_id: id.into(),
        connector: "claude_code".into(),
        origin_kind: Some("local".into()),
        origin_host: None,
        origin_source_version: None,
        role: Some("primary_session_log".into()),
        platform: None,
        root_id: "/synthetic/c10".into(),
        relative_locator: locator,
        discovery: context.clone(),
        parser_context: context.clone(),
        sealed_ref: context,
        format: SourceFormat::Jsonl,
        normalizer_id: normalizer.into(),
        safety_contract_id: safety_contract.into(),
    };
    VerifiedSourceInput::verify(declaration, sealed, &safety())
        .expect("public verifier accepts the synthetic input")
        .0
}

fn verified(id: &str, sealed: &[u8]) -> VerifiedSourceInput {
    verified_with(id, sealed, "C10_NORMALIZER", "C10_SAFETY")
}

/// A legal rich-information input: distinct role/platform/host/version and
/// three distinct lossless trees. The tuple, context digest and sealed digest
/// are derived by the same public verifier, never filled by the test.
fn verified_rich(id: &str, sealed: &[u8]) -> VerifiedSourceInput {
    let discovery =
        LosslessSourceValue::parse(br#"{"fixture":"C10_DISCOVERY"}"#).expect("discovery tree");
    let parser_context =
        LosslessSourceValue::parse(br#"{"fixture":"C10_PARSER_CONTEXT"}"#).expect("context tree");
    let sealed_ref =
        LosslessSourceValue::parse(br#"{"fixture":"C10_SEALED_REF"}"#).expect("sealed tree");
    let context_hex = context_digest(&parser_context)
        .expect("context digest")
        .hex();
    let payload_hex = Sha256Digest::of(sealed).hex();
    let locator = format!("{id}.jsonl");
    let tuple = vec![
        Some("cass.source-input/2".to_string()),
        Some("C10_NAMESPACE".to_string()),
        Some(id.to_string()),
        Some("claude_code".to_string()),
        Some("/synthetic/c10".to_string()),
        Some(locator.clone()),
        Some("primary_session_log".to_string()),
        Some("local".to_string()),
        Some("C10_HOST".to_string()),
        Some("C10_SOURCE_VERSION".to_string()),
        Some("linux".to_string()),
        Some(context_hex),
        Some(payload_hex),
        Some("C10_NORMALIZER".to_string()),
        Some("C10_SAFETY".to_string()),
    ];
    let declaration = SourceInputDeclaration {
        identity_tuple: tuple,
        identity_namespace: "C10_NAMESPACE".into(),
        source_id: id.into(),
        connector: "claude_code".into(),
        origin_kind: Some("local".into()),
        origin_host: Some("C10_HOST".into()),
        origin_source_version: Some("C10_SOURCE_VERSION".into()),
        role: Some("primary_session_log".into()),
        platform: Some("linux".into()),
        root_id: "/synthetic/c10".into(),
        relative_locator: locator,
        discovery,
        parser_context,
        sealed_ref,
        format: SourceFormat::Jsonl,
        normalizer_id: "C10_NORMALIZER".into(),
        safety_contract_id: "C10_SAFETY".into(),
    };
    VerifiedSourceInput::verify(declaration, sealed, &safety())
        .expect("public verifier accepts the rich input")
        .0
}

/// The scope fixture's three records with native ids, diagnostics and an
/// observed digest on records 1 and 3, and all three irrelevant on record 2.
fn staged_scope_rich(sealed: &[u8]) -> Vec<VerifiedStagedRecord> {
    let states = [
        RecordMappingState::Mixed,
        RecordMappingState::NoClaims,
        RecordMappingState::AllCanonical,
    ];
    let frames = frames_for(sealed);
    assert_eq!(frames.len(), 3);
    frames
        .iter()
        .enumerate()
        .map(|(index, frame)| {
            let locator = frame.locator();
            let native_ids = if index == 1 {
                None
            } else {
                Some(
                    LosslessSourceValue::parse(format!("{{\"native\":\"N{index}\"}}").as_bytes())
                        .expect("native tree"),
                )
            };
            let diagnostics = if index == 0 {
                Some(vec![SafeDiagnostic {
                    code: "C10_DIAG".into(),
                    detail: Some("kept".into()),
                    offset: Some(0),
                    position: None,
                }])
            } else {
                None
            };
            let observed = if index == 1 {
                None
            } else {
                Some(*frame.raw_sha256())
            };
            VerifiedStagedRecord::from_frame(
                frame,
                observed,
                ParseState::Parsed,
                states[index],
                SafetyState::Preserved,
                native_ids,
                Some(safe_value(
                    &sealed[locator.byte_start as usize..locator.byte_end as usize],
                )),
                diagnostics,
            )
        })
        .collect()
}

fn safe_value(text: &[u8]) -> LosslessSourceValue {
    let mut envelope = b"\x82\xa7version\x01\xa9safe_json".to_vec();
    assert!(text.len() < 256);
    envelope.extend_from_slice(&[0xd9, text.len() as u8]);
    envelope.extend_from_slice(text);
    decode_safe_source(&envelope)
        .expect("independent codec fixture")
        .value()
        .clone()
}

fn dense_payload() -> Vec<u8> {
    let mut out = Vec::new();
    for index in 0..65 {
        out.extend_from_slice(format!("{{\"n\":{index},\"body\":\"C10\"}}\n").as_bytes());
    }
    out
}

fn finish_from(
    manifest: &coding_agent_search::storage::source_facts::VerifiedExpectedManifest,
) -> VerifiedFinish {
    VerifiedFinish {
        content_digest: *manifest.sealed_sha256(),
        bytes_read: manifest.byte_len(),
        records_seen: manifest.records(),
        blank_lines: manifest.blank_lines(),
        parse_failed: 0,
        mapping_diagnostics: 0,
        unprocessed_ranges: vec![],
        reached_eof: true,
    }
}

fn library_of(tx: &Tx<'_>) -> String {
    tx.query_row_map(
        "SELECT value FROM meta WHERE key = 'library_identity'",
        &[],
        |row| row.get_typed(0),
    )
    .expect("library identity")
}

fn header_of(tx: &Tx<'_>, input_id: i64) -> Vec<u8> {
    tx.query_row_map(
        "SELECT expected_manifest_bin FROM source_inputs WHERE id = ?1",
        &[Value::Integer(input_id)],
        |row| row.get_typed(0),
    )
    .expect("expected manifest header")
}

fn mark_staged(tx: &Tx<'_>, input_id: i64, records: &[VerifiedStagedRecord]) {
    for record in records {
        let locator = record.locator();
        assert_eq!(
            tx.execute(
                "UPDATE source_records SET frame_state = 'staged'
                 WHERE input_id = ?1 AND ordinal = ?2 AND record_pointer = ?3",
                &[
                    Value::Integer(input_id),
                    Value::Blob(u64_be8(locator.ordinal).to_vec()),
                    Value::Text(locator.record_pointer.clone()),
                ],
            )
            .expect("frame state update"),
            1
        );
    }
}

fn frames_for(
    sealed: &[u8],
) -> Vec<coding_agent_search::storage::source_facts::FramedSourceRecord> {
    let mut scan = FramingScan::new(sealed, SourceFormat::Jsonl);
    let mut frames = Vec::new();
    while !scan.is_done() {
        frames.extend(scan.next_page(64).expect("scan page"));
    }
    frames
}

fn staged_records(
    sealed: &[u8],
    states: &[RecordMappingState],
    with_payload: bool,
) -> Vec<VerifiedStagedRecord> {
    let frames = frames_for(sealed);
    assert_eq!(frames.len(), states.len(), "fixture record count");
    frames
        .iter()
        .zip(states.iter())
        .map(|(frame, state)| {
            let locator = frame.locator();
            let payload = if with_payload {
                Some(safe_value(
                    &sealed[locator.byte_start as usize..locator.byte_end as usize],
                ))
            } else {
                None
            };
            VerifiedStagedRecord::from_frame(
                frame,
                Some(*frame.raw_sha256()),
                ParseState::Parsed,
                *state,
                SafetyState::Preserved,
                None,
                payload,
                None,
            )
        })
        .collect()
}

fn canonical_claim(key: &Sha256Digest, ordinal: u64) -> SourceClaim {
    SourceClaim {
        input_key: *key,
        record_ordinal: ordinal,
        record_pointer: String::new(),
        conversation_ordinal: Some(0),
        final_message_idx: Some(0),
        positions: vec![],
        projection_pointer: Some("/messages/0".into()),
        evidence_kind: EvidenceKind::Prose,
        mapping_state: ClaimMappingState::Canonical,
    }
}

fn standalone_claim(key: &Sha256Digest, ordinal: u64) -> SourceClaim {
    SourceClaim {
        input_key: *key,
        record_ordinal: ordinal,
        record_pointer: String::new(),
        conversation_ordinal: None,
        final_message_idx: None,
        positions: vec![],
        projection_pointer: None,
        evidence_kind: EvidenceKind::NoMessage,
        mapping_state: ClaimMappingState::Standalone,
    }
}

fn unmapped_claim(key: &Sha256Digest, ordinal: u64) -> SourceClaim {
    SourceClaim {
        input_key: *key,
        record_ordinal: ordinal,
        record_pointer: String::new(),
        conversation_ordinal: None,
        final_message_idx: None,
        positions: vec![],
        projection_pointer: None,
        evidence_kind: EvidenceKind::ParseFailed,
        mapping_state: ClaimMappingState::Unmapped,
    }
}

fn canonical_installation(digest: Sha256Digest, message_id: i64) -> OriginalInstallation {
    OriginalInstallation {
        semantic_request_digest: digest,
        class: InstallationClass::CanonicalBound,
        binding: Some(OriginalBinding {
            outcome: OriginalBindingOutcome::AcceptedNew,
            original_conversation_id: 1,
            original_message_id: message_id,
            stored_idx: 0,
            stored_merge_fingerprint: MergeFingerprint {
                idx: 0,
                created_at: Some(1),
                role: "User".into(),
                author: None,
                content_blake3_hex: "ab".repeat(32),
            },
            safe_content_sha256: Sha256Digest::of(b"hello"),
            extra_storage_kind: ExtraStorageKind::Null,
            extra_json_sha256: None,
            extra_bin_sha256: None,
            extra_semantic_digest: None,
            excluded_semantic_digest: None,
            conversation_identity_digest: Sha256Digest::of(b"identity"),
        }),
        rejection: None,
        reason: None,
    }
}

fn simple_installation(
    digest: Sha256Digest,
    class: InstallationClass,
    reason: Option<ReplayRejectReason>,
) -> OriginalInstallation {
    OriginalInstallation {
        semantic_request_digest: digest,
        class,
        binding: None,
        rejection: None,
        reason,
    }
}

fn activate(
    tx: &Tx<'_>,
    input: &VerifiedSourceInput,
    input_id: i64,
    disposition: ProjectionDisposition,
    terminal: TerminalState,
) {
    let (records_root, claims_root) =
        source_a_roots_in_tx(tx, input.input_key(), input_id).expect("A roots");
    let header = header_of(tx, input_id);
    let (manifest, _) = decode_expected_manifest_header(&header).expect("header");
    let finish = finish_from(&manifest);
    let (normalizer_id, safety_contract_id): (String, String) = tx
        .query_row_map(
            "SELECT normalizer_id, safety_contract_id FROM source_inputs WHERE id = ?1",
            &[Value::Integer(input_id)],
            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
        )
        .expect("stored profile");
    let request = SourceActivationRequest {
        input_key: *input.input_key(),
        library_identity: library_of(tx),
        normalizer_id,
        safety_contract_id,
        expected_manifest_digest: Sha256Digest::of(&header),
        finish,
        projection_disposition: disposition,
        source_semantic_records_root: records_root,
        claims_root,
        requested_terminal: terminal,
    };
    activate_source_input_in_tx(tx, &request, &manifest).expect("activation");
}

fn publish_empty(db: &Path, id: &str, normalizer: &str, safety_contract: &str) -> Sha256Digest {
    let storage = FrankenStorage::open(db).expect("open schema9");
    let input = verified_with(id, b"", normalizer, safety_contract);
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &[]).expect("stage");
    activate(
        &tx,
        &input,
        staged.input_id,
        ProjectionDisposition::Ready,
        TerminalState::Complete,
    );
    tx.commit().expect("commit");
    storage.close().expect("close");
    *input.input_key()
}

fn publish_catalog(db: &Path) -> Sha256Digest {
    let storage = FrankenStorage::open(db).expect("open schema9");
    let dense = dense_payload();
    let mut dense_key = None;
    for id in CATALOG_IDS {
        let sealed = if id == "C10_DENSE" {
            dense.as_slice()
        } else {
            &[][..]
        };
        let input = verified(id, sealed);
        let states = vec![RecordMappingState::NoClaims; if sealed.is_empty() { 0 } else { 65 }];
        let records = staged_records(sealed, &states, true);
        let tx = storage
            .raw()
            .transaction_with_mode(TxMode::Immediate)
            .expect("tx");
        let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
        mark_staged(&tx, staged.input_id, &records);
        if sealed.is_empty() {
            activate(
                &tx,
                &input,
                staged.input_id,
                ProjectionDisposition::Ready,
                TerminalState::Complete,
            );
        } else {
            activate(
                &tx,
                &input,
                staged.input_id,
                ProjectionDisposition::WholeInputRejected,
                TerminalState::Failed,
            );
            dense_key = Some(*input.input_key());
        }
        tx.commit().expect("commit");
    }
    storage.close().expect("close");
    dense_key.expect("dense input")
}

fn replay_dense_failure(storage: &FrankenStorage) {
    let dense = dense_payload();
    let input = verified("C10_DENSE", &dense);
    let states = vec![RecordMappingState::NoClaims; 65];
    let records = staged_records(&dense, &states, true);
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
    mark_staged(&tx, staged.input_id, &records);
    activate(
        &tx,
        &input,
        staged.input_id,
        ProjectionDisposition::WholeInputRejected,
        TerminalState::Failed,
    );
    tx.commit().expect("commit");
}

const SCOPE_SEALED: &[u8] =
    b"{\"n\":0,\"body\":\"C10\"}\n{\"n\":1,\"body\":\"C10\"}\n{\"n\":2,\"body\":\"C10\"}\n";

fn seed_conversation(tx: &Tx<'_>) {
    tx.execute_batch(
        "INSERT OR IGNORE INTO agents(id,slug,name,kind,created_at,updated_at) \
             VALUES(1,'claude','Claude','agent',0,0);\
         INSERT OR IGNORE INTO conversations(id,agent_id,source_id,source_path,identity_host) \
             VALUES(1,1,'local','/synthetic/c10-canonical/session.jsonl','local');\
         INSERT OR IGNORE INTO messages(id,conversation_id,idx,role,content) \
             VALUES(7,1,0,'user','hello');",
    )
    .expect("seed conversation");
}

fn publish_scope(db: &Path) -> Sha256Digest {
    let storage = FrankenStorage::open(db).expect("open schema9");
    let input = verified_rich("C10_SCOPE", SCOPE_SEALED);
    let records = staged_scope_rich(SCOPE_SEALED);
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
    mark_staged(&tx, staged.input_id, &records);
    seed_conversation(&tx);

    let key = *input.input_key();
    let claims = vec![
        canonical_claim(&key, 1),
        standalone_claim(&key, 1),
        canonical_claim(&key, 3),
    ];
    install_source_links_in_tx(
        &tx,
        staged.input_id,
        &claims
            .iter()
            .map(|claim| ClaimLinkInstall {
                claim: claim.clone(),
                installation: None,
            })
            .collect::<Vec<_>>(),
    )
    .expect("pending links");

    let header = header_of(&tx, staged.input_id);
    let (manifest, _) = decode_expected_manifest_header(&header).expect("header");
    let (records_root, claims_root) =
        source_a_roots_in_tx(&tx, &key, staged.input_id).expect("A roots");
    let finish = finish_from(&manifest);
    let digest = semantic_request_digest(
        &key,
        &Sha256Digest::of(&header),
        manifest.sealed_sha256(),
        manifest.byte_len(),
        manifest.format().as_str(),
        "C10_NORMALIZER",
        "C10_SAFETY",
        &finish,
        ProjectionDisposition::Ready,
        &records_root,
        &claims_root,
    );
    let installations: Vec<ClaimLinkInstall> = claims
        .iter()
        .map(|claim| ClaimLinkInstall {
            claim: claim.clone(),
            installation: Some(if claim.mapping_state == ClaimMappingState::Canonical {
                canonical_installation(digest, 7)
            } else {
                simple_installation(digest, InstallationClass::StandaloneNoBinding, None)
            }),
        })
        .collect();
    install_source_links_in_tx(&tx, staged.input_id, &installations).expect("installed links");

    let request = SourceActivationRequest {
        input_key: key,
        library_identity: library_of(&tx),
        normalizer_id: "C10_NORMALIZER".into(),
        safety_contract_id: "C10_SAFETY".into(),
        expected_manifest_digest: Sha256Digest::of(&header),
        finish,
        projection_disposition: ProjectionDisposition::Ready,
        source_semantic_records_root: records_root,
        claims_root,
        requested_terminal: TerminalState::Complete,
    };
    activate_source_input_in_tx(&tx, &request, &manifest).expect("activation");
    tx.commit().expect("commit");
    storage.close().expect("close");
    key
}

fn publish_boundary(db: &Path, mode: &str) -> Sha256Digest {
    let storage = FrankenStorage::open(db).expect("open schema9");
    let bytes = SCOPE_SEALED;
    let staged_only = mode.starts_with("staged_");
    let sealed = if staged_only { &[][..] } else { bytes };
    let input = verified(&format!("C10_{mode}"), sealed);
    let states: Vec<RecordMappingState> = if staged_only {
        vec![]
    } else if mode == "pending" {
        vec![RecordMappingState::ClaimsPending; 3]
    } else {
        vec![
            RecordMappingState::AllUnmapped,
            RecordMappingState::AllCanonical,
            RecordMappingState::AllCanonical,
        ]
    };
    let records = staged_records(sealed, &states, true);
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
    mark_staged(&tx, staged.input_id, &records);

    let key = *input.input_key();
    let claims = if staged_only {
        vec![]
    } else {
        vec![
            unmapped_claim(&key, 1),
            canonical_claim(&key, 2),
            canonical_claim(&key, 3),
        ]
    };
    install_source_links_in_tx(
        &tx,
        staged.input_id,
        &claims
            .iter()
            .map(|claim| ClaimLinkInstall {
                claim: claim.clone(),
                installation: None,
            })
            .collect::<Vec<_>>(),
    )
    .expect("pending links");

    let header = header_of(&tx, staged.input_id);
    let (manifest, _) = decode_expected_manifest_header(&header).expect("header");
    let (records_root, claims_root) =
        source_a_roots_in_tx(&tx, &key, staged.input_id).expect("A roots");
    let finish = finish_from(&manifest);
    let disposition = if staged_only {
        ProjectionDisposition::Ready
    } else {
        ProjectionDisposition::WholeInputRejected
    };
    let digest = semantic_request_digest(
        &key,
        &Sha256Digest::of(&header),
        manifest.sealed_sha256(),
        manifest.byte_len(),
        manifest.format().as_str(),
        "C10_NORMALIZER",
        "C10_SAFETY",
        &finish,
        disposition,
        &records_root,
        &claims_root,
    );
    if mode == "installed" {
        let installations: Vec<ClaimLinkInstall> = claims
            .iter()
            .map(|claim| ClaimLinkInstall {
                claim: claim.clone(),
                installation: Some(if claim.record_ordinal == 1 {
                    simple_installation(digest, InstallationClass::UnmappedNoBinding, None)
                } else {
                    simple_installation(
                        digest,
                        InstallationClass::UnresolvedNoBinding,
                        Some(ReplayRejectReason::NoMatchingStoredRow),
                    )
                }),
            })
            .collect();
        install_source_links_in_tx(&tx, staged.input_id, &installations).expect("installed links");
    }
    let terminal = if mode == "staged_partial" {
        TerminalState::Partial
    } else {
        TerminalState::Failed
    };
    let request = SourceActivationRequest {
        input_key: key,
        library_identity: library_of(&tx),
        normalizer_id: "C10_NORMALIZER".into(),
        safety_contract_id: "C10_SAFETY".into(),
        expected_manifest_digest: Sha256Digest::of(&header),
        finish,
        projection_disposition: disposition,
        source_semantic_records_root: records_root,
        claims_root,
        requested_terminal: terminal,
    };
    activate_source_input_in_tx(&tx, &request, &manifest).expect("activation");
    tx.commit().expect("commit");
    storage.close().expect("close");
    key
}

fn publish_one(db: &Path, id: &str, with_payload: bool) -> Sha256Digest {
    publish_one_sealed(db, id, b"{\"n\":0,\"body\":\"C10\"}\n", with_payload)
}

fn publish_one_sealed(db: &Path, id: &str, sealed: &[u8], with_payload: bool) -> Sha256Digest {
    let input = verified(id, sealed);
    let records = staged_records(sealed, &[RecordMappingState::NoClaims], with_payload);
    let storage = FrankenStorage::open(db).expect("open schema9");
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
    mark_staged(&tx, staged.input_id, &records);
    activate(
        &tx,
        &input,
        staged.input_id,
        ProjectionDisposition::WholeInputRejected,
        TerminalState::Failed,
    );
    tx.commit().expect("commit");
    storage.close().expect("close");
    *input.input_key()
}

/// A private SQL seam snapshot on top of the complete scope fixture: the
/// documented authority-class boundary plus a real pending claim. This is not
/// an activation or receipt fixture and the parent receipt is not reissued.
fn build_edges(before: &Path, edges: &Path, pending: &Path, key: &Sha256Digest) {
    std::fs::copy(before, edges).expect("copy edges");
    let storage = FrankenStorage::open(edges).expect("open edges");
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let digest = Sha256Digest::of(b"edges");
    let updates = [
        (
            unmapped_claim(key, 1),
            simple_installation(digest, InstallationClass::UnmappedNoBinding, None),
            "unmapped",
            "standalone",
        ),
        (
            canonical_claim(key, 3),
            simple_installation(
                digest,
                InstallationClass::UnresolvedNoBinding,
                Some(ReplayRejectReason::NoMatchingStoredRow),
            ),
            "unresolved",
            "canonical",
        ),
    ];
    for (claim, installation, new_authority, old_authority) in updates {
        assert_eq!(
            tx.execute(
                "UPDATE source_message_links SET projection_key = ?1, source_positions_bin = ?2, \
                 message_id = NULL, authority = ?3, evidence_kind = ?4, binding_digest = ?5 \
                 WHERE record_id = (SELECT id FROM source_records WHERE input_id = 1 AND ordinal = ?6) \
                 AND authority = ?7",
                &[
                    Value::Blob(claim.projection_key().as_bytes().to_vec()),
                    Value::Blob(encode_link_evidence(&claim, Some(&installation)).expect("envelope")),
                    Value::Text(new_authority.into()),
                    Value::Text(claim.evidence_kind.as_str().into()),
                    Value::Blob(binding_digest(&claim, &installation).as_bytes().to_vec()),
                    Value::Blob(u64_be8(claim.record_ordinal).to_vec()),
                    Value::Text(old_authority.into()),
                ],
            )
            .expect("edge update"),
            1
        );
    }
    tx.commit().expect("commit");
    storage.close().expect("close");

    std::fs::copy(edges, pending).expect("copy pending");
    let storage = FrankenStorage::open(pending).expect("open pending");
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    install_source_links_in_tx(
        &tx,
        1,
        &[ClaimLinkInstall {
            claim: canonical_claim(key, 2),
            installation: None,
        }],
    )
    .expect("pending claim");
    assert_eq!(
        tx.execute(
            "UPDATE source_records SET record_mapping_state = 'claims_pending' \
             WHERE input_id = 1 AND ordinal = ?1",
            &[Value::Blob(u64_be8(2).to_vec())],
        )
        .expect("mapping state"),
        1
    );
    tx.commit().expect("commit");
    storage.close().expect("close");
}

// ---------------------------------------------------------------------------
// Reading helpers (assertions only; never produce expected values)
// ---------------------------------------------------------------------------

fn collect(
    reader: &SourceFactsReader,
    filter: &SourceFactsFilter,
    limits: SourceFactsPageLimits,
) -> Vec<RawSourceFactsPage> {
    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = reader
            .read_raw_source_facts(filter, cursor.as_deref(), limits)
            .expect("read page");
        let next = page.next_cursor.clone();
        if next.is_some() {
            assert!(
                !page.records.is_empty() || !page.inputs.is_empty(),
                "a non-terminal page must make progress"
            );
        }
        pages.push(page);
        assert!(pages.len() < 500, "pagination must terminate");
        match next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    pages
}

fn ordinals(pages: &[RawSourceFactsPage]) -> Vec<u64> {
    pages
        .iter()
        .flat_map(|page| page.records.iter().map(|record| record.ordinal))
        .collect()
}

fn reason(error: &SourceFactsReadError) -> String {
    error
        .detail()
        .get("reason")
        .and_then(Json::as_str)
        .expect("detail.reason")
        .to_string()
}

fn cursor_parts(cursor: &str) -> Vec<Json> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .expect("cursor base64");
    serde_json::from_slice::<Json>(&bytes)
        .expect("cursor json")
        .as_array()
        .expect("cursor array")
        .clone()
}

fn cursor_from_parts(parts: &[Json]) -> String {
    let bytes = serde_json::to_vec(&Json::Array(parts.to_vec())).expect("cursor json");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Independent implementation of the documented header snapshot: the domain
/// plus 31 `[column, tag, value]` triples, compact UTF-8 JSON, SHA-256.
fn independent_snapshot_digest(conn: &Conn, key: &[u8]) -> String {
    let select = INPUT_SNAPSHOT_COLUMNS.join(", ");
    let row: Vec<Value> = conn
        .query_row_map(
            &format!("SELECT {select} FROM source_inputs WHERE input_key = ?1"),
            &[Value::Blob(key.to_vec())],
            |row| {
                let mut values = Vec::new();
                for index in 0..31 {
                    values.push(row.get_value(index)?);
                }
                Ok(values)
            },
        )
        .expect("snapshot columns");
    let mut triples = Vec::new();
    for (name, value) in INPUT_SNAPSHOT_COLUMNS.iter().zip(row.iter()) {
        let (tag, encoded) = match value {
            Value::Blob(bytes) => {
                let mut hex = String::new();
                for byte in bytes {
                    hex.push_str(&format!("{byte:02x}"));
                }
                ("b", Json::String(hex))
            }
            Value::Text(text) => ("s", Json::String(text.clone())),
            Value::Null => ("n", Json::Null),
            other => panic!("unexpected snapshot type: {other:?}"),
        };
        triples.push(json!([name, tag, encoded]));
    }
    let mut root = vec![json!(INPUT_HEADER_SNAPSHOT_DOMAIN)];
    root.extend(triples);
    let bytes = serde_json::to_vec(&Json::Array(root)).expect("snapshot json");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut hex = String::new();
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

// ---------------------------------------------------------------------------
// Full-DTO assertions against independent SQL rows and the frozen literals
// ---------------------------------------------------------------------------

fn value_blob(value: &Value) -> &[u8] {
    match value {
        Value::Blob(bytes) => bytes,
        other => panic!("expected BLOB, got {other:?}"),
    }
}

fn value_text(value: &Value) -> &str {
    match value {
        Value::Text(text) => text,
        other => panic!("expected TEXT, got {other:?}"),
    }
}

fn value_opt_text(value: &Value) -> Option<&str> {
    match value {
        Value::Text(text) => Some(text),
        Value::Null => None,
        other => panic!("expected TEXT or NULL, got {other:?}"),
    }
}

fn value_opt_blob(value: &Value) -> Option<&[u8]> {
    match value {
        Value::Blob(bytes) => Some(bytes),
        Value::Null => None,
        other => panic!("expected BLOB or NULL, got {other:?}"),
    }
}

fn value_digest(value: &Value) -> Sha256Digest {
    Sha256Digest::from_slice(value_blob(value)).expect("32-byte digest")
}

fn value_opt_digest(value: &Value) -> Option<Sha256Digest> {
    value_opt_blob(value).map(|bytes| Sha256Digest::from_slice(bytes).expect("32-byte digest"))
}

fn value_u64(value: &Value) -> u64 {
    u64::from_be_bytes(value_blob(value).try_into().expect("8-byte ordinal"))
}

fn value_opt_u64(value: &Value) -> Option<u64> {
    value_opt_blob(value).map(|bytes| u64::from_be_bytes(bytes.try_into().expect("8-byte ordinal")))
}

fn value_opt_i64(value: &Value) -> Option<i64> {
    match value {
        Value::Integer(number) => Some(*number),
        Value::Null => None,
        other => panic!("expected INTEGER or NULL, got {other:?}"),
    }
}

fn value_opt_text_blob(value: &Value) -> Option<String> {
    value_opt_blob(value).map(|bytes| String::from_utf8(bytes.to_vec()).expect("stored text blob"))
}

/// Some optional text columns are stored as UTF-8 BLOB bytes by the public
/// staging path; accept both representations here.
fn value_opt_string(value: &Value) -> Option<String> {
    match value {
        Value::Text(text) => Some(text.clone()),
        Value::Blob(bytes) => Some(String::from_utf8(bytes.clone()).expect("stored text blob")),
        Value::Null => None,
        other => panic!("expected TEXT/BLOB or NULL, got {other:?}"),
    }
}

fn tree_of(bytes: &[u8]) -> LosslessSourceValue {
    LosslessSourceValue::parse(bytes).expect("stored lossless tree")
}

fn input_columns(conn: &Conn, key: &Sha256Digest) -> Vec<Value> {
    let select = INPUT_SNAPSHOT_COLUMNS.join(", ");
    conn.query_row_map(
        &format!("SELECT {select} FROM source_inputs WHERE input_key = ?1"),
        &[Value::Blob(key.as_bytes().to_vec())],
        |row| {
            let mut values = Vec::with_capacity(31);
            for index in 0..31 {
                values.push(row.get_value(index)?);
            }
            Ok(values)
        },
    )
    .expect("input SQL row")
}

fn record_columns(conn: &Conn, key: &Sha256Digest, ordinal: u64) -> (i64, Vec<Value>) {
    conn.query_row_map(
        "SELECT id, ordinal, record_pointer, position_bin, expected_source_record_sha256, \
         observed_source_record_sha256, frame_state, parse_state, record_mapping_state, \
         safety_state, retention_state, codec, payload_bin, safe_value_hash, native_ids_bin, \
         diagnostics_bin FROM source_records \
         WHERE input_id = (SELECT id FROM source_inputs WHERE input_key = ?1) AND ordinal = ?2",
        &[
            Value::Blob(key.as_bytes().to_vec()),
            Value::Blob(u64_be8(ordinal).to_vec()),
        ],
        |row| {
            let row_id: i64 = row.get_typed(0)?;
            let mut values = Vec::with_capacity(15);
            for index in 1..=15 {
                values.push(row.get_value(index)?);
            }
            Ok((row_id, values))
        },
    )
    .expect("record SQL row")
}

fn link_columns(conn: &Conn, record_id: i64) -> Vec<Vec<Value>> {
    conn.query_all_map(
        "SELECT projection_key, binding_digest, source_positions_bin, authority, message_id, \
         conversation_ordinal, final_message_idx, projection_pointer, evidence_kind \
         FROM source_message_links WHERE record_id = ?1 ORDER BY projection_key ASC",
        &[Value::Integer(record_id)],
        |row| {
            let mut values = Vec::with_capacity(9);
            for index in 0..9 {
                values.push(row.get_value(index)?);
            }
            Ok(values)
        },
    )
    .expect("link SQL rows")
}

/// Every public `SourceFactsInput` field, checked against the independent SQL
/// row (and the frozen sealed bytes / public manifest decoder).
fn assert_input_full(
    input: &coding_agent_search::storage::source_facts::SourceFactsInput,
    key: &Sha256Digest,
    sealed: &[u8],
    conn: &Conn,
) {
    let cols = input_columns(conn, key);
    assert_eq!(cols.len(), 31);
    assert_eq!(input.input_key, *key);
    let tuple_json: Json = serde_json::from_slice(value_blob(&cols[1])).expect("tuple json");
    let expected_tuple: Vec<Option<String>> = tuple_json
        .as_array()
        .expect("tuple array")
        .iter()
        .map(|item| match item {
            Json::Null => None,
            Json::String(text) => Some(text.clone()),
            other => panic!("unexpected tuple element {other:?}"),
        })
        .collect();
    assert_eq!(input.identity_tuple, expected_tuple);
    assert_eq!(input.identity_namespace, value_text(&cols[3]));
    assert_eq!(input.source_id, value_text(&cols[2]));
    assert_eq!(input.connector, value_text(&cols[4]));
    assert_eq!(input.origin_host, value_opt_string(&cols[5]));
    assert_eq!(input.origin_source_version, value_opt_string(&cols[6]));
    assert_eq!(input.role, value_opt_text_blob(&cols[7]));
    assert_eq!(input.platform, value_opt_text_blob(&cols[8]));
    assert_eq!(
        input.root_id,
        std::str::from_utf8(value_blob(&cols[9])).expect("root utf8")
    );
    assert_eq!(
        input.relative_locator,
        std::str::from_utf8(value_blob(&cols[10])).expect("locator utf8")
    );
    assert_eq!(input.discovery, tree_of(value_blob(&cols[11])));
    assert_eq!(input.parser_context, tree_of(value_blob(&cols[12])));
    assert_eq!(input.sealed_ref, tree_of(value_blob(&cols[14])));
    assert_eq!(input.context_digest, value_digest(&cols[13]));
    assert_eq!(
        input.context_digest,
        context_digest(&input.parser_context).expect("context digest")
    );
    assert_eq!(input.sealed_sha256, value_digest(&cols[15]));
    assert_eq!(input.sealed_sha256, Sha256Digest::of(sealed));
    assert_eq!(input.byte_len, value_u64(&cols[16]));
    assert_eq!(input.byte_len, sealed.len() as u64);
    assert_eq!(input.format.as_str(), value_text(&cols[17]));
    let (manifest, safety) =
        decode_expected_manifest_header(value_blob(&cols[18])).expect("manifest header");
    assert_eq!(
        input.expected_manifest.manifest.verifier_version(),
        manifest.verifier_version()
    );
    assert_eq!(
        input.expected_manifest.manifest.sealed_sha256(),
        manifest.sealed_sha256()
    );
    assert_eq!(
        input.expected_manifest.manifest.byte_len(),
        manifest.byte_len()
    );
    assert_eq!(input.expected_manifest.manifest.format(), manifest.format());
    assert_eq!(
        input.expected_manifest.manifest.records(),
        manifest.records()
    );
    assert_eq!(
        input.expected_manifest.manifest.blank_lines(),
        manifest.blank_lines()
    );
    assert_eq!(
        input.expected_manifest.manifest.framing_sha256(),
        manifest.framing_sha256()
    );
    assert_eq!(
        input.expected_manifest.manifest.complete(),
        manifest.complete()
    );
    assert_eq!(
        input.expected_manifest.manifest.blank_bytes(),
        manifest.blank_bytes()
    );
    assert_eq!(
        input.expected_manifest.safety.code_version(),
        safety.code_version()
    );
    assert_eq!(
        input.expected_manifest.safety.desensitization_enabled(),
        safety.desensitization_enabled()
    );
    assert_eq!(
        input.expected_manifest.safety.config_source_identity(),
        safety.config_source_identity()
    );
    assert_eq!(
        input.expected_manifest.safety.fixed_config_sha256(),
        safety.fixed_config_sha256()
    );
    assert_eq!(
        input
            .expected_manifest
            .safety
            .effective_four_arrays_sha256(),
        safety.effective_four_arrays_sha256()
    );
    assert_eq!(input.normalizer_id, value_text(&cols[19]));
    assert_eq!(input.safety_contract_id, value_text(&cols[20]));
    assert_eq!(input.state, value_text(&cols[21]));
    assert_eq!(input.expected_records, value_u64(&cols[22]));
    assert_eq!(input.expected_blank_lines, value_u64(&cols[23]));
    assert_eq!(input.observed_records, value_opt_u64(&cols[24]));
    assert_eq!(input.observed_blank_lines, value_opt_u64(&cols[25]));
    assert_eq!(
        input.unprocessed_ranges,
        value_opt_blob(&cols[26]).map(|bytes| rmp_serde::from_slice::<UnprocessedRangesEnvelope>(
            bytes
        )
        .expect("ranges envelope"))
    );
    assert_eq!(
        input.attempt_history,
        value_opt_blob(&cols[27]).map(|bytes| {
            rmp_serde::from_slice::<AttemptHistory>(bytes).expect("attempt history")
        })
    );
    assert_eq!(input.activation_request_hash, value_opt_digest(&cols[28]));
    assert_eq!(input.receipt_key.as_deref(), value_opt_text(&cols[29]));
    assert_eq!(
        input.applied_content_generation.as_deref(),
        value_opt_text(&cols[30])
    );
    assert_eq!(input.origin_kind, expected_tuple[7].clone());
}

/// Every public `RawSourceFactsRecord` field plus every link, checked against
/// the independent SQL rows and the frozen sealed bytes.
fn assert_record_full(
    record: &coding_agent_search::storage::source_facts::RawSourceFactsRecord,
    key: &Sha256Digest,
    sealed: &[u8],
    conn: &Conn,
) {
    let (row_id, cols) = record_columns(conn, key, record.ordinal);
    assert_eq!(record.input_key, *key);
    assert_eq!(record.record_pointer, value_text(&cols[1]));
    let position: Json = serde_json::from_slice(value_blob(&cols[2])).expect("position json");
    let parts = position.as_array().expect("position array");
    let start: u64 = parts[2]
        .as_str()
        .expect("byte_start")
        .parse()
        .expect("start");
    let end: u64 = parts[3].as_str().expect("byte_end").parse().expect("end");
    assert_eq!(record.byte_start, start);
    assert_eq!(record.byte_end, end);
    assert_eq!(record.record_byte_len, end - start);
    assert_eq!(record.expected_source_record_sha256, value_digest(&cols[3]));
    assert_eq!(
        record.expected_source_record_sha256,
        Sha256Digest::of(&sealed[start as usize..end as usize])
    );
    assert_eq!(
        record.observed_source_record_sha256,
        value_opt_digest(&cols[4])
    );
    assert_eq!(record.frame_state, value_text(&cols[5]));
    assert_eq!(record.parse_state, value_text(&cols[6]));
    assert_eq!(record.record_mapping_state, value_text(&cols[7]));
    assert_eq!(record.safety_state, value_text(&cols[8]));
    assert_eq!(record.retention_state, value_text(&cols[9]));
    assert_eq!(record.codec.as_deref(), value_opt_text(&cols[10]));
    let payload = value_opt_blob(&cols[11]);
    assert_eq!(record.payload.as_deref(), payload);
    match payload {
        Some(bytes) => {
            assert_eq!(record.payload_sha256, Some(Sha256Digest::of(bytes)));
            let decoded = decode_safe_source(bytes).expect("safe source");
            assert_eq!(record.safe_value.as_ref(), Some(decoded.value()));
            let mut canonical = Vec::new();
            decoded
                .value()
                .write_canonical(&mut canonical)
                .expect("canonical safe tree");
            assert_eq!(record.safe_value_hash, Some(Sha256Digest::of(&canonical)));
        }
        None => {
            assert!(record.payload_sha256.is_none());
            assert!(record.safe_value.is_none());
            assert!(record.safe_value_hash.is_none());
        }
    }
    assert_eq!(record.safe_value_hash, value_opt_digest(&cols[12]));
    assert_eq!(record.native_ids, value_opt_blob(&cols[13]).map(tree_of));
    assert_eq!(
        record.diagnostics,
        value_opt_blob(&cols[14]).map(|bytes| {
            rmp_serde::from_slice::<DiagnosticsEnvelope>(bytes).expect("diagnostics")
        })
    );
    assert_links_full(&record.links, conn, row_id);
}

fn assert_links_full(
    links: &[coding_agent_search::storage::source_facts::SourceFactsRecordLink],
    conn: &Conn,
    record_id: i64,
) {
    let rows = link_columns(conn, record_id);
    assert_eq!(links.len(), rows.len(), "one DTO link per SQL link row");
    for (link, cols) in links.iter().zip(rows.iter()) {
        let evidence: LinkEvidence =
            rmp_serde::from_slice(value_blob(&cols[2])).expect("link evidence");
        assert_eq!(link.claim, evidence.claim);
        assert_eq!(link.original_installation, evidence.installation);
        let expected_digest = match &evidence.installation {
            Some(installation) => binding_digest(&evidence.claim, installation),
            None => evidence.claim.pending_claim_digest(),
        };
        assert_eq!(link.binding_digest, expected_digest);
        assert_eq!(link.authority.as_deref(), value_opt_text(&cols[3]));
        assert_eq!(link.message_id, value_opt_i64(&cols[4]));
    }
}

// ---------------------------------------------------------------------------
// r01–r05: empty library, empty input and the fixed catalog
// ---------------------------------------------------------------------------

#[test]
fn r01_empty_library() {
    let (_dir, db) = db_path("r01");
    FrankenStorage::open(&db)
        .expect("create schema9")
        .close()
        .expect("close");
    let reader = SourceFactsReader::open(&db).expect("open reader");
    for scope in [
        SourceFactsScope::Analysis,
        SourceFactsScope::HistoryUnresolved,
        SourceFactsScope::AllSource,
    ] {
        let filter = SourceFactsFilter {
            scope,
            ..Default::default()
        };
        let page = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect("empty page");
        assert_eq!(page.reader_version, 2, "{scope:?}: version");
        assert!(page.inputs.is_empty(), "{scope:?}: no headers");
        assert!(page.records.is_empty(), "{scope:?}: no records");
        assert!(page.next_cursor.is_none(), "{scope:?}: EOF");
    }
}

#[test]
fn r02_empty_published_input() {
    let (_dir, db) = db_path("r02");
    let key = publish_empty(&db, "C10_EMPTY_SINGLE", "C10_NORMALIZER", "C10_SAFETY");
    let reader = SourceFactsReader::open(&db).expect("open reader");
    for scope in [
        SourceFactsScope::Analysis,
        SourceFactsScope::HistoryUnresolved,
        SourceFactsScope::AllSource,
    ] {
        let filter = SourceFactsFilter {
            scope,
            ..Default::default()
        };
        let pages = collect(&reader, &filter, SourceFactsPageLimits::default());
        assert_eq!(pages.len(), 1, "{scope:?}: one page");
        assert_eq!(pages[0].inputs.len(), 1, "{scope:?}: one real header");
        assert_eq!(pages[0].inputs[0].input_key, key, "{scope:?}: header key");
        assert!(
            pages[0].records.is_empty(),
            "{scope:?}: no fabricated ordinal 0"
        );
        assert!(pages[0].next_cursor.is_none(), "{scope:?}: EOF");
    }

    // Full input fields: a completed empty input exposes the receipt,
    // generation and activation hash Some side and no failure envelopes.
    let conn = Conn::open_read(&db).expect("SQL side");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("full page");
    assert_input_full(&page.inputs[0], &key, b"", &conn);
    assert_eq!(page.inputs[0].observed_records, Some(0));
    assert_eq!(page.inputs[0].observed_blank_lines, Some(0));
    assert!(page.inputs[0].unprocessed_ranges.is_none());
    assert!(
        page.inputs[0].attempt_history.is_some(),
        "a completed activation records its success attempt"
    );
    assert!(page.inputs[0].activation_request_hash.is_some());
    assert!(page.inputs[0].receipt_key.is_some());
    assert!(page.inputs[0].applied_content_generation.is_some());
}

#[test]
fn r03_catalog_default_pages() {
    let (_dir, db) = db_path("r03");
    let dense = publish_catalog(&db);
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let pages = collect(&reader, &filter, SourceFactsPageLimits::default());
    assert_eq!(pages.len(), 2, "default limits take two pages");

    let first = &pages[0];
    assert_eq!(first.inputs.len(), 64, "first page headers");
    assert_eq!(first.records.len(), 64, "first page records");
    assert_eq!(
        ordinals(&pages[..1]),
        (1..=64).collect::<Vec<u64>>(),
        "first page ordinals"
    );
    assert!(
        first.records.iter().all(|record| record.input_key == dense),
        "first page record input"
    );
    assert!(first.next_cursor.is_some(), "first page continues");

    let second = &pages[1];
    assert_eq!(second.inputs.len(), 3, "second page headers");
    assert_eq!(second.records.len(), 1, "second page records");
    assert_eq!(second.records[0].ordinal, 65, "second page ordinal");
    assert_eq!(
        second.records[0].input_key, dense,
        "second page record input"
    );
    assert!(second.next_cursor.is_none(), "second page is EOF");

    let mut headers: Vec<Sha256Digest> = pages
        .iter()
        .flat_map(|page| page.inputs.iter().map(|input| input.input_key))
        .collect();
    headers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let before = headers.len();
    headers.dedup();
    assert_eq!(headers.len(), 66, "66 unique headers");
    assert_eq!(
        before, 67,
        "the dense header repeats on page two, so 67 entries"
    );
    let records = ordinals(&pages);
    assert_eq!(
        records,
        (1..=65).collect::<Vec<u64>>(),
        "65 unique records without duplicates"
    );
}

#[test]
fn r04_catalog_header_limit_one() {
    let (_dir, db) = db_path("r04");
    let dense = publish_catalog(&db);
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let limits = SourceFactsPageLimits {
        max_records: 1,
        target_bytes: 8_388_608,
    };
    let pages = collect(&reader, &filter, limits);
    assert_eq!(
        pages.len(),
        130,
        "130 pages at one header/one record per page"
    );

    let leading = pages
        .iter()
        .take_while(|page| page.records.is_empty())
        .count();
    assert_eq!(leading, 63, "63 leading empty headers");
    let trailing = pages
        .iter()
        .rev()
        .take_while(|page| page.records.is_empty())
        .count();
    assert_eq!(trailing, 2, "two trailing empty headers");

    let record_pages: Vec<&RawSourceFactsPage> = pages
        .iter()
        .filter(|page| !page.records.is_empty())
        .collect();
    assert_eq!(record_pages.len(), 65, "65 dense record pages");
    let ords: Vec<u64> = record_pages
        .iter()
        .map(|page| page.records[0].ordinal)
        .collect();
    assert_eq!(
        ords,
        (1..=65).collect::<Vec<u64>>(),
        "records 1..65 in order"
    );
    for page in &record_pages {
        assert_eq!(page.records.len(), 1, "exactly one record per dense page");
        assert_eq!(
            page.inputs.len(),
            1,
            "dense header repeats on each record page"
        );
        assert_eq!(page.inputs[0].input_key, dense);
        assert_eq!(page.oversized_records, 0, "no record is oversized");
    }
    assert!(
        pages.last().expect("last page").next_cursor.is_none(),
        "last page is EOF"
    );

    // A corrupt second header must fail only on the page that requests it:
    // with limit 1 the first page emits the legal header and a cursor, and the
    // second page reaches the corrupt header and refuses it.
    let (_dir, cap_db) = db_path("r04-header-cap");
    let a = publish_empty(&cap_db, "C10_CAP_A", "C10_NORMALIZER", "C10_SAFETY");
    let b = publish_empty(&cap_db, "C10_CAP_B", "C10_NORMALIZER", "C10_SAFETY");
    let (first_key, second_key) = if a.as_bytes() < b.as_bytes() {
        (a, b)
    } else {
        (b, a)
    };
    corrupt(
        &cap_db,
        "UPDATE source_inputs SET source_id = 'C10_CAP_BROKEN' WHERE input_key = ?1",
        &[Value::Blob(second_key.as_bytes().to_vec())],
    );
    let reader = SourceFactsReader::open(&cap_db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let limits = SourceFactsPageLimits {
        max_records: 1,
        target_bytes: 8_388_608,
    };
    let first_page = reader
        .read_raw_source_facts(&filter, None, limits)
        .expect("the first page does not touch the corrupt header");
    assert_eq!(first_page.inputs.len(), 1);
    assert_eq!(first_page.inputs[0].input_key, first_key);
    assert!(first_page.records.is_empty());
    let cursor = first_page.next_cursor.clone().expect("first page cursor");
    let error = reader
        .read_raw_source_facts(&filter, Some(&cursor), limits)
        .expect_err("the second page reaches the corrupt header");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::DecodeFailed);
    assert_eq!(reason(&error), "invalid_input_metadata");
}

#[test]
fn r05_catalog_byte_target_20() {
    let (_dir, db) = db_path("r05");
    let dense = publish_catalog(&db);
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let limits = SourceFactsPageLimits {
        max_records: 64,
        target_bytes: 20,
    };
    let pages = collect(&reader, &filter, limits);

    let record_pages: Vec<&RawSourceFactsPage> = pages
        .iter()
        .filter(|page| !page.records.is_empty())
        .collect();
    assert_eq!(record_pages.len(), 65, "65 pages carry records");
    let mut oversized_pages = Vec::new();
    let mut oversized_total = 0u64;
    for (index, page) in record_pages.iter().enumerate() {
        assert_eq!(
            page.records.len(),
            1,
            "target 20 leaves one record per page"
        );
        assert_eq!(page.records[0].ordinal, index as u64 + 1, "record order");
        if page.oversized_records == 1 {
            oversized_pages.push(index + 1);
            oversized_total += page.oversized_records;
        }
        if page.records[0].ordinal <= 10 {
            assert_eq!(
                page.records[0].record_byte_len, 20,
                "records 1..10 are 20 bytes"
            );
            assert_eq!(page.oversized_records, 0, "20 bytes is not oversized");
        } else {
            assert_eq!(
                page.records[0].record_byte_len, 21,
                "records 11..65 are 21 bytes"
            );
        }
    }
    assert_eq!(
        oversized_pages,
        (11..=65).collect::<Vec<usize>>(),
        "records 11..65 are oversized"
    );
    assert_eq!(oversized_total, 55, "oversized sum is 55");

    for page in pages.iter().filter(|page| page.records.is_empty()) {
        assert_eq!(
            page.oversized_records, 0,
            "header-only pages never count an oversized record"
        );
    }
    let mut headers: Vec<Sha256Digest> = pages
        .iter()
        .flat_map(|page| page.inputs.iter().map(|input| input.input_key))
        .collect();
    headers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    headers.dedup();
    assert_eq!(headers.len(), 66, "all 66 headers are reached");
    assert!(headers.contains(&dense), "dense input header reached");
    let last_page = pages.last().expect("last page");
    assert!(
        last_page.next_cursor.is_none(),
        "EOF after both trailing headers"
    );
    assert!(
        last_page.records.is_empty(),
        "trailing headers finish the traversal"
    );

    // Cross-input ordinary overflow: two independent 20-byte records must not
    // share a 30-byte page. The first page carries one record; the second
    // input is left untouched and starts the next page.
    let (_dir, multi_db) = db_path("r05-cross-input");
    let key_a = publish_one(&multi_db, "C10_MULTI_A", true);
    let key_b = publish_one(&multi_db, "C10_MULTI_B", true);
    let reader = SourceFactsReader::open(&multi_db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let limits = SourceFactsPageLimits {
        max_records: 64,
        target_bytes: 30,
    };
    let pages = collect(&reader, &filter, limits);
    assert_eq!(pages.len(), 2, "one record per page");
    assert_eq!(pages[0].records.len(), 1);
    assert_eq!(pages[1].records.len(), 1);
    assert_eq!(pages[0].records[0].record_byte_len, 20);
    assert_eq!(pages[1].records[0].record_byte_len, 20);
    assert_eq!(pages[0].oversized_records + pages[1].oversized_records, 0);
    let page_keys: Vec<Sha256Digest> = pages
        .iter()
        .flat_map(|page| page.inputs.iter().map(|input| input.input_key))
        .collect();
    assert_eq!(page_keys.len(), 2);
    assert!(
        page_keys.contains(&key_a) && page_keys.contains(&key_b),
        "both keys are reached"
    );
    assert!(
        pages.last().expect("last").next_cursor.is_none(),
        "EOF after two records"
    );

    // A second record that is itself oversized stays alone on the next page.
    let (_dir, cross_db) = db_path("r05-cross-oversized");
    let normal = publish_one_sealed(
        &cross_db,
        "C10_CROSS_NORMAL_3",
        b"{\"n\":0,\"body\":\"C10\"}\n",
        true,
    );
    let large = publish_one_sealed(
        &cross_db,
        "C10_CROSS_LARGE_3",
        b"{\"n\":11,\"body\":\"C10\"}\n",
        true,
    );
    assert_eq!(
        normal.hex(),
        "831b2ea3577992242dbac8f901d2a1e5130ec212d206ebb26b6c95376edced05",
        "frozen normal key"
    );
    assert_eq!(
        large.hex(),
        "a08a41eb3edcad62e00df0f2360b7767467dfce6f6df19fe929445ad59362435",
        "frozen large key"
    );
    assert!(
        normal.as_bytes() < large.as_bytes(),
        "normal sorts before large"
    );
    let reader = SourceFactsReader::open(&cross_db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let limits = SourceFactsPageLimits {
        max_records: 64,
        target_bytes: 20,
    };
    let pages = collect(&reader, &filter, limits);
    assert_eq!(pages.len(), 2, "normal page then oversized page");
    assert_eq!(pages[0].records.len(), 1);
    assert_eq!(pages[0].records[0].input_key, normal);
    assert_eq!(pages[0].records[0].record_byte_len, 20);
    assert_eq!(pages[0].oversized_records, 0);
    assert_eq!(pages[1].records.len(), 1);
    assert_eq!(pages[1].records[0].input_key, large);
    assert_eq!(pages[1].records[0].record_byte_len, 21);
    assert_eq!(pages[1].oversized_records, 1);
    assert!(pages.last().expect("last").next_cursor.is_none());
}

// ---------------------------------------------------------------------------
// r06–r09: scopes, real public forget, valid unmapped/unresolved links
// ---------------------------------------------------------------------------

fn scope_ordinals(
    reader: &SourceFactsReader,
    scope: SourceFactsScope,
) -> (Vec<u64>, Vec<RawSourceFactsPage>) {
    let filter = SourceFactsFilter {
        scope,
        ..Default::default()
    };
    let pages = collect(reader, &filter, SourceFactsPageLimits::default());
    (ordinals(&pages), pages)
}

#[test]
fn r06_scope_before_public_forget() {
    let (_dir, db) = db_path("r06");
    let key = publish_scope(&db);
    let reader = SourceFactsReader::open(&db).expect("open reader");

    let (analysis, analysis_pages) = scope_ordinals(&reader, SourceFactsScope::Analysis);
    let (history, history_pages) = scope_ordinals(&reader, SourceFactsScope::HistoryUnresolved);
    let (all, all_pages) = scope_ordinals(&reader, SourceFactsScope::AllSource);
    assert_eq!(analysis, vec![1, 3], "analysis before forget");
    assert_eq!(history, vec![2], "history before forget");
    assert_eq!(all, vec![1, 2, 3], "all_source before forget");
    assert_eq!(
        all_pages[0].source_facts_revision, 1,
        "revision before forget"
    );
    for page in [&analysis_pages[0], &history_pages[0], &all_pages[0]] {
        assert_eq!(page.inputs.len(), 1, "each scope returns the input header");
        assert_eq!(page.inputs[0].input_key, key);
        assert_eq!(page.inputs[0].state, "complete");
    }

    let mixed = all_pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 1)
        .expect("record 1");
    let mut authorities: Vec<&str> = mixed
        .links
        .iter()
        .map(|link| link.authority.as_deref().expect("authority"))
        .collect();
    authorities.sort_unstable();
    assert_eq!(
        authorities,
        vec!["canonical", "standalone"],
        "record 1 keeps both links"
    );
    assert_eq!(mixed.record_mapping_state, "mixed");
    assert_eq!(mixed.links.len(), 2);
    let canonical = mixed
        .links
        .iter()
        .find(|link| link.authority.as_deref() == Some("canonical"))
        .expect("canonical link");
    assert_eq!(canonical.message_id, Some(7));
    assert!(canonical.original_installation.is_some());

    let record3 = all_pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 3)
        .expect("record 3");
    assert_eq!(record3.record_mapping_state, "all_canonical");
    assert_eq!(record3.links[0].authority.as_deref(), Some("canonical"));

    // Complete input fields and every raw record field, against the
    // independent SQL rows and the frozen sealed bytes.
    let conn = Conn::open_read(&db).expect("SQL side");
    let input = &all_pages[0].inputs[0];
    assert_input_full(input, &key, SCOPE_SEALED, &conn);
    assert_eq!(input.origin_kind.as_deref(), Some("local"));
    assert_eq!(input.origin_host.as_deref(), Some("C10_HOST"));
    assert_eq!(
        input.origin_source_version.as_deref(),
        Some("C10_SOURCE_VERSION")
    );
    assert_eq!(input.role.as_deref(), Some("primary_session_log"));
    assert_eq!(input.platform.as_deref(), Some("linux"));
    assert_ne!(input.discovery, input.parser_context);
    assert_ne!(input.parser_context, input.sealed_ref);
    assert!(input.activation_request_hash.is_some());
    assert!(input.receipt_key.is_some());
    assert!(input.applied_content_generation.is_some());
    assert!(input.unprocessed_ranges.is_none());
    assert!(input.attempt_history.is_some());

    assert_eq!(all_pages[0].records.len(), 3);
    for record in &all_pages[0].records {
        assert_record_full(record, &key, SCOPE_SEALED, &conn);
    }
    let record1 = all_pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 1)
        .expect("record 1");
    assert_eq!(record1.links.len(), 2);
    for link in &record1.links {
        assert_eq!(link.claim.input_key, key);
        assert_eq!(link.claim.record_ordinal, 1);
        assert_eq!(link.claim.record_pointer, "");
        match link.claim.mapping_state {
            ClaimMappingState::Canonical => {
                assert_eq!(link.claim.conversation_ordinal, Some(0));
                assert_eq!(link.claim.final_message_idx, Some(0));
                assert_eq!(
                    link.claim.projection_pointer.as_deref(),
                    Some("/messages/0")
                );
                assert_eq!(link.claim.evidence_kind, EvidenceKind::Prose);
                assert_eq!(link.authority.as_deref(), Some("canonical"));
                assert_eq!(link.message_id, Some(7));
                let installation = link.original_installation.as_ref().expect("installation");
                assert_eq!(installation.class, InstallationClass::CanonicalBound);
                let binding = installation.binding.as_ref().expect("binding");
                assert_eq!(binding.original_conversation_id, 1);
                assert_eq!(binding.original_message_id, 7);
                assert_eq!(binding.stored_idx, 0);
                assert_eq!(binding.safe_content_sha256, Sha256Digest::of(b"hello"));
            }
            ClaimMappingState::Standalone => {
                assert_eq!(link.claim.conversation_ordinal, None);
                assert_eq!(link.claim.final_message_idx, None);
                assert_eq!(link.claim.projection_pointer, None);
                assert_eq!(link.claim.evidence_kind, EvidenceKind::NoMessage);
                assert_eq!(link.authority.as_deref(), Some("standalone"));
                assert_eq!(link.message_id, None);
                let installation = link.original_installation.as_ref().expect("installation");
                assert_eq!(installation.class, InstallationClass::StandaloneNoBinding);
            }
            other => panic!("unexpected record-1 claim state {other:?}"),
        }
    }
}

fn sql_snapshot(db: &Path) -> Vec<(u64, String, String, String)> {
    let conn = Conn::open_read(db).expect("open for SQL snapshot");
    let mut rows: Vec<(u64, String, String, String)> = conn
        .query_all_map(
            "SELECT ordinal, record_pointer,
                    hex(source_positions_bin), hex(binding_digest)
             FROM source_records r JOIN source_message_links l ON l.record_id = r.id
             ORDER BY ordinal, record_pointer, projection_key",
            &[],
            |row| {
                let ordinal: Vec<u8> = row.get_typed(0)?;
                let pointer: String = row.get_typed(1)?;
                let positions: String = row.get_typed(2)?;
                let digest: String = row.get_typed(3)?;
                Ok((
                    u64::from_be_bytes(ordinal.try_into().expect("ordinal width")),
                    pointer,
                    positions,
                    digest,
                ))
            },
        )
        .expect("snapshot rows");
    rows.sort();
    rows
}

#[test]
fn r07_scope_after_public_forget() {
    let (_dir, db) = db_path("r07");
    let before_db = db.with_extension("before.db");
    publish_scope(&db);
    std::fs::copy(&db, &before_db).expect("copy before");
    let before_snapshot = sql_snapshot(&db);

    // Take an analysis cursor that names record 1 before the revision moves.
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::Analysis,
        ..Default::default()
    };
    let first = reader
        .read_raw_source_facts(
            &filter,
            None,
            SourceFactsPageLimits {
                max_records: 1,
                target_bytes: 8_388_608,
            },
        )
        .expect("first analysis page");
    let old_cursor = first.next_cursor.clone().expect("analysis cursor");
    drop(reader);

    let storage = FrankenStorage::open(&db).expect("open writer");
    storage
        .forget_conversations_by_source_glob("/synthetic/c10-canonical/*", false)
        .expect("public forget");
    storage.close().expect("close");

    let reader = SourceFactsReader::open(&db).expect("reopen reader");
    let (analysis, _) = scope_ordinals(&reader, SourceFactsScope::Analysis);
    let (history, _) = scope_ordinals(&reader, SourceFactsScope::HistoryUnresolved);
    let (all, all_pages) = scope_ordinals(&reader, SourceFactsScope::AllSource);
    assert_eq!(analysis, vec![1], "analysis after forget");
    assert_eq!(history, vec![1, 2, 3], "history after forget");
    assert_eq!(all, vec![1, 2, 3], "all_source after forget");
    assert_eq!(
        all_pages[0].source_facts_revision, 2,
        "revision after forget"
    );

    let record1 = all_pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 1)
        .expect("record 1");
    let mut authorities: Vec<&str> = record1
        .links
        .iter()
        .map(|link| link.authority.as_deref().expect("authority"))
        .collect();
    authorities.sort_unstable();
    assert_eq!(
        authorities,
        vec!["historical", "standalone"],
        "record 1 after forget"
    );
    let historical = record1
        .links
        .iter()
        .find(|link| link.authority.as_deref() == Some("historical"))
        .expect("historical link");
    assert_eq!(historical.message_id, None);

    let record3 = all_pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 3)
        .expect("record 3");
    assert_eq!(
        record3.record_mapping_state, "all_canonical",
        "mapping state unchanged"
    );
    assert_eq!(
        record3.links[0].authority.as_deref(),
        Some("historical"),
        "current authority moved"
    );
    assert_eq!(record3.links[0].message_id, None);

    // No duplicate record inside either scope even though record 1 now matches both.
    assert_eq!(analysis.len(), 1);
    assert_eq!(history.iter().filter(|ordinal| **ordinal == 1).count(), 1);

    let after_snapshot = sql_snapshot(&db);
    assert_eq!(
        before_snapshot, after_snapshot,
        "record bytes and witnesses unchanged"
    );

    // The old cursor is stale after the public forget.
    let error = reader
        .read_raw_source_facts(&filter, Some(&old_cursor), SourceFactsPageLimits::default())
        .expect_err("old cursor must be stale");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::StaleCursor);
    assert_eq!(reason(&error), "revision_changed");
}

#[test]
fn r08_valid_unmapped_unresolved_links() {
    let (_dir, db) = db_path("r08");
    let key = publish_boundary(&db, "installed");
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let (all, pages) = scope_ordinals(&reader, SourceFactsScope::AllSource);
    assert_eq!(
        all,
        vec![1, 2, 3],
        "failed publication is all_source visible"
    );
    let (analysis, _) = scope_ordinals(&reader, SourceFactsScope::Analysis);
    let (history, _) = scope_ordinals(&reader, SourceFactsScope::HistoryUnresolved);
    assert!(analysis.is_empty(), "failed input is not in analysis");
    assert!(history.is_empty(), "failed input is not in history");

    let input = &pages[0].inputs[0];
    assert_eq!(input.input_key, key);
    assert_eq!(input.state, "failed");
    assert_eq!(pages[0].source_facts_revision, 1);

    let record1 = pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 1)
        .expect("record 1");
    assert_eq!(record1.record_mapping_state, "all_unmapped");
    let link = &record1.links[0];
    assert_eq!(link.claim.mapping_state, ClaimMappingState::Unmapped);
    assert_eq!(link.claim.evidence_kind, EvidenceKind::ParseFailed);
    assert_eq!(link.authority.as_deref(), Some("unmapped"));
    assert_eq!(link.message_id, None);
    let installation = link.original_installation.as_ref().expect("installation");
    assert_eq!(installation.class, InstallationClass::UnmappedNoBinding);
    assert!(installation.reason.is_none());

    let record2 = pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 2)
        .expect("record 2");
    let installation = record2.links[0]
        .original_installation
        .as_ref()
        .expect("installation");
    assert_eq!(installation.class, InstallationClass::UnresolvedNoBinding);
    assert_eq!(
        installation.reason,
        Some(ReplayRejectReason::NoMatchingStoredRow)
    );
    assert_eq!(record2.links[0].authority.as_deref(), Some("unresolved"));
    assert_eq!(record2.links[0].message_id, None);

    // A published failure keeps its full input and record fields: attempt
    // history and the ranges envelope are Some, the receipt side is None.
    let conn = Conn::open_read(&db).expect("SQL side");
    assert_input_full(input, &key, SCOPE_SEALED, &conn);
    assert!(input.unprocessed_ranges.is_some());
    assert!(input.attempt_history.is_some());
    assert!(input.activation_request_hash.is_none());
    assert!(input.receipt_key.is_none());
    assert!(input.applied_content_generation.is_none());
    assert_eq!(input.observed_records, Some(3));
    for record in &pages[0].records {
        assert_record_full(record, &key, SCOPE_SEALED, &conn);
    }
}

#[test]
fn r09_pending_claims_not_no_claims() {
    let (_dir, db) = db_path("r09-pending");
    publish_boundary(&db, "pending");
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let (all, pages) = scope_ordinals(&reader, SourceFactsScope::AllSource);
    assert_eq!(
        all,
        vec![1, 2, 3],
        "pending failed publication is all_source visible"
    );
    for record in &pages[0].records {
        assert_eq!(record.record_mapping_state, "claims_pending");
        assert_eq!(record.links.len(), 1, "a pending claim is a real link row");
        let link = &record.links[0];
        assert!(
            link.original_installation.is_none(),
            "no installation was ever promised"
        );
        assert_eq!(link.authority, None, "pending authority stays NULL");
        assert_eq!(link.message_id, None);
    }
    let states: Vec<ClaimMappingState> = pages[0]
        .records
        .iter()
        .map(|record| record.links[0].claim.mapping_state)
        .collect();
    assert_eq!(
        states,
        vec![
            ClaimMappingState::Unmapped,
            ClaimMappingState::Canonical,
            ClaimMappingState::Canonical
        ],
        "the stored claims are preserved, not rewritten as no-claim"
    );

    // The SQL edge snapshot proves a pending claim is not the no-claim branch.
    let (_dir2, scope_db) = db_path("r09-edges");
    let edges = scope_db.with_extension("edges.db");
    let pending = scope_db.with_extension("pending.db");
    let key = publish_scope(&scope_db);
    build_edges(&scope_db, &edges, &pending, &key);
    let reader = SourceFactsReader::open(&pending).expect("open pending snapshot");
    let (history, hist_pages) = scope_ordinals(&reader, SourceFactsScope::HistoryUnresolved);
    assert_eq!(history, vec![1, 3], "claims_pending record is not history");
    let record2 = hist_pages[0]
        .records
        .iter()
        .map(|record| record.ordinal)
        .collect::<Vec<u64>>();
    assert!(!record2.contains(&2), "record 2 is excluded from history");
    let all_record2 = {
        let (_, all_pages) = scope_ordinals(&reader, SourceFactsScope::AllSource);
        all_pages[0]
            .records
            .iter()
            .find(|record| record.ordinal == 2)
            .expect("record 2")
            .clone()
    };
    assert_eq!(all_record2.record_mapping_state, "claims_pending");
    assert_eq!(all_record2.links[0].authority, None);
    assert!(all_record2.links[0].original_installation.is_none());
}

// ---------------------------------------------------------------------------
// r10–r14: publication boundary, explicit failures and filters
// ---------------------------------------------------------------------------

#[test]
fn r10_unpublished_partial_failed_broad() {
    for mode in ["staged_partial", "staged_failed"] {
        let (_dir, db) = db_path(&format!("r10-{mode}"));
        publish_boundary(&db, mode);
        let reader = SourceFactsReader::open(&db).expect("open reader");
        let filter = SourceFactsFilter {
            scope: SourceFactsScope::AllSource,
            ..Default::default()
        };
        let page = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect("broad page");
        assert!(
            page.inputs.is_empty(),
            "{mode}: unpublished input is skipped"
        );
        assert!(page.records.is_empty(), "{mode}: no records");
        assert_eq!(page.source_facts_revision, 0, "{mode}: revision untouched");
        assert!(page.next_cursor.is_none());
    }
}

#[test]
fn r11_unpublished_partial_failed_explicit() {
    for mode in ["staged_partial", "staged_failed"] {
        let (_dir, db) = db_path(&format!("r11-{mode}"));
        let key = publish_boundary(&db, mode);
        let reader = SourceFactsReader::open(&db).expect("open reader");
        let filter = SourceFactsFilter {
            scope: SourceFactsScope::AllSource,
            input_keys: vec![key],
            ..Default::default()
        };
        let error = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect_err("explicit unpublished input must be refused");
        assert_eq!(error.kind(), SourceFactsReadErrorCode::InputIncomplete);
        assert_eq!(reason(&error), "input_not_available_in_scope");
        assert_eq!(
            error.detail().get("input_key").and_then(Json::as_str),
            Some(key.hex().as_str())
        );
    }

    // Published control: the same explicit shape reads normally.
    let (_dir, db) = db_path("r11-control");
    let key = publish_scope(&db);
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![key],
        ..Default::default()
    };
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("published explicit read");
    assert_eq!(page.records.len(), 3);
}

#[test]
fn r12_published_failure_empty_ranges() {
    let (_dir, db) = db_path("r12");
    let key = publish_catalog(&db);
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![key],
        ..Default::default()
    };
    let pages = collect(&reader, &filter, SourceFactsPageLimits::default());
    let page = &pages[0];
    assert_eq!(page.inputs.len(), 1);
    let input = &page.inputs[0];
    assert_eq!(input.state, "failed");
    let ranges = input
        .unprocessed_ranges
        .as_ref()
        .expect("ranges envelope present");
    assert!(
        ranges.items.is_empty(),
        "an empty items list is still a publication"
    );
    let all_records: usize = pages.iter().map(|page| page.records.len()).sum();
    assert_eq!(all_records, 65, "published failure facts are visible");
}

#[test]
fn r13_filter_sets_canonical_digest() {
    let key_a =
        Sha256Digest::from_hex("478c3e19f3170b8bf14f824d535b91e46184448656990a3daf87cd7be86c73e7")
            .expect("key a");
    let key_b =
        Sha256Digest::from_hex("13a377adc8c4ef043f3581b75b9a8d77ca920bef868a0aa9a89e1cf61f0c1abe")
            .expect("key b");

    let analysis = SourceFactsFilter {
        scope: SourceFactsScope::Analysis,
        connectors: vec![],
        input_keys: vec![],
    };
    assert_eq!(
        analysis.digest().hex(),
        "5ebd9526211027945bd715204ecfd94202a48a07d775068eb1a6e120e32a7eb4"
    );

    let all = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        connectors: vec!["codex".into(), "claude_code".into(), "codex".into()],
        input_keys: vec![key_a, key_b, key_a],
    };
    let before = all.clone();
    assert_eq!(
        all.digest().hex(),
        "666b5c58d5f227f5751f81f24dc3dd6978825da08bcf1f0ac79bb786dafc88a1"
    );
    assert_eq!(all, before, "the caller's vectors are not modified");

    let history = SourceFactsFilter {
        scope: SourceFactsScope::HistoryUnresolved,
        connectors: vec!["测".into(), "codex".into(), "测".into()],
        input_keys: vec![],
    };
    assert_eq!(
        history.digest().hex(),
        "0deb81adcf5aeca5c2ca9b5e2e69aa245a5a47a4c6b13f898d2bf47dec74a39f"
    );
}

#[test]
fn r14_filter_exact_connector() {
    let (_dir, db) = db_path("r14");
    publish_scope(&db);
    let reader = SourceFactsReader::open(&db).expect("open reader");

    let exact = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        connectors: vec!["claude_code".into()],
        ..Default::default()
    };
    let page = reader
        .read_raw_source_facts(&exact, None, SourceFactsPageLimits::default())
        .expect("exact connector");
    assert_eq!(page.inputs.len(), 1, "exact connector matches");

    let alias = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        connectors: vec!["claude".into()],
        ..Default::default()
    };
    let page = reader
        .read_raw_source_facts(&alias, None, SourceFactsPageLimits::default())
        .expect("alias connector");
    assert!(
        page.inputs.is_empty(),
        "'claude' is not an alias for 'claude_code'"
    );

    let unlimited = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        connectors: vec![],
        ..Default::default()
    };
    let page = reader
        .read_raw_source_facts(&unlimited, None, SourceFactsPageLimits::default())
        .expect("empty set does not limit");
    assert_eq!(page.inputs.len(), 1);

    // An explicit key that is not available in the scope is refused.
    let (_dir2, staged_db) = db_path("r14-staged");
    let staged_key = publish_boundary(&staged_db, "staged_partial");
    let staged_reader = SourceFactsReader::open(&staged_db).expect("open staged reader");
    let explicit = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![staged_key],
        ..Default::default()
    };
    let error = staged_reader
        .read_raw_source_facts(&explicit, None, SourceFactsPageLimits::default())
        .expect_err("explicit unavailable key");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::InputIncomplete);
}

// ---------------------------------------------------------------------------
// r15–r20: cursors, reopen, rejection, drift and unrelated staging
// ---------------------------------------------------------------------------

#[test]
fn r15_cursor_reopen_roundtrip_and_eof() {
    let (_dir, db) = db_path("r15");
    let dense = publish_catalog(&db);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let filter_digest = filter.digest();

    let reader = SourceFactsReader::open(&db).expect("open reader");
    let first = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("first page");
    let cursor = first.next_cursor.clone().expect("cursor after page one");
    let parts = cursor_parts(&cursor);
    assert_eq!(parts.len(), 8);
    assert_eq!(parts[0], json!("cass.source-facts-cursor/2"));
    assert_eq!(parts[1], json!(first.library_identity));
    assert_eq!(parts[2], json!(first.source_facts_revision.to_string()));
    assert_eq!(parts[3], json!(filter_digest.hex()));
    assert_eq!(parts[4], json!(dense.hex()));
    assert_eq!(parts[5], json!("64"));
    assert_eq!(parts[6], json!(""));
    let independent =
        independent_snapshot_digest(&Conn::open_read(&db).expect("read conn"), dense.as_bytes());
    assert_eq!(
        parts[7],
        json!(independent),
        "cursor binds the raw header snapshot"
    );
    drop(reader);

    // A reopened handle continues from the same string.
    let reader = SourceFactsReader::open(&db).expect("reopen reader");
    let second = reader
        .read_raw_source_facts(&filter, Some(&cursor), SourceFactsPageLimits::default())
        .expect("second page");
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].ordinal, 65);
    assert!(second.next_cursor.is_none(), "global EOF");

    // The completion-marker position kind: one header per page.
    let limits = SourceFactsPageLimits {
        max_records: 1,
        target_bytes: 8_388_608,
    };
    let reader = SourceFactsReader::open(&db).expect("reopen reader");
    let first = reader
        .read_raw_source_facts(&filter, None, limits)
        .expect("marker page");
    assert!(
        first.records.is_empty(),
        "first page is a zero-record header"
    );
    let marker = first.next_cursor.clone().expect("marker cursor");
    let parts = cursor_parts(&marker);
    assert_eq!(parts[5], Json::Null, "completion marker ordinal is null");
    assert_eq!(parts[6], Json::Null, "completion marker pointer is null");
    let second = reader
        .read_raw_source_facts(&filter, Some(&marker), limits)
        .expect("continue after marker");
    assert_ne!(
        second.inputs[0].input_key, first.inputs[0].input_key,
        "progress, no loop"
    );
}

#[test]
fn r16_cursor_library_revision_filter_rejected() {
    // library_changed
    let (_dir, db) = db_path("r16-library");
    publish_catalog(&db);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("page");
    let cursor = page.next_cursor.clone().expect("cursor");
    drop(reader);
    let storage = FrankenStorage::open(&db).expect("writer");
    storage
        .raw()
        .execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('library_identity', 'other-library')",
            &[],
        )
        .expect("change library");
    storage.close().expect("close");
    let reader = SourceFactsReader::open(&db).expect("reader");
    let error = reader
        .read_raw_source_facts(&filter, Some(&cursor), SourceFactsPageLimits::default())
        .expect_err("library change");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::StaleCursor);
    assert_eq!(reason(&error), "library_changed");

    // revision_changed via the real public forget
    let (_dir, db) = db_path("r16-revision");
    publish_scope(&db);
    let analysis = SourceFactsFilter {
        scope: SourceFactsScope::Analysis,
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let page = reader
        .read_raw_source_facts(
            &analysis,
            None,
            SourceFactsPageLimits {
                max_records: 1,
                target_bytes: 8_388_608,
            },
        )
        .expect("page");
    let cursor = page.next_cursor.clone().expect("cursor");
    drop(reader);
    let storage = FrankenStorage::open(&db).expect("writer");
    storage
        .forget_conversations_by_source_glob("/synthetic/c10-canonical/*", false)
        .expect("forget");
    storage.close().expect("close");
    let reader = SourceFactsReader::open(&db).expect("reader");
    let error = reader
        .read_raw_source_facts(&analysis, Some(&cursor), SourceFactsPageLimits::default())
        .expect_err("revision change");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::StaleCursor);
    assert_eq!(reason(&error), "revision_changed");

    // filter_changed
    let reader = SourceFactsReader::open(&db).expect("reader");
    let changed = SourceFactsFilter {
        scope: SourceFactsScope::Analysis,
        connectors: vec!["codex".into()],
        ..Default::default()
    };
    let error = reader
        .read_raw_source_facts(&changed, Some(&cursor), SourceFactsPageLimits::default())
        .expect_err("filter change");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::InvalidCursor);
    assert_eq!(reason(&error), "filter_changed");
}

#[test]
fn r17_cursor_encoding_shape_version_rejected() {
    let (_dir, db) = db_path("r17");
    publish_catalog(&db);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("page");
    let cursor = page.next_cursor.clone().expect("cursor");

    // Non-canonical base64: padding is not part of the unpadded form.
    let padded = format!("{cursor}=");
    let error = reader
        .read_raw_source_facts(&filter, Some(&padded), SourceFactsPageLimits::default())
        .expect_err("padded cursor");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::InvalidCursor);
    assert_eq!(reason(&error), "invalid_encoding");

    let parts = cursor_parts(&cursor);
    let variants: Vec<(&str, Vec<Json>, &str)> = vec![
        (
            "pair mismatch",
            {
                let mut p = parts.clone();
                p[6] = Json::Null;
                p
            },
            "invalid_cursor_shape",
        ),
        (
            "leading zero revision",
            {
                let mut p = parts.clone();
                p[2] = json!("01");
                p
            },
            "invalid_cursor_shape",
        ),
        (
            "uppercase filter hex",
            {
                let mut p = parts.clone();
                p[3] = json!(p[3].as_str().expect("hex").to_uppercase());
                p
            },
            "invalid_cursor_shape",
        ),
        (
            "short tuple",
            {
                let mut p = parts.clone();
                p.pop();
                p
            },
            "invalid_cursor_shape",
        ),
        (
            "unknown domain",
            {
                let mut p = parts.clone();
                p[0] = json!("cass.source-facts-cursor-x/2");
                p
            },
            "invalid_cursor_shape",
        ),
    ];
    for (label, parts, expected_reason) in variants {
        let variant = cursor_from_parts(&parts);
        let error = reader
            .read_raw_source_facts(&filter, Some(&variant), SourceFactsPageLimits::default())
            .expect_err(label);
        assert_eq!(
            error.kind(),
            SourceFactsReadErrorCode::InvalidCursor,
            "{label}"
        );
        assert_eq!(reason(&error), expected_reason, "{label}");
    }

    // Whitespace inside the JSON is not the canonical compact form.
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&cursor)
        .expect("decode");
    let value: Json = serde_json::from_slice(&bytes).expect("json");
    let pretty = serde_json::to_string_pretty(&value).expect("pretty");
    let spaced = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pretty.as_bytes());
    let error = reader
        .read_raw_source_facts(&filter, Some(&spaced), SourceFactsPageLimits::default())
        .expect_err("spaced cursor");
    assert_eq!(reason(&error), "invalid_encoding");

    // A real canonical `/1` seven-tuple is an older version, not a malformed
    // `/2` eight-tuple.
    let seven = vec![
        json!("cass.source-facts-cursor/1"),
        parts[1].clone(),
        parts[2].clone(),
        parts[3].clone(),
        parts[4].clone(),
        parts[5].clone(),
        parts[6].clone(),
    ];
    let error = reader
        .read_raw_source_facts(
            &filter,
            Some(&cursor_from_parts(&seven)),
            SourceFactsPageLimits::default(),
        )
        .expect_err("legacy seven-tuple");
    assert_eq!(
        error.kind(),
        SourceFactsReadErrorCode::UnsupportedReaderVersion
    );
    assert_eq!(reason(&error), "unsupported_reader_version");
    assert_eq!(
        error.detail().get("found_version").and_then(Json::as_str),
        Some("1")
    );

    // A newer version is its own refusal too.
    let mut newer = parts.clone();
    newer[0] = json!("cass.source-facts-cursor/99");
    let error = reader
        .read_raw_source_facts(
            &filter,
            Some(&cursor_from_parts(&newer)),
            SourceFactsPageLimits::default(),
        )
        .expect_err("newer version");
    assert_eq!(
        error.kind(),
        SourceFactsReadErrorCode::UnsupportedReaderVersion
    );
    assert_eq!(
        error.detail().get("found_version").and_then(Json::as_str),
        Some("99")
    );

    // Only a canonical non-empty ASCII decimal u32 suffix is a recognised
    // version. Illegal suffixes are shape errors and must not echo their raw
    // text in detail, Display or Debug.
    for suffix in [
        "",
        "C10_PRIVATE_PATH_SENTINEL/a",
        "01",
        "+1",
        "１２",
        "4294967296",
    ] {
        let mut p = parts.clone();
        p[0] = json!(format!("cass.source-facts-cursor/{suffix}"));
        let error = reader
            .read_raw_source_facts(
                &filter,
                Some(&cursor_from_parts(&p)),
                SourceFactsPageLimits::default(),
            )
            .expect_err("illegal version suffix");
        assert_eq!(
            error.kind(),
            SourceFactsReadErrorCode::InvalidCursor,
            "suffix {suffix:?}"
        );
        assert_eq!(reason(&error), "invalid_cursor_shape", "suffix {suffix:?}");
        let rendered = format!("{error:?} {error}");
        assert!(
            !rendered.contains("C10_PRIVATE_PATH_SENTINEL"),
            "suffix raw text must not be echoed: {rendered}"
        );
        assert_eq!(
            error.detail().as_object().expect("detail").len(),
            1,
            "only reason is present for an illegal suffix"
        );
    }
}

#[test]
fn r18_cursor_position_rejected() {
    let (_dir, db) = db_path("r18");
    publish_catalog(&db);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("page");
    let cursor = page.next_cursor.clone().expect("cursor");
    let parts = cursor_parts(&cursor);

    // Unknown last key.
    let mut unknown = parts.clone();
    unknown[4] = json!("00".repeat(32));
    let error = reader
        .read_raw_source_facts(
            &filter,
            Some(&cursor_from_parts(&unknown)),
            SourceFactsPageLimits::default(),
        )
        .expect_err("unknown key");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::InvalidCursor);
    assert_eq!(reason(&error), "invalid_position");

    // Non-existent ordinal/pointer under a real key.
    for (ordinal, pointer) in [("999", ""), ("64", "not-a-pointer")] {
        let mut bad = parts.clone();
        bad[5] = json!(ordinal);
        bad[6] = json!(pointer);
        let error = reader
            .read_raw_source_facts(
                &filter,
                Some(&cursor_from_parts(&bad)),
                SourceFactsPageLimits::default(),
            )
            .expect_err("missing position");
        assert_eq!(reason(&error), "invalid_position", "ordinal {ordinal}");
    }

    // A record that exists but is not part of the queried scope.
    let (_dir2, scope_db) = db_path("r18-scope");
    publish_scope(&scope_db);
    let analysis = SourceFactsFilter {
        scope: SourceFactsScope::Analysis,
        ..Default::default()
    };
    let scope_reader = SourceFactsReader::open(&scope_db).expect("scope reader");
    let first = scope_reader
        .read_raw_source_facts(
            &analysis,
            None,
            SourceFactsPageLimits {
                max_records: 1,
                target_bytes: 8_388_608,
            },
        )
        .expect("analysis page");
    let analysis_cursor = first.next_cursor.clone().expect("analysis cursor");
    let mut parts = cursor_parts(&analysis_cursor);
    parts[5] = json!("2");
    parts[6] = json!("");
    let error = scope_reader
        .read_raw_source_facts(
            &analysis,
            Some(&cursor_from_parts(&parts)),
            SourceFactsPageLimits::default(),
        )
        .expect_err("non-scope position");
    assert_eq!(reason(&error), "invalid_position");

    // The untouched position continues correctly.
    let second = scope_reader
        .read_raw_source_facts(
            &analysis,
            Some(&analysis_cursor),
            SourceFactsPageLimits::default(),
        )
        .expect("valid continuation");
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].ordinal, 3);
}

#[test]
fn r19_header_drift_same_revision() {
    let (_dir, db) = db_path("r19");
    publish_catalog(&db);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("page");
    let cursor = page.next_cursor.clone().expect("cursor");
    let revision = page.source_facts_revision;
    assert_eq!(
        revision, 66,
        "one revision increment per catalog activation"
    );

    // Same-value replay of the published failure: attempt history changes,
    // the facts revision does not.
    let storage = FrankenStorage::open(&db).expect("writer");
    replay_dense_failure(&storage);
    storage.close().expect("close");

    let after = SourceFactsReader::open(&db).expect("new reader");
    let fresh = after
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("fresh page");
    assert_eq!(
        fresh.source_facts_revision, revision,
        "revision did not move"
    );

    for handle in [&reader, &after] {
        let error = handle
            .read_raw_source_facts(&filter, Some(&cursor), SourceFactsPageLimits::default())
            .expect_err("header drift");
        assert_eq!(error.kind(), SourceFactsReadErrorCode::StaleCursor);
        assert_eq!(reason(&error), "input_header_changed");
    }
}

#[test]
fn r20_unrelated_staging_keeps_cursor() {
    let (_dir, db) = db_path("r20");
    publish_catalog(&db);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let first = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("page one");
    let cursor = first.next_cursor.clone().expect("cursor");
    let before = collect(&reader, &filter, SourceFactsPageLimits::default());
    drop(reader);

    // Stage a new, never-published input with one record. Its header, records
    // and revision are all outside the stable all_source domain.
    let sealed = b"{\"n\":0,\"body\":\"C10\"}\n";
    let input = verified("C10_UNRELATED_STAGING", sealed);
    let records = staged_records(sealed, &[RecordMappingState::NoClaims], true);
    let storage = FrankenStorage::open(&db).expect("writer");
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
    mark_staged(&tx, staged.input_id, &records);
    tx.commit().expect("commit");
    storage.close().expect("close");

    let reader = SourceFactsReader::open(&db).expect("reopen");
    let after = collect(&reader, &filter, SourceFactsPageLimits::default());
    assert_eq!(
        ordinals(&before),
        ordinals(&after),
        "the unrelated staging does not change the visible set"
    );
    assert_eq!(
        before.iter().map(|page| page.inputs.len()).sum::<usize>(),
        after.iter().map(|page| page.inputs.len()).sum::<usize>(),
        "header set unchanged"
    );
    let continued = reader
        .read_raw_source_facts(&filter, Some(&cursor), SourceFactsPageLimits::default())
        .expect("old cursor still continues");
    assert_eq!(continued.records.len(), 1);
    assert_eq!(continued.records[0].ordinal, 65);
}

// ---------------------------------------------------------------------------
// r21–r26: metadata, observed values, codec and link evidence
// ---------------------------------------------------------------------------

fn corrupt(db: &Path, sql: &str, params: &[Value]) {
    let storage = FrankenStorage::open(db).expect("corruption writer");
    storage
        .raw()
        .execute(sql, params)
        .expect("corruption update");
    storage.close().expect("close");
}

/// Deliberate multi-statement fixture corruption (for CHECK-constrained
/// columns the writer path cannot reach).
fn corrupt_batch(db: &Path, sql: &str) {
    let storage = FrankenStorage::open(db).expect("corruption writer");
    storage.raw().execute_batch(sql).expect("corruption batch");
    storage.close().expect("close");
}

/// Replace `identity_tuple[0]` with `domain`, recompute the canonical tuple
/// bytes and the matching input key, and store both. Every other column is
/// left exactly as it was.
fn rewrite_identity_domain(db: &Path, old_key: &Sha256Digest, domain: Json) -> Sha256Digest {
    let conn = Conn::open_read(db).expect("read tuple");
    let tuple_bytes: Vec<u8> = conn
        .query_row_map(
            "SELECT identity_tuple_bin FROM source_inputs WHERE input_key = ?1",
            &[Value::Blob(old_key.as_bytes().to_vec())],
            |row| row.get_typed(0),
        )
        .expect("identity tuple");
    drop(conn);
    let mut tuple: Json = serde_json::from_slice(&tuple_bytes).expect("tuple json");
    tuple.as_array_mut().expect("tuple array")[0] = domain;
    let bytes = serde_json::to_vec(&tuple).expect("canonical tuple");
    let new_key = Sha256Digest::of(&bytes);
    corrupt(
        db,
        "UPDATE source_inputs SET identity_tuple_bin = ?1, input_key = ?2 WHERE input_key = ?3",
        &[
            Value::Blob(bytes),
            Value::Blob(new_key.as_bytes().to_vec()),
            Value::Blob(old_key.as_bytes().to_vec()),
        ],
    );
    new_key
}

/// Publish one input with `count` records and no claims as a failed input.
fn publish_records(db: &Path, id: &str, sealed: &[u8], count: usize) -> Sha256Digest {
    let input = verified(id, sealed);
    let records = staged_records(sealed, &vec![RecordMappingState::NoClaims; count], true);
    let storage = FrankenStorage::open(db).expect("open schema9");
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
    mark_staged(&tx, staged.input_id, &records);
    activate(
        &tx,
        &input,
        staged.input_id,
        ProjectionDisposition::WholeInputRejected,
        TerminalState::Failed,
    );
    tx.commit().expect("commit");
    storage.close().expect("close");
    *input.input_key()
}

#[test]
fn r21_input_metadata_crosschecks() {
    let (_dir, base) = db_path("r21-base");
    let key = publish_empty(&base, "C10_META", "C10_NORMALIZER", "C10_SAFETY");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![key],
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&base).expect("open reader");
    reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("normal side");
    drop(reader);

    let cases: Vec<(&str, String, Vec<Value>)> = vec![
        (
            "connector disagrees with the tuple",
            "UPDATE source_inputs SET connector = 'codex'".into(),
            vec![],
        ),
        (
            "context digest mismatch",
            "UPDATE source_inputs SET context_digest = zeroblob(32)".into(),
            vec![],
        ),
        (
            "sealed digest mismatch",
            "UPDATE source_inputs SET sealed_sha256 = zeroblob(32)".into(),
            vec![],
        ),
        (
            "byte_len disagrees with the header",
            "UPDATE source_inputs SET byte_len = ?1".into(),
            vec![Value::Blob(u64_be8(999).to_vec())],
        ),
        (
            "expected_records disagrees with the header",
            "UPDATE source_inputs SET expected_records = ?1".into(),
            vec![Value::Blob(u64_be8(7).to_vec())],
        ),
        (
            "normalizer disagrees with the tuple",
            "UPDATE source_inputs SET normalizer_id = 'other-normalizer'".into(),
            vec![],
        ),
        (
            "source_id disagrees with the tuple",
            "UPDATE source_inputs SET source_id = 'other-source'".into(),
            vec![],
        ),
        (
            "identity_namespace disagrees with the tuple",
            "UPDATE source_inputs SET identity_namespace = 'other-namespace'".into(),
            vec![],
        ),
        (
            "root_id disagrees with the tuple",
            "UPDATE source_inputs SET root_id_bin = ?1".into(),
            vec![Value::Blob(b"/synthetic/other-root".to_vec())],
        ),
        (
            "relative_locator disagrees with the tuple",
            "UPDATE source_inputs SET relative_locator_bin = ?1".into(),
            vec![Value::Blob(b"other-locator.jsonl".to_vec())],
        ),
        (
            "role disagrees with the tuple",
            "UPDATE source_inputs SET role_bin = ?1".into(),
            vec![Value::Blob(b"other-role".to_vec())],
        ),
        (
            "platform disagrees with the tuple",
            "UPDATE source_inputs SET platform_bin = ?1".into(),
            vec![Value::Blob(b"other-platform".to_vec())],
        ),
        (
            "origin_host disagrees with the tuple",
            "UPDATE source_inputs SET origin_host = 'other-host'".into(),
            vec![],
        ),
        (
            "origin_source_version disagrees with the tuple",
            "UPDATE source_inputs SET origin_source_version = 'other-version'".into(),
            vec![],
        ),
        (
            "safety_contract disagrees with the tuple",
            "UPDATE source_inputs SET safety_contract_id = 'other-safety'".into(),
            vec![],
        ),
        (
            "expected_blank_lines disagrees with the header",
            "UPDATE source_inputs SET expected_blank_lines = ?1".into(),
            vec![Value::Blob(u64_be8(7).to_vec())],
        ),
    ];
    for (index, (label, sql, params)) in cases.iter().enumerate() {
        let (_dir, db) = db_path(&format!("r21-{index}"));
        std::fs::copy(&base, &db).expect("copy fixture");
        corrupt(&db, sql, params);
        let reader = SourceFactsReader::open(&db).expect("open reader");
        let error = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect_err(label);
        assert_eq!(
            error.kind(),
            SourceFactsReadErrorCode::DecodeFailed,
            "{label}"
        );
        assert_eq!(reason(&error), "invalid_input_metadata", "{label}");
    }

    // The input key must equal the SHA-256 of the stored identity tuple. A
    // rewritten key is read through the broad query so the old explicit key
    // cannot fail as `input_incomplete` first.
    let (_dir, bad_key_db) = db_path("r21-bad-key");
    std::fs::copy(&base, &bad_key_db).expect("copy fixture");
    corrupt(
        &bad_key_db,
        "UPDATE source_inputs SET input_key = zeroblob(32)",
        &[],
    );
    let reader = SourceFactsReader::open(&bad_key_db).expect("open reader");
    let broad = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let error = reader
        .read_raw_source_facts(&broad, None, SourceFactsPageLimits::default())
        .expect_err("key/tuple hash mismatch");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::DecodeFailed);
    assert_eq!(reason(&error), "invalid_input_metadata");

    // B1: the identity domain must be exactly `cass.source-input/2`. Each
    // variant rewrites tuple[0], the canonical tuple bytes and the matching
    // input key; every other repeated column stays as it was.
    for (label, domain) in [
        ("legacy identity domain", json!("cass.source-input/1")),
        ("null identity domain", Json::Null),
    ] {
        let (_dir, db) = db_path(&format!("r21-domain-{}", label.replace(' ', "-")));
        std::fs::copy(&base, &db).expect("copy fixture");
        rewrite_identity_domain(&db, &key, domain);
        let reader = SourceFactsReader::open(&db).expect("open reader");
        let broad = SourceFactsFilter {
            scope: SourceFactsScope::AllSource,
            ..Default::default()
        };
        let error = reader
            .read_raw_source_facts(&broad, None, SourceFactsPageLimits::default())
            .expect_err(label);
        assert_eq!(
            error.kind(),
            SourceFactsReadErrorCode::DecodeFailed,
            "{label}"
        );
        assert_eq!(reason(&error), "invalid_input_metadata", "{label}");
    }
}

#[test]
fn r22_observed_null_partial_and_profiles() {
    // A legal published failure has expected_records >= 3. The schema allows
    // a non-complete row to carry a partial or NULL observation, so both are
    // produced with plain updates on that failed row -- no CHECK is bypassed.
    let (_dir, base) = db_path("r22-failed-base");
    let failed = publish_boundary(&base, "installed");
    let partial_db = base.with_extension("partial.db");
    let null_db = base.with_extension("null.db");
    std::fs::copy(&base, &partial_db).expect("copy partial");
    std::fs::copy(&base, &null_db).expect("copy null");
    corrupt(
        &partial_db,
        "UPDATE source_inputs SET observed_records = ?1 WHERE input_key = ?2",
        &[
            Value::Blob(u64_be8(1).to_vec()),
            Value::Blob(failed.as_bytes().to_vec()),
        ],
    );
    corrupt(
        &null_db,
        "UPDATE source_inputs SET observed_records = NULL, observed_blank_lines = NULL WHERE input_key = ?1",
        &[Value::Blob(failed.as_bytes().to_vec())],
    );

    for (db, observed) in [(&partial_db, Some(1)), (&null_db, None)] {
        let reader = SourceFactsReader::open(db).expect("open reader");
        let filter = SourceFactsFilter {
            scope: SourceFactsScope::AllSource,
            input_keys: vec![failed],
            ..Default::default()
        };
        let page = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect("failed input");
        let input = &page.inputs[0];
        assert_eq!(input.state, "failed");
        assert_eq!(
            input.expected_records, 3,
            "the failed input has a real expected denominator"
        );
        assert_eq!(
            input.observed_records, observed,
            "the observation is not copied from expected"
        );
        if observed.is_none() {
            assert_eq!(input.observed_blank_lines, None, "a legal NULL stays NULL");
        }
        let conn = Conn::open_read(db).expect("SQL side");
        assert_input_full(input, &failed, SCOPE_SEALED, &conn);
        assert!(input.attempt_history.is_some());
        assert!(input.unprocessed_ranges.is_some());
        assert!(input.activation_request_hash.is_none());
        assert!(input.receipt_key.is_none());
        assert!(input.applied_content_generation.is_none());
    }

    // Two complete inputs from different historical profiles keep their own
    // material; neither is rewritten from the current build.
    let (_dir, db) = db_path("r22-profiles");
    let plain = publish_empty(&db, "C10_PLAIN", "C10_NORMALIZER", "C10_SAFETY");
    let other = publish_empty(&db, "C10_OTHER", "C10_NORMALIZER_B", "C10_SAFETY_B");
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let pages = collect(&reader, &filter, SourceFactsPageLimits::default());
    let inputs: Vec<_> = pages.iter().flat_map(|page| page.inputs.iter()).collect();
    let plain_input = inputs
        .iter()
        .find(|input| input.input_key == plain)
        .expect("plain");
    let other_input = inputs
        .iter()
        .find(|input| input.input_key == other)
        .expect("other");
    assert_eq!(plain_input.expected_records, 0);
    assert_eq!(
        plain_input.observed_records,
        Some(0),
        "the empty input's measured count"
    );
    assert_eq!(plain_input.normalizer_id, "C10_NORMALIZER");
    assert_eq!(plain_input.safety_contract_id, "C10_SAFETY");
    assert_eq!(other_input.normalizer_id, "C10_NORMALIZER_B");
    assert_eq!(other_input.safety_contract_id, "C10_SAFETY_B");
    let conn = Conn::open_read(&db).expect("SQL side");
    assert_input_full(plain_input, &plain, b"", &conn);
    assert_input_full(other_input, &other, b"", &conn);
    assert_ne!(plain_input.normalizer_id, other_input.normalizer_id);
}

#[test]
fn r23_codec_payload_hash_rejected() {
    let (_dir, base) = db_path("r23-base");
    let key = publish_one(&base, "C10_CODEC", true);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![key],
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&base).expect("open reader");
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("normal payload");
    let record = &page.records[0];
    let payload = record.payload.as_ref().expect("payload");
    assert_eq!(
        record.payload_sha256,
        Some(Sha256Digest::of(payload)),
        "payload_sha256 measures the actual BLOB"
    );
    drop(reader);

    let cases: Vec<(&str, &str, &str)> = vec![
        (
            "unknown codec",
            "PRAGMA ignore_check_constraints = ON; UPDATE source_records SET codec = 'mystery/9'; PRAGMA ignore_check_constraints = OFF",
            "unsupported",
        ),
        (
            "bad messagepack",
            "UPDATE source_records SET payload_bin = X'cc'",
            "safe-json-msgpack/1",
        ),
        (
            "wrong safe hash",
            "UPDATE source_records SET safe_value_hash = zeroblob(32)",
            "safe_value_hash_mismatch",
        ),
    ];
    for (index, (label, sql, expected_detail)) in cases.iter().enumerate() {
        let (_dir, db) = db_path(&format!("r23-{index}"));
        std::fs::copy(&base, &db).expect("copy fixture");
        corrupt_batch(&db, sql);
        let reader = SourceFactsReader::open(&db).expect("open reader");
        let error = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect_err(label);
        assert_eq!(
            error.kind(),
            SourceFactsReadErrorCode::DecodeFailed,
            "{label}"
        );
        if *expected_detail == "safe_value_hash_mismatch" {
            assert_eq!(reason(&error), "safe_value_hash_mismatch", "{label}");
        } else {
            assert_eq!(reason(&error), "codec_invalid", "{label}");
            assert_eq!(
                error.detail().get("codec").and_then(Json::as_str),
                Some(*expected_detail),
                "{label}"
            );
        }
        let rendered = format!("{error:?} {error}");
        assert!(
            !rendered.contains("mystery/9"),
            "{label}: no raw codec text"
        );
    }
}

#[test]
fn r24_missing_payload_is_absent() {
    let (_dir, db) = db_path("r24");
    let key = publish_one(&db, "C10_NO_PAYLOAD", false);
    corrupt(
        &db,
        "UPDATE source_inputs SET observed_records = NULL, observed_blank_lines = NULL",
        &[],
    );
    corrupt(
        &db,
        "UPDATE source_records SET observed_source_record_sha256 = NULL",
        &[],
    );
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![key],
        ..Default::default()
    };
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("record");
    let record = &page.records[0];
    assert!(record.payload.is_none(), "no payload is not fabricated");
    assert!(record.payload_sha256.is_none());
    assert!(record.codec.is_none());
    assert!(record.safe_value_hash.is_none());
    assert!(record.safe_value.is_none());
    assert!(record.native_ids.is_none());
    assert!(record.diagnostics.is_none());
    assert!(
        record.observed_source_record_sha256.is_none(),
        "observed is not copied"
    );
    assert_eq!(record.retention_state, "payload_absent");
    assert_eq!(
        record.expected_source_record_sha256.hex().len(),
        64,
        "the expected digest is still retained"
    );
}

#[test]
fn r25_record_metadata_rejected() {
    let (_dir, base) = db_path("r25-base");
    let key = publish_one(&base, "C10_POSITION", true);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![key],
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&base).expect("open reader");
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("normal position");
    assert_eq!(page.records[0].record_byte_len, 20);
    assert_eq!(
        page.records[0].byte_end - page.records[0].byte_start,
        page.records[0].record_byte_len
    );
    drop(reader);

    let bodies = [
        "[\"9\",\"\",\"0\",\"20\"]",
        "[\"1\",\"other\",\"0\",\"20\"]",
        "[\"1\",\"\",\"20\",\"0\"]",
        " [\"1\",\"\",\"0\",\"20\"]",
    ];
    for (index, body) in bodies.iter().enumerate() {
        let (_dir, db) = db_path(&format!("r25-{index}"));
        std::fs::copy(&base, &db).expect("copy fixture");
        corrupt(
            &db,
            "UPDATE source_records SET position_bin = ?1",
            &[Value::Blob(body.as_bytes().to_vec())],
        );
        let reader = SourceFactsReader::open(&db).expect("open reader");
        let error = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect_err("bad position");
        assert_eq!(
            error.kind(),
            SourceFactsReadErrorCode::DecodeFailed,
            "body {body}"
        );
        assert_eq!(reason(&error), "invalid_record_metadata", "body {body}");
    }

    // N2: a record-column type error is a record-context failure, not an
    // input-header failure. `record_pointer` is TEXT in the frozen schema; a
    // BLOB there must report invalid_record_metadata.
    let (_dir, db) = db_path("r25-pointer-type");
    std::fs::copy(&base, &db).expect("copy fixture");
    corrupt(&db, "UPDATE source_records SET record_pointer = X'00'", &[]);
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let error = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect_err("BLOB record pointer");
    assert_eq!(error.kind(), SourceFactsReadErrorCode::DecodeFailed);
    assert_eq!(reason(&error), "invalid_record_metadata");
}

#[test]
fn r26_link_evidence_rejected() {
    let (_dir, base) = db_path("r26-base");
    let key = publish_scope(&base);
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![key],
        ..Default::default()
    };
    let reader = SourceFactsReader::open(&base).expect("open reader");
    let normal = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("normal links");
    let conn = Conn::open_read(&base).expect("SQL side");
    assert_eq!(normal.records.len(), 3);
    for record in &normal.records {
        assert_record_full(record, &key, SCOPE_SEALED, &conn);
    }
    drop(reader);

    let cases = [
        "UPDATE source_message_links SET binding_digest = zeroblob(32)",
        "UPDATE source_message_links SET conversation_ordinal = 1 WHERE authority = 'canonical'",
        "UPDATE source_message_links SET source_positions_bin = X'00' WHERE authority = 'canonical'",
        "UPDATE source_message_links SET evidence_kind = 'no_message' WHERE authority = 'canonical'",
    ];
    for (index, sql) in cases.iter().enumerate() {
        let (_dir, db) = db_path(&format!("r26-{index}"));
        std::fs::copy(&base, &db).expect("copy fixture");
        corrupt(&db, sql, &[]);
        let reader = SourceFactsReader::open(&db).expect("open reader");
        let error = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect_err("bad link");
        assert_eq!(
            error.kind(),
            SourceFactsReadErrorCode::DecodeFailed,
            "case {index}"
        );
        assert_eq!(reason(&error), "invalid_link_evidence", "case {index}");
    }

    // SPEC-R2-02: a column *type* error on a link row is link-evidence
    // damage, not a database read failure. These rows are negative-only
    // fixtures; the CHECK bypass is explicit and applies to a throwaway copy.
    // (`authority` has TEXT affinity, so an INTEGER literal would be stored as
    // text; a BLOB is the value that really keeps a non-TEXT type.)
    let type_cases = [
        (
            "authority as BLOB",
            "UPDATE source_message_links SET authority = X'00' WHERE authority = 'canonical'",
        ),
        (
            "projection_key as TEXT",
            "UPDATE source_message_links SET projection_key = 'not-a-blob' WHERE authority = 'canonical'",
        ),
    ];
    for (index, (label, update)) in type_cases.iter().enumerate() {
        let (_dir, db) = db_path(&format!("r26-type-{index}"));
        std::fs::copy(&base, &db).expect("copy fixture");
        corrupt_batch(
            &db,
            &format!(
                "PRAGMA ignore_check_constraints = ON; {update}; PRAGMA ignore_check_constraints = OFF;"
            ),
        );
        let reader = SourceFactsReader::open(&db).expect("open reader");
        let error = reader
            .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
            .expect_err(label);
        assert_eq!(
            error.kind(),
            SourceFactsReadErrorCode::DecodeFailed,
            "{label}"
        );
        assert_eq!(reason(&error), "invalid_link_evidence", "{label}");
    }

    // Valid historical links with a NULL message must not be refused.
    let (_dir, db) = db_path("r26-forget");
    publish_scope(&db);
    let storage = FrankenStorage::open(&db).expect("writer");
    storage
        .forget_conversations_by_source_glob("/synthetic/c10-canonical/*", false)
        .expect("forget");
    storage.close().expect("close");
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let (ordinals, pages) = scope_ordinals(&reader, SourceFactsScope::HistoryUnresolved);
    assert_eq!(ordinals, vec![1, 2, 3]);
    let historical = pages[0]
        .records
        .iter()
        .flat_map(|record| record.links.iter())
        .filter(|link| link.authority.as_deref() == Some("historical"))
        .count();
    assert!(historical >= 1, "historical NULL-message links are valid");
}

// ---------------------------------------------------------------------------
// r27–r31: schema gates, WAL, limits and the public error shape
// ---------------------------------------------------------------------------

fn build_legacy(db: &Path, ddl: &str, version: i64) {
    let mut guard = open_test_writer(db, Profile::Production).expect("legacy writer");
    {
        let conn = guard.storage().raw();
        conn.execute_batch(ddl).expect("historical ddl");
        conn.execute_batch(&format!("PRAGMA user_version = {version};"))
            .expect("version");
        conn.execute_batch("PRAGMA journal_mode = DELETE;")
            .expect("non-wal fixture");
    }
    guard.mark_committed();
}

fn file_sha(db: &Path) -> [u8; 32] {
    Sha256::digest(std::fs::read(db).expect("read db")).into()
}

#[test]
fn r27_schema7_readonly() {
    let (_dir, db) = db_path("r27");
    build_legacy(&db, SCHEMA7_DDL, 7);
    let before = file_sha(&db);
    let wal = PathBuf::from(format!("{}-wal", db.display()));
    let shm = PathBuf::from(format!("{}-shm", db.display()));
    assert!(!wal.exists() && !shm.exists());

    let error = SourceFactsReader::open(&db).expect_err("schema7 refused");
    assert_eq!(
        error.kind(),
        SourceFactsReadErrorCode::SourceFactsUnavailable
    );
    assert_eq!(reason(&error), "source_facts_unavailable");
    assert_eq!(file_sha(&db), before, "the archive is not written");
    assert!(!wal.exists() && !shm.exists(), "no sidecar is created");
}

#[test]
fn r28_schema8_readonly() {
    let (_dir, db) = db_path("r28");
    build_legacy(&db, SCHEMA8_DDL, 8);
    let before = file_sha(&db);
    let error = SourceFactsReader::open(&db).expect_err("schema8 refused");
    assert_eq!(
        error.kind(),
        SourceFactsReadErrorCode::SourceFactsUnavailable
    );
    assert_eq!(file_sha(&db), before);
    assert!(!PathBuf::from(format!("{}-wal", db.display())).exists());
}

#[test]
fn r29_wal_readonly_committed_view() {
    let (_dir, db) = db_path("r29");
    let storage = FrankenStorage::open(&db).expect("live writer");
    {
        let conn = storage.raw();
        let mode: String = conn
            .query_row_map("PRAGMA journal_mode = WAL;", &[], |row| row.get_typed(0))
            .expect("wal mode");
        assert_eq!(mode.to_lowercase(), "wal");
    }
    let key_one = publish_empty_via(&storage, "C10_WAL_ONE");
    // The reader sees a commit that is still only in the WAL.
    let reader = SourceFactsReader::open(&db).expect("reader over live WAL");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let pages = collect(&reader, &filter, SourceFactsPageLimits::default());
    assert_eq!(pages[0].inputs.len(), 1);
    assert_eq!(pages[0].inputs[0].input_key, key_one);

    // A later commit by the same writer is visible to the same reader.
    let key_two = publish_empty_via(&storage, "C10_WAL_TWO");
    let pages = collect(&reader, &filter, SourceFactsPageLimits::default());
    let keys: Vec<Sha256Digest> = pages
        .iter()
        .flat_map(|page| page.inputs.iter().map(|i| i.input_key))
        .collect();
    assert!(
        keys.contains(&key_one) && keys.contains(&key_two),
        "both WAL commits are visible"
    );
    drop(reader);
    storage.close().expect("close");
}

/// Publish an empty input through an already-open writer.
fn publish_empty_via(storage: &FrankenStorage, id: &str) -> Sha256Digest {
    let input = verified(id, b"");
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &[]).expect("stage");
    activate(
        &tx,
        &input,
        staged.input_id,
        ProjectionDisposition::Ready,
        TerminalState::Complete,
    );
    tx.commit().expect("commit");
    *input.input_key()
}

#[test]
fn r30_zero_page_limits_rejected() {
    let (_dir, db) = db_path("r30");
    publish_scope(&db);
    let reader = SourceFactsReader::open(&db).expect("open reader");
    let filter = SourceFactsFilter::default();
    for limits in [
        SourceFactsPageLimits {
            max_records: 0,
            target_bytes: 8_388_608,
        },
        SourceFactsPageLimits {
            max_records: 64,
            target_bytes: 0,
        },
    ] {
        let error = reader
            .read_raw_source_facts(&filter, None, limits)
            .expect_err("zero limit");
        assert_eq!(error.kind(), SourceFactsReadErrorCode::InvalidCursor);
        assert_eq!(reason(&error), "invalid_page_limits");
    }

    // N4: a huge `max_records` must not become a negative/unbounded LIMIT or
    // an implicit 64 cap. The byte target still bounds the pages.
    let (_dir, bounded_db) = db_path("r30-bounded");
    let sealed =
        b"{\"n\":0,\"body\":\"C10\"}\n{\"n\":1,\"body\":\"C10\"}\n{\"n\":2,\"body\":\"C10\"}\n";
    publish_records(&bounded_db, "C10_BOUNDED_3", sealed, 3);
    let reader = SourceFactsReader::open(&bounded_db).expect("open reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let pages = collect(
        &reader,
        &filter,
        SourceFactsPageLimits {
            max_records: usize::MAX,
            target_bytes: 30,
        },
    );
    assert_eq!(
        pages.len(),
        3,
        "three 20-byte records under a 30-byte target"
    );
    for (index, page) in pages.iter().enumerate() {
        assert_eq!(page.records.len(), 1, "one record per bounded page");
        assert_eq!(page.records[0].ordinal, index as u64 + 1);
        assert_eq!(page.records[0].record_byte_len, 20);
        assert_eq!(page.oversized_records, 0);
    }
    assert!(pages.last().expect("last").next_cursor.is_none());

    // The full catalog under unlimited limits: all 65 records and all 66
    // unique headers, with no hard 64-record/64-header cap.
    let (_dir, catalog_db) = db_path("r30-unlimited");
    publish_catalog(&catalog_db);
    let reader = SourceFactsReader::open(&catalog_db).expect("open reader");
    let pages = collect(
        &reader,
        &filter,
        SourceFactsPageLimits {
            max_records: usize::MAX,
            target_bytes: u64::MAX,
        },
    );
    assert_eq!(pages.len(), 1, "unlimited limits consume the whole catalog");
    assert_eq!(pages[0].records.len(), 65, "all 65 catalog records");
    let mut headers: Vec<Sha256Digest> = pages[0]
        .inputs
        .iter()
        .map(|input| input.input_key)
        .collect();
    headers.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    headers.dedup();
    assert_eq!(headers.len(), 66, "all 66 catalog headers");
}

#[test]
fn r31_public_error_shape_safe() {
    fn assert_copy<T: Copy>() {}
    fn assert_eq_trait<T: Eq + Clone>() {}
    assert_copy::<SourceFactsReadErrorCode>();
    assert_eq_trait::<SourceFactsReadErrorCode>();

    // Each of the seven kinds through a real call.
    let (_dir, c7) = db_path("r31-schema7");
    build_legacy(&c7, SCHEMA7_DDL, 7);
    let unavailable = SourceFactsReader::open(&c7).expect_err("schema7");

    let (_dir, db) = db_path("r31");
    publish_catalog(&db);
    let reader = SourceFactsReader::open(&db).expect("reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        ..Default::default()
    };
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("page");
    let cursor = page.next_cursor.expect("cursor");
    let mut parts = cursor_parts(&cursor);
    parts[0] = json!("cass.source-facts-cursor/1");
    let unsupported = reader
        .read_raw_source_facts(
            &filter,
            Some(&cursor_from_parts(&parts)),
            SourceFactsPageLimits::default(),
        )
        .expect_err("version");
    let invalid = reader
        .read_raw_source_facts(&filter, Some("!!!"), SourceFactsPageLimits::default())
        .expect_err("encoding");

    // An illegal version suffix is a shape error with no raw-suffix echo.
    let mut sentinel_parts = cursor_parts(&cursor);
    sentinel_parts[0] = json!("cass.source-facts-cursor/C10_PRIVATE_PATH_SENTINEL/a");
    let sentinel_error = reader
        .read_raw_source_facts(
            &filter,
            Some(&cursor_from_parts(&sentinel_parts)),
            SourceFactsPageLimits::default(),
        )
        .expect_err("illegal suffix");
    assert_eq!(
        sentinel_error.kind(),
        SourceFactsReadErrorCode::InvalidCursor
    );
    assert_eq!(reason(&sentinel_error), "invalid_cursor_shape");
    let sentinel_rendered = format!("{sentinel_error:?} {sentinel_error}");
    assert!(!sentinel_rendered.contains("C10_PRIVATE_PATH_SENTINEL"));
    assert!(
        !sentinel_error
            .detail()
            .to_string()
            .contains("C10_PRIVATE_PATH_SENTINEL")
    );

    let (_dir, staged_db) = db_path("r31-staged");
    let staged_key = publish_boundary(&staged_db, "staged_failed");
    let staged_reader = SourceFactsReader::open(&staged_db).expect("reader");
    let incomplete = staged_reader
        .read_raw_source_facts(
            &SourceFactsFilter {
                scope: SourceFactsScope::AllSource,
                input_keys: vec![staged_key],
                ..Default::default()
            },
            None,
            SourceFactsPageLimits::default(),
        )
        .expect_err("incomplete");

    let (_dir, meta_db) = db_path("r31-meta");
    let key = publish_empty(&meta_db, "C10_ERR", "C10_NORMALIZER", "C10_SAFETY");
    corrupt(
        &meta_db,
        "UPDATE source_inputs SET connector = 'codex'",
        &[],
    );
    let meta_reader = SourceFactsReader::open(&meta_db).expect("reader");
    let decode = meta_reader
        .read_raw_source_facts(
            &SourceFactsFilter {
                scope: SourceFactsScope::AllSource,
                input_keys: vec![key],
                ..Default::default()
            },
            None,
            SourceFactsPageLimits::default(),
        )
        .expect_err("decode");

    let (_dir, garbage) = db_path("r31-garbage");
    std::fs::write(&garbage, b"this is not a database").expect("write garbage");
    let db_error = SourceFactsReader::open(&garbage).expect_err("garbage");

    let (_dir, stale_db) = db_path("r31-stale");
    publish_catalog(&stale_db);
    let stale_reader = SourceFactsReader::open(&stale_db).expect("reader");
    let page = stale_reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("page");
    let stale_cursor = page.next_cursor.expect("cursor");
    drop(stale_reader);
    let storage = FrankenStorage::open(&stale_db).expect("writer");
    storage
        .raw()
        .execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES('library_identity', 'other')",
            &[],
        )
        .expect("library");
    storage.close().expect("close");
    let stale_reader = SourceFactsReader::open(&stale_db).expect("reader");
    let stale = stale_reader
        .read_raw_source_facts(
            &filter,
            Some(&stale_cursor),
            SourceFactsPageLimits::default(),
        )
        .expect_err("stale");

    let errors = [
        unavailable,
        unsupported,
        stale,
        decode,
        incomplete,
        invalid,
        db_error,
    ];
    let expected = [
        SourceFactsReadErrorCode::SourceFactsUnavailable,
        SourceFactsReadErrorCode::UnsupportedReaderVersion,
        SourceFactsReadErrorCode::StaleCursor,
        SourceFactsReadErrorCode::DecodeFailed,
        SourceFactsReadErrorCode::InputIncomplete,
        SourceFactsReadErrorCode::InvalidCursor,
        SourceFactsReadErrorCode::DbError,
    ];
    let whitelist = [
        "reason",
        "input_key",
        "ordinal",
        "pointer_sha256",
        "codec",
        "found_version",
        "expected_version",
        "schema_version",
        "sqlite_code",
        "range_count",
    ];
    for (error, kind) in errors.iter().zip(expected.iter()) {
        assert_eq!(error.kind(), *kind);
        let detail = error.detail();
        let map = detail.as_object().expect("detail object");
        assert!(map.contains_key("reason"), "reason is always present");
        for key in map.keys() {
            assert!(
                whitelist.contains(&key.as_str()),
                "unexpected detail key {key}"
            );
        }
        let _: &dyn std::error::Error = error;
        let rendered = format!("{error:?} {error}");
        for sentinel in ["SENTINEL-", "/home/", "SENTINEL_PATH"] {
            assert!(
                !rendered.contains(sentinel),
                "no private marker in {rendered}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// r32: Debug redaction across every data-bearing DTO
// ---------------------------------------------------------------------------

fn fact(field: &str) -> FieldFact {
    FieldFact {
        field: field.into(),
        status: FactStatus::Present,
        value: None,
        value_kind: None,
        raw_ref: None,
        presence_ref: None,
        reason: None,
        refs: None,
        unit: None,
    }
}

#[test]
fn r32_all_data_dto_debug_redacted() {
    const S_PAYLOAD: &str = "SENTINEL_PAYLOAD_9c1";
    const S_NAMESPACE: &str = "SENTINEL_NAMESPACE_4a7";
    const S_SOURCE: &str = "SENTINEL_SOURCE_88b";
    const S_POINTER: &str = "SENTINEL_POINTER_1f2";
    const S_NATIVE: &str = "SENTINEL_NATIVE_77e";
    const S_DIAG: &str = "SENTINEL_DIAG_5d0";
    const S_MODEL: &str = "SENTINEL_MODEL_2c9";
    const S_TOOL: &str = "SENTINEL_TOOL_6b4";
    const S_REASON: &str = "SENTINEL_REASON_3aa";

    let (_dir, db) = db_path("r32");
    let sealed = format!("{{\"secret\":\"{S_PAYLOAD}\"}}\n");
    let input = verified(S_SOURCE, sealed.as_bytes());
    let frames = frames_for(sealed.as_bytes());
    let locator = frames[0].locator();
    let native = LosslessSourceValue::parse(format!("{{\"native\":\"{S_NATIVE}\"}}").as_bytes())
        .expect("native tree");
    let diagnostics = vec![coding_agent_search::storage::source_facts::SafeDiagnostic {
        code: S_DIAG.into(),
        detail: Some(S_DIAG.into()),
        offset: None,
        position: None,
    }];
    let records = vec![VerifiedStagedRecord::from_frame(
        &frames[0],
        Some(*frames[0].raw_sha256()),
        ParseState::Parsed,
        RecordMappingState::NoClaims,
        SafetyState::Preserved,
        Some(native),
        Some(safe_value(
            &sealed.as_bytes()[locator.byte_start as usize..locator.byte_end as usize],
        )),
        Some(diagnostics),
    )];
    let storage = FrankenStorage::open(&db).expect("open");
    let tx = storage
        .raw()
        .transaction_with_mode(TxMode::Immediate)
        .expect("tx");
    let staged = stage_source_records_in_tx(&tx, &input, &records).expect("stage");
    mark_staged(&tx, staged.input_id, &records);
    activate(
        &tx,
        &input,
        staged.input_id,
        ProjectionDisposition::WholeInputRejected,
        TerminalState::Failed,
    );
    tx.commit().expect("commit");
    storage.close().expect("close");

    let reader = SourceFactsReader::open(&db).expect("reader");
    let filter = SourceFactsFilter {
        scope: SourceFactsScope::AllSource,
        input_keys: vec![*input.input_key()],
        ..Default::default()
    };
    let page = reader
        .read_raw_source_facts(&filter, None, SourceFactsPageLimits::default())
        .expect("page");
    let input_dto = &page.inputs[0];
    let raw = &page.records[0];
    assert_eq!(input_dto.source_id, S_SOURCE, "fields are not removed");
    assert_eq!(input_dto.identity_namespace, "C10_NAMESPACE");
    assert_eq!(raw.record_pointer, "");
    assert!(
        raw.payload
            .as_ref()
            .expect("payload")
            .windows(S_PAYLOAD.len())
            .any(|w| w == S_PAYLOAD.as_bytes())
    );
    assert!(raw.native_ids.is_some());
    assert!(raw.diagnostics.is_some());

    // A link with sentinel-ish private members (canonical binding witness).
    let (_link_dir, link_db) = db_path("r32-link");
    publish_scope(&link_db);
    let link_reader = SourceFactsReader::open(&link_db).expect("reader");
    let link_pages = collect(
        &link_reader,
        &SourceFactsFilter {
            scope: SourceFactsScope::AllSource,
            ..Default::default()
        },
        SourceFactsPageLimits::default(),
    );
    let link = &link_pages[0]
        .records
        .iter()
        .flat_map(|record| record.links.iter())
        .find(|link| link.original_installation.is_some())
        .expect("installed link");

    let standard = StandardFacts {
        model: FieldFact {
            value: Some(FactValue::String(S_MODEL.into())),
            ..fact("model")
        },
        provider: FieldFact {
            reason: Some(S_REASON.into()),
            ..fact("provider")
        },
        native_ids: BTreeMap::new(),
        times: BTreeMap::new(),
        tools: vec![ToolFact {
            kind: S_TOOL.into(),
            raw_ref: S_POINTER.into(),
            fields: BTreeMap::from([("name".to_string(), fact("name"))]),
        }],
        usage: vec![UsageSnapshot {
            scope: "message".into(),
            role: "assistant".into(),
            raw_ref: S_POINTER.into(),
            fields: BTreeMap::new(),
        }],
        messages: vec![MessageFacts {
            reference: S_POINTER.into(),
            model: fact("model"),
            ids: BTreeMap::new(),
            times: BTreeMap::new(),
            role: vec![fact("role")],
            usage: vec![],
            tools: vec![],
        }],
    };
    let full = SourceFactsRecord {
        raw: raw.clone(),
        standard: Some(standard.clone()),
    };

    let rendered = format!(
        "{page:?} {input_dto:?} {raw:?} {full:?} {link:?} {:?} {standard:?}",
        input_dto.expected_manifest
    );
    for sentinel in [
        S_PAYLOAD,
        S_NAMESPACE,
        S_SOURCE,
        S_POINTER,
        S_NATIVE,
        S_DIAG,
        S_MODEL,
        S_TOOL,
        S_REASON,
        "canonical",
        "C10_NORMALIZER",
    ] {
        assert!(
            !rendered.contains(sentinel),
            "Debug leaked {sentinel}: {rendered}"
        );
    }
    // The Debug still names the types and carries shape.
    for name in [
        "RawSourceFactsPage",
        "SourceFactsInput",
        "RawSourceFactsRecord",
        "SourceFactsRecordLink",
        "SourceFactsExpectedManifest",
        "StandardFacts",
    ] {
        assert!(rendered.contains(name), "Debug names {name}");
    }

    // A boolean payload is a field value: Debug hides it, Serialize keeps it.
    for (value, expected) in [(false, json!(false)), (true, json!(true))] {
        assert_eq!(format!("{:?}", FactValue::Boolean(value)), "Boolean(..)");
        assert_eq!(
            serde_json::to_value(FactValue::Boolean(value)).expect("bool"),
            expected
        );
    }
}

// ---------------------------------------------------------------------------
// r33–r35: standard DTO serialisation
// ---------------------------------------------------------------------------

fn empty_standard() -> StandardFacts {
    StandardFacts {
        model: fact("model"),
        provider: fact("provider"),
        native_ids: BTreeMap::new(),
        times: BTreeMap::new(),
        tools: vec![],
        usage: vec![],
        messages: vec![],
    }
}

#[test]
fn r33_standard_seven_roots_status_serialize() {
    let json = serde_json::to_value(empty_standard()).expect("serialize");
    let object = json.as_object().expect("object");
    let expected = [
        "model",
        "provider",
        "native_ids",
        "times",
        "tools",
        "usage",
        "messages",
    ];
    let mut keys: Vec<&String> = object.keys().collect();
    keys.sort();
    let mut expected_sorted: Vec<&str> = expected.to_vec();
    expected_sorted.sort_unstable();
    assert_eq!(
        keys.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
        expected_sorted
    );
    assert_eq!(
        object["native_ids"],
        json!({}),
        "empty roots are still present"
    );
    assert_eq!(object["times"], json!({}));
    assert_eq!(object["tools"], json!([]));
    assert_eq!(object["usage"], json!([]));
    assert_eq!(object["messages"], json!([]));
    assert_eq!(object["model"]["field"], json!("model"));
    assert_eq!(object["model"]["status"], json!("present"));
    assert!(
        !object["model"].as_object().unwrap().contains_key("value"),
        "None members are omitted"
    );

    for (status, text) in [
        (FactStatus::Present, "present"),
        (FactStatus::Missing, "missing"),
        (FactStatus::Invalid, "invalid"),
        (FactStatus::Conflict, "conflict"),
    ] {
        assert_eq!(serde_json::to_value(status).expect("status"), json!(text));
    }
    assert_eq!(
        serde_json::to_value(FactValueKind::Object).expect("kind"),
        json!("object")
    );
    assert_eq!(
        serde_json::to_value(FactValueKind::Array).expect("kind"),
        json!("array")
    );
    assert_eq!(
        serde_json::to_value(FactUnit::Count).expect("unit"),
        json!("count")
    );
    assert_eq!(
        serde_json::to_value(FactUnit::Epoch).expect("unit"),
        json!("epoch")
    );
    assert_eq!(
        serde_json::to_value(FactUnit::NumberText).expect("unit"),
        json!("number_text")
    );
}

#[test]
fn r34_standard_optional_recursive_flatten() {
    let nested = CandidateFact {
        status: FactStatus::Conflict,
        value: None,
        value_kind: None,
        raw_ref: Some("raw-1".into()),
        presence_ref: None,
        reason: None,
        refs: Some(vec![CandidateFact {
            status: FactStatus::Invalid,
            value: None,
            value_kind: None,
            raw_ref: None,
            presence_ref: None,
            reason: Some("bad".into()),
            refs: None,
            unit: Some(FactUnit::Count),
        }]),
        unit: None,
    };
    let root = FieldFact {
        field: "root".into(),
        status: FactStatus::Conflict,
        value: None,
        value_kind: None,
        raw_ref: None,
        presence_ref: None,
        reason: None,
        refs: Some(vec![nested]),
        unit: None,
    };
    let root_json = serde_json::to_value(&root).expect("field");
    let object = root_json.as_object().expect("object");
    assert!(!object.contains_key("value"), "None value omitted");
    assert!(!object.contains_key("unit"), "None unit omitted");
    let refs = object["refs"].as_array().expect("refs");
    assert_eq!(refs[0]["raw_ref"], json!("raw-1"));
    assert_eq!(refs[0]["refs"][0]["status"], json!("invalid"));
    assert_eq!(refs[0]["refs"][0]["unit"], json!("count"));
    assert_eq!(refs[0]["refs"][0]["reason"], json!("bad"));

    let tool = ToolFact {
        kind: "tool_kind".into(),
        raw_ref: "raw-tool".into(),
        fields: BTreeMap::from([("name".to_string(), fact("name"))]),
    };
    let tool_json = serde_json::to_value(&tool).expect("tool");
    let object = tool_json.as_object().expect("object");
    assert!(
        !object.contains_key("fields"),
        "ToolFact fields are flattened"
    );
    assert_eq!(object["name"]["field"], json!("name"));
    assert_eq!(object["kind"], json!("tool_kind"));

    let usage = UsageSnapshot {
        scope: "message".into(),
        role: "assistant".into(),
        raw_ref: "raw-usage".into(),
        fields: BTreeMap::from([("tokens".to_string(), fact("tokens"))]),
    };
    let usage_json = serde_json::to_value(&usage).expect("usage");
    assert_eq!(
        usage_json["fields"]["tokens"]["field"],
        json!("tokens"),
        "usage keeps fields"
    );

    let message = MessageFacts {
        reference: "m1".into(),
        model: fact("model"),
        ids: BTreeMap::new(),
        times: BTreeMap::new(),
        role: vec![fact("role")],
        usage: vec![usage],
        tools: vec![tool],
    };
    let message_json = serde_json::to_value(&message).expect("message");
    assert_eq!(message_json["ref"], json!("m1"), "MessageFacts uses ref");
    assert!(message_json.as_object().unwrap().get("reference").is_none());
}

#[test]
fn r35_standard_lossless_tree_serialize() {
    assert_eq!(
        serde_json::to_value(FactValue::String("text".into())).expect("string"),
        json!("text")
    );
    assert_eq!(
        serde_json::to_value(FactValue::Boolean(true)).expect("bool"),
        json!(true)
    );

    let tree =
        LosslessSourceValue::parse(br#"{"a":18446744073709551615,"b":1e999999,"c":"s","d":true}"#)
            .expect("lossless tree");
    let mut before = Vec::new();
    tree.write_canonical(&mut before).expect("canonical before");
    let serialized = serde_json::to_string(&FactValue::Tree(tree.clone())).expect("tree json");
    assert!(
        serialized.contains(r#"["num","18446744073709551615"]"#),
        "u64 max text kept: {serialized}"
    );
    assert!(
        serialized.contains(r#"["num","1e999999"]"#),
        "extreme exponent text kept: {serialized}"
    );
    assert!(serialized.contains(r#"["str","s"]"#), "strings are tagged");
    assert!(
        serialized.contains(r#"["bool",true]"#),
        "booleans are tagged"
    );
    assert!(
        serialized.starts_with(r#"["obj",["#),
        "object order is preserved: {serialized}"
    );
    let mut after = Vec::new();
    tree.write_canonical(&mut after).expect("canonical after");
    assert_eq!(
        before, after,
        "the original tree is not changed by serialisation"
    );
}

// ---------------------------------------------------------------------------
// r36: the complete-authority SQL seam snapshot
// ---------------------------------------------------------------------------

#[test]
fn r36_complete_authority_edges_sql_snapshot() {
    let (_dir, db) = db_path("r36");
    let edges = db.with_extension("edges.db");
    let pending = db.with_extension("pending.db");
    let key = publish_scope(&db);
    build_edges(&db, &edges, &pending, &key);

    let reader = SourceFactsReader::open(&edges).expect("open edges");
    let (analysis, _) = scope_ordinals(&reader, SourceFactsScope::Analysis);
    let (history, history_pages) = scope_ordinals(&reader, SourceFactsScope::HistoryUnresolved);
    let (all, all_pages) = scope_ordinals(&reader, SourceFactsScope::AllSource);
    assert_eq!(analysis, vec![1], "edges analysis");
    assert_eq!(history, vec![1, 2, 3], "edges history");
    assert_eq!(all, vec![1, 2, 3], "edges all_source");
    let record1 = all_pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 1)
        .expect("record 1");
    assert_eq!(record1.links.len(), 2, "record 1 keeps both links");
    let mut authorities: Vec<&str> = record1
        .links
        .iter()
        .map(|link| link.authority.as_deref().expect("authority"))
        .collect();
    authorities.sort_unstable();
    assert_eq!(
        authorities,
        vec!["canonical", "unmapped"],
        "legal envelope not rejected"
    );
    let canonical = record1
        .links
        .iter()
        .find(|link| link.authority.as_deref() == Some("canonical"))
        .expect("canonical");
    assert_eq!(canonical.message_id, Some(7));
    let record3 = all_pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 3)
        .expect("record 3");
    assert_eq!(record3.links[0].authority.as_deref(), Some("unresolved"));
    assert_eq!(record3.links[0].message_id, None);
    assert_eq!(
        history_pages[0]
            .records
            .iter()
            .map(|record| record.links.len())
            .sum::<usize>(),
        3,
        "three records keep every legal witness (record 1 has two links)"
    );
    let conn = Conn::open_read(&edges).expect("edges SQL side");
    assert_input_full(&all_pages[0].inputs[0], &key, SCOPE_SEALED, &conn);
    for record in &all_pages[0].records {
        assert_record_full(record, &key, SCOPE_SEALED, &conn);
    }

    let reader = SourceFactsReader::open(&pending).expect("open pending");
    let (analysis, _) = scope_ordinals(&reader, SourceFactsScope::Analysis);
    let (history, history_pages) = scope_ordinals(&reader, SourceFactsScope::HistoryUnresolved);
    let (all, all_pages) = scope_ordinals(&reader, SourceFactsScope::AllSource);
    assert_eq!(analysis, vec![1], "pending analysis");
    assert_eq!(history, vec![1, 3], "a pending claim is not history");
    assert_eq!(all, vec![1, 2, 3], "pending all_source");
    let record2 = all_pages[0]
        .records
        .iter()
        .find(|record| record.ordinal == 2)
        .expect("record 2");
    assert_eq!(record2.record_mapping_state, "claims_pending");
    assert_eq!(record2.links.len(), 1);
    assert_eq!(record2.links[0].authority, None);
    assert_eq!(record2.links[0].message_id, None);
    assert!(record2.links[0].original_installation.is_none());
    assert!(
        !history_pages[0]
            .records
            .iter()
            .any(|record| record.ordinal == 2)
    );
    let conn = Conn::open_read(&pending).expect("pending SQL side");
    assert_input_full(&all_pages[0].inputs[0], &key, SCOPE_SEALED, &conn);
    for record in &all_pages[0].records {
        assert_record_full(record, &key, SCOPE_SEALED, &conn);
    }
}
