//! Full-search/off capture. Quality evaluation belongs to a later runner.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Instant;

use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::run::{RegressionSearchRun, milliseconds};
use super::types::{InputWindow, LabelKey, RegressionCommand};
use crate::search::query::SearchMode;
use crate::search::regression_trace::{TextDigest, candidate_instance_key};

pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(crate) fn file_digest(path: &Path) -> Result<String> {
    let mut reader = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}

pub(crate) fn query_manifest_bytes(windows: &[InputWindow]) -> Result<Vec<u8>> {
    const QIDS: [&str; 9] = [
        "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
    ];
    if windows.len() != 9
        || windows.iter().zip(QIDS).any(|(w, q)| {
            w.qid != q
                || w.query_sha256.len() != 64
                || !w
                    .query_sha256
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        })
    {
        bail!("QUERY_MANIFEST_INVALID");
    }
    let rows: Vec<_> = windows.iter().map(|w| (&w.qid, &w.query_sha256)).collect();
    let mut bytes = b"cass.regression-query-manifest.v1\0".to_vec();
    bytes.extend(serde_json::to_vec(&rows)?);
    Ok(bytes)
}

/// Captures the running file and actual process arguments. A missing compile-time
/// source pin is rejected; a checkout HEAD cannot identify a built executable.
pub(crate) struct RunProvenance {
    pub(crate) source_commit: String,
    pub(crate) binary_sha256: String,
    pub(crate) argv: Vec<String>,
}

impl RunProvenance {
    pub(crate) fn capture() -> Result<Self> {
        let source_commit = option_env!("CASS_BUILD_SOURCE_COMMIT").unwrap_or("");
        if option_env!("CASS_BUILD_SOURCE_CLEAN") != Some("true")
            || source_commit.len() != 40
            || !source_commit
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        {
            bail!("REGRESSION_PROVENANCE_UNAVAILABLE");
        }
        let argv = std::env::args_os()
            .map(|s| {
                s.into_string()
                    .map_err(|_| anyhow::anyhow!("REGRESSION_PROVENANCE_UNAVAILABLE"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            source_commit: source_commit.into(),
            binary_sha256: file_digest(&std::env::current_exe()?)?,
            argv,
        })
    }
}

pub(crate) fn write_private(root: &Path, relative: &str, value: &Value) -> Result<Value> {
    crate::search::regression_io::validate_private_run_root(root)?;
    let path = root.join(relative);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(&path)?;
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    output.write_all(&bytes)?;
    output.sync_all()?;
    Ok(json!({"relative_path":relative,"sha256":digest(&bytes)}))
}

pub(crate) fn private_files(root: &Path) -> Result<Vec<String>> {
    fn walk(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                bail!("REGRESSION_REPORT_WRITE_FAILED");
            }
            if kind.is_dir() {
                walk(root, &entry.path(), files)?;
            } else if kind.is_file() {
                files.push(
                    entry
                        .path()
                        .strip_prefix(root)?
                        .to_str()
                        .ok_or_else(|| anyhow::anyhow!("REGRESSION_REPORT_WRITE_FAILED"))?
                        .to_string(),
                );
            } else {
                bail!("REGRESSION_REPORT_WRITE_FAILED");
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    walk(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn counts(mode: SearchMode, embedding: Option<Value>) -> Vec<Value> {
    let mut values = vec![
        json!({"scope":"rerank-http-v1","http_attempts":0,"http_response_observed":0,"delivery_unknown":0,"model_executions":0,"basis":"not-called"}),
    ];
    if mode != SearchMode::Lexical {
        values.push(embedding.unwrap_or_else(|| json!({"scope":"embedding-http","http_attempts":null,"http_response_observed":null,"delivery_unknown":null,"model_executions":null,"basis":"unknown"})));
    }
    values
}

pub(crate) fn run(command: &RegressionCommand) -> Result<Value> {
    let started = Instant::now();
    let provenance = RunProvenance::capture()?;
    let validated = super::input::prepare_full(command)?;
    let root = validated.paths.run_root.clone();
    let activation = RegressionSearchRun::activate(validated, command);
    let run = match activation {
        Ok(run) => run,
        Err(error) => {
            write_private(
                &root,
                "search-failure.json",
                &json!({"terminal":"FAILED","quality_status":"FAILED","failure_code":super::run::error_code(&error),"stage":"ACTIVATION"}),
            )?;
            return Err(error);
        }
    };
    collect(&run, &provenance, started, milliseconds(started))
}

/// Also used by synthetic module tests. Production always enters through prepare_full.
pub(crate) fn collect(
    run: &RegressionSearchRun,
    provenance: &RunProvenance,
    started: Instant,
    identity_before_ms: f64,
) -> Result<Value> {
    let root = &run.validated.paths.run_root;
    let argv_value = serde_json::to_value(&provenance.argv)?;
    let argv_ref = write_private(root, "argv.json", &argv_value)?;
    let request_ref = write_private(root, "request.json", &run.request)?;
    let mut writes = vec!["argv.json".to_string(), "request.json".to_string()];
    let mut questions = Vec::new();
    let mut times = Vec::new();
    let mut failure = None;
    for window in &run.validated.inputs.windows {
        let start = Instant::now();
        match run.search_off(&window.query) {
            Ok(search) => {
                let mut slots = Vec::new();
                let mut subjects = Vec::new();
                for (hit, slot) in search.result.hits.iter().zip(&search.evidence.final_slots) {
                    let text = TextDigest::of(&hit.content);
                    let key = LabelKey {
                        query_sha256: window.query_sha256.clone(),
                        label_text_sha256: text.sha256.clone(),
                        label_policy_sha256: run.validated.inputs.label_policy_sha256.clone(),
                    };
                    let label = run
                        .validated
                        .inputs
                        .labels
                        .iter()
                        .find(|row| row.key == key)
                        .map(|row| row.value.as_str())
                        .unwrap_or("unknown");
                    let instance_key = candidate_instance_key(&slot.identity)?;
                    subjects.push(json!({"candidate_instance_key":instance_key,"label_key":key,"text":{"utf8":hit.content,"sha256":text.sha256,"utf8_bytes":text.utf8_bytes}}));
                    slots.push(json!({"candidate_instance_key":instance_key,"label_key":key,"input_slot":slot.input_slot,"retrieval_rank":slot.retrieval_rank,"final_rank":slot.retrieval_rank,"identity":slot.identity,"message_id":hit.message_id,"conversation_id":hit.conversation_id,"candidate_text":text,"sent_text":null,"source_sha256":null,"original_score":hit.score,"rerank_score":null,"label":label}));
                }
                let query_digest = TextDigest::of(&window.query);
                let subjects_relative = format!("label-subjects-{}.json", window.qid);
                write_private(
                    root,
                    &subjects_relative,
                    &json!({"schema":"cass.regression-label-subjects.v1","qid":window.qid,"query":{"utf8":window.query,"sha256":query_digest.sha256,"utf8_bytes":query_digest.utf8_bytes},"label_policy_sha256":run.validated.inputs.label_policy_sha256,"candidates":subjects}),
                )?;
                writes.push(subjects_relative);
                let evidence_relative = search
                    .evidence_path
                    .strip_prefix(root)?
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("REGRESSION_REPORT_WRITE_FAILED"))?
                    .to_string();
                writes.push(evidence_relative.clone());
                let total = milliseconds(start);
                times.push(total);
                let actual_n = slots.len();
                let question = json!({"qid":window.qid,"query_sha256":window.query_sha256,"requested_n":run.n,"actual_n":actual_n,"pool_complete":true,"terminal":if actual_n < run.n {"SHORT_WINDOW"} else {"SUCCESS"},"full_requested_n_claim":actual_n == run.n,"rerank_applied":false,"ordered_pool_sha256":null,"slots":slots,"pages":[],"window_evidence":{"relative_path":evidence_relative,"sha256":file_digest(&search.evidence_path)?},"partial":false,"timed_out":false,"failure_code":null,"lexical_statistics_status":if run.mode == SearchMode::Semantic {"NOT_USED"} else {"USED"},"lexical_statistics_sha256":search.evidence.lexical_statistics_sha256,"cost":{"identity_before_ms":search.identity_before_ms,"identity_after_ms":search.identity_after_ms,"retrieval_ms":search.retrieval_ms,"rerank_client_ms":0.0,"model_execution_ms":null,"paging_ms":0.0,"question_total_ms":total,"http":counts(run.mode, run.embedding_cost(false)),"resource_measurements":[]}});
                let relative = format!("question-{}.json", window.qid);
                write_private(root, &relative, &question)?;
                writes.push(relative);
                questions.push(question);
            }
            Err(error) => {
                failure = Some(super::run::error_code(&error).to_string());
                break;
            }
        }
    }
    let identity_after_start = Instant::now();
    let verified = run.verify_end();
    let identity_after_ms = milliseconds(identity_after_start);
    if let Err(error) = verified {
        failure = Some(super::run::error_code(&error).to_string());
    }
    let succeeded = failure.is_none();
    let terminal = if !succeeded {
        "FAILED"
    } else if questions.iter().any(|q| q["terminal"] == "SHORT_WINDOW") {
        "SHORT_WINDOW"
    } else {
        "SUCCESS"
    };
    run.persist_embedding_calls()?;
    let after = succeeded.then(|| json!({"basis":"equal-physical-db-and-source-generation-policy","inventory_digests":"reused-initial-not-independently-reexported","database_sha256":run.binding.database_sha256,"source_manifest_sha256":run.binding.source_manifest_sha256,"wal_bytes":0,"generation_unchanged":true,"policies_unchanged":true,"shared_maintenance_lease_held":true}));
    let mut sorted = times.clone();
    sorted.sort_by(f64::total_cmp);
    let mean = (!times.is_empty()).then(|| times.iter().sum::<f64>() / times.len() as f64);
    let quantile = |p: f64| {
        (!sorted.is_empty()).then(|| sorted[(p * sorted.len() as f64).ceil() as usize - 1])
    };
    writes = private_files(root)?;
    writes.push("run.json".into());
    let output = json!({"schema":"cass.regression-run.v1","run_id":root.file_name().and_then(|s|s.to_str()).ok_or_else(||anyhow::anyhow!("REGRESSION_REPORT_WRITE_FAILED"))?,"mode":"full-search","terminal":terminal,"quality_status":if succeeded {"NOT_EVALUATED"} else {"FAILED"},"failure_code":failure,"source_commit":provenance.source_commit,"binary_sha256":provenance.binary_sha256,"argv_sha256":argv_ref["sha256"],"suite_sha256":run.validated.inputs.suite_sha256,"query_manifest_sha256":digest(&query_manifest_bytes(&run.validated.inputs.windows)?),"labels_sha256":run.validated.inputs.labels_sha256,"label_policy_sha256":run.validated.inputs.label_policy_sha256,"question_count":9,"suite_candidate_slots":1800,"source_identity":{"source_manifest_sha256":run.binding.source_manifest_sha256,"source_checked":5049,"source_producer_receipt_sha256":run.validated.source_receipt_sha256,"message_text_sha256":run.binding.message_text_sha256,"chunk_text_sha256":run.binding.chunk_text_sha256,"canonicalize_version":run.binding.canonicalize_version,"chunking_policy_version":run.binding.chunking_policy_version,"statistics_policy":run.binding.statistics_policy},"expected_binding_file_sha256":run.validated.expected_binding_file_sha256,"expected_binding":run.validated.expected_binding,"observed_before":run.binding,"observed_after":if succeeded { Some(&run.binding) } else { None },"fixed_input_manifest_sha256":null,"fixed_windows_file_sha256":null,"backend_identity":{"provider":null,"actual_model":null,"model_revision":null,"endpoint_origin_sha256":null,"server_template_policy":null,"document_assembly_policy":null,"client_submission_policy":null},"request":{"search_mode":crate::search_mode_canonical_str(run.mode),"vector_search_mode":run.vector_mode.map(crate::vector_search_mode_wire),"rerank":false,"n":run.n,"page_k":null,"resolved_filters":run.request["resolved_filters"],"request_profile":"d5-fixed-filters-v1","request_evidence_sha256":request_ref["sha256"]},"output":{"private_root":root.parent().and_then(|s|s.to_str()).ok_or_else(||anyhow::anyhow!("REGRESSION_REPORT_WRITE_FAILED"))?,"run_relative_path":root.file_name().and_then(|s|s.to_str()),"root_mode":"0700","file_mode":"0600","symlink_free":true,"fresh":true,"outside_input_and_repo":true,"writes_relative_paths":writes},"questions":questions,"cost":{"all_run_ms":milliseconds(started),"identity_before_ms":identity_before_ms,"identity_after_ms":identity_after_ms,"sample_count":times.len(),"mean_question_ms":mean,"p50_question_ms":quantile(0.5),"p95_question_ms":quantile(0.95),"quantile_method":"nearest-rank","counts":counts(run.mode, run.embedding_cost(true))},"claims":{"dataset":"development-regression-9-small-sample","attribution":"observed-comparison","fts_vec_correctness":"NOT_VERIFIED","pure_engine":false},"after_verification":after});
    write_private(root, "run.json", &output)?;
    if let Some(code) = failure {
        bail!("{code}");
    }
    // Public stdout contains only non-sensitive terminal facts. Full evidence is private.
    Ok(
        json!({"schema":"cass.regression-run-summary.v1","mode":"full-search","terminal":terminal,"quality_status":"NOT_EVALUATED","question_count":questions.len()}),
    )
}

#[cfg(all(test, target_os = "linux"))]
pub(super) mod tests {
    use super::*;
    use crate::regression::types::*;
    use crate::search::{regression_binding, regression_trace};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    const QIDS: [&str; 9] = [
        "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
    ];
    pub(in crate::regression) struct Fixture {
        _root: tempfile::TempDir,
        input: InputOptions,
        pool: PathBuf,
        pool_sha: String,
    }

    fn fixture(fault: &str) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let suite = root.path().join("package");
        let output = root.path().join("output");
        let bindings = root.path().join("bindings");
        for path in [&suite, &output, &bindings] {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let mut registry = Vec::new();
        let mut add = |relative: &str, bytes: Vec<u8>, roles: &[&str]| -> Value {
            let path = suite.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &bytes).unwrap();
            let source = format!("/synthetic-frozen/{relative}");
            registry.push(json!({"source_path":source,"path":relative,"sha256":digest(&bytes),"bytes":bytes.len(),"roles":roles}));
            json!({"path":source,"sha256":digest(&bytes)})
        };
        let mut text_refs = Vec::new();
        for index in 1..=200 {
            let text = format!("Synthetic candidate {index}. No private content.");
            let reference = add(
                &format!("assets/pr3/task-18/text/{index}.txt"),
                text.as_bytes().to_vec(),
                &["candidate_text"],
            );
            text_refs.push((reference, text.len()));
        }
        let policy = digest(b"synthetic-label-policy-v1");
        let mut windows = Vec::new();
        let mut spans = Vec::new();
        let mut rows = Vec::new();
        let mut pool_windows = Vec::new();
        for (qindex, qid) in QIDS.iter().enumerate() {
            let query = "retrieval".to_string();
            let query_sha = digest(query.as_bytes());
            let mut items = Vec::new();
            let mut span_items = Vec::new();
            for index in 1..=200 {
                let mid = if index % 2 == 0 {
                    json!(format!("synthetic-{index}"))
                } else {
                    json!(index)
                };
                let (reference, bytes) = &text_refs[index - 1];
                let item = json!({"rank":index,"message_id":mid,"conversation_id":qindex as i64,"text_path":reference["path"],"text_sha256":reference["sha256"],"bytes":bytes,"source_sha256":digest(b"synthetic-source"),"original_score":1.25,"scoreable":true,"fallback_reason":null});
                items.push(item);
                span_items.push(json!({"rank":index,"message_id":mid}));
                rows.push(json!({"qid":qid,"rank":index,"message_id":mid,"query_sha256":query_sha,"text_sha256":reference["sha256"],"label":"direct","reason":"synthetic judgement","provenance":{"kind":"synthetic"}}));
            }
            if qindex == 0 {
                match fault {
                    "missing_slot" => {
                        items.pop();
                    }
                    "duplicate_rank" => items[1]["rank"] = json!(1),
                    "duplicate_mid" => items[1]["message_id"] = items[0]["message_id"].clone(),
                    "unregistered_text" => {
                        items[0]["text_path"] = json!("/synthetic-frozen/unregistered.txt")
                    }
                    "wrong_query" => items[0]["text_sha256"] = json!(digest(b"unrelated")),
                    "wrong_span" => span_items[0]["message_id"] = json!(999999),
                    "unsure_required" => items[0]["scoreable"] = json!(false),
                    "valid_categories" => items[0]["scoreable"] = json!(false),
                    "missing_fallback" => {
                        items[0].as_object_mut().unwrap().remove("fallback_reason");
                    }
                    _ => {}
                }
            }
            windows.push(json!({"qid":qid,"query":query,"query_sha256":query_sha,"items":items}));
            spans.push(json!({"qid":qid,"items":span_items}));
            pool_windows.push(json!({"qid":qid,"query_sha256":query_sha,"count":200,"ordered_pool_sha256":digest(b"synthetic-pool-not-yet-evaluated")}));
        }
        if fault == "duplicate_qid" {
            windows[1]["qid"] = windows[0]["qid"].clone();
        }
        if fault == "wrong_label" {
            rows[0]["message_id"] = json!(999999);
        }
        if fault == "duplicate_label" {
            rows[1] = rows[0].clone();
        }
        if fault == "valid_categories" {
            rows[0]["label"] = json!("unsure");
            rows[0]["provenance"] = json!({"kind":"structural_unscoreable"});
            rows[1]["label"] = json!("partial");
            rows[2]["label"] = json!("none");
        }
        let encode_lines = |values: &[Value]| -> Vec<u8> {
            values
                .iter()
                .flat_map(|v| {
                    let mut bytes = serde_json::to_vec(v).unwrap();
                    bytes.push(b'\n');
                    bytes
                })
                .collect()
        };
        let window_ref = add(
            "assets/pr3/task-18/out/windows.jsonl",
            encode_lines(&windows),
            &["windows"],
        );
        let span_ref = add(
            "assets/pr3/task-18/out/span_proofs.jsonl",
            encode_lines(&spans),
            &["span_proofs"],
        );
        let manifest = json!({"schema":"cass.pr3.default-input.v1","query_order":QIDS,"pool_limit":200,"source_query_manifest_sha256":digest(b"synthetic-historical-identity"),"files":{"windows":window_ref,"span_proofs":span_ref}});
        let input_ref = add(
            "assets/pr3/task-18/out/INPUT-MANIFEST.json",
            serde_json::to_vec(&manifest).unwrap(),
            &["input_manifest"],
        );
        let input_sha = input_ref["sha256"].as_str().unwrap();
        let labels = json!({"schema":"cass.pr3.default-labels.v1","input_manifest_sha256":if fault == "wrong_input_identity" { digest(b"wrong") } else { input_sha.to_string() },"label_policy_sha256":policy,"rows":rows});
        let label_bytes = serde_json::to_vec(&labels).unwrap();
        let label_sha = digest(&label_bytes);
        add(
            "assets/pr3/task-19m/LABELS.json",
            label_bytes.clone(),
            &["labels"],
        );
        let freeze = json!({"schema":"cass.pr3.default-labels-freeze-manifest.v1","labels_frozen":true,"labels_sha256":label_sha,"labels_bytes":label_bytes.len(),"labels_rows":1800,"input_manifest_sha256":input_sha,"label_policy_sha256":if fault == "wrong_freeze" { digest(b"wrong") } else { policy.clone() },"not_user_confirmed":true,"not_an_independent_test_set":true});
        let freeze_ref = add(
            "assets/pr3/task-19m/LABELS-FREEZE-MANIFEST.json",
            serde_json::to_vec(&freeze).unwrap(),
            &["labels_freeze"],
        );
        drop(add);
        if fault == "asset_escape" {
            registry[0]["path"] = json!("../outside.txt");
        }
        if fault == "asset_alias" {
            let mut alias = registry[0].clone();
            alias["source_path"] = json!("/synthetic-frozen/alternate-source.txt");
            alias["roles"] = json!([]);
            registry.push(alias);
        }
        let counts = if fault == "valid_categories" {
            json!({"direct":1797,"partial":1,"none":1,"unsure":1})
        } else {
            json!({"direct":1800,"partial":0,"none":0,"unsure":0})
        };
        let inventory = json!({"schema":"cass.regression.source-inventory.v1","suite_id":"synthetic-suite-v1","mode":"synthetic","query_order":QIDS,"candidate_slots":1800,"labels":counts,"runtime_prefix_map":{},"files":registry,"limits":{}});
        let inventory_bytes = serde_json::to_vec(&inventory).unwrap();
        let inventory_sha = digest(&inventory_bytes);
        fs::write(suite.join("SOURCE-INVENTORY.json"), inventory_bytes).unwrap();
        let suite_value = json!({"schema":"cass.regression.suite-manifest.v1","suite_id":"synthetic-suite-v1","stage":"assets_only","mode":"synthetic","query_order":QIDS,"candidate_slots":1800,"label_counts":counts,"runtime_prefix_map":{},"files":registry,"limits":{},"source_inventory_sha256":inventory_sha});
        let suite_bytes = serde_json::to_vec(&suite_value).unwrap();
        fs::write(suite.join("SUITE-MANIFEST.json"), &suite_bytes).unwrap();
        let pool = bindings.join("pool.json");
        let pool_bytes = serde_json::to_vec(&json!({"schema":"cass.regression-fixed-pool.v1","suite_sha256":digest(&suite_bytes),"input_manifest_sha256":input_sha,"windows_file_sha256":window_ref["sha256"],"labels_sha256":label_sha,"label_freeze_sha256":freeze_ref["sha256"],"label_policy_sha256":policy,"source_inventory_sha256":inventory_sha,"windows":pool_windows})).unwrap();
        fs::write(&pool, &pool_bytes).unwrap();
        Fixture {
            input: InputOptions {
                suite: suite.clone(),
                suite_sha256: digest(&suite_bytes),
                labels: suite.join("assets/pr3/task-19m/LABELS.json"),
                labels_sha256: label_sha,
                output: OutputOptions {
                    output_root: output,
                    run_id: "synthetic-run".into(),
                },
            },
            pool,
            pool_sha: digest(&pool_bytes),
            _root: root,
        }
    }

    #[test]
    fn api_full_search_semantic_nine_questions_records_actual_query_costs() {
        use crate::search::model_api::{ApiConfig, ApiClient, EnvCredentialResolver, PrimaryEmbeddingCall};
        use crate::search::model_api::test_support::{HttpFixture, Reply};
        let (_f, data, mut cmd) = full_fixture_mode(7, 7, SearchMode::Semantic, Some(crate::search::query::VectorSearchMode::Exact));
        let server = HttpFixture::start(vec![Reply::Embeddings(8)]);
        let text = format!(r#"
version=1
default_embedding="embed"
[profiles.embed]
kind="embedding"
protocol="openai-embeddings-v1"
scope="loopback"
endpoint="{}"
model="example/api-embed"
model_revision="r1"
normalization="l2"
query_prefix="Query: "
"#, server.base());
        let config_path = data.path().join("api.toml");
        fs::write(&config_path, &text).unwrap();
        let config = ApiConfig::parse_toml(&text).unwrap();
        let profile = config.profile("embed").unwrap().clone();
        let RegressionCommand::FullSearch { api, database, source_manifest, expected_binding, expected_binding_sha256, .. } = &mut cmd else { unreachable!() };
        api.config_path = Some(config_path.clone());
        let storage = crate::storage::sqlite::FrankenStorage::open(database).unwrap();
        let call = PrimaryEmbeddingCall::new(ApiClient::new(config, Box::new(EnvCredentialResolver)), profile.clone(), false).unwrap();
        let probe = call.probe().unwrap();
        let built = crate::indexer::db_vector_catchup::run_api_primary_catchup_backfill(&storage, 64, &call, &profile, &probe, 42).unwrap_or_else(|error| panic!("{error}"));
        assert!(built.catchup.activated);
        storage.raw().execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;").unwrap();
        drop(storage);
        let expected_root = data.path().join("api-expected");
        fs::create_dir(&expected_root).unwrap();
        let (expected, pin) = regression_binding::tests::prepare_expected(&expected_root, database, source_manifest);
        *expected_binding = expected;
        *expected_binding_sha256 = pin;
        let db = database.clone();
        let before = fs::read(&db).unwrap();
        let before_calls = server.hits();
        let started = Instant::now();
        let provenance = RunProvenance::capture().unwrap();
        let owner = RegressionSearchRun::activate(super::super::input::prepare_full(&cmd).unwrap(), &cmd).unwrap();
        fs::write(config_path, "invalid after activation").unwrap();
        let summary = collect(&owner, &provenance, started, 0.0).unwrap();
        assert_eq!(summary["terminal"], "SUCCESS", "{summary}");
        let result: Value = serde_json::from_slice(&fs::read(owner.validated.paths.run_root.join("run.json")).unwrap()).unwrap();
        assert_eq!(result["terminal"], "SUCCESS", "{result}");
        assert_eq!(result["questions"].as_array().unwrap().len(), 9);
        let observed = server.hits() - before_calls;
        assert!(observed > 0);
        let reported = result["cost"]["counts"][1]["http_attempts"].as_u64().unwrap();
        assert_eq!(reported, observed as u64);
        assert_eq!(result["questions"].as_array().unwrap().iter().map(|q| q["cost"]["http"][1]["http_attempts"].as_u64().unwrap()).sum::<u64>(), reported);
        assert_eq!(result["quality_status"], "NOT_EVALUATED");
        for request in &server.requests()[before_calls..] {
            assert!(request.body()["input"][0].as_str().unwrap().starts_with("Query: "));
        }
        assert_eq!(before, fs::read(db).unwrap());
        let calls: Value = serde_json::from_slice(&fs::read(owner.validated.paths.run_root.join("api-embedding-calls.json")).unwrap()).unwrap();
        assert_eq!(calls["calls"].as_array().unwrap().len(), observed);
    }

    fn full_fixture(n: u32, count: usize) -> (Fixture, tempfile::TempDir, RegressionCommand) {
        full_fixture_mode(n, count, SearchMode::Lexical, None)
    }

    pub(in crate::regression) fn full_fixture_mode(
        n: u32,
        count: usize,
        mode: SearchMode,
        vector: Option<crate::search::query::VectorSearchMode>,
    ) -> (Fixture, tempfile::TempDir, RegressionCommand) {
        let f = fixture("");
        assert_eq!(file_digest(&f.pool).unwrap(), f.pool_sha);
        let (data, database, _, source_manifest) = if mode == SearchMode::Lexical {
            regression_binding::tests::searchable_fixture_with_count(count)
        } else {
            regression_binding::tests::searchable_fixture_with_embedding(count, "BAAI/bge-m3", 1024)
        };
        let (expected_binding, expected_binding_sha256) =
            regression_binding::tests::prepare_expected(data.path(), &database, &source_manifest);
        let manifest_sha = file_digest(&source_manifest).unwrap();
        let source_producer_receipt = data.path().join("source-receipt.json");
        let bytes = serde_json::to_vec(&json!({"schema":"cass.regression-source-receipt.v1","producer_id":"cass.pr9.verify-corpus","verification_policy":"cass.pr9.corpus-content-stable-file-v1","producer_source_sha256":digest(b"synthetic-producer"),"source_manifest_sha256":manifest_sha,"expected_file_count":5049,"checked":5049,"passed":true,"exit_code":0,"failure_count":0,"raw_evidence_sha256":digest(b"synthetic-evidence")})).unwrap();
        fs::write(&source_producer_receipt, &bytes).unwrap();
        let cmd = RegressionCommand::FullSearch {
            api: Default::default(),
            input: f.input.clone(),
            database,
            expected_binding,
            expected_binding_sha256,
            source_manifest,
            source_producer_receipt,
            source_producer_receipt_sha256: digest(&bytes),
            search_mode: mode,
            vector_search_mode: vector,
            rrf_limit: n,
            rerank: RerankSwitch::Off,
            page_size: None,
            rerank_provider: None,
            cutoffs: vec![5, 10, 20],
        };
        (f, data, cmd)
    }

    /// Like [`full_fixture_mode`], but the fixture's vector generation is built
    /// through the frozen model API named by `config`, so a semantic or hybrid
    /// run can bind to it. Local inference is retired.
    pub(in crate::regression) fn api_full_fixture_mode(
        n: u32,
        count: usize,
        mode: SearchMode,
        vector: Option<crate::search::query::VectorSearchMode>,
        config: &std::path::Path,
    ) -> (Fixture, tempfile::TempDir, RegressionCommand) {
        let f = fixture("");
        assert_eq!(file_digest(&f.pool).unwrap(), f.pool_sha);
        let (data, database, _run, source_manifest) =
            regression_binding::tests::searchable_fixture_with_api_embedding(count, config);
        let (expected_binding, expected_binding_sha256) =
            regression_binding::tests::prepare_expected(data.path(), &database, &source_manifest);
        let manifest_sha = file_digest(&source_manifest).unwrap();
        let source_producer_receipt = data.path().join("source-receipt.json");
        let bytes = serde_json::to_vec(&json!({"schema":"cass.regression-source-receipt.v1","producer_id":"cass.pr9.verify-corpus","verification_policy":"cass.pr9.corpus-content-stable-file-v1","producer_source_sha256":digest(b"synthetic-producer"),"source_manifest_sha256":manifest_sha,"expected_file_count":5049,"checked":5049,"passed":true,"exit_code":0,"failure_count":0,"raw_evidence_sha256":digest(b"synthetic-evidence")})).unwrap();
        fs::write(&source_producer_receipt, &bytes).unwrap();
        let cmd = RegressionCommand::FullSearch {
            api: crate::search::regression_input::RegressionApiOptions {
                config_path: Some(config.to_path_buf()),
                ..Default::default()
            },
            input: f.input.clone(),
            database,
            expected_binding,
            expected_binding_sha256,
            source_manifest,
            source_producer_receipt,
            source_producer_receipt_sha256: digest(&bytes),
            search_mode: mode,
            vector_search_mode: vector,
            rrf_limit: n,
            rerank: RerankSwitch::Off,
            page_size: None,
            rerank_provider: None,
            cutoffs: vec![5, 10, 20],
        };
        (f, data, cmd)
    }

    fn prepared(n: u32, count: usize) -> (Fixture, tempfile::TempDir, RegressionSearchRun) {
        let (f, data, cmd) = full_fixture(n, count);
        let validated = crate::regression::input::prepare_full(&cmd).unwrap();
        let run = RegressionSearchRun::activate(validated, &cmd).unwrap();
        (f, data, run)
    }

    #[test]
    fn full_off_n5_n10_preserves_complete_same_parameter_ids_order_scores() {
        for n in [5, 10] {
            let (_f, _data, run) = prepared(n, 12);
            let original = run
                .client
                .search_with_fallback(
                    "retrieval",
                    Default::default(),
                    n as usize + 1,
                    0,
                    crate::sparse_threshold_for_visible_limit(3, n as usize, false),
                    crate::search::query::FieldMask::FULL,
                )
                .unwrap();
            assert!(original.hits.len() >= n as usize + 1);
            for _ in QIDS {
                let search = run.search_off("retrieval").unwrap();
                assert_eq!(search.result.hits.len(), n as usize);
                for (actual, expected) in search.result.hits.iter().zip(&original.hits) {
                    assert_eq!(
                        (actual.message_id, actual.conversation_id, actual.score),
                        (
                            expected.message_id,
                            expected.conversation_id,
                            expected.score
                        )
                    );
                }
                assert!(search.evidence.transport.requests.is_empty());
                assert_eq!(search.evidence.final_slots, search.evidence.retrieval);
            }
            run.verify_end().unwrap();
            let inventory_files = fs::read_dir(&run.validated.paths.run_root)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|e| e.file_name() == "input-binding-candidate.json")
                .count();
            assert_eq!(inventory_files, 1);
            let (f, _fresh_data, command) = full_fixture(n, 12);
            super::run(&command).unwrap();
            let run_root = f.input.output.output_root.join(&f.input.output.run_id);
            let report: Value =
                serde_json::from_slice(&fs::read(run_root.join("run.json")).unwrap()).unwrap();
            assert_eq!(report["questions"].as_array().unwrap().len(), 9);
            assert_eq!(report["terminal"], "SUCCESS");
            assert_eq!(report["cost"]["sample_count"], 9);
            assert_eq!(
                report["after_verification"]["inventory_digests"],
                "reused-initial-not-independently-reexported"
            );
            assert!(
                report["questions"][0]["slots"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|slot| slot["label"] == "unknown" && slot["sent_text"].is_null())
            );
            check_subjects(&run_root, &report);
            if let Ok(root) = dotenvy::var("CASS_S2_04_TEST_EVIDENCE") {
                let output = Path::new(&root).join(format!("module-n{n}"));
                fs::create_dir(&output).unwrap();
                fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
                for relative in private_files(&run_root).unwrap() {
                    let source = run_root.join(&relative);
                    let destination = output.join(&relative);
                    if let Some(parent) = destination.parent() {
                        fs::create_dir_all(parent).unwrap();
                        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
                    }
                    fs::copy(source, &destination).unwrap();
                    fs::set_permissions(destination, fs::Permissions::from_mode(0o600)).unwrap();
                }
            }
        }
    }

    #[test]
    fn short_complete_pool_is_short_window_and_not_evaluated() {
        let (f, _data, command) = full_fixture(10, 3);
        let result = super::run(&command).unwrap();
        let run_root = f.input.output.output_root.join(&f.input.output.run_id);
        assert_eq!(result["terminal"], "SHORT_WINDOW");
        assert_eq!(result["quality_status"], "NOT_EVALUATED");
        let report: Value =
            serde_json::from_slice(&fs::read(run_root.join("run.json")).unwrap()).unwrap();
        for q in report["questions"].as_array().unwrap() {
            assert_eq!(q["actual_n"], 3);
            assert_eq!(q["pool_complete"], true);
            assert_eq!(q["full_requested_n_claim"], false);
        }
    }

    #[test]
    fn aggregate_end_rejects_policy_and_source_changes() {
        let (_f, _data, mut run) = prepared(5, 12);
        run.search_off("retrieval").unwrap();
        run.binding.statistics_policy = "wrong-policy".into();
        assert_eq!(
            super::super::run::error_code(&run.verify_end().unwrap_err()),
            "AGGREGATE_POLICY_CHANGED"
        );
        run.binding.statistics_policy = "regression-fresh-v1".into();
        fs::write(
            run.validated.source_manifest.as_ref().unwrap(),
            b"changed synthetic manifest",
        )
        .unwrap();
        assert_eq!(
            super::super::run::error_code(&run.verify_end().unwrap_err()),
            "BINDING_SOURCE_CHANGED"
        );
    }

    #[test]
    fn missing_slots_are_rejected_by_product_complete_mapping_guard() {
        let (_f, _data, run) = prepared(5, 12);
        let evidence = run.search_off("retrieval").unwrap().evidence;
        assert!(regression_trace::final_slot_mapping(&evidence.retrieval, &[0, 1, 2, 3]).is_err());
    }

    #[test]
    fn partial_degraded_timeout_are_named_failures() {
        let (_f, _data, run) = prepared(5, 12);
        let mut result = run.search_off("retrieval").unwrap().result;
        assert_eq!(
            super::super::run::error_code(
                &super::super::run::validate_retrieval(&result, true, true).unwrap_err()
            ),
            "REGRESSION_SEARCH_TIMEOUT"
        );
        result.semantic_degraded = true;
        assert_eq!(
            super::super::run::error_code(
                &super::super::run::validate_retrieval(&result, true, false).unwrap_err()
            ),
            "REGRESSION_RETRIEVAL_DEGRADED"
        );
        result.semantic_degraded = false;
        assert_eq!(
            super::super::run::error_code(
                &super::super::run::validate_retrieval(&result, false, false).unwrap_err()
            ),
            "REGRESSION_RETRIEVAL_DEGRADED"
        );
        result.candidates = Some(serde_json::from_value(json!({"mode":"exact","k":0,"first_round_rows":0,"unique_messages":5,"incomplete":true,"reason":null,"approximate":false})).unwrap());
        assert_eq!(
            super::super::run::error_code(
                &super::super::run::validate_retrieval(&result, true, false).unwrap_err()
            ),
            "REGRESSION_PARTIAL_RESULTS"
        );
    }

    #[test]
    fn full_identity_golden_bytes_hashes_and_i64_boundaries() {
        let identity: regression_trace::CandidateIdentity = serde_json::from_str(r###"{"identity_host":"SYNTHETIC_HOST","agent_slug":"synthetic-agent","external_id":"synthetic-session","message_idx":3,"chunk_idx":null}"###).unwrap();
        assert_eq!(
            hex::encode(serde_json::to_vec(&identity).unwrap()),
            "7b226964656e746974795f686f7374223a2253594e5448455449435f484f5354222c226167656e745f736c7567223a2273796e7468657469632d6167656e74222c2265787465726e616c5f6964223a2273796e7468657469632d73657373696f6e222c226d6573736167655f696478223a332c226368756e6b5f696478223a6e756c6c7d"
        );
        assert_eq!(
            candidate_instance_key(&identity).unwrap(),
            "59d417d9d84056b8fa9eb2d4baf4d00ad6ef7a1bfdfca228a048806abcf08c61"
        );
        let identity: regression_trace::CandidateIdentity = serde_json::from_str(r###"{"identity_host":"SYNTHETIC_HOST","agent_slug":"synthetic-agent","external_id":"synthetic-session","message_idx":3,"chunk_idx":0}"###).unwrap();
        assert_eq!(
            hex::encode(serde_json::to_vec(&identity).unwrap()),
            "7b226964656e746974795f686f7374223a2253594e5448455449435f484f5354222c226167656e745f736c7567223a2273796e7468657469632d6167656e74222c2265787465726e616c5f6964223a2273796e7468657469632d73657373696f6e222c226d6573736167655f696478223a332c226368756e6b5f696478223a307d"
        );
        assert_eq!(
            candidate_instance_key(&identity).unwrap(),
            "00f2dd566ebb4a21d9db7bd5d5072460173b4af37dd63811b38009b410c83e8a"
        );
        let identity: regression_trace::CandidateIdentity = serde_json::from_str(r###"{"identity_host":"SYNTHETIC_示例","agent_slug":"synthetic-agent","external_id":"synthetic-\\\"\n","message_idx":3,"chunk_idx":null}"###).unwrap();
        assert_eq!(
            hex::encode(serde_json::to_vec(&identity).unwrap()),
            "7b226964656e746974795f686f7374223a2253594e5448455449435fe7a4bae4be8b222c226167656e745f736c7567223a2273796e7468657469632d6167656e74222c2265787465726e616c5f6964223a2273796e7468657469632d5c5c5c225c6e222c226d6573736167655f696478223a332c226368756e6b5f696478223a6e756c6c7d"
        );
        assert_eq!(
            candidate_instance_key(&identity).unwrap(),
            "b3cd7d718546dac4e1aaa7eb90ac6058d1bb16a0ab60b9058ebc0de0cf675f14"
        );
        let mut identity = identity;
        identity.message_idx = i64::MIN;
        identity.chunk_idx = Some(i64::MAX);
        let bytes = serde_json::to_vec(&identity).unwrap();
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("-9223372036854775808")
        );
        let key = candidate_instance_key(&identity).unwrap();
        let slot = regression_trace::RetrievalSlot {
            input_slot: 0,
            retrieval_rank: 1,
            identity: identity.clone(),
            message_id: 1,
        };
        let mut reordered = slot.clone();
        reordered.input_slot = 4;
        reordered.retrieval_rank = 5;
        reordered.message_id = 99;
        assert_eq!(key, candidate_instance_key(&reordered.identity).unwrap());
        identity.chunk_idx = None;
        assert_ne!(key, candidate_instance_key(&identity).unwrap());
    }

    #[test]
    fn query_manifest_golden_bytes_and_order_digest_guard() {
        let rows: Vec<(String,String)> = serde_json::from_str(r###"[["N01","b1ff87f436a4f5c4e0aba3ccfd9b6585c4e5f801875baa338d2772e046a7874c"],["N02","fe8cd4f65a88c3d95106571782dfe00d7590cc3018fdcda8c0f898749680625a"],["N03","8c00694d0a9957131f32765ddc0be78834abb8ee2a3a70402fe833ed067efbd2"],["N04","5ab0e0180d72d0b4b7fe6a7d1842a008a728650f27170dfd46b261352ff46635"],["N05","145b98bd5690315c03a0bc17f87b37f4e30ac63f0951e3d9011d65c651d6c897"],["N06","e809f738b8744362772d97fd8f2e9addd52d2bcb2aa3328da7b57f08b841c3fb"],["N07","7abd20756d5133873b7cccaf2e4ec828c4c26b9410723c416cbccc1b1d60f8db"],["N08","597e70fe7a76189f381d78f834e366b64de898cb26ecfb0ec706a69e43b32ffb"],["N12","e109e00189bc127bc6f50eb1238cb09d11a56399d1b96ed51eca9e42995668c0"]]"###).unwrap();
        let windows: Vec<_> = rows
            .into_iter()
            .map(|(qid, query_sha256)| InputWindow {
                qid,
                query: String::new(),
                query_sha256,
                items: vec![],
            })
            .collect();
        let bytes = query_manifest_bytes(&windows).unwrap();
        assert_eq!(
            hex::encode(&bytes),
            "636173732e72656772657373696f6e2d71756572792d6d616e69666573742e7631005b5b224e3031222c2262316666383766343336613466356334653061626133636366643962363538356334653566383031383735626161333338643237373265303436613738373463225d2c5b224e3032222c2266653863643466363561383863336439353130363537313738326466653030643735393063633330313866646364613863306638393837343936383036323561225d2c5b224e3033222c2238633030363934643061393935373133316633323736356464633062653738383334616262386565326133613730343032666538333365643036376566626432225d2c5b224e3034222c2235616230653031383064373264306234623766653661376431383432613030386137323836353066323731373064666434366232363133353266663436363335225d2c5b224e3035222c2231343562393862643536393033313563303361306263313766383762333766346533306163363366303935316533643930313164363563363531643663383937225d2c5b224e3036222c2265383039663733386238373434333632373732643937666438663265396164646435326432626362326161333332386461376235376630386238343163336662225d2c5b224e3037222c2237616264323037353664353133333837336237636363616632653465633832386334633236623934313037323363343136636263636331623164363066386462225d2c5b224e3038222c2235393765373066653761373631383966333831643738663833346533363662363464653839386362323665636662306563373036613639653433623332666662225d2c5b224e3132222c2265313039653030313839626331323762633666353065623132333863623039643131613536333939643162393665643531656361396534323939353636386330225d5d"
        );
        assert_eq!(
            digest(&bytes),
            "bd6ea1d32e88d456b63c3dd10ac21509e96727de6f0b30359973d00962605649"
        );
        let mut changed = windows.clone();
        changed.swap(0, 1);
        assert!(query_manifest_bytes(&changed).is_err());
        changed = windows.clone();
        changed[0].query_sha256 = "00".repeat(32);
        assert_ne!(
            digest(&bytes),
            digest(&query_manifest_bytes(&changed).unwrap())
        );
        changed[0].query_sha256 = "AA".repeat(32);
        assert!(query_manifest_bytes(&changed).is_err());
        changed = windows.clone();
        changed.pop();
        assert!(query_manifest_bytes(&changed).is_err());
    }
    #[test]
    fn aggregate_rejects_runtime_database_and_wal_changes() {
        for wal in [false, true] {
            let (_f, _data, run) = prepared(5, 12);
            run.search_off("retrieval").unwrap();
            if wal {
                let path =
                    std::path::PathBuf::from(format!("{}-wal", run.context.database().display()));
                fs::write(path, b"synthetic non-empty WAL").unwrap();
            } else {
                let mut file = OpenOptions::new()
                    .append(true)
                    .open(run.context.database())
                    .unwrap();
                file.write_all(b"synthetic database mutation").unwrap();
                file.sync_all().unwrap();
            }
            let error = run.verify_end().unwrap_err();
            assert!(matches!(
                super::super::run::error_code(&error),
                "regression_database_digest_mismatch"
                    | "regression_input_changed"
                    | "regression_wal_not_finalized"
            ));
        }
    }

    #[test]
    fn aggregate_rejects_wrong_expected_generation_and_policy() {
        for field in ["generation", "statistics_policy"] {
            let (_f, _data, mut cmd) = full_fixture(5, 12);
            let RegressionCommand::FullSearch {
                expected_binding,
                expected_binding_sha256,
                ..
            } = &mut cmd
            else {
                unreachable!()
            };
            let mut value: Value =
                serde_json::from_slice(&fs::read(&expected_binding).unwrap()).unwrap();
            if field == "generation" {
                value["generation"]["generation_id"] = json!(99);
            } else {
                value["statistics_policy"] = json!("wrong-policy");
            }
            let bytes = serde_json::to_vec(&value).unwrap();
            fs::write(&expected_binding, &bytes).unwrap();
            *expected_binding_sha256 = digest(&bytes);
            let result = crate::regression::input::prepare_full(&cmd)
                .and_then(|validated| RegressionSearchRun::activate(validated, &cmd));
            let error = result.err().unwrap();
            assert!(matches!(
                super::super::run::error_code(&error),
                "EXPECTED_INPUT_BINDING_MISMATCH" | "INPUT_BINDING_POLICY_MISMATCH"
            ));
        }
    }

    #[test]
    fn semantic_fake_http_child() {
        let Ok(mode) = dotenvy::var("CASS_S2_04_SEMANTIC_CHILD") else {
            return;
        };
        let Ok(config) = dotenvy::var("CASS_S2_04_API_CONFIG") else {
            return;
        };
        let config = std::path::PathBuf::from(config);
        let mode = if mode == "semantic" {
            SearchMode::Semantic
        } else {
            SearchMode::Hybrid
        };
        let vector = if dotenvy::var("CASS_S2_04_VECTOR_CHILD").unwrap() == "fast" {
            crate::search::query::VectorSearchMode::Fast
        } else {
            crate::search::query::VectorSearchMode::Exact
        };
        let (_f, _data, cmd) = api_full_fixture_mode(5, 12, mode, Some(vector), &config);
        let result = super::run(&cmd).unwrap();
        let run_root = _f.input.output.output_root.join(&_f.input.output.run_id);
        assert_eq!(result["terminal"], "SUCCESS");
        let report: Value =
            serde_json::from_slice(&fs::read(run_root.join("run.json")).unwrap()).unwrap();
        // The semantic leg is served exclusively by the isolated fake embedding
        // HTTP now: the rerank bucket is never called, the embedding bucket sees
        // the isolated request(s), and no local model ever executes (the retired
        // provider reported the embedding leg under a different scope).
        assert_eq!(report["cost"]["counts"][0]["model_executions"], 0);
        assert_eq!(report["cost"]["counts"][1]["http_attempts"], 1);
        assert_eq!(report["cost"]["counts"][1]["http_response_observed"], 1);
        assert!(report["cost"]["counts"][1]["model_executions"].is_null());
        assert!(report["questions"][0]["cost"]["model_execution_ms"].is_null());
    }

    #[test]
    fn semantic_and_hybrid_off_use_only_isolated_fake_embedding_http() {
        use std::net::TcpListener;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::Duration;
        for mode in ["semantic", "hybrid"] {
            for vector_mode in ["exact", "fast"] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let origin = format!("http://{}", listener.local_addr().unwrap());
                // Freeze the embedding profile the child runs under. Local
                // inference is retired, so this explicit API config replaces the
                // retired `CASS_INFINITY_URL` provider selection.
                let api_config = tempfile::NamedTempFile::new().unwrap();
                {
                    use std::io::Write as _;
                    write!(
                        api_config.as_file(),
                        "version=1\n\
                         default_embedding=\"main\"\n\
                         [profiles.main]\n\
                         kind=\"embedding\"\n\
                         protocol=\"openai-embeddings-v1\"\n\
                         scope=\"loopback\"\n\
                         endpoint=\"{origin}/embeddings\"\n\
                         model=\"BAAI/bge-m3\"\n\
                         model_revision=\"fixture-r1\"\n\
                         normalization=\"l2\"\n\
                         expected_dimension=1024\n"
                    )
                    .unwrap();
                }
                let api_config = api_config.into_temp_path();
                let stop = Arc::new(AtomicBool::new(false));
                let done = stop.clone();
                let worker = std::thread::spawn(move || {
                    let mut paths = vec![];
                    while !done.load(Ordering::Acquire) {
                        let (mut stream, _) = match listener.accept() {
                            Ok(value) => value,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            Err(e) => panic!("{e}"),
                        };
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut bytes = Vec::new();
                        let mut buffer = [0; 4096];
                        let body = loop {
                            let n = stream.read(&mut buffer).unwrap();
                            assert!(n > 0);
                            bytes.extend_from_slice(&buffer[..n]);
                            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                                let header = String::from_utf8_lossy(&bytes[..end]);
                                let length = header
                                    .lines()
                                    .filter_map(|l| l.split_once(':'))
                                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                    .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                                    .unwrap_or(0);
                                if bytes.len() >= end + 4 + length {
                                    let path = header
                                        .lines()
                                        .next()
                                        .unwrap()
                                        .split_whitespace()
                                        .nth(1)
                                        .unwrap()
                                        .to_string();
                                    paths.push(path);
                                    break serde_json::from_slice::<Value>(
                                        &bytes[end + 4..end + 4 + length],
                                    )
                                    .unwrap();
                                }
                            }
                        };
                        assert_eq!(paths.last().unwrap(), "/embeddings");
                        assert_eq!(body["model"], "BAAI/bge-m3");
                        let mut embedding = vec![0.0; 1024];
                        embedding[0] = 1.0;
                        let body=json!({"data":body["input"].as_array().unwrap().iter().enumerate().map(|(i,_)|json!({"index":i,"embedding":embedding})).collect::<Vec<_>>()}).to_string();
                        write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                    }
                    paths
                });
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "regression::off::tests::semantic_fake_http_child",
                        "--nocapture",
                    ])
                    .env("CASS_S2_04_SEMANTIC_CHILD", mode)
                    .env("CASS_S2_04_VECTOR_CHILD", vector_mode)
                    .env("CASS_S2_04_API_CONFIG", &api_config)
                    .env("NO_PROXY", "127.0.0.1,localhost")
                    .env("no_proxy", "127.0.0.1,localhost")
                    .output()
                    .unwrap();
                stop.store(true, Ordering::Release);
                let paths = worker.join().unwrap();
                assert!(
                    output.status.success(),
                    "child stdout:\n{}\nchild stderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(!paths.is_empty());
                assert!(paths.iter().all(|p| p == "/embeddings"));
                println!(
                    "FAKE_HTTP mode={mode} vector={vector_mode} observed_embedding_requests={} observed_rerank_requests=0",
                    paths.len()
                );
            }
        }
    }
    fn check_subjects(root: &Path, report: &Value) {
        assert_eq!(
            fs::metadata(root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for q in report["questions"].as_array().unwrap() {
            let relative = format!("label-subjects-{}.json", q["qid"].as_str().unwrap());
            assert!(
                report["output"]["writes_relative_paths"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p == &relative)
            );
            let path = root.join(&relative);
            assert!(
                !fs::symlink_metadata(&path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let body: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(body["schema"], "cass.regression-label-subjects.v1");
            assert_eq!(body["qid"], q["qid"]);
            assert_eq!(body["label_policy_sha256"], report["label_policy_sha256"]);
            let query = body["query"]["utf8"].as_str().unwrap();
            assert_eq!(body["query"]["sha256"], digest(query.as_bytes()));
            assert_eq!(body["query"]["sha256"], q["query_sha256"]);
            assert_eq!(body["query"]["utf8_bytes"], query.len());
            let candidates = body["candidates"].as_array().unwrap();
            let slots = q["slots"].as_array().unwrap();
            assert_eq!(candidates.len(), slots.len());
            let mut keys = std::collections::HashSet::new();
            for (subject, slot) in candidates.iter().zip(slots) {
                assert!(keys.insert(subject["candidate_instance_key"].as_str().unwrap()));
                assert_eq!(
                    subject["candidate_instance_key"],
                    slot["candidate_instance_key"]
                );
                assert_eq!(subject["label_key"], slot["label_key"]);
                let text = subject["text"]["utf8"].as_str().unwrap();
                assert_eq!(subject["text"]["sha256"], digest(text.as_bytes()));
                assert_eq!(subject["text"]["sha256"], slot["candidate_text"]["sha256"]);
                assert_eq!(subject["text"]["utf8_bytes"], text.len());
                assert_eq!(
                    subject["text"]["utf8_bytes"],
                    slot["candidate_text"]["utf8_bytes"]
                );
            }
        }
    }

    fn full_cli(command: &RegressionCommand) -> crate::CliResult<()> {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        let RegressionCommand::FullSearch {
            input,
            database,
            expected_binding,
            expected_binding_sha256,
            source_manifest,
            source_producer_receipt,
            source_producer_receipt_sha256,
            search_mode,
            vector_search_mode,
            rrf_limit,
            ..
        } = command
        else {
            unreachable!()
        };
        let mut argv = vec![
            "cass".into(),
            "regression".into(),
            "full-search".into(),
            "--suite".into(),
            input.suite.display().to_string(),
            "--suite-sha256".into(),
            input.suite_sha256.clone(),
            "--labels".into(),
            input.labels.display().to_string(),
            "--labels-sha256".into(),
            input.labels_sha256.clone(),
            "--output-root".into(),
            input.output.output_root.display().to_string(),
            "--run-id".into(),
            input.output.run_id.clone(),
            "--database".into(),
            database.display().to_string(),
            "--expected-binding".into(),
            expected_binding.display().to_string(),
            "--expected-binding-sha256".into(),
            expected_binding_sha256.clone(),
            "--source-manifest".into(),
            source_manifest.display().to_string(),
            "--source-producer-receipt".into(),
            source_producer_receipt.display().to_string(),
            "--source-producer-receipt-sha256".into(),
            source_producer_receipt_sha256.clone(),
            "--search-mode".into(),
            crate::search_mode_canonical_str(*search_mode).into(),
            "--rrf-limit".into(),
            rrf_limit.to_string(),
            "--rerank".into(),
            "off".into(),
        ];

        if let Some(vector) = vector_search_mode {
            argv.extend([
                "--vector-search-mode".into(),
                crate::vector_search_mode_wire(*vector).into(),
            ]);
        }
        let parsed = crate::parse_cli(argv)?;
        let mut future = std::pin::pin!(crate::run_with_parsed(parsed));
        let Poll::Ready(result) = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
        else {
            panic!("synchronous regression must complete");
        };
        result
    }

    fn archive_run(root: &Path, destination: &Path) {
        fs::create_dir(destination).unwrap();
        fs::set_permissions(destination, fs::Permissions::from_mode(0o700)).unwrap();
        for relative in private_files(root).unwrap() {
            let target = destination.join(&relative);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).unwrap();
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();
            }
            fs::copy(root.join(relative), &target).unwrap();
            fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn private_label_body_stdout_child() {
        if dotenvy::var("CASS_S2_04_STDOUT_CHILD").is_err() {
            return;
        }
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let (_f, _data, command) = full_fixture(5, 12);
                full_cli(&command).unwrap();
                let input = &_f.input;
                let run_root = input.output.output_root.join(&input.output.run_id);
                let report: Value =
                    serde_json::from_slice(&fs::read(run_root.join("run.json")).unwrap()).unwrap();
                check_subjects(&run_root, &report);
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn top_level_off_summary_does_not_print_query_or_candidate_bodies() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "regression::off::tests::private_label_body_stdout_child",
                "--nocapture",
            ])
            .env("CASS_S2_04_STDOUT_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("cass.regression-run-summary.v1"));
        assert!(!stdout.contains("retrieval"));
        assert!(!stdout.contains("Investigate retrieval ranking"));
        assert!(!stdout.contains("Synthetic candidate"));
    }
    #[test]
    fn failed_activation_preserves_failed_terminal_quality_and_named_error() {
        let (f, _data, mut command) = full_fixture(5, 12);
        let RegressionCommand::FullSearch {
            expected_binding,
            expected_binding_sha256,
            ..
        } = &mut command
        else {
            unreachable!()
        };
        let mut expected: Value =
            serde_json::from_slice(&fs::read(&expected_binding).unwrap()).unwrap();
        expected["generation"]["generation_id"] = json!(99);
        let bytes = serde_json::to_vec(&expected).unwrap();
        fs::write(&expected_binding, &bytes).unwrap();
        *expected_binding_sha256 = digest(&bytes);
        let error = super::run(&command).unwrap_err();
        assert_eq!(
            super::super::run::error_code(&error),
            "EXPECTED_INPUT_BINDING_MISMATCH"
        );
        let root = f.input.output.output_root.join(&f.input.output.run_id);
        let report: Value =
            serde_json::from_slice(&fs::read(root.join("search-failure.json")).unwrap()).unwrap();
        assert_eq!(report["terminal"], "FAILED");
        assert_eq!(report["quality_status"], "FAILED");
        assert_eq!(report["failure_code"], "EXPECTED_INPUT_BINDING_MISMATCH");
        assert_eq!(report["stage"], "ACTIVATION");
        assert!(root.join("input-binding-candidate.json").is_file());
        assert!(!root.join("run.json").exists());
        if let Ok(directory) = dotenvy::var("CASS_S2_04_TEST_EVIDENCE") {
            archive_run(&root, &Path::new(&directory).join("failure-activation"));
        }
    }

    #[test]
    fn failed_final_source_verification_keeps_nine_questions_and_original_scores() {
        let started = Instant::now();
        let (_f, _data, run) = prepared(5, 12);
        let initial_ms = milliseconds(started);
        let original = run
            .client
            .search_with_fallback(
                "retrieval",
                Default::default(),
                6,
                0,
                3,
                crate::search::query::FieldMask::FULL,
            )
            .unwrap();
        fs::write(
            run.validated.source_manifest.as_ref().unwrap(),
            b"changed synthetic manifest inside aggregate lifetime",
        )
        .unwrap();
        let error = collect(
            &run,
            &RunProvenance::capture().unwrap(),
            started,
            initial_ms,
        )
        .unwrap_err();
        assert_eq!(
            super::super::run::error_code(&error),
            "BINDING_SOURCE_CHANGED"
        );
        let root = &run.validated.paths.run_root;
        let report: Value =
            serde_json::from_slice(&fs::read(root.join("run.json")).unwrap()).unwrap();
        assert_eq!(report["terminal"], "FAILED");
        assert_eq!(report["quality_status"], "FAILED");
        assert_eq!(report["failure_code"], "BINDING_SOURCE_CHANGED");
        assert!(report["observed_after"].is_null());
        assert!(report["after_verification"].is_null());
        assert_eq!(report["questions"].as_array().unwrap().len(), 9);
        for question in report["questions"].as_array().unwrap() {
            assert_eq!(question["terminal"], "SUCCESS");
            assert_eq!(question["actual_n"], 5);
            for (slot, hit) in question["slots"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&original.hits)
            {
                assert_eq!(slot["message_id"], json!(hit.message_id));
                assert_eq!(slot["original_score"], json!(hit.score));
                assert!(slot["rerank_score"].is_null());
            }
        }
        check_subjects(root, &report);
        if let Ok(directory) = dotenvy::var("CASS_S2_04_TEST_EVIDENCE") {
            archive_run(root, &Path::new(&directory).join("failure-final-source"));
        }
    }

    #[test]
    fn embedding_transport_failure_child() {
        let Ok(mode) = dotenvy::var("CASS_S2_04_FAILURE_CHILD") else {
            return;
        };
        let rc = std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(move || {
                let mode = if mode == "semantic" {
                    SearchMode::Semantic
                } else {
                    SearchMode::Hybrid
                };
                let (f, _data, command) = full_fixture_mode(
                    5,
                    12,
                    mode,
                    Some(crate::search::query::VectorSearchMode::Exact),
                );
                let error = full_cli(&command).unwrap_err();
                assert_eq!(error.code, 2);
                let root = f.input.output.output_root.join(&f.input.output.run_id);
                let report: Value =
                    serde_json::from_slice(&fs::read(root.join("run.json")).unwrap()).unwrap();
                assert_eq!(report["terminal"], "FAILED");
                assert_eq!(report["quality_status"], "FAILED");
                assert_eq!(report["failure_code"], error.message);
                assert_eq!(report["questions"].as_array().unwrap().len(), 0);
                assert!(report["observed_after"].is_null());
                assert!(report["after_verification"].is_null());
                assert_eq!(report["cost"]["counts"][0]["model_executions"], 0);
                assert!(report["cost"]["counts"][1]["http_attempts"].is_null());
                archive_run(
                    &root,
                    &PathBuf::from(dotenvy::var("CASS_S2_04_FAILURE_EVIDENCE").unwrap())
                        .join("run-artifacts"),
                );
                println!("FAILED_CLI_RC={} CODE={}", error.code, error.message);
                error.code
            })
            .unwrap()
            .join()
            .unwrap();
        std::process::exit(rc);
    }

    #[test]
    fn aggregate_semantic_hybrid_http500_invalid_response_disconnect_are_failed() {
        use std::net::TcpListener;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::Duration;
        for mode in ["semantic", "hybrid"] {
            for fault in ["http500", "invalid-response", "disconnect"] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                listener.set_nonblocking(true).unwrap();
                let origin = format!("http://{}", listener.local_addr().unwrap());
                let stop = Arc::new(AtomicBool::new(false));
                let done = stop.clone();
                let worker = std::thread::spawn(move || {
                    let mut paths = vec![];
                    while !done.load(Ordering::Acquire) {
                        let (mut stream, _) = match listener.accept() {
                            Ok(v) => v,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            Err(e) => panic!("{e}"),
                        };
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let mut bytes = Vec::new();
                        let mut buffer = [0; 4096];
                        loop {
                            let n = stream.read(&mut buffer).unwrap();
                            assert!(n > 0);
                            bytes.extend_from_slice(&buffer[..n]);
                            if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                                let header = String::from_utf8_lossy(&bytes[..end]);
                                let length = header
                                    .lines()
                                    .filter_map(|l| l.split_once(':'))
                                    .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                                    .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                                    .unwrap_or(0);
                                if bytes.len() >= end + 4 + length {
                                    let path = header
                                        .lines()
                                        .next()
                                        .unwrap()
                                        .split_whitespace()
                                        .nth(1)
                                        .unwrap()
                                        .to_string();
                                    assert_eq!(path, "/embeddings");
                                    paths.push(path);
                                    let body: Value =
                                        serde_json::from_slice(&bytes[end + 4..end + 4 + length])
                                            .unwrap();
                                    assert_eq!(body["model"], "BAAI/bge-m3");
                                    break;
                                }
                            }
                        }
                        if fault == "disconnect" {
                            drop(stream);
                            continue;
                        }
                        let (status, body) = if fault == "http500" {
                            (
                                "500 Internal Server Error",
                                "{\"error\":\"synthetic server failure\"}",
                            )
                        } else {
                            ("200 OK", "synthetic invalid JSON")
                        };
                        write!(stream,"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                    }
                    paths
                });
                let temporary = tempfile::tempdir().unwrap();
                let case = if let Ok(directory) = dotenvy::var("CASS_S2_04_TEST_EVIDENCE") {
                    PathBuf::from(directory).join(format!("failure-{mode}-{fault}"))
                } else {
                    temporary.path().join("case")
                };
                fs::create_dir(&case).unwrap();
                fs::set_permissions(&case, fs::Permissions::from_mode(0o700)).unwrap();
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "regression::off::tests::embedding_transport_failure_child",
                        "--nocapture",
                    ])
                    .env("CASS_S2_04_FAILURE_CHILD", mode)
                    .env("CASS_S2_04_FAILURE_EVIDENCE", &case)
                    .env("CASS_INFINITY_URL", origin)
                    .env("CASS_INFINITY_EMBED_MODEL", "BAAI/bge-m3")
                    .env("NO_PROXY", "127.0.0.1,localhost")
                    .env("no_proxy", "127.0.0.1,localhost")
                    .output()
                    .unwrap();
                stop.store(true, Ordering::Release);
                let paths = worker.join().unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(2),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(!paths.is_empty());
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(stdout.contains("FAILED_CLI_RC=2"));
                assert!(!stdout.contains("retrieval"));
                assert!(!stdout.contains("Investigate retrieval ranking"));
                assert!(!stdout.contains("SUCCESS"));
                fs::write(case.join("stdout.log"), &output.stdout).unwrap();
                fs::write(case.join("stderr.log"), &output.stderr).unwrap();
                write_private(&case,"transport.json",&json!({"mode":mode,"fault":fault,"observed_paths":paths,"observed_rerank_requests":0,"child_exit_code":output.status.code(),"cli_rc":2,"timeout_deadline_tested":false})).unwrap();
                println!("REAL_AGGREGATE_FAILURE mode={mode} fault={fault} cli_rc=2");
            }
        }
    }
    #[test]
    fn exact_partial_aggregate_child() {
        if dotenvy::var("CASS_S2_04_PARTIAL_CHILD").is_err() {
            return;
        }
        struct ResetBudget;
        impl Drop for ResetBudget {
            fn drop(&mut self) {
                crate::search::query::reset_exact_scan_row_budget_for_test();
            }
        }
        let _reset = ResetBudget;
        crate::search::query::set_exact_scan_row_budget_for_test(10);
        let started = Instant::now();
        let (_f, _data, command) = full_fixture_mode(
            5000,
            4200,
            SearchMode::Semantic,
            Some(crate::search::query::VectorSearchMode::Exact),
        );
        let validated = crate::regression::input::prepare_full(&command).unwrap();
        let run = RegressionSearchRun::activate(validated, &command).unwrap();
        let identity_ms = milliseconds(started);
        let (hits, metadata) = run
            .client
            .search_semantic_with_meta(
                "retrieval",
                Default::default(),
                5001,
                0,
                crate::search::query::FieldMask::FULL,
            )
            .unwrap();
        assert_eq!(metadata.mode, crate::search::query::CandidateMode::Exact);
        assert!(metadata.incomplete);
        assert_eq!(metadata.reason.as_deref(), Some("exact_scan_row_budget"));
        assert_eq!(metadata.unique_messages, 10);
        assert_eq!(hits.len(), 10);
        let root = &run.validated.paths.run_root;
        write_private(
            root,
            "actual-partial-metadata.json",
            &serde_json::to_value(&metadata).unwrap(),
        )
        .unwrap();
        let error = collect(
            &run,
            &RunProvenance::capture().unwrap(),
            started,
            identity_ms,
        )
        .unwrap_err();
        assert_eq!(
            super::super::run::error_code(&error),
            "REGRESSION_PARTIAL_RESULTS"
        );
        let report: Value =
            serde_json::from_slice(&fs::read(root.join("run.json")).unwrap()).unwrap();
        assert_eq!(report["terminal"], "FAILED");
        assert_eq!(report["quality_status"], "FAILED");
        assert_eq!(report["failure_code"], "REGRESSION_PARTIAL_RESULTS");
        assert_eq!(report["questions"].as_array().unwrap().len(), 0);
        archive_run(
            root,
            &PathBuf::from(dotenvy::var("CASS_S2_04_PARTIAL_EVIDENCE").unwrap())
                .join("run-artifacts"),
        );
        println!("REAL_PARTIAL_AGGREGATE_REJECTED_CODE=REGRESSION_PARTIAL_RESULTS");
    }

    #[test]
    fn aggregate_exact_budget_partial_is_rejected_in_isolated_child() {
        use std::net::TcpListener;
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use std::time::Duration;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let worker = std::thread::spawn(move || {
            let mut requests = 0;
            while !done.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = vec![];
                let mut buffer = [0; 4096];
                let input = loop {
                    let n = stream.read(&mut buffer).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&buffer[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&bytes[..end]);
                        let length = header
                            .lines()
                            .filter_map(|l| l.split_once(':'))
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                            .map(|(_, v)| v.trim().parse::<usize>().unwrap())
                            .unwrap_or(0);
                        if bytes.len() >= end + 4 + length {
                            assert_eq!(
                                header.lines().next().unwrap().split_whitespace().nth(1),
                                Some("/embeddings")
                            );
                            break serde_json::from_slice::<Value>(
                                &bytes[end + 4..end + 4 + length],
                            )
                            .unwrap();
                        }
                    }
                };
                assert_eq!(input["model"], "BAAI/bge-m3");
                requests += 1;
                let mut embedding = vec![0.0; 1024];
                embedding[0] = 1.0;
                let body=json!({"data":input["input"].as_array().unwrap().iter().enumerate().map(|(i,_)|json!({"index":i,"embedding":embedding})).collect::<Vec<_>>()}).to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
            }
            requests
        });
        let temporary = tempfile::tempdir().unwrap();
        let case = if let Ok(directory) = dotenvy::var("CASS_S2_04_TEST_EVIDENCE") {
            PathBuf::from(directory).join("failure-exact-partial")
        } else {
            temporary.path().join("case")
        };
        fs::create_dir(&case).unwrap();
        fs::set_permissions(&case, fs::Permissions::from_mode(0o700)).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "regression::off::tests::exact_partial_aggregate_child",
                "--nocapture",
            ])
            .env("CASS_S2_04_PARTIAL_CHILD", "1")
            .env("CASS_S2_04_PARTIAL_EVIDENCE", &case)
            .env("CASS_INFINITY_URL", origin)
            .env("CASS_INFINITY_EMBED_MODEL", "BAAI/bge-m3")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .output()
            .unwrap();
        stop.store(true, Ordering::Release);
        let count = worker.join().unwrap();
        fs::write(case.join("stdout.log"), &output.stdout).unwrap();
        fs::write(case.join("stderr.log"), &output.stderr).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(count > 0);
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("REAL_PARTIAL_AGGREGATE_REJECTED_CODE=REGRESSION_PARTIAL_RESULTS")
        );
        write_private(&case,"transport.json",&json!({"observed_embedding_requests":count,"observed_rerank_requests":0,"child_exit_code":output.status.code(),"timeout_deadline_tested":false})).unwrap();
    }
}
