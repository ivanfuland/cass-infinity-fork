//! Complete aggregate on windows. P09 remains the only scorer and page protocol.
use super::off::{
    RunProvenance, digest, file_digest, private_files, query_manifest_bytes, write_private,
};
use super::run::{RegressionSearchRun, milliseconds};
use super::types::{LabelKey, RegressionCommand};
use crate::search::query::{SearchFilters, SearchMode};
use crate::search::regression_trace::{
    self, PageEvidence, TextDigest, WindowEvidence, candidate_instance_key,
};
use crate::search::rerank::window::{self, WindowPolicy, WindowSnapshot, WindowStore};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Instant;

struct OnQuestion {
    question: Value,
    identity: crate::search::rerank::types::CallIdentity,
}

fn artifact(root: &Path, path: &Path) -> Result<Value> {
    Ok(
        json!({"relative_path":path.strip_prefix(root)?.to_str().ok_or_else(||anyhow::anyhow!("REGRESSION_REPORT_WRITE_FAILED"))?,"sha256":file_digest(path)?}),
    )
}

fn counts(trace: &regression_trace::RequestTrace, mode: SearchMode) -> Vec<Value> {
    let responses = trace
        .requests
        .iter()
        .filter(|r| r.http_status.is_some())
        .count();
    let mut result = vec![
        json!({"scope":"rerank-http-v1","http_attempts":trace.requests.len(),"http_response_observed":responses,"delivery_unknown":trace.requests.len()-responses,"model_executions":if trace.requests.is_empty() {Some(0)} else {None},"basis":if trace.requests.is_empty() {"not-called"} else {"observed-client"}}),
    ];
    if mode != SearchMode::Lexical {
        result.push(json!({"scope":"embedding-http","http_attempts":null,"http_response_observed":null,"delivery_unknown":null,"model_executions":null,"basis":"unknown"}));
    }
    result
}

fn validate_snapshot(
    run: &RegressionSearchRun,
    query: &str,
    snapshot: &WindowSnapshot,
    evidence: &WindowEvidence,
) -> Result<()> {
    if evidence.request != run.request {
        bail!("TRACE_WINDOW_REQUEST_MISMATCH");
    }
    evidence.validate(
        &run.context,
        &run.binding,
        query,
        &snapshot.result.hits,
        snapshot.rerank.applied,
    )?;
    if evidence.failure_reason.is_some() || (!evidence.final_slots.is_empty() && !evidence.applied)
    {
        bail!("TRACE_FAILED_WINDOW");
    }
    Ok(())
}

fn score_question(
    run: &RegressionSearchRun,
    window: &super::types::InputWindow,
) -> Result<OnQuestion> {
    let started = Instant::now();
    let root = &run.validated.paths.run_root;
    let (k, provider) = run
        .rerank
        .ok_or_else(|| anyhow::anyhow!("REQUEST_PROFILE_INVALID"))?;
    let raw = run.search_window(&window.query)?;
    let mode_meta = crate::SearchModeMeta::new(run.mode, false);
    let trace = std::sync::Arc::new(std::sync::Mutex::new(
        regression_trace::RequestTrace::default(),
    ));
    let execution = crate::RegressionSearchExecution {
        context: run.context.clone(),
        verified: None,
        binding: run.binding.clone(),
        trace: trace.clone(),
        endpoint: run.endpoint.clone(),
        window_root: None,
        source_manifest: run
            .validated
            .source_manifest
            .clone()
            .ok_or_else(|| anyhow::anyhow!("AGGREGATE_INPUT_MISSING"))?,
    };
    let semantic = crate::SemanticSearchOptions {
        model: (run.mode != SearchMode::Lexical).then(|| "bge-m3".into()),
        rerank: true,
        reranker: None,
        use_daemon: false,
        rerank_limit: Some(k),
        rerank_provider: Some(provider),
    };
    let mut capture = crate::FirstWindowCapture::default();
    let score_started = Instant::now();
    let outcome = crate::score_search_first_window(
        crate::FirstWindowInput {
            query: &window.query,
            result: raw.result,
            regression: Some(&execution),
            filters: &SearchFilters::default(),
            semantic_opts: &semantic,
            rerank_ctx: &crate::RerankRequestContext::default(),
            mode: Some(run.mode),
            vector_search_mode: run.vector_mode,
            effective_model: semantic.model.clone(),
            limit_val: run.n,
            aggregate: &None,
            has_aggregation: false,
            agg_fields: &[],
            explain: false,
            timeout_ms: None,
            timeout_duration: None,
            start_time: started,
            robot_meta: false,
            data_dir: root,
            db_path: &run.context.database().to_path_buf(),
            mode_meta: &mode_meta,
            search_ms: raw.retrieval_ms as u64,
            rerank_stamp_before: Some(raw.stamp),
            regression_embedding_binding: run
                .request
                .get("embedding_http_configuration")
                .filter(|v| !v.is_null())
                .cloned(),
        },
        Some(&mut capture),
    );
    let rerank_ms = milliseconds(score_started);
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            let observed = trace
                .lock()
                .map_err(|_| anyhow::anyhow!("REGRESSION_SEARCH_EVIDENCE_FAILED"))?
                .clone();
            // Raw preparation is retained as diagnostics. Only observed POST
            // documents can establish submission; a failed Run blocks labels.
            write_private(
                root,
                &format!("failed-window-{}.json", window.qid),
                &json!({"terminal":"FAILED","quality_status":"FAILED","failure_code":error.message,"query":TextDigest::of(&window.query),"transport":observed,"identity":capture.identity,"prepared_documents":capture.prepared_documents,"known_result":capture.result,"evidence":capture.evidence}),
            )?;
            bail!("{}", error.message);
        }
    };
    let snapshot = outcome
        .snapshot
        .ok_or_else(|| anyhow::anyhow!("REGRESSION_WINDOW_UNAVAILABLE"))?;
    let id = outcome
        .window_id
        .ok_or_else(|| anyhow::anyhow!("REGRESSION_WINDOW_UNAVAILABLE"))?;
    let evidence = capture
        .evidence
        .ok_or_else(|| anyhow::anyhow!("TRACE_WINDOW_MISSING"))?;
    let evidence_path = capture
        .evidence_path
        .ok_or_else(|| anyhow::anyhow!("TRACE_WINDOW_MISSING"))?;
    validate_snapshot(run, &window.query, &snapshot, &evidence)?;
    // Preserve the exact native cache wire bytes in a non-evictable artifact.
    let native_bytes = std::fs::read(root.join("cache/rerank-windows").join(format!("{id}.json")))?;
    if digest(&native_bytes) != id {
        bail!("TRACE_WINDOW_BINDING_MISMATCH");
    }
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut durable = options.open(root.join(format!("window-{}.json", window.qid)))?;
    use std::io::Write;
    durable.write_all(&native_bytes)?;
    durable.sync_all()?;
    let docs = capture.prepared_documents.unwrap_or_default();
    let paging_started = Instant::now();
    let store = WindowStore::open_existing(root, WindowPolicy::default())
        .map_err(|e| anyhow::anyhow!("{}", e.as_str()))?;
    let mut pages = vec![];
    let mut raw_pages = vec![];
    let mut current = snapshot.clone();
    let mut offset = 0;
    let mut cursor_in: Option<String> = None;
    if evidence.final_slots.is_empty() {
        if !current.result.hits.is_empty()
            || current.rerank.applied
            || evidence.applied
            || !evidence.transport.requests.is_empty()
        {
            bail!("TRACE_WINDOW_SLOT_MAPPING_MISMATCH");
        }
        write_private(
            root,
            &format!("empty-coverage-{}.json", window.qid),
            &json!({"schema":"cass.regression-empty-coverage.v1","query_sha256":window.query_sha256,"actual_n":0,"pages":0,"scoring_posts":0,"window_evidence":artifact(root,&evidence_path)?}),
        )?;
    } else {
        loop {
            validate_snapshot(run, &window.query, &current, &evidence)?;
            let hits = window::page_hits(&current, offset)
                .map_err(|e| anyhow::anyhow!("{}", e.as_str()))?;
            let page_path = regression_trace::persist_page(
                &run.context,
                &evidence,
                &id,
                offset,
                hits.len(),
                offset > 0,
            )?;
            let page: PageEvidence = serde_json::from_slice(&std::fs::read(&page_path)?)?;
            let cursor_out = window::next_cursor(&id, &current, offset, hits.len())
                .map_err(|e| anyhow::anyhow!("{}", e.as_str()))?;
            let keys = page
                .slots
                .iter()
                .map(|s| candidate_instance_key(&s.identity))
                .collect::<Result<Vec<_>>>()?;
            pages.push(json!({"window_id":id,"trace_sha256":page.trace_sha256,"offset":offset,"total_slots":page.total_slots,"candidate_instance_keys":keys,"cache_reused":page.cache_reused,"http_requests":page.http_requests,"model_requests":page.model_requests,"cursor_in_sha256":cursor_in.as_ref().map(|s|digest(s.as_bytes())),"cursor_out_sha256":cursor_out.as_ref().map(|s|digest(s.as_bytes())),"child_run_relative_path":page_path.strip_prefix(root)?.to_str(),"page_evidence":artifact(root,&page_path)?}));
            offset += hits.len();
            raw_pages.push(page);
            let Some(cursor) = cursor_out else {
                break;
            };
            let (loaded, loaded_offset) = store
                .load_for_regression(
                    &cursor,
                    &snapshot.request_binding,
                    &run.context,
                    crate::storage::sqlite::FrankenStorage::now_millis(),
                )
                .map_err(|e| anyhow::anyhow!("{}", e.as_str()))?;
            if loaded_offset != offset {
                bail!("TRACE_PAGE_SEQUENCE_MISMATCH");
            }
            let loaded_evidence: WindowEvidence = serde_json::from_value(
                loaded
                    .retrieval_status
                    .get("regression")
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("TRACE_WINDOW_MISSING"))?,
            )?;
            if serde_json::to_vec(&loaded_evidence)? != serde_json::to_vec(&evidence)? {
                bail!("TRACE_WINDOW_BINDING_MISMATCH");
            }
            cursor_in = Some(cursor);
            current = loaded;
        }
        regression_trace::validate_complete_pages(&raw_pages, &evidence)?;
    }
    let paging_ms = milliseconds(paging_started);
    let mut slots = vec![];
    let mut subjects = vec![];
    for (rank, (hit, slot)) in snapshot
        .result
        .hits
        .iter()
        .zip(&evidence.final_slots)
        .enumerate()
    {
        let doc = docs
            .get(slot.input_slot)
            .ok_or_else(|| anyhow::anyhow!("TRACE_MISSING_SUBMITTED_TEXT"))?;
        let sent = TextDigest::of(doc);
        let candidate = TextDigest::of(&hit.content);
        let instance = candidate_instance_key(&slot.identity)?;
        let key = LabelKey {
            query_sha256: window.query_sha256.clone(),
            label_text_sha256: sent.sha256.clone(),
            label_policy_sha256: run.validated.inputs.label_policy_sha256.clone(),
        };
        let label = run
            .validated
            .inputs
            .labels
            .iter()
            .find(|r| r.key == key)
            .map(|r| r.value.as_str())
            .unwrap_or("unknown");
        slots.push(json!({"candidate_instance_key":instance,"label_key":key,"input_slot":slot.input_slot,"retrieval_rank":slot.retrieval_rank,"final_rank":rank+1,"identity":slot.identity,"message_id":hit.message_id,"conversation_id":hit.conversation_id,"candidate_text":candidate,"sent_text":sent,"source_sha256":null,"original_score":hit.score,"rerank_score":hit.rerank_score,"label":label}));
        subjects.push(json!({"candidate_instance_key":instance,"label_key":key,"text":{"utf8":doc,"sha256":sent.sha256,"utf8_bytes":sent.utf8_bytes}}));
    }
    let query = TextDigest::of(&window.query);
    write_private(
        root,
        &format!("label-subjects-{}.json", window.qid),
        &json!({"schema":"cass.regression-label-subjects.v1","qid":window.qid,"query":{"utf8":window.query,"sha256":query.sha256,"utf8_bytes":query.utf8_bytes},"label_policy_sha256":run.validated.inputs.label_policy_sha256,"candidates":subjects}),
    )?;
    let actual_n = slots.len();
    let question = json!({"qid":window.qid,"query_sha256":window.query_sha256,"requested_n":run.n,"actual_n":actual_n,"pool_complete":true,"terminal":if actual_n<run.n {"SHORT_WINDOW"} else {"SUCCESS"},"full_requested_n_claim":actual_n==run.n,"rerank_applied":snapshot.rerank.applied,"ordered_pool_sha256":null,"slots":slots,"pages":pages,"window_evidence":artifact(root,&evidence_path)?,"partial":false,"timed_out":false,"failure_code":null,"lexical_statistics_status":if run.mode==SearchMode::Semantic {"NOT_USED"} else {"USED"},"lexical_statistics_sha256":evidence.lexical_statistics_sha256,"cost":{"identity_before_ms":raw.identity_before_ms,"identity_after_ms":raw.identity_after_ms,"retrieval_ms":raw.retrieval_ms,"rerank_client_ms":rerank_ms,"model_execution_ms":null,"paging_ms":paging_ms,"question_total_ms":milliseconds(started),"http":counts(&evidence.transport,run.mode),"resource_measurements":[]}});
    write_private(root, &format!("question-{}.json", window.qid), &question)?;
    Ok(OnQuestion {
        question,
        identity: snapshot.rerank.identity,
    })
}

fn summary_identity(values: &[crate::search::rerank::types::CallIdentity]) -> Value {
    let known = |field: fn(&crate::search::rerank::types::CallIdentity) -> Option<Value>| {
        let Some(first) = values.first().and_then(field) else {
            return Value::Null;
        };
        if values.len() != 9 || values.iter().any(|v| field(v).as_ref() != Some(&first)) {
            Value::Null
        } else {
            first
        }
    };
    json!({"provider":known(|v|v.actual_provider.and_then(|p|serde_json::to_value(p).ok())),"actual_model":known(|v|v.actual_model.as_ref().map(|s|json!(s))),"model_revision":null,"endpoint_origin_sha256":null,"server_template_policy":null,"document_assembly_policy":crate::search::rerank::context::document_assembly_policy(),"client_submission_policy":"verbatim-query-documents-v1"})
}

pub(crate) fn run(command: &RegressionCommand) -> Result<Value> {
    let started = Instant::now();
    let provenance = RunProvenance::capture()?;
    let validated = super::input::prepare_full(command)?;
    let root = validated.paths.run_root.clone();
    let owner = match RegressionSearchRun::activate(validated, command) {
        Ok(owner) => owner,
        Err(error) => {
            write_private(
                &root,
                "search-failure.json",
                &json!({"terminal":"FAILED","quality_status":"FAILED","failure_code":super::run::error_code(&error),"stage":"ACTIVATION"}),
            )?;
            return Err(error);
        }
    };
    collect(&owner, &provenance, started, milliseconds(started))
}

pub(crate) fn collect(
    run: &RegressionSearchRun,
    provenance: &RunProvenance,
    started: Instant,
    identity_before_ms: f64,
) -> Result<Value> {
    let root = &run.validated.paths.run_root;
    let argv_ref = write_private(root, "argv.json", &json!(provenance.argv))?;
    let request_ref = write_private(root, "request.json", &run.request)?;
    let mut questions = vec![];
    let mut times = vec![];
    let mut identities = vec![];
    let mut failure = None;
    let mut failed_transport = regression_trace::RequestTrace::default();
    for window in &run.validated.inputs.windows {
        match score_question(run, window) {
            Ok(outcome) => {
                times.push(
                    outcome.question["cost"]["question_total_ms"]
                        .as_f64()
                        .ok_or_else(|| anyhow::anyhow!("REGRESSION_REPORT_WRITE_FAILED"))?,
                );
                questions.push(outcome.question);
                identities.push(outcome.identity);
            }
            Err(error) => {
                failure = Some(super::run::error_code(&error).to_string());
                let failure_path = root.join(format!("failed-window-{}.json", window.qid));
                if failure_path.is_file() {
                    let known: Value = serde_json::from_slice(&std::fs::read(failure_path)?)?;
                    failed_transport = serde_json::from_value(known["transport"].clone())?;
                }
                break;
            }
        }
    }
    let end = Instant::now();
    if let Err(error) = run.verify_end() {
        failure = Some(super::run::error_code(&error).to_string());
    }
    let identity_after_ms = milliseconds(end);
    let succeeded = failure.is_none();
    let terminal = if !succeeded {
        "FAILED"
    } else if questions.iter().any(|q| q["terminal"] == "SHORT_WINDOW") {
        "SHORT_WINDOW"
    } else {
        "SUCCESS"
    };
    let mut sorted = times.clone();
    sorted.sort_by(f64::total_cmp);
    let mean = (!times.is_empty()).then(|| times.iter().sum::<f64>() / times.len() as f64);
    let quantile = |p: f64| {
        (!sorted.is_empty()).then(|| sorted[(p * sorted.len() as f64).ceil() as usize - 1])
    };
    let mut writes = private_files(root)?;
    writes.push("run.json".into());
    let (k, _) = run
        .rerank
        .ok_or_else(|| anyhow::anyhow!("REQUEST_PROFILE_INVALID"))?;
    let mut totals = failed_transport;
    for q in &questions {
        let path = q["window_evidence"]["relative_path"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("TRACE_WINDOW_MISSING"))?;
        let evidence: WindowEvidence = serde_json::from_slice(&std::fs::read(root.join(path))?)?;
        totals.requests.extend(evidence.transport.requests);
    }
    let after=succeeded.then(||json!({"basis":"equal-physical-db-and-source-generation-policy","inventory_digests":"reused-initial-not-independently-reexported","database_sha256":run.binding.database_sha256,"source_manifest_sha256":run.binding.source_manifest_sha256,"wal_bytes":0,"generation_unchanged":true,"policies_unchanged":true,"shared_maintenance_lease_held":true}));
    let output = json!({"schema":"cass.regression-run.v1","run_id":root.file_name().and_then(|s|s.to_str()),"mode":"full-search","terminal":terminal,"quality_status":if succeeded {"NOT_EVALUATED"} else {"FAILED"},"failure_code":failure,"source_commit":provenance.source_commit,"binary_sha256":provenance.binary_sha256,"argv_sha256":argv_ref["sha256"],"suite_sha256":run.validated.inputs.suite_sha256,"query_manifest_sha256":digest(&query_manifest_bytes(&run.validated.inputs.windows)?),"labels_sha256":run.validated.inputs.labels_sha256,"label_policy_sha256":run.validated.inputs.label_policy_sha256,"question_count":9,"suite_candidate_slots":1800,"source_identity":{"source_manifest_sha256":run.binding.source_manifest_sha256,"source_checked":5049,"source_producer_receipt_sha256":run.validated.source_receipt_sha256,"message_text_sha256":run.binding.message_text_sha256,"chunk_text_sha256":run.binding.chunk_text_sha256,"canonicalize_version":run.binding.canonicalize_version,"chunking_policy_version":run.binding.chunking_policy_version,"statistics_policy":run.binding.statistics_policy},"expected_binding_file_sha256":run.validated.expected_binding_file_sha256,"expected_binding":run.validated.expected_binding,"observed_before":run.binding,"observed_after":if succeeded {Some(&run.binding)} else {None},"fixed_input_manifest_sha256":null,"fixed_windows_file_sha256":null,"backend_identity":summary_identity(&identities),"request":{"search_mode":crate::search_mode_canonical_str(run.mode),"vector_search_mode":run.vector_mode.map(crate::vector_search_mode_wire),"rerank":true,"n":run.n,"page_k":k,"resolved_filters":run.request["resolved_filters"],"request_profile":"d5-fixed-filters-v1","request_evidence_sha256":request_ref["sha256"]},"output":{"private_root":root.parent().and_then(|p|p.to_str()),"run_relative_path":root.file_name().and_then(|p|p.to_str()),"root_mode":"0700","file_mode":"0600","symlink_free":true,"fresh":true,"outside_input_and_repo":true,"writes_relative_paths":writes},"questions":questions,"cost":{"all_run_ms":milliseconds(started),"identity_before_ms":identity_before_ms,"identity_after_ms":identity_after_ms,"sample_count":times.len(),"mean_question_ms":mean,"p50_question_ms":quantile(0.5),"p95_question_ms":quantile(0.95),"quantile_method":"nearest-rank","counts":counts(&totals,run.mode)},"claims":{"dataset":"development-regression-9-small-sample","attribution":"observed-comparison","fts_vec_correctness":"NOT_VERIFIED","pure_engine":false},"after_verification":after});
    write_private(root, "run.json", &output)?;
    if let Some(code) = failure {
        bail!("{code}");
    }
    Ok(
        json!({"schema":"cass.regression-run-summary.v1","mode":"full-search","terminal":terminal,"quality_status":"NOT_EVALUATED","question_count":questions.len()}),
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::types::*;
    use super::*;
    use crate::search::regression_binding;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    const QIDS: [&str; 9] = [
        "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
    ];
    struct Fixture {
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

    fn command(n: u32, k: u32, count: usize) -> (Fixture, tempfile::TempDir, RegressionCommand) {
        let f = fixture("");
        assert_eq!(file_digest(&f.pool).unwrap(), f.pool_sha);
        let (data, database, _, source_manifest) =
            regression_binding::tests::searchable_fixture_with_count(count);
        let (expected_binding, expected_binding_sha256) =
            regression_binding::tests::prepare_expected(data.path(), &database, &source_manifest);
        let source_producer_receipt = data.path().join("source-receipt.json");
        let bytes=serde_json::to_vec(&json!({"schema":"cass.regression-source-receipt.v1","producer_id":"cass.pr9.verify-corpus","verification_policy":"cass.pr9.corpus-content-stable-file-v1","producer_source_sha256":digest(b"synthetic-producer"),"source_manifest_sha256":file_digest(&source_manifest).unwrap(),"expected_file_count":5049,"checked":5049,"passed":true,"exit_code":0,"failure_count":0,"raw_evidence_sha256":digest(b"synthetic-evidence")})).unwrap();
        std::fs::write(&source_producer_receipt, &bytes).unwrap();
        let cmd = RegressionCommand::FullSearch {
            input: f.input.clone(),
            database,
            expected_binding,
            expected_binding_sha256,
            source_manifest,
            source_producer_receipt,
            source_producer_receipt_sha256: digest(&bytes),
            search_mode: SearchMode::Lexical,
            vector_search_mode: None,
            rrf_limit: n,
            rerank: RerankSwitch::On,
            page_size: Some(k),
            rerank_provider: Some(crate::search::rerank::types::ProviderChoice::BgeLocal),
            cutoffs: vec![5, 10, 20],
        };
        (f, data, cmd)
    }

    #[test]
    fn on_window_child() {
        let Ok(marker) = dotenvy::var("CASS_S2_05_CHILD") else {
            return;
        };
        let config: Value = serde_json::from_str(&marker).unwrap();
        let n = config["n"].as_u64().unwrap() as u32;
        let k = config["k"].as_u64().unwrap() as u32;
        let count = config["count"].as_u64().unwrap() as usize;
        let (f, _data, cmd) = command(n, k, count);
        let result = super::run(&cmd).unwrap();
        assert_eq!(
            result["terminal"],
            if count < n as usize {
                "SHORT_WINDOW"
            } else {
                "SUCCESS"
            }
        );
        let root = f.input.output.output_root.join(&f.input.output.run_id);
        let report: Value =
            serde_json::from_slice(&std::fs::read(root.join("run.json")).unwrap()).unwrap();
        assert_eq!(report["questions"].as_array().unwrap().len(), 9);
        for q in report["questions"].as_array().unwrap() {
            assert_eq!(q["actual_n"], n.min(count as u32));
            let actual = q["actual_n"].as_u64().unwrap() as usize;
            assert_eq!(
                q["pages"].as_array().unwrap().len(),
                actual.div_ceil(k as usize)
            );
            let slots = q["slots"].as_array().unwrap();
            let keys: std::collections::HashSet<_> = slots
                .iter()
                .map(|s| s["candidate_instance_key"].as_str().unwrap())
                .collect();
            assert_eq!(keys.len(), actual);
            for (i, slot) in slots.iter().enumerate() {
                assert_eq!(slot["retrieval_rank"], i + 1);
                assert_eq!(slot["final_rank"], i + 1);
                assert_eq!(slot["rerank_score"], 1.0);
                assert!(!slot["sent_text"].is_null());
            }
            for page in q["pages"].as_array().unwrap().iter().skip(1) {
                assert_eq!(page["http_requests"], 0);
                assert_eq!(page["model_requests"], 0);
            }
        }
        let output = PathBuf::from(config["output"].as_str().unwrap());
        std::fs::create_dir(&output).unwrap();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
        for relative in private_files(&root).unwrap() {
            let dest = output.join(&relative);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).unwrap();
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            std::fs::copy(root.join(relative), &dest).unwrap();
            std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn window_case(n: u32, k: u32, count: usize) {
        use std::io::{Read, Write};
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
            let mut posts = vec![];
            let mut gets = 0;
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
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut bytes = vec![];
                let mut buffer = [0; 4096];
                let (path, body) = loop {
                    let size = stream.read(&mut buffer).unwrap();
                    assert!(size > 0);
                    bytes.extend_from_slice(&buffer[..size]);
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
                            break (
                                path,
                                if length == 0 {
                                    Value::Null
                                } else {
                                    serde_json::from_slice(&bytes[end + 4..end + 4 + length])
                                        .unwrap()
                                },
                            );
                        }
                    }
                };
                let response=if path=="/models" {gets+=1;json!({"data":[{"id":"BAAI/bge-reranker-v2-m3"}]})} else {assert_eq!(path,"/rerank");let len=body["documents"].as_array().unwrap().len();posts.push(body);json!({"model":"BAAI/bge-reranker-v2-m3","results":(0..len).map(|i|json!({"index":i,"relevance_score":1.0})).collect::<Vec<_>>()})}.to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",response.len()).unwrap();
            }
            (gets, posts)
        });
        let temporary = tempfile::tempdir().unwrap();
        let evidence = dotenvy::var("CASS_S2_05_EVIDENCE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| temporary.path().to_path_buf());
        let output = evidence.join(format!("n{n}-k{k}-count{count}"));
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "regression::on::tests::on_window_child",
                "--nocapture",
            ])
            .env(
                "CASS_S2_05_CHILD",
                json!({"n":n,"k":k,"count":count,"output":output}).to_string(),
            )
            .env("CASS_INFINITY_URL", origin)
            .output()
            .unwrap();
        stop.store(true, Ordering::Release);
        let (gets, posts) = worker.join().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert_eq!(gets, 9);
        assert_eq!(posts.len(), 9);
        assert!(
            posts
                .iter()
                .all(|p| p["documents"].as_array().unwrap().len() == n.min(count as u32) as usize)
        );
        write_private(&evidence,&format!("http-n{n}-k{k}-count{count}.json"),&json!({"gets":gets,"posts":posts.iter().map(|p|json!({"query":TextDigest::of(p["query"].as_str().unwrap()),"documents":p["documents"].as_array().unwrap().iter().map(|d|TextDigest::of(d.as_str().unwrap())).collect::<Vec<_>>() })).collect::<Vec<_>>(),"child_rc":result.status.code()})).unwrap();
    }

    #[test]
    fn first_on_window_has_complete_pages_and_one_scoring_post_per_query() {
        window_case(7, 3, 9);
    }
    #[test]
    fn full_n200_k5_collects_nine_complete_forty_page_windows() {
        window_case(200, 5, 201);
    }
    #[test]
    fn full_n200_k10_collects_nine_complete_twenty_page_windows() {
        window_case(200, 10, 201);
    }
    #[test]
    fn short_n200_k5_preserves_actual_seven_and_two_pages() {
        window_case(200, 5, 7);
    }
    #[test]
    fn full_n7_k5_delivers_five_then_two() {
        window_case(7, 5, 9);
    }
}
