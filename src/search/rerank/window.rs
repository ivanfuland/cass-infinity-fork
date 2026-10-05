//! Fixed-order rerank window snapshots and cursors.
//!
//! A rerank first lookup computes a full ordering of the candidate window
//! (`N` hits) and returns the first page (`K` hits). Every later page must
//! reuse that same ordering instead of re-running retrieval or the rerank
//! model. This module owns the private, reclaimable cache that makes that
//! possible:
//!
//! - [`WindowSnapshot`] is the complete first-lookup result plus the metadata
//!   needed to prove a later page belongs to the same request and the same
//!   index generation.
//! - [`WindowStore`] writes and reads one snapshot per file under
//!   `<data_dir>/cache/rerank-windows/`, private (`0700`/`0600`), atomically
//!   published and bounded by [`WindowPolicy`].
//! - [`page_hits`] and [`next_cursor`] slice the stored ordering without
//!   touching the model, and advance the cursor by the number of hits
//!   actually delivered (a display budget may shrink a page below `K`).
//! - [`capture_index_stamp`] is the cross-process index identity guard: a
//!   persisted DB/WAL file fingerprint plus the active vector generation,
//!   never an in-process value such as `reader_generation`.
//!
//! Error codes are the whole vocabulary a caller may branch on:
//! [`WindowError`] renders only a `snake_case` short code, never a query, a
//! path or a response body. The mapping this module uses:
//!
//! - `InvalidInput` — a caller-supplied snapshot or binding violates the
//!   frozen contract (bad limits, non-finite scores, applied/score mismatch,
//!   duplicate hit identity, a snapshot that is too large for the policy, a
//!   private directory that is not owner-only, or a malformed `load` argument).
//! - `CacheUnavailable` — the private cache cannot be used safely right now
//!   (I/O error, lock busy, unsafe existing permissions, missing data root).
//! - `NotFound` — the cursor names a window file that is not present.
//! - `InvalidCursor` — the cursor itself is malformed, or its offset lies
//!   outside the window it names.
//! - `Corrupt` — the stored bytes, schema, key set or content violate the
//!   frozen window format, or the index identity cannot be established.
//! - `Expired` — the window's own `expires_at_ms` has passed.
//! - `BindingMismatch` — the continuation request differs from the frozen one.
//! - `IndexChanged` — the database or vector generation changed since the
//!   window was written (or changed while it was being fingerprinted).
//!
//! The WAL boundary follows the frozen P04 verdict
//! (`reports/window-stamp-boundary-verdict.md`): "no WAL" and "a zero-length
//! regular WAL" normalise to the same absent state, the SHM file is never part
//! of the identity, and every other DB/WAL field plus the first 32 WAL header
//! bytes are compared strictly.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::types::{
    CallIdentity, ProviderChoice, RerankFailureReason, decode_search_result, encode_search_result,
};
use crate::search::query::{SearchFilters, SearchHit, SearchResult};
use crate::sources::provenance::SourceFilter;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::query::{
        CacheStats, CandidateMeta, CandidateMode, MatchType, SearchHit, SearchResult,
    };
    use crate::storage::api::{Conn, Profile};
    use serde_json::json;
    use std::collections::HashSet;

    const NOW: i64 = 1_700_000_000_000;

    /// The libtest name of the subprocess entrypoint, resolved from the crate
    /// root. `--exact` needs this whole path, not the short function name.
    const CHILD_TEST_NAME: &str = "search::rerank::window::tests::p04_child_entrypoint";

    // ------------------------------------------------------------------
    // Fixtures
    // ------------------------------------------------------------------

    fn make_db(dir: &Path) -> PathBuf {
        let db = dir.join("agent_search.db");
        make_db_at(&db, false);
        db
    }

    fn make_db_with_generation(dir: &Path) -> PathBuf {
        let db = dir.join("agent_search.db");
        make_db_at(&db, true);
        db
    }

    fn make_db_at(db: &Path, with_generation: bool) {
        let conn =
            Conn::open_writable(db, Profile::Production).expect("open writable test database");
        crate::storage::schema::ensure(&conn).expect("build current schema");
        if with_generation {
            conn.execute(
                "INSERT INTO embedding_generations \
                 (embedder_id, dim, canonicalize_version, chunking_policy_version, fingerprint, \
                  byte_order, audit_status, is_active, created_at, activated_at, vector_revision) \
                 VALUES ('test-embedder', 4, 1, 1, X'0102', 'le', 'passed', 1, 1, 1, 0)",
                &[],
            )
            .expect("insert active embedding generation");
        }
        drop(conn);
    }

    fn store(dir: &Path) -> WindowStore {
        WindowStore::new(dir, WindowPolicy::default()).expect("open window store")
    }

    fn binding(n: usize, k: usize) -> RequestBinding {
        RequestBinding {
            query: "how do I page a rerank window".to_string(),
            agents: vec![
                "codex".to_string(),
                "claude".to_string(),
                "claude".to_string(),
            ],
            workspaces: vec!["/w/b".to_string(), "/w/a".to_string()],
            roles: Some(vec![2, 1, 2]),
            source_filter: SourceFilter::All,
            session_paths: vec!["/s/b.jsonl".to_string(), "/s/a.jsonl".to_string()],
            time: TimeSelectors {
                days: Some(7),
                today: false,
                yesterday: true,
                week: false,
                since: Some("2026-01-01".to_string()),
                until: None,
            },
            mode: "hybrid".to_string(),
            vector_search_mode: "exact".to_string(),
            embedding_model: Some("bge-m3".to_string()),
            rrf_limit: n,
            rerank_limit: k,
            provider: ProviderChoice::Qwen3Local,
            endpoint: "http://127.0.0.1:8000/v1/rerank?x=1".to_string(),
            aggregate: Some(vec!["agent".to_string(), "workspace".to_string()]),
            explain: true,
            timeout_ms: Some(60_000),
            daemon: false,
            no_daemon: true,
        }
    }

    fn hit(index: usize, score: f32) -> SearchHit {
        let message_id = index as i64 + 1;
        SearchHit {
            title: format!("hit-{index:02}"),
            snippet: format!("snippet {index}"),
            content: format!("content {index}"),
            content_hash: 0xDEAD_BEEF_0000_0000 + message_id as u64,
            conversation_id: Some(1000 + message_id),
            score,
            source_path: format!("/tmp/hit-{index:02}.jsonl"),
            agent: "claude".to_string(),
            workspace: "/w/a".to_string(),
            workspace_original: None,
            created_at: Some(NOW),
            line_number: Some(message_id as usize),
            match_type: MatchType::Exact,
            source_id: "local".to_string(),
            origin_kind: "local".to_string(),
            origin_host: None,
            message_id: Some(message_id),
            winning_chunk_idx: Some(1),
            winning_chunk_span: Some((10, 20)),
            winning_chunk_hash: Some("abc123".to_string()),
            rerank_score: None,
        }
    }

    /// `hits` is how many hits the frozen ordering stores; `n`/`k` are the
    /// bound window and page sizes (so an empty window still has `N >= 1`).
    fn snapshot(
        db: &Path,
        now: i64,
        applied: bool,
        hits: usize,
        n: usize,
        k: usize,
    ) -> WindowSnapshot {
        let binding = binding(n, k);
        let mut ordered = Vec::with_capacity(hits);
        for index in 0..hits {
            let mut entry = hit(index, 100.0 - index as f32);
            if applied {
                entry.rerank_score = Some(0.5 + index as f64);
            }
            ordered.push(entry);
        }

        WindowSnapshot {
            created_at_ms: now,
            expires_at_ms: now + WindowPolicy::default().ttl_ms as i64,
            request_binding: binding,
            index_stamp: capture_index_stamp(db).expect("capture index stamp"),
            resolved_filters: SearchFilters {
                agents: HashSet::from(["claude".to_string()]),
                created_from: Some(now - 86_400_000),
                created_to: Some(now),
                ..Default::default()
            },
            result: SearchResult {
                hits: ordered,
                wildcard_fallback: true,
                cache_stats: CacheStats {
                    cache_hits: 3,
                    eviction_policy: "s3-fifo".to_string(),
                    reader_generation: Some(11),
                    ..Default::default()
                },
                suggestions: Vec::new(),
                total_count: Some(hits),
                candidates: Some(CandidateMeta {
                    mode: CandidateMode::Knn,
                    k: 800,
                    first_round_rows: 812,
                    unique_messages: hits,
                    incomplete: false,
                    reason: None,
                    approximate: true,
                    requested_coarse_k: Some(4096),
                    effective_coarse_k: Some(1024),
                    coarse_cap_hit: Some(true),
                    corpus_limited: Some(false),
                    coarse_shard_count: Some(4),
                    coarse_rows_collected: Some(1024),
                    float_rescore_rows: Some(800),
                    coarse_skip_reason: None,
                }),
                semantic_degraded: false,
            },
            aggregates: Some(json!({"agent": {"claude": hits}})),
            explanation: Some(json!({"rrf": {"k": 60}})),
            retrieval_status: json!({"mode": "hybrid", "partial": false}),
            rerank: WindowRerankMeta {
                requested_provider: ProviderChoice::Qwen3Local,
                requested_model: ProviderChoice::Qwen3Local.request_model().to_string(),
                identity: CallIdentity {
                    actual_provider: Some(ProviderChoice::Qwen3Local),
                    actual_model: Some("Qwen3-Reranker-8B-local".to_string()),
                    serving_provider: None,
                },
                applied,
                failure_reason: if applied {
                    None
                } else {
                    Some(RerankFailureReason::HttpError)
                },
                http_status: if applied { Some(200) } else { Some(503) },
                scored_count: if applied { hits } else { 0 },
                http_requests: if applied { Some(2) } else { None },
                model_requests: if applied { Some(1) } else { None },
                duration_ms: 42,
            },
        }
    }

    fn titles(hits: &[SearchHit]) -> Vec<String> {
        hits.iter().map(|hit| hit.title.clone()).collect()
    }

    fn window_dir(root: &Path) -> PathBuf {
        root.join(WINDOW_DIR_RELATIVE)
    }

    fn save_and_cursor(st: &WindowStore, snap: &WindowSnapshot, offset: usize) -> (String, String) {
        let id = st.save(snap, snap.created_at_ms).expect("save window");
        let cursor = encode_cursor(&id, offset).expect("encode cursor");
        (id, cursor)
    }

    fn read_saved(root: &Path, id: &str) -> Value {
        let bytes = fs::read(window_dir(root).join(format!("{id}.json"))).expect("read window");
        serde_json::from_slice(&bytes).expect("parse window json")
    }

    /// Write a file `0600` so it passes the private-file gate.
    fn write_private(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("write file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("tighten to 0600");
        }
    }

    /// Write tampered bytes under their own content hash so the load path
    /// reaches schema/key validation instead of failing the hash check first.
    fn write_tampered(root: &Path, value: &Value) -> String {
        let bytes = serde_json::to_vec(value).expect("serialize tampered window");
        let id = sha256_hex(&bytes);
        write_private(&window_dir(root).join(format!("{id}.json")), &bytes);
        encode_cursor(&id, 0).expect("encode tampered cursor")
    }

    fn raw_cursor(value: Value) -> String {
        use base64::Engine as _;
        base64::prelude::BASE64_STANDARD.encode(serde_json::to_vec(&value).unwrap())
    }

    // ------------------------------------------------------------------
    // C1 - storage round trip and pagination
    // ------------------------------------------------------------------

    #[test]
    fn round_trip_preserves_private_fields_and_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);
        assert!(is_window_id(&id));

        let (loaded, offset) = st.load(&cursor, &snap.request_binding, &db, NOW).unwrap();
        assert_eq!(offset, 0);
        assert_eq!(loaded.result.hits.len(), 12);
        assert_eq!(
            loaded.result.hits[0].content_hash,
            snap.result.hits[0].content_hash
        );
        assert_eq!(loaded.result.hits[0].conversation_id, Some(1001));
        assert_eq!(loaded.result.hits[0].rerank_score, Some(0.5));
        assert_eq!(loaded.result.hits[1].rerank_score, Some(1.5));
        assert!(loaded.result.wildcard_fallback);
        assert_eq!(loaded.result.cache_stats.reader_generation, Some(11));
        assert_eq!(loaded.result.cache_stats.eviction_policy, "s3-fifo");

        let candidates = loaded.result.candidates.as_ref().expect("candidates");
        assert_eq!(candidates.mode, CandidateMode::Knn);
        assert_eq!(candidates.effective_coarse_k, Some(1024));
        assert_eq!(candidates.coarse_skip_reason, None);

        assert_eq!(loaded.resolved_filters.created_from, Some(NOW - 86_400_000));
        assert_eq!(loaded.resolved_filters.created_to, Some(NOW));
        assert_eq!(loaded.aggregates, Some(json!({"agent": {"claude": 12}})));
        assert_eq!(loaded.explanation, Some(json!({"rrf": {"k": 60}})));
        assert_eq!(
            loaded.retrieval_status,
            json!({"mode": "hybrid", "partial": false})
        );
        assert_eq!(loaded.rerank.http_requests, Some(2));
        assert_eq!(loaded.rerank.model_requests, Some(1));
        assert_eq!(loaded.rerank.scored_count, 12);
        assert_eq!(loaded.index_stamp, snap.index_stamp);
        assert_eq!(
            titles(&loaded.result.hits),
            (0..12).map(|i| format!("hit-{i:02}")).collect::<Vec<_>>()
        );
    }

    #[test]
    fn round_trip_preserves_null_call_counts_for_failed_window() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, false, 3, 5, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let (loaded, _) = st.load(&cursor, &snap.request_binding, &db, NOW).unwrap();
        assert!(!loaded.rerank.applied);
        assert_eq!(loaded.rerank.scored_count, 0);
        assert_eq!(loaded.rerank.http_requests, None);
        assert_eq!(loaded.rerank.model_requests, None);
        assert_eq!(
            loaded.rerank.failure_reason,
            Some(RerankFailureReason::HttpError)
        );
        assert!(
            loaded
                .result
                .hits
                .iter()
                .all(|hit| hit.rerank_score.is_none()),
            "a failed window must keep every rerank score absent"
        );
    }

    #[test]
    fn pages_advance_by_delivered_and_stop_at_end() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);

        let page1 = page_hits(&snap, 0).unwrap();
        assert_eq!(
            titles(&page1),
            ["hit-00", "hit-01", "hit-02", "hit-03", "hit-04"]
        );
        let cursor1 = next_cursor(&id, &snap, 0, page1.len()).unwrap().unwrap();

        let (snap2, offset2) = st.load(&cursor1, &snap.request_binding, &db, NOW).unwrap();
        assert_eq!(offset2, 5);
        let page2 = page_hits(&snap2, offset2).unwrap();
        assert_eq!(
            titles(&page2),
            ["hit-05", "hit-06", "hit-07", "hit-08", "hit-09"]
        );
        let cursor2 = next_cursor(&id, &snap2, offset2, page2.len())
            .unwrap()
            .unwrap();

        let (snap3, offset3) = st.load(&cursor2, &snap.request_binding, &db, NOW).unwrap();
        assert_eq!(offset3, 10);
        let page3 = page_hits(&snap3, offset3).unwrap();
        assert_eq!(titles(&page3), ["hit-10", "hit-11"]);
        assert_eq!(
            next_cursor(&id, &snap3, offset3, page3.len()).unwrap(),
            None
        );
    }

    #[test]
    fn budget_shrink_advances_by_delivered_without_skipping() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);

        // The display budget let only 2 of the first 5 through.
        let cursor = next_cursor(&id, &snap, 0, 2).unwrap().unwrap();
        let (snap2, offset) = st.load(&cursor, &snap.request_binding, &db, NOW).unwrap();
        assert_eq!(offset, 2);
        assert_eq!(
            titles(&page_hits(&snap2, offset).unwrap()),
            ["hit-02", "hit-03", "hit-04", "hit-05", "hit-06"]
        );

        // Zero delivered, and over-delivery, are handled distinctly.
        assert_eq!(next_cursor(&id, &snap, 0, 0).unwrap(), None);
        assert_eq!(
            next_cursor(&id, &snap, 0, 13).unwrap_err(),
            WindowError::InvalidInput
        );
    }

    #[test]
    fn empty_window_has_no_continuation_cursor() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 0, 5, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);

        assert!(page_hits(&snap, 0).unwrap().is_empty());
        assert_eq!(next_cursor(&id, &snap, 0, 0).unwrap(), None);
        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::InvalidCursor
        );
    }

    // ------------------------------------------------------------------
    // C2 - request/index identity, corruption and reclaim
    // ------------------------------------------------------------------

    #[test]
    fn relative_time_window_survives_changed_now() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let later = NOW + 120_000;
        let (loaded, _) = st.load(&cursor, &snap.request_binding, &db, later).unwrap();
        // The relative selectors are unchanged and the resolved bounds stay
        // frozen at the first lookup, not re-derived from `later`.
        assert_eq!(loaded.request_binding.time, snap.request_binding.time);
        assert_eq!(loaded.resolved_filters.created_from, Some(NOW - 86_400_000));
        assert_eq!(loaded.resolved_filters.created_to, Some(NOW));
    }

    #[test]
    fn changed_request_is_a_binding_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let mut variants = Vec::new();
        let mut query = snap.request_binding.clone();
        query.query = "a different query".to_string();
        variants.push(query);
        let mut agents = snap.request_binding.clone();
        agents.agents = vec!["other".to_string()];
        variants.push(agents);
        let mut limits = snap.request_binding.clone();
        limits.rerank_limit = 4;
        variants.push(limits);
        let mut provider = snap.request_binding.clone();
        provider.provider = ProviderChoice::BgeLocal;
        variants.push(provider);
        let mut endpoint = snap.request_binding.clone();
        endpoint.endpoint = "http://127.0.0.1:9999".to_string();
        variants.push(endpoint);
        let mut filters = snap.request_binding.clone();
        filters.roles = Some(vec![3]);
        variants.push(filters);

        for variant in variants {
            assert_eq!(
                st.load(&cursor, &variant, &db, NOW).unwrap_err(),
                WindowError::BindingMismatch
            );
        }
    }

    #[test]
    fn reordered_collections_are_the_same_binding() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let mut reordered = snap.request_binding.clone();
        reordered.agents = vec!["claude".to_string(), "codex".to_string()];
        reordered.workspaces = vec!["/w/a".to_string(), "/w/b".to_string()];
        reordered.session_paths = vec!["/s/a.jsonl".to_string(), "/s/b.jsonl".to_string()];
        reordered.roles = Some(vec![1, 2]);
        assert!(st.load(&cursor, &reordered, &db, NOW).is_ok());
    }

    #[test]
    fn tampered_bytes_fail_the_raw_hash_check() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);

        // Re-serialize valid JSON with a changed field: the filename no longer
        // matches the raw-byte digest, so the whole window is refused.
        let mut value = read_saved(tmp.path(), &id);
        value["result"]["hits"][0]["title"] = json!("tampered");
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(window_dir(tmp.path()).join(format!("{id}.json")), &bytes).unwrap();

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::Corrupt
        );
    }

    #[test]
    fn unknown_schema_and_missing_keys_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);
        let base = read_saved(tmp.path(), &id);

        let mut wrong_schema = base.clone();
        wrong_schema["schema"] = json!("cass.rerank-window.v2");
        let cursor = write_tampered(tmp.path(), &wrong_schema);
        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::Corrupt
        );

        for key in WINDOW_KEYS {
            let mut value = base.clone();
            value.as_object_mut().unwrap().remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing outer key {key} must be Corrupt"
            );
        }
        for key in BINDING_KEYS {
            let mut value = base.clone();
            value["request_binding"]
                .as_object_mut()
                .unwrap()
                .remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing binding key {key} must be Corrupt"
            );
        }
        for key in TIME_KEYS {
            let mut value = base.clone();
            value["request_binding"]["time"]
                .as_object_mut()
                .unwrap()
                .remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing time key {key} must be Corrupt"
            );
        }
        for key in RERANK_KEYS {
            let mut value = base.clone();
            value["rerank"].as_object_mut().unwrap().remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing rerank key {key} must be Corrupt"
            );
        }
        for key in IDENTITY_KEYS {
            let mut value = base.clone();
            value["rerank"]["identity"]
                .as_object_mut()
                .unwrap()
                .remove(*key);
            let cursor = write_tampered(tmp.path(), &value);
            assert_eq!(
                st.load(&cursor, &snap.request_binding, &db, NOW)
                    .unwrap_err(),
                WindowError::Corrupt,
                "missing identity key {key} must be Corrupt"
            );
        }
    }

    #[test]
    fn null_option_keys_are_accepted_but_missing_is_not() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, false, 3, 5, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);
        let base = read_saved(tmp.path(), &id);

        // Nulls round-trip: they are present keys. The expected binding must
        // carry the same nulled roles to compare equal.
        let mut nulled = base.clone();
        nulled["aggregates"] = Value::Null;
        nulled["explanation"] = Value::Null;
        nulled["request_binding"]["roles"] = Value::Null;
        nulled["rerank"]["failure_reason"] = Value::Null;
        nulled["rerank"]["http_status"] = Value::Null;
        let mut expected = snap.request_binding.clone();
        expected.roles = None;
        let cursor = write_tampered(tmp.path(), &nulled);
        assert!(st.load(&cursor, &expected, &db, NOW).is_ok());

        // A missing null-valued key is Corrupt.
        let mut missing = base.clone();
        missing["rerank"]
            .as_object_mut()
            .unwrap()
            .remove("http_status");
        let cursor = write_tampered(tmp.path(), &missing);
        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::Corrupt
        );
    }

    #[test]
    fn duplicate_message_identity_is_refused_on_save() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());

        // Duplicate identity.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[1].message_id = snap.result.hits[0].message_id;
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // Zero identity.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[0].message_id = Some(0);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // Negative identity.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[0].message_id = Some(-4);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // Absent identity.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[2].message_id = None;
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // A normal all-positive, unique window still saves.
        let snap = snapshot(&db, NOW, true, 3, 5, 5);
        assert!(st.save(&snap, NOW).is_ok());
    }

    #[test]
    fn next_cursor_enforces_the_page_contract() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);

        // A page that delivered nothing never repeats the same cursor.
        assert_eq!(next_cursor(&id, &snap, 5, 0).unwrap(), None);
        assert_eq!(next_cursor(&id, &snap, 0, 0).unwrap(), None);

        // One page can never deliver more than min(K, remaining).
        assert_eq!(
            next_cursor(&id, &snap, 0, 6).unwrap_err(),
            WindowError::InvalidInput
        );
        assert_eq!(
            next_cursor(&id, &snap, 0, 12).unwrap_err(),
            WindowError::InvalidInput
        );
        // Exactly K is the largest legal page.
        assert!(next_cursor(&id, &snap, 0, 5).unwrap().is_some());

        // On the last page the cap is what remains, which is below K.
        assert_eq!(next_cursor(&id, &snap, 10, 2).unwrap(), None);
        assert_eq!(
            next_cursor(&id, &snap, 10, 3).unwrap_err(),
            WindowError::InvalidInput
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_window_file_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);

        let path = window_dir(tmp.path()).join(format!("{id}.json"));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::CacheUnavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_lock_file_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());

        let lock = window_dir(tmp.path()).join(LOCK_FILE_NAME);
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();

        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        assert_eq!(
            st.save(&snap, NOW).unwrap_err(),
            WindowError::CacheUnavailable
        );
    }

    #[test]
    fn applied_flag_must_match_the_scores() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());

        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits[0].rerank_score = None;
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        let mut snap = snapshot(&db, NOW, false, 3, 5, 5);
        snap.result.hits[0].rerank_score = Some(0.1);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.rerank.identity.actual_provider = Some(ProviderChoice::BgeLocal);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);

        // The applied flag says every hit was scored, but the stored count no
        // longer matches the number of hits.
        let mut snap = snapshot(&db, NOW, true, 3, 5, 5);
        snap.result.hits.push(hit(9, 1.0));
        snap.result.hits.last_mut().unwrap().rerank_score = Some(0.9);
        snap.rerank.scored_count = 3;
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);
    }

    #[test]
    fn hits_beyond_the_window_bound_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 6, 5, 5);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);
    }

    #[test]
    fn the_policy_bounds_are_validated() {
        let tmp = tempfile::tempdir().unwrap();
        let base = WindowPolicy::default();

        for policy in [
            WindowPolicy { ttl_ms: 0, ..base },
            WindowPolicy {
                max_windows: 0,
                ..base
            },
            WindowPolicy {
                max_total_bytes: 0,
                ..base
            },
            WindowPolicy {
                max_window_bytes: 0,
                ..base
            },
            WindowPolicy {
                max_window_bytes: base.max_total_bytes + 1,
                ..base
            },
        ] {
            assert_eq!(
                WindowStore::new(tmp.path(), policy).unwrap_err(),
                WindowError::InvalidInput
            );
        }
    }

    #[test]
    fn malformed_cursors_are_rejected() {
        use base64::Engine as _;

        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, _) = save_and_cursor(&st, &snap, 0);

        let cases = vec![
            // offset at the window length is out of range
            raw_cursor(json!({"version": 2, "window_id": id.clone(), "offset": 12})),
            // old cursor version
            raw_cursor(json!({"version": 1, "window_id": id.clone(), "offset": 0})),
            // negative offset
            raw_cursor(json!({"version": 2, "window_id": id.clone(), "offset": -1})),
            // fractional offset
            raw_cursor(json!({"version": 2, "window_id": id.clone(), "offset": 1.5})),
            // extra field
            raw_cursor(json!({"version": 2, "window_id": id.clone(), "offset": 0, "extra": 1})),
            // path traversal in the id
            raw_cursor(json!({"version": 2, "window_id": "../escape", "offset": 0})),
            // uppercase hex is not the frozen spelling
            raw_cursor(json!({"version": 2, "window_id": id.to_uppercase(), "offset": 0})),
            // not base64 at all
            "not-base64!!".to_string(),
            // base64 that decodes to a non-JSON body
            base64::prelude::BASE64_STANDARD.encode(b"not json"),
            // base64 of trailing garbage after a valid object
            base64::prelude::BASE64_STANDARD
                .encode(format!(r#"{{"version":2,"window_id":"{id}","offset":0}}}}"#).as_bytes()),
        ];

        for cursor in cases {
            let result = st.load(&cursor, &snap.request_binding, &db, NOW);
            assert!(
                matches!(
                    result,
                    Err(WindowError::InvalidCursor) | Err(WindowError::NotFound)
                ),
                "cursor {cursor:?} must be refused, got {result:?}"
            );
        }
    }

    #[test]
    fn expired_window_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, snap.expires_at_ms)
                .unwrap_err(),
            WindowError::Expired
        );
        assert!(
            st.load(&cursor, &snap.request_binding, &db, snap.expires_at_ms - 1)
                .is_ok()
        );
    }

    #[test]
    fn missing_window_is_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let cursor = encode_cursor(&"a".repeat(64), 0).unwrap();
        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::NotFound
        );
    }

    #[test]
    fn index_change_invalidates_a_window() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);
        assert!(st.load(&cursor, &snap.request_binding, &db, NOW).is_ok());

        {
            let conn = Conn::open_writable(&db, Profile::Production).unwrap();
            conn.execute(
                "INSERT INTO meta(key, value) VALUES ('p04_index_probe', '1')",
                &[],
            )
            .unwrap();
        }

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::IndexChanged
        );
    }

    #[test]
    fn oversized_single_window_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let policy = WindowPolicy {
            max_window_bytes: 256,
            max_total_bytes: 1024,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        assert_eq!(st.save(&snap, NOW).unwrap_err(), WindowError::InvalidInput);
    }

    #[test]
    fn prune_enforces_the_window_count_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let ttl = WindowPolicy::default().ttl_ms as i64;
        let policy = WindowPolicy {
            max_windows: 2,
            max_window_bytes: 4_000_000,
            max_total_bytes: 8_000_000,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();

        let mut ids = Vec::new();
        for step in 0..3i64 {
            let created = NOW + step;
            let mut snap = snapshot(&db, created, true, 3, 5, 5);
            snap.created_at_ms = created;
            snap.expires_at_ms = created + ttl;
            ids.push(st.save(&snap, created).unwrap());
        }

        let files: Vec<String> = fs::read_dir(window_dir(tmp.path()))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".json"))
            .collect();
        assert_eq!(files.len(), 2, "only max_windows files may remain");
        assert!(
            !files.contains(&format!("{}.json", ids[0])),
            "oldest must go"
        );
        assert!(
            files.contains(&format!("{}.json", ids[2])),
            "newest must stay"
        );
    }

    #[test]
    fn prune_enforces_the_total_byte_bound() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let first = snapshot(&db, NOW, true, 3, 5, 5);
        let first_id = st.save(&first, NOW).unwrap();
        let size = fs::metadata(window_dir(tmp.path()).join(format!("{first_id}.json")))
            .unwrap()
            .len();

        let policy = WindowPolicy {
            max_windows: 16,
            max_window_bytes: size,
            max_total_bytes: size * 2,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();

        let mut ids = vec![first_id];
        for step in 1..3i64 {
            let created = NOW + step;
            let mut snap = snapshot(&db, created, true, 3, 5, 5);
            snap.created_at_ms = created;
            snap.expires_at_ms = created + policy.ttl_ms as i64;
            ids.push(st.save(&snap, created).unwrap());
        }

        let names: Vec<String> = fs::read_dir(window_dir(tmp.path()))
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().into_string().ok())
            .filter(|name| name.ends_with(".json"))
            .collect();
        assert!(names.len() <= 2, "total bytes must stay within the bound");
        assert!(names.contains(&format!("{}.json", ids[2])));
    }

    #[test]
    fn reclaim_leaves_neighbour_files_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let policy = WindowPolicy {
            max_windows: 1,
            max_window_bytes: 4_000_000,
            max_total_bytes: 8_000_000,
            ..WindowPolicy::default()
        };
        let st = WindowStore::new(tmp.path(), policy).unwrap();

        let dir = window_dir(tmp.path());
        let stray = dir.join("notes.txt");
        fs::write(&stray, b"keep me").unwrap();
        let subdir = dir.join("subdir");
        fs::create_dir(&subdir).unwrap();

        for step in 0..3i64 {
            let created = NOW + step;
            let mut snap = snapshot(&db, created, true, 3, 5, 5);
            snap.created_at_ms = created;
            snap.expires_at_ms = created + policy.ttl_ms as i64;
            st.save(&snap, created).unwrap();
        }

        assert_eq!(fs::read(&stray).unwrap(), b"keep me");
        assert!(subdir.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_private_directory_permissions_are_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let dir = window_dir(tmp.path());
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            WindowStore::new(tmp.path(), WindowPolicy::default()).unwrap_err(),
            WindowError::CacheUnavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_window_directory_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("elsewhere");
        fs::create_dir_all(&target).unwrap();
        let cache = tmp.path().join("cache");
        fs::create_dir_all(&cache).unwrap();
        std::os::unix::fs::symlink(&target, cache.join("rerank-windows")).unwrap();

        assert_eq!(
            WindowStore::new(tmp.path(), WindowPolicy::default()).unwrap_err(),
            WindowError::CacheUnavailable
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_window_file_is_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (id, cursor) = save_and_cursor(&st, &snap, 0);

        // Replace the published file with a symlink to a copy of the same
        // bytes: identity is the inode's content, not whatever a link names.
        let path = window_dir(tmp.path()).join(format!("{id}.json"));
        let copy = tmp.path().join("copy.json");
        fs::rename(&path, &copy).unwrap();
        std::os::unix::fs::symlink(&copy, &path).unwrap();

        assert_eq!(
            st.load(&cursor, &snap.request_binding, &db, NOW)
                .unwrap_err(),
            WindowError::Corrupt
        );
    }

    // ------------------------------------------------------------------
    // C2 - two real processes
    // ------------------------------------------------------------------

    #[test]
    #[ignore]
    fn p04_child_entrypoint() {
        let action = std::env::var("CASS_P04_ACTION").expect("CASS_P04_ACTION");
        let data_dir =
            PathBuf::from(std::env::var("CASS_P04_DATA_DIR").expect("CASS_P04_DATA_DIR"));
        let db_path = PathBuf::from(std::env::var("CASS_P04_DB").expect("CASS_P04_DB"));
        let result_path = PathBuf::from(std::env::var("CASS_P04_RESULT").expect("CASS_P04_RESULT"));
        let st = WindowStore::new(&data_dir, WindowPolicy::default()).expect("open store");

        match action.as_str() {
            "save" => {
                let snap = snapshot(&db_path, NOW, true, 12, 12, 5);
                let id = st.save(&snap, NOW).expect("save");
                let cursor = next_cursor(&id, &snap, 0, 5)
                    .expect("cursor")
                    .expect("a window with 12 hits must have a continuation");
                fs::write(&result_path, format!("{id}\n{cursor}\n")).expect("write child result");
            }
            "load" => {
                let cursor = std::env::var("CASS_P04_CURSOR").expect("CASS_P04_CURSOR");
                let expected = binding(12, 5);
                let (snap, offset) = st.load(&cursor, &expected, &db_path, NOW).expect("load");
                let titles = titles(&page_hits(&snap, offset).expect("page"));
                fs::write(&result_path, format!("{offset}\n{}\n", titles.join(",")))
                    .expect("write child result");
            }
            other => panic!("unknown child action {other}"),
        }
    }

    fn run_child(data_dir: &Path, db: &Path, action: &str, result: &Path, cursor: Option<&str>) {
        let exe = std::env::current_exe().expect("test binary path");
        let mut cmd = std::process::Command::new(exe);
        cmd.args(["--ignored", "--exact", CHILD_TEST_NAME])
            .env("CASS_P04_ACTION", action)
            .env("CASS_P04_DATA_DIR", data_dir)
            .env("CASS_P04_DB", db)
            .env("CASS_P04_RESULT", result);
        if let Some(cursor) = cursor {
            cmd.env("CASS_P04_CURSOR", cursor);
        }
        let output = cmd.output().expect("spawn child test process");
        assert!(
            output.status.success(),
            "child {action} failed: status={:?}\nstdout={}\nstderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn cross_process_child_saves_parent_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let result = tmp.path().join("child-save.txt");
        run_child(tmp.path(), &db, "save", &result, None);

        let text = fs::read_to_string(&result).unwrap();
        let mut lines = text.lines();
        let id = lines.next().unwrap().to_string();
        let cursor = lines.next().unwrap().to_string();
        assert!(is_window_id(&id));

        let st = store(tmp.path());
        let (snap, offset) = st.load(&cursor, &binding(12, 5), &db, NOW).unwrap();
        assert_eq!(offset, 5);
        assert_eq!(snap.result.hits.len(), 12);
        assert_eq!(titles(&page_hits(&snap, offset).unwrap())[0], "hit-05");
    }

    #[test]
    fn cross_process_parent_saves_child_loads() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let st = store(tmp.path());
        let snap = snapshot(&db, NOW, true, 12, 12, 5);
        let (_, cursor) = save_and_cursor(&st, &snap, 0);

        let result = tmp.path().join("child-load.txt");
        run_child(tmp.path(), &db, "load", &result, Some(&cursor));

        let text = fs::read_to_string(&result).unwrap();
        let mut lines = text.lines();
        assert_eq!(lines.next().unwrap(), "0");
        assert_eq!(lines.next().unwrap(), "hit-00,hit-01,hit-02,hit-03,hit-04");
    }

    // ------------------------------------------------------------------
    // C3 - real WAL, replacement and generation change
    // ------------------------------------------------------------------

    #[test]
    fn real_wal_write_invalidates_the_stamp() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());

        // A live writer keeps the committed frames un-checkpointed.
        let conn = Conn::open_writable(&db, Profile::Production).unwrap();
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('p04_wal_probe_a', '1')",
            &[],
        )
        .unwrap();

        let before = capture_index_stamp(&db).unwrap();
        assert!(
            before.wal.is_some(),
            "a committed write must leave a non-empty WAL"
        );

        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('p04_wal_probe_b', '2')",
            &[],
        )
        .unwrap();
        let after = capture_index_stamp(&db).unwrap();

        assert_ne!(before, after);
        assert_ne!(
            before.wal.as_ref().map(|wal| wal.file.len),
            after.wal.as_ref().map(|wal| wal.file.len),
            "the WAL file must actually grow across the write"
        );
        drop(conn);
    }

    #[test]
    fn empty_wal_creation_and_shm_do_not_invalidate() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let wal = wal_path_for(&db);
        let shm = {
            let mut raw = db.as_os_str().to_os_string();
            raw.push("-shm");
            PathBuf::from(raw)
        };
        let _ = fs::remove_file(&wal);
        let _ = fs::remove_file(&shm);

        let before = capture_index_stamp(&db).unwrap();
        assert_eq!(before.wal, None, "an absent WAL is the absent state");

        // A read-only open may create a zero-length WAL; it must stay absent.
        let after = capture_index_stamp(&db).unwrap();
        assert_eq!(before, after);
        if let Ok(meta) = fs::metadata(&wal) {
            assert_eq!(meta.len(), 0, "a created WAL must be zero-length here");
        }

        // The SHM file is never part of the identity.
        fs::write(&shm, b"shm bytes that must not matter").unwrap();
        let with_shm = capture_index_stamp(&db).unwrap();
        assert_eq!(before, with_shm);
        let _ = fs::remove_file(&shm);
    }

    #[test]
    fn same_path_replacement_invalidates_the_stamp() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let before = capture_index_stamp(&db).unwrap();

        fs::remove_file(&db).unwrap();
        let _ = fs::remove_file(wal_path_for(&db));
        make_db_at(&db, false);

        let after = capture_index_stamp(&db).unwrap();
        assert_ne!(before, after);
        assert_ne!(
            before.db_file.inode, after.db_file.inode,
            "a replaced file must be a new inode"
        );
    }

    #[test]
    fn vector_revision_and_generation_change_invalidate_the_stamp() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db_with_generation(tmp.path());

        let before = capture_index_stamp(&db).unwrap();
        assert_eq!(before.vector.as_ref().map(|v| v.revision), Some(0));

        {
            let conn = Conn::open_writable(&db, Profile::Production).unwrap();
            conn.execute(
                "UPDATE embedding_generations SET vector_revision = vector_revision + 1 \
                 WHERE is_active = 1",
                &[],
            )
            .unwrap();
        }
        let after_revision = capture_index_stamp(&db).unwrap();
        assert_eq!(after_revision.vector.as_ref().map(|v| v.revision), Some(1));
        assert_ne!(before.vector, after_revision.vector);

        {
            let conn = Conn::open_writable(&db, Profile::Production).unwrap();
            conn.execute(
                "UPDATE embedding_generations SET is_active = 0 WHERE is_active = 1",
                &[],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO embedding_generations \
                 (embedder_id, dim, canonicalize_version, chunking_policy_version, fingerprint, \
                  byte_order, audit_status, is_active, created_at, activated_at, vector_revision) \
                 VALUES ('other-embedder', 8, 1, 1, X'AA', 'le', 'passed', 1, 2, 2, 0)",
                &[],
            )
            .unwrap();
        }
        let after_generation = capture_index_stamp(&db).unwrap();
        assert_ne!(
            after_revision.vector.as_ref().map(|v| v.generation_id),
            after_generation.vector.as_ref().map(|v| v.generation_id),
            "a new active generation must be a new vector identity"
        );
    }

    #[test]
    fn absent_vector_generation_is_stamped_as_none() {
        let tmp = tempfile::tempdir().unwrap();
        let db = make_db(tmp.path());
        let stamp = capture_index_stamp(&db).unwrap();
        assert_eq!(stamp.vector, None);
        assert_eq!(
            stamp.schema_version,
            crate::storage::schema::CURRENT_SCHEMA_VERSION
        );
        assert!(stamp.db_path.ends_with("agent_search.db"));
    }

    #[test]
    fn endpoint_normalisation_uses_the_origin_only() {
        assert_eq!(
            normalize_endpoint("http://127.0.0.1:8000/v1/rerank?x=1").unwrap(),
            "http://127.0.0.1:8000"
        );
        assert_eq!(
            normalize_endpoint("https://API.OpenRouter.ai/api/v1?k=1#f").unwrap(),
            "https://api.openrouter.ai"
        );
        assert_eq!(
            normalize_endpoint("https://example.com:443/path").unwrap(),
            "https://example.com"
        );
        assert!(normalize_endpoint("ftp://example.com").is_err());
        assert!(normalize_endpoint("http://user:pass@example.com").is_err());
        assert!(normalize_endpoint("not a url").is_err());
    }
}
