//! PR9 task 09a: the real-CLI contract of `cass search --vector-search-mode`.
//!
//! Every assertion here drives the real `cass` binary against a real
//! file-backed schema-8 database. Nothing in this file parses the argument
//! struct in isolation or stubs the search path: the seam the ticket asks for
//! is "real CLI subprocess, real file library, real output formats".
//!
//! The semantic leg needs a query embedding. It is served by a loopback stub
//! reached through `CASS_INFINITY_URL`, so the end-to-end path runs with no
//! external service and no test-only product switch. The stub and the fixture
//! derive their vectors from the same deterministic function of the text, so
//! the query vector the CLI computes is byte-identical to the one baked into
//! the fixture.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use coding_agent_search::storage::api::{TxMode, Value};
use coding_agent_search::storage::schema::{self, ChunkRow};
use coding_agent_search::storage::sqlite::FrankenStorage;
use coding_agent_search::storage::vector_domain;
use once_cell::sync::Lazy;

/// `src/search/infinity.rs::DIMENSION` — the served dimension the embedder
/// contract fixes; not configurable, so the fixture must match it.
const EMBED_DIM: usize = 1024;
/// The model id the stub serves and the CLI is asked for (`--model bge-m3`).
const EMBED_MODEL: &str = "BAAI/bge-m3";
const QUERY: &str = "pr9 cli candidate ranking fixture";

/// `--rrf-limit 1` makes the CLI ask for `(1 + 1) * OVERFETCH_FACTOR(4) = 8`
/// candidates, so each int8 shard is asked for `8 * 4 = 32` rows: an 8-shard
/// pool of 256 out of 804 stored chunks.
const PER_SHARD_K: usize = 32;

// ---------------------------------------------------------------------------
// Deterministic embedding stub
// ---------------------------------------------------------------------------

fn fnv1a(text: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A fixed pseudo-random vector per input text.
///
/// The distribution carries no meaning — the vector leg only has to place
/// stored vectors and the query vector in the same space deterministically.
/// What matters is that this function is the single source of both, so the
/// fixture can predict the CLI's query vector exactly.
fn embed(text: &str) -> Vec<f32> {
    let mut state = 0x243f_6a88_85a3_08d3_u64 ^ fnv1a(text);
    (0..EMBED_DIM)
        .map(|_| {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            ((z >> 40) as f32 / (1u64 << 24) as f32) - 0.5
        })
        .collect()
}

fn l2_norm(vector: &[f32]) -> f32 {
    vector.iter().map(|v| v * v).sum::<f32>().sqrt()
}

struct StubInfinity {
    base_url: String,
    wake_addr: String,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for StubInfinity {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(&self.wake_addr) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl StubInfinity {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind infinity stub");
        listener
            .set_nonblocking(true)
            .expect("set infinity stub nonblocking");
        let addr = listener.local_addr().expect("stub address");
        let wake_addr = addr.to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => stub_handle_request(stream),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            base_url: format!("http://{wake_addr}"),
            wake_addr,
            stop,
            handle: Some(handle),
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 4096];
    let header_end = loop {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 65536 {
            return None;
        }
    };
    let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = header_str.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let content_length: usize = lines
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .unwrap_or(0);
    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    let body = buf[header_end..buf.len().min(header_end + content_length)].to_vec();
    Some((method, path, body))
}

fn stub_handle_request(mut stream: TcpStream) {
    let Some((method, path, body)) = read_http_request(&mut stream) else {
        return;
    };
    let response = if method == "POST" && path == "/embeddings" {
        let requested = serde_json::from_slice::<serde_json::Value>(&body).ok();
        let model = requested
            .as_ref()
            .and_then(|v| v.get("model"))
            .and_then(|m| m.as_str())
            .unwrap_or_default();
        if model != EMBED_MODEL {
            let msg = format!("stub infinity: unexpected model {model:?}");
            format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                msg.len(),
                msg
            )
        } else {
            let inputs: Vec<String> = requested
                .as_ref()
                .and_then(|v| v.get("input"))
                .and_then(|i| i.as_array())
                .map(|items| {
                    items
                        .iter()
                        .map(|item| item.as_str().unwrap_or_default().to_string())
                        .collect()
                })
                .unwrap_or_default();
            // `http_embed` requires `data[].index` to be a permutation of
            // 0..N-1; the vectors are `embed()` of the input text, which is
            // the same function the fixture used to build its rows.
            let data: Vec<serde_json::Value> = inputs
                .iter()
                .enumerate()
                .map(
                    |(index, text)| serde_json::json!({ "embedding": embed(text), "index": index }),
                )
                .collect();
            let payload = serde_json::json!({ "data": data }).to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                payload.len(),
                payload
            )
        }
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    };
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

static STUB: Lazy<StubInfinity> = Lazy::new(StubInfinity::start);

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

struct Fixture {
    _dir: tempfile::TempDir,
    data_dir: PathBuf,
    /// Authoritative chunk rows stored in the active generation.
    rows: usize,
    /// The message whose authoritative float vector IS the query vector, but
    /// which the eight-shard int8 screen cannot see (see `build_fixture`).
    /// `-1` on the empty fixture, which has no target.
    target_message_id: i64,
}

impl Fixture {
    fn data_dir(&self) -> &str {
        self.data_dir.to_str().expect("utf-8 fixture path")
    }
}

/// Which searchable state the fixture's active generation is left in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureState {
    /// Active and certified: the ordinary searchable shape.
    Active,
    /// A generation exists but none is active — what a running backfill
    /// looks like, and what `probe_db_vector_domain_availability` reports as
    /// `IndexBuilding`.
    Building,
    /// Active and certified, but one int8 shard has been dropped: a
    /// structurally broken mirror that must fail loudly rather than quietly
    /// degrading to the exact path.
    MissingInt8Shard,
}

/// The delta that moves a stored vector off the query *within its int8 cell*.
///
/// `vec_quantize_int8(..., 'unit')` scales by the largest magnitude component
/// and rounds to int8, so a small perturbation of the smallest-magnitude
/// component usually leaves the quantized code untouched. The fixture needs
/// exactly that: every stored chunk must share the query's int8 code, so the
/// eight-shard screen sees a 256-row pool of equally-(zero-)distance rows and
/// can be made to miss one of them.
fn distractor_with_same_int8_code(storage: &FrankenStorage, query: &[f32]) -> Vec<f32> {
    let conn = storage.raw();
    let query_code = vector_domain::quantize_unit_int8(conn, query).expect("quantize query");
    let dimension = query
        .iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| a.abs().partial_cmp(&b.abs()).expect("finite"))
        .map(|(index, _)| index)
        .expect("non-empty vector");
    let mut best: Option<Vec<f32>> = None;
    for delta in [3e-2_f32, 1e-2, 3e-3, 1e-3, 3e-4, 1e-4] {
        let mut candidate = query.to_vec();
        candidate[dimension] += delta;
        if vector_domain::quantize_unit_int8(conn, &candidate).expect("quantize candidate")
            == query_code
        {
            best = Some(candidate);
            break;
        }
    }
    let candidate = best.expect("a same-cell perturbation must exist for a unit-int8 cell");
    assert_ne!(
        candidate, query,
        "the distractor must differ from the query in float space"
    );
    candidate
}

fn build_fixture(rows: usize, state: FixtureState) -> Fixture {
    let dir = tempfile::tempdir().expect("fixture tempdir");
    let data_dir = dir.path().join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let db_path = data_dir.join("agent_search.db");

    let query = embed(QUERY);
    let query_norm = l2_norm(&query);

    let mut pairs: Vec<(i64, i64)> = Vec::with_capacity(rows);
    let mut target_message_id = -1;
    {
        let storage = FrankenStorage::open(&db_path).expect("open schema-8 fixture db");
        let distractor = distractor_with_same_int8_code(&storage, &query);
        let distractor_norm = l2_norm(&distractor);
        let conn = storage.raw();

        conn.execute_batch(
            "INSERT INTO agents(id,slug,name,kind,created_at,updated_at) \
             VALUES(1,'codex','codex','cli',0,0);",
        )
        .expect("insert agent");

        let generation = conn
            .with_tx_no_replay(TxMode::Immediate, |tx| {
                schema::create_embedding_generation(tx, "bge-m3", 1024, 1, 1, b"fixture", 1)
            })
            .expect("create generation");
        vector_domain::create_vec0_table_for_generation(conn, generation, 1024)
            .expect("create vec0 tables");

        for start in (0..rows).step_by(256) {
            let end = (start + 256).min(rows);
            let batch: Vec<(i64, Vec<u8>)> = conn
                .with_tx_no_replay(TxMode::Immediate, |tx| {
                    let mut batch = Vec::with_capacity(end - start);
                    for index in start..end {
                        let message_id = 1000 + index as i64;
                        let content = format!("PR9 vector candidate synthetic message {index}");
                        let title = format!("PR9 09a {index}");
                        let source_path = format!("/fixture/pr9-09a-{index}.jsonl");
                        tx.execute(
                            "INSERT INTO conversations(id,agent_id,source_id,title,source_path) \
                             VALUES(?1,1,'local',?2,?3)",
                            &[
                                Value::from(message_id),
                                Value::from(title.clone()),
                                Value::from(source_path.clone()),
                            ],
                        )?;
                        tx.execute(
                            "INSERT INTO messages(id,conversation_id,idx,role,created_at,content) \
                             VALUES(?1,?1,0,'user',1,?2)",
                            &[Value::from(message_id), Value::from(content.clone())],
                        )?;
                        tx.execute(
                            "INSERT INTO lex_docs(doc_id,content,title,agent,workspace,source_path) \
                             VALUES(?1,?2,?3,'codex','',?4)",
                            &[
                                Value::from(message_id),
                                Value::from(content.clone()),
                                Value::from(title.clone()),
                                Value::from(source_path.clone()),
                            ],
                        )?;
                        let chunk_id = schema::insert_chunk_row_in_tx(
                            tx,
                            &ChunkRow {
                                generation_id: generation,
                                message_id,
                                conversation_id: message_id,
                                chunk_idx: 0,
                                byte_start: 0,
                                byte_end: content.len(),
                                content_hash: format!("pr9-09a-{index}"),
                                embedding: distractor.clone(),
                                norm: distractor_norm,
                                created_at_ms: 1,
                            },
                        )?;
                        batch.push((chunk_id, schema::f32_vector_to_le_blob(&distractor)));
                        pairs.push((chunk_id, message_id));
                    }
                    Ok(batch)
                })
                .expect("insert batch");

            let refs: Vec<(i64, &[u8])> = batch
                .iter()
                .map(|(id, blob)| (*id, blob.as_slice()))
                .collect();
            conn.with_tx_no_replay(TxMode::Immediate, |tx| {
                vector_domain::insert_vec0_rows_in_tx(tx, generation, &refs)
            })
            .expect("insert vec0 rows");
        }

        // The lexical side has to be genuinely searchable: the marker is what
        // `lex_domain_rebuild_marker_state_for_search` reads, and a `Completed`
        // marker with zero docs is the "genuinely empty archive" case.
        conn.execute_batch("INSERT INTO fts_lex(fts_lex) VALUES('rebuild');")
            .expect("rebuild fts_lex");
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) \
             VALUES('lex_domain_rebuild_state', ?1)",
            &[Value::from(format!("completed:{rows}:{rows}"))],
        )
        .expect("set lex domain marker");
        if state != FixtureState::Building {
            conn.execute(
                "UPDATE embedding_generations SET is_active=1, audit_status='passed' WHERE id=?1",
                &[Value::from(generation)],
            )
            .expect("activate generation");
        }
        if state == FixtureState::MissingInt8Shard {
            let shard = vector_domain::int8_table_name(generation, 3).expect("shard name");
            conn.execute_batch(&format!("DROP TABLE {shard}"))
                .expect("drop one int8 shard");
        }

        // Recompute the real eight-shard pool the fast path will collect, and
        // hand the float-top slot to a chunk the screen cannot reach. This is
        // the fixture's whole point: `exact` must return that chunk and `fast`
        // must not, which only happens if `fast` really runs the screen.
        //
        // Only the two full-width corpora need it; a corpus the pool covers
        // entirely has nothing outside it, and the deliberately broken states
        // cannot run the pool query at all.
        if rows > 8 * PER_SHARD_K {
            let query_code =
                vector_domain::quantize_unit_int8(conn, &query).expect("quantize query");
            let mut selected: HashSet<i64> = HashSet::new();
            for shard in 0..8 {
                let table = vector_domain::int8_table_name(generation, shard).expect("shard name");
                let hits: Vec<(i64, f64)> = conn
                    .with_tx_no_replay(TxMode::Deferred, |tx| {
                        tx.query_all_map(
                            &format!(
                                "SELECT rowid,distance FROM {table} \
                             WHERE embedding MATCH vec_int8(?1) AND k=?2 ORDER BY distance"
                            ),
                            &[
                                Value::from(query_code.clone()),
                                Value::from(PER_SHARD_K as i64),
                            ],
                            |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
                        )
                    })
                    .expect("collect int8 shard pool");
                assert_eq!(hits.len(), PER_SHARD_K, "shard {shard} must fill its K");
                selected.extend(hits.into_iter().map(|(chunk_id, _)| chunk_id));
            }
            assert_eq!(
                selected.len(),
                8 * PER_SHARD_K,
                "the coarse pool must be 256 distinct chunks out of {rows}"
            );
            let (target_chunk, target_message) = pairs
                .iter()
                .rev()
                .find(|(chunk_id, _)| !selected.contains(chunk_id))
                .copied()
                .expect("at least one stored chunk falls outside the coarse pool");
            target_message_id = target_message;

            conn.with_tx_no_replay(TxMode::Immediate, |tx| {
                tx.execute(
                    "UPDATE message_chunks SET embedding=?1, norm=?2 WHERE chunk_id=?3",
                    &[
                        Value::from(schema::f32_vector_to_le_blob(&query)),
                        Value::from(f64::from(query_norm)),
                        Value::from(target_chunk),
                    ],
                )?;
                tx.execute(
                    &format!("DELETE FROM vec_index_gen_{generation} WHERE rowid=?1"),
                    &[Value::from(target_chunk)],
                )?;
                tx.execute(
                    &format!(
                        "INSERT INTO vec_index_gen_{generation}(rowid,embedding) VALUES(?1,?2)"
                    ),
                    &[
                        Value::from(target_chunk),
                        Value::from(schema::f32_vector_to_le_blob(&query)),
                    ],
                )?;
                Ok(())
            })
            .expect("promote the target chunk to the float top");

            let float_top: (i64, f64) = conn
                .query_row_map(
                    &format!(
                        "SELECT rowid,distance FROM vec_index_gen_{generation} \
                     WHERE embedding MATCH vec_f32(?1) AND k=1 ORDER BY distance"
                    ),
                    &[Value::from(schema::f32_vector_to_le_blob(&query))],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
                )
                .expect("float KNN for the target");
            assert_eq!(
                float_top.0, target_chunk,
                "the target must be the float top-1"
            );

            vector_domain::audit_int8_mirror_identity(conn, generation, 1024)
                .expect("the nine mirrors must remain identity-consistent");
        }
    }

    Fixture {
        _dir: dir,
        data_dir,
        rows,
        target_message_id,
    }
}

/// 804 chunks over eight shards, 256 of them inside the `--rrf-limit 1` coarse pool.
static SMALL: Lazy<Fixture> = Lazy::new(|| build_fixture(804, FixtureState::Active));

/// The large-window fixture is its own corpus: `--rrf-limit 1025` asks for
/// `(1025 + 1) * 4 = 4104` candidates, which is above both the vec0 `k` ceiling
/// and this generation's row count, so the direct-exact window applies.
static LARGE: Lazy<Fixture> = Lazy::new(|| build_fixture(4204, FixtureState::Active));

/// An active generation that holds nothing — the "empty active generation"
/// boundary, which must stay a normal empty result and not an error.
static EMPTY: Lazy<Fixture> = Lazy::new(|| build_fixture(0, FixtureState::Active));

/// One generation, none active: the state a backfill reports while it runs.
static BUILDING: Lazy<Fixture> = Lazy::new(|| build_fixture(256, FixtureState::Building));

/// Active and certified, but shard 3 of the int8 mirror is gone.
static SHARDLESS: Lazy<Fixture> = Lazy::new(|| build_fixture(256, FixtureState::MissingInt8Shard));

// ---------------------------------------------------------------------------
// CLI helpers
// ---------------------------------------------------------------------------

fn cass(args: &[&str], data_dir: &str) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cass"));
    command
        .args(args)
        .arg("--data-dir")
        .arg(data_dir)
        // Keep the subprocess away from whatever the developer's shell or the
        // repository `.env` happens to set, and point the embedder at the stub.
        .env("CASS_INFINITY_URL", STUB.base_url.as_str())
        .env_remove("CASS_SEARCH_MODE")
        .env_remove("CASS_SEMANTIC_EMBEDDER")
        .env_remove("CASS_SEARCH_LIMIT")
        .env_remove("CASS_OUTPUT_FORMAT")
        .env_remove("TOON_DEFAULT_FORMAT")
        .current_dir(data_dir);
    command.output().expect("run the cass binary")
}

/// The CLI keeps stdout data-only, so both the clap `argument_parsing`
/// envelope and the `usage` envelope land on stderr.
fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn stdout_json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "stdout is not JSON ({err}); stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn semantic_search(fixture: &Fixture, limit: usize, extra: &[&str]) -> Output {
    let mut args = vec![
        "search", QUERY, "--mode", "semantic", "--model", "bge-m3", "--rrf-limit",
    ];
    let limit = limit.to_string();
    args.push(&limit);
    args.push("--json");
    args.extend_from_slice(extra);
    cass(&args, fixture.data_dir())
}

fn first_message(result: &serde_json::Value) -> i64 {
    result["hits"][0]["message_id"]
        .as_i64()
        .unwrap_or_else(|| panic!("no first hit in {result}"))
}

// ---------------------------------------------------------------------------
// AC1 — parameter surface and rejection
// ---------------------------------------------------------------------------

#[test]
fn help_advertises_exactly_the_two_vector_search_modes() {
    let output = cass(&["search", "--help"], "/tmp");
    assert!(output.status.success(), "search --help must exit 0");
    let help = String::from_utf8_lossy(&output.stdout);

    assert!(
        help.contains("--vector-search-mode"),
        "the public help must list the new flag"
    );
    assert!(
        help.contains("[possible values: exact, fast]"),
        "the flag must accept exactly exact|fast"
    );
}

#[test]
fn an_unknown_vector_search_mode_value_is_a_usage_error() {
    let output = cass(
        &["search", "x", "--robot", "--vector-search-mode", "turbo"],
        "/tmp",
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "invalid enum values are usage (rc2)"
    );
    let text = stderr_text(&output);
    assert!(
        text.contains("turbo") && text.contains("exact") && text.contains("fast"),
        "the rejection must name the value and the accepted set: {text}"
    );
}

#[test]
fn lexical_search_rejects_an_explicit_vector_search_mode() {
    for mode in ["exact", "fast"] {
        let output = cass(
            &[
                "search",
                "x",
                "--robot",
                "--mode",
                "lexical",
                "--vector-search-mode",
                mode,
            ],
            "/tmp",
        );
        assert_eq!(
            output.status.code(),
            Some(2),
            "--mode lexical --vector-search-mode {mode} must be a usage error"
        );
        let text = stderr_text(&output);
        assert!(
            text.contains("lexical") && text.contains("vector-search-mode"),
            "the usage error must explain the lexical conflict: {text}"
        );
    }
}

#[test]
fn lexical_search_without_the_flag_is_untouched() {
    let output = cass(
        &[
            "search",
            "synthetic",
            "--mode",
            "lexical",
            "--rrf-limit",
            "3",
            "--json",
        ],
        SMALL.data_dir(),
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "omitting --vector-search-mode must leave lexical search working: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = stdout_json(&output);
    assert!(
        result.get("search_precision").is_none(),
        "a lexical-only result must not claim a vector precision: {result}"
    );
}

// ---------------------------------------------------------------------------
// AC2 — the two modes over one library
// ---------------------------------------------------------------------------

#[test]
fn default_and_explicit_exact_agree_field_by_field() {
    let default_run = semantic_search(&SMALL, 5, &[]);
    let exact_run = semantic_search(&SMALL, 5, &["--vector-search-mode", "exact"]);
    assert!(
        default_run.status.success(),
        "default semantic search must succeed"
    );
    assert!(exact_run.status.success(), "explicit exact must succeed");

    let default_json = stdout_json(&default_run);
    let exact_json = stdout_json(&exact_run);
    assert_eq!(
        default_json, exact_json,
        "an omitted flag must be exactly what `exact` means, field for field"
    );
    assert_eq!(default_json["search_precision"], serde_json::json!("exact"));
    assert_eq!(
        default_json["candidates"]["approximate"],
        serde_json::json!(false)
    );
    assert!(
        default_json["candidates"]
            .get("requested_coarse_k")
            .is_none(),
        "the exact path must not invent coarse-screen fields"
    );
}

#[test]
fn fast_runs_all_eight_shards_and_rescores_every_collected_candidate() {
    let output = semantic_search(&SMALL, 1, &["--vector-search-mode", "fast"]);
    assert!(output.status.success(), "fast semantic search must succeed");
    let result = stdout_json(&output);

    assert_eq!(result["search_precision"], serde_json::json!("approximate"));
    let candidates = &result["candidates"];
    assert_eq!(candidates["approximate"], serde_json::json!(true));
    assert_eq!(candidates["coarse_shard_count"], serde_json::json!(8));
    assert_eq!(
        candidates["requested_coarse_k"],
        serde_json::json!(PER_SHARD_K)
    );
    assert_eq!(
        candidates["effective_coarse_k"],
        serde_json::json!(PER_SHARD_K)
    );
    assert_eq!(candidates["coarse_cap_hit"], serde_json::json!(false));
    assert!(
        SMALL.rows > 8 * PER_SHARD_K,
        "the fixture corpus must be larger than the pool for this to mean anything"
    );
    assert_eq!(candidates["corpus_limited"], serde_json::json!(false));

    let collected = candidates["coarse_rows_collected"]
        .as_u64()
        .expect("pool size");
    let rescored = candidates["float_rescore_rows"]
        .as_u64()
        .expect("rescore count");
    assert_eq!(
        collected,
        8 * PER_SHARD_K as u64,
        "eight shards each fill K"
    );
    assert_eq!(
        rescored, collected,
        "every collected candidate must be rescored on the authoritative float vectors"
    );
    assert_eq!(
        candidates["first_round_rows"].as_u64(),
        Some(collected),
        "first_round_rows reports the collected pool, not a single-table K"
    );
}

#[test]
fn fast_cannot_reach_a_float_top_chunk_outside_its_coarse_pool() {
    let exact_run = semantic_search(&SMALL, 1, &["--vector-search-mode", "exact"]);
    let fast_run = semantic_search(&SMALL, 1, &["--vector-search-mode", "fast"]);
    assert!(exact_run.status.success() && fast_run.status.success());

    let exact_first = first_message(&stdout_json(&exact_run));
    let fast_json = stdout_json(&fast_run);
    let fast_first = first_message(&fast_json);

    assert_eq!(
        exact_first, SMALL.target_message_id,
        "the fixture's float top-1 must be the promoted chunk"
    );
    assert_ne!(
        fast_first, exact_first,
        "fast must not reach a chunk its eight-shard screen never collected"
    );
    assert!(
        !fast_json["hits"]
            .as_array()
            .expect("hits array")
            .iter()
            .any(|hit| hit["message_id"].as_i64() == Some(exact_first)),
        "the unreachable chunk must be absent from the fast result, not merely outranked"
    );
}

#[test]
fn fast_reports_a_filtering_shortfall_instead_of_hiding_it() {
    // The fixture stores only `user` messages, so a `--role assistant` filter
    // cannot be satisfied from the coarse pool. The ticket's contract is that
    // this falls through to the bounded float path and says so, rather than
    // returning a silent empty set that looks like "no matches".
    let filtered = semantic_search(
        &SMALL,
        3,
        &["--vector-search-mode", "fast", "--role", "assistant"],
    );
    assert!(
        filtered.status.success(),
        "a filtering shortfall is a result, not a failure: {}",
        stderr_text(&filtered)
    );
    let filtered = stdout_json(&filtered);
    assert_eq!(filtered["count"], serde_json::json!(0));
    assert_eq!(
        filtered["candidates"]["mode"],
        serde_json::json!("knn+exact"),
        "the bounded float fallback must be visible in the candidate meta"
    );
    assert_eq!(
        filtered["candidates"]["approximate"],
        serde_json::json!(true)
    );

    // A filter the pool can satisfy stays on the plain coarse path.
    let satisfiable = semantic_search(
        &SMALL,
        3,
        &["--vector-search-mode", "fast", "--agent", "codex"],
    );
    assert!(satisfiable.status.success());
    let satisfiable = stdout_json(&satisfiable);
    assert_eq!(satisfiable["count"], serde_json::json!(3));
    assert_eq!(satisfiable["candidates"]["mode"], serde_json::json!("knn"));
    assert_eq!(
        satisfiable["candidates"]["coarse_shard_count"],
        serde_json::json!(8)
    );
    assert_eq!(
        satisfiable["candidates"]["coarse_rows_collected"],
        satisfiable["candidates"]["float_rescore_rows"]
    );
}

#[test]
fn hybrid_accepts_both_vector_search_modes() {
    for mode in ["exact", "fast"] {
        let output = cass(
            &[
                "search",
                QUERY,
                "--mode",
                "hybrid",
                "--model",
                "bge-m3",
                "--rrf-limit",
                "3",
                "--json",
                "--vector-search-mode",
                mode,
            ],
            SMALL.data_dir(),
        );
        assert_eq!(
            output.status.code(),
            Some(0),
            "hybrid with --vector-search-mode {mode} must run: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result = stdout_json(&output);
        let expected = if mode == "fast" {
            "approximate"
        } else {
            "exact"
        };
        assert_eq!(result["search_precision"], serde_json::json!(expected));
    }
}

// ---------------------------------------------------------------------------
// AC3 — the three output formats and the boundaries
// ---------------------------------------------------------------------------

#[test]
fn all_three_output_formats_report_the_actual_precision() {
    // JSON: the precision is a top-level field.
    let json_run = semantic_search(&SMALL, 1, &["--vector-search-mode", "fast"]);
    assert!(json_run.status.success());
    let json = stdout_json(&json_run);
    assert_eq!(json["search_precision"], serde_json::json!("approximate"));

    // JSONL: it rides in the `_meta` header line.
    let jsonl_run = cass(
        &[
            "search",
            QUERY,
            "--mode",
            "semantic",
            "--model",
            "bge-m3",
            "--rrf-limit",
            "1",
            "--robot-format",
            "jsonl",
            "--vector-search-mode",
            "fast",
        ],
        SMALL.data_dir(),
    );
    assert!(jsonl_run.status.success(), "jsonl fast must succeed");
    let jsonl = String::from_utf8_lossy(&jsonl_run.stdout);
    let header: serde_json::Value =
        serde_json::from_str(jsonl.lines().next().expect("jsonl header"))
            .expect("jsonl header json");
    assert_eq!(
        header["_meta"]["search_precision"],
        serde_json::json!("approximate")
    );
    assert_eq!(
        header["_meta"]["candidates"]["coarse_shard_count"],
        serde_json::json!(8)
    );

    // Text: the renderer prints the precision ahead of the hits.
    let text_run = cass(
        &[
            "search",
            QUERY,
            "--mode",
            "semantic",
            "--model",
            "bge-m3",
            "--rrf-limit",
            "1",
            "--vector-search-mode",
            "fast",
        ],
        SMALL.data_dir(),
    );
    assert!(text_run.status.success(), "text fast must succeed");
    let text = String::from_utf8_lossy(&text_run.stdout);
    assert!(
        text.contains("Search precision: approximate"),
        "the text renderer must show the actual precision: {text}"
    );

    let text_exact = cass(
        &[
            "search",
            QUERY,
            "--mode",
            "semantic",
            "--model",
            "bge-m3",
            "--rrf-limit",
            "1",
            "--vector-search-mode",
            "exact",
        ],
        SMALL.data_dir(),
    );
    let text_exact = String::from_utf8_lossy(&text_exact.stdout).to_string();
    assert!(
        text_exact.contains("Search precision: exact"),
        "explicit exact must render as exact: {text_exact}"
    );
}

#[test]
fn fast_keeps_the_exact_float_path_above_the_large_window_boundary() {
    let fast_run = semantic_search(&LARGE, 1025, &["--vector-search-mode", "fast"]);
    assert!(fast_run.status.success(), "large-window fast must succeed");
    let fast = stdout_json(&fast_run);
    assert_eq!(
        fast["search_precision"],
        serde_json::json!("exact"),
        "above the direct-exact window the actual path is the float one"
    );
    assert_eq!(fast["candidates"]["approximate"], serde_json::json!(false));
    assert_eq!(
        fast["candidates"]["coarse_skip_reason"],
        serde_json::json!("large_window")
    );
    assert_eq!(fast["candidates"]["k"], serde_json::json!(0));
    assert_eq!(fast["candidates"]["first_round_rows"], serde_json::json!(0));

    let default_run = semantic_search(&LARGE, 1025, &[]);
    let default_json = stdout_json(&default_run);
    assert_eq!(
        default_json["hits"], fast["hits"],
        "the requested mode must not change which rows the float path returns"
    );

    // The fallback has to be visible in every real output surface, not only
    // the JSON payload the test can parse most easily.
    let jsonl_run = cass(
        &[
            "search",
            QUERY,
            "--mode",
            "semantic",
            "--model",
            "bge-m3",
            "--rrf-limit",
            "1025",
            "--robot-format",
            "jsonl",
            "--vector-search-mode",
            "fast",
        ],
        LARGE.data_dir(),
    );
    assert!(
        jsonl_run.status.success(),
        "large-window jsonl fast must succeed"
    );
    let jsonl = String::from_utf8_lossy(&jsonl_run.stdout);
    let header: serde_json::Value =
        serde_json::from_str(jsonl.lines().next().expect("jsonl header"))
            .expect("jsonl header json");
    assert_eq!(
        header["_meta"]["search_precision"],
        serde_json::json!("exact")
    );
    assert_eq!(
        header["_meta"]["candidates"]["approximate"],
        serde_json::json!(false)
    );
    assert_eq!(
        header["_meta"]["candidates"]["coarse_skip_reason"],
        serde_json::json!("large_window")
    );

    let text_run = cass(
        &[
            "search",
            QUERY,
            "--mode",
            "semantic",
            "--model",
            "bge-m3",
            "--rrf-limit",
            "1025",
            "--vector-search-mode",
            "fast",
        ],
        LARGE.data_dir(),
    );
    assert!(
        text_run.status.success(),
        "large-window text fast must succeed"
    );
    let text = String::from_utf8_lossy(&text_run.stdout);
    assert!(
        text.contains("Search precision: exact"),
        "the text renderer must report the realized float path, not the requested fast one"
    );
    assert!(
        !text.contains("Search precision: approximate"),
        "the large-window run must not claim the quantized path"
    );
}

#[test]
fn fast_fails_loudly_while_a_generation_is_building_or_a_shard_is_missing() {
    // A generation exists but none is active: the semantic context cannot be
    // built at all, so the CLI must refuse rather than quietly fall back to
    // lexical or to the float path and report hits as if the screen had run.
    let building = semantic_search(&BUILDING, 5, &["--vector-search-mode", "fast"]);
    assert_eq!(
        building.status.code(),
        Some(15),
        "a building generation is a semantic-unavailable refusal, got stdout={} stderr={}",
        String::from_utf8_lossy(&building.stdout),
        stderr_text(&building)
    );
    assert!(
        stderr_text(&building).contains("building index"),
        "the refusal must say the index is still building: {}",
        stderr_text(&building)
    );
    assert!(
        building.stdout.is_empty(),
        "a refused search must not print hits: {}",
        String::from_utf8_lossy(&building.stdout)
    );

    // Active and certified, but the int8 mirror is structurally incomplete.
    // `fast` needs that mirror, so the query has to fail loudly instead of
    // silently serving the exact result under an approximate request.
    let shardless = semantic_search(&SHARDLESS, 5, &["--vector-search-mode", "fast"]);
    assert_eq!(
        shardless.status.code(),
        Some(9),
        "a missing int8 shard must surface as a search failure, got stdout={} stderr={}",
        String::from_utf8_lossy(&shardless.stdout),
        stderr_text(&shardless)
    );
    assert!(
        stderr_text(&shardless).contains("missing int8 mirror"),
        "the failure must name the missing mirror: {}",
        stderr_text(&shardless)
    );
    assert!(
        shardless.stdout.is_empty(),
        "a failed search must not print hits: {}",
        String::from_utf8_lossy(&shardless.stdout)
    );

    // The same library is still searchable on the exact path: the damage is
    // in the int8 mirror the fast screen needs, not in the authoritative rows.
    let exact = semantic_search(&SHARDLESS, 5, &["--vector-search-mode", "exact"]);
    assert_eq!(
        exact.status.code(),
        Some(0),
        "exact must keep working on an incomplete int8 mirror: {}",
        stderr_text(&exact)
    );
    assert!(stdout_json(&exact)["count"].as_u64().unwrap_or(0) > 0);
}

#[test]
fn an_empty_active_generation_is_an_empty_result_not_an_error() {
    let output = semantic_search(&EMPTY, 5, &["--vector-search-mode", "fast"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "an empty archive must not become an error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = stdout_json(&output);
    assert_eq!(result["count"], serde_json::json!(0));
    assert!(result["hits"].as_array().expect("hits").is_empty());
}

#[test]
fn offset_pagination_is_shared_by_both_modes() {
    for mode in ["exact", "fast"] {
        let first = semantic_search(&SMALL, 2, &["--vector-search-mode", mode]);
        let second = semantic_search(&SMALL, 2, &["--vector-search-mode", mode, "--offset", "2"]);
        assert!(first.status.success() && second.status.success());
        let first = stdout_json(&first);
        let second = stdout_json(&second);
        let first_ids: Vec<i64> = first["hits"]
            .as_array()
            .expect("hits")
            .iter()
            .map(|hit| hit["message_id"].as_i64().expect("id"))
            .collect();
        let second_ids: Vec<i64> = second["hits"]
            .as_array()
            .expect("hits")
            .iter()
            .map(|hit| hit["message_id"].as_i64().expect("id"))
            .collect();
        assert_eq!(second["offset"], serde_json::json!(2));
        assert!(
            first_ids.iter().all(|id| !second_ids.contains(id)),
            "{mode}: a page must not repeat the previous page's messages"
        );
    }
}

#[test]
fn hybrid_fast_missing_shard_is_an_error_with_or_without_metadata() {
    for metadata in [false, true] {
        let mut args = vec![
            "search", QUERY, "--mode", "hybrid", "--model", "bge-m3",
            "--rrf-limit", "5", "--json", "--vector-search-mode", "fast",
        ];
        if metadata {
            args.push("--robot-meta");
        }
        let result = cass(&args, SHARDLESS.data_dir());
        assert_eq!(result.status.code(), Some(9), "stdout={} stderr={}",
            String::from_utf8_lossy(&result.stdout), stderr_text(&result));
        assert!(result.stdout.is_empty(), "damage must not return lexical-only hits");
        assert!(stderr_text(&result).contains("missing int8 mirror"));
    }
}

#[test]
fn stats_respects_schema_guard_without_modifying_the_archive() {
    for version in [1, 7, schema::CURRENT_SCHEMA_VERSION, schema::CURRENT_SCHEMA_VERSION + 1] {
        let fixture = build_fixture(16, FixtureState::Active);
        let db_path = fixture.data_dir.join("agent_search.db");
        {
            let storage = FrankenStorage::open(&db_path).unwrap();
            storage.raw().execute_batch(&format!("PRAGMA user_version={version};")).unwrap();
        }
        let before = std::fs::read(&db_path).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_cass"))
            .args(["stats", "--db"]).arg(&db_path).arg("--json")
            .current_dir(&fixture.data_dir).output().unwrap();
        assert_eq!(std::fs::read(&db_path).unwrap(), before, "schema {version} changed");
        if version == schema::CURRENT_SCHEMA_VERSION {
            assert!(result.status.success(), "{}", stderr_text(&result));
            assert!(serde_json::from_slice::<serde_json::Value>(&result.stdout).is_ok());
        } else {
            assert_eq!(result.status.code(), Some(9), "schema {version}: stdout={} stderr={}",
                String::from_utf8_lossy(&result.stdout), stderr_text(&result));
            assert!(result.stdout.is_empty());
            assert!(stderr_text(&result).contains("schema"));
        }
    }
}
