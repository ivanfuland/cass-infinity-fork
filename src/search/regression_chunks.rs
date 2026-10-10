//! Active-generation chunk inventory, recomputed with the production Rust policy.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::storage::api::{Conn, Profile, Row, StorageError, Value, params};

use super::canonicalize::CANONICALIZE_PIPELINE_VERSION;
use super::chunking::CHUNKING_POLICY_VERSION;
use super::eligibility::{expected_chunks, normalized_for_chunks};
use super::regression_inventory::{ConversationRow, string};
use super::regression_io::{RegressionIoContext, validate_private_run_root};

const PAGE_SIZE: i64 = 128;

pub(crate) struct ChunkInventory {
    pub(crate) sha256: String,
    pub(crate) chunk_count: u64,
    pub(crate) generation_id: i64,
    pub(crate) rows_path: PathBuf,
}

struct StoredChunk {
    id: i64,
    conversation: i64,
    idx: i64,
    start: i64,
    end: i64,
    hash: String,
}

impl StoredChunk {
    fn read(row: &Row) -> Result<Self, StorageError> {
        Ok(Self {
            id: row.get_typed(0)?,
            conversation: row.get_typed(1)?,
            idx: row.get_typed(2)?,
            start: row.get_typed(3)?,
            end: row.get_typed(4)?,
            hash: row.get_typed(5)?,
        })
    }
}

pub(crate) fn export_chunks(context: &RegressionIoContext) -> Result<ChunkInventory> {
    context.verify_input()?;
    validate_private_run_root(context.run_root())?;
    let source = context.connection()?;
    let active: Vec<i64> = source.query_all_map(
        "SELECT id FROM embedding_generations WHERE is_active=1 LIMIT 2",
        &[],
        |row| row.get_typed(0),
    )?;
    let generation_id = match active.as_slice() {
        [id] => *id,
        [] => bail!("NO_ACTIVE_GENERATION"),
        _ => bail!("AMBIGUOUS_ACTIVE_GENERATION"),
    };
    if source.query_opt_map("SELECT 1 FROM message_chunks ch LEFT JOIN messages m ON m.id=ch.message_id WHERE ch.generation_id=?1 AND m.id IS NULL LIMIT 1",&params![generation_id],|r|r.get_typed::<i64>(0))?.is_some() {
        bail!("ORPHAN_ACTIVE_CHUNK");
    }
    let spool_path = context.run_root().join("chunk-inventory-spool.sqlite");
    tempfile::NamedTempFile::new_in(context.run_root())?.persist_noclobber(&spool_path)?;
    let spool = Conn::open_writable(&spool_path, Profile::Production)?;
    spool.execute_batch("CREATE TABLE chunk_rows(chunk_id INTEGER UNIQUE NOT NULL, message_id INTEGER NOT NULL, conversation_id INTEGER NOT NULL, host TEXT NOT NULL, agent TEXT NOT NULL, external TEXT NOT NULL, idx INTEGER NOT NULL, chunk_idx INTEGER NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(host,agent,external,idx,chunk_idx)) WITHOUT ROWID;")?;
    let mut cursor: Option<i64> = None;
    let mut chunk_count = 0u64;
    loop {
        context.verify_input()?;
        let predicate = if cursor.is_some() { "m.id>?1" } else { "1" };
        let sql = format!(
            "SELECT c.id,c.identity_host,a.slug,c.external_id,c.metadata_json,c.metadata_bin,m.id,m.idx,m.role,m.content FROM messages m LEFT JOIN conversations c ON c.id=m.conversation_id LEFT JOIN agents a ON a.id=c.agent_id WHERE {predicate} ORDER BY m.id LIMIT ?2"
        );
        let messages = source.query_all_map(&sql, &params![cursor, PAGE_SIZE], |r| {
            Ok((
                ConversationRow::read(r)?,
                r.get_typed::<i64>(6)?,
                r.get_typed::<i64>(7)?,
                r.get_typed::<String>(8)?,
                r.get_typed::<String>(9)?,
            ))
        })?;
        if messages.is_empty() {
            break;
        }
        let tx = spool.transaction()?;
        for (conversation, id, idx, role, content) in messages {
            let (cid, host, agent, external) = conversation.key()?;
            let normalized = normalized_for_chunks(&content);
            let expected = expected_chunks(id, cid, &role, &content);
            let actual = source.query_all_map("SELECT chunk_id,conversation_id,chunk_idx,byte_start,byte_end,content_hash FROM message_chunks WHERE generation_id=?1 AND message_id=?2 ORDER BY chunk_idx",&params![generation_id,id],StoredChunk::read)?;
            if actual.windows(2).any(|rows| rows[0].idx == rows[1].idx) {
                bail!("DUPLICATE_STABLE_CHUNK_KEY");
            }
            if actual.len() != expected.len() {
                bail!("CHUNK_MEMBERSHIP_MISMATCH");
            }
            for (stored, wanted) in actual.iter().zip(&expected) {
                if stored.id < 0 {
                    bail!("NEGATIVE_CHUNK_ID");
                }
                if stored.conversation != cid {
                    bail!("CHUNK_ASSOCIATION_MISMATCH");
                }
                let start = i64::try_from(wanted.byte_start)?;
                let end = i64::try_from(wanted.byte_end)?;
                if (stored.idx, stored.start, stored.end)
                    != (i64::from(wanted.chunk_idx), start, end)
                {
                    bail!("CHUNK_SPAN_MISMATCH");
                }
                if stored.hash.len() != 64 {
                    bail!("CHUNK_HASH_MISMATCH");
                }
                let stored_hash = hex::decode(&stored.hash).context("CHUNK_HASH_MISMATCH")?;
                let expected_hash = hex::decode(&wanted.content_hash)?;
                if stored_hash != expected_hash {
                    bail!("CHUNK_HASH_MISMATCH");
                }
                let text = normalized
                    .get(wanted.byte_start..wanted.byte_end)
                    .context("CHUNK_SPAN_MISMATCH")?;
                let mut payload = Vec::new();
                string(&mut payload, &host);
                string(&mut payload, &agent);
                string(&mut payload, &external);
                payload.extend_from_slice(&idx.to_be_bytes());
                payload.extend_from_slice(&i64::from(wanted.chunk_idx).to_be_bytes());
                payload.extend_from_slice(&start.to_be_bytes());
                payload.extend_from_slice(&end.to_be_bytes());
                payload.extend_from_slice(&Sha256::digest(text.as_bytes()));
                payload.extend_from_slice(&expected_hash);
                match tx.execute(
                    "INSERT INTO chunk_rows VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    &params![
                        stored.id,
                        id,
                        cid,
                        host.clone(),
                        agent.clone(),
                        external.clone(),
                        idx,
                        stored.idx,
                        payload
                    ],
                ) {
                    Err(StorageError::Constraint { .. }) => bail!("DUPLICATE_STABLE_CHUNK_KEY"),
                    value => {
                        value?;
                    }
                }
                chunk_count += 1;
            }
            cursor = Some(id);
        }
        tx.commit()?;
    }
    let actual_count: i64 = source.query_row_map(
        "SELECT COUNT(*) FROM message_chunks WHERE generation_id=?1",
        &params![generation_id],
        |r| r.get_typed(0),
    )?;
    if u64::try_from(actual_count)? != chunk_count {
        bail!("CHUNK_INVENTORY_COUNT_MISMATCH");
    }
    // Build after bulk insertion for the trace validator's per-candidate lookup.
    spool.execute_batch(
        "CREATE INDEX chunk_rows_message_chunk ON chunk_rows(message_id,chunk_idx);",
    )?;
    let mut output = tempfile::NamedTempFile::new_in(context.run_root())?;
    let mut hash = Sha256::new();
    let mut header = Vec::new();
    string(&mut header, "chunk-text-v1");
    header.extend_from_slice(&CANONICALIZE_PIPELINE_VERSION.to_be_bytes());
    header.extend_from_slice(&CHUNKING_POLICY_VERSION.to_be_bytes());
    output.write_all(&header)?;
    hash.update(header);
    let mut key: Option<(String, String, String, i64, i64)> = None;
    let mut emitted = 0u64;
    loop {
        context.verify_input()?;
        let params = match &key {
            None => vec![
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                PAGE_SIZE.into(),
            ],
            Some((h, a, e, i, c)) => vec![
                h.clone().into(),
                a.clone().into(),
                e.clone().into(),
                (*i).into(),
                (*c).into(),
                PAGE_SIZE.into(),
            ],
        };
        let predicate = if key.is_some() {
            "(host,agent,external,idx,chunk_idx)>(?1,?2,?3,?4,?5)"
        } else {
            "1"
        };
        let sql = format!(
            "SELECT host,agent,external,idx,chunk_idx,payload FROM chunk_rows WHERE {predicate} ORDER BY host,agent,external,idx,chunk_idx LIMIT ?6"
        );
        let rows = spool.query_all_map(&sql, &params, |r| {
            Ok((
                r.get_typed::<String>(0)?,
                r.get_typed::<String>(1)?,
                r.get_typed::<String>(2)?,
                r.get_typed::<i64>(3)?,
                r.get_typed::<i64>(4)?,
                r.get_typed::<Vec<u8>>(5)?,
            ))
        })?;
        if rows.is_empty() {
            break;
        }
        for (h, a, e, i, c, payload) in rows {
            let length = (payload.len() as u64).to_be_bytes();
            output.write_all(&length)?;
            output.write_all(&payload)?;
            hash.update(length);
            hash.update(payload);
            key = Some((h, a, e, i, c));
            emitted += 1;
        }
    }
    if emitted != chunk_count {
        bail!("CHUNK_INVENTORY_COUNT_MISMATCH");
    }
    let tail = chunk_count.to_be_bytes();
    output.write_all(&tail)?;
    hash.update(tail);
    output.as_file().sync_all()?;
    context.verify_input()?;
    validate_private_run_root(context.run_root())?;
    spool.close_with_checkpoint()?;
    let rows_path = context.run_root().join("chunk-text-v1.bin");
    output.persist_noclobber(&rows_path)?;
    Ok(ChunkInventory {
        sha256: hex::encode(hash.finalize()),
        chunk_count,
        generation_id,
        rows_path,
    })
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use std::fs;

    pub(crate) fn fixture(
        message_change: &str,
        chunk_change: &str,
    ) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let (root, db, run) = super::super::regression_inventory::tests::fixture(message_change);
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        writer.execute_batch("CREATE TABLE embedding_generations(id INTEGER PRIMARY KEY,is_active INTEGER); INSERT INTO embedding_generations VALUES(1,1),(9,0); CREATE TABLE message_chunks(chunk_id INTEGER PRIMARY KEY,generation_id INTEGER,message_id INTEGER,conversation_id INTEGER,chunk_idx INTEGER,byte_start INTEGER,byte_end INTEGER,content_hash TEXT,embedding BLOB,norm REAL);").unwrap();
        let messages = writer
            .query_all_map(
                "SELECT id,conversation_id,role,content FROM messages",
                &[],
                |r| {
                    Ok((
                        r.get_typed::<i64>(0)?,
                        r.get_typed::<i64>(1)?,
                        r.get_typed::<String>(2)?,
                        r.get_typed::<String>(3)?,
                    ))
                },
            )
            .unwrap();
        let mut id = 1i64;
        for (mid, cid, role, content) in messages {
            for chunk in expected_chunks(mid, cid, &role, &content) {
                writer
                    .execute(
                        "INSERT INTO message_chunks VALUES(?1,1,?2,?3,?4,?5,?6,?7,X'00000000',1)",
                        &params![
                            id,
                            mid,
                            cid,
                            i64::from(chunk.chunk_idx),
                            chunk.byte_start as i64,
                            chunk.byte_end as i64,
                            chunk.content_hash
                        ],
                    )
                    .unwrap();
                id += 1;
            }
        }
        writer.execute_batch(chunk_change).unwrap();
        writer
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .unwrap();
        drop(writer);
        (root, db, run)
    }

    fn export(message: &str, chunks: &str) -> Result<ChunkInventory> {
        let (_root, db, run) = fixture(message, chunks);
        let context = RegressionIoContext::open(&db, &run)?;
        export_chunks(&context)
    }

    #[test]
    fn chunk_inventory_uses_rust_policy_and_private_recomputable_records() {
        let (_root, db, run) = fixture("", "");
        let before = fs::read(&db).unwrap();
        let context = RegressionIoContext::open(&db, &run).unwrap();
        let inventory = export_chunks(&context).unwrap();
        assert_eq!(inventory.chunk_count, 1);
        assert_eq!(inventory.generation_id, 1);
        let bytes = fs::read(&inventory.rows_path).unwrap();
        assert_eq!(inventory.sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(&bytes[..8], &13u64.to_be_bytes());
        assert_eq!(&bytes[8..21], b"chunk-text-v1");
        assert_eq!(fs::read(&db).unwrap(), before);
    }

    #[test]
    fn spool_lookup_index_preserves_results_and_canonical_export() {
        let (_root, db, run) = fixture("", "");
        let context = RegressionIoContext::open(&db, &run).unwrap();
        let inventory = export_chunks(&context).unwrap();
        let spool = Conn::open_writable(
            &run.join("chunk-inventory-spool.sqlite"),
            Profile::Production,
        )
        .unwrap();
        let lookup = "SELECT 1 FROM chunk_rows WHERE message_id=?1 AND chunk_idx=?2";
        let plan_sql = format!("EXPLAIN QUERY PLAN {lookup}");
        let plan = || {
            spool
                .query_all_map(&plan_sql, &params![1i64, 0i64], |r| {
                    r.get_typed::<String>(3)
                })
                .unwrap()
                .join("\n")
        };
        let results = || {
            [(1i64, 0i64), (1, 999), (999, 0)].map(|(message, chunk)| {
                spool
                    .query_all_map(lookup, &params![message, chunk], |r| r.get_typed::<i64>(0))
                    .unwrap()
            })
        };
        let canonical = || {
            let payloads = spool
                .query_all_map(
                    "SELECT payload FROM chunk_rows ORDER BY host,agent,external,idx,chunk_idx",
                    &[],
                    |r| r.get_typed::<Vec<u8>>(0),
                )
                .unwrap();
            let mut bytes = Vec::new();
            string(&mut bytes, "chunk-text-v1");
            bytes.extend_from_slice(&CANONICALIZE_PIPELINE_VERSION.to_be_bytes());
            bytes.extend_from_slice(&CHUNKING_POLICY_VERSION.to_be_bytes());
            for payload in &payloads {
                bytes.extend_from_slice(&(payload.len() as u64).to_be_bytes());
                bytes.extend_from_slice(payload);
            }
            bytes.extend_from_slice(&(payloads.len() as u64).to_be_bytes());
            bytes
        };
        let indexed_plan = plan();
        assert!(indexed_plan.contains("USING COVERING INDEX chunk_rows_message_chunk"));
        let indexed_results = results();
        assert_eq!(indexed_results, [vec![1], vec![], vec![]]);
        let bytes = fs::read(&inventory.rows_path).unwrap();
        assert_eq!(canonical(), bytes);
        let non_unique: i64 = spool
            .query_row_map(
                "SELECT \"unique\" FROM pragma_index_list('chunk_rows') WHERE name='chunk_rows_message_chunk'",
                &[],
                |r| r.get_typed(0),
            )
            .unwrap();
        assert_eq!(non_unique, 0);
        spool
            .execute_batch("DROP INDEX chunk_rows_message_chunk;")
            .unwrap();
        let unindexed_plan = plan();
        assert!(unindexed_plan.contains("SCAN chunk_rows"));
        assert_eq!(results(), indexed_results);
        assert_eq!(canonical(), bytes);
        assert_eq!(hex::encode(Sha256::digest(canonical())), inventory.sha256);
        assert_eq!(inventory.chunk_count, 1);
        println!(
            "unindexed_plan={unindexed_plan}; indexed_plan={indexed_plan}; canonical_sha256={}; chunk_count={}",
            inventory.sha256, inventory.chunk_count
        );
    }

    #[test]
    fn text_inventory_ignores_raw_ids_vectors_and_inactive_chunks() {
        let original = export("", "").unwrap().sha256;
        for change in [
            "UPDATE message_chunks SET chunk_id=chunk_id+10;",
            "UPDATE message_chunks SET embedding=randomblob(16),norm=2;",
            "UPDATE message_chunks SET content_hash=upper(content_hash);",
            "INSERT INTO message_chunks SELECT 999,9,message_id,conversation_id,chunk_idx,-4,-2,'wrong',embedding,norm FROM message_chunks;",
            "UPDATE conversations SET id=40; UPDATE messages SET id=100,conversation_id=40; UPDATE lex_docs SET doc_id=100; UPDATE message_chunks SET message_id=100,conversation_id=40;",
        ] {
            assert_eq!(original, export("", change).unwrap().sha256, "{change}");
        }
    }

    #[test]
    fn refuses_wrong_chunk_membership_spans_hashes_and_associations() {
        for (change, rejection) in [
            ("DELETE FROM message_chunks;", "CHUNK_MEMBERSHIP_MISMATCH"),
            (
                "UPDATE message_chunks SET byte_start=byte_start+1;",
                "CHUNK_SPAN_MISMATCH",
            ),
            (
                "UPDATE message_chunks SET content_hash=printf('%064d',0);",
                "CHUNK_HASH_MISMATCH",
            ),
            (
                "UPDATE message_chunks SET conversation_id=999;",
                "CHUNK_ASSOCIATION_MISMATCH",
            ),
            (
                "UPDATE message_chunks SET message_id=999;",
                "ORPHAN_ACTIVE_CHUNK",
            ),
            (
                "UPDATE message_chunks SET chunk_id=-1;",
                "NEGATIVE_CHUNK_ID",
            ),
            (
                "INSERT INTO message_chunks SELECT 999,generation_id,message_id,conversation_id,chunk_idx,byte_start,byte_end,content_hash,embedding,norm FROM message_chunks;",
                "DUPLICATE_STABLE_CHUNK_KEY",
            ),
            (
                "UPDATE embedding_generations SET is_active=0;",
                "NO_ACTIVE_GENERATION",
            ),
            (
                "UPDATE embedding_generations SET is_active=1;",
                "AMBIGUOUS_ACTIVE_GENERATION",
            ),
        ] {
            let error = export("", change).err().expect("must reject");
            assert!(
                format!("{error:#}").contains(rejection),
                "{change}: {error:#}"
            );
        }
    }

    #[test]
    fn excluded_role_has_no_chunks_and_stored_message_changes_require_new_chunks() {
        assert_eq!(
            export(
                "UPDATE messages SET role='reasoning'; DELETE FROM lex_docs;",
                ""
            )
            .unwrap()
            .chunk_count,
            0
        );
        let (_root, db, run) = fixture("", "");
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        writer.execute_batch("UPDATE messages SET content=content||' Changed.'; PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;").unwrap();
        drop(writer);
        let context = RegressionIoContext::open(&db, &run).unwrap();
        assert!(export_chunks(&context).is_err());
    }

    #[test]
    fn chunk_inventory_streams_across_multiple_pages() {
        let change = "WITH RECURSIVE numbers(n) AS(SELECT 2 UNION ALL SELECT n+1 FROM numbers WHERE n<260) INSERT INTO messages SELECT n,1,261-n,'user',20,'Investigate retrieval ranking and compare the evidence from both runs.',NULL FROM numbers; INSERT INTO lex_docs SELECT id,content,'title','codex','workspace','synthetic.jsonl' FROM messages WHERE id>1;";
        assert_eq!(export(change, "").unwrap().chunk_count, 260);
    }

    #[test]
    fn chunk_inventory_readonly_child() -> Result<()> {
        let Some(database) = std::env::var_os("CASS_CHUNK_INVENTORY_DB") else {
            return Ok(());
        };
        let run = std::env::var_os("CASS_CHUNK_INVENTORY_RUN").unwrap();
        let context =
            RegressionIoContext::open(std::path::Path::new(&database), std::path::Path::new(&run))?;
        super::super::regression_inventory::export_messages(&context)?;
        assert_eq!(export_chunks(&context)?.chunk_count, 1);
        println!("MESSAGE_AND_CHUNK_INVENTORY_READONLY_VERIFIED");
        Ok(())
    }

    #[test]
    fn exports_message_and_chunk_inventory_on_os_readonly_input() {
        let (_root, db, run) = fixture("", "");
        let before = fs::read(&db).unwrap();
        let output = std::process::Command::new("/usr/bin/bwrap")
            .args(["--ro-bind", "/", "/", "--bind"])
            .arg(&run)
            .arg(&run)
            .args(["--unshare-net", "--proc", "/proc", "--dev", "/dev"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "search::regression_chunks::tests::chunk_inventory_readonly_child",
                "--nocapture",
            ])
            .env("CASS_CHUNK_INVENTORY_DB", &db)
            .env("CASS_CHUNK_INVENTORY_RUN", &run)
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
                .contains("MESSAGE_AND_CHUNK_INVENTORY_READONLY_VERIFIED")
        );
        assert_eq!(fs::read(&db).unwrap(), before);
    }
}
