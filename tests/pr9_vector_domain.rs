//! PR9 file-backed mirror identity and transaction boundaries.
use coding_agent_search::storage::api::{Conn, StorageError, TxMode, Value};
use coding_agent_search::storage::{schema, sqlite::FrankenStorage, vector_domain};

fn archive() -> (tempfile::TempDir, FrankenStorage, i64) {
    let dir = tempfile::tempdir().unwrap();
    let storage = FrankenStorage::open(&dir.path().join("archive.db")).unwrap();
    let conn = storage.raw();
    conn.execute_batch(
        "INSERT INTO agents(id,slug,name,kind,created_at,updated_at) VALUES(1,'fixture','fixture','cli',0,0);
         INSERT INTO conversations(id,agent_id,title,source_path) VALUES(1,1,'fixture','/fixture/session.jsonl');
         INSERT INTO messages(id,conversation_id,idx,role,content) VALUES(1,1,0,'user','fixture');",
    ).unwrap();
    let generation = conn
        .with_tx_no_replay(TxMode::Immediate, |tx| {
            schema::create_embedding_generation(tx, "fixture", 4, 1, 1, b"fingerprint", 0)
        })
        .unwrap();
    vector_domain::create_vec0_table_for_generation(conn, generation, 4).unwrap();
    (dir, storage, generation)
}

fn count(conn: &Conn, table: &str) -> i64 {
    conn.query_row_map(&format!("SELECT count(*) FROM {table}"), &[], |row| {
        row.get_typed(0)
    })
    .unwrap()
}

fn insert(conn: &Conn, generation: i64) -> Result<i64, StorageError> {
    insert_at(conn, generation, 0, &[1.0, 0.0, 0.0, 0.0])
}

fn insert_at(conn: &Conn, generation: i64, index: u32, embedding: &[f32]) -> Result<i64, StorageError> {
    conn.with_tx_no_replay(TxMode::Immediate, |tx| {
        let id = schema::insert_chunk_row_in_tx(
            tx,
            &schema::ChunkRow {
                generation_id: generation,
                message_id: 1,
                conversation_id: 1,
                chunk_idx: index,
                byte_start: 0,
                byte_end: 7,
                content_hash: "fixture".into(),
                embedding: embedding.to_vec(),
                norm: 1.0,
                created_at_ms: 0,
            },
        )?;
        let blob = schema::f32_vector_to_le_blob(embedding);
        vector_domain::insert_vec0_rows_in_tx(tx, generation, &[(id, blob.as_slice())])?;
        Ok(id)
    })
}

fn revision(conn: &Conn, generation: i64) -> i64 {
    conn.query_row_map("SELECT vector_revision FROM embedding_generations WHERE id=?1", &[Value::from(generation)], |row| row.get_typed(0)).unwrap()
}

#[test]
fn pr9_delete_failure_after_first_row_restores_all_mirrors_and_authority() {
    let (_dir, storage, generation)=archive();
    let conn=storage.raw();
    let one=insert(conn,generation).unwrap();
    let two=insert_at(conn,generation,1,&[0.0,1.0,0.0,0.0]).unwrap();
    let table=vector_domain::int8_table_name(generation,2).unwrap();
    let blob: Vec<u8>=conn.query_row_map(&format!("SELECT embedding FROM {table} WHERE rowid=?1"), &[Value::from(two)], |row| row.get_typed(0)).unwrap();
    conn.execute_batch(&format!("DROP TABLE {table}; CREATE TABLE {table}(rowid INTEGER PRIMARY KEY,embedding BLOB); CREATE TRIGGER fail_delete BEFORE DELETE ON {table} BEGIN SELECT RAISE(ABORT,'fixture delete failure'); END;")).unwrap();
    conn.execute(&format!("INSERT INTO {table}(rowid,embedding) VALUES(?1,?2)"), &[Value::from(two),Value::from(blob)]).unwrap();
    let before=revision(conn,generation);
    let result=conn.with_tx_no_replay(TxMode::Immediate,|tx| {
        tx.execute("DELETE FROM message_chunks WHERE chunk_id IN (?1,?2)",&[Value::from(one),Value::from(two)])?;
        vector_domain::delete_vec0_rows_in_tx(tx,generation,&[one,two])?;
        Ok(())
    });
    assert!(result.unwrap_err().to_string().contains("fixture delete failure"));
    assert_eq!(count(conn,"message_chunks"),2);
    assert_eq!(count(conn,&format!("vec_index_gen_{generation}")),2);
    assert_eq!(count(conn,&vector_domain::int8_table_name(generation,1).unwrap()),1);
    assert_eq!(count(conn,&table),1);
    assert_eq!(revision(conn,generation),before);
}

#[test]
fn pr9_missing_int8_row_cannot_be_silently_healed_by_a_delete() {
    let (_dir,storage,generation)=archive();
    let conn=storage.raw();
    let id=insert(conn,generation).unwrap();
    let shard=vector_domain::int8_table_name(generation,(id%8) as usize).unwrap();
    conn.execute(&format!("DELETE FROM {shard} WHERE rowid=?1"),&[Value::from(id)]).unwrap();
    let before=revision(conn,generation);
    let result=conn.with_tx_no_replay(TxMode::Immediate,|tx| {
        tx.execute("DELETE FROM message_chunks WHERE chunk_id=?1",&[Value::from(id)])?;
        vector_domain::delete_vec0_rows_in_tx(tx,generation,&[id])?;
        Ok(())
    });
    assert!(result.is_err(),"missing shard identity must abort the entire authoritative delete");
    assert_eq!(count(conn,"message_chunks"),1);
    assert_eq!(count(conn,&format!("vec_index_gen_{generation}")),1);
    assert_eq!(revision(conn,generation),before);
}

#[test]
fn pr9_rebuild_failure_restores_the_previous_committed_layout() {
    let (_dir,storage,generation)=archive();
    let conn=storage.raw();
    insert(conn,generation).unwrap();
    let two=insert_at(conn,generation,1,&[0.0,1.0,0.0,0.0]).unwrap();
    let invalid=schema::f32_vector_to_le_blob(&[2.0,0.0,0.0,0.0]);
    conn.execute("UPDATE message_chunks SET embedding=?1 WHERE chunk_id=?2",&[Value::from(invalid.clone()),Value::from(two)]).unwrap();
    let before=revision(conn,generation);
    assert!(vector_domain::rebuild_vec0_table_for_generation(conn,generation,4).is_err());
    assert_eq!(revision(conn,generation),before);
    let authoritative: Vec<u8>=conn.query_row_map("SELECT embedding FROM message_chunks WHERE chunk_id=?1",&[Value::from(two)],|row|row.get_typed(0)).unwrap();
    assert_eq!(authoritative,invalid);
    let mirror: Vec<u8>=conn.query_row_map(&format!("SELECT embedding FROM vec_index_gen_{generation} WHERE rowid=?1"),&[Value::from(two)],|row|row.get_typed(0)).unwrap();
    assert_eq!(mirror,schema::f32_vector_to_le_blob(&[0.0,1.0,0.0,0.0]));
    vector_domain::check_int8_layout(conn,generation,4).unwrap();
    assert_eq!(count(conn,&format!("vec_index_gen_{generation}")),2);
}

#[test]
fn pr9_mirror_identity_audit_rejects_equal_size_swaps_and_wrong_shards() {
    let (_dir,storage,generation)=archive();
    let conn=storage.raw();
    let id=insert(conn,generation).unwrap();
    assert_eq!(vector_domain::audit_int8_mirror_identity(conn,generation,4).unwrap(),vector_domain::Int8MirrorAudit { rows:1, ..Default::default() });
    let table=vector_domain::int8_table_name(generation,1).unwrap();
    let other=vector_domain::int8_table_name(generation,0).unwrap();
    conn.execute(&format!("INSERT INTO {other}(rowid,embedding) SELECT rowid,vec_int8(embedding) FROM {table} WHERE rowid=?1"),&[Value::from(id)]).unwrap();
    let audit=vector_domain::audit_int8_mirror_identity(conn,generation,4).unwrap();
    assert_eq!(audit.duplicates,1);
    assert_eq!(audit.wrong_shard,1);
    conn.execute(&format!("DELETE FROM {table} WHERE rowid=?1"),&[Value::from(id)]).unwrap();
    let audit=vector_domain::audit_int8_mirror_identity(conn,generation,4).unwrap();
    assert_eq!(audit.rows,1);
    assert_eq!(audit.missing,1);
    assert_eq!(audit.wrong_shard,1);
    assert_eq!(audit.duplicates,0);
}

#[test]
fn pr9_database_identity_is_generated_once_and_cannot_be_replaced() {
    let (_dir,storage,_generation)=archive();
    let conn=storage.raw();
    let id: String=conn.query_row_map("SELECT value FROM meta WHERE key='vector_domain_instance_id'",&[],|row|row.get_typed(0)).unwrap();
    assert_eq!(id.len(),32);
    schema::ensure(conn).unwrap();
    assert!(conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('vector_domain_instance_id','other')",&[]).is_err());
    assert!(conn.execute("DELETE FROM meta WHERE key='vector_domain_instance_id'",&[]).is_err());
    assert!(conn.execute("UPDATE meta SET value='other' WHERE key='vector_domain_instance_id'",&[]).is_err());
    let after: String=conn.query_row_map("SELECT value FROM meta WHERE key='vector_domain_instance_id'",&[],|row|row.get_typed(0)).unwrap();
    assert_eq!(after,id);
}

#[test]
fn pr9_int8_layout_rejects_wrong_type_and_extra_logical_shards() {
    let (_dir,storage,generation)=archive();
    let conn=storage.raw();
    let last=vector_domain::int8_table_name(generation,7).unwrap();
    conn.execute_batch(&format!("DROP TABLE {last}; CREATE TABLE {last}(embedding BLOB)")).unwrap();
    assert!(vector_domain::check_int8_layout(conn,generation,4).unwrap_err().to_string().contains("invalid int8 layout"));
    conn.execute_batch(&format!("DROP TABLE {last}; CREATE VIRTUAL TABLE {last} USING vec0(embedding int8[4] distance_metric=cosine)")).unwrap();
    vector_domain::check_int8_layout(conn,generation,4).unwrap();
    conn.execute_batch(&format!("CREATE TABLE vec_index_gen_{generation}_int8_shard_9(embedding BLOB)")).unwrap();
    assert!(vector_domain::check_int8_layout(conn,generation,4).unwrap_err().to_string().contains("unexpected int8 shard table"));
}

#[cfg(target_os = "linux")]
fn resource_rebuild(rows: usize) {
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use std::time::{Duration, Instant};
    let dir=tempfile::tempdir().unwrap();
    let path=dir.path().join("corpus.db");
    let storage=FrankenStorage::open(&path).unwrap();
    let conn=storage.raw();
    conn.execute_batch(
        "INSERT INTO agents(id,slug,name,kind,created_at,updated_at) VALUES(1,'fixture','fixture','cli',0,0);
         INSERT INTO conversations(id,agent_id,title,source_path) VALUES(1,1,'fixture','/fixture/session.jsonl');
         INSERT INTO messages(id,conversation_id,idx,role,content) VALUES(1,1,0,'user','fixture');"
    ).unwrap();
    let generation=conn.with_tx_no_replay(TxMode::Immediate,|tx| schema::create_embedding_generation(tx,"fixture",1024,1,1,b"fingerprint",0)).unwrap();
    let vector=vec![1.0_f32;1024];
    for start in (0..rows).step_by(2048) {
        conn.with_tx_no_replay(TxMode::Immediate,|tx| {
            for i in start..(start+2048).min(rows) {
                schema::insert_chunk_row_in_tx(tx,&schema::ChunkRow {
                    generation_id:generation,message_id:1,conversation_id:1,chunk_idx:i as u32,
                    byte_start:0,byte_end:1,content_hash:"fixture".into(),embedding:vector.clone(),
                    norm:32.0,created_at_ms:0,
                })?;
            }
            Ok(())
        }).unwrap();
    }
    let peak_before=std::fs::read_to_string("/proc/self/status").unwrap().lines()
        .find_map(|line| line.strip_prefix("VmHWM:")).unwrap().split_whitespace().next().unwrap().parse::<u64>().unwrap();
    let done=Arc::new(AtomicBool::new(false));
    let watch=done.clone();
    let watch_path=path.clone();
    let monitor=std::thread::spawn(move || {
        let mut db_peak=0u64;
        let mut wal_peak=0u64;
        let mut rss_peak=0u64;
        loop {
            db_peak=db_peak.max(std::fs::metadata(&watch_path).map(|m|m.len()).unwrap_or(0));
            wal_peak=wal_peak.max(std::fs::metadata(format!("{}-wal",watch_path.display())).map(|m|m.len()).unwrap_or(0));
            let status=std::fs::read_to_string("/proc/self/status").unwrap();
            let hwm=status.lines().find_map(|line|line.strip_prefix("VmHWM:")).unwrap().split_whitespace().next().unwrap().parse::<u64>().unwrap();
            rss_peak=rss_peak.max(hwm);
            if watch.load(Ordering::Acquire) {break;}
            std::thread::sleep(Duration::from_millis(10));
        }
        (db_peak,wal_peak,rss_peak)
    });
    let started=Instant::now();
    let result=vector_domain::rebuild_vec0_table_for_generation(conn,generation,1024);
    let elapsed=started.elapsed();
    done.store(true,Ordering::Release);
    let (db_peak,wal_peak,rss_peak)=monitor.join().unwrap();
    assert_eq!(result.unwrap(),rows);
    assert_eq!(count(conn,&format!("vec_index_gen_{generation}")),rows as i64);
    let audit=vector_domain::audit_int8_mirror_identity(conn,generation,1024).unwrap();
    assert_eq!(audit,vector_domain::Int8MirrorAudit { rows:rows as i64, ..Default::default() });
    conn.execute("UPDATE embedding_generations SET is_active=1 WHERE id=?1",&[Value::from(generation)]).unwrap();
    let client=coding_agent_search::search::query::SearchClient::open(&dir.path().join("index"),Some(&path)).unwrap().unwrap()
        .with_vector_search_mode(coding_agent_search::search::query::VectorSearchMode::Fast);
    let requested=rows+1;
    let (hits,meta)=client.search_vector_candidates(
        &vector,&coding_agent_search::search::query::SearchFilters::default(),None,requested,
    ).unwrap();
    assert_eq!(hits.len(),1);
    if rows>4096 {
        assert_eq!(meta.first_round_rows,0,"large window must not run int8 KNN");
        assert_eq!(meta.coarse_skip_reason.as_deref(),Some("large_window"));
        assert!(!meta.approximate);
    } else {
        assert_eq!(meta.first_round_rows,rows);
        assert_eq!(meta.corpus_limited,Some(true));
        assert!(meta.approximate);
    }
    println!("PR9_RESOURCE rows={rows} rebuild_ms={} vmhwm_before_kib={peak_before} vmhwm_peak_kib={rss_peak} db_peak_bytes={db_peak} wal_peak_bytes={wal_peak}",elapsed.as_millis());
}

#[cfg(target_os = "linux")]
#[test]
fn pr9_resource_rebuild_4096_rows() {resource_rebuild(4096);}

#[cfg(target_os = "linux")]
#[test]
fn pr9_resource_rebuild_16384_rows() {resource_rebuild(16384);}

#[test]
fn pr9_nine_mirrors_share_the_authoritative_row_identity() {
    let (_dir, storage, generation) = archive();
    let conn = storage.raw();
    let id = insert(conn, generation).unwrap();
    let float = format!("vec_index_gen_{generation}");
    assert_eq!(count(conn, &float), 1);
    let mut total = 0;
    for shard in 0..8 {
        let table = format!("{float}_int8_shard_{shard}");
        let n = count(conn, &table);
        assert_eq!(n, i64::from(shard == id % 8));
        total += n;
    }
    assert_eq!(total, 1);
    let blob: Vec<u8> = conn
        .query_row_map(
            &format!("SELECT embedding FROM {float} WHERE rowid=?1"),
            &[Value::from(id)],
            |row| row.get_typed(0),
        )
        .unwrap();
    assert_eq!(blob, schema::f32_vector_to_le_blob(&[1.0, 0.0, 0.0, 0.0]));
}

#[test]
fn pr9_int8_write_failure_rolls_back_authority_float_and_revision() {
    let (_dir, storage, generation) = archive();
    let conn = storage.raw();
    // A genuine SQLite constraint error in the first chunk's routed shard.
    conn.execute_batch(&format!(
        "DROP TABLE vec_index_gen_{generation}_int8_shard_1;
         CREATE TABLE vec_index_gen_{generation}_int8_shard_1(rowid INTEGER PRIMARY KEY,embedding BLOB CHECK(0));"
    )).unwrap();
    let revision: i64 = conn
        .query_row_map(
            "SELECT vector_revision FROM embedding_generations WHERE id=?1",
            &[Value::from(generation)],
            |row| row.get_typed(0),
        )
        .unwrap();
    assert!(insert(conn, generation).is_err());
    assert_eq!(count(conn, "message_chunks"), 0);
    assert_eq!(count(conn, &format!("vec_index_gen_{generation}")), 0);
    let after: i64 = conn
        .query_row_map(
            "SELECT vector_revision FROM embedding_generations WHERE id=?1",
            &[Value::from(generation)],
            |row| row.get_typed(0),
        )
        .unwrap();
    assert_eq!(after, revision);
}
