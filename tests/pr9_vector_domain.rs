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
    conn.with_tx_no_replay(TxMode::Immediate, |tx| {
        let embedding = vec![1.0, 0.0, 0.0, 0.0];
        let id = schema::insert_chunk_row_in_tx(
            tx,
            &schema::ChunkRow {
                generation_id: generation,
                message_id: 1,
                conversation_id: 1,
                chunk_idx: 0,
                byte_start: 0,
                byte_end: 7,
                content_hash: "fixture".into(),
                embedding: embedding.clone(),
                norm: 1.0,
                created_at_ms: 0,
            },
        )?;
        let blob = schema::f32_vector_to_le_blob(&embedding);
        vector_domain::insert_vec0_rows_in_tx(tx, generation, &[(id, blob.as_slice())])?;
        Ok(id)
    })
}

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
