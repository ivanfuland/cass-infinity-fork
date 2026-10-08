//! Private, streaming inventory of the stored message domain.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::indexer::exclusion::ExcludedMarker;
use crate::storage::api::{Conn, Profile, Row, StorageError, Value, params};
use crate::storage::sqlite::conversation_identity_host_from_metadata;

use super::canonicalize::CANONICALIZE_PIPELINE_VERSION;
use super::chunking::CHUNKING_POLICY_VERSION;
use super::eligibility::{expected_chunks, lexical_eligible, normalized_for_chunks};
use super::regression_io::{RegressionIoContext, validate_private_run_root};

const PAGE_SIZE: i64 = 128;

pub(crate) struct MessageInventory {
    pub(crate) sha256: String,
    pub(crate) message_count: u64,
    pub(crate) conversation_count: u64,
    pub(crate) rows_path: PathBuf,
}

pub(crate) struct ConversationRow {
    id: i64,
    host: Option<String>,
    agent: Option<String>,
    external: Option<String>,
    json: Option<String>,
    binary: Option<Vec<u8>>,
}

impl ConversationRow {
    pub(crate) fn read(row: &Row) -> Result<Self, StorageError> {
        Ok(Self {
            id: row.get_typed(0)?,
            host: row.get_typed(1)?,
            agent: row.get_typed(2)?,
            external: row.get_typed(3)?,
            json: row.get_typed(4)?,
            binary: row.get_typed(5)?,
        })
    }

    pub(crate) fn key(self) -> Result<(i64, String, String, String)> {
        let host = self
            .host
            .filter(|s| !s.is_empty())
            .context("IDENTITY_CARRIER_MISMATCH")?;
        let agent = self
            .agent
            .filter(|s| !s.is_empty())
            .context("MISSING_STABLE_CONVERSATION_KEY")?;
        let external = self
            .external
            .filter(|s| !s.is_empty())
            .context("MISSING_STABLE_CONVERSATION_KEY")?;
        let metadata: serde_json::Value = if let Some(bytes) = self.binary.filter(|b| !b.is_empty())
        {
            rmp_serde::from_slice(&bytes).context("IDENTITY_CARRIER_DECODE_FAILED")?
        } else {
            // Match the existing JSON carrier fallback. Binary corruption above
            // is a named rejection and must never silently use this branch.
            self.json
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_else(|| serde_json::json!({}))
        };
        if conversation_identity_host_from_metadata(&metadata) != host {
            bail!("IDENTITY_CARRIER_MISMATCH");
        }
        Ok((self.id, host, agent, external))
    }
}

struct MessageRow {
    id: i64,
    conversation: i64,
    idx: i64,
    role: String,
    created: Option<i64>,
    started: Option<i64>,
    source: Option<String>,
    origin: Option<String>,
    kind: Option<String>,
    title: Option<String>,
    workspace: Option<String>,
    path: String,
    content: String,
    excluded: Option<String>,
    lexical: Option<i64>,
    projection: [Option<String>; 5],
}

impl MessageRow {
    fn read(row: &Row) -> Result<Self, StorageError> {
        Ok(Self {
            id: row.get_typed(0)?,
            conversation: row.get_typed(1)?,
            idx: row.get_typed(2)?,
            role: row.get_typed(3)?,
            created: row.get_typed(4)?,
            started: row.get_typed(5)?,
            source: row.get_typed(6)?,
            origin: row.get_typed(7)?,
            kind: row.get_typed(8)?,
            title: row.get_typed(9)?,
            workspace: row.get_typed(10)?,
            path: row.get_typed(11)?,
            content: row.get_typed(12)?,
            excluded: row.get_typed(13)?,
            lexical: row.get_typed(14)?,
            projection: [
                row.get_typed(15)?,
                row.get_typed(16)?,
                row.get_typed(17)?,
                row.get_typed(18)?,
                row.get_typed(19)?,
            ],
        })
    }

    fn encode(&self, key: &(String, String, String)) -> Result<Vec<u8>> {
        let excluded = self
            .excluded
            .as_deref()
            .map(ExcludedMarker::from_json_str)
            .transpose()
            .context("EXCLUDED_MARKER_INVALID")?
            .is_some();
        let eligible = lexical_eligible(&self.role, &self.content);
        if eligible != self.lexical.is_some() {
            bail!("LEXICAL_PROJECTION_MEMBERSHIP_MISMATCH");
        }
        if self.lexical.is_some() {
            let expected = [
                &self.content,
                self.title.as_deref().unwrap_or(""),
                &key.1,
                self.workspace.as_deref().unwrap_or(""),
                &self.path,
            ];
            if self
                .projection
                .iter()
                .zip(expected)
                .any(|(actual, expected)| actual.as_deref() != Some(expected))
            {
                bail!("LEXICAL_PROJECTION_MISMATCH");
            }
        }
        let mut bytes = Vec::new();
        string(&mut bytes, &key.0);
        string(&mut bytes, &key.1);
        string(&mut bytes, &key.2);
        bytes.extend_from_slice(&self.idx.to_be_bytes());
        string(&mut bytes, &self.role);
        bytes.push(u8::from(excluded));
        optional_integer(&mut bytes, self.created);
        optional_integer(&mut bytes, self.started);
        for value in [
            &self.source,
            &self.origin,
            &self.kind,
            &self.title,
            &self.workspace,
        ] {
            optional_digest(&mut bytes, value.as_deref());
        }
        bytes.extend_from_slice(&Sha256::digest(self.path.as_bytes()));
        bytes.push(u8::from(self.lexical.is_some()));
        if self.lexical.is_some() {
            for value in &self.projection {
                bytes.extend_from_slice(&Sha256::digest(
                    value
                        .as_deref()
                        .context("LEXICAL_PROJECTION_MISMATCH")?
                        .as_bytes(),
                ));
            }
        }
        bytes.extend_from_slice(&Sha256::digest(self.content.as_bytes()));
        bytes.extend_from_slice(&Sha256::digest(
            normalized_for_chunks(&self.content).as_bytes(),
        ));
        bytes.push(u8::from(eligible));
        bytes.extend_from_slice(
            &(expected_chunks(self.id, self.conversation, &self.role, &self.content).len() as u64)
                .to_be_bytes(),
        );
        Ok(bytes)
    }
}

pub(crate) fn string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn optional_integer(bytes: &mut Vec<u8>, value: Option<i64>) {
    bytes.push(u8::from(value.is_some()));
    if let Some(value) = value {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
}

fn optional_digest(bytes: &mut Vec<u8>, value: Option<&str>) {
    bytes.push(u8::from(value.is_some()));
    if let Some(value) = value {
        bytes.extend_from_slice(&Sha256::digest(value.as_bytes()));
    }
}

/// Source scans are by integer primary key. Stable-key sorting happens only
/// in this run's private spool, whose payloads contain hashes rather than text.
pub(crate) fn export_messages(context: &RegressionIoContext) -> Result<MessageInventory> {
    context.verify_input()?;
    validate_private_run_root(context.run_root())?;
    let spool_file = tempfile::NamedTempFile::new_in(context.run_root())?;
    let spool_path = context.run_root().join("message-inventory-spool.sqlite");
    spool_file.persist_noclobber(&spool_path)?;
    let spool = Conn::open_writable(&spool_path, Profile::Production)?;
    spool.execute_batch("CREATE TABLE conversations(cid INTEGER UNIQUE NOT NULL, host TEXT NOT NULL, agent TEXT NOT NULL, external TEXT NOT NULL, PRIMARY KEY(host,agent,external)) WITHOUT ROWID; CREATE TABLE message_rows(mid INTEGER UNIQUE NOT NULL, cid INTEGER NOT NULL, lexical INTEGER UNIQUE, host TEXT NOT NULL, agent TEXT NOT NULL, external TEXT NOT NULL, idx INTEGER NOT NULL, payload BLOB NOT NULL, PRIMARY KEY(host,agent,external,idx)) WITHOUT ROWID;")?;
    let source = context.connection()?;
    let mut cursor: Option<i64> = None;
    let mut conversation_count = 0u64;
    loop {
        context.verify_input()?;
        let predicate = if cursor.is_some() { "c.id>?1" } else { "1" };
        let sql = format!(
            "SELECT c.id,c.identity_host,a.slug,c.external_id,c.metadata_json,c.metadata_bin FROM conversations c LEFT JOIN agents a ON a.id=c.agent_id WHERE {predicate} ORDER BY c.id LIMIT ?2"
        );
        let rows =
            source.query_all_map(&sql, &params![cursor, PAGE_SIZE], ConversationRow::read)?;
        if rows.is_empty() {
            break;
        }
        let tx = spool.transaction()?;
        for row in rows {
            let (id, host, agent, external) = row.key()?;
            match tx.execute(
                "INSERT INTO conversations VALUES(?1,?2,?3,?4)",
                &params![id, host, agent, external],
            ) {
                Err(StorageError::Constraint { .. }) => bail!("DUPLICATE_STABLE_CONVERSATION_KEY"),
                value => {
                    value?;
                }
            }
            cursor = Some(id);
            conversation_count += 1;
        }
        tx.commit()?;
    }
    // Reject orphan associations without grouping or sorting on the source.
    for (sql, rejection) in [
        (
            "SELECT 1 FROM messages m LEFT JOIN conversations c ON c.id=m.conversation_id WHERE c.id IS NULL LIMIT 1",
            "ORPHAN_MESSAGE",
        ),
        (
            "SELECT 1 FROM lex_docs l LEFT JOIN messages m ON m.id=l.doc_id WHERE m.id IS NULL LIMIT 1",
            "ORPHAN_LEXICAL_DOCUMENT",
        ),
        (
            "SELECT 1 FROM conversations c LEFT JOIN workspaces w ON w.id=c.workspace_id WHERE c.workspace_id IS NOT NULL AND w.id IS NULL LIMIT 1",
            "ORPHAN_WORKSPACE",
        ),
        (
            "SELECT 1 FROM conversations c LEFT JOIN sources s ON s.id=c.source_id WHERE c.source_id IS NOT NULL AND s.id IS NULL LIMIT 1",
            "ORPHAN_SOURCE",
        ),
    ] {
        if source
            .query_opt_map(sql, &[], |r| r.get_typed::<i64>(0))?
            .is_some()
        {
            bail!("{rejection}");
        }
    }
    cursor = None;
    let mut message_count = 0u64;
    loop {
        context.verify_input()?;
        let predicate = if cursor.is_some() { "m.id>?1" } else { "1" };
        let sql = format!(
            "SELECT m.id,m.conversation_id,m.idx,m.role,m.created_at,c.started_at,c.source_id,c.origin_host,s.kind,c.title,w.path,c.source_path,m.content,json(m.excluded),l.doc_id,l.content,l.title,l.agent,l.workspace,l.source_path FROM messages m JOIN conversations c ON c.id=m.conversation_id LEFT JOIN sources s ON s.id=c.source_id LEFT JOIN workspaces w ON w.id=c.workspace_id LEFT JOIN lex_docs l ON l.doc_id=m.id WHERE {predicate} ORDER BY m.id LIMIT ?2"
        );
        let rows = source.query_all_map(&sql, &params![cursor, PAGE_SIZE], MessageRow::read)?;
        if rows.is_empty() {
            break;
        }
        let tx = spool.transaction()?;
        for row in rows {
            let key = tx.query_row_map(
                "SELECT host,agent,external FROM conversations WHERE cid=?1",
                &params![row.conversation],
                |r| {
                    Ok((
                        r.get_typed::<String>(0)?,
                        r.get_typed::<String>(1)?,
                        r.get_typed::<String>(2)?,
                    ))
                },
            )?;
            let payload = row.encode(&key)?;
            match tx.execute(
                "INSERT INTO message_rows VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                &params![
                    row.id,
                    row.conversation,
                    row.lexical,
                    key.0,
                    key.1,
                    key.2,
                    row.idx,
                    payload
                ],
            ) {
                Err(StorageError::Constraint { .. }) => bail!("DUPLICATE_STABLE_MESSAGE_KEY"),
                value => {
                    value?;
                }
            }
            cursor = Some(row.id);
            message_count += 1;
        }
        tx.commit()?;
    }
    let mut output = tempfile::NamedTempFile::new_in(context.run_root())?;
    let mut hash = Sha256::new();
    let mut header = Vec::new();
    string(&mut header, "message-text-v3");
    header.extend_from_slice(&CANONICALIZE_PIPELINE_VERSION.to_be_bytes());
    header.extend_from_slice(&CHUNKING_POLICY_VERSION.to_be_bytes());
    output.write_all(&header)?;
    hash.update(&header);
    let mut key: Option<(String, String, String, i64)> = None;
    let mut emitted = 0u64;
    loop {
        context.verify_input()?;
        let params = match &key {
            None => vec![
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                PAGE_SIZE.into(),
            ],
            Some((h, a, e, i)) => vec![
                h.clone().into(),
                a.clone().into(),
                e.clone().into(),
                (*i).into(),
                PAGE_SIZE.into(),
            ],
        };
        let predicate = if key.is_some() {
            "(host,agent,external,idx)>(?1,?2,?3,?4)"
        } else {
            "1"
        };
        let sql = format!(
            "SELECT host,agent,external,idx,payload FROM message_rows WHERE {predicate} ORDER BY host,agent,external,idx LIMIT ?5"
        );
        let rows = spool.query_all_map(&sql, &params, |r| {
            Ok((
                r.get_typed::<String>(0)?,
                r.get_typed::<String>(1)?,
                r.get_typed::<String>(2)?,
                r.get_typed::<i64>(3)?,
                r.get_typed::<Vec<u8>>(4)?,
            ))
        })?;
        if rows.is_empty() {
            break;
        }
        for (h, a, e, i, payload) in rows {
            let length = (payload.len() as u64).to_be_bytes();
            output.write_all(&length)?;
            output.write_all(&payload)?;
            hash.update(length);
            hash.update(&payload);
            key = Some((h, a, e, i));
            emitted += 1;
        }
    }
    if emitted != message_count {
        bail!("INVENTORY_COUNT_MISMATCH");
    }
    let tail = message_count.to_be_bytes();
    output.write_all(&tail)?;
    hash.update(tail);
    output.as_file().sync_all()?;
    context.verify_input()?;
    validate_private_run_root(context.run_root())?;
    let rows_path = context.run_root().join("message-text-v3.bin");
    spool.close_with_checkpoint()?;
    output.persist_noclobber(&rows_path)?;
    Ok(MessageInventory {
        sha256: hex::encode(hash.finalize()),
        message_count,
        conversation_count,
        rows_path,
    })
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    pub(crate) fn fixture(change: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        let run = root.path().join("run");
        fs::create_dir_all(input.join("doctor/locks")).unwrap();
        fs::File::create(input.join("doctor/locks/doctor-repair.lock")).unwrap();
        fs::create_dir(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let db = input.join("agent_search.db");
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        writer.execute_batch("PRAGMA user_version=8;
            CREATE TABLE agents(id INTEGER PRIMARY KEY,slug TEXT);
            CREATE TABLE workspaces(id INTEGER PRIMARY KEY,path TEXT);
            CREATE TABLE sources(id TEXT PRIMARY KEY,kind TEXT);
            CREATE TABLE conversations(id INTEGER PRIMARY KEY,identity_host TEXT,agent_id INTEGER,external_id TEXT,metadata_json TEXT,metadata_bin BLOB,source_id TEXT,origin_host TEXT,title TEXT,workspace_id INTEGER,source_path TEXT,started_at INTEGER);
            CREATE TABLE messages(id INTEGER PRIMARY KEY,conversation_id INTEGER,idx INTEGER,role TEXT,created_at INTEGER,content TEXT,excluded BLOB);
            CREATE TABLE lex_docs(doc_id INTEGER PRIMARY KEY,content TEXT,title TEXT,agent TEXT,workspace TEXT,source_path TEXT);
            INSERT INTO agents VALUES(1,'codex');
            INSERT INTO sources VALUES('local','local');
            INSERT INTO workspaces VALUES(1,'workspace');
            INSERT INTO conversations VALUES(1,'local',1,'session',NULL,NULL,'local',NULL,'title',1,'synthetic.jsonl',10);
            INSERT INTO messages VALUES(1,1,0,'user',20,'Investigate retrieval ranking and compare the evidence from both runs.',NULL);
            INSERT INTO lex_docs SELECT 1,content,'title','codex','workspace','synthetic.jsonl' FROM messages;").unwrap();
        writer.execute_batch(change).unwrap();
        writer
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .unwrap();
        drop(writer);
        (root, db, run)
    }

    fn export(change: &str) -> Result<MessageInventory> {
        let (_root, db, run) = fixture(change);
        let context = RegressionIoContext::open(&db, &run)?;
        export_messages(&context)
    }

    #[test]
    fn streams_stored_messages_to_private_recomputable_inventory() {
        let (_root, db, run) = fixture("");
        let before = fs::read(&db).unwrap();
        let context = RegressionIoContext::open(&db, &run).unwrap();
        let inventory = export_messages(&context).unwrap();
        assert_eq!(inventory.message_count, 1);
        assert_eq!(inventory.conversation_count, 1);
        let bytes = fs::read(&inventory.rows_path).unwrap();
        assert_eq!(inventory.sha256, hex::encode(Sha256::digest(&bytes)));
        assert_eq!(&bytes[..8], &15u64.to_be_bytes());
        assert_eq!(&bytes[8..23], b"message-text-v3");
        assert_eq!(&bytes[bytes.len() - 8..], &1u64.to_be_bytes());
        assert!(!bytes.windows(11).any(|s| s == b"Investigate"));
        assert_eq!(
            fs::metadata(&inventory.rows_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(fs::read(&db).unwrap(), before);
        assert!(!db.with_file_name("agent_search.db-wal").exists());
    }

    #[test]
    fn inventory_readonly_child() -> Result<()> {
        let Some(database) = std::env::var_os("CASS_INVENTORY_CHILD_DB") else {
            return Ok(());
        };
        let run = std::env::var_os("CASS_INVENTORY_CHILD_RUN").unwrap();
        let context =
            RegressionIoContext::open(std::path::Path::new(&database), std::path::Path::new(&run))?;
        let inventory = export_messages(&context)?;
        assert_eq!(inventory.message_count, 1);
        println!("MESSAGE_INVENTORY_READONLY_VERIFIED");
        Ok(())
    }

    #[test]
    fn exports_inventory_with_os_readonly_input() {
        let (_root, db, run) = fixture("");
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        writer
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(writer);
        let input = db.parent().unwrap();
        let before: Vec<_> = fs::read_dir(input)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        let bytes = fs::read(&db).unwrap();
        let output = std::process::Command::new("/usr/bin/bwrap")
            .args(["--ro-bind", "/", "/", "--bind"])
            .arg(&run)
            .arg(&run)
            .args(["--unshare-net", "--proc", "/proc", "--dev", "/dev"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "search::regression_inventory::tests::inventory_readonly_child",
                "--nocapture",
            ])
            .env("CASS_INVENTORY_CHILD_DB", &db)
            .env("CASS_INVENTORY_CHILD_RUN", &run)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("MESSAGE_INVENTORY_READONLY_VERIFIED")
        );
        assert_eq!(fs::read(&db).unwrap(), bytes);
        let after: Vec<_> = fs::read_dir(input)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(before, after);
    }

    #[test]
    fn stable_message_digest_survives_raw_id_reassignment() {
        let original = export("").unwrap();
        let changed=export("UPDATE conversations SET id=40; UPDATE messages SET id=100,conversation_id=40; UPDATE lex_docs SET doc_id=100;").unwrap();
        assert_eq!(original.sha256, changed.sha256);
    }

    #[test]
    fn metadata_and_projection_changes_modify_message_identity() {
        let original = export("").unwrap().sha256;
        for change in [
            "UPDATE messages SET created_at=21;",
            "UPDATE conversations SET started_at=11;",
            "UPDATE conversations SET origin_host='other';",
            "UPDATE sources SET kind='ssh';",
            "UPDATE conversations SET source_path='moved.jsonl'; UPDATE lex_docs SET source_path='moved.jsonl';",
            "UPDATE workspaces SET path='new-workspace'; UPDATE lex_docs SET workspace='new-workspace';",
            "UPDATE conversations SET title='new-title'; UPDATE lex_docs SET title='new-title';",
            "UPDATE messages SET idx=2;",
            "UPDATE conversations SET external_id='other-session';",
            "UPDATE messages SET content=content||' Revised.'; UPDATE lex_docs SET content=content||' Revised.';",
        ] {
            assert_ne!(original, export(change).unwrap().sha256, "{change}");
        }
    }

    #[test]
    fn refuses_missing_duplicate_and_orphan_keys() {
        for (change, rejection) in [
            (
                "UPDATE conversations SET external_id=NULL;",
                "MISSING_STABLE_CONVERSATION_KEY",
            ),
            (
                "INSERT INTO conversations SELECT 2,identity_host,agent_id,external_id,metadata_json,metadata_bin,source_id,origin_host,title,workspace_id,source_path,started_at FROM conversations;",
                "DUPLICATE_STABLE_CONVERSATION_KEY",
            ),
            (
                "INSERT INTO messages SELECT 2,conversation_id,idx,role,created_at,content,excluded FROM messages; INSERT INTO lex_docs SELECT 2,content,title,agent,workspace,source_path FROM lex_docs;",
                "DUPLICATE_STABLE_MESSAGE_KEY",
            ),
            ("UPDATE messages SET conversation_id=999;", "ORPHAN_MESSAGE"),
            (
                "INSERT INTO lex_docs SELECT 999,content,title,agent,workspace,source_path FROM lex_docs;",
                "ORPHAN_LEXICAL_DOCUMENT",
            ),
            (
                "UPDATE conversations SET workspace_id=999;",
                "ORPHAN_WORKSPACE",
            ),
            (
                "UPDATE conversations SET source_id='missing';",
                "ORPHAN_SOURCE",
            ),
        ] {
            let error = export(change).err().expect("must reject");
            assert!(
                format!("{error:#}").contains(rejection),
                "{change}: {error:#}"
            );
        }
    }

    #[test]
    fn rejects_wrong_lexical_membership_and_each_projection_column() {
        assert!(
            export("DELETE FROM lex_docs;")
                .err()
                .unwrap()
                .to_string()
                .contains("MEMBERSHIP")
        );
        for column in ["content", "title", "agent", "workspace", "source_path"] {
            let error = export(&format!("UPDATE lex_docs SET {column}='wrong';"))
                .err()
                .unwrap();
            assert!(error.to_string().contains("LEXICAL_PROJECTION_MISMATCH"));
        }
        assert!(
            export("UPDATE messages SET role='reasoning';")
                .err()
                .unwrap()
                .to_string()
                .contains("MEMBERSHIP")
        );
    }

    #[test]
    fn binary_identity_carrier_has_priority_and_corruption_does_not_fall_back() {
        let (_root, db, run) = fixture(
            "UPDATE conversations SET metadata_json='{\"cass\":{\"identity\":{\"identity_host\":\"other\"}}}';",
        );
        let writer = Conn::open_writable(&db, Profile::Production).unwrap();
        let binary =
            rmp_serde::to_vec(&serde_json::json!({"cass":{"identity":{"identity_host":"local"}}}))
                .unwrap();
        writer
            .execute("UPDATE conversations SET metadata_bin=?1", &params![binary])
            .unwrap();
        writer
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .unwrap();
        drop(writer);
        let context = RegressionIoContext::open(&db, &run).unwrap();
        export_messages(&context).unwrap();
        assert!(
            export("UPDATE conversations SET metadata_bin=X'C1';")
                .err()
                .unwrap()
                .to_string()
                .contains("IDENTITY_CARRIER_DECODE_FAILED")
        );
        assert!(
            export("UPDATE conversations SET identity_host='other';")
                .err()
                .unwrap()
                .to_string()
                .contains("IDENTITY_CARRIER_MISMATCH")
        );
    }

    #[test]
    fn retains_duplicates_and_streams_across_source_and_stable_key_pages() {
        let change = "WITH RECURSIVE numbers(n) AS(SELECT 2 UNION ALL SELECT n+1 FROM numbers WHERE n<260) INSERT INTO messages SELECT n,1,261-n,'user',20,'Investigate retrieval ranking and compare the evidence from both runs.',NULL FROM numbers; INSERT INTO lex_docs SELECT id,content,'title','codex','workspace','synthetic.jsonl' FROM messages WHERE id>1;";
        let inventory = export(change).unwrap();
        assert_eq!(inventory.message_count, 260);
        assert_ne!(inventory.sha256, export("").unwrap().sha256);
    }
}
