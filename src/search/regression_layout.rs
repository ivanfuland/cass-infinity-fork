//! Ordered stable identities and raw ID layout are distinct experiment inputs.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::storage::api::{Conn, Row, StorageError, Value};

use super::canonicalize::CANONICALIZE_PIPELINE_VERSION;
use super::chunking::CHUNKING_POLICY_VERSION;
use super::regression_inventory::string;
use super::regression_io::{RegressionIoContext, validate_private_run_root};

const PAGE_SIZE: i64 = 128;

pub(crate) struct OrderingInventory {
    pub(crate) order_sha256: String,
    pub(crate) layout_sha256: String,
    pub(crate) total_elements: u64,
    pub(crate) order_path: PathBuf,
    pub(crate) layout_path: PathBuf,
}

#[derive(Clone, Copy)]
enum Entity {
    Conversation,
    Message,
    Lexical,
    Chunk,
}

struct EntitySql {
    table: &'static str,
    id: &'static str,
    stable_columns: &'static str,
    select: &'static str,
    order_name: &'static str,
    layout_name: &'static str,
    arity: usize,
}

impl Entity {
    fn sql(self) -> EntitySql {
        let (table, id, stable_columns, select, order_name, layout_name, arity) = match self {
            Self::Conversation => (
                "conversations",
                "cid",
                "host,agent,external",
                "host,agent,external,NULL,NULL,cid,NULL",
                "conversation-id-order",
                "conversation-map",
                3,
            ),
            Self::Message => (
                "message_rows",
                "mid",
                "host,agent,external,idx",
                "host,agent,external,idx,NULL,mid,cid",
                "message-id-order",
                "message-map",
                4,
            ),
            Self::Lexical => (
                "message_rows",
                "lexical",
                "host,agent,external,idx",
                "host,agent,external,idx,NULL,lexical,NULL",
                "lex-doc-order",
                "lex-map",
                4,
            ),
            Self::Chunk => (
                "chunk_rows",
                "chunk_id",
                "host,agent,external,idx,chunk_idx",
                "host,agent,external,idx,chunk_idx,chunk_id,conversation_id",
                "chunk-id-order",
                "chunk-map",
                5,
            ),
        };
        EntitySql {
            table,
            id,
            stable_columns,
            select,
            order_name,
            layout_name,
            arity,
        }
    }
}

struct MappedRow {
    host: String,
    agent: String,
    external: String,
    idx: Option<i64>,
    chunk: Option<i64>,
    id: i64,
    conversation: Option<i64>,
}
impl MappedRow {
    fn read(row: &Row) -> Result<Self, StorageError> {
        Ok(Self {
            host: row.get_typed(0)?,
            agent: row.get_typed(1)?,
            external: row.get_typed(2)?,
            idx: row.get_typed(3)?,
            chunk: row.get_typed(4)?,
            id: row.get_typed(5)?,
            conversation: row.get_typed(6)?,
        })
    }
    fn stable(&self, entity: Entity) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        string(&mut bytes, &self.host);
        string(&mut bytes, &self.agent);
        string(&mut bytes, &self.external);
        if !matches!(entity, Entity::Conversation) {
            bytes.extend_from_slice(
                &self
                    .idx
                    .context("MISSING_STABLE_MESSAGE_KEY")?
                    .to_be_bytes(),
            );
        }
        if matches!(entity, Entity::Chunk) {
            bytes.extend_from_slice(
                &self
                    .chunk
                    .context("MISSING_STABLE_CHUNK_KEY")?
                    .to_be_bytes(),
            );
        }
        Ok(bytes)
    }
    fn encode(&self, entity: Entity, layout: bool) -> Result<Vec<u8>> {
        let mut bytes = self.stable(entity)?;
        if layout {
            bytes.extend_from_slice(&self.id.to_be_bytes());
            if matches!(entity, Entity::Message) {
                bytes
                    .extend_from_slice(&self.conversation.context("ORPHAN_MESSAGE")?.to_be_bytes());
            }
            if matches!(entity, Entity::Chunk) {
                if self.id < 0 {
                    bail!("NEGATIVE_CHUNK_ID");
                }
                bytes.push((self.id % 8) as u8);
            }
        }
        Ok(bytes)
    }
    fn cursor(&self, entity: Entity, layout: bool) -> Result<Vec<Value>> {
        let mut values = if layout {
            vec![
                self.host.clone().into(),
                self.agent.clone().into(),
                self.external.clone().into(),
            ]
        } else {
            vec![self.id.into()]
        };
        if layout && !matches!(entity, Entity::Conversation) {
            values.push(self.idx.context("MISSING_STABLE_MESSAGE_KEY")?.into());
        }
        if layout && matches!(entity, Entity::Chunk) {
            values.push(self.chunk.context("MISSING_STABLE_CHUNK_KEY")?.into());
        }
        Ok(values)
    }
}

fn append_bytes(file: &mut File, hash: &mut Sha256, bytes: &[u8]) -> Result<()> {
    file.write_all(bytes)?;
    hash.update(bytes);
    Ok(())
}

fn append_sequence(
    context: &RegressionIoContext,
    conn: &Conn,
    entity: Entity,
    layout: bool,
    file: &mut File,
    hash: &mut Sha256,
) -> Result<u64> {
    let descriptor = entity.sql();
    let table = descriptor.table;
    let filter = if matches!(entity, Entity::Lexical) {
        "lexical IS NOT NULL"
    } else {
        "1"
    };
    let count: i64 = conn.query_row_map(
        &format!("SELECT COUNT(*) FROM {table} WHERE {filter}"),
        &[],
        |r| r.get_typed(0),
    )?;
    let count = u64::try_from(count)?;
    let mut header = Vec::new();
    string(
        &mut header,
        if layout {
            descriptor.layout_name
        } else {
            descriptor.order_name
        },
    );
    header.extend_from_slice(&count.to_be_bytes());
    append_bytes(file, hash, &header)?;
    let columns = if layout {
        descriptor.stable_columns
    } else {
        descriptor.id
    };
    let select = descriptor.select;
    let arity = if layout { descriptor.arity } else { 1 };
    let placeholders = (1..=arity)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(",");
    let mut cursor: Option<Vec<Value>> = None;
    let mut emitted = 0u64;
    loop {
        context.verify_input()?;
        let predicate = if cursor.is_some() {
            format!("({columns})>({placeholders})")
        } else {
            "1".into()
        };
        let mut params = cursor.clone().unwrap_or_else(|| vec![Value::Null; arity]);
        params.push(PAGE_SIZE.into());
        let sql = format!(
            "SELECT {select} FROM {table} WHERE {filter} AND {predicate} ORDER BY {columns} LIMIT ?{}",
            arity + 1
        );
        let rows = conn.query_all_map(&sql, &params, MappedRow::read)?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            let payload = row.encode(entity, layout)?;
            append_bytes(file, hash, &(payload.len() as u64).to_be_bytes())?;
            append_bytes(file, hash, &payload)?;
            cursor = Some(row.cursor(entity, layout)?);
            emitted += 1;
        }
    }
    if emitted != count {
        bail!("ORDERING_INVENTORY_COUNT_MISMATCH");
    }
    Ok(count)
}

fn open_private_spool(path: &Path) -> Result<Conn> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("INVENTORY_SPOOL_NOT_REGULAR");
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != std::fs::metadata("/proc/self")?.uid()
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            bail!("INVENTORY_SPOOL_NOT_PRIVATE");
        }
    }
    Conn::open_frozen_read(path).map_err(Into::into)
}

/// Called only after both message and active-chunk inventory exports succeed.
pub(crate) fn export_order_and_layout(context: &RegressionIoContext) -> Result<OrderingInventory> {
    context.verify_input()?;
    validate_private_run_root(context.run_root())?;
    let messages = open_private_spool(&context.run_root().join("message-inventory-spool.sqlite"))?;
    let chunks = open_private_spool(&context.run_root().join("chunk-inventory-spool.sqlite"))?;
    let mut order = tempfile::NamedTempFile::new_in(context.run_root())?;
    let mut layout = tempfile::NamedTempFile::new_in(context.run_root())?;
    let mut order_hash = Sha256::new();
    let mut layout_hash = Sha256::new();
    for (domain, file, hash) in [
        ("retrieval-order-v2", order.as_file_mut(), &mut order_hash),
        (
            "retrieval-layout-v1",
            layout.as_file_mut(),
            &mut layout_hash,
        ),
    ] {
        let mut header = Vec::new();
        string(&mut header, domain);
        header.extend_from_slice(&CANONICALIZE_PIPELINE_VERSION.to_be_bytes());
        header.extend_from_slice(&CHUNKING_POLICY_VERSION.to_be_bytes());
        append_bytes(file, hash, &header)?;
    }
    let mut total = 0u64;
    for entity in [
        Entity::Conversation,
        Entity::Message,
        Entity::Lexical,
        Entity::Chunk,
    ] {
        let conn = if matches!(entity, Entity::Chunk) {
            &chunks
        } else {
            &messages
        };
        let count = append_sequence(
            context,
            conn,
            entity,
            false,
            order.as_file_mut(),
            &mut order_hash,
        )?;
        let layout_count = append_sequence(
            context,
            conn,
            entity,
            true,
            layout.as_file_mut(),
            &mut layout_hash,
        )?;
        if count != layout_count {
            bail!("ORDERING_INVENTORY_COUNT_MISMATCH");
        }
        total = total
            .checked_add(count)
            .context("INVENTORY_COUNT_OVERFLOW")?;
    }
    for (file, hash) in [
        (order.as_file_mut(), &mut order_hash),
        (layout.as_file_mut(), &mut layout_hash),
    ] {
        append_bytes(file, hash, &total.to_be_bytes())?;
        file.sync_all()?;
    }
    context.verify_input()?;
    validate_private_run_root(context.run_root())?;
    let order_path = context.run_root().join("retrieval-order-v2.bin");
    let layout_path = context.run_root().join("retrieval-layout-v1.bin");
    order.persist_noclobber(&order_path)?;
    layout.persist_noclobber(&layout_path)?;
    Ok(OrderingInventory {
        order_sha256: hex::encode(order_hash.finalize()),
        layout_sha256: hex::encode(layout_hash.finalize()),
        total_elements: total,
        order_path,
        layout_path,
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::super::regression_chunks::export_chunks;
    use super::super::regression_inventory::export_messages;
    use super::*;

    fn fixture(change: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let (root, db, run) = super::super::regression_chunks::tests::fixture("", "");
        let writer = Conn::open_writable(&db, crate::storage::api::Profile::Production).unwrap();
        writer.execute_batch(change).unwrap();
        writer
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;")
            .unwrap();
        drop(writer);
        (root, db, run)
    }

    fn export(change: &str) -> Result<(String, String, OrderingInventory)> {
        let (_root, db, run) = fixture(change);
        let context = RegressionIoContext::open(&db, &run)?;
        let messages = export_messages(&context)?;
        let chunks = export_chunks(&context)?;
        Ok((
            messages.sha256,
            chunks.sha256,
            export_order_and_layout(&context)?,
        ))
    }

    #[test]
    fn emits_four_order_and_layout_sequences_with_independent_digests() {
        let (_root, db, run) = fixture("");
        let context = RegressionIoContext::open(&db, &run).unwrap();
        export_messages(&context).unwrap();
        export_chunks(&context).unwrap();
        let result = export_order_and_layout(&context).unwrap();
        assert_eq!(result.total_elements, 4);
        for (path, sha) in [
            (&result.order_path, &result.order_sha256),
            (&result.layout_path, &result.layout_sha256),
        ] {
            let bytes = std::fs::read(path).unwrap();
            assert_eq!(*sha, hex::encode(Sha256::digest(&bytes)));
            assert_eq!(&bytes[bytes.len() - 8..], &4u64.to_be_bytes());
        }
    }

    #[test]
    fn monotonic_raw_id_changes_preserve_text_and_order_but_change_layout() {
        let (m, c, original) = export("").unwrap();
        let(mm,cc,changed)=export("UPDATE conversations SET id=id+40; UPDATE messages SET id=id+100,conversation_id=conversation_id+40; UPDATE lex_docs SET doc_id=doc_id+100; UPDATE message_chunks SET chunk_id=chunk_id+10,message_id=message_id+100,conversation_id=conversation_id+40;").unwrap();
        assert_eq!(m, mm);
        assert_eq!(c, cc);
        assert_eq!(original.order_sha256, changed.order_sha256);
        assert_ne!(original.layout_sha256, changed.layout_sha256);
    }

    #[test]
    fn chunk_partition_changes_are_explicit_layout_changes() {
        let (_, _, original) = export("").unwrap();
        let (_, _, shift) = export("UPDATE message_chunks SET chunk_id=chunk_id+1;").unwrap();
        let (_, _, same_partition) =
            export("UPDATE message_chunks SET chunk_id=chunk_id+8;").unwrap();
        assert_eq!(original.order_sha256, shift.order_sha256);
        assert_ne!(original.layout_sha256, shift.layout_sha256);
        assert_ne!(original.layout_sha256, same_partition.layout_sha256);
        let row = MappedRow {
            host: "local".into(),
            agent: "codex".into(),
            external: "session".into(),
            idx: Some(0),
            chunk: Some(0),
            id: 10,
            conversation: Some(1),
        };
        let bytes = row.encode(Entity::Chunk, true).unwrap();
        assert_eq!(*bytes.last().unwrap(), 2);
    }

    const SECOND_MESSAGE: &str = "INSERT INTO messages SELECT 2,conversation_id,1,role,created_at,content,excluded FROM messages; INSERT INTO lex_docs SELECT 2,content,title,agent,workspace,source_path FROM lex_docs; INSERT INTO message_chunks SELECT 2,generation_id,2,conversation_id,chunk_idx,byte_start,byte_end,content_hash,embedding,norm FROM message_chunks;";

    #[test]
    fn nonmonotonic_message_id_swaps_change_relative_order_without_changing_text() {
        let (m, c, original) = export(SECOND_MESSAGE).unwrap();
        let change = format!(
            "{SECOND_MESSAGE} UPDATE messages SET id=-id; UPDATE messages SET id=3+id; UPDATE lex_docs SET doc_id=-doc_id; UPDATE lex_docs SET doc_id=3+doc_id; UPDATE message_chunks SET message_id=3-message_id;"
        );
        let (mm, cc, changed) = export(&change).unwrap();
        assert_eq!(m, mm);
        assert_eq!(c, cc);
        assert_ne!(original.order_sha256, changed.order_sha256);
        assert_ne!(original.layout_sha256, changed.layout_sha256);
    }

    #[test]
    fn conversation_id_swaps_change_the_conversation_order_sequence() {
        let second = "INSERT INTO conversations SELECT 2,identity_host,agent_id,'second-session',metadata_json,metadata_bin,source_id,origin_host,title,workspace_id,source_path,started_at FROM conversations;";
        let (m, c, original) = export(second).unwrap();
        let change = format!(
            "{second} UPDATE conversations SET id=-id; UPDATE conversations SET id=3+id; UPDATE messages SET conversation_id=3-conversation_id; UPDATE message_chunks SET conversation_id=3-conversation_id;"
        );
        let (mm, cc, changed) = export(&change).unwrap();
        assert_eq!(m, mm);
        assert_eq!(c, cc);
        assert_ne!(original.order_sha256, changed.order_sha256);
    }

    #[test]
    fn layout_inventory_readonly_child() -> Result<()> {
        let Some(db) = std::env::var_os("CASS_LAYOUT_INVENTORY_DB") else {
            return Ok(());
        };
        let run = std::env::var_os("CASS_LAYOUT_INVENTORY_RUN").unwrap();
        let context = RegressionIoContext::open(Path::new(&db), Path::new(&run))?;
        export_messages(&context)?;
        export_chunks(&context)?;
        assert_eq!(export_order_and_layout(&context)?.total_elements, 4);
        println!("ALL_INVENTORY_DOMAINS_READONLY_VERIFIED");
        Ok(())
    }

    #[test]
    fn all_inventory_domains_export_on_os_readonly_input() {
        let (_root, db, run) = fixture("");
        let before = std::fs::read(&db).unwrap();
        let output = std::process::Command::new("/usr/bin/bwrap")
            .args(["--ro-bind", "/", "/", "--bind"])
            .arg(&run)
            .arg(&run)
            .args(["--unshare-net", "--proc", "/proc", "--dev", "/dev"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "search::regression_layout::tests::layout_inventory_readonly_child",
                "--nocapture",
            ])
            .env("CASS_LAYOUT_INVENTORY_DB", &db)
            .env("CASS_LAYOUT_INVENTORY_RUN", &run)
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
                .contains("ALL_INVENTORY_DOMAINS_READONLY_VERIFIED")
        );
        assert_eq!(std::fs::read(&db).unwrap(), before);
    }
}
