//! Frozen-input admission and per-run lexical statistics for retrieval regression.
//! Ordinary search keeps its existing connection and cache policies.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::SystemTime;

use anyhow::{Context, Result, bail};

use crate::storage::api::Conn;
use crate::storage::sqlite::{SendFrankenConnection, ensure_readonly_schema_current};

use super::query::{LexicalCorpusStats, SearchClient};

#[derive(Clone, Debug, PartialEq, Eq)]
struct InputStamp {
    size: u64,
    modified: SystemTime,
    canonical_path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

impl InputStamp {
    fn capture(path: &Path) -> Result<Self> {
        reject_symlink_components(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            bail!("regression_input_not_regular");
        }
        Ok(Self {
            size: metadata.len(),
            modified: metadata.modified()?,
            canonical_path: path.canonicalize()?,
            #[cfg(unix)]
            device: {
                use std::os::unix::fs::MetadataExt;
                metadata.dev()
            },
            #[cfg(unix)]
            inode: {
                use std::os::unix::fs::MetadataExt;
                metadata.ino()
            },
        })
    }
}

/// The connection is dropped before the shared maintenance lock.
/// This stamp is an I/O guard, not a strong corpus binding.
pub(crate) struct RegressionIoContext {
    connection: Mutex<SendFrankenConnection>,
    statistics: Mutex<Option<LexicalCorpusStats>>,
    database: PathBuf,
    input_stamp: InputStamp,
    run_root: PathBuf,
    _maintenance_lock: File,
}

impl RegressionIoContext {
    pub(crate) fn open(database: &Path, run_root: &Path) -> Result<Self> {
        if database.file_name().and_then(|s| s.to_str()) != Some("agent_search.db") {
            bail!("regression_input_name");
        }
        validate_run_root(run_root)?;
        if run_root.starts_with(database.parent().context("regression_input_parent")?) {
            bail!("regression_output_inside_input");
        }
        let input_stamp = InputStamp::capture(database)?;
        ensure_no_wal(database)?;

        // Validate the format before opening; the frozen connection avoids
        // WAL sidecar creation. A nonempty WAL is never ignored.
        let mut header = [0; 20];
        File::open(database)?.read_exact(&mut header)?;
        if &header[..16] != b"SQLite format 3\0" {
            bail!("regression_input_format");
        }

        let lock_path = database
            .parent()
            .context("regression_input_parent")?
            .join("doctor/locks/doctor-repair.lock");
        reject_symlink_components(&lock_path).context("regression_maintenance_lock_unavailable")?;
        if !fs::symlink_metadata(&lock_path)?.is_file() {
            bail!("regression_maintenance_lock_not_regular");
        }
        let maintenance_lock =
            File::open(&lock_path).context("regression_maintenance_lock_unavailable")?;
        fs2::FileExt::try_lock_shared(&maintenance_lock)
            .context("regression_maintenance_lock_busy")?;
        verify_lock_identity(&maintenance_lock, &lock_path)?;
        ensure_no_wal(database)?;
        if InputStamp::capture(database)? != input_stamp {
            bail!("regression_input_changed");
        }
        let connection = Conn::open_frozen_read(database)?;
        ensure_readonly_schema_current(&connection)?;
        if InputStamp::capture(database)? != input_stamp {
            bail!("regression_input_changed");
        }
        ensure_no_wal(database)?;
        Ok(Self {
            connection: Mutex::new(SendFrankenConnection::new(connection)),
            statistics: Mutex::new(None),
            database: database.to_path_buf(),
            input_stamp,
            run_root: run_root.to_path_buf(),
            _maintenance_lock: maintenance_lock,
        })
    }

    pub(crate) fn connection(&self) -> Result<MutexGuard<'_, SendFrankenConnection>> {
        self.verify_input()?;
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("regression_connection_poisoned"))
    }

    pub(crate) fn lexical_statistics(&self) -> Result<LexicalCorpusStats> {
        self.verify_input()?;
        let connection = self.connection()?;
        let mut cache = self
            .statistics
            .lock()
            .map_err(|_| anyhow::anyhow!("regression_statistics_poisoned"))?;
        if let Some(stats) = *cache {
            return Ok(stats);
        }
        let stats = SearchClient::compute_lexical_corpus_stats(&connection)?;
        self.verify_input()?;
        *cache = Some(stats);
        Ok(stats)
    }

    pub(crate) fn run_root(&self) -> &Path {
        &self.run_root
    }

    pub(crate) fn verify_input(&self) -> Result<()> {
        verify_lock_identity(
            &self._maintenance_lock,
            &self
                .database
                .parent()
                .context("regression_input_parent")?
                .join("doctor/locks/doctor-repair.lock"),
        )?;
        ensure_no_wal(&self.database)?;
        if InputStamp::capture(&self.database)? != self.input_stamp {
            bail!("regression_input_changed");
        }
        Ok(())
    }
}

fn verify_lock_identity(file: &File, path: &Path) -> Result<()> {
    reject_symlink_components(path).context("regression_maintenance_lock_changed")?;
    let current = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    if !current.is_file() {
        bail!("regression_maintenance_lock_changed");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (current.dev(), current.ino()) != (opened.dev(), opened.ino()) {
            bail!("regression_maintenance_lock_changed");
        }
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::storage::api::Profile;
    use std::os::unix::fs::PermissionsExt;

    fn fixture(content: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        let run = root.path().join("run");
        fs::create_dir(&input).unwrap();
        fs::create_dir(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(input.join("doctor/locks")).unwrap();
        File::create(input.join("doctor/locks/doctor-repair.lock")).unwrap();
        let db = input.join("agent_search.db");
        let writer =
            crate::storage::testing::open_writable_for_tests(&db, Profile::Production).unwrap();
        writer.execute_batch("PRAGMA user_version=8; CREATE TABLE lex_docs(doc_id INTEGER PRIMARY KEY, content TEXT, title TEXT); PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;").unwrap();
        writer
            .execute(
                "INSERT INTO lex_docs VALUES(1, ?1, 'alpha')",
                &[content.into()],
            )
            .unwrap();
        drop(writer);
        (root, db, run)
    }

    #[test]
    fn reads_without_input_writes_and_holds_existing_shared_lock() {
        let (_root, db, run) = fixture("one two three");
        let before = fs::read(&db).unwrap();
        let context = RegressionIoContext::open(&db, &run).unwrap();
        let stats = context.lexical_statistics().unwrap();
        assert_eq!(stats.total_docs, 1);
        assert_eq!(stats.avgdl.content, 3.0);
        assert_eq!(context.run_root(), run);
        assert_eq!(fs::read(&db).unwrap(), before);
        let writer_lock = File::options()
            .read(true)
            .write(true)
            .open(db.parent().unwrap().join("doctor/locks/doctor-repair.lock"))
            .unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&writer_lock).is_err());
        drop(context);
        fs2::FileExt::try_lock_exclusive(&writer_lock).unwrap();
    }

    #[test]
    fn each_context_ignores_poisoned_input_stats_cache() {
        let (_a, a, arun) = fixture("one");
        let (_b, b, brun) = fixture("one two three four");
        for db in [&a, &b] {
            fs::write(
                db.parent().unwrap().join(".lexical-avgdl-cache.json"),
                r#"{"total_docs":999,"avgdl_content":999,"avgdl_title":999}"#,
            )
            .unwrap();
        }
        let ac = RegressionIoContext::open(&a, &arun).unwrap();
        let bc = RegressionIoContext::open(&b, &brun).unwrap();
        assert_eq!(ac.lexical_statistics().unwrap().avgdl.content, 1.0);
        assert_eq!(bc.lexical_statistics().unwrap().avgdl.content, 4.0);
        assert_eq!(ac.lexical_statistics().unwrap().total_docs, 1);
    }

    #[test]
    fn refuses_missing_or_exclusive_maintenance_lock() {
        let (_root, db, run) = fixture("one");
        let path = db.parent().unwrap().join("doctor/locks/doctor-repair.lock");
        let lock = File::options().read(true).write(true).open(&path).unwrap();
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        assert!(RegressionIoContext::open(&db, &run).is_err());
        drop(lock);
        fs::remove_file(path).unwrap();
        assert!(RegressionIoContext::open(&db, &run).is_err());
    }

    #[test]
    fn rejects_wrong_schema_wal_and_nonprivate_output() {
        let (_root, db, run) = fixture("one");
        fs::set_permissions(&run, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(RegressionIoContext::open(&db, &run).is_err());
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let wal = db.with_file_name("agent_search.db-wal");
        fs::write(&wal, b"not finalized").unwrap();
        assert!(RegressionIoContext::open(&db, &run).is_err());
        fs::remove_file(wal).unwrap();
        let writer =
            crate::storage::testing::open_writable_for_tests(&db, Profile::Production).unwrap();
        writer.execute_batch("PRAGMA user_version=7; PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;").unwrap();
        drop(writer);
        assert!(RegressionIoContext::open(&db, &run).is_err());
    }

    #[test]
    fn rejects_symlink_and_replaced_maintenance_lock() {
        use std::os::unix::fs::symlink;
        let (_root, db, run) = fixture("one");
        let path = db.parent().unwrap().join("doctor/locks/doctor-repair.lock");
        let context = RegressionIoContext::open(&db, &run).unwrap();
        fs::rename(&path, path.with_extension("old")).unwrap();
        File::create(&path).unwrap();
        assert!(context.verify_input().is_err());
        drop(context);
        fs::remove_file(&path).unwrap();
        symlink(path.with_extension("old"), &path).unwrap();
        assert!(RegressionIoContext::open(&db, &run).is_err());
    }

    #[test]
    fn readonly_mount_child() {
        let Some(db) = std::env::var_os("CASS_REGRESSION_IO_CHILD_DB") else {
            return;
        };
        let run = std::env::var_os("CASS_REGRESSION_IO_CHILD_RUN").unwrap();
        let context = RegressionIoContext::open(Path::new(&db), Path::new(&run)).unwrap();
        assert_eq!(context.lexical_statistics().unwrap().total_docs, 1);
        assert!(
            context
                .connection()
                .unwrap()
                .execute("INSERT INTO lex_docs VALUES(2, 'write', 'blocked')", &[])
                .is_err()
        );
        println!("REGRESSION_READONLY_CONTEXT_VERIFIED");
    }

    #[test]
    fn constructs_and_queries_on_os_readonly_input() {
        let (root, db, run) = fixture("one");
        let writer =
            crate::storage::testing::open_writable_for_tests(&db, Profile::Production).unwrap();
        writer
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(writer);
        let input = db.parent().unwrap();
        let before_db = fs::read(&db).unwrap();
        let before_lock = fs::read(input.join("doctor/locks/doctor-repair.lock")).unwrap();
        let output = std::process::Command::new("/usr/bin/bwrap")
            .args(["--ro-bind", "/", "/", "--bind"])
            .arg(root.path())
            .arg(root.path())
            .arg("--ro-bind")
            .arg(input)
            .arg(input)
            .args(["--unshare-net", "--proc", "/proc", "--dev", "/dev"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "search::regression_io::tests::readonly_mount_child",
                "--nocapture",
            ])
            .env("CASS_REGRESSION_IO_CHILD_DB", &db)
            .env("CASS_REGRESSION_IO_CHILD_RUN", &run)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("REGRESSION_READONLY_CONTEXT_VERIFIED")
        );
        assert_eq!(fs::read(&db).unwrap(), before_db);
        assert_eq!(
            fs::read(input.join("doctor/locks/doctor-repair.lock")).unwrap(),
            before_lock
        );
        assert!(!db.with_file_name("agent_search.db-wal").exists());
        assert!(!db.with_file_name("agent_search.db-shm").exists());
    }

    #[test]
    fn frozen_wal_format_without_sidecars_stays_unmodified() {
        let (_root, db, run) = fixture("one two");
        let writer =
            crate::storage::testing::open_writable_for_tests(&db, Profile::Production).unwrap();
        writer
            .execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
        drop(writer);
        let before = fs::read(&db).unwrap();
        assert_eq!(before[18], 2);
        assert!(!db.with_file_name("agent_search.db-wal").exists());
        let context = RegressionIoContext::open(&db, &run).unwrap();
        assert_eq!(context.lexical_statistics().unwrap().avgdl.content, 2.0);
        drop(context);
        assert_eq!(fs::read(&db).unwrap(), before);
        assert!(!db.with_file_name("agent_search.db-wal").exists());
        assert!(!db.with_file_name("agent_search.db-shm").exists());
    }
}

fn ensure_no_wal(database: &Path) -> Result<()> {
    let wal = database.with_file_name("agent_search.db-wal");
    match fs::symlink_metadata(&wal) {
        Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() || meta.len() != 0 => {
            bail!("regression_wal_not_finalized")
        }
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("regression_path_not_absolute");
    }
    let mut prefix = PathBuf::new();
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            bail!("regression_path_escape");
        }
        prefix.push(component);
        if fs::symlink_metadata(&prefix)?.file_type().is_symlink() {
            bail!("regression_path_symlink");
        }
    }
    Ok(())
}

fn validate_run_root(path: &Path) -> Result<()> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        bail!("regression_run_root_not_directory");
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o777 != 0o700
            || metadata.uid() != fs::metadata("/proc/self")?.uid()
        {
            bail!("regression_run_root_not_private");
        }
    }
    #[cfg(not(target_os = "linux"))]
    bail!("regression_platform_not_verified");
    if fs::read_dir(path)?.next().is_some() {
        bail!("regression_run_root_not_empty");
    }
    Ok(())
}
