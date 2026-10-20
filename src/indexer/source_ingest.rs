//! SRC05B-07: the formal single-input safe-ingest vertical slice.
//!
//! One sealed input (a Claude or Codex session file already captured into the
//! raw mirror) travels the whole formal path here: the fixed safety config is
//! loaded and verified, the profile identity is assembled by one factory, a
//! CASS-side verifier independently frames the sealed bytes, the pinned FAD
//! connector projects records and claims by opening the same sealed locator,
//! the per-record lossless pass applies exclusion and redaction, and finally
//! one transaction stages the records, installs the links, activates the input
//! and writes the receipt.
//!
//! What FAD and the verifier share is the **sealed identity** — the locator,
//! its digest and length, and the expected manifest — not one operating-system
//! file handle. The pinned interface opens `sealed_locator` itself, so the
//! path is checked to still be the same blob after the read rather than
//! claimed to be the same descriptor.
//!
//! Two passes, on purpose:
//!
//! - pass 1 keeps only in-memory structure (record locators, claims,
//!   conversations) and never writes source text anywhere;
//! - pass 2 re-reads each record through the sealed handle and performs the
//!   lossless copy/redaction work that produces the safe values.
//!
//! The module is deliberately independent of the legacy `Batch` transport: an
//! input is one unit of work and may not be split into several independent
//! conversations commits.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufReader, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use franken_agent_detection as fad;

use crate::storage::source_facts::{
    self, Sha256Digest, SourceFormat, SourceInstallError, SourceInputDeclaration, SourceSafetyConfig,
};

/// The pinned franken_agent_detection revision this build consumed. Part of the
/// normalizer identity: a different pin is a different projection of the same
/// bytes, so it must change the profile.
pub(crate) const FAD_PIN: &str = "61f975f3b56f8dabc4ecbe1dae4102c1ea6b16e5";

/// The fixed safety-config copy's own epoch. Constraint 4: this epoch covers
/// the lossless-copy cleanup and key-collision semantics, which the redaction
/// regex fingerprint alone does not.
pub(crate) const SOURCE_EXCLUSION_EPOCH: &str = "cass-source-exclusion/1";

/// The safety contract's domain tag.
pub(crate) const SOURCE_SAFETY_CONTRACT: &str = "cass.source-safety/1";

/// The normalizer identity's domain tag.
pub(crate) const SOURCE_NORMALIZER_DOMAIN: &str = "cass.source-normalizer/1";

/// The mapping identity's domain tag.
///
/// `/2` is the native-document framing epoch. Revision `/1` framed every
/// discovered file as JSONL, so a whole-document input and a line-oriented one
/// could produce source facts at different record boundaries from the same
/// bytes. The domain is part of the normalizer identity, so the upgrade keeps
/// both generations: every `/1` record, link, receipt and mirror stays exactly
/// as it was, and each source re-scans once under the new identity.
pub(crate) const SOURCE_MAPPING_DOMAIN: &str = "cass-source-mapping/2";

/// Everything that can stop this path before a source fact is written.
///
/// The variants name the *stage*, because the difference matters to a caller:
/// a configuration error must not be retried, while a transient storage error
/// may be.
#[derive(Debug)]
pub(crate) enum SourceIngestError {
    /// The fixed safety configuration could not be loaded or is not usable.
    Config { detail: String },
    /// A capture could not be verified or the sealed bytes moved under us.
    Capture { detail: String },
    /// The sealed input's own declared/measured facts disagree.
    Verify(SourceInstallError),
    /// The pinned connector refused to read the sealed input.
    Read { detail: String },
    /// The sink rejected a record, conversation or claim.
    Sink { detail: String },
    /// The transactional activation failed.
    Install(SourceInstallError),
    /// A storage helper outside the transaction returned its own error.
    Storage { detail: String },
}

impl std::fmt::Display for SourceIngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config { detail } => write!(f, "source safety configuration: {detail}"),
            Self::Capture { detail } => write!(f, "verified capture: {detail}"),
            Self::Verify(err) => write!(f, "sealed input verification: {err}"),
            Self::Read { detail } => write!(f, "sealed read: {detail}"),
            Self::Sink { detail } => write!(f, "source sink: {detail}"),
            Self::Install(err) => write!(f, "source installation: {err}"),
            Self::Storage { detail } => write!(f, "storage: {detail}"),
        }
    }
}

impl std::error::Error for SourceIngestError {}

impl From<SourceInstallError> for SourceIngestError {
    fn from(err: SourceInstallError) -> Self {
        Self::Install(err)
    }
}

/// Test-only hooks. Production never compiles this module.
///
/// Most hooks live in a `thread_local` slot, so two tests running in parallel
/// never overwrite each other's arming, and a guard clears this thread's slots
/// when it drops. The scripted fault context is the exception, and it is the
/// reason this module is not purely thread-local: a retry's attempts can run on
/// the dedicated writer thread, so the script is held in an `Arc` that the
/// dispatching thread hands to whichever thread runs the commit.
#[cfg(test)]
pub(crate) mod test_hooks {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    type AfterCapture = Box<dyn FnOnce(&Path) + 'static>;
    type AfterRead = Box<
        dyn FnMut(
            &mut Vec<crate::indexer::source_ingest::Pass1Record>,
            &mut crate::indexer::source_ingest::fad::SourceInputFinish,
        ),
    >;
    type BeforeBodyClear = Box<dyn FnMut(u64, &mut Vec<super::ExcludedBody>)>;

    /// The typed class a scripted fault fires.
    ///
    /// A class has to be exercised as its real typed error: a string that
    /// merely reads like "busy" would prove nothing about the retry, which is
    /// typed-only on purpose.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum TypedFault {
        Busy,
        /// The lock the retry whitelist excludes on purpose.
        Locked,
        OutOfMemory,
    }

    /// A script of typed faults, one per reached point, in order.
    ///
    /// The queue and the record of what fired are shared, not thread-local, so
    /// a script armed by the test thread is consumed in one order no matter
    /// which thread reaches the points -- and a spent entry stays spent when
    /// the next attempt runs on a fresh writer thread.
    #[derive(Debug, Default)]
    pub(crate) struct FaultScript {
        entries: VecDeque<(&'static str, TypedFault)>,
        fired: Vec<(&'static str, TypedFault, std::thread::ThreadId)>,
    }

    impl FaultScript {
        /// Every fault this script has really fired, in order, with the thread
        /// that reached it. The thread is the point: it is how a case shows
        /// the fault landed on the dedicated writer thread rather than on the
        /// thread that submitted the job.
        pub(crate) fn fired(&self) -> &[(&'static str, TypedFault, std::thread::ThreadId)] {
            &self.fired
        }
    }

    thread_local! {
        static AFTER_CAPTURE: RefCell<Option<AfterCapture>> = const { RefCell::new(None) };
        static AFTER_READ: RefCell<Option<AfterRead>> = const { RefCell::new(None) };
        static BEFORE_BODY_CLEAR: RefCell<Option<BeforeBodyClear>> = const { RefCell::new(None) };
        static FAIL_AT: RefCell<Option<&'static str>> = const { RefCell::new(None) };
        static FAIL_AT_NTH: RefCell<Option<(&'static str, usize)>> = const { RefCell::new(None) };
        static FAULT_SCRIPT: RefCell<Option<Arc<Mutex<FaultScript>>>> = const { RefCell::new(None) };
        static WRITER_MODE: RefCell<Option<bool>> = const { RefCell::new(None) };
        static HITS: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
    }

    /// Clears every hook this thread armed, when it goes out of scope.
    pub(crate) struct HookGuard;

    impl Drop for HookGuard {
        fn drop(&mut self) {
            clear_all();
        }
    }

    /// Restores the fault context this thread held before a scope installed
    /// another one, so a writer thread leaves as it arrived.
    pub(crate) struct FaultScopeGuard(Option<Arc<Mutex<FaultScript>>>);

    impl Drop for FaultScopeGuard {
        fn drop(&mut self) {
            let previous = self.0.take();
            FAULT_SCRIPT.with(|slot| *slot.borrow_mut() = previous);
        }
    }

    fn clear_all() {
        AFTER_CAPTURE.with(|slot| *slot.borrow_mut() = None);
        AFTER_READ.with(|slot| *slot.borrow_mut() = None);
        BEFORE_BODY_CLEAR.with(|slot| *slot.borrow_mut() = None);
        FAIL_AT.with(|slot| *slot.borrow_mut() = None);
        FAIL_AT_NTH.with(|slot| *slot.borrow_mut() = None);
        FAULT_SCRIPT.with(|slot| *slot.borrow_mut() = None);
        WRITER_MODE.with(|slot| *slot.borrow_mut() = None);
        HITS.with(|slot| slot.borrow_mut().clear());
    }

    /// How many times each named hook has fired on this thread.
    pub(crate) fn hits() -> Vec<&'static str> {
        HITS.with(|slot| slot.borrow().clone())
    }

    fn record_hit(name: &'static str) {
        HITS.with(|slot| slot.borrow_mut().push(name));
    }

    pub(crate) fn arm_after_capture(hook: impl FnOnce(&Path) + 'static) -> HookGuard {
        AFTER_CAPTURE.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        HookGuard
    }

    pub(crate) fn take_after_capture() -> Option<AfterCapture> {
        AFTER_CAPTURE.with(|slot| {
            let taken = slot.borrow_mut().take();
            if taken.is_some() {
                record_hit("after_capture");
            }
            taken
        })
    }

    pub(crate) fn arm_after_read(
        hook: impl FnMut(
                &mut Vec<crate::indexer::source_ingest::Pass1Record>,
                &mut crate::indexer::source_ingest::fad::SourceInputFinish,
            ) + 'static,
    ) -> HookGuard {
        AFTER_READ.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        HookGuard
    }

    pub(crate) fn take_after_read() -> Option<AfterRead> {
        AFTER_READ.with(|slot| {
            let taken = slot.borrow_mut().take();
            if taken.is_some() {
                record_hit("after_read");
            }
            taken
        })
    }

    pub(crate) fn arm_before_body_clear(
        hook: impl FnMut(u64, &mut Vec<super::ExcludedBody>) + 'static,
    ) -> HookGuard {
        BEFORE_BODY_CLEAR.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        HookGuard
    }

    pub(crate) fn take_before_body_clear() -> Option<BeforeBodyClear> {
        BEFORE_BODY_CLEAR.with(|slot| {
            let taken = slot.borrow_mut().take();
            if taken.is_some() {
                record_hit("before_body_clear");
            }
            taken
        })
    }

    pub(crate) fn arm_fail_at(point: &'static str) -> HookGuard {
        FAIL_AT.with(|slot| *slot.borrow_mut() = Some(point));
        HookGuard
    }

    pub(crate) fn clear_fail_at() {
        FAIL_AT.with(|slot| *slot.borrow_mut() = None);
        FAIL_AT_NTH.with(|slot| *slot.borrow_mut() = None);
        FAULT_SCRIPT.with(|slot| *slot.borrow_mut() = None);
    }

    pub(crate) fn armed_fail_at() -> Option<&'static str> {
        FAIL_AT.with(|slot| *slot.borrow())
    }

    /// Fire a fault on the *n*-th time the named point is reached.
    pub(crate) fn arm_fail_at_nth(point: &'static str, nth: usize) -> HookGuard {
        FAIL_AT_NTH.with(|slot| *slot.borrow_mut() = Some((point, nth)));
        HookGuard
    }

    /// Consume one occurrence of `point`; `true` means fire.
    pub(crate) fn take_nth_fault(point: &str) -> bool {
        FAIL_AT_NTH.with(|slot| {
            let mut slot = slot.borrow_mut();
            match slot.as_mut() {
                Some((armed_point, remaining)) if *armed_point == point => {
                    if *remaining <= 1 {
                        *slot = None;
                        record_hit("fail_at_nth");
                        true
                    } else {
                        *remaining -= 1;
                        false
                    }
                }
                _ => false,
            }
        })
    }

    /// Arm a script of typed faults for this thread, and for every thread a
    /// writer dispatch from this thread runs the commit on.
    ///
    /// Returns the shared script beside the guard, so a case can read what
    /// actually fired rather than infer it from the arming.
    pub(crate) fn arm_fault_script(
        entries: &[(&'static str, TypedFault)],
    ) -> (HookGuard, Arc<Mutex<FaultScript>>) {
        let script = Arc::new(Mutex::new(FaultScript {
            entries: entries.iter().copied().collect(),
            fired: Vec::new(),
        }));
        FAULT_SCRIPT.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&script)));
        (HookGuard, script)
    }

    /// The script this thread currently holds, if any.
    pub(crate) fn current_fault_script() -> Option<Arc<Mutex<FaultScript>>> {
        FAULT_SCRIPT.with(|slot| slot.borrow().clone())
    }

    /// Install a script on *this* thread until the guard drops.
    ///
    /// This is what carries the script across the writer-thread boundary: the
    /// thread that submits the job installs the very same `Arc`, so the
    /// consumed state is one state and a spent entry stays spent.
    pub(crate) fn install_fault_script(script: Arc<Mutex<FaultScript>>) -> FaultScopeGuard {
        let previous = FAULT_SCRIPT.with(|slot| slot.borrow_mut().replace(script));
        FaultScopeGuard(previous)
    }

    /// Take the next scripted fault, if it is this point's turn.
    pub(crate) fn take_scripted_fault(point: &str) -> Option<TypedFault> {
        let script = FAULT_SCRIPT.with(|slot| slot.borrow().clone())?;
        let mut script = script.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match script.entries.front() {
            Some((armed_point, fault)) if *armed_point == point => {
                let (armed_point, fault) = script.entries.pop_front().expect("front checked");
                script
                    .fired
                    .push((armed_point, fault, std::thread::current().id()));
                record_hit("scripted_fault");
                Some(fault)
            }
            _ => None,
        }
    }

    /// Force the writer mode for this thread, so one case can drive both
    /// writer modes without touching a process-wide environment variable.
    pub(crate) fn arm_writer_mode(concurrent: bool) -> HookGuard {
        WRITER_MODE.with(|slot| *slot.borrow_mut() = Some(concurrent));
        HookGuard
    }

    /// The writer mode this thread was forced into, if any.
    pub(crate) fn forced_writer_mode() -> Option<bool> {
        WRITER_MODE.with(|slot| *slot.borrow())
    }

    pub(crate) fn blob_path(data_dir: &Path, blob_relative_path: &str) -> PathBuf {
        data_dir.join("raw-mirror").join("v1").join(blob_relative_path)
    }
}

/// The loaded, verified fixed safety configuration.
///
/// Built only by [`load_fixed_safety_config`]: it holds the copy's original
/// UTF-8 path and exact bytes, so the same bytes can be re-checked immediately
/// before an input is activated.
pub(crate) struct FixedSafetyConfig {
    /// The fixed copy's absolute path, as an original UTF-8 string. Never a
    /// lossy conversion of a non-UTF-8 path.
    original_path: String,
    bytes: Vec<u8>,
    bytes_sha256: Sha256Digest,
    config: SourceSafetyConfig,
}

impl std::fmt::Debug for FixedSafetyConfig {
    /// Digest-only on purpose.
    ///
    /// The derived form would print the fixed copy's absolute path and its
    /// whole body — the path is private state, and the body is the exclusion
    /// rule set. Neither belongs in a log, so the manual rendering reports the
    /// two facts that identify this copy without reproducing it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedSafetyConfig")
            .field("bytes_sha256", &self.bytes_sha256.hex())
            .field("bytes", &self.bytes.len())
            .field("redaction_epoch", &self.config.code_version)
            .field("desensitization_enabled", &self.config.desensitization_enabled)
            .finish()
    }
}

impl FixedSafetyConfig {
    #[must_use]
    pub(crate) fn original_path(&self) -> &str {
        &self.original_path
    }

    #[must_use]
    pub(crate) fn bytes_sha256(&self) -> &Sha256Digest {
        &self.bytes_sha256
    }

    #[must_use]
    pub(crate) fn config(&self) -> &SourceSafetyConfig {
        &self.config
    }

    #[must_use]
    pub(crate) fn config_source_identity(&self) -> &str {
        &self.config.config_source_identity
    }

    /// Re-read the fixed copy and refuse when it is no longer the same bytes.
    ///
    /// Called immediately before an input is processed, so a copy that changed
    /// (or vanished) between startup and activation is not a success.
    pub(crate) fn recheck_bytes(&self) -> Result<(), SourceIngestError> {
        let current = read_fixed_copy(Path::new(&self.original_path))?;
        if current != self.bytes {
            return Err(SourceIngestError::Config {
                detail: "the fixed configuration copy changed after it was loaded".to_string(),
            });
        }
        Ok(())
    }
}

/// Read the fixed copy: an ordinary, non-symlink regular file with a UTF-8 path.
fn read_fixed_copy(path: &Path) -> Result<Vec<u8>, SourceIngestError> {
    let path_text = path.to_str().ok_or_else(|| SourceIngestError::Config {
        detail: "the fixed configuration path is not valid UTF-8".to_string(),
    })?;
    if path_text.is_empty() {
        return Err(SourceIngestError::Config {
            detail: "the fixed configuration path is empty".to_string(),
        });
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|err| SourceIngestError::Config {
        detail: format!("the fixed configuration copy is unreadable ({})", err.kind()),
    })?;
    if metadata.file_type().is_symlink() {
        return Err(SourceIngestError::Config {
            detail: "the fixed configuration copy is a symlink".to_string(),
        });
    }
    if !metadata.is_file() {
        return Err(SourceIngestError::Config {
            detail: "the fixed configuration copy is not a regular file".to_string(),
        });
    }
    std::fs::read(path).map_err(|err| SourceIngestError::Config {
        detail: format!("the fixed configuration copy could not be read ({})", err.kind()),
    })
}

/// The four array keys, in the order the effective digest uses.
const FOUR_ARRAY_KEYS: [&str; 4] = [
    "injection_only_files",
    "memory_files",
    "project_read_documents",
    "workspace_scoped_files",
];

/// Load and verify the caller-supplied fixed safety-config copy.
///
/// The caller must provide the copy; this never creates or repairs a missing
/// file. The four array keys are checked for *presence* in the raw TOML before
/// the typed deserialisation runs, because [`crate::sources::config::ExcludedContextPaths`]
/// carries `#[serde(default)]` on every field: a deserialised value alone
/// cannot distinguish "the key was there" from "a live default was filled in".
pub(crate) fn load_fixed_safety_config(path: &Path) -> Result<FixedSafetyConfig, SourceIngestError> {
    // The identity names an absolute UTF-8 path, resolved once here. A
    // relative spelling would make the identity depend on the process's working
    // directory, so it is made absolute first -- and deliberately *without*
    // canonicalising, because resolving symlinks would defeat the symlink
    // rejection below.
    let absolute = {
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::path::absolute(path).map_err(|_| SourceIngestError::Config {
                detail: "the fixed configuration path could not be made absolute".to_string(),
            })?
        };
        candidate
            .to_str()
            .ok_or_else(|| SourceIngestError::Config {
                detail: "the fixed configuration path is not valid UTF-8".to_string(),
            })?
            .to_string()
    };
    let absolute_path = std::path::PathBuf::from(&absolute);
    let path = absolute_path.as_path();
    let original_path = absolute;
    let bytes = read_fixed_copy(path)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| SourceIngestError::Config {
        detail: "the fixed configuration copy is not UTF-8".to_string(),
    })?;

    // Presence check first: every array key must really be in the file.
    let raw: toml::Value = toml::from_str(text).map_err(|err| SourceIngestError::Config {
        detail: "the fixed configuration copy does not parse".to_string(),
    })?;
    let table = raw.as_table().ok_or_else(|| SourceIngestError::Config {
        detail: "the fixed configuration copy is not a TOML table".to_string(),
    })?;
    for key in FOUR_ARRAY_KEYS {
        match table.get(key) {
            Some(toml::Value::Array(values)) => {
                if !values.iter().all(|value| value.is_str()) {
                    return Err(SourceIngestError::Config {
                        detail: format!("the fixed configuration key {key} is not an array of strings"),
                    });
                }
            }
            Some(_) => {
                return Err(SourceIngestError::Config {
                    detail: format!("the fixed configuration key {key} is not an array"),
                });
            }
            None => {
                return Err(SourceIngestError::Config {
                    detail: format!("the fixed configuration copy has no {key} array"),
                });
            }
        }
    }

    let effective_four_arrays: crate::sources::config::ExcludedContextPaths =
        toml::from_str(text).map_err(|err| SourceIngestError::Config {
            detail: format!("the fixed configuration copy does not parse: {err}"),
        })?;

    // The new path always desensitises. The legacy environment switch may turn
    // the legacy path's redaction off; it can never turn this one off.
    let config = SourceSafetyConfig {
        code_version: format!("{SOURCE_EXCLUSION_EPOCH}+{}", crate::indexer::redact_secrets::redaction_algorithm_fingerprint()),
        desensitization_enabled: true,
        config_source_identity: original_path.clone(),
        fixed_config_bytes: bytes.clone(),
        effective_four_arrays,
    };
    // Recomputes the two collection digests and refuses an inconsistent copy.
    config.verify().map_err(SourceIngestError::Verify)?;

    Ok(FixedSafetyConfig {
        original_path,
        bytes_sha256: Sha256Digest::of(&bytes),
        bytes,
        config,
    })
}

/// Restore a frozen fixed safety configuration from the copy a journal names.
///
/// The caller supplies the physical copy path, the frozen logical identity and
/// the material facts the journal recorded: the fixed-copy digest, the
/// effective four-array digest and the code version the capture ran under. The
/// logical identity never decides where the bytes are read from. Both digests
/// are recomputed from the copy actually loaded, and the version must match
/// exactly instead of merely being non-empty.
///
/// This entry never creates, repairs or republishes a copy. Every refusal is
/// one short `Config` reason that carries neither the rule text nor the
/// caller's identity, version or private path.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn load_restore_fixed_safety(
    path: &Path,
    identity: &str,
    fixed_sha: &Sha256Digest,
    arrays_sha: &Sha256Digest,
    code_version: &str,
) -> Result<FixedSafetyConfig, SourceIngestError> {
    // One local refusal shape: a fixed short reason, never the rule text, the
    // caller's identity or version values, or the private path.
    let refuse = |reason: &str| SourceIngestError::Config {
        detail: format!("source_restore_material_mismatch {reason}"),
    };
    if identity.trim().is_empty() {
        return Err(refuse("blank_identity"));
    }
    let mut loaded =
        load_fixed_safety_config(path).map_err(|_| refuse("fixed_copy_unusable"))?;
    if loaded.config.code_version != code_version {
        return Err(refuse("code_version_unsupported"));
    }
    let verified = loaded
        .config
        .verify()
        .map_err(|_| refuse("fixed_config_unverified"))?;
    if verified.fixed_config_sha256() != fixed_sha {
        return Err(refuse("fixed_sha_mismatch"));
    }
    if verified.effective_four_arrays_sha256() != arrays_sha {
        return Err(refuse("arrays_sha_mismatch"));
    }
    // Only now is the frozen logical identity restored. The loaded path, the
    // bytes and the byte digest stay exactly as the strict loader produced
    // them, and the second verify keeps the restored identity non-empty.
    loaded.config.config_source_identity = identity.to_string();
    loaded
        .config
        .verify()
        .map_err(|_| refuse("identity_unverified"))?;
    Ok(loaded)
}

/// P0/C5 (2026-10-15 execution contract v2): the fixed configuration one run
/// consumes.
///
/// With an explicit copy this is exactly [`load_fixed_safety_config`]: the
/// operator's absolute path and its original bytes *are* the identity, and
/// nothing is republished or migrated.
///
/// Without one, the effective rules are discovered once through
/// [`crate::sources::config::ExcludedContextPaths::load_for_source_fidelity`],
/// frozen into a content-addressed private copy under `data_dir`, and read back
/// through the same strict loader. Every input of the run therefore binds one
/// immutable copy, and a later edit of the live file cannot change what this
/// run ran under.
///
/// `explicit` is a decision the caller has already taken, never an environment
/// lookup: a named copy is not re-discovered here.
pub(crate) fn prepare_source_safety(
    data_dir: &Path,
    explicit: Option<&Path>,
) -> Result<Arc<FixedSafetyConfig>, SourceIngestError> {
    match explicit {
        Some(path) => Ok(Arc::new(load_fixed_safety_config(path)?)),
        None => Ok(Arc::new(prepare_default_source_safety(data_dir)?)),
    }
}

/// The automatic identity's domain tag.
///
/// The identity names the copy's *bytes*, so the same effective rules migrated
/// to another `data_dir` keep one safety identity while their physical location
/// changes. The location still travels separately, in `original_path`, for
/// [`FixedSafetyConfig::recheck_bytes`].
const SOURCE_CONFIG_IDENTITY_DOMAIN: &str = "cass.source-config/1";

/// The fixed copies' layout under the data directory.
const SOURCE_CONFIG_DIR: &str = "source-configs";
const SOURCE_CONFIG_VERSION_DIR: &str = "v1";

/// Discover the effective rules once, publish them, and load the copy back.
fn prepare_default_source_safety(data_dir: &Path) -> Result<FixedSafetyConfig, SourceIngestError> {
    let effective = crate::sources::config::ExcludedContextPaths::load_for_source_fidelity()
        .map_err(|err| {
            config_failure("source_config_load_failed", &describe_rule_discovery_failure(&err))
        })?;

    // The pinned `toml` serialiser over the existing `Serialize` shape: all
    // four keys, every array in its own order, nothing sorted or deduplicated.
    let bytes = toml::to_string(&effective)
        .map_err(|_| {
            config_failure(
                "source_config_publish_failed",
                "the effective rule set could not be serialised",
            )
        })?
        .into_bytes();
    let digest = Sha256Digest::of(&bytes);

    let directory = prepare_fixed_copy_directory(data_dir)?;
    let fixed_path = directory.join(format!("{}.toml", digest.hex()));
    publish_fixed_copy(&fixed_path, &bytes)?;

    // Re-read the published file through the strict loader, so the copy this
    // run consumes is one that really passed the four-key presence check.
    let mut loaded = load_fixed_safety_config(&fixed_path).map_err(|_| {
        config_failure(
            "source_config_mismatch",
            "the published fixed configuration copy did not reload",
        )
    })?;
    if loaded.bytes_sha256.hex() != digest.hex() {
        return Err(config_failure(
            "source_config_mismatch",
            "the published fixed configuration copy is not the bytes that were written",
        ));
    }
    // The automatic mode's identity is the content address, not the location.
    loaded.config.config_source_identity =
        format!("{SOURCE_CONFIG_IDENTITY_DOMAIN}:sha256:{}", digest.hex());
    loaded.config.verify().map_err(SourceIngestError::Verify)?;
    Ok(loaded)
}

/// A class-based description of a failed rule-file discovery.
///
/// The discovery error can carry the file's own text: a TOML parse error
/// quotes the offending line and its value. None of that may reach a log, a
/// report or a CLI message, so every branch here is a fixed sentence, and the
/// only variable part is an I/O error *kind* -- which names neither content
/// nor path. The legacy loader's own rendering is deliberately not used here.
fn describe_rule_discovery_failure(err: &crate::sources::config::ConfigError) -> String {
    use crate::sources::config::ConfigError;

    match err {
        ConfigError::Read(io) => format!("the live rule file could not be read ({})", io.kind()),
        ConfigError::Parse(_) => "the live rule file is not valid TOML".to_string(),
        ConfigError::Serialize(_) => "the live rule set could not be serialised".to_string(),
        ConfigError::NoConfigDir => "the live rule file has no configuration directory".to_string(),
        ConfigError::Validation(_) => "the live rule file failed validation".to_string(),
    }
}

/// Create `data_dir/source-configs/v1` with the private mode the layout wants.
fn prepare_fixed_copy_directory(data_dir: &Path) -> Result<PathBuf, SourceIngestError> {
    let base = data_dir.join(SOURCE_CONFIG_DIR);
    let directory = base.join(SOURCE_CONFIG_VERSION_DIR);
    for path in [&base, &directory] {
        std::fs::create_dir_all(path).map_err(|err| {
            publish_failure(&format!(
                "the fixed configuration directory could not be created ({})",
                err.kind()
            ))
        })?;
        set_private_directory_mode(path)?;
    }
    Ok(directory)
}

/// The copy's own bytes, or `None` when the name is free.
///
/// A symlink, a directory or any other non-regular file at the name is refused
/// outright: it is neither followed nor repaired.
fn existing_fixed_copy(path: &Path) -> Result<Option<Vec<u8>>, SourceIngestError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(copy_mismatch(
                    "an existing fixed configuration copy is not a regular file",
                ));
            }
            std::fs::read(path).map(Some).map_err(|err| {
                publish_failure(&format!(
                    "an existing fixed configuration copy could not be read ({})",
                    err.kind()
                ))
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(publish_failure(&format!(
            "an existing fixed configuration copy could not be inspected ({})",
            err.kind()
        ))),
    }
}

/// Publish the fixed copy at `path` without ever replacing an existing name.
///
/// The final name is created by a same-directory `hard_link` from an
/// exclusively-created, flushed temporary file. A reader therefore sees either
/// no file or the whole file, never a partial one; and a name that already
/// exists -- including one a concurrent publisher just created -- is decided by
/// byte comparison, so a wrong copy is refused rather than overwritten.
fn publish_fixed_copy(path: &Path, bytes: &[u8]) -> Result<(), SourceIngestError> {
    publish_fixed_copy_at(path, bytes, &unique_fixed_copy_temp_path(path))
}

/// The publication step, with the temporary name supplied.
///
/// [`publish_fixed_copy`] is the only production caller and hands it the
/// unique name; the tests name the temporary path so the "remove only what
/// this call created" rule can be exercised against a fixed synthetic name.
fn publish_fixed_copy_at(
    path: &Path,
    bytes: &[u8],
    temporary: &Path,
) -> Result<(), SourceIngestError> {
    if let Some(existing) = existing_fixed_copy(path)? {
        if existing != bytes {
            return Err(copy_mismatch(
                "an existing fixed configuration copy has different bytes",
            ));
        }
        return Ok(());
    }

    let directory = path
        .parent()
        .ok_or_else(|| publish_failure("the fixed configuration copy has no parent directory"))?;

    let mut temporary_file = match create_owned_temporary(temporary) {
        Ok(Some(file)) => file,
        // The exclusive create did not succeed, so this call never owned that
        // name: whatever is there belongs to someone else, and it is left
        // exactly as it was found.
        Ok(None) => {
            return Err(publish_failure(
                "the fixed configuration copy's temporary name was already taken",
            ));
        }
        Err(err) => {
            return Err(publish_failure(&format!(
                "the fixed configuration copy could not be created ({})",
                err.kind()
            )));
        }
    };

    if let Err(err) = fill_owned_temporary(&mut temporary_file, bytes) {
        drop(temporary_file);
        // This call did create the name, so the partial file is its own to
        // remove -- and nobody else's.
        let _ = std::fs::remove_file(temporary);
        return Err(publish_failure(&format!(
            "the fixed configuration copy could not be written ({})",
            err.kind()
        )));
    }
    drop(temporary_file);

    let linked = std::fs::hard_link(temporary, path);
    // Reached only past a successful exclusive create, so this name is ours
    // whichever way the link went.
    let _ = std::fs::remove_file(temporary);
    match linked {
        Ok(()) => sync_directory(directory),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            // Another publisher won the name. The address *is* the content, so
            // the winner is reused only when it really holds these bytes.
            match existing_fixed_copy(path)? {
                Some(existing) if existing == bytes => Ok(()),
                Some(_) => Err(copy_mismatch(
                    "an existing fixed configuration copy has different bytes",
                )),
                None => Err(copy_mismatch(
                    "the fixed configuration copy vanished while it was being published",
                )),
            }
        }
        Err(err) => Err(publish_failure(&format!(
            "the fixed configuration copy could not be linked into place ({})",
            err.kind()
        ))),
    }
}

/// Create `path` exclusively, and report whether this call created it.
///
/// `Ok(None)` is the one outcome in which the caller owns nothing: the name
/// was already taken, so the file at that path is not this call's to remove.
fn create_owned_temporary(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(None),
        Err(err) => Err(err),
    }
}

/// Fill and flush a temporary file this call created.
fn fill_owned_temporary(file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn set_private_directory_mode(path: &Path) -> Result<(), SourceIngestError> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
        publish_failure(&format!(
            "the fixed configuration directory permissions could not be set ({})",
            err.kind()
        ))
    })
}

/// Windows relies on the user's own private profile ACL, which is the existing
/// private-file capability this layout builds on there.
#[cfg(not(unix))]
fn set_private_directory_mode(_path: &Path) -> Result<(), SourceIngestError> {
    Ok(())
}

fn unique_fixed_copy_temp_path(path: &Path) -> PathBuf {
    static NEXT_NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let nonce = NEXT_NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("fixed-safety.toml");

    path.with_file_name(format!(
        ".{name}.tmp.{}.{}.{}",
        std::process::id(),
        timestamp,
        nonce
    ))
}

/// Flush the directory entry itself, so the new name survives a crash.
///
/// The result is returned rather than dropped: a publish whose directory could
/// not be synced has not met the contract and must not report success.
fn sync_directory(directory: &Path) -> Result<(), SourceIngestError> {
    #[cfg(unix)]
    {
        let handle = std::fs::File::open(directory).map_err(|err| {
            publish_failure(&format!(
                "the fixed configuration directory could not be opened for sync ({})",
                err.kind()
            ))
        })?;
        handle.sync_all().map_err(|err| {
            publish_failure(&format!(
                "the fixed configuration directory could not be synced ({})",
                err.kind()
            ))
        })?;
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
    }
    Ok(())
}

/// A `Config` failure whose detail opens with the contract's stable short code.
fn config_failure(code: &str, detail: &str) -> SourceIngestError {
    SourceIngestError::Config {
        detail: format!("{code}: {detail}"),
    }
}

fn publish_failure(detail: &str) -> SourceIngestError {
    config_failure("source_config_publish_failed", detail)
}

fn copy_mismatch(detail: &str) -> SourceIngestError {
    config_failure("source_config_mismatch", detail)
}

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

/// Write a compact JSON view of `value` with every object's members sorted by
/// key and every array in its original order.
///
/// This is the encoding the two profile identities hash, so it must not depend
/// on the map implementation behind `serde_json::Value`.
pub(crate) fn write_canonical_json(
    value: &serde_json::Value,
    out: &mut Vec<u8>,
) -> Result<(), SourceIngestError> {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();
            for (key, item) in map {
                entries.insert(key.as_str(), item);
            }
            out.push(b'{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_json_string(key, out);
                out.push(b':');
                write_canonical_json(item, out)?;
            }
            out.push(b'}');
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(b']');
        }
        other => {
            serde_json::to_writer(&mut *out, other).map_err(|err| SourceIngestError::Config {
                detail: format!("canonical JSON encoding failed: {err}"),
            })?;
        }
    }
    Ok(())
}

/// The contract's string escape rule: the two mandatory escapes plus `\u00XX`
/// for every other control character.
fn write_json_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(br#"\""#),
            '\\' => out.extend_from_slice(br"\\"),
            '\u{08}' => out.extend_from_slice(br"\b"),
            '\u{0c}' => out.extend_from_slice(br"\f"),
            '\n' => out.extend_from_slice(br"\n"),
            '\r' => out.extend_from_slice(br"\r"),
            '\t' => out.extend_from_slice(br"\t"),
            ch if (ch as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", ch as u32).as_bytes());
            }
            ch => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// SHA-256 of the canonical encoding of `value`, as lowercase hex.
fn canonical_digest(value: &serde_json::Value) -> Result<String, SourceIngestError> {
    let mut bytes = Vec::new();
    write_canonical_json(value, &mut bytes)?;
    Ok(Sha256Digest::of(&bytes).hex())
}

// ---------------------------------------------------------------------------
// Profile identity
// ---------------------------------------------------------------------------

/// The two identities one effective configuration produces.
///
/// Both are 64-character lowercase hex, produced by the single assembly
/// factory: nothing else in this path may hand-write either string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceProfile {
    /// `SHA256(["cass.source-normalizer/1", FAD pin, "cass-source-mapping/2",
    /// effective_config_digest])`.
    pub(crate) normalizer_id: String,
    /// `SHA256(["cass.source-safety/1", "cass-source-exclusion/1", redaction
    /// algorithm fingerprint, config source identity, fixed config sha256,
    /// effective four arrays sha256, true])`.
    pub(crate) safety_contract_id: String,
    /// The effective-configuration digest the normalizer identity embedded.
    pub(crate) effective_config_digest: String,
}

impl SourceProfile {
    /// The one way a profile is produced.
    ///
    /// `effective_config` is the canonical material of the *explicitly parsed*
    /// configuration this input ran under: the ordered roots, the origin, the
    /// platform and the workspace rewrites. `relative_locator`, `mtime` and
    /// `since_ts` are excluded, so two files under one root share a profile
    /// while two roots never do.
    pub(crate) fn assemble(
        safety: &FixedSafetyConfig,
        effective_config: &serde_json::Value,
    ) -> Result<Self, SourceIngestError> {
        let effective_config_digest = canonical_digest(effective_config)?;
        let identity = safety.config.verify().map_err(SourceIngestError::Verify)?;
        let redaction = crate::indexer::redact_secrets::redaction_algorithm_fingerprint();

        let normalizer = serde_json::json!([
            SOURCE_NORMALIZER_DOMAIN,
            FAD_PIN,
            SOURCE_MAPPING_DOMAIN,
            effective_config_digest,
        ]);
        let safety_array = serde_json::json!([
            SOURCE_SAFETY_CONTRACT,
            SOURCE_EXCLUSION_EPOCH,
            redaction,
            safety.config_source_identity(),
            identity.fixed_config_sha256().hex(),
            identity.effective_four_arrays_sha256().hex(),
            true,
        ]);

        Ok(Self {
            normalizer_id: canonical_digest(&normalizer)?,
            safety_contract_id: canonical_digest(&safety_array)?,
            effective_config_digest,
        })
    }
}

/// The profile identity the scan path assembles for **every** input from one
/// scan root and one role (SRC05B-08).
///
/// The scan needs this before it reads anything: it is what decides whether a
/// completed input recorded under this configuration is evidence that the file
/// in front of it was already read. It goes through the single assembly
/// factory -- [`SourceProfile::assemble`] -- and feeds it the same
/// effective-configuration material [`prepare_source_input`] builds for a real
/// input, from the same fields: the root path, its origin, its platform and its
/// workspace rewrites. `relative_locator`, `mtime` and `since_ts` are excluded
/// by that material, so one profile covers every file under the root.
///
/// A caller that derives a different context here would make the identity two
/// derivations of one thing; the safe failure is a miss, which reads the file
/// again.
pub(crate) fn root_profile(
    safety: &FixedSafetyConfig,
    connector_name: &str,
    root: &crate::connectors::ScanRoot,
    role: fad::SourceInputRole,
) -> Result<SourceProfile, SourceIngestError> {
    let context = fad::SourceParserContext {
        schema: "cass.source-parser-context/1".to_string(),
        connector: fad_connector_name(connector_name),
        roots: vec![fad::SourceParserRoot {
            path: root.path.clone(),
            origin: fad::SourceOrigin {
                origin: root.origin.clone(),
                source_version: None,
            },
            platform: root.platform,
            workspace_rewrites: root.workspace_rewrites.clone(),
        }],
        // Not part of the effective-configuration material this assembles.
        relative_locator: String::new(),
        role,
        effective_config_digest: None,
    };
    SourceProfile::assemble(safety, &effective_config_material(&context)?)
}

/// Every role the sealed path can carry.
///
/// The two functions below are two views of this one list, which is what keeps
/// the spelling stored in `source_inputs.role_bin` and the role parsed back out
/// of it from drifting apart. A variant added upstream without being listed
/// here makes [`sealed_role_key`] answer `None`, which reads the file instead
/// of filing its evidence under a name nothing looks up.
pub(crate) const SEALED_ROLES: [fad::SourceInputRole; 2] = [
    fad::SourceInputRole::PrimarySessionLog,
    fad::SourceInputRole::MetadataSidecar,
];

/// The stored spelling of a discovered role: the key a completed input's
/// evidence is filed under. `None` for a role the sealed path cannot carry
/// (`sqlite_database`), which [`prepare_source_input`] refuses anyway -- so
/// the file is read and the root fails with the real reason instead of being
/// skipped on a technicality.
pub(crate) fn sealed_role_key(role: crate::connectors::DiscoveredSourceRole) -> Option<&'static str> {
    let sealed = fad::SourceInputRole::try_from(role).ok()?;
    SEALED_ROLES
        .into_iter()
        .find(|candidate| *candidate == sealed)
        .map(fad::SourceInputRole::as_str)
}

/// The role one stored spelling names, or `None` for a spelling this build
/// does not know -- again answered by reading the file rather than guessing.
pub(crate) fn sealed_role_from_key(key: &str) -> Option<fad::SourceInputRole> {
    SEALED_ROLES
        .into_iter()
        .find(|role| role.as_str() == key)
}

/// Build the effective-configuration material a profile is assembled from.
///
/// Only the fields that change what the parser *sees* belong here: the ordered
/// discovery roots, the origin, the platform and the workspace rewrites.
pub(crate) fn effective_config_material(
    context: &fad::SourceParserContext,
) -> Result<serde_json::Value, SourceIngestError> {
    // Every path here is identity. A non-UTF-8 path is refused rather than
    // rendered lossily: two distinct unrepresentable paths can collapse onto
    // the same replacement-character string, so a lossy conversion would let
    // two different configurations hash to one profile.
    let mut roots: Vec<serde_json::Value> = Vec::with_capacity(context.roots.len());
    for root in &context.roots {
        roots.push(serde_json::json!({
            "path": path_text_required(&root.path)?,
            "origin": {
                "kind": root.origin.origin.kind,
                "host": root.origin.origin.host,
                "source_version": root.origin.source_version,
            },
            "platform": root.platform,
            "workspace_rewrites": root.workspace_rewrites,
        }));
    }
    Ok(serde_json::json!({
        "schema": context.schema,
        "connector": context.connector,
        "roots": roots,
        "role": context.role,
    }))
}

/// A `BufReader` over a verified capture's file handle, for the independent
/// CASS-side framing scan.
pub(crate) fn verified_reader(file: std::fs::File) -> BufReader<std::fs::File> {
    BufReader::new(file)
}

/// The declared format of a sealed input, mapped onto the storage enum.
pub(crate) fn source_format_of(format: fad::SourceFormat) -> SourceFormat {
    match format {
        fad::SourceFormat::Jsonl => SourceFormat::Jsonl,
        fad::SourceFormat::JsonDocument => SourceFormat::JsonDocument,
    }
}

/// The declaration side of one sealed input, ready for
/// [`source_facts::VerifiedSourceInput::verify_reader`].
pub(crate) struct SealedInputPlan {
    pub(crate) declaration: SourceInputDeclaration,
    pub(crate) sealed: fad::SealedInputContext,
}

// ---------------------------------------------------------------------------
// Pass 1: structure only
// ---------------------------------------------------------------------------

/// One source record as the pinned connector reported it.
///
/// No source text is retained here: only the physical position, that position's
/// own digest, the parse outcome and any diagnostics. Pass 2 reads the bytes
/// again through the verified handle.
#[derive(Debug, Clone)]
pub(crate) struct Pass1Record {
    pub(crate) ordinal: u64,
    pub(crate) locator: fad::SourceRecordLocator,
    pub(crate) record_sha256: fad::Sha256Digest,
    pub(crate) parse_state: fad::SourceParseState,
    pub(crate) diagnostics: Vec<fad::SourceDiagnostic>,
    pub(crate) claims: Vec<fad::SourceMappingClaim>,
}

/// One conversation the pinned connector projected, with the claims that
/// justified it.
#[derive(Debug, Clone)]
pub(crate) struct Pass1Conversation {
    pub(crate) ordinal: u32,
    pub(crate) conversation: crate::connectors::NormalizedConversation,
    pub(crate) claims: Vec<fad::SourceMappingClaim>,
}

/// What pass 1 produced, plus everything pass 2 needs to finish the input.
///
/// The job carries the *whole* input: one input is one unit of work and may
/// never be split into several conversation commits.
#[derive(Clone)]
pub(crate) struct SourceInputJob {
    pub(crate) connector_name: &'static str,
    pub(crate) root_id: String,
    pub(crate) data_dir: PathBuf,
    pub(crate) safety: Arc<FixedSafetyConfig>,
    /// The root this input came from, carrying the effective workspace
    /// rewrites the projection applies once.
    pub(crate) root: crate::connectors::ScanRoot,
    /// The capture record this input was sealed under, so the commit can
    /// re-open and re-verify the very same blob.
    pub(crate) capture: crate::raw_mirror::RawMirrorCaptureRecord,
    /// The managed blob this input's sealed bytes were read from.
    pub(crate) blob_path: PathBuf,
    /// The blob's transport hash, as the capture recorded it.
    pub(crate) blob_blake3: String,
    /// The capture's own recorded original path (never re-derived).
    pub(crate) original_path: String,
    pub(crate) input: source_facts::VerifiedSourceInput,
    /// The profile identity this input was assembled under, kept beside the
    /// verified input because the activation request must name the same two.
    pub(crate) normalizer_id: String,
    pub(crate) safety_contract_id: String,
    pub(crate) finish: crate::indexer::source_ingest::fad::SourceInputFinish,
    pub(crate) records: Vec<Pass1Record>,
    pub(crate) conversations: Vec<Pass1Conversation>,
    /// Text bytes this job holds on the ingest channel, released after commit.
    pub(crate) byte_reservation: usize,
}

impl SourceInputJob {
    /// A log-safe description: the connector and the root it came from. Never
    /// the source path and never any record text.
    #[must_use]
    pub(crate) fn origin_hint(&self) -> String {
        format!("{}@{}", self.connector_name, self.root_id)
    }
}

impl std::fmt::Debug for SourceInputJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately narrow: a job holds projected conversation text, and a
        // Debug rendering must not be the thing that copies it into a log.
        f.debug_struct("SourceInputJob")
            .field("connector", &self.connector_name)
            .field("root_id", &self.root_id)
            .field("records", &self.records.len())
            .field("conversations", &self.conversations.len())
            .field("bytes", &self.byte_reservation)
            .finish()
    }
}

/// The classifying result of one input.
///
/// These four are separate facts on purpose (SRC05B-07 "实现顺序与硬约束"):
/// only a committed activation is `Completed`; a refusal is durable; a
/// transient failure may be retried; and a derivation that failed *after* the
/// commit is neither a failure nor a silent success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceInputOutcome {
    /// The input committed and its receipt verifies.
    Completed {
        input_key: Sha256Digest,
        records: u64,
        conversations: u64,
        replay: bool,
        /// How many semantic inputs this commit's delta produced, read back
        /// from canonical storage in memory. Zero on a replay.
        semantic_inputs: usize,
    },
    /// The input was refused and the refusal is recorded.
    Rejected { input_key: Sha256Digest, reason: String },
    /// The input could not be committed now; nothing was activated.
    Transient { input_key: Sha256Digest, reason: String },
    /// The input committed, but a post-commit derivation still needs recovery.
    PostCommitPendingRecovery {
        input_key: Sha256Digest,
        reason: String,
        /// The commit's own delta size, kept so the pending work is countable.
        semantic_inputs: usize,
    },
}

impl SourceInputOutcome {
    #[must_use]
    pub(crate) fn input_key(&self) -> &Sha256Digest {
        match self {
            Self::Completed { input_key, .. }
            | Self::Rejected { input_key, .. }
            | Self::Transient { input_key, .. }
            | Self::PostCommitPendingRecovery { input_key, .. } => input_key,
        }
    }

    /// Whether this outcome lets the enclosing root count as scanned cleanly.
    #[must_use]
    pub(crate) fn is_success(&self) -> bool {
        matches!(self, Self::Completed { .. } | Self::PostCommitPendingRecovery { .. })
    }

    #[must_use]
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Completed { records, conversations, replay, semantic_inputs, .. } => format!(
                "completed ({records} records, {conversations} conversations, \
                 {semantic_inputs} semantic inputs{})",
                if *replay { ", replay" } else { "" }
            ),
            Self::Rejected { reason, .. } => format!("rejected: {reason}"),
            Self::Transient { reason, .. } => format!("transient failure: {reason}"),
            Self::PostCommitPendingRecovery { reason, semantic_inputs, .. } => format!(
                "committed ({semantic_inputs} semantic inputs); derivation pending recovery: {reason}"
            ),
        }
    }
}

/// The pass-1 sink. It accepts every record, conversation and claim the pinned
/// connector projects, and never touches source text.
#[derive(Default)]
struct Pass1Sink {
    records: Vec<Pass1Record>,
    /// Physical position -> record slot. Built as records arrive so a claim
    /// lookup is a map probe, not a scan of every record: a single large input
    /// would otherwise make claim delivery quadratic in its own record count.
    ///
    /// The key is the *verified* locator pair the reader delivered. A claim is
    /// never matched by an event id or any other identifier the mapping layer
    /// merely asserts, because two different records can carry the same event
    /// id and a positional guess would cross attribution between them.
    by_locator: BTreeMap<(u64, String), usize>,
    /// Claims that arrived before their record was indexed. Resolved by
    /// [`Pass1Sink::finish`]; anything still here is a contract violation.
    deferred_claims: Vec<(fad::SourceRecordLocator, Vec<fad::SourceMappingClaim>)>,
    conversations: Vec<Pass1Conversation>,
    diagnostics: Vec<fad::SourceMappingDiagnostic>,
}

impl Pass1Sink {
    /// Close pass 1 and refuse any claim that never found its record.
    fn finish(self) -> Result<(Vec<Pass1Record>, Vec<Pass1Conversation>, Vec<fad::SourceMappingDiagnostic>), SourceIngestError> {
        if let Some((locator, _)) = self.deferred_claims.first() {
            return Err(SourceIngestError::Sink {
                detail: format!(
                    "claims for record ordinal {} address no delivered record",
                    locator.ordinal
                ),
            });
        }
        Ok((self.records, self.conversations, self.diagnostics))
    }
}

impl fad::SourceRecordSink for Pass1Sink {
    fn on_record(
        &mut self,
        record: fad::SourceRecordOutcome,
    ) -> Result<fad::SourceSinkControl, fad::SourceSinkFailure> {
        let record_sha256 = match fad::Sha256Digest::from_hex(&record.source_record_sha256.to_string())
        {
            Ok(digest) => digest,
            Err(_) => return Err(sink_failure("pass1_record_digest_unrepresentable")),
        };
        let key = (record.locator.ordinal, record.locator.record_pointer.clone());
        if self.by_locator.contains_key(&key) {
            // Two records at one physical position is not something to index
            // twice: whichever claim arrived later would bind to the wrong one.
            return Err(sink_failure("pass1_duplicate_record_locator"));
        }
        self.by_locator.insert(key, self.records.len());
        self.records.push(Pass1Record {
            ordinal: record.locator.ordinal,
            locator: record.locator,
            record_sha256,
            parse_state: record.parse_state,
            diagnostics: record.diagnostics,
            claims: Vec::new(),
        });
        Ok(fad::SourceSinkControl::Continue)
    }
}

impl fad::SourceMappingSink for Pass1Sink {
    fn on_record_claims(
        &mut self,
        locator: fad::SourceRecordLocator,
        claims: Vec<fad::SourceMappingClaim>,
    ) -> Result<fad::SourceSinkControl, fad::SourceSinkFailure> {
        // Claims address their record by ordinal and pointer. A claim whose
        // locator matches no record is a contract violation, not something to
        // attach to a neighbour: two different records may carry the same
        // event id, so positional guessing would cross attribution.
        let key = (locator.ordinal, locator.record_pointer.clone());
        let Some(index) = self.by_locator.get(&key).copied() else {
            self.deferred_claims.push((locator, claims));
            return Ok(fad::SourceSinkControl::Continue);
        };
        if !self.records[index].claims.is_empty() {
            // One record's claims are delivered once. A second delivery for the
            // same position would silently double-count it.
            return Err(sink_failure("pass1_duplicate_record_claims"));
        }
        self.records[index].locator = locator;
        self.records[index].claims = claims;
        Ok(fad::SourceSinkControl::Continue)
    }

    fn on_conversation(
        &mut self,
        item: fad::SourceMappedConversation,
    ) -> Result<fad::SourceSinkControl, fad::SourceSinkFailure> {
        self.conversations.push(Pass1Conversation {
            ordinal: item.conversation_ordinal,
            conversation: item.conversation,
            claims: item.claims,
        });
        Ok(fad::SourceSinkControl::Continue)
    }

    fn on_diagnostic(
        &mut self,
        item: fad::SourceMappingDiagnostic,
    ) -> Result<fad::SourceSinkControl, fad::SourceSinkFailure> {
        // Diagnostics are evidence, not a stop signal: one unreachable member
        // does not make the whole input unreadable, and the finish measurement
        // is what decides whether the read was complete.
        self.diagnostics.push(item);
        Ok(fad::SourceSinkControl::Continue)
    }
}

fn sink_failure(code: &str) -> fad::SourceSinkFailure {
    fad::SourceSinkFailure {
        code: fad::SourceSinkFailureCode::Rejected,
        detail_digest: Some(fad::Sha256Digest::of(code.as_bytes())),
    }
}

// ---------------------------------------------------------------------------
// Pass 1 entry
// ---------------------------------------------------------------------------

/// Everything pass 1 needs about one discovered file.
pub(crate) struct SourceInputRequest<'a> {
    pub(crate) connector_name: &'static str,
    pub(crate) data_dir: &'a Path,
    /// The root this input was actually discovered under, including the
    /// effective workspace rewrites the configuration carries.
    pub(crate) root: &'a crate::connectors::ScanRoot,
    pub(crate) meta: &'a crate::indexer::scan_root_meta::ScanRootMeta,
    pub(crate) discovered: &'a crate::connectors::DiscoveredSourceFile,
    pub(crate) safety: &'a Arc<FixedSafetyConfig>,
}

/// Everything the shared material factory needs to build one input's materials.
///
/// The factory borrows an already verified capture handle, the caller's
/// descriptor and parser context, and the fixed safety configuration. It never
/// reads the live source, never discovers or loads a configuration, never
/// re-captures and never writes to the database.
pub(crate) struct SourceInputMaterialRequest<'a> {
    /// The CASS scheduling slug (`claude`, `codex`) -- never the FAD connector
    /// name. The format table is keyed by what CASS registered.
    pub(crate) cass_connector: &'a str,
    /// The machine identity the declaration and the sealed context carry.
    pub(crate) identity_namespace: &'a str,
    pub(crate) descriptor: &'a fad::SourceInputDescriptor,
    /// The caller's parser context, carrying no effective-configuration digest
    /// yet. The factory resolves the digest in a clone and leaves this object
    /// untouched.
    pub(crate) parser_context: &'a fad::SourceParserContext,
    pub(crate) capture: &'a crate::raw_mirror::VerifiedRawMirrorCapture,
    pub(crate) safety: &'a FixedSafetyConfig,
}

/// The structure one verified capture yields.
///
/// The verified input, the profile identity it was assembled under, the parser
/// context with the real effective-configuration digest filled in, and the
/// independent framing measurement the input was checked against.
///
/// Deliberately not `Debug`: it holds the descriptor and the configuration
/// material, and a stray `{:?}` must not copy a path or a configuration into a
/// log.
pub(crate) struct VerifiedSourceMaterials {
    pub(crate) input: source_facts::VerifiedSourceInput,
    pub(crate) profile: SourceProfile,
    pub(crate) parser_context: fad::SourceParserContext,
    pub(crate) summary: source_facts::FramingSummary,
}

/// Build the source materials every consumer of one sealed input shares.
///
/// This is the single place the profile identity, the format decision, the
/// 15-element identity tuple and the two independent framing measurements are
/// computed. The ordinary entry calls it and keeps the orchestration around it
/// -- capture, the sealed FAD context and the job -- so an ordinary ingest and
/// any later recovery path consume one algorithm instead of two copies of it.
///
/// The capture handle must be the verified one; the factory takes the sealed
/// reference's blob digest and relative path from its getters.
pub(crate) fn verify_source_input_materials(
    request: &SourceInputMaterialRequest<'_>,
) -> Result<VerifiedSourceMaterials, SourceIngestError> {
    // The profile is assembled from the caller's context, but the resolved
    // `effective_config_digest` is written into a *copy*: the caller keeps its
    // own object, and only this one carries the digest the declaration names.
    let mut parser_context = request.parser_context.clone();
    let profile =
        SourceProfile::assemble(request.safety, &effective_config_material(&parser_context)?)?;
    parser_context.effective_config_digest = Some(
        fad::Sha256Digest::from_hex(&profile.effective_config_digest).map_err(|_| {
            SourceIngestError::Config {
                detail: "the effective configuration digest is not a sha256".to_string(),
            }
        })?,
    );

    let descriptor = request.descriptor;
    let capture = request.capture;

    // The one format decision for this input, taken from the CASS connector and
    // the discovered file's own extension before anything reads a byte. Every
    // later stage consumes this value: the independent scan below, the
    // declaration, the sealed context, the expected manifest and, through the
    // verified input, the commit. Nothing downstream re-derives it from the
    // connector.
    let format = sealed_format_for(request.cass_connector, &descriptor.source_path);

    // Independent CASS framing first: the expectation every other reader is
    // held to comes from this measurement and from nothing the connector says.
    let summary = {
        let reader = BufReader::new(reader_at_start(capture.file())?);
        let mut scan = source_facts::FramingStream::new(reader, format);
        scan.run_to_end().map_err(SourceIngestError::Verify)?;
        let summary = scan.finish();
        if !summary.complete {
            return Err(SourceIngestError::Verify(SourceInstallError::Activation {
                detail: "the independent scan did not reach the end of the sealed bytes".to_string(),
            }));
        }
        summary
    };

    let parser_context_value =
        lossless_from_value(&parser_context.to_wire().map_err(|kind| SourceIngestError::Verify(
            SourceInstallError::Activation { detail: format!("parser context wire: {kind:?}") },
        ))?)?;
    let discovery_value = lossless_from_value(
        &descriptor.to_wire().map_err(|kind| SourceIngestError::Verify(
            SourceInstallError::Activation { detail: format!("discovery wire: {kind:?}") },
        ))?,
    )?;
    // The sealed reference is read off the verified handle's own getters, never
    // off the unverified capture record.
    let sealed_ref_value = lossless_from_value(&serde_json::json!({
        "transport": "raw_blob",
        "blob_algorithm": "blake3",
        "blob_digest": capture.blob_blake3(),
        "blob_relative_path": capture.blob_relative_path(),
    }))?;

    let sealed_sha256_hex = summary.sealed_sha256.hex();
    let context_digest_hex = source_facts::context_digest(&parser_context_value)
        .map_err(SourceIngestError::Verify)?
        .hex();
    // The original scan-root path, for identity element 4. Validating (and
    // discarding) it here keeps a non-UTF-8 root a refusal rather than a lossy
    // identity.
    let scan_root_text = path_text_required(&descriptor.scan_root)?;

    let declaration = SourceInputDeclaration {
        identity_tuple: vec![
            Some("cass.source-input/2".to_string()),
            Some(request.identity_namespace.to_string()),
            Some(descriptor.origin.origin.source_id.clone()),
            Some(descriptor.connector.clone()),
            // Identity element 4 is the **original scan-root path**, and the
            // storage field it is checked against is spelled `root_id`. The
            // two names disagree: the declaration's `root_id` carries the
            // scan-root string here (the fixed storage interface reads that
            // field straight into this position), while the job's and the
            // root outcome's `root_id` stay the watermark/routing id
            // (`home:claude:...`). They are deliberately different values and
            // are never interchanged.
            Some(scan_root_text.clone()),
            Some(descriptor.relative_locator.clone()),
            Some(descriptor.role.as_str().to_string()),
            Some(format!("{}", descriptor.origin.origin.kind)),
            descriptor.origin.origin.host.clone(),
            descriptor.origin.source_version.clone(),
            descriptor.platform.map(|platform| format!("{platform}")),
            Some(context_digest_hex),
            Some(sealed_sha256_hex),
            Some(profile.normalizer_id.clone()),
            Some(profile.safety_contract_id.clone()),
        ],
        identity_namespace: request.identity_namespace.to_string(),
        source_id: descriptor.origin.origin.source_id.clone(),
        connector: descriptor.connector.clone(),
        origin_kind: Some(format!("{}", descriptor.origin.origin.kind)),
        origin_host: descriptor.origin.origin.host.clone(),
        origin_source_version: descriptor.origin.source_version.clone(),
        role: Some(descriptor.role.as_str().to_string()),
        platform: descriptor.platform.map(|platform| format!("{platform}")),
        // The declaration's `root_id` field is the value checked against
        // identity element 4, i.e. the original scan root. The job and the
        // root outcome keep `meta.root_id` as the watermark/routing id.
        root_id: scan_root_text,
        relative_locator: descriptor.relative_locator.clone(),
        discovery: discovery_value,
        parser_context: parser_context_value,
        sealed_ref: sealed_ref_value,
        format,
        normalizer_id: profile.normalizer_id.clone(),
        safety_contract_id: profile.safety_contract_id.clone(),
    };

    // The independent verifier re-measures the same handle; the declaration is
    // checked against that second measurement, not the first.
    let reader = BufReader::new(reader_at_start(capture.file())?);
    let (input, recheck) = source_facts::VerifiedSourceInput::verify_reader(
        declaration,
        reader,
        request.safety.config(),
    )
    .map_err(SourceIngestError::Verify)?;
    if recheck.sealed_sha256 != summary.sealed_sha256
        || recheck.records != summary.records
        || recheck.blank_lines != summary.blank_lines
        || recheck.framing_sha256 != summary.framing_sha256
    {
        return Err(SourceIngestError::Capture {
            detail: "the sealed input changed between the two independent measurements".to_string(),
        });
    }

    Ok(VerifiedSourceMaterials {
        input,
        profile,
        parser_context,
        summary,
    })
}

/// Everything one sealed preparation needs from its caller.
///
/// The capture and the verified handle must come from the same
/// `open_verified_capture` call; the root, descriptor, parser context and
/// namespace must describe the same declaration. That pairing is an internal
/// precondition of this narrow entry, not a second manifest: the shared entry
/// never re-opens, re-captures or re-validates the caller's material.
///
/// Deliberately not `Debug`: it borrows a descriptor and a parser context that
/// carry the original path and the configuration material.
pub(crate) struct SealedSourceInputRequest<'a> {
    pub(crate) connector_name: &'static str,
    pub(crate) data_dir: &'a Path,
    pub(crate) root: &'a crate::connectors::ScanRoot,
    /// The watermark/routing identity. Never the scan-root text and never the
    /// namespace.
    pub(crate) root_id: &'a str,
    /// The machine identity the declaration and the sealed context carry.
    pub(crate) identity_namespace: &'a str,
    pub(crate) descriptor: &'a fad::SourceInputDescriptor,
    pub(crate) parser_context: &'a fad::SourceParserContext,
    pub(crate) capture: &'a crate::raw_mirror::RawMirrorCaptureRecord,
    pub(crate) verified: &'a crate::raw_mirror::VerifiedRawMirrorCapture,
    pub(crate) safety: &'a Arc<FixedSafetyConfig>,
}

/// Build one sealed `SourceInputJob` from an already verified capture.
///
/// This is the shared tail an ordinary ingest and any later recovery adapter
/// consume. It derives the blob locator, the transport digest and the capture's
/// own original path from the verified handle. It never reads the live source,
/// never discovers or loads a configuration, never captures or opens a blob a
/// second time, and never writes to the database.
pub(crate) fn prepare_sealed_source_input(
    connector: &(dyn crate::connectors::Connector + Send),
    request: &SealedSourceInputRequest<'_>,
) -> Result<SourceInputJob, SourceIngestError> {
    // The material factory borrows the fixed configuration itself; the caller
    // keeps the shared handle for the job this entry builds.
    let fixed_safety: &FixedSafetyConfig = request.safety;
    let materials = verify_source_input_materials(&SourceInputMaterialRequest {
        cass_connector: request.connector_name,
        identity_namespace: request.identity_namespace,
        descriptor: request.descriptor,
        parser_context: request.parser_context,
        capture: request.verified,
        safety: fixed_safety,
    })?;
    let VerifiedSourceMaterials { input, profile, parser_context, summary } = materials;
    // The verified input's own manifest is the downstream authority for the
    // format: nothing past this point re-derives it from the connector.
    let format = input.manifest().format();

    let blob_path = request
        .data_dir
        .join("raw-mirror")
        .join("v1")
        .join(request.verified.blob_relative_path());
    let blob_blake3 = request.verified.blob_blake3().to_string();

    // The pinned connector reads the sealed locator itself. Point it at the
    // managed blob, never at the live source and never at a scratch copy.
    let sealed = fad::SealedInputContext {
        input_key: fad::Sha256Digest::of(b""),
        identity_namespace: request.identity_namespace.to_string(),
        parser_context_digest: parser_context
            .digest()
            .map_err(|kind| SourceIngestError::Verify(SourceInstallError::Activation {
                detail: format!("parser context digest: {kind:?}"),
            }))?,
        content_digest: fad::ContentDigest::of(&[]),
        byte_len: summary.byte_len,
        format: source_format_to_fad(format),
        normalizer_id: profile.normalizer_id.clone(),
        safety_contract_id: profile.safety_contract_id.clone(),
        sealed_locator: blob_path.clone(),
        sealed_ref: fad::SealedSourceRef {
            transport: "raw_blob".to_string(),
            blob_algorithm: Some("blake3".to_string()),
            blob_digest: Some(blob_blake3.clone()),
            blob_relative_path: Some(request.verified.blob_relative_path().to_string()),
        },
        expected_manifest: fad::SourceExpectedManifest {
            verifier_version: "cass.source-verifier/1".to_string(),
            format: source_format_to_fad(format),
            records: summary.records,
            blank_lines: summary.blank_lines,
            blank_bytes: summary.blank_bytes,
            framing_sha256: source_facts_digest_to_fad(&summary.framing_sha256),
            complete: true,
        },
        discovery: request.descriptor.clone(),
        parser_context: parser_context.clone(),
    };
    let sealed = rebind_sealed_identity(sealed, &summary.sealed_sha256)?;

    let mut sink = Pass1Sink::default();
    let mut finish = connector
        .scan_source_aware(&sealed, &mut sink)
        .map_err(|failure| SourceIngestError::Read {
            detail: format!("{:?}", failure.kind),
        })?;
    let (mut records, conversations, _diagnostics) = sink.finish()?;
    // A test may tamper the read result *here*, before any validation, so the
    // gates below are what refuse it. The sealed bytes and the independent
    // manifest are untouched.
    #[cfg(test)]
    if let Some(mut tamper) = test_hooks::take_after_read() {
        tamper(&mut records, &mut finish);
    }

    // What the connector delivered must be what it reported: a read that hands
    // over fewer records than its own finish counted is not a shorter input,
    // it is a lost one.
    if u64::try_from(records.len()).unwrap_or(u64::MAX) != finish.records_seen {
        return Err(SourceIngestError::Capture {
            detail: format!(
                "the read delivered {} records but reported {}",
                records.len(),
                finish.records_seen
            ),
        });
    }

    // The connector's own finish must agree with the independent expectation.
    if !finish.reached_eof
        || finish.bytes_read != summary.byte_len
        || finish.records_seen != summary.records
        || finish.blank_lines != summary.blank_lines
        || finish.content_digest.value.to_string() != summary.sealed_sha256.hex()
    {
        return Err(SourceIngestError::Capture {
            detail: "the pinned read does not agree with the independent framing expectation"
                .to_string(),
        });
    }

    let byte_reservation = conversations
        .iter()
        .map(|item| conversation_text_bytes(&item.conversation))
        .sum();

    Ok(SourceInputJob {
        connector_name: request.connector_name,
        root_id: request.root_id.to_string(),
        data_dir: request.data_dir.to_path_buf(),
        safety: Arc::clone(request.safety),
        blob_path,
        blob_blake3,
        original_path: request.verified.original_path().to_string(),
        root: (*request.root).clone(),
        input,
        normalizer_id: profile.normalizer_id.clone(),
        safety_contract_id: profile.safety_contract_id.clone(),
        capture: request.capture.clone(),
        finish,
        records,
        conversations,
        byte_reservation,
    })
}

/// Capture, verify and project one sealed input. Structure only.
pub(crate) fn prepare_source_input(
    connector: &(dyn crate::connectors::Connector + Send),
    request: &SourceInputRequest<'_>,
) -> Result<SourceInputJob, SourceIngestError> {
    let SourceInputRequest { connector_name, data_dir, root, meta, discovered, safety } = request;
    safety.recheck_bytes()?;

    let role = fad::SourceInputRole::try_from(discovered.role)
        .map_err(|_| SourceIngestError::Capture {
            detail: format!("role {:?} has no sealed-input equivalent", discovered.role),
        })?;

    // The same guard the legacy capture applies: a discovered file that does
    // not resolve inside its own scan root is never sealed.
    if let Err(reason) = crate::indexer::validate_discovered_source_path(discovered) {
        return Err(SourceIngestError::Capture { detail: reason.to_string() });
    }

    // Capture first: the sealed bytes must exist before anything reads them.
    let capture = crate::raw_mirror::capture_source_file_with_identity(
        crate::raw_mirror::RawMirrorCaptureInput {
            data_dir,
            provider: connector_name,
            source_id: &discovered.origin.source_id,
            origin_kind: discovered.origin.kind.as_str(),
            origin_host: discovered.origin.host.as_deref(),
            source_path: &discovered.source_path,
            db_links: &[],
        },
        crate::raw_mirror::RawMirrorSessionIdentity {
            // The raw mirror's session identity is the *legacy* constant, not
            // the source namespace. A manifest's key does not carry this field,
            // so a file the legacy paths already captured is the same capture:
            // re-capturing it under the source namespace would be refused
            // (`E-MANIFEST-SESSION-KEY-CONFLICT`) instead of merged, and a tree
            // the legacy path has ever scanned could never migrate to the
            // source kernel.
            //
            // Three values live in this function and none may stand in for
            // another: `identity_host` (below) is the declaration's namespace
            // and stays `meta.origin_host` -- the machine identity; the scan
            // root text is the original root path; and `meta.root_id` is the
            // routing id. This capture field is a fourth, older thing: it is
            // what the raw mirror records *about the session*, and it keeps the
            // value every pre-existing capture of the same file used.
            identity_host: crate::raw_mirror::RAW_MIRROR_LOCAL_IDENTITY_HOST,
            external_id: None,
        },
    )
    // The raw-mirror capture's own reason is carried through: the guard that
    // refuses a capture (a manifest whose recorded session identity disagrees,
    // a source that is no longer the file that was stat'ed) is exactly the
    // fact an operator needs, and a bare "could not be captured" sends them to
    // the raw mirror's internals to find it again.
    .map_err(|error| SourceIngestError::Capture {
            detail: format!("the source could not be captured into the raw mirror: {error:#}"),
        })?;

    #[cfg(test)]
    if let Some(mutate) = test_hooks::take_after_capture() {
        mutate(&test_hooks::blob_path(data_dir, capture.blob_relative_path.as_str()));
    }

    let verified = crate::raw_mirror::open_verified_capture(data_dir, &capture)
        .map_err(|err| SourceIngestError::Capture { detail: err.code().to_string() })?;

    // Discovery and parser context, built once and shared by every consumer.
    // Validating (and discarding) the source path here is deliberate: a path
    // that is not UTF-8 cannot enter any identity, so the input is refused
    // before a capture is written.
    path_text_required(&discovered.source_path)?;
    let relative_locator = relative_locator_within(&discovered.scan_root, &discovered.source_path)?;
    // The namespace is the machine identity, exactly as the rest of ingest
    // spells it. Three values live on this path and none may stand in for
    // another: `identity_host` names the machine (tuple item 1, the
    // declaration and the sealed context), the original root path is tuple
    // item 4 and the declaration's `root_id` field (resolved inside the
    // material factory), and `meta.root_id` is the watermark/routing id, which
    // carries neither.
    let identity_host = crate::indexer::IngestIdentity::for_meta(meta).identity_host;
    let fad_connector = fad_connector_name(connector_name);
    let descriptor = fad::SourceInputDescriptor {
        connector: fad_connector.clone(),
        scan_root: discovered.scan_root.clone(),
        source_path: discovered.source_path.clone(),
        relative_locator: relative_locator.clone(),
        role,
        origin: fad::SourceOrigin {
            origin: discovered.origin.clone(),
            source_version: None,
        },
        platform: discovered.platform,
        size_bytes: discovered.size_bytes,
        modified_at_ms: discovered.modified_at_ms,
    };
    let parser_context = fad::SourceParserContext {
        schema: "cass.source-parser-context/1".to_string(),
        connector: fad_connector,
        roots: vec![fad::SourceParserRoot {
            path: discovered.scan_root.clone(),
            origin: fad::SourceOrigin {
                origin: discovered.origin.clone(),
                source_version: None,
            },
            platform: discovered.platform,
            // The effective mapping from the configuration, never an empty
            // placeholder: this is what makes a mapping change move the profile.
            workspace_rewrites: root.workspace_rewrites.clone(),
        }],
        relative_locator: relative_locator.clone(),
        role,
        effective_config_digest: None,
    };
    // One factory builds the profile, the declaration, the sealed framing
    // measurement and the verified input. The shared entry keeps what surrounds
    // it: the caller's capture/verified pair, the sealed FAD context and the
    // job. This call is the only difference between the ordinary path and a
    // later recovery adapter.
    prepare_sealed_source_input(
        connector,
        &SealedSourceInputRequest {
            connector_name,
            data_dir,
            root,
            root_id: meta.root_id.as_str(),
            identity_namespace: &identity_host,
            descriptor: &descriptor,
            parser_context: &parser_context,
            capture: &capture,
            verified: &verified,
            safety,
        },
    )
}

fn rebind_sealed_identity(
    mut sealed: fad::SealedInputContext,
    sealed_sha256: &Sha256Digest,
) -> Result<fad::SealedInputContext, SourceIngestError> {
    let content = fad::ContentDigest {
        algorithm: fad::DigestAlgorithm::Sha256,
        value: fad::Sha256Digest::from_hex(&sealed_sha256.hex()).map_err(|_| {
            SourceIngestError::Capture { detail: "the sealed digest is not a sha256".to_string() }
        })?,
    };
    sealed.content_digest = content.clone();
    sealed.input_key = sealed
        .identity_for(content)
        .map_err(|kind| SourceIngestError::Capture {
            detail: format!("sealed identity: {kind:?}"),
        })?;
    Ok(sealed)
}

/// The pinned connector's own name for a CASS connector.
///
/// The discovery and parser-context connector is checked by the connector
/// itself (`claude_code`, `codex`), while CASS registers Claude under `claude`.
/// One mapping, so the two names cannot drift apart between the descriptor and
/// the parser context.
pub(crate) fn fad_connector_name(cass_name: &str) -> String {
    match cass_name {
        "claude" => "claude_code".to_string(),
        other => other.to_string(),
    }
}

/// The one capability predicate every source-aware dispatch site asks.
///
/// It answers for the **scheduling slug** (`claude`, `codex`) -- the name a
/// caller holds at its own dispatch point. The storage name (`claude_code`) is
/// what [`fad_connector_name`] derives from that slug for discovery and parser
/// contexts; it is never the value tested here, so the two names cannot drift
/// into each other and the database keeps its own spelling.
///
/// Only these two connectors implement the sealed read (`scan_source_aware`);
/// every other connector inherits the trait's explicit `Unsupported` failure.
/// A caller that skipped this predicate would therefore push a connector that
/// has no sealed read onto the source path, where it can only fail the root --
/// and, on the plan and completion-evidence side, would demand a source receipt
/// from a connector that never writes one.
pub(crate) fn supports_source_fidelity(connector_name: &str) -> bool {
    matches!(connector_name, "claude" | "codex")
}

/// An independent reader over the verified capture, positioned at the start.
///
/// `File::try_clone` duplicates the descriptor, and a duplicated descriptor
/// shares one file offset with the original: reading one clone moves every
/// other handle. Each reader therefore seeks back to the start before it
/// reads, or the second pass would see an empty file.
fn reader_at_start(
    file: &std::fs::File,
) -> Result<std::fs::File, SourceIngestError> {
    let mut handle = file.try_clone().map_err(|_| SourceIngestError::Capture {
        detail: "the verified capture handle could not be duplicated".to_string(),
    })?;
    handle
        .seek(SeekFrom::Start(0))
        .map_err(|_| SourceIngestError::Capture {
            detail: "the verified capture handle could not be rewound".to_string(),
        })?;
    Ok(handle)
}

/// The physical format of a sealed input, chosen once per input.
///
/// The decision reads two facts and nothing else: the CASS scheduling slug and
/// the extension of the path the connector originally discovered. It never
/// looks at content, never at the capture's own `.raw` spelling, and has no
/// configuration switch.
///
/// The extension table is closed. `claude` publishes whole JSON documents as
/// `.json` and `.claude`; `codex` publishes them as `rollout-*.json`. `jsonl`
/// stays line-oriented for both, and every other suffix, every suffixless
/// file and every other connector keeps the historical JSONL default. The
/// comparison ignores ASCII case, because the pinned discovery already does
/// for codex and a case-sensitive reader here would disagree with the file
/// that was found.
fn sealed_format_for(connector_name: &str, source_path: &Path) -> SourceFormat {
    let Some(extension) = source_path.extension().and_then(std::ffi::OsStr::to_str) else {
        return SourceFormat::Jsonl;
    };
    let document = match connector_name {
        "claude" => {
            extension.eq_ignore_ascii_case("json") || extension.eq_ignore_ascii_case("claude")
        }
        "codex" => extension.eq_ignore_ascii_case("json"),
        _ => false,
    };
    if document {
        SourceFormat::JsonDocument
    } else {
        SourceFormat::Jsonl
    }
}

fn source_format_to_fad(format: SourceFormat) -> fad::SourceFormat {
    match format {
        SourceFormat::Jsonl => fad::SourceFormat::Jsonl,
        SourceFormat::JsonDocument => fad::SourceFormat::JsonDocument,
    }
}

fn source_facts_digest_to_fad(digest: &Sha256Digest) -> fad::Sha256Digest {
    fad::Sha256Digest::from_hex(&digest.hex()).expect("a sha256 hex round-trips")
}

/// One structural event of one record, beside the document element it came
/// from.
struct RecordEvent {
    /// The index of the document element this event was read from. `None` for a
    /// JSONL record, whose whole frame is that one entry.
    element: Option<usize>,
    event: crate::indexer::exclusion::RawEvent,
}

/// The structural events one record yields, for the format it was declared in.
///
/// The two formats put a different amount of input in one record. A JSONL
/// record is one entry, so the pinned per-record core answers for it directly.
/// A document record is the whole file, so it answers per element of the array
/// its connector projects its messages from: one event per element, in the
/// element's own order, so a claim is served by the event of the element its
/// own source block pointer names.
fn structural_events_for_record(
    fad_name: &str,
    format: SourceFormat,
    json: &serde_json::Value,
    ordinal: u64,
) -> Vec<RecordEvent> {
    use crate::indexer::exclusion::{
        claude_code_events_for_value, codex_events_for_value,
    };

    if format == SourceFormat::Jsonl {
        let events = match fad_name {
            "claude_code" => claude_code_events_for_value(json, ordinal as usize),
            "codex" => codex_events_for_value(json, ordinal as usize),
            _ => Vec::new(),
        };
        return events
            .into_iter()
            .map(|event| RecordEvent { element: None, event })
            .collect();
    }

    let elements = match fad_name {
        "claude_code" => json.get("messages").and_then(serde_json::Value::as_array),
        "codex" => json.get("items").and_then(serde_json::Value::as_array),
        _ => None,
    };
    let Some(elements) = elements else { return Vec::new() };

    elements
        .iter()
        .enumerate()
        .map(|(index, element)| RecordEvent {
            element: Some(index),
            event: document_element_event(fad_name, element, index),
        })
        .collect()
}

/// The structural event of one element of a document.
///
/// The element's own fields are read exactly as the document projection reads
/// them - claude takes `role` and then `type`, and `content` and then `text`;
/// codex takes `role` and `content` - and are handed to the same per-record core
/// the JSONL path uses, which is what classifies the element's content blocks
/// for the anchor rules.
///
/// The core answers for the entry shape it knows, prose in a `user`/`assistant`
/// role. The document projection is wider than that: it also projects, for
/// instance, a `text`-only or role-less element, as it does any element whose
/// flattened content is not empty. Such an element still becomes a message, so
/// it still gets an event here - an event with no blocks, keyed by the
/// element's own identifier when it has one and by its position inside the
/// document otherwise. It carries no anchors instead of a guess, which is the
/// direction the exclusion rules already take when a fact is missing.
fn document_element_event(
    fad_name: &str,
    element: &serde_json::Value,
    index: usize,
) -> crate::indexer::exclusion::RawEvent {
    use crate::indexer::exclusion::{
        RawEvent, claude_code_events_for_value, codex_events_for_value,
    };

    let role = match fad_name {
        "claude_code" => element
            .get("role")
            .or_else(|| element.get("type"))
            .and_then(serde_json::Value::as_str),
        "codex" => element.get("role").and_then(serde_json::Value::as_str),
        _ => None,
    };
    let content = match fad_name {
        "claude_code" => element.get("content").or_else(|| element.get("text")),
        "codex" => element.get("content"),
        _ => None,
    };
    let content = content.cloned().unwrap_or(serde_json::Value::Null);
    let role = role.unwrap_or("");

    let entry = match fad_name {
        "claude_code" => serde_json::json!({
            "type": role,
            "message": {"role": role, "content": content},
        }),
        "codex" => serde_json::json!({
            "type": "response_item",
            "payload": {"type": "message", "role": role, "content": content},
        }),
        _ => serde_json::Value::Null,
    };
    let classified = match fad_name {
        "claude_code" => claude_code_events_for_value(&entry, index).into_iter().next(),
        "codex" => codex_events_for_value(&entry, index).into_iter().next(),
        _ => None,
    };

    RawEvent {
        event_key: element
            .get("uuid")
            .or_else(|| element.get("id"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("element:{index}")),
        blocks: classified.map_or_else(Vec::new, |event| event.blocks),
    }
}

/// The structural event one claim is served by.
///
/// A JSONL record answers for its single entry, which is what it has always
/// done. A document record answers per element: the claim's own source block
/// pointer names the element it was projected from (`/messages/3`,
/// `/items/3`), so the events of that element are the ones that describe it.
fn event_for_claim<'a>(
    format: SourceFormat,
    events: &'a [RecordEvent],
    claim: &fad::SourceMappingClaim,
) -> Option<&'a crate::indexer::exclusion::RawEvent> {
    match format {
        SourceFormat::Jsonl => events.first().map(|record| &record.event),
        SourceFormat::JsonDocument => {
            let element = document_element_of(claim)?;
            events
                .iter()
                .find(|record| record.element == Some(element))
                .map(|record| &record.event)
        }
    }
}

/// The element index a record pointer names (`/messages/3`, `/items/3`).
fn document_element_index(pointer: &str) -> Option<usize> {
    pointer.rsplit('/').next()?.parse().ok()
}

/// The element a document claim was projected from.
///
/// The claim's own `projection_pointer` is the *message* index inside the
/// projected conversation (`/messages/{idx}`, set by the pinned
/// `push_message` for every connector), which is not the element it came from.
/// The pointer that names the element inside the record is the claim's source
/// block pointer: `/messages/{i}` for a claude document and `/items/{i}` for a
/// codex one.
fn document_element_of(claim: &fad::SourceMappingClaim) -> Option<usize> {
    claim
        .source_block_pointers
        .first()
        .and_then(|pointer| document_element_index(pointer.as_str()))
}

/// The subtree a record pointer addresses, for surgery that must stay inside
/// one element.
fn document_element_mut<'a>(
    root: &'a mut fad::LosslessSourceValue,
    pointer: &str,
) -> Option<&'a mut fad::LosslessSourceValue> {
    let steps = parse_json_pointer(pointer).ok()?;
    let mut node = root;
    for step in steps {
        node = match (&mut *node, step) {
            (fad::LosslessSourceValue::Object(members), PointerStep::Key(key)) => members
                .iter_mut()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value)?,
            (fad::LosslessSourceValue::Array(items), PointerStep::Index(index)) => {
                items.get_mut(index)?
            }
            (fad::LosslessSourceValue::Array(items), PointerStep::Key(key)) => {
                items.get_mut(key.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(node)
}

/// The scope one excluded body's clearing stays inside.
///
/// A JSONL record is the entry, so its whole frame is the body's own range.
/// A document record holds every element of the document at once, so the scope
/// is the element this message was projected from, named by the claim's own
/// source block pointer.
fn excluded_body_pointer(format: SourceFormat, claim: &fad::SourceMappingClaim) -> Option<String> {
    match format {
        SourceFormat::Jsonl => None,
        SourceFormat::JsonDocument => claim
            .source_block_pointers
            .first()
            .map(|pointer| pointer.as_str().to_string()),
    }
}

/// The exclusion field map the commit clears a message `extra` through, for the
/// shape this input's messages were projected from.
///
/// A JSONL entry is an envelope around the content the rules address: codex
/// keeps it under `payload`, claude under `message`. A document element *is*
/// the message the projection reads - codex reads `role` and `content` from the
/// element itself, claude reads `role`/`type` and `content`/`text` - and the
/// `extra` a document message carries is that element. Addressing such an
/// `extra` through the envelope paths would match no key at all, and
/// [`apply_path`] silently does nothing when a path is absent, so the excluded
/// body would stay in the canonical store.
///
/// The document tables are therefore built from the body sources the document
/// projections actually render, not by stripping the envelope prefix off the
/// JSONL table: a field the document projection never consumes (`payload.output`
/// and friends for codex, `toolUseResult` for claude) stays untouched even
/// though its name matches a JSONL entry field, because clearing it would
/// delete data the connector never read as a body.
///
/// [`apply_path`]: crate::indexer::exclusion
fn extra_field_map(
    agent_slug: &str,
    format: SourceFormat,
) -> crate::indexer::exclusion::ExtraFieldMap {
    if format == SourceFormat::Jsonl {
        return crate::indexer::exclusion::field_map_for(agent_slug);
    }
    match agent_slug {
        "claude_code" => CLAUDE_DOCUMENT_EXTRA_FIELDS,
        "codex" => CODEX_DOCUMENT_EXTRA_FIELDS,
        _ => &[],
    }
}

/// Claude's document elements carry the body the projection renders under
/// `content` (a string, or an array of blocks whose own `text` is the body),
/// and under `text` when `content` is absent. Nothing else is addressed: the
/// JSONL-only entry fields (`toolUseResult`) are not part of what a document
/// projection consumes, so clearing them would delete data the connector never
/// read as a body.
const CLAUDE_DOCUMENT_EXTRA_FIELDS: &[&str] = &["content[*].text", "content", "text"];

/// Codex's document items carry the body the projection renders under
/// `content` alone - a string, or an array of blocks whose own `text` is the
/// body. `output`, `arguments`, `input` and `message` are not read by the
/// document projection at all, so they stay untouched even though the JSONL
/// envelope's field map addresses them.
const CODEX_DOCUMENT_EXTRA_FIELDS: &[&str] = &["content[*].text", "content"];

fn path_text_required(path: &Path) -> Result<String, SourceIngestError> {
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| SourceIngestError::Capture {
            detail: "a source path that is not valid UTF-8 cannot be sealed".to_string(),
        })
}

fn relative_locator_within(root: &Path, path: &Path) -> Result<String, SourceIngestError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| SourceIngestError::Capture {
            detail: "the discovered source is outside its scan root".to_string(),
        })?;
    let text = path_text_required(relative)?;
    if text.is_empty() || text.starts_with('/') {
        return Err(SourceIngestError::Capture {
            detail: "the relative locator is not a clean relative path".to_string(),
        });
    }
    Ok(text)
}

fn lossless_from_value(
    value: &serde_json::Value,
) -> Result<fad::LosslessSourceValue, SourceIngestError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| SourceIngestError::Config {
            detail: "a decrypted context value could not be re-encoded".to_string(),
        })?;
    fad::LosslessSourceValue::parse(&bytes).map_err(|diagnostic| SourceIngestError::Config {
        detail: format!("lossless conversion failed: {}", diagnostic.code),
    })
}

fn conversation_text_bytes(conversation: &crate::connectors::NormalizedConversation) -> usize {
    conversation
        .messages
        .iter()
        .map(|message| message.content.len().saturating_add(64))
        .sum()
}

// ---------------------------------------------------------------------------
// Lossless record surgery
// ---------------------------------------------------------------------------

/// One step of a JSON pointer into a source record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PointerStep {
    Key(String),
    Index(usize),
}

/// Parse a JSON pointer into steps. `""` is the whole document.
pub(crate) fn parse_json_pointer(pointer: &str) -> Result<Vec<PointerStep>, SourceIngestError> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let body = pointer.strip_prefix('/').ok_or_else(|| SourceIngestError::Capture {
        detail: "a record pointer must be empty or start with '/'".to_string(),
    })?;
    let mut steps = Vec::new();
    for raw in body.split('/') {
        let mut text = String::with_capacity(raw.len());
        let mut chars = raw.chars();
        while let Some(ch) = chars.next() {
            if ch == '~' {
                match chars.next() {
                    Some('0') => text.push('~'),
                    Some('1') => text.push('/'),
                    _ => {
                        return Err(SourceIngestError::Capture {
                            detail: "a record pointer has an invalid escape".to_string(),
                        });
                    }
                }
            } else {
                text.push(ch);
            }
        }
        // A purely numeric component addresses an array element; anything else
        // addresses an object member by name.
        match text.parse::<usize>() {
            Ok(index) if text == index.to_string() => steps.push(PointerStep::Index(index)),
            _ => steps.push(PointerStep::Key(text)),
        }
    }
    Ok(steps)
}

/// The index path a pointer addresses, resolved against the tree it names.
fn resolve_index_path(
    root: &fad::LosslessSourceValue,
    steps: &[PointerStep],
) -> Option<Vec<source_facts::IndexStep>> {
    let mut node = root;
    let mut path = Vec::with_capacity(steps.len());
    for step in steps {
        match (node, step) {
            (fad::LosslessSourceValue::Object(members), PointerStep::Key(key)) => {
                let index = members.iter().position(|(name, _)| name == key)?;
                path.push(source_facts::IndexStep::ObjectMember(index as u64));
                node = &members[index].1;
            }
            (fad::LosslessSourceValue::Array(items), PointerStep::Index(index)) => {
                path.push(source_facts::IndexStep::ArrayElement(*index as u64));
                node = items.get(*index)?;
            }
            (fad::LosslessSourceValue::Array(items), PointerStep::Key(key)) => {
                let index = key.parse::<usize>().ok()?;
                path.push(source_facts::IndexStep::ArrayElement(index as u64));
                node = items.get(index)?;
            }
            _ => return None,
        }
    }
    Some(path)
}

/// Replace the subtree a pointer addresses with `placeholder`, returning what
/// was removed.
fn clear_pointer(
    root: &mut fad::LosslessSourceValue,
    steps: &[PointerStep],
    placeholder: &fad::LosslessSourceValue,
) -> Option<fad::LosslessSourceValue> {
    if steps.is_empty() {
        return Some(std::mem::replace(root, placeholder.clone()));
    }
    let (head, tail) = steps.split_first()?;
    match (root, head) {
        (fad::LosslessSourceValue::Object(members), PointerStep::Key(key)) => {
            let index = members.iter().position(|(name, _)| name == key)?;
            if tail.is_empty() {
                return Some(std::mem::replace(&mut members[index].1, placeholder.clone()));
            }
            clear_pointer(&mut members[index].1, tail, placeholder)
        }
        (fad::LosslessSourceValue::Array(items), step) => {
            let index = match step {
                PointerStep::Index(index) => *index,
                PointerStep::Key(key) => key.parse::<usize>().ok()?,
            };
            let slot = items.get_mut(index)?;
            if tail.is_empty() {
                return Some(std::mem::replace(slot, placeholder.clone()));
            }
            clear_pointer(slot, tail, placeholder)
        }
        _ => None,
    }
}

/// Every non-empty string this subtree holds, in document order.
fn collect_strings(value: &fad::LosslessSourceValue, out: &mut Vec<String>, budget: &mut usize) {
    match value {
        fad::LosslessSourceValue::String(text) => {
            if !text.is_empty() && *budget > 0 {
                *budget -= 1;
                out.push(text.clone());
            }
        }
        fad::LosslessSourceValue::Array(items) => {
            for item in items {
                collect_strings(item, out, budget);
            }
        }
        fad::LosslessSourceValue::Object(members) => {
            for (_, item) in members {
                collect_strings(item, out, budget);
            }
        }
        fad::LosslessSourceValue::Number(_)
        | fad::LosslessSourceValue::Bool(_)
        | fad::LosslessSourceValue::Null => {}
    }
}

/// Clear every remaining copy of an excluded body inside one record.
///
/// Two shapes count, and only these two: a string that *is* the body or a
/// small wrapper around it ([`crate::indexer::exclusion::text_is_owned_body_copy`]),
/// and an array of text parts whose newline join reconstructs it. Everything
/// else is left byte-identical, so an unknown field or a numeric literal that
/// merely happens to sit near an excluded body is never touched.
fn sweep_body_copies(
    value: &mut fad::LosslessSourceValue,
    bodies: &[String],
    placeholder: &fad::LosslessSourceValue,
) {
    fn joined_text_parts(value: &fad::LosslessSourceValue) -> Option<String> {
        let fad::LosslessSourceValue::Array(items) = value else { return None };
        if items.is_empty() {
            return None;
        }
        let mut parts = Vec::with_capacity(items.len());
        for item in items {
            match item {
                fad::LosslessSourceValue::String(text) if !text.is_empty() => parts.push(text.clone()),
                fad::LosslessSourceValue::Object(members) => {
                    let text = members
                        .iter()
                        .find(|(name, _)| name == "text")
                        .and_then(|(_, value)| match value {
                            fad::LosslessSourceValue::String(text) => Some(text.clone()),
                            _ => None,
                        })?;
                    let kind_ok = members
                        .iter()
                        .find(|(name, _)| name == "type")
                        .is_none_or(|(_, value)| match value {
                            fad::LosslessSourceValue::String(kind) => {
                                matches!(kind.as_str(), "text" | "input_text" | "output_text")
                            }
                            fad::LosslessSourceValue::Null => true,
                            _ => false,
                        });
                    if !kind_ok || text.is_empty() {
                        return None;
                    }
                    parts.push(text);
                }
                _ => return None,
            }
        }
        Some(parts.join("\n"))
    }

    match value {
        fad::LosslessSourceValue::String(text) => {
            if bodies.iter().any(|body| crate::indexer::exclusion::text_is_owned_body_copy(text, body))
            {
                *value = placeholder.clone();
            }
        }
        fad::LosslessSourceValue::Array(_) => {
            if let Some(joined) = joined_text_parts(value)
                && bodies.iter().any(|body| crate::indexer::exclusion::text_is_owned_body_copy(&joined, body))
            {
                *value = placeholder.clone();
                return;
            }
            if let fad::LosslessSourceValue::Array(items) = value {
                for item in items {
                    sweep_body_copies(item, bodies, placeholder);
                }
            }
        }
        fad::LosslessSourceValue::Object(members) => {
            for (_, item) in members {
                sweep_body_copies(item, bodies, placeholder);
            }
        }
        fad::LosslessSourceValue::Number(_)
        | fad::LosslessSourceValue::Bool(_)
        | fad::LosslessSourceValue::Null => {}
    }
}

/// Map a claim's mapping state onto the storage enum. An unrecognized state is
/// not guessed into a neighbouring one.
fn claim_mapping_state(state: &str) -> Result<source_facts::ClaimMappingState, SourceIngestError> {
    match state {
        "canonical" => Ok(source_facts::ClaimMappingState::Canonical),
        "standalone" => Ok(source_facts::ClaimMappingState::Standalone),
        "unmapped" => Ok(source_facts::ClaimMappingState::Unmapped),
        other => Err(SourceIngestError::Sink {
            detail: format!("unknown claim mapping state {other:?}"),
        }),
    }
}

/// Map a claim's evidence kind onto the storage enum.
fn evidence_kind(kind: &str) -> Result<source_facts::EvidenceKind, SourceIngestError> {
    match kind {
        "prose" => Ok(source_facts::EvidenceKind::Prose),
        "tool_call" => Ok(source_facts::EvidenceKind::ToolCall),
        "tool_result" => Ok(source_facts::EvidenceKind::ToolResult),
        "reasoning" => Ok(source_facts::EvidenceKind::Reasoning),
        "no_message" => Ok(source_facts::EvidenceKind::NoMessage),
        "parse_failed" => Ok(source_facts::EvidenceKind::ParseFailed),
        other => Err(SourceIngestError::Sink {
            detail: format!("unknown evidence kind {other:?}"),
        }),
    }
}

/// Convert one pinned-connector claim into the storage claim, resolving its
/// source positions against the record the claim addresses.
fn storage_claim(
    input_key: &Sha256Digest,
    record_root: Option<&fad::LosslessSourceValue>,
    claim: &fad::SourceMappingClaim,
) -> Result<source_facts::SourceClaim, SourceIngestError> {
    let mut positions = Vec::with_capacity(claim.source_block_pointers.len());
    for pointer in &claim.source_block_pointers {
        let steps = parse_json_pointer(pointer.as_str())?;
        let index_path = record_root
            .and_then(|root| resolve_index_path(root, &steps))
            .unwrap_or_default();
        positions.push(source_facts::SafePosition {
            index_path,
            original_pointer_sha256: Sha256Digest::of(pointer.as_str().as_bytes()),
            safe_pointer: Some(pointer.as_str().to_string()),
        });
    }
    Ok(source_facts::SourceClaim {
        input_key: *input_key,
        record_ordinal: claim.record_ordinal,
        record_pointer: claim.record_pointer.clone(),
        conversation_ordinal: claim.conversation_ordinal,
        final_message_idx: claim.final_message_idx,
        positions,
        projection_pointer: claim.projection_pointer.clone(),
        evidence_kind: evidence_kind(&claim.evidence_kind)?,
        mapping_state: claim_mapping_state(&claim.mapping_state)?,
    })
}

/// The fields that identify one FAD declaration across its two conversions.
///
/// Everything the declaration itself carries is here: the input, the record
/// locator, the target triple, the evidence kind, the mapping state *and* the
/// declared source positions (`safe_pointer` and the pointer's own digest). The
/// one thing left out is `index_path`, which is not declared but derived -- the
/// record-level safety pass resolves it against the real safe tree, while the
/// conversation callback's claim has no root to resolve against -- so leaving it
/// out is what lets the install path hand the projection the safety pass's
/// authoritative claim instead of a second, less resolved conversion of the same
/// thing.
#[must_use]
fn claim_identity_key(claim: &source_facts::SourceClaim) -> Vec<u8> {
    let mut declaration = claim.clone();
    for position in &mut declaration.positions {
        position.index_path.clear();
    }
    // Use the existing canonical encoding so delimiters in pointers and null
    // fields cannot alias another declaration. This key is never persisted.
    declaration.encode_leaf()
}

/// The record-level mapping state, from the claims that addressed it.
fn record_mapping_state(claims: &[fad::SourceMappingClaim]) -> Result<source_facts::RecordMappingState, SourceIngestError> {
    if claims.is_empty() {
        return Ok(source_facts::RecordMappingState::NoClaims);
    }
    let mut canonical = false;
    let mut standalone = false;
    let mut unmapped = false;
    for claim in claims {
        match claim_mapping_state(&claim.mapping_state)? {
            source_facts::ClaimMappingState::Canonical => canonical = true,
            source_facts::ClaimMappingState::Standalone => standalone = true,
            source_facts::ClaimMappingState::Unmapped => unmapped = true,
        }
    }
    Ok(match (canonical, standalone, unmapped) {
        (true, false, false) => source_facts::RecordMappingState::AllCanonical,
        (false, true, false) => source_facts::RecordMappingState::AllStandalone,
        (false, false, true) => source_facts::RecordMappingState::AllUnmapped,
        _ => source_facts::RecordMappingState::Mixed,
    })
}

// ---------------------------------------------------------------------------
// Pass 2 and the one activation transaction
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Pass 2: per-record safety, attributed through the claims
// ---------------------------------------------------------------------------

/// What pass 2 produced: the records to stage, and the storage claims each
/// record carries.
struct Pass2Result {
    records: Vec<source_facts::VerifiedStagedRecord>,
    claims_by_ordinal: BTreeMap<u64, Vec<source_facts::SourceClaim>>,
    parse_failed: u64,
    diagnostics: u64,
}

/// One conversation's judged messages, ready to install.
struct JudgedConversation {
    /// The ordinal the pinned connector assigned this conversation.
    ordinal: u32,
    prepared: crate::indexer::exclusion::PreparedConversation,
    claims: Vec<fad::SourceMappingClaim>,
}

/// Everything pass 2 hands the transaction.
struct SafetyPass {
    staged: Pass2Result,
    judged: Vec<JudgedConversation>,
}

/// The text an array of content parts renders to, mirroring the connector's own
/// expansion: a bare string is itself, a text-ish block contributes its `text`,
/// and every other block kind contributes nothing. `None` when `value` is not
/// an array.
fn expanded_text(items: &[fad::LosslessSourceValue]) -> String {
    let mut parts = Vec::with_capacity(items.len());
    for item in items {
        match item {
            fad::LosslessSourceValue::String(text) if !text.is_empty() => parts.push(text.clone()),
            fad::LosslessSourceValue::Object(members) => {
                if let Some(text) = text_slot(members)
                    && !text.is_empty()
                {
                    parts.push(text.to_string());
                }
            }
            _ => {}
        }
    }
    parts.join("\n")
}

/// The `text` of a text-bearing block, or `None` when the object is not one.
///
/// A block qualifies when its `type` is absent or one of the text kinds: an
/// arbitrary object with a `text` member is not a registered text structure,
/// and its members are treated as unknown fields.
fn text_slot(members: &[(String, fad::LosslessSourceValue)]) -> Option<&str> {
    let kind_ok = members
        .iter()
        .find(|(name, _)| name == "type")
        .is_none_or(|(_, value)| match value {
            fad::LosslessSourceValue::String(kind) => {
                matches!(kind.as_str(), "text" | "input_text" | "output_text")
            }
            fad::LosslessSourceValue::Null => true,
            _ => false,
        });
    if !kind_ok {
        return None;
    }
    members
        .iter()
        .find(|(name, _)| name == "text")
        .and_then(|(_, value)| match value {
            fad::LosslessSourceValue::String(text) => Some(text.as_str()),
            _ => None,
        })
}

/// Walk one record subtree, counting (and, when `placeholder` is given,
/// clearing) every slot that carries an excluded body.
///
/// Two rules, deliberately narrow:
///
/// - a bare string counts only when it *is* the body. Unknown fields are not
///   matched with any slack, so a `note` that merely quotes the body is left
///   alone and later fails the residue check rather than being deleted.
/// - a registered text structure — a text-bearing block's `text`, or an array
///   of content parts whose expansion is the body — is matched under the
///   existing exact-or-bounded-wrapper rule, and only its text slot is
///   replaced. The surrounding array, the object and every other member
///   (`type`, `keep`, `usage`, ids, unknown fields) survive untouched.
fn walk_body_slots(
    value: &mut fad::LosslessSourceValue,
    bodies: &[String],
    placeholder: Option<&fad::LosslessSourceValue>,
) -> usize {
    match value {
        fad::LosslessSourceValue::String(text) => {
            if bodies.iter().any(|body| text == body) {
                if let Some(placeholder) = placeholder {
                    *value = placeholder.clone();
                }
                1
            } else {
                0
            }
        }
        fad::LosslessSourceValue::Array(items) => {
            let mut cleared = 0;
            let is_complete_copy = {
                let expanded = expanded_text(items);
                bodies.iter().any(|body| &expanded == body)
            };
            if is_complete_copy {
                // The array as a whole is the body: clear only the text slots.
                for item in items.iter_mut() {
                    if let fad::LosslessSourceValue::Object(members) = item {
                        let owned = text_slot(members).is_some();
                        if owned
                            && let Some((_, slot)) = members.iter_mut().find(|(name, _)| name == "text")
                        {
                            if let Some(placeholder) = placeholder {
                                *slot = placeholder.clone();
                            }
                            cleared += 1;
                        }
                    }
                }
            }
            for item in items.iter_mut() {
                cleared += walk_body_slots(item, bodies, placeholder);
            }
            cleared
        }
        fad::LosslessSourceValue::Object(members) => {
            let mut cleared = 0;
            let owned = text_slot(members)
                .map(|text| bodies.iter().any(|body| crate::indexer::exclusion::text_is_owned_body_copy(text, body)))
                .unwrap_or(false);
            if owned
                && let Some((_, slot)) = members.iter_mut().find(|(name, _)| name == "text")
            {
                if let Some(placeholder) = placeholder {
                    *slot = placeholder.clone();
                }
                cleared += 1;
            }
            for (_, item) in members.iter_mut() {
                cleared += walk_body_slots(item, bodies, placeholder);
            }
            cleared
        }
        fad::LosslessSourceValue::Number(_)
        | fad::LosslessSourceValue::Bool(_)
        | fad::LosslessSourceValue::Null => 0,
    }
}

/// Clear the text slots that carry an excluded body, reporting how many there
/// were. A body that survives everywhere is a failure, not a quiet pass.
/// One body an exclusion decision proved, with the scope its clearing stays in.
struct ExcludedBody {
    /// The document element this message was projected from, or `None` for a
    /// JSONL record, whose whole frame is the entry and therefore the scope.
    element_pointer: Option<String>,
    body: String,
}

fn sweep_body_copies_counted(
    value: &mut fad::LosslessSourceValue,
    body: &str,
    placeholder: &fad::LosslessSourceValue,
) -> usize {
    let bodies = [body.to_string()];
    walk_body_slots(value, &bodies, Some(placeholder))
}

/// The fixed refusal code for a registered source ID that equals the excluded
/// body it names. The detail carries neither the body, the ID nor a path.
const SOURCE_SAFETY_ID_BODY_CONFLICT: &str = "source_safety_id_body_conflict";

/// The five Codex document tool item names whose own `call_id` is a registered
/// identity slot. `document_element_event` does not copy `call_id`, so the raw
/// element is the only place this value can be read.
const CODEX_DOCUMENT_TOOL_TYPES: [&str; 5] = [
    "function_call",
    "custom_tool_call",
    "function_call_output",
    "custom_tool_call_output",
    "tool_call",
];

/// A registered ID only participates when its trimmed form is non-empty.
/// The comparison itself still uses the original, untrimmed bytes.
fn push_present_string_id(ids: &mut Vec<String>, value: &str) {
    if !value.trim().is_empty() {
        ids.push(value.to_string());
    }
}

fn push_fact_id(ids: &mut Vec<String>, fact: &source_facts::FieldFact) {
    if fact.status != source_facts::FactStatus::Present {
        return;
    }
    if let Some(source_facts::FactValue::String(value)) = &fact.value {
        push_present_string_id(ids, value);
    }
}

/// The registered IDs the two standard mappers expose for one JSONL record.
///
/// `cwd` is the one `native_ids` member the Codex mapper records with
/// `id=false`: it is a path, not an identity, so it stays out of the set.
/// Every remaining slot is an existence check, never a slot-name map, so a
/// duplicate value can neither change the answer nor hide another slot.
fn push_mapper_ids(ids: &mut Vec<String>, facts: &source_facts::StandardFacts) {
    for (name, fact) in &facts.native_ids {
        if name == "cwd" {
            continue;
        }
        push_fact_id(ids, fact);
    }
    for message in &facts.messages {
        for fact in message.ids.values() {
            push_fact_id(ids, fact);
        }
        for tool in &message.tools {
            if let Some(fact) = tool.fields.get("id") {
                push_fact_id(ids, fact);
            }
        }
    }
    for tool in &facts.tools {
        if let Some(fact) = tool.fields.get("id") {
            push_fact_id(ids, fact);
        }
    }
}

fn push_block_ids(ids: &mut Vec<String>, events: &[RecordEvent]) {
    for record in events {
        for block in &record.event.blocks {
            if let Some(id) = block.tool_use_id.as_deref() {
                push_present_string_id(ids, id);
            }
        }
    }
}

/// The registered IDs of one document element: its own `uuid`/`id` slot, the
/// five Codex tool types' raw `call_id`, and the element's classified blocks.
/// Sibling elements and generated `element:N` fallbacks are never read.
fn push_document_element_ids(
    ids: &mut Vec<String>,
    fad_name: &str,
    element: &serde_json::Value,
    events: &[RecordEvent],
    element_index: usize,
) {
    if let Some(id) = element
        .get("uuid")
        .or_else(|| element.get("id"))
        .and_then(serde_json::Value::as_str)
    {
        push_present_string_id(ids, id);
    }
    if fad_name == "codex"
        && element
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| CODEX_DOCUMENT_TOOL_TYPES.contains(&kind))
        && let Some(id) = element.get("call_id").and_then(serde_json::Value::as_str)
    {
        push_present_string_id(ids, id);
    }
    for record in events
        .iter()
        .filter(|record| record.element == Some(element_index))
    {
        for block in &record.event.blocks {
            if let Some(id) = block.tool_use_id.as_deref() {
                push_present_string_id(ids, id);
            }
        }
    }
}

/// True when any registered ID in this record's scope equals its excluded body.
///
/// The comparison is strict and untrimmed on both sides; an empty or
/// whitespace-only ID is not present and never participates. A JSONL record is
/// one frame, so its whole frame is the scope. A document record is narrowed to
/// the element the body was proven in, so a sibling element's same-valued ID
/// stays accepted. The values are read from the pre-sweep record and its
/// events; the stored `[REDACTED]` state is never an input.
fn id_body_conflict_in_record(
    fad_name: &str,
    format: SourceFormat,
    json: &serde_json::Value,
    value: Option<&fad::LosslessSourceValue>,
    events: &[RecordEvent],
    bodies: &[ExcludedBody],
) -> bool {
    if bodies.is_empty() {
        return false;
    }
    match format {
        SourceFormat::Jsonl => {
            let mut ids = Vec::new();
            if let Some(root) = value {
                match fad_name {
                    "claude_code" => {
                        push_mapper_ids(&mut ids, &source_facts::map_claude_standard(format, root));
                    }
                    "codex" => {
                        push_mapper_ids(&mut ids, &source_facts::map_codex_standard(format, root));
                    }
                    _ => return false,
                }
            }
            push_block_ids(&mut ids, events);
            bodies
                .iter()
                .any(|excluded| ids.iter().any(|id| id == &excluded.body))
        }
        SourceFormat::JsonDocument => bodies.iter().any(|excluded| {
            let Some(pointer) = excluded.element_pointer.as_deref() else {
                return false;
            };
            let Some(element) = json.pointer(pointer) else {
                return false;
            };
            let Some(element_index) = document_element_index(pointer) else {
                return false;
            };
            let mut ids = Vec::new();
            push_document_element_ids(&mut ids, fad_name, element, events, element_index);
            ids.iter().any(|id| id == &excluded.body)
        }),
    }
}

/// Read every record again through the verified handle, judge it, and build
/// the staged rows.
///
/// Attribution runs through the *claims*: a message is the one a claim proved
/// for that (conversation ordinal, final message index), and the structural
/// facts used to judge it come from that record's own bytes through the same
/// per-record core the legacy scanner uses. Nothing here aligns two lists by
/// position, and no event id stands in for a proven claim.
///
/// On the record side, only the text slots that actually carry an excluded body
/// are cleared. A claim proves the *range* a message came from; it is not a
/// licence to delete that range, which for Codex is the whole `/payload`
/// including `usage`, ids, call ids and unknown members. A body that cannot be
/// located in its own record fails that record.
fn safety_pass(
    job: &SourceInputJob,
    verified: &crate::raw_mirror::VerifiedRawMirrorCapture,
    paths_cfg: &crate::sources::config::ExcludedContextPaths,
) -> Result<SafetyPass, SourceIngestError> {
    use crate::indexer::exclusion::{Decision, ExcludedMarker, PairingContext};

    let fad_name = fad_connector_name(job.connector_name);
    // One mutable copy of each projected conversation: the judgment mutates
    // message content exactly as the legacy path does.
    let mut conversations: Vec<crate::connectors::NormalizedConversation> =
        job.conversations.iter().map(|item| item.conversation.clone()).collect();
    // The pinned read does not apply workspace rewrites, so this is the one
    // place they are applied -- with the same rules the legacy path uses, and
    // before anything derived from the workspace is written.
    for conversation in conversations.iter_mut() {
        crate::indexer::apply_workspace_rewrite(conversation, &job.root);
    }
    // The commit consumes the format the input was prepared and verified
    // under. It is the same value the declaration, the sealed context and the
    // expected manifest carry, so a commit can never re-frame an input that
    // was handed over as a document.
    let format = job.input.manifest().format();

    let pairing: Vec<PairingContext> = conversations
        .iter()
        .map(|conv| PairingContext::build(&crate::indexer::build_pairing_candidates(conv)))
        .collect();
    // The field map the exclusion decision clears *through* is the one for the
    // shape this input's messages were projected from, not only for the
    // connector: a document's message `extra` is the document element itself,
    // so the JSONL envelope paths would address nothing.
    let field_maps: Vec<_> = conversations
        .iter()
        .map(|conv| extra_field_map(&conv.agent_slug, format))
        .collect();
    let mut by_ordinal: BTreeMap<u32, usize> = BTreeMap::new();
    for (idx, item) in job.conversations.iter().enumerate() {
        by_ordinal.insert(item.ordinal, idx);
    }

    let mut reader = BufReader::new(reader_at_start(verified.file())?);
    let mut bytes_handle = reader_at_start(verified.file())?;
    let placeholder = fad::LosslessSourceValue::String("[REDACTED]".to_string());

    let mut records = Vec::with_capacity(job.records.len());
    let mut claims_by_ordinal: BTreeMap<u64, Vec<source_facts::SourceClaim>> = BTreeMap::new();
    let mut parse_failed = 0u64;
    let mut diagnostics_count = 0u64;
    let mut scanned = 0usize;
    let mut decisions: Vec<(usize, usize, u64, Decision)> = Vec::new();
    let mut bodies_by_ordinal: BTreeMap<u64, Vec<ExcludedBody>> = BTreeMap::new();

    let mut scan = source_facts::FramingStream::new(&mut reader, format);
    while !scan.is_done() {
        let page = scan
            .next_page_bounded(64, 8 * 1024 * 1024)
            .map_err(SourceIngestError::Verify)?;
        if page.is_empty() {
            break;
        }
        for frame in &page {
            let locator = frame.locator().clone();
            let plan = job
                .records
                .iter()
                .find(|record| {
                    record.ordinal == locator.ordinal
                        && record.locator.record_pointer == locator.record_pointer
                })
                .ok_or_else(|| SourceIngestError::Sink {
                    detail: format!("record ordinal {} was staged without a plan", locator.ordinal),
                })?;
            scanned += 1;

            let length = locator
                .byte_end
                .checked_sub(locator.byte_start)
                .ok_or_else(|| SourceIngestError::Capture {
                    detail: "a record locator ends before it starts".to_string(),
                })?;
            let mut raw = vec![0u8; usize::try_from(length).map_err(|_| SourceIngestError::Capture {
                detail: "a record is too large for this platform".to_string(),
            })?];
            // try_clone shares the OS cursor with the framing reader. Preserve
            // its buffered read-ahead position while re-reading this record.
            let framing_position = bytes_handle.stream_position().map_err(|_| {
                SourceIngestError::Capture {
                    detail: "the sealed framing position could not be read".to_string(),
                }
            })?;
            bytes_handle
                .seek(SeekFrom::Start(locator.byte_start))
                .and_then(|_| bytes_handle.read_exact(&mut raw))
                .and_then(|_| {
                    bytes_handle
                        .seek(SeekFrom::Start(framing_position))
                        .map(|_| ())
                })
                .map_err(|_| SourceIngestError::Capture {
                    detail: "a record could not be re-read from the sealed input".to_string(),
                })?;

            let observed = Sha256Digest::of(&raw);
            if observed != *frame.raw_sha256() || observed != source_facts_digest(&plan.record_sha256)
            {
                return Err(SourceIngestError::Capture {
                    detail: "a record's bytes changed between the passes".to_string(),
                });
            }

            let (mut value, parse_state) = match fad::LosslessSourceValue::parse(&raw) {
                Ok(value) => (Some(value), source_facts::ParseState::Parsed),
                Err(_) => {
                    parse_failed += 1;
                    (None, source_facts::ParseState::ParseFailed)
                }
            };

            // Structural facts for this record, from this record's own bytes
            // through the same per-record core the legacy scanner calls.
            //
            // A JSONL record is one entry, so the core answers for it directly.
            // A document record is a whole file whose projected messages come
            // from its own `messages`/`items` array, so the same core is applied
            // to each element in projection order, wrapped in the envelope the
            // equivalent JSONL entry would have carried. Each element is kept
            // beside the events it produced, so a claim is served by the events
            // of the element its own source block pointer names.
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&raw) {
                let events = structural_events_for_record(&fad_name, format, &json, locator.ordinal);
                for claim in plan.claims.iter().filter(|claim| claim.mapping_state == "canonical") {
                    let (Some(conv_ordinal), Some(message_idx)) =
                        (claim.conversation_ordinal, claim.final_message_idx)
                    else {
                        continue;
                    };
                    let Some(&conv_idx) = by_ordinal.get(&conv_ordinal) else {
                        return Err(SourceIngestError::Sink {
                            detail: format!(
                                "record {} claims conversation ordinal {conv_ordinal}, which was not projected",
                                locator.ordinal
                            ),
                        });
                    };
                    let Ok(msg_idx) = usize::try_from(message_idx) else { continue };
                    let Some(message) = conversations[conv_idx].messages.get(msg_idx) else {
                        continue;
                    };
                    let Some(event) = event_for_claim(format, &events, claim) else {
                        return Err(SourceIngestError::Sink {
                            detail: format!(
                                "record {} claims message {message_idx} but yields no structural event",
                                locator.ordinal
                            ),
                        });
                    };
                    if let Some(decision) = crate::indexer::exclusion::decide(
                        message,
                        msg_idx,
                        event,
                        &pairing[conv_idx],
                        &conversations[conv_idx].agent_slug,
                        paths_cfg,
                    ) {
                        bodies_by_ordinal
                            .entry(locator.ordinal)
                            .or_default()
                            .push(ExcludedBody {
                                element_pointer: excluded_body_pointer(format, claim),
                                body: message.content.clone(),
                            });
                        decisions.push((conv_idx, msg_idx, locator.ordinal, decision));
                    }
                }

                // A registered source ID that equals the body this record is
                // about to clear cannot be kept as an identity. Refuse the
                // whole input before any sweep, transaction or replay, so the
                // old wrong completion is not replayed and no stored byte moves.
                if bodies_by_ordinal
                    .get(&locator.ordinal)
                    .is_some_and(|bodies| {
                        id_body_conflict_in_record(
                            &fad_name,
                            format,
                            &json,
                            value.as_ref(),
                            &events,
                            bodies,
                        )
                    })
                {
                    return Err(SourceIngestError::Sink {
                        detail: SOURCE_SAFETY_ID_BODY_CONFLICT.to_string(),
                    });
                }
            }

            // A test may rewrite the bodies this record is about to be cleared
            // of. The hook is taken only for a record that really carries
            // bodies, so an earlier record without any cannot consume it.
            #[cfg(test)]
            if bodies_by_ordinal
                .get(&locator.ordinal)
                .is_some_and(|bodies| !bodies.is_empty())
                && let Some(mut tamper) = test_hooks::take_before_body_clear()
            {
                let bodies = bodies_by_ordinal
                    .get_mut(&locator.ordinal)
                    .expect("checked just above");
                tamper(locator.ordinal, bodies);
            }
            let mut exclusions_proved = true;
            if let Some(root) = value.as_mut()
                && let Some(bodies) = bodies_by_ordinal.get(&locator.ordinal)
            {
                for excluded in bodies {
                    let cleared = match excluded.element_pointer.as_deref() {
                        // The record is the entry, so its whole frame is the
                        // range this body was proven in.
                        None => sweep_body_copies_counted(root, &excluded.body, &placeholder),
                        // A document record holds every element at once, and
                        // two elements may carry the same text: sweeping the
                        // frame would take a sibling element's copy with it, so
                        // the clearing stays inside this body's own element.
                        Some(pointer) => document_element_mut(root, pointer).map_or(0, |element| {
                            sweep_body_copies_counted(element, &excluded.body, &placeholder)
                        }),
                    };
                    if cleared == 0 {
                        exclusions_proved = false;
                    }
                }
            }
            if !exclusions_proved {
                return Err(SourceIngestError::Sink {
                    detail: format!(
                        "an excluded body of record {} could not be located in that record",
                        locator.ordinal
                    ),
                });
            }

            let safe_value = match value.as_ref() {
                Some(root) => Some(
                    crate::indexer::redact_secrets::redact_lossless_source(root).map_err(|err| {
                        SourceIngestError::Install(SourceInstallError::Staging {
                            detail: format!("lossless redaction failed: {}", err.code()),
                        })
                    })?,
                ),
                None => None,
            };

            let claims = plan
                .claims
                .iter()
                .map(|claim| storage_claim(job.input.input_key(), safe_value.as_ref(), claim))
                .collect::<Result<Vec<_>, _>>()?;
            let mapping_state = record_mapping_state(&plan.claims)?;
            let diagnostics: Vec<source_facts::SafeDiagnostic> = plan
                .diagnostics
                .iter()
                .map(|diagnostic| source_facts::SafeDiagnostic {
                    code: diagnostic.code.clone(),
                    detail: None,
                    offset: None,
                    position: None,
                })
                .collect();
            diagnostics_count += diagnostics.len() as u64;
            claims_by_ordinal.insert(locator.ordinal, claims);

            records.push(source_facts::VerifiedStagedRecord::from_frame(
                frame,
                Some(observed),
                parse_state,
                mapping_state,
                source_facts::SafetyState::Preserved,
                None,
                safe_value,
                if diagnostics.is_empty() { None } else { Some(diagnostics) },
            ));
        }
    }

    if scanned != job.records.len() {
        return Err(SourceIngestError::Capture {
            detail: "the second pass covered a different number of records than the first".to_string(),
        });
    }

    // Apply the decisions the per-record pass proved, then the sibling pass for
    // rows that share a record but were not themselves excluded.
    let blob_label = job.blob_path.to_string_lossy().to_string();
    let mut redactor = crate::indexer::redact_secrets::MemoizingRedactor::new();
    let mut markers: Vec<Vec<Option<ExcludedMarker>>> = conversations
        .iter()
        .map(|conv| vec![None; conv.messages.len()])
        .collect();
    for (conv_idx, msg_idx, _, decision) in &decisions {
        let pre_redaction_content = conversations[*conv_idx].messages[*msg_idx].content.clone();
        let marker = crate::indexer::exclusion::apply_with_redaction(
            &mut conversations[*conv_idx].messages[*msg_idx],
            decision,
            &mut redactor,
            &blob_label,
            *msg_idx as u32,
            field_maps[*conv_idx],
            true,
        );
        if let Some(title) = conversations[*conv_idx].title.as_ref().filter(|t| !t.is_empty())
            && pre_redaction_content.contains(title.as_str())
        {
            conversations[*conv_idx].title = Some(String::new());
        }
        markers[*conv_idx][*msg_idx] = Some(marker);
    }
    // A JSONL record can project several messages from the one entry, and those
    // rows share that entry's blocks: the sibling pass clears the same event's
    // blocks in the rows that were not themselves excluded. A document element
    // projects exactly one message, so a document has no siblings to clear -
    // and the record ordinal alone cannot tell the two cases apart, because
    // every element of a document shares its record.
    if format == SourceFormat::Jsonl {
        for (conv_idx, msg_idx, record_ordinal, _) in &decisions {
            let Some(marker) = markers[*conv_idx][*msg_idx].clone() else { continue };
            for other in 0..conversations[*conv_idx].messages.len() {
                if other == *msg_idx {
                    continue;
                }
                let other_record = job.conversations[*conv_idx]
                    .claims
                    .iter()
                    .find(|claim| {
                        claim.final_message_idx == Some(other as i64)
                            && claim.mapping_state == "canonical"
                    })
                    .map(|claim| claim.record_ordinal);
                if other_record == Some(*record_ordinal) {
                    crate::indexer::exclusion::apply_sibling(
                        &mut conversations[*conv_idx].messages[other],
                        &marker,
                        field_maps[*conv_idx],
                    );
                }
            }
        }
    }

    let judged = job
        .conversations
        .iter()
        .enumerate()
        .map(|(idx, item)| JudgedConversation {
            ordinal: item.ordinal,
            prepared: crate::indexer::exclusion::PreparedConversation {
                conv: conversations[idx].clone(),
                excluded: markers[idx].clone(),
            },
            claims: item.claims.clone(),
        })
        .collect();

    Ok(SafetyPass {
        staged: Pass2Result {
            records,
            claims_by_ordinal,
            parse_failed,
            diagnostics: diagnostics_count,
        },
        judged,
    })
}

/// The storage-side digest type from a pinned-connector digest.
fn source_facts_digest(digest: &fad::Sha256Digest) -> Sha256Digest {
    Sha256Digest::from_hex(&digest.to_string()).expect("a sha256 hex round-trips")
}

/// Read one TEXT column out of `meta`.
fn meta_text(
    tx: &crate::storage::api::Tx<'_>,
    key: &str,
) -> Result<Option<String>, SourceIngestError> {
    tx.query_opt_map(
        "SELECT value FROM meta WHERE key = ?1",
        &[crate::storage::api::Value::Text(key.to_string())],
        |row| row.get_typed(0),
    )
    .map_err(|err| SourceIngestError::Install(SourceInstallError::Db(err)))
}

/// The activation request plus the semantic request digest it commits to.
struct ActivationPlan {
    request: source_facts::SourceActivationRequest,
    request_digest: Sha256Digest,
}

impl ActivationPlan {
    fn digest(&self) -> Sha256Digest {
        self.request_digest
    }
}

/// Build the activation request from the rows this input already has.
///
/// The A side is read back, not remembered: the digest binds what the database
/// actually stores, so a replay recomputes exactly what the first commit
/// committed to.
fn build_activation_request(
    tx: &crate::storage::api::Tx<'_>,
    input_id: i64,
    input_key: &Sha256Digest,
    normalizer_id: &str,
    safety_contract_id: &str,
    job: &SourceInputJob,
) -> Result<ActivationPlan, SourceIngestError> {
    let (records_root, claims_root) = source_facts::source_a_roots_in_tx(tx, input_key, input_id)
        .map_err(SourceIngestError::Verify)?;
    let library_identity = meta_text(tx, "library_identity")?.ok_or_else(|| {
        SourceIngestError::Install(SourceInstallError::Corrupt {
            detail: "the database has no library identity".to_string(),
        })
    })?;
    let manifest = job.input.manifest();
    let expected_manifest_digest =
        source_facts::expected_manifest_digest(manifest, job.input.safety_identity());
    let finish = storage_finish(&job.finish, job.input.manifest());
    let request_digest = source_facts::semantic_request_digest(
        input_key,
        &expected_manifest_digest,
        manifest.sealed_sha256(),
        manifest.byte_len(),
        manifest.format().as_str(),
        normalizer_id,
        safety_contract_id,
        &finish,
        source_facts::ProjectionDisposition::Ready,
        &records_root,
        &claims_root,
    );
    Ok(ActivationPlan {
        request: source_facts::SourceActivationRequest {
            input_key: *input_key,
            library_identity,
            normalizer_id: normalizer_id.to_string(),
            safety_contract_id: safety_contract_id.to_string(),
            expected_manifest_digest,
            finish,
            projection_disposition: source_facts::ProjectionDisposition::Ready,
            source_semantic_records_root: records_root,
            claims_root,
            requested_terminal: requested_terminal(job),
        },
        request_digest,
    })
}

/// The terminal state this input can honestly request.
///
/// A record the connector could not parse means the input did not come through
/// whole: requesting `Complete` would be a claim the run cannot support, so it
/// asks for `Partial` and the activation publishes that instead.
fn requested_terminal(job: &SourceInputJob) -> source_facts::TerminalState {
    if job.finish.parse_failed > 0 || !job.finish.unprocessed_ranges.is_empty() {
        source_facts::TerminalState::Partial
    } else {
        source_facts::TerminalState::Complete
    }
}

/// Turn the pinned connector's finish into the storage finish.
///
/// The four measurements that *are* the independent denominator — the content
/// digest, the byte length, the record count and the blank-line count — come
/// from the CASS scan, never from the connector's own report. The connector
/// contributes only what only it can know: how many records failed to parse,
/// how many mapping diagnostics it raised, and which ranges it left unprocessed.
/// A malformed record is exactly the case where the two counts differ, and the
/// storage row must record the independent one.
fn storage_finish(
    finish: &crate::indexer::source_ingest::fad::SourceInputFinish,
    manifest: &source_facts::VerifiedExpectedManifest,
) -> source_facts::VerifiedFinish {
    source_facts::VerifiedFinish {
        content_digest: *manifest.sealed_sha256(),
        bytes_read: manifest.byte_len(),
        records_seen: manifest.records(),
        blank_lines: manifest.blank_lines(),
        parse_failed: finish.parse_failed,
        mapping_diagnostics: finish.mapping_diagnostics,
        unprocessed_ranges: finish
            .unprocessed_ranges
            .iter()
            .map(|range| source_facts::SourceUnprocessedRange {
                start: range.byte_start,
                end: range.byte_end,
                reason: range.reason.clone(),
                ordinal: range.ordinal,
                record_pointer: range.record_pointer.clone(),
            })
            .collect(),
        reached_eof: finish.reached_eof,
    }
}

/// A deliberate fault at a named point in the commit, for the rollback tests.
///
/// The value is read once per call so a test can name exactly one point and
/// leave production runs untouched (the variable is unset there).
fn injected_fault(point: &str) -> Result<(), SourceIngestError> {
    #[cfg(test)]
    {
        // The scripted class comes first: it is the only hook that can name a
        // *typed* class, and the only one that survives a writer thread.
        if let Some(fault) = test_hooks::take_scripted_fault(point) {
            return Err(match fault {
                test_hooks::TypedFault::Busy => busy_storage_error(),
                test_hooks::TypedFault::Locked => locked_storage_error(),
                test_hooks::TypedFault::OutOfMemory => out_of_memory_storage_error(),
            });
        }
    }
    // A typed busy error, so the retryable classification can be exercised for
    // real rather than inferred from a string.
    if point == "busy" && std::env::var("CASS_SRC05B07_FAIL_AT").ok().as_deref() == Some("busy") {
        return Err(busy_storage_error());
    }
    #[cfg(test)]
    {
        if test_hooks::take_nth_fault(point) || test_hooks::armed_fail_at() == Some(point) {
            return Err(SourceIngestError::Storage {
                detail: format!("injected fault at {point}"),
            });
        }
    }
    if std::env::var("CASS_SRC05B07_FAIL_AT").ok().as_deref() == Some(point) {
        return Err(SourceIngestError::Storage {
            detail: format!("injected fault at {point}"),
        });
    }
    Ok(())
}

/// The typed transient the storage layer reports for a busy database, so a
/// fault can carry the real class instead of a message that reads like it.
fn busy_storage_error() -> SourceIngestError {
    SourceIngestError::Install(SourceInstallError::Db(
        crate::storage::api::StorageError::Busy {
            scope: crate::storage::api::BusyScope::Statement,
        },
    ))
}

/// The typed lock, which the retry whitelist excludes on purpose: retrying it
/// loops, per the storage layer's own note on `Conn::with_tx`.
///
/// Test-only: production never constructs a lock to hand itself, it only has
/// to classify one the storage layer produced.
#[cfg(test)]
fn locked_storage_error() -> SourceIngestError {
    SourceIngestError::Install(SourceInstallError::Db(
        crate::storage::api::StorageError::Locked,
    ))
}

/// The typed out-of-memory this crate's OOM detector recognises: the storage
/// layer folds `FrankenError::OutOfMemory` into `Other { detail: "out of
/// memory" }`, which is what the indexer's own exact-message test looks for.
///
/// Test-only, for the same reason as the lock above.
#[cfg(test)]
fn out_of_memory_storage_error() -> SourceIngestError {
    SourceIngestError::Install(SourceInstallError::Db(
        crate::storage::api::StorageError::Other {
            code: None,
            detail: "out of memory".to_string(),
        },
    ))
}

/// Read a committed input's semantic delta back from storage, in memory.
///
/// There is no new outbox and no new table: the delta is the set of canonical
/// messages this commit created, read through the builder the rest of the
/// indexer already uses. A failure here is not a failed commit — the rows and
/// the receipt are already durable — so it is reported as a derivation still
/// pending recovery, and the existing hole/catch-up path picks it up.
fn read_back_delta(
    storage: &crate::storage::sqlite::FrankenStorage,
    accepted: &[(i64, Vec<i64>, bool)],
) -> std::result::Result<Vec<crate::indexer::semantic::EmbeddingInput>, String> {
    if accepted.is_empty() {
        return Ok(Vec::new());
    }
    #[cfg(test)]
    if test_hooks::armed_fail_at() == Some("postcommit") {
        return Err("the committed input's semantic delta could not be read back".to_string());
    }
    if std::env::var("CASS_SRC05B07_FAIL_AT").ok().as_deref() == Some("postcommit") {
        return Err("the committed input's semantic delta could not be read back".to_string());
    }
    let conversation_ids: Vec<i64> = accepted.iter().map(|(id, _, _)| *id).collect();
    let message_ids: std::collections::HashSet<i64> = accepted
        .iter()
        .flat_map(|(_, ids, _)| ids.iter().copied())
        .collect();
    crate::indexer::semantic::packet_embedding_inputs_from_storage_for_message_ids(
        storage,
        &conversation_ids,
        &message_ids,
    )
    .map_err(|_| "the committed input's semantic delta could not be read back".to_string())
}

/// What one commit hands its caller.
#[derive(Debug)]
pub(crate) struct SourceInputCommit {
    pub(crate) outcome: SourceInputOutcome,
    /// The semantic delta this commit created, read back from canonical
    /// storage: one entry per newly inserted message, carrying its id and its
    /// already-desensitised body. Empty for a replay and for a refusal.
    pub(crate) delta: Vec<crate::indexer::semantic::EmbeddingInput>,
    /// Canonical rows this commit created, for the run's own counters.
    pub(crate) inserted_conversations: usize,
    pub(crate) inserted_messages: usize,
}

/// The typed storage error a `SourceIngestError` carries, when it carries one.
///
/// Classification reads only this channel. No decision below inspects an
/// error's text, so a message that merely says "busy" is never retried.
fn storage_error_of(error: &SourceIngestError) -> Option<&crate::storage::api::StorageError> {
    match error {
        SourceIngestError::Install(SourceInstallError::Db(inner))
        | SourceIngestError::Verify(SourceInstallError::Db(inner)) => Some(inner),
        _ => None,
    }
}

/// The one retryable class, and the same one the rest of the indexer accepts:
/// every transient the storage layer folds into `Busy`. `Locked` is
/// deliberately outside it -- the storage layer's own note on `Conn::with_tx`
/// records that retrying it loops.
fn retryable_busy_error(error: &SourceIngestError) -> Option<&crate::storage::api::StorageError> {
    storage_error_of(error)
        .filter(|inner| matches!(inner, crate::storage::api::StorageError::Busy { .. }))
}

/// Whether the failure is the non-retryable lock the whitelist excludes.
fn is_locked_error(error: &SourceIngestError) -> bool {
    matches!(
        storage_error_of(error),
        Some(crate::storage::api::StorageError::Locked)
    )
}

/// A typed out-of-memory, and nothing else.
///
/// The boundary is exact: the failure must be the installation's own typed
/// storage error `Other { detail }`, and only then is that detail put to the
/// same exact-message test the legacy ingest OOM path uses. A `Verify`, a
/// configuration or read error, and any untyped text are all outside it, so no
/// other failure is promoted into the isolation retry. The broader anyhow
/// detector is deliberately not used: it also accepts any cause whose text
/// reads like the message, which is not a class this retry may spend a whole
/// extra attempt on.
fn typed_out_of_memory(error: &SourceIngestError) -> bool {
    match error {
        SourceIngestError::Install(SourceInstallError::Db(
            crate::storage::api::StorageError::Other { detail, .. },
        )) => crate::indexer::error_message_is_exact_out_of_memory(detail),
        _ => false,
    }
}

/// The outcome this path has always reported when the database is busy: a
/// transient non-success, so the enclosing root keeps its watermark.
fn busy_transient_commit(job: &SourceInputJob) -> SourceInputCommit {
    SourceInputCommit {
        outcome: SourceInputOutcome::Transient {
            input_key: *job.input.input_key(),
            reason: "the database was busy".to_string(),
        },
        delta: Vec::new(),
        inserted_conversations: 0,
        inserted_messages: 0,
    }
}

/// The whole-input retry budget, held by one logical input.
///
/// The busy budget belongs to the input rather than to one writer round, so an
/// out-of-memory isolation round cannot hand the same input a second, fresh
/// busy budget. Mixed faults therefore share one finite count.
struct BusyRetryBudget {
    limit: usize,
    spent: usize,
}

impl BusyRetryBudget {
    fn for_one_input() -> Self {
        Self {
            limit: crate::indexer::persist::begin_concurrent_retry_limit(),
            spent: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.spent)
    }
}

/// Route one complete input through the same writer dispatch the legacy
/// persist paths use, and retry the whole input on the two classes this path
/// is allowed to retry.
///
/// The atomic kernel stays [`commit_source_input`]: it commits one input in one
/// transaction either way. What changes is *which writer* runs it --
///
/// - the default serial mode goes through the existing ephemeral writer, with
///   the same acquire / return / discard-on-failure discipline;
/// - the configured writer mode hands the whole input to the existing
///   dedicated writer thread (`WriterHandle`), still committing through the
///   same `Immediate` API. Nothing here invents a concurrent transaction mode.
///
/// Either way the unit of work is the whole `SourceInputJob`: one input is one
/// commit, never several projections committed apart.
///
/// Retry is the *second* thing this function does, and it repeats exactly this
/// whole call -- the same sealed job, the same identity, the same pass-2
/// verification over the sealed blob, and a fresh writer cycle per attempt. It
/// never re-reads the live file to rebuild a job, and it never splits an input:
///
/// - a typed `Busy` retries inside the existing begin-concurrent budget, with
///   that helper's own backoff, and is reported with [`busy_transient_commit`]
///   once the budget is spent;
/// - a typed out-of-memory gets exactly one further complete isolation attempt;
///   a second one returns the error, so the input is honestly unfinished and
///   its root keeps its watermark;
/// - anything else, `Locked` included, is returned as itself without retry.
pub(crate) fn commit_source_input_dispatched(
    storage: &crate::storage::sqlite::FrankenStorage,
    job: &SourceInputJob,
    defer_checkpoints: bool,
) -> Result<SourceInputCommit, SourceIngestError> {
    let mut busy = BusyRetryBudget::for_one_input();
    let mut isolation_rounds = 0usize;
    loop {
        match commit_source_input_busy_round(storage, job, defer_checkpoints, &mut busy) {
            Ok(commit) => return Ok(commit),
            Err(error) => {
                if !typed_out_of_memory(&error) {
                    return Err(error);
                }
                if isolation_rounds > 0 {
                    tracing::warn!(
                        target: "cass::source_input",
                        connector = job.connector_name,
                        root_id = %job.root_id,
                        "source_input_retry: the isolation attempt ran out of memory again; this \
                         input stays unfinished and its root keeps its watermark"
                    );
                    return Err(error);
                }
                // One isolation attempt, and it is a new *complete* attempt
                // rather than a narrower one: an input is one unit of work, so
                // making it smaller is not something this path may do on its
                // own. It shares the input's one busy budget.
                isolation_rounds += 1;
                tracing::warn!(
                    target: "cass::source_input",
                    connector = job.connector_name,
                    root_id = %job.root_id,
                    isolation_round = isolation_rounds,
                    "source_input_retry: retrying the whole input once after a typed out-of-memory"
                );
            }
        }
    }
}

/// One writer round of the whole input, with whatever is left of the input's
/// begin-concurrent budget.
///
/// The retry sits *outside* the writer cycle on purpose: each attempt acquires
/// a writer and gives it back through the ordinary lifecycle, so a failed
/// attempt leaves no half-written input and no borrowed connection behind, in
/// either writer mode.
fn commit_source_input_busy_round(
    storage: &crate::storage::sqlite::FrankenStorage,
    job: &SourceInputJob,
    defer_checkpoints: bool,
    busy: &mut BusyRetryBudget,
) -> Result<SourceInputCommit, SourceIngestError> {
    let remaining = busy.remaining();
    // Only a retryable `Busy` is handed to the retry wrapper, and it is handed
    // over as its own typed value, so the wrapper's whitelist is what decides
    // what "retryable" means here -- this path cannot drift from the rest of
    // the indexer. A stop for any other reason keeps its typed error here.
    let stopped: std::cell::RefCell<Option<SourceIngestError>> = std::cell::RefCell::new(None);
    let outcome = crate::indexer::persist::with_concurrent_retry(remaining, || {
        match commit_source_input_dispatched_once(storage, job, defer_checkpoints) {
            Ok(commit) => Ok(commit),
            Err(error) => match retryable_busy_error(&error) {
                Some(busy_error) => {
                    busy.spent += 1;
                    // Bounded and readable: one line per failed attempt, with
                    // the count this input has now spent, so a real run's log
                    // says how many attempts a typed Busy produced. The line
                    // says what happened (the attempt failed) rather than what
                    // the budget will allow next: whether a further attempt
                    // follows is the wrapper's decision, not this one's.
                    tracing::warn!(
                        target: "cass::source_input",
                        connector = job.connector_name,
                        root_id = %job.root_id,
                        spent = busy.spent,
                        limit = busy.limit,
                        "source_input_retry: a typed Busy failed this whole-input attempt"
                    );
                    Err(anyhow::Error::new(busy_error.clone()))
                }
                None => {
                    *stopped.borrow_mut() = Some(error);
                    Err(anyhow::anyhow!(
                        "the source input stopped for a non-retryable reason"
                    ))
                }
            },
        }
    });

    match outcome {
        Ok(commit) => Ok(commit),
        Err(_) => match stopped.into_inner() {
            // The budget ran out on a retryable Busy: report what this path has
            // always reported for a busy database.
            None => Ok(busy_transient_commit(job)),
            // `Locked` is not in the whitelist, so it is not retried; it has
            // always been reported as the same transient outcome.
            Some(error) if is_locked_error(&error) => Ok(busy_transient_commit(job)),
            Some(error) => Err(error),
        },
    }
}

/// Whether this attempt runs on the dedicated writer thread.
///
/// Test-only seam: a case that has to drive both writer modes in one process
/// forces the mode for its own thread instead of writing a process-wide
/// environment variable, so two cases running in parallel cannot see each
/// other's choice.
fn writer_mode_is_concurrent() -> bool {
    #[cfg(test)]
    if let Some(forced) = test_hooks::forced_writer_mode() {
        return forced;
    }
    crate::indexer::persist::begin_concurrent_writes_enabled()
}

/// One attempt: the writer dispatch itself, with no retry of its own.
fn commit_source_input_dispatched_once(
    storage: &crate::storage::sqlite::FrankenStorage,
    job: &SourceInputJob,
    defer_checkpoints: bool,
) -> Result<SourceInputCommit, SourceIngestError> {
    if writer_mode_is_concurrent() {
        return commit_source_input_on_writer_thread(storage, job, defer_checkpoints);
    }

    // `with_ephemeral_writer` is `anyhow`-shaped, and `anyhow` is not a place
    // to hide a storage error's kind. The typed error is kept beside the call
    // and returned as itself; only an error that never reached the kernel is
    // reported as a plain writer failure.
    let typed: std::cell::RefCell<Option<SourceIngestError>> = std::cell::RefCell::new(None);
    let outcome = crate::indexer::persist::with_ephemeral_writer(
        storage,
        defer_checkpoints,
        "committing one source-aware input",
        |writer| {
            // Recorded *inside* the ephemeral writer's own callback, so the
            // evidence says this branch really ran rather than which value was
            // selected.
            tracing::info!(
                target: "cass::source_input",
                mode = "ephemeral-writer",
                connector = job.connector_name,
                root_id = %job.root_id,
                "source_input_dispatch"
            );
            match commit_source_input(writer, job) {
            Ok(commit) => Ok(commit),
            Err(error) => {
                *typed.borrow_mut() = Some(error);
                Err(anyhow::anyhow!("the source-aware input did not commit"))
            }
            }
        },
    );
    match outcome {
        Ok(commit) => Ok(commit),
        Err(writer_error) => Err(typed.into_inner().unwrap_or(SourceIngestError::Storage {
            detail: format!("the ephemeral writer failed: {writer_error}"),
        })),
    }
}

/// The configured writer mode: the whole input travels to the dedicated writer
/// thread, which owns the only writable connection on this path.
fn commit_source_input_on_writer_thread(
    storage: &crate::storage::sqlite::FrankenStorage,
    job: &SourceInputJob,
    defer_checkpoints: bool,
) -> Result<SourceInputCommit, SourceIngestError> {
    let db_path = storage.database_path().map_err(|error| {
        SourceIngestError::Storage {
            detail: format!("resolving the database path: {error}"),
        }
    })?;
    let path_for_build = db_path.clone();
    let (handle, join) =
        crate::storage::api::WriterHandle::<crate::storage::sqlite::FrankenStorage>::spawn(
            db_path,
            crate::storage::api::Profile::Production,
            move |conn| {
                let storage = crate::storage::sqlite::FrankenStorage::from_writer_handle_conn(
                    conn,
                    path_for_build,
                )
                .map_err(crate::storage::sqlite::anyhow_error_into_storage_error)?;
                crate::indexer::persist::apply_begin_concurrent_writer_tuning(&storage, defer_checkpoints);
                Ok(storage)
            },
        )
        .map_err(|error| SourceIngestError::Storage {
            detail: format!("spawning the source-aware writer thread: {error}"),
        })?;

    let owned = job.clone();
    let typed: Arc<std::sync::Mutex<Option<SourceIngestError>>> =
        Arc::new(std::sync::Mutex::new(None));
    let typed_for_job = Arc::clone(&typed);
    // A test-only script has to reach the thread that really commits: the job
    // closure below runs there, so the context this thread holds travels with
    // it, and the guard restores the writer thread's own state on the way out.
    #[cfg(test)]
    let fault_script = test_hooks::current_fault_script();
    let result = handle.submit(move |writer| {
        #[cfg(test)]
        let _fault_scope = fault_script.map(test_hooks::install_fault_script);
        // Recorded *inside* the dedicated writer thread's job, so the evidence
        // says the input really ran on that thread.
        tracing::info!(
            target: "cass::source_input",
            mode = "writer-handle",
            connector = owned.connector_name,
            root_id = %owned.root_id,
            "source_input_dispatch"
        );
        match commit_source_input(writer, &owned) {
        Ok(commit) => Ok(commit),
        Err(error) => {
            *typed_for_job.lock().expect("typed error slot") = Some(error);
            Err(crate::storage::api::StorageError::Other {
                code: None,
                detail: "the source-aware input did not commit".to_string(),
            })
        }
        }
    });
    // Dropping every handle clone ends the thread's job loop; join so the
    // connection is really closed before the caller continues.
    drop(handle);
    let _ = join.join();

    match result {
        Ok(commit) => Ok(commit),
        Err(transport) => {
            let typed = typed.lock().expect("typed error slot").take();
            Err(typed.unwrap_or(SourceIngestError::Storage {
                detail: format!("the source-aware writer thread failed: {transport}"),
            }))
        }
    }
}

/// Carry a storage failure through the writer channel without erasing its kind.
fn source_ingest_error_to_storage(error: SourceIngestError) -> crate::storage::api::StorageError {
    match error {
        SourceIngestError::Install(SourceInstallError::Db(err)) => err,
        other => crate::storage::api::StorageError::Other {
            code: None,
            detail: other.to_string(),
        },
    }
}

/// Re-check the frozen material and run the shared safety pass.
///
/// The ordinary commit and the read-only preview share this one entry, so the
/// order — fixed configuration first, then the sealed blob identity, then the
/// per-record judgment — cannot drift between them.
fn verify_and_judge_source_input(
    job: &SourceInputJob,
) -> Result<SafetyPass, SourceIngestError> {
    job.safety.recheck_bytes()?;

    // The blob identity is re-checked here, not assumed from pass 1: the path
    // must still hold the same bytes before anything is written.
    let verified = crate::raw_mirror::open_verified_capture(&job.data_dir, &job.capture)
        .map_err(|err| SourceIngestError::Capture { detail: err.code().to_string() })?;
    if verified.blob_blake3() != job.blob_blake3
        || verified.blob_size_bytes() != job.input.manifest().byte_len()
    {
        return Err(SourceIngestError::Capture {
            detail: "the sealed blob changed between capture and commit".to_string(),
        });
    }

    safety_pass(job, &verified, &job.safety.config().effective_four_arrays)
}

/// One conversation as the read-only preview returns it: the judged messages
/// the ordinary commit would install, and the SQL projection those messages
/// map to under the same explicit redaction.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SourceSafetyPreviewConversation {
    pub(crate) ordinal: u32,
    pub(crate) prepared: crate::indexer::exclusion::PreparedConversation,
    pub(crate) sql_projection: crate::model::types::Conversation,
}

/// The two read-only projections of one sealed input.
///
/// These are the same values the ordinary commit computes from the same
/// material. They are not a completion proof: producing them writes no DB
/// row, link or receipt.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct SourceSafetyPreview {
    pub(crate) records: Vec<source_facts::VerifiedStagedRecord>,
    pub(crate) parse_failed: u64,
    pub(crate) diagnostics: u64,
    pub(crate) conversations: Vec<SourceSafetyPreviewConversation>,
}

/// Judge a sealed input and keep both projections, without opening storage.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn preview_source_input_safety(
    job: &SourceInputJob,
) -> Result<SourceSafetyPreview, SourceIngestError> {
    let safety = verify_and_judge_source_input(job)?;
    let conversations = safety
        .judged
        .into_iter()
        .map(|item| SourceSafetyPreviewConversation {
            ordinal: item.ordinal,
            sql_projection: crate::indexer::persist::map_to_internal_with_explicit_redaction(
                &item.prepared,
                None,
                true,
            ),
            prepared: item.prepared,
        })
        .collect();
    Ok(SourceSafetyPreview {
        records: safety.staged.records,
        parse_failed: safety.staged.parse_failed,
        diagnostics: safety.staged.diagnostics,
        conversations,
    })
}

/// Assemble one declared restore input and prove the journal's seven-field
/// binding.
///
/// The order is fixed. The declared-input adapter consumes the declaration and
/// the same-capture record, the read-only safety preview re-verifies the sealed
/// bytes, the restore admission applies the same parse/record/zero-conversation
/// rules the ordinary path uses, and only then are the seven binding fields
/// recomputed from the returned job and compared with the caller's values.
///
/// This function never opens storage, never reads the live source and never
/// captures. A projection count above one keeps its own exact code; every other
/// material failure is one fixed mismatch code.
pub(crate) fn prepare_restore_source_job(
    data_dir: &Path,
    capture: &crate::raw_mirror::RawMirrorCaptureRecord,
    binding: &crate::phase3_restore::SourceBindingMaterial,
    safety: Arc<FixedSafetyConfig>,
) -> Result<SourceInputJob, SourceIngestError> {
    let mismatch = || SourceIngestError::Config {
        detail: "source_restore_material_mismatch".to_string(),
    };

    // 1. The existing declared-input adapter: declaration admission, one
    // same-capture open and the one shared sealed preparation.
    let job = crate::phase3_restore::source_binding::prepare_declared_restore_source_input(
        data_dir,
        capture,
        &binding.declaration,
        safety,
    )?;

    // 2. The read-only preview re-verifies the sealed bytes and produces both
    // projections. An unusable material is one fixed mismatch code here.
    let preview = preview_source_input_safety(&job).map_err(|_| mismatch())?;

    // 3. The restore admission keeps the same parse/record/zero-conversation
    // rules. Its own short codes are forwarded exactly, never flattened.
    crate::phase3_restore::validate_restore_source_preview(&job, &preview).map_err(|error| {
        SourceIngestError::Config {
            detail: error.code().to_string(),
        }
    })?;

    // 4. Six fields come from the real job; the declaration is the value the
    // adapter actually consumed. Copying any calculated field from the binding
    // would make the comparison prove itself.
    let context_digest = job
        .input
        .identity_tuple()
        .get(11)
        .cloned()
        .flatten()
        .ok_or_else(mismatch)?;
    let recomputed = crate::phase3_restore::SourceBindingMaterial {
        declaration: binding.declaration.clone(),
        context_digest,
        sealed_sha256: job.input.manifest().sealed_sha256().hex(),
        byte_len: job.input.manifest().byte_len(),
        normalizer_id: job.normalizer_id.clone(),
        safety_contract_id: job.safety_contract_id.clone(),
        input_key: job.input.input_key().hex(),
    };
    if recomputed != *binding {
        return Err(mismatch());
    }
    Ok(job)
}

// ---------------------------------------------------------------------------
// The shared install kernel (Task15)
// ---------------------------------------------------------------------------

/// One prepared input: the job plus the safety pass its commit will install.
///
/// The fields stay private to this module. The ordinary wrapper and the
/// restore path both call [`prepare_source_input_commit`] and then
/// [`install_source_input_in_tx`], so neither can drift into a second
/// derivation.
pub(crate) struct PreparedSourceInputCommit<'a> {
    job: &'a SourceInputJob,
    safety: SafetyPass,
}

/// What one install did, for callers that must write their own receipt.
pub(crate) struct SourceInputInstallResult {
    pub(crate) request: source_facts::SourceActivationRequest,
    pub(crate) outcome: source_facts::SourceActivationOutcome,
    /// One entry per projected conversation that either created a row or
    /// accepted new messages. Each tuple is
    /// `(conversation_id, accepted_message_ids, conversation_inserted)`:
    /// the canonical conversation id, the ids of the messages this input
    /// actually accepted, and whether this install created the conversation
    /// row rather than content-deduping into an existing one.
    pub(crate) accepted_by_conversation: Vec<(i64, Vec<i64>, bool)>,
    /// The number of conversations the real safety pass judged, not the
    /// number of messages and not a planned count.
    pub(crate) judged_conversations: usize,
}

/// Re-check the frozen material and judge the input, before any transaction.
///
/// Only the existing [`verify_and_judge_source_input`] entry is called: fixed
/// configuration first, then the sealed bytes, then the per-record judgment.
pub(crate) fn prepare_source_input_commit(
    job: &SourceInputJob,
) -> Result<PreparedSourceInputCommit<'_>, SourceIngestError> {
    Ok(PreparedSourceInputCommit {
        job,
        safety: verify_and_judge_source_input(job)?,
    })
}

/// Install one prepared input inside the caller's transaction.
///
/// Opens nothing, commits nothing, never reads the live source and never reads
/// the delta back. The transaction and its outcome belong to the caller.
pub(crate) fn install_source_input_in_tx(
    storage: &crate::storage::sqlite::FrankenStorage,
    tx: &crate::storage::api::Tx<'_>,
    prepared: &PreparedSourceInputCommit<'_>,
) -> Result<SourceInputInstallResult, SourceIngestError> {
    install_source_input_with_projection_in_tx(
        tx,
        prepared,
        |tx, agent_id, workspace_id, conversation, input_key, conversation_ordinal, claims| {
            storage.install_conversation_projection_in_tx(
                tx,
                agent_id,
                workspace_id,
                conversation,
                input_key,
                conversation_ordinal,
                claims,
            )
        },
    )
}

/// The one shared install kernel, with the conversation projection supplied by
/// the caller.
///
/// Every other step is identical for the ordinary projector and the source
/// Replace projector: the complete-input Replay proof runs before any
/// staging/parent/callback work, then records are staged, claims are installed,
/// the input is activated and its receipt is verified. The callback receives
/// the transaction it must write in, the ensured parent ids, the projected
/// conversation, the input key, the conversation ordinal and the complete
/// resolved claims; it returns the same outcome the ordinary storage projector
/// returns. A `VerifiedReplay` returns before the callback is ever called.
#[allow(clippy::type_complexity)]
pub(crate) fn install_source_input_with_projection_in_tx<F>(
    tx: &crate::storage::api::Tx<'_>,
    prepared: &PreparedSourceInputCommit<'_>,
    mut project: F,
) -> Result<SourceInputInstallResult, SourceIngestError>
where
    F: FnMut(
        &crate::storage::api::Tx<'_>,
        i64,
        Option<i64>,
        &crate::model::types::Conversation,
        &source_facts::Sha256Digest,
        u32,
        &[source_facts::SourceClaim],
    ) -> Result<source_facts::SourceAwareInsertOutcome, source_facts::SourceInstallError>,
{
    let job = prepared.job;
    let input_key = *job.input.input_key();
    let judged = &prepared.safety.judged;
    let pass2 = &prepared.safety.staged;

    let normalizer_id = job.normalizer_id.clone();
    let safety_contract_id = job.safety_contract_id.clone();

                // A replay is proved, never assumed, and it is decided before
                // anything is written: an input this database already completed
                // is verified against its stored receipt and the canonical
                // binding its rows already carry. A mismatch is a corrupt or
                // conflicting state and is refused -- it is never folded into
                // "already done". Nothing is staged or re-marked here, because
                // the stored frame states are part of what the receipt binds.
                if let Some(existing_id) = source_facts::registered_source_input_id(tx, &input_key)
                    .map_err(SourceIngestError::Verify)?
                {
                    let stored_state: Option<String> = tx
                        .query_opt_map(
                            "SELECT state FROM source_inputs WHERE id = ?1",
                            &[crate::storage::api::Value::Integer(existing_id)],
                            |row| row.get_typed(0),
                        )
                        .map_err(|err| SourceIngestError::Install(SourceInstallError::Db(err)))?;
                    if stored_state.as_deref() == Some("complete") {
                        let request = build_activation_request(
                            tx,
                            existing_id,
                            &input_key,
                            &normalizer_id,
                            &safety_contract_id,
                            job,
                        )?;
                        return match source_facts::verify_source_receipt_in_tx(tx, &request.request)
                            .map_err(SourceIngestError::Install)?
                        {
                            source_facts::SourceReceiptMatch::VerifiedReplay { receipt, .. } => {
                                Ok(SourceInputInstallResult {
                                    request: request.request,
                                    outcome: source_facts::SourceActivationOutcome::Replay {
                                        receipt: *receipt,
                                    },
                                    accepted_by_conversation: Vec::new(),
                                    judged_conversations: judged.len(),
                                })
                            }
                            source_facts::SourceReceiptMatch::Conflict { .. } => {
                                Err(SourceIngestError::Install(SourceInstallError::Conflict {
                                    detail: "the stored receipt disagrees with the current input"
                                        .to_string(),
                                }))
                            }
                            source_facts::SourceReceiptMatch::Inconsistent { reason } => {
                                Err(SourceIngestError::Install(SourceInstallError::Receipt(reason)))
                            }
                            source_facts::SourceReceiptMatch::Absent => {
                                Err(SourceIngestError::Install(SourceInstallError::Corrupt {
                                    detail: "the input is complete but carries no receipt"
                                        .to_string(),
                                }))
                            }
                        };
                    }
                }

                // 1. Stage every record of this input. The primitive leaves
                //    the frames `frame_pending`; the reader marks the ones it
                //    actually read and verified, one row at a time, so a frame
                //    pass 2 never covered stays pending and blocks activation.
                let staged = source_facts::stage_source_records_in_tx(tx, &job.input, &pass2.records)
                    .map_err(SourceIngestError::Verify)?;
                let input_id = staged.input_id;
                for record in &pass2.records {
                    let locator = record.locator();
                    let updated = tx
                        .execute(
                            "UPDATE source_records SET frame_state = 'staged'
                             WHERE input_id = ?1 AND ordinal = ?2 AND record_pointer = ?3",
                            &[
                                crate::storage::api::Value::Integer(input_id),
                                crate::storage::api::Value::Blob(
                                    source_facts::u64_be8(locator.ordinal).to_vec(),
                                ),
                                crate::storage::api::Value::Text(locator.record_pointer.clone()),
                            ],
                        )
                        .map_err(|err| SourceIngestError::Install(SourceInstallError::Db(err)))?;
                    if updated != 1 {
                        return Err(SourceIngestError::Install(SourceInstallError::Corrupt {
                            detail: format!(
                                "record ordinal {} has no staged row to mark",
                                locator.ordinal
                            ),
                        }));
                    }
                }

                injected_fault("busy")?;
                injected_fault("staging")?;

                // 2. First-time commit: project every conversation in this
                //    same transaction, resolving the parent rows here too (the
                //    non-caching entry, so a rollback leaves no parent row and
                //    no cached id behind).
                let mut installs: Vec<(source_facts::SourceClaim, source_facts::SourceAwareInsertOutcome)> =
                    Vec::new();
                // The safety pass's claims are the authoritative, fully
                // resolved form of every declaration this input carries: they
                // are the ones whose source positions were resolved against the
                // actual safe tree. The conversation callback reports the same
                // declarations, and the projection installs the safety pass's
                // claim rather than re-deriving a second, unresolved copy of
                // it.
                let mut complete_claims: HashMap<Vec<u8>, VecDeque<source_facts::SourceClaim>> =
                    HashMap::new();
                for claim in pass2.claims_by_ordinal.values().flatten() {
                    let key = claim_identity_key(claim);
                    if let Some(existing) = complete_claims.get_mut(&key) {
                        // The same identity twice is the same declaration; a
                        // difference anywhere inside it is a contradiction, not
                        // a queue to append to.
                        if existing.iter().any(|prior| prior != claim) {
                            return Err(SourceIngestError::Sink {
                                detail: format!(
                                    "record {} ({}) declares two different claims under one \
                                     identity",
                                    claim.record_pointer, claim.record_ordinal
                                ),
                            });
                        }
                    }
                    complete_claims.entry(key).or_default().push_back(claim.clone());
                }
                // (conversation id, deduped new message ids, did this
                // projection *create* the conversation).
                let mut accepted_by_conversation: Vec<(i64, Vec<i64>, bool)> = Vec::new();
                for item in judged {
                    let conversation = crate::indexer::persist::map_to_internal_with_explicit_redaction(
                        &item.prepared,
                        None,
                        true,
                    );
                    let mut claims: Vec<source_facts::SourceClaim> =
                        Vec::with_capacity(item.claims.len());
                    for claim in &item.claims {
                        let key = claim_identity_key(&storage_claim(&input_key, None, claim)?);
                        let complete = complete_claims
                            .get_mut(&key)
                            .and_then(VecDeque::pop_front)
                            .ok_or_else(|| SourceIngestError::Sink {
                                detail: format!(
                                    "the safety pass resolved no complete claim for record {} \
                                     ({}) of conversation {}",
                                    claim.record_pointer, claim.record_ordinal, item.ordinal
                                ),
                            })?;
                        claims.push(complete);
                    }
                    let claims = claims;
                    let (agent_id, workspace_id) =
                        crate::storage::sqlite::ensure_parent_rows_in_tx(tx, &conversation)
                            .map_err(SourceInstallError::Db)
                            .map_err(SourceIngestError::Install)?;
                    let inserted = project(
                        tx,
                        agent_id,
                        workspace_id,
                        &conversation,
                        &input_key,
                        item.ordinal,
                        &claims,
                    )
                    .map_err(SourceIngestError::Install)?;
                    for claim in &claims {
                        installs.push((claim.clone(), inserted.clone()));
                    }
                    // The commit summary: per projection, the canonical
                    // messages this input *created*. A replay creates none, so
                    // its summary is empty and its delta is zero.
                    let mut accepted: Vec<i64> = inserted
                        .incoming
                        .iter()
                        .filter(|binding| {
                            binding.status == source_facts::IncomingStatus::AcceptedNew
                        })
                        .filter_map(|binding| {
                            binding.stored.as_ref().map(|stored| stored.original_message_id)
                        })
                        .collect();
                    accepted.sort_unstable();
                    accepted.dedup();
                    if !accepted.is_empty() || inserted.conversation_inserted {
                        accepted_by_conversation.push((
                            inserted.conversation_id,
                            accepted,
                            inserted.conversation_inserted,
                        ));
                    }
                    injected_fault("projection")?;
                }

                // A claim no conversation projection consumed is a record
                // that projected no message: it carries no conversation, so
                // the conversation loop never saw it and its link would be
                // missing. Its own mapping state decides its class -- an
                // explicit standalone takes `StandaloneNoBinding`, an unmapped
                // claim takes `UnmappedNoBinding` (which the activation
                // refuses to complete, exactly as the contract says); a claim
                // that claims a canonical mapping but reached no conversation
                // is an inconsistency between the two reports, not something to
                // classify by hand.
                let mut standalone_claims: Vec<source_facts::SourceClaim> = Vec::new();
                for (_, claims) in std::mem::take(&mut complete_claims) {
                    for claim in claims {
                        match claim.mapping_state {
                            source_facts::ClaimMappingState::Standalone
                            | source_facts::ClaimMappingState::Unmapped => {
                                standalone_claims.push(claim);
                            }
                            source_facts::ClaimMappingState::Canonical => {
                                return Err(SourceIngestError::Sink {
                                    detail: format!(
                                        "record {} ({}) claims a canonical mapping but no \
                                         conversation projection consumed it",
                                        claim.record_pointer, claim.record_ordinal
                                    ),
                                });
                            }
                        }
                    }
                }
                standalone_claims.sort_by(|left, right| {
                    (left.record_ordinal, left.projection_key().hex())
                        .cmp(&(right.record_ordinal, right.projection_key().hex()))
                });
                debug_assert!(standalone_claims.iter().all(|claim| claim.input_key == input_key));

                // 3. The claims go in first: the A side the request digest
                //    binds *is* the stored claims, so computing that digest
                //    before they exist would commit to a root the rows do not
                //    hash to.
                //
                // A claim whose link already carries a verified installation
                // keeps it: this pre-pass exists to stage the A side, not to
                // demote an installed witness back to its pending form (which
                // recomputing `None` here would do, and which
                // `install_source_links_in_tx` then refuses as a conflict --
                // leaving a retry of an input that already published its links
                // unable to ever proceed). Only a claim with no row, or one
                // still genuinely pending, is staged as pending.
                let mut claims_only: Vec<source_facts::ClaimLinkInstall> =
                    Vec::with_capacity(installs.len() + standalone_claims.len());
                for claim in installs
                    .iter()
                    .map(|(claim, _)| claim)
                    .chain(standalone_claims.iter())
                {
                    let installation = match source_facts::read_installed_link_evidence(
                        tx, input_id, claim,
                    )? {
                        source_facts::InstalledLinkEvidence::Installed(installation) => {
                            Some(*installation)
                        }
                        source_facts::InstalledLinkEvidence::Absent
                        | source_facts::InstalledLinkEvidence::Pending => None,
                    };
                    claims_only.push(source_facts::ClaimLinkInstall {
                        claim: claim.clone(),
                        installation,
                    });
                }
                injected_fault("links")?;
                source_facts::install_source_links_in_tx(tx, input_id, &claims_only)
                    .map_err(SourceIngestError::Install)?;

                // 4. The A side exists now, so the request digest can be
                //    computed over it, and the claims take their installations.
                let request = build_activation_request(
                    tx,
                    input_id,
                    &input_key,
                    &normalizer_id,
                    &safety_contract_id,
                    job,
                )?;
                let mut with_installations: Vec<source_facts::ClaimLinkInstall> = installs
                    .iter()
                    .map(|(claim, outcome)| source_facts::ClaimLinkInstall {
                        claim: claim.clone(),
                        installation: outcome.installation_for_claim(claim, request.digest()),
                    })
                    .collect();
                for claim in &standalone_claims {
                    let class = match claim.mapping_state {
                        source_facts::ClaimMappingState::Standalone => {
                            source_facts::InstallationClass::StandaloneNoBinding
                        }
                        source_facts::ClaimMappingState::Unmapped => {
                            source_facts::InstallationClass::UnmappedNoBinding
                        }
                        source_facts::ClaimMappingState::Canonical => {
                            unreachable!("a canonical leftover was refused above")
                        }
                    };
                    with_installations.push(source_facts::ClaimLinkInstall {
                        claim: claim.clone(),
                        installation: Some(source_facts::OriginalInstallation {
                            semantic_request_digest: request.digest(),
                            class,
                            binding: None,
                            rejection: None,
                            reason: None,
                        }),
                    });
                }
                source_facts::install_source_links_in_tx(tx, input_id, &with_installations)
                    .map_err(SourceIngestError::Install)?;

                injected_fault("activation")?;
                // 5. Activate, then verify the receipt that was just written.
                let activated =
                    source_facts::activate_source_input_in_tx(tx, &request.request, job.input.manifest())
                        .map_err(SourceIngestError::Install)?;
                // A receipt exists only when the activation committed one.
                // The input's own intent is not the test: an input that asked
                // for `Complete` but could only be staged, or whose records
                // published a failure, has no complete state to verify, and
                // verifying it would report an internal inconsistency instead
                // of the unfinished input it is. A staged input stays
                // unfinished and its root keeps its watermark.
                let completes = matches!(
                    &activated,
                    source_facts::SourceActivationOutcome::Activated { .. }
                        | source_facts::SourceActivationOutcome::Replay { .. }
                );
                if !completes {
                    return Ok(SourceInputInstallResult {
                        request: request.request,
                        outcome: activated,
                        accepted_by_conversation,
                        judged_conversations: judged.len(),
                    });
                }
                match source_facts::verify_source_receipt_in_tx(tx, &request.request)
                    .map_err(SourceIngestError::Install)?
                {
                    source_facts::SourceReceiptMatch::VerifiedReplay { .. } => {}
                    other => {
                        return Err(SourceIngestError::Install(SourceInstallError::Receipt(
                            match other {
                                source_facts::SourceReceiptMatch::Conflict { .. } => {
                                    source_facts::ReceiptInconsistency::RecordMismatch
                                }
                                source_facts::SourceReceiptMatch::Absent => {
                                    source_facts::ReceiptInconsistency::InvalidHeader
                                }
                                source_facts::SourceReceiptMatch::Inconsistent { reason } => reason,
                                source_facts::SourceReceiptMatch::VerifiedReplay { .. } => unreachable!(),
                            },
                        )));
                    }
                }
    Ok(SourceInputInstallResult {
        request: request.request,
        outcome: activated,
        accepted_by_conversation,
        judged_conversations: judged.len(),
    })
}

/// Commit one prepared input: one transaction, one receipt.
pub(crate) fn commit_source_input(
    storage: &crate::storage::sqlite::FrankenStorage,
    job: &SourceInputJob,
) -> Result<SourceInputCommit, SourceIngestError> {
    let prepared = prepare_source_input_commit(job)?;
    let input_key = *job.input.input_key();
    let records = prepared.safety.staged.records.len() as u64;
    let judged_conversations = prepared.safety.judged.len() as u64;

    let outcome = {
        let conn = storage.raw();
        conn.with_tx(crate::storage::api::TxMode::Immediate, |tx| {
            install_source_input_in_tx(storage, tx, &prepared)
                .map_err(source_ingest_error_to_storage)
        })
    };

    // Conversations *created* by this input, and messages it inserted. An
    // input that only appended to an existing conversation creates none.
    let count = |accepted: &[(i64, Vec<i64>, bool)]| {
        (
            accepted.iter().filter(|(_, _, created)| *created).count(),
            accepted.iter().map(|(_, ids, _)| ids.len()).sum::<usize>(),
        )
    };

    match outcome {
        Ok(result) => match result.outcome {
            source_facts::SourceActivationOutcome::Activated { .. } => {
                let accepted = result.accepted_by_conversation;
                let (inserted_conversations, inserted_messages) = count(&accepted);
                // The commit is durable; the derivation is read back in memory. A
                // failure to read it is reported as still-pending, never as a
                // failed input, and the rows stay for the catch-up to find.
                match read_back_delta(storage, &accepted) {
                    Ok(delta) => {
                        let semantic_inputs = delta.len();
                        Ok(SourceInputCommit {
                            outcome: SourceInputOutcome::Completed {
                                input_key,
                                records,
                                conversations: judged_conversations,
                                replay: false,
                                semantic_inputs,
                            },
                            delta,
                            inserted_conversations,
                            inserted_messages,
                        })
                    }
                    Err(reason) => Ok(SourceInputCommit {
                        outcome: SourceInputOutcome::PostCommitPendingRecovery {
                            input_key,
                            reason,
                            semantic_inputs: inserted_messages,
                        },
                        delta: Vec::new(),
                        inserted_conversations,
                        inserted_messages,
                    }),
                }
            }
            source_facts::SourceActivationOutcome::Replay { .. } => Ok(SourceInputCommit {
                outcome: SourceInputOutcome::Completed {
                    input_key,
                    records,
                    conversations: judged_conversations,
                    replay: true,
                    semantic_inputs: 0,
                },
                delta: Vec::new(),
                inserted_conversations: 0,
                inserted_messages: 0,
            }),
            source_facts::SourceActivationOutcome::PublishedFailure { state, .. } => {
                Ok(SourceInputCommit {
                    outcome: SourceInputOutcome::Rejected {
                        input_key,
                        reason: format!("terminal state {state:?}"),
                    },
                    delta: Vec::new(),
                    inserted_conversations: 0,
                    inserted_messages: 0,
                })
            }
            source_facts::SourceActivationOutcome::StagedOnly { state, .. } => {
                Ok(SourceInputCommit {
                    outcome: SourceInputOutcome::Transient {
                        input_key,
                        reason: format!("still {state:?}"),
                    },
                    delta: Vec::new(),
                    inserted_conversations: 0,
                    inserted_messages: 0,
                })
            }
        },
        // A retryable storage failure leaves this kernel as its own typed
        // error. Folding `Busy`/`Locked` into a `Transient` outcome here would
        // hide the class from the whole-input retry one writer cycle up, and
        // flattening it into a string would hide it from the caller.
        Err(err) => Err(SourceIngestError::Install(SourceInstallError::Db(err))),
    }
}

#[cfg(test)]
mod content_identity_tests {
    //! The sealed blob's content identity is load-bearing: a blob whose bytes
    //! changed between the capture and the open must be refused.
    //!
    //! The test drives the real `prepare_source_input` over a private fixture
    //! and uses the module's one-shot capture hook to change the blob in place,
    //! keeping its length and its JSON validity so nothing but the identity
    //! check can notice.

    use super::*;
    use franken_agent_detection as fad;

    /// A private root with one Claude session, a data directory and the fixed
    /// safety copy.
    fn fixture() -> (
        tempfile::TempDir,
        Arc<FixedSafetyConfig>,
        crate::connectors::ScanRoot,
        crate::indexer::scan_root_meta::ScanRootMeta,
        crate::connectors::DiscoveredSourceFile,
    ) {
        fixture_with(&[serde_json::json!({
            "type": "user",
            "uuid": "evt-1",
            "message": {"role": "user", "content": "synthetic content identity question"}
        })])
    }

    fn fixture_with(
        lines: &[serde_json::Value],
    ) -> (
        tempfile::TempDir,
        Arc<FixedSafetyConfig>,
        crate::connectors::ScanRoot,
        crate::indexer::scan_root_meta::ScanRootMeta,
        crate::connectors::DiscoveredSourceFile,
    ) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let home = temp.path().join("home");
        let projects = home.join(".claude/projects/proj");
        std::fs::create_dir_all(&projects).expect("mkdir project");
        let session = projects.join("session.jsonl");
        let body: String = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&session, body).expect("write session");

        let copy = temp.path().join("fixed-safety.toml");
        std::fs::write(&copy, include_bytes!("../../config/excluded_context_paths.toml"))
            .expect("write fixed copy");
        let safety = Arc::new(load_fixed_safety_config(&copy).expect("load the fixed copy"));

        let scan_root = crate::connectors::ScanRoot::local(home.join(".claude/projects"));
        let meta = crate::indexer::scan_root_meta::ScanRootMeta {
            root_id: "home:claude:synthetic".to_string(),
            origin_host: "local".to_string(),
            readonly: false,
            canonical_path: home.join(".claude/projects"),
            source_name: "claude".to_string(),
            watermarks_enabled: true,
            mirror_root: false,
        };
        let discovered = crate::connectors::DiscoveredSourceFile {
            provider_slug: "claude_code".to_string(),
            scan_root: home.join(".claude/projects"),
            source_path: session,
            role: crate::connectors::DiscoveredSourceRole::PrimarySessionLog,
            origin: crate::connectors::Origin::local(),
            platform: None,
            required_for_reconstruction: true,
            size_bytes: None,
            modified_at_ms: None,
        };
        (temp, safety, scan_root, meta, discovered)
    }

    /// A private root whose session is read by the Codex connector.
    fn fixture_codex(
        lines: &[serde_json::Value],
    ) -> (
        tempfile::TempDir,
        Arc<FixedSafetyConfig>,
        crate::connectors::ScanRoot,
        crate::indexer::scan_root_meta::ScanRootMeta,
        crate::connectors::DiscoveredSourceFile,
    ) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let home = temp.path().join("home");
        let sessions = home.join(".codex/sessions/2026/01");
        std::fs::create_dir_all(&sessions).expect("mkdir codex sessions");
        let session = sessions.join("rollout-2026-01-01T00-00-00-session.jsonl");
        let body: String = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        std::fs::write(&session, body).expect("write session");

        let copy = temp.path().join("fixed-safety.toml");
        std::fs::write(&copy, include_bytes!("../../config/excluded_context_paths.toml"))
            .expect("write fixed copy");
        let safety = Arc::new(load_fixed_safety_config(&copy).expect("load the fixed copy"));

        let scan_root = crate::connectors::ScanRoot::local(home.join(".codex/sessions"));
        let meta = crate::indexer::scan_root_meta::ScanRootMeta {
            root_id: "home:codex:synthetic".to_string(),
            origin_host: "local".to_string(),
            readonly: false,
            canonical_path: home.join(".codex/sessions"),
            source_name: "codex".to_string(),
            watermarks_enabled: true,
            mirror_root: false,
        };
        let discovered = crate::connectors::DiscoveredSourceFile {
            provider_slug: "codex".to_string(),
            scan_root: home.join(".codex/sessions"),
            source_path: session,
            role: crate::connectors::DiscoveredSourceRole::PrimarySessionLog,
            origin: crate::connectors::Origin::local(),
            platform: None,
            required_for_reconstruction: true,
            size_bytes: None,
            modified_at_ms: None,
        };
        (temp, safety, scan_root, meta, discovered)
    }

    /// A Codex session whose first user turn is a shell opener, i.e. the shape
    /// the connector's own anchor excludes.
    fn codex_excluded_lines() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:00.000Z",
                "type": "session_meta",
                "payload": {"id": "sess-codex", "cwd": "/synthetic/project", "cli_version": "0.42.0"}
            }),
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:01.000Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": "sess-codex-msg-1",
                    "role": "user",
                    "content": [{"type": "input_text", "text":
                        "<environment_context>\n<cwd>/synthetic/project</cwd>\nsynthetic body that anchoring must exclude\n</environment_context>"}]
                }
            }),
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:02.000Z",
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "id": "sess-codex-msg-2",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "acknowledged"}]
                }
            }),
        ]
    }

    fn prepare(
        temp: &tempfile::TempDir,
        safety: &Arc<FixedSafetyConfig>,
        root: &crate::connectors::ScanRoot,
        meta: &crate::indexer::scan_root_meta::ScanRootMeta,
        discovered: &crate::connectors::DiscoveredSourceFile,
    ) -> Result<SourceInputJob, SourceIngestError> {
        prepare_with("claude", temp, safety, root, meta, discovered)
    }

    fn prepare_with(
        connector_name: &str,
        temp: &tempfile::TempDir,
        safety: &Arc<FixedSafetyConfig>,
        root: &crate::connectors::ScanRoot,
        meta: &crate::indexer::scan_root_meta::ScanRootMeta,
        discovered: &crate::connectors::DiscoveredSourceFile,
    ) -> Result<SourceInputJob, SourceIngestError> {
        let connector: Box<dyn crate::connectors::Connector + Send> = match connector_name {
            "codex" => Box::new(crate::connectors::codex::CodexConnector::new()),
            _ => Box::new(crate::connectors::claude_code::ClaudeCodeConnector::new()),
        };
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("mkdir data");
        let request = SourceInputRequest {
            connector_name: connector_name_for(connector_name),
            data_dir: &data_dir,
            root,
            meta,
            discovered,
            safety,
        };
        prepare_source_input(connector.as_ref(), &request)
    }

    fn connector_name_for(name: &str) -> &'static str {
        match name {
            "codex" => "codex",
            _ => "claude",
        }
    }

    /// SRC05B-08: the association key carries every declared identity field,
    /// including the declared source positions, so two declarations that differ
    /// only in a declared pointer are not the same claim; the derived
    /// `index_path` is deliberately not part of it.
    #[test]
    fn the_claim_identity_key_separates_declared_positions_and_ignores_the_derived_path() {
        let base = source_facts::SourceClaim {
            input_key: Sha256Digest::of(b"input"),
            record_ordinal: 1,
            record_pointer: "r0".to_string(),
            conversation_ordinal: Some(0),
            final_message_idx: Some(0),
            positions: vec![source_facts::SafePosition {
                index_path: vec![source_facts::IndexStep::ObjectMember(0)],
                original_pointer_sha256: Sha256Digest::of(b"/message/content"),
                safe_pointer: Some("/message/content".to_string()),
            }],
            projection_pointer: Some("/messages/0".to_string()),
            evidence_kind: source_facts::EvidenceKind::Prose,
            mapping_state: source_facts::ClaimMappingState::Canonical,
        };
        let key = claim_identity_key(&base);

        // The derived path is not identity.
        let mut derived_only = base.clone();
        derived_only.positions[0].index_path = vec![source_facts::IndexStep::ArrayElement(9)];
        assert_eq!(claim_identity_key(&derived_only), key);

        // A declared pointer is.
        let mut other_pointer = base.clone();
        other_pointer.positions[0].safe_pointer = Some("/message/other".to_string());
        assert_ne!(claim_identity_key(&other_pointer), key);

        let mut other_digest = base.clone();
        other_digest.positions[0].original_pointer_sha256 = Sha256Digest::of(b"/other");
        assert_ne!(claim_identity_key(&other_digest), key);

        let mut other_kind = base.clone();
        other_kind.evidence_kind = source_facts::EvidenceKind::ToolCall;
        assert_ne!(claim_identity_key(&other_kind), key);

        let mut other_record = base.clone();
        other_record.record_pointer = "r1".to_string();
        assert_ne!(claim_identity_key(&other_record), key);

        // Both are valid JSON pointers. A delimiter-joined key made these
        // different record/target declarations indistinguishable.
        let mut left = base.clone();
        left.record_pointer = "/r".to_string();
        left.projection_pointer = Some("/p|0|1|/q".to_string());
        let mut right = base.clone();
        right.record_pointer = "/r|0|0|/p".to_string();
        right.final_message_idx = Some(1);
        right.projection_pointer = Some("/q".to_string());
        assert_ne!(claim_identity_key(&left), claim_identity_key(&right));

        let mut missing = base.clone();
        missing.positions[0].safe_pointer = None;
        let mut literal = missing.clone();
        literal.positions[0].safe_pointer = Some("-".to_string());
        assert_ne!(claim_identity_key(&missing), claim_identity_key(&literal));
    }

    #[test]
    fn a_blob_changed_between_capture_and_open_is_refused() {
        let (temp, safety, root, meta, discovered) = fixture();

        // Change one character of the blob in place. The length is unchanged,
        // the JSON still parses, and the capture record still names the digest
        // it recorded -- so only a content-identity check can refuse this.
        let _guard = test_hooks::arm_after_capture(|blob: &std::path::Path| {
            let mut bytes = std::fs::read(blob).expect("read the sealed blob");
            let needle = b"synthetic content identity question";
            let at = bytes
                .windows(needle.len())
                .position(|window| window == needle)
                .expect("the fixture body is in the blob");
            // Same length, still valid JSON.
            bytes[at + needle.len() - 1] = b'x';
            std::fs::write(blob, &bytes).expect("rewrite the sealed blob");
        });

        let outcome = prepare(&temp, &safety, &root, &meta, &discovered);
        assert!(
            outcome.is_err(),
            "a sealed blob whose bytes changed must be refused, not ingested"
        );
    }

    /// The whole input kernel on one storage object: a late fault rolls the
    /// input back, and the retry on the *same* connection succeeds with no
    /// ghost id left behind.
    #[test]
    fn a_failed_commit_retries_cleanly_on_the_same_storage_object() {
        let (temp, safety, root, meta, discovered) = fixture();
        let job = prepare(&temp, &safety, &root, &meta, &discovered)
            .expect("the fixture prepares");
        let storage = crate::storage::sqlite::FrankenStorage::open(&temp.path().join("data/agent_search.db"))
            .expect("open the database");

        let _stopped = test_hooks::arm_fail_at("activation");
        let failed = commit_source_input(&storage, &job);
        assert!(
            failed.is_err(),
            "the armed fault must stop the commit at activation"
        );
        test_hooks::clear_fail_at();

        let commit = commit_source_input(&storage, &job)
            .expect("the retry on the same storage object succeeds");
        assert!(
            commit.outcome.is_success(),
            "the retry completes the input: {:?}",
            commit.outcome
        );

        let db = storage.raw();
        let inputs: i64 = db
            .query_row_map("SELECT COUNT(*) FROM source_inputs", &[], |row| row.get_typed(0))
            .expect("count inputs");
        assert_eq!(inputs, 1);
        let complete: i64 = db
            .query_row_map(
                "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("count complete");
        assert_eq!(complete, 1);
        let messages: i64 = db
            .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
            .expect("count messages");
        assert!(messages >= 1, "the session's messages landed");
        let dangling: i64 = db
            .query_row_map(
                "SELECT COUNT(*) FROM source_message_links WHERE message_id IS NULL",
                &[],
                |row| row.get_typed(0),
            )
            .expect("count dangling links");
        assert_eq!(dangling, 0, "no link points at a ghost message");
        let receipts: i64 = db
            .query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt WHERE state = 'committed'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("count receipts");
        assert_eq!(receipts, 1, "exactly one receipt for one completed input");
    }

    /// A post-commit read failure is its own classification, not a failure and
    /// not a quiet success.
    #[test]
    fn a_post_commit_read_failure_is_reported_as_pending_recovery() {
        let (temp, safety, root, meta, discovered) = fixture();
        let job = prepare(&temp, &safety, &root, &meta, &discovered)
            .expect("the fixture prepares");
        let storage = crate::storage::sqlite::FrankenStorage::open(
            &temp.path().join("data/agent_search.db"),
        )
        .expect("open the database");

        let _armed = test_hooks::arm_fail_at("postcommit");
        let commit = commit_source_input(&storage, &job).expect("the commit itself succeeds");
        assert!(matches!(
            commit.outcome,
            SourceInputOutcome::PostCommitPendingRecovery { .. }
        ), "the failure to read the delta back is reported as pending recovery: {:?}", commit.outcome);
        assert!(
            commit.outcome.is_success(),
            "the input still lets its root count as scanned"
        );
        assert!(
            commit.delta.is_empty(),
            "a delta that could not be read back is not reported as delivered"
        );
        assert!(
            commit.inserted_messages >= 1,
            "the commit still counts the rows it wrote: {commit:?}",
        );

        // The commit stands: receipt present, input complete, rows durable.
        let db = storage.raw();
        let complete: i64 = db
            .query_row_map(
                "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("count complete");
        assert_eq!(complete, 1);
        let receipts: i64 = db
            .query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt WHERE state = 'committed'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("count receipts");
        assert_eq!(receipts, 1);
    }

    /// The commit hands back the delta it actually created: one entry per new
    /// message, carrying that message's id and its already-desensitised body.
    #[test]
    fn a_commit_returns_the_real_delta_for_the_messages_it_inserted() {
        let (temp, safety, root, meta, discovered) = fixture();
        let job = prepare(&temp, &safety, &root, &meta, &discovered)
            .expect("the fixture prepares");
        let storage = crate::storage::sqlite::FrankenStorage::open(
            &temp.path().join("data/agent_search.db"),
        )
        .expect("open the database");

        let commit = commit_source_input(&storage, &job).expect("the first commit succeeds");
        let SourceInputOutcome::Completed { semantic_inputs, replay, .. } = commit.outcome else {
            panic!("expected a completed first commit, got {:?}", commit.outcome);
        };
        assert!(!replay);
        assert_eq!(
            commit.delta.len(),
            semantic_inputs,
            "the reported size is the payload's own size"
        );
        assert_eq!(
            commit.inserted_messages,
            commit.delta.len(),
            "one delta entry per inserted message"
        );
        assert_eq!(commit.inserted_conversations, 1);
        assert!(!commit.delta.is_empty(), "the fixture's message is in the delta");
        for input in &commit.delta {
            assert!(input.message_id > 0, "the delta names a real message id");
            assert!(
                input.content.contains("synthetic content identity question"),
                "the delta carries the canonical body: {:?}",
                input.content
            );
        }

        // A replay creates nothing, so its delta is empty and nothing is
        // counted as inserted.
        let replay = commit_source_input(&storage, &job).expect("the replay succeeds");
        assert!(matches!(
            replay.outcome,
            SourceInputOutcome::Completed { replay: true, .. }
        ));
        assert!(replay.delta.is_empty(), "a replay adds no delta");
        assert_eq!(replay.inserted_messages, 0);
        assert_eq!(replay.inserted_conversations, 0);
    }

    /// Appending to a conversation that already exists creates no conversation
    /// and still inserts its new messages.
    #[test]
    fn appending_to_an_existing_conversation_counts_only_the_new_messages() {
        let (temp, safety, root, meta, discovered) = fixture();
        let storage = crate::storage::sqlite::FrankenStorage::open(
            &temp.path().join("data/agent_search.db"),
        )
        .expect("open the database");

        let first = prepare(&temp, &safety, &root, &meta, &discovered).expect("prepare");
        let first_commit = commit_source_input(&storage, &first).expect("first commit");
        assert_eq!(first_commit.inserted_conversations, 1, "the first input creates the row");

        // Extend the same session: same conversation, one more message.
        let mut body = std::fs::read_to_string(&discovered.source_path).expect("read the session");
        body.push_str(
            &serde_json::json!({
                "type": "assistant",
                "uuid": "evt-2",
                "message": {"role": "assistant", "content": "synthetic appended answer"}
            })
            .to_string(),
        );
        body.push('\n');
        std::fs::write(&discovered.source_path, body).expect("append to the session");

        let second = prepare(&temp, &safety, &root, &meta, &discovered).expect("prepare again");
        let second_commit = commit_source_input(&storage, &second).expect("second commit");
        assert_eq!(
            second_commit.inserted_conversations, 0,
            "an append creates no conversation"
        );
        assert!(
            second_commit.inserted_messages >= 1,
            "the appended message is still inserted: {second_commit:?}"
        );
    }

    /// A deterministic, purely synthetic embedding used by the recovery test.
    /// It is a fixture, not a claim about any real model.
    fn synthetic_vector(text: &str, dim: usize) -> Vec<f32> {
        let mut hash: u64 = 1469598103934665603;
        for byte in text.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(1099511628211);
        }
        let mut out: Vec<f32> = (0..dim)
            .map(|i| {
                let mixed = hash.wrapping_add((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
                ((mixed >> 11) as f32 / (1u64 << 53) as f32) - 0.5
            })
            .collect();
        let norm: f32 = out.iter().map(|value| value * value).sum::<f32>().sqrt();
        if norm > 0.0 {
            for value in out.iter_mut() {
                *value /= norm;
            }
        }
        out
    }

    /// The committed rows are recoverable by the existing catch-up: the holes
    /// this input left are drained and its chunks get vectors.
    #[test]
    fn the_committed_rows_are_recovered_by_the_existing_catchup() {
        use crate::search::generation_fingerprint::FINGERPRINT_SENTINELS;

        let (temp, safety, root, meta, discovered) = fixture();
        let job = prepare(&temp, &safety, &root, &meta, &discovered).expect("prepare");
        let storage = crate::storage::sqlite::FrankenStorage::open(
            &temp.path().join("data/agent_search.db"),
        )
        .expect("open the database");
        let commit = commit_source_input(&storage, &job).expect("commit");
        assert!(commit.outcome.is_success());

        let dim = 8usize;
        let identity = crate::indexer::db_vector_catchup::ServedEmbeddingIdentity {
            model_id: "synthetic-src05b07".to_string(),
            dimension: dim,
        };
        // The fingerprint is built from the *official* sentinels through this
        // same callback: the values are imported, never re-typed.
        let mut fingerprint = Vec::new();
        for sentinel in FINGERPRINT_SENTINELS {
            fingerprint
                .extend_from_slice(&crate::storage::schema::f32_vector_to_le_blob(&synthetic_vector(
                    sentinel, dim,
                )));
        }
        let embed = |texts: &[&str]| -> std::result::Result<Vec<Vec<f32>>, String> {
            Ok(texts.iter().map(|text| synthetic_vector(text, dim)).collect())
        };

        let report = crate::indexer::db_vector_catchup::run_db_vector_catchup_backfill(
            &storage,
            100,
            &identity,
            crate::search::canonicalize::CANONICALIZE_PIPELINE_VERSION,
            crate::search::chunking::CHUNKING_POLICY_VERSION,
            &fingerprint,
            &embed,
            7,
        )
        .expect("the backfill runs");

        assert_eq!(
            report.holes_after, 0,
            "the catch-up drains the holes the commit left: {report:?}"
        );
        assert!(
            report.vec0_rows >= 1,
            "the committed chunk got a vector: {report:?}"
        );
        assert_eq!(report.embedder_id, identity.model_id);
    }

    /// The delta test also pins *which* messages it carries and that their
    /// bodies are the desensitised ones.
    #[test]
    fn the_delta_names_exactly_the_canonical_rows_it_created() {
        const SENTINEL: &str = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"; // ubs:ignore -- synthetic fixture.
        let lines = [serde_json::json!({
            "type": "user",
            "uuid": "evt-secret",
            "message": {"role": "user", "content": format!("key {SENTINEL} lives here")}
        })];
        let (temp, safety, root, meta, discovered) = fixture_with(&lines);
        let job = prepare(&temp, &safety, &root, &meta, &discovered).expect("prepare");
        let storage = crate::storage::sqlite::FrankenStorage::open(
            &temp.path().join("data/agent_search.db"),
        )
        .expect("open the database");
        let commit = commit_source_input(&storage, &job).expect("commit");

        let canonical: std::collections::BTreeSet<i64> = {
            let db = storage.raw();
            let rows: Vec<i64> = db
                .query_all_map("SELECT id FROM messages", &[], |row| row.get_typed(0))
                .expect("read the canonical ids");
            rows.into_iter().collect()
        };
        let delta_ids: std::collections::BTreeSet<i64> =
            commit.delta.iter().map(|input| input.message_id as i64).collect();
        assert_eq!(
            delta_ids, canonical,
            "the delta names exactly the canonical rows this commit created"
        );
        for input in &commit.delta {
            assert!(
                !input.content.contains(SENTINEL),
                "the delta body is desensitised: {:?}",
                input.content
            );
            assert!(input.content.contains("[REDACTED]"));
        }
    }

    /// The full recovery scenario: an existing generation, a post-commit
    /// failure, a reopen, a replay that adds nothing, and a real backfill that
    /// covers the new messages' vectors.
    #[test]
    fn recovery_after_a_post_commit_failure_covers_the_new_messages() {
        use crate::search::generation_fingerprint::FINGERPRINT_SENTINELS;

        const DIM: usize = 8;
        let identity = crate::indexer::db_vector_catchup::ServedEmbeddingIdentity {
            model_id: "synthetic-src05b07-full".to_string(),
            dimension: DIM,
        };
        let mut fingerprint = Vec::new();
        for sentinel in FINGERPRINT_SENTINELS {
            fingerprint
                .extend_from_slice(&crate::storage::schema::f32_vector_to_le_blob(&synthetic_vector(
                    sentinel, DIM,
                )));
        }
        let embed = |texts: &[&str]| -> std::result::Result<Vec<Vec<f32>>, String> {
            Ok(texts.iter().map(|text| synthetic_vector(text, DIM)).collect())
        };
        let backfill = |storage: &crate::storage::sqlite::FrankenStorage| {
            crate::indexer::db_vector_catchup::run_db_vector_catchup_backfill(
                storage,
                100,
                &identity,
                crate::search::canonicalize::CANONICALIZE_PIPELINE_VERSION,
                crate::search::chunking::CHUNKING_POLICY_VERSION,
                &fingerprint,
                &embed,
                7,
            )
            .expect("the backfill runs")
        };

        let (temp, safety, root, meta, discovered) = fixture();
        let db_path = temp.path().join("data/agent_search.db");
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).expect("open");

        // A first input establishes the generation the later one recovers into.
        let first = prepare(&temp, &safety, &root, &meta, &discovered).expect("prepare");
        let first_commit = commit_source_input(&storage, &first).expect("the first commit");
        assert!(first_commit.outcome.is_success());
        let genesis = backfill(&storage);
        assert!(genesis.activated, "the first backfill activates: {genesis:?}");

        // A second, distinct input, committed with the derivation read failing.
        let second_path = discovered
            .scan_root
            .join("proj/session-second.jsonl");
        std::fs::write(
            &second_path,
            format!(
                "{}\n",
                serde_json::json!({
                    "type": "user",
                    "uuid": "evt-second",
                    "message": {"role": "user", "content": "synthetic second question"}
                })
            ),
        )
        .expect("write the second session");
        let mut second = discovered.clone();
        second.source_path = second_path;
        let job = prepare(&temp, &safety, &root, &meta, &second).expect("prepare");
        let ids_now = |storage: &crate::storage::sqlite::FrankenStorage| {
            let rows: Vec<i64> = storage
                .raw()
                .query_all_map("SELECT id FROM messages", &[], |row| row.get_typed(0))
                .expect("read the canonical ids");
            rows.into_iter().collect::<std::collections::BTreeSet<i64>>()
        };
        let before_ids = ids_now(&storage);

        let stopped = test_hooks::arm_fail_at("postcommit");
        let commit = commit_source_input(&storage, &job).expect("the commit itself succeeds");
        drop(stopped);
        test_hooks::clear_fail_at();
        assert!(
            matches!(
                commit.outcome,
                SourceInputOutcome::PostCommitPendingRecovery { .. }
            ),
            "the derivation is pending: {:?}",
            commit.outcome
        );
        // A pending derivation has no delta, so the new rows are taken from the
        // database itself: the difference the commit made.
        assert!(
            commit.delta.is_empty(),
            "a pending derivation reports no delivered delta"
        );
        let inserted = commit.inserted_messages;
        let after_ids = ids_now(&storage);
        let new_ids: std::collections::BTreeSet<i64> =
            after_ids.difference(&before_ids).copied().collect();
        assert!(
            !new_ids.is_empty(),
            "the commit inserted rows even though its derivation is pending"
        );
        assert_eq!(
            new_ids.len(),
            inserted,
            "the new id set is exactly what the commit counted"
        );
        assert!(
            new_ids.is_disjoint(&before_ids),
            "the baseline rows are not mixed into the new set"
        );
        let receipt_keys_before: String = {
            let db = storage.raw();
            db.query_row_map(
                "SELECT group_concat(idempotency_key, '|') FROM operation_commit_receipt",
                &[],
                |row| row.get_typed(0),
            )
            .expect("read receipts")
        };
        let generation_before: String = {
            let db = storage.raw();
            db.query_row_map(
                "SELECT value FROM meta WHERE key = 'source_content_generation'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("read generation")
        };
        drop(storage);

        // Re-open the same database and re-submit the *same* prepared input:
        // the same sealed identity, so this is a replay of that input and not a
        // fresh capture.
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).expect("re-open");
        let replay = commit_source_input(&storage, &job).expect("the replay succeeds");
        assert!(
            matches!(replay.outcome, SourceInputOutcome::Completed { replay: true, .. }),
            "a replay: {:?}",
            replay.outcome
        );
        assert_eq!(replay.inserted_messages, 0);
        assert!(replay.delta.is_empty());

        let after_replay: (String, String) = {
            let db = storage.raw();
            (
                db.query_row_map(
                    "SELECT group_concat(idempotency_key, '|') FROM operation_commit_receipt",
                    &[],
                    |row| row.get_typed(0),
                )
                .expect("read receipts"),
                db.query_row_map(
                    "SELECT value FROM meta WHERE key = 'source_content_generation'",
                    &[],
                    |row| row.get_typed(0),
                )
                .expect("read generation"),
            )
        };
        assert_eq!(
            after_replay.0, receipt_keys_before,
            "a replay rewrites no receipt"
        );
        assert_eq!(
            after_replay.1, generation_before,
            "a replay moves no content generation"
        );

        // The real catch-up recovers the messages the failed derivation left.
        let recovered = backfill(&storage);
        assert_eq!(
            recovered.holes_after, 0,
            "the catch-up drains every hole: {recovered:?}"
        );
        let db = storage.raw();
        let covered: i64 = db
            .query_row_map(
                "SELECT COUNT(DISTINCT message_id) FROM message_chunks
                 WHERE generation_id = ?1 AND length(embedding) = 4 * ?2",
                &[
                    crate::storage::api::Value::Integer(recovered.generation_id),
                    crate::storage::api::Value::Integer(DIM as i64),
                ],
                |row| row.get_typed(0),
            )
            .expect("count covered messages");
        assert!(
            covered >= inserted as i64,
            "every new message has a vector in the active generation: covered={covered} inserted={inserted}"
        );
        for id in &new_ids {
            let chunked: i64 = db
                .query_row_map(
                    "SELECT COUNT(*) FROM message_chunks
                     WHERE generation_id = ?1 AND message_id = ?2 AND length(embedding) = 4 * ?3",
                    &[
                        crate::storage::api::Value::Integer(recovered.generation_id),
                        crate::storage::api::Value::Integer(*id),
                        crate::storage::api::Value::Integer(DIM as i64),
                    ],
                    |row| row.get_typed(0),
                )
                .expect("count one message's chunks");
            assert!(
                chunked >= 1,
                "message {id} was recovered into the active generation"
            );
        }
    }

    /// Changing the live source after a capture does not change the sealed
    /// input's replay: the committed rows keep the bytes they were sealed with.
    #[test]
    fn a_live_source_change_does_not_alter_a_sealed_replay() {
        let (temp, safety, root, meta, discovered) = fixture();
        let storage = crate::storage::sqlite::FrankenStorage::open(
            &temp.path().join("data/agent_search.db"),
        )
        .expect("open the database");
        let job = prepare(&temp, &safety, &root, &meta, &discovered).expect("prepare");
        let first = commit_source_input(&storage, &job).expect("the first commit");
        assert!(matches!(
            first.outcome,
            SourceInputOutcome::Completed { replay: false, .. }
        ));

        let receipt_before: String = storage
            .raw()
            .query_row_map(
                "SELECT group_concat(idempotency_key, '|') FROM operation_commit_receipt",
                &[],
                |row| row.get_typed(0),
            )
            .expect("receipts");
        let generation_before: String = storage
            .raw()
            .query_row_map(
                "SELECT value FROM meta WHERE key = 'source_content_generation'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("generation");
        let messages_before: i64 = storage
            .raw()
            .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
            .expect("messages");

        // The live file changes underneath the already-sealed input.
        let mut body = std::fs::read_to_string(&discovered.source_path).expect("read");
        body.push_str(
            &serde_json::json!({
                "type": "assistant",
                "uuid": "evt-live-change",
                "message": {"role": "assistant", "content": "synthetic live-only text"}
            })
            .to_string(),
        );
        body.push('\n');
        std::fs::write(&discovered.source_path, body).expect("rewrite the live file");

        // The same sealed input replays: nothing moves, and the live-only text
        // never reaches the store.
        let replay = commit_source_input(&storage, &job).expect("the replay succeeds");
        assert!(matches!(
            replay.outcome,
            SourceInputOutcome::Completed { replay: true, .. }
        ));
        let receipt_after: String = storage
            .raw()
            .query_row_map(
                "SELECT group_concat(idempotency_key, '|') FROM operation_commit_receipt",
                &[],
                |row| row.get_typed(0),
            )
            .expect("receipts");
        assert_eq!(receipt_after, receipt_before);
        let generation_after: String = storage
            .raw()
            .query_row_map(
                "SELECT value FROM meta WHERE key = 'source_content_generation'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("generation");
        assert_eq!(generation_after, generation_before);
        let messages_after: i64 = storage
            .raw()
            .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
            .expect("messages");
        assert_eq!(messages_after, messages_before, "a replay adds no row");
        let leaked: i64 = storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM messages WHERE content LIKE '%synthetic live-only text%'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("search the live text");
        assert_eq!(leaked, 0, "the live edit is not part of the sealed input");
    }

    /// A blob that is truncated between capture and open is content the
    /// verifier never agreed to, so the input is refused.
    #[test]
    fn a_truncated_blob_is_refused() {
        let (temp, safety, root, meta, discovered) = fixture();
        let _guard = test_hooks::arm_after_capture(|blob: &std::path::Path| {
            let mut bytes = std::fs::read(blob).expect("read the sealed blob");
            bytes.truncate(bytes.len() / 2);
            std::fs::write(blob, &bytes).expect("truncate the sealed blob");
        });
        let outcome = prepare(&temp, &safety, &root, &meta, &discovered);
        assert!(
            outcome.is_err(),
            "a truncated blob must be refused, not framed as a shorter input"
        );
    }

    /// A session whose tool result reads an injection-only filename, so the
    /// connector's own anchor excludes that row.
    fn excluded_session() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "type": "assistant",
                "uuid": "evt-read",
                "message": {"role": "assistant", "content": [
                    {"type": "text", "text": "reading the file"},
                    {"type": "tool_use", "id": "toolu_synthetic_1", "name": "Read",
                     "input": {"file_path": "/synthetic/CLAUDE.local.md"}}
                ]}
            }),
            serde_json::json!({
                "type": "user",
                "uuid": "evt-result",
                "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_synthetic_1",
                     "content": "synthetic injected body that anchoring must exclude"}
                ]}
            }),
        ]
    }

    /// I4 in-kernel negative: a read that drops a record -- from the middle or
    /// from the end -- never agrees with the scan's own denominator.
    #[test]
    fn a_read_that_drops_a_record_is_refused() {
        let lines: Vec<serde_json::Value> = (0..3)
            .map(|n| {
                serde_json::json!({
                    "type": "user",
                    "uuid": format!("evt-{n}"),
                    "message": {"role": "user", "content": format!("synthetic turn {n}")}
                })
            })
            .collect();

        for drop_middle in [true, false] {
            let (temp, safety, root, meta, discovered) = fixture_with(&lines);
            let _guard = test_hooks::arm_after_read(move |records, _finish| {
                // The connector's own finish and the independent manifest are
                // left exactly as they were: only the delivery is short.
                if drop_middle {
                    records.remove(1);
                } else {
                    records.pop();
                }
            });
            let outcome = prepare(&temp, &safety, &root, &meta, &discovered);
            assert!(
                outcome.is_err(),
                "a read that drops a {} record must be refused, not accepted as shorter",
                if drop_middle { "middle" } else { "last" }
            );
            assert_eq!(
                test_hooks::hits(),
                vec!["after_read"],
                "the tamper really fired"
            );
        }
    }

    /// I4 in-kernel negative: a read whose own finish disagrees with the
    /// independent measurement is refused.
    #[test]
    fn a_read_with_a_wrong_finish_is_refused() {
        let (temp, safety, root, meta, discovered) = fixture();
        let _guard = test_hooks::arm_after_read(|_records, finish| {
            finish.records_seen = finish.records_seen.saturating_add(1);
        });
        let outcome = prepare(&temp, &safety, &root, &meta, &discovered);
        assert!(
            outcome.is_err(),
            "a finish that disagrees with the independent framing is refused"
        );
        assert_eq!(test_hooks::hits(), vec!["after_read"]);
    }

    /// I4 in-kernel negative: a read that stops short of the end is refused,
    /// however complete its own counts look.
    #[test]
    fn a_read_that_stops_before_eof_is_refused() {
        let (temp, safety, root, meta, discovered) = fixture();
        let _guard = test_hooks::arm_after_read(|_records, finish| {
            finish.reached_eof = false;
        });
        let outcome = prepare(&temp, &safety, &root, &meta, &discovered);
        assert!(
            outcome.is_err(),
            "a read that did not reach the end of the sealed bytes is refused"
        );
        assert_eq!(test_hooks::hits(), vec!["after_read"]);
    }

    /// I5 in-kernel negative: a body the record cannot be shown to contain
    /// fails the record instead of being kept.
    #[test]
    fn a_body_that_cannot_be_located_in_its_record_fails_the_record() {
        let lines = codex_excluded_lines();

        // Control, on its own database: this session's exclusion is provable
        // and the input commits.
        {
            let (temp, safety, root, meta, discovered) = fixture_codex(&lines);
            let ok = prepare_with("codex", &temp, &safety, &root, &meta, &discovered)
                .expect("prepare");
            assert!(
                !ok.records.is_empty(),
                "the control's read delivered records"
            );
            let storage = crate::storage::sqlite::FrankenStorage::open(
                &temp.path().join("data/agent_search.db"),
            )
            .expect("open the database");
            assert!(
                commit_source_input(&storage, &ok).expect("commit").outcome.is_success(),
                "the control's exclusion is provable"
            );
        }

        let (temp, safety, root, meta, discovered) = fixture_codex(&lines);
        let storage = crate::storage::sqlite::FrankenStorage::open(
            &temp.path().join("data/agent_search.db"),
        )
        .expect("open the database");
        let _guard = test_hooks::arm_before_body_clear(|_ordinal, bodies| {
            // A body the record does not contain anywhere, so the clearing has
            // nowhere to land.
            bodies.push(ExcludedBody {
                element_pointer: None,
                body: "a body that appears nowhere in this record".to_string(),
            });
        });
        let job = prepare_with("codex", &temp, &safety, &root, &meta, &discovered)
            .expect("prepare");
        let result = commit_source_input(&storage, &job);
        assert_eq!(
            test_hooks::hits(),
            vec!["before_body_clear"],
            "the body hook really fired on a record that carries bodies"
        );
        let error = result.expect_err("an excluded body that cannot be located must fail its record");
        assert!(
            error.to_string().contains("could not be located"),
            "the refusal names the reason: {error}"
        );
    }

    /// I3 in-kernel: with two projections of one input, a failure at the
    /// second rolls the first back too.
    #[test]
    fn a_failure_at_the_second_projection_rolls_the_first_back() {
        let (temp, safety, root, meta, discovered) = fixture();
        let storage = crate::storage::sqlite::FrankenStorage::open(
            &temp.path().join("data/agent_search.db"),
        )
        .expect("open the database");
        let mut job = prepare(&temp, &safety, &root, &meta, &discovered).expect("prepare");

        // A synthetic second projection of the same input, on its own ordinal.
        let second = Pass1Conversation {
            ordinal: 1,
            conversation: job.conversations[0].conversation.clone(),
            claims: job.conversations[0]
                .claims
                .iter()
                .cloned()
                .map(|mut claim| {
                    claim.conversation_ordinal = Some(1);
                    claim
                })
                .collect(),
        };
        for record in job.records.iter_mut() {
            let extra: Vec<fad::SourceMappingClaim> = record
                .claims
                .iter()
                .cloned()
                .map(|mut claim| {
                    claim.conversation_ordinal = Some(1);
                    claim
                })
                .collect();
            record.claims.extend(extra);
        }
        job.conversations.push(second);

        // Control: the same job with no fault commits, which is what proves the
        // first projection really writes before the second one runs.
        {
            let (temp, safety, root, meta, discovered) = fixture();
            let storage = crate::storage::sqlite::FrankenStorage::open(
                &temp.path().join("data/agent_search.db"),
            )
            .expect("open the database");
            let mut control =
                prepare(&temp, &safety, &root, &meta, &discovered).expect("prepare");
            control.conversations.push(Pass1Conversation {
                ordinal: 1,
                conversation: control.conversations[0].conversation.clone(),
                claims: control.conversations[0]
                    .claims
                    .iter()
                    .cloned()
                    .map(|mut claim| {
                        claim.conversation_ordinal = Some(1);
                        claim
                    })
                    .collect(),
            });
            for record in control.records.iter_mut() {
                let extra: Vec<fad::SourceMappingClaim> = record
                    .claims
                    .iter()
                    .cloned()
                    .map(|mut claim| {
                        claim.conversation_ordinal = Some(1);
                        claim
                    })
                    .collect();
                record.claims.extend(extra);
            }
            assert!(
                commit_source_input(&storage, &control)
                    .expect("the control commits")
                    .outcome
                    .is_success(),
                "without a fault the dual-projection job completes"
            );
            let written: i64 = storage
                .raw()
                .query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
                .expect("count messages");
            assert!(written > 0, "the control really wrote canonical rows");
        }

        // The *second* projection is the one that fails.
        let _guard = test_hooks::arm_fail_at_nth("projection", 2);
        let result = commit_source_input(&storage, &job);
        let error = result.expect_err("the second projection's failure must fail the input");
        assert_eq!(
            test_hooks::hits(),
            vec!["fail_at_nth"],
            "the second-projection fault really fired"
        );
        assert!(
            error.to_string().contains("injected fault at projection"),
            "and it is that fault, not an earlier refusal: {error}"
        );

        let db = storage.raw();
        for (label, sql) in [
            ("messages", "SELECT COUNT(*) FROM messages"),
            ("conversations", "SELECT COUNT(*) FROM conversations"),
            ("links", "SELECT COUNT(*) FROM source_message_links"),
            ("records", "SELECT COUNT(*) FROM source_records"),
            ("receipts", "SELECT COUNT(*) FROM operation_commit_receipt"),
        ] {
            let left: i64 = db
                .query_row_map(sql, &[], |row| row.get_typed(0))
                .expect("count rows");
            assert_eq!(
                left, 0,
                "the first projection and everything derived from it is rolled back ({label})"
            );
        }
        let revision: String = db
            .query_row_map(
                "SELECT COALESCE((SELECT value FROM meta WHERE key = 'source_facts_revision'), '0')",
                &[],
                |row| row.get_typed(0),
            )
            .expect("read the revision");
        assert_eq!(revision, "0");
    }

    /// SRC05B-09C: one sealed input, prepared over a private fixture, with its
    /// own database open beside it.
    ///
    /// The dispatcher is driven directly, so a case can watch the whole-input
    /// retry over a real SQLite transaction in both writer modes and read what
    /// the scripted faults really did.
    struct PreparedInput {
        temp: tempfile::TempDir,
        job: SourceInputJob,
        storage: crate::storage::sqlite::FrankenStorage,
        live_path: std::path::PathBuf,
    }

    impl PreparedInput {
        fn new() -> Self {
            let (temp, safety, root, meta, discovered) = fixture();
            let job =
                prepare(&temp, &safety, &root, &meta, &discovered).expect("the fixture prepares");
            let storage = crate::storage::sqlite::FrankenStorage::open(
                &temp.path().join("data/agent_search.db"),
            )
            .expect("open the database");
            Self {
                temp,
                job,
                storage,
                live_path: discovered.source_path,
            }
        }

        /// One whole-input dispatch, in the writer mode this case names.
        fn dispatch(&self, concurrent: bool) -> Result<SourceInputCommit, SourceIngestError> {
            let _mode = test_hooks::arm_writer_mode(concurrent);
            commit_source_input_dispatched(&self.storage, &self.job, false)
        }

        fn count(&self, sql: &str) -> i64 {
            self.storage
                .raw()
                .query_row_map(sql, &[], |row| row.get_typed(0))
                .unwrap_or_else(|error| panic!("count failed for {sql}: {error}"))
        }

        /// Nothing of a failed attempt survived it.
        fn assert_no_half_input(&self, label: &str) {
            for (what, sql) in [
                (
                    "complete inputs",
                    "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
                ),
                (
                    "receipts",
                    "SELECT COUNT(*) FROM operation_commit_receipt WHERE state = 'committed'",
                ),
                ("messages", "SELECT COUNT(*) FROM messages"),
                ("links", "SELECT COUNT(*) FROM source_message_links"),
                ("records", "SELECT COUNT(*) FROM source_records"),
            ] {
                assert_eq!(self.count(sql), 0, "{label}: {what} survived the rollback");
            }
        }
    }

    /// A one-shot typed fault lands on the writer thread that really commits
    /// the transaction.
    ///
    /// The two modes are driven in one process by forcing the mode on this
    /// thread, so no process-wide environment variable is written and a case
    /// running beside this one cannot see the choice. In the writer mode the
    /// fault's own record names the thread that fired it, which is what shows
    /// the commit -- and the retry -- really ran on the dedicated writer
    /// thread rather than on the submitting one.
    #[test]
    fn a_late_typed_busy_is_retried_inside_the_real_transaction_in_both_writer_modes() {
        for concurrent in [false, true] {
            let input = PreparedInput::new();
            let (_guard, script) =
                test_hooks::arm_fault_script(&[("activation", test_hooks::TypedFault::Busy)]);
            let submitter = std::thread::current().id();

            let commit = input
                .dispatch(concurrent)
                .unwrap_or_else(|error| panic!("concurrent={concurrent}: {error}"));
            assert!(
                commit.outcome.is_success(),
                "concurrent={concurrent}: the retry completes the whole input: {:?}",
                commit.outcome
            );

            let fired = script.lock().expect("script lock").fired().to_vec();
            assert_eq!(
                fired.len(),
                1,
                "concurrent={concurrent}: exactly one attempt met the armed fault"
            );
            assert_eq!(
                fired[0].0, "activation",
                "concurrent={concurrent}: the fault was the late one inside the transaction"
            );
            if concurrent {
                assert_ne!(
                    fired[0].2, submitter,
                    "the dedicated writer mode really committed on a thread of its own"
                );
            } else {
                assert_eq!(
                    fired[0].2, submitter,
                    "the ephemeral mode commits on the calling thread"
                );
            }

            assert_eq!(
                input.count("SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"),
                1,
                "concurrent={concurrent}: exactly one complete input"
            );
            assert_eq!(
                input.count(
                    "SELECT COUNT(*) FROM operation_commit_receipt WHERE state = 'committed'"
                ),
                1,
                "concurrent={concurrent}: exactly one receipt"
            );
            assert_eq!(
                input.count("SELECT COUNT(*) FROM source_message_links WHERE message_id IS NULL"),
                0,
                "concurrent={concurrent}: the failed attempt left no dangling link"
            );
            assert!(
                input.count("SELECT COUNT(*) FROM messages") >= 1,
                "concurrent={concurrent}: the input's messages landed"
            );
        }
    }

    /// The whitelist's other side: a typed `Locked` is not retried, and it
    /// keeps the outcome this path has always reported for it.
    #[test]
    fn a_typed_locked_is_reported_without_a_retry() {
        for concurrent in [false, true] {
            let input = PreparedInput::new();
            let (_guard, script) =
                test_hooks::arm_fault_script(&[("activation", test_hooks::TypedFault::Locked)]);

            let commit = input
                .dispatch(concurrent)
                .expect("a lock is reported as the transient outcome");
            assert!(
                matches!(commit.outcome, SourceInputOutcome::Transient { .. }),
                "concurrent={concurrent}: a lock keeps the transient shape: {:?}",
                commit.outcome
            );
            assert!(
                !commit.outcome.is_success(),
                "concurrent={concurrent}: and it is not a success"
            );
            // Had the lock been retried, the second attempt would have reached
            // the point with an empty script and completed the input. The
            // outcome above rules that out; this rules out a second attempt
            // reaching the point at all.
            assert_eq!(
                script.lock().expect("script lock").fired().len(),
                1,
                "concurrent={concurrent}: the input was attempted once"
            );
            input.assert_no_half_input(&format!("concurrent={concurrent}"));
        }
    }

    /// One typed out-of-memory buys exactly one further complete isolation
    /// attempt, and the whole input then commits.
    #[test]
    fn one_typed_oom_is_absorbed_by_one_complete_isolation_attempt() {
        let input = PreparedInput::new();
        let (_guard, script) =
            test_hooks::arm_fault_script(&[("activation", test_hooks::TypedFault::OutOfMemory)]);

        let commit = input
            .dispatch(false)
            .expect("the isolation attempt completes the input");
        assert!(
            commit.outcome.is_success(),
            "the input completed after the isolation attempt: {:?}",
            commit.outcome
        );
        assert_eq!(
            script.lock().expect("script lock").fired().len(),
            1,
            "one out-of-memory was spent and no second one was armed"
        );
        assert_eq!(
            input.count("SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'"),
            1,
            "exactly one complete input"
        );
        assert_eq!(
            input.count("SELECT COUNT(*) FROM operation_commit_receipt WHERE state = 'committed'"),
            1,
            "exactly one receipt"
        );
        assert_eq!(
            input.count("SELECT COUNT(*) FROM source_message_links WHERE message_id IS NULL"),
            0,
            "the isolation attempt left no dangling link"
        );
    }

    /// A second typed out-of-memory stops the input unfinished instead of
    /// looping, and the failed attempts leave no half input behind.
    #[test]
    fn a_second_typed_oom_leaves_the_input_unfinished() {
        let input = PreparedInput::new();
        let (_guard, script) = test_hooks::arm_fault_script(&[
            ("activation", test_hooks::TypedFault::OutOfMemory),
            ("activation", test_hooks::TypedFault::OutOfMemory),
        ]);

        let error = input
            .dispatch(false)
            .expect_err("the second out-of-memory is reported, not absorbed");
        assert!(
            typed_out_of_memory(&error),
            "the error is still the typed out-of-memory: {error}"
        );
        assert_eq!(
            script.lock().expect("script lock").fired().len(),
            2,
            "exactly two complete attempts were made"
        );
        input.assert_no_half_input("after the second out-of-memory");
    }

    /// The busy budget belongs to the input, so the isolation round inherits
    /// what the first round spent rather than being granted a fresh one.
    ///
    /// The script spends the whole budget on `Busy`, then asks for the
    /// isolation round with an out-of-memory, then arms one more `Busy`. The
    /// isolation round's single attempt therefore finds the budget already
    /// spent and stops unfinished. A budget re-granted per round would have
    /// retried that last `Busy` and completed the input instead.
    #[test]
    fn the_busy_budget_is_not_re_granted_by_the_isolation_round() {
        let input = PreparedInput::new();
        let limit = crate::indexer::persist::begin_concurrent_retry_limit();
        let mut entries: Vec<(&'static str, test_hooks::TypedFault)> =
            vec![("activation", test_hooks::TypedFault::Busy); limit];
        entries.push(("activation", test_hooks::TypedFault::OutOfMemory));
        entries.push(("activation", test_hooks::TypedFault::Busy));
        let (_guard, script) = test_hooks::arm_fault_script(&entries);

        let commit = input
            .dispatch(false)
            .expect("a spent budget is reported, not an error");

        assert!(
            !commit.outcome.is_success(),
            "the shared budget is spent, so the input is not successful: {:?}",
            commit.outcome
        );
        assert_eq!(
            script.lock().expect("script lock").fired().len(),
            limit + 2,
            "one attempt per armed entry: the budget's worth of busy attempts, the \
             out-of-memory, and the isolation round's single attempt"
        );
        input.assert_no_half_input("after the shared budget was spent");
    }

    /// SRC05B-09C (D): a retry of a sealed input reads the sealed blob, never
    /// the live source.
    ///
    /// The job is prepared and then the live file is rewritten and removed, so
    /// anything that consulted it again would either fail or commit the
    /// replacement text. The armed typed busy makes the first attempt fail at
    /// the last point inside the transaction, which is the attempt the retry
    /// has to repeat.
    #[test]
    fn a_retry_of_a_sealed_input_never_re_reads_the_live_source() {
        let input = PreparedInput::new();

        // The sealed job is now the only place this input's content exists.
        std::fs::write(
            &input.live_path,
            "{\"type\":\"user\",\"message\":{\"role\":\"user\",\"content\":\"replaced\"}}\n",
        )
        .expect("rewrite the live source");
        std::fs::remove_file(&input.live_path).expect("remove the live source");

        let (_guard, script) =
            test_hooks::arm_fault_script(&[("activation", test_hooks::TypedFault::Busy)]);
        let commit = input
            .dispatch(false)
            .expect("the retry completes the sealed input");
        assert!(
            commit.outcome.is_success(),
            "the retried input completes: {:?}",
            commit.outcome
        );
        assert_eq!(
            script.lock().expect("script lock").fired().len(),
            1,
            "the armed typed busy really fired, so this case exercised a retry rather \
             than a first-attempt success"
        );

        let sealed = input.count(
            "SELECT COUNT(*) FROM messages WHERE content LIKE '%synthetic content identity question%'",
        );
        assert!(
            sealed >= 1,
            "the retry committed the sealed content this input was prepared from"
        );
        let replaced = input.count("SELECT COUNT(*) FROM messages WHERE content LIKE '%replaced%'");
        assert_eq!(
            replaced, 0,
            "and never the replacement the live file held, which the retry could only \
             have read by going back to the live source"
        );
        assert_eq!(
            input.count("SELECT COUNT(*) FROM operation_commit_receipt WHERE state = 'committed'"),
            1,
            "the failed attempt wrote no receipt of its own"
        );
        assert_eq!(
            input.count("SELECT COUNT(*) FROM source_message_links WHERE message_id IS NULL"),
            0,
            "and left no dangling link"
        );
    }

    #[test]
    fn an_untouched_blob_is_accepted() {
        let (temp, safety, root, meta, discovered) = fixture();
        let job = prepare(&temp, &safety, &root, &meta, &discovered)
            .expect("the untouched fixture prepares");
        assert_eq!(job.connector_name, "claude");
    }

    /// The shared sealed-preparation entry's direct tests.
    ///
    /// These drive `prepare_sealed_source_input` over this module's private
    /// fixture. The direct path captures and opens explicitly, constructs its
    /// descriptor and parser context from the fixture, and never consumes the
    /// ordinary entry's output as an expectation.
    mod sealed_job_tests {
        use super::*;
        use franken_agent_detection as fad;
        use std::path::Path;

        fn claude_connector() -> Box<dyn crate::connectors::Connector + Send> {
            Box::new(crate::connectors::claude_code::ClaudeCodeConnector::new())
        }

        /// Observes the sealed read's own view of the discovery record and
        /// delegates every call to the real Claude connector. The wrapper adds
        /// no parsing and changes no field: it records what the production
        /// boundary actually received.
        struct RecordingConnector {
            inner: Box<dyn crate::connectors::Connector + Send>,
            seen: Arc<std::sync::Mutex<Vec<(Option<u64>, Option<i64>)>>>,
        }

        impl RecordingConnector {
            fn new(inner: Box<dyn crate::connectors::Connector + Send>) -> Self {
                Self {
                    inner,
                    seen: Arc::new(std::sync::Mutex::new(Vec::new())),
                }
            }

            fn seen(&self) -> Vec<(Option<u64>, Option<i64>)> {
                self.seen.lock().expect("recorder lock").clone()
            }
        }

        impl crate::connectors::Connector for RecordingConnector {
            fn scan_source_aware(
                &self,
                sealed: &fad::SealedInputContext,
                sink: &mut dyn fad::SourceMappingSink,
            ) -> Result<fad::SourceInputFinish, fad::SourceReadFailure> {
                self.seen
                    .lock()
                    .expect("recorder lock")
                    .push((sealed.discovery.size_bytes, sealed.discovery.modified_at_ms));
                self.inner.scan_source_aware(sealed, sink)
            }

            fn detect(&self) -> fad::DetectionResult {
                self.inner.detect()
            }

            fn scan(
                &self,
                ctx: &fad::ScanContext,
            ) -> anyhow::Result<Vec<fad::NormalizedConversation>> {
                self.inner.scan(ctx)
            }

            fn supports_streaming_scan(&self) -> bool {
                self.inner.supports_streaming_scan()
            }

            fn discover_source_files(
                &self,
                ctx: &fad::ScanContext,
            ) -> anyhow::Result<Vec<fad::DiscoveredSourceFile>> {
                self.inner.discover_source_files(ctx)
            }

            fn scan_with_callback(
                &self,
                ctx: &fad::ScanContext,
                on_conversation: &mut dyn FnMut(fad::NormalizedConversation) -> anyhow::Result<()>,
            ) -> anyhow::Result<()> {
                self.inner.scan_with_callback(ctx, on_conversation)
            }
        }

        /// The A1 fixture: the synthetic discovery values are deliberately
        /// unlike the real blob length and capture time, and the three
        /// identities (namespace, physical root, routing id) are distinct.
        fn sealed_fixture() -> (
            tempfile::TempDir,
            Arc<FixedSafetyConfig>,
            crate::connectors::ScanRoot,
            crate::indexer::scan_root_meta::ScanRootMeta,
            crate::connectors::DiscoveredSourceFile,
        ) {
            let (temp, safety, root, mut meta, mut discovered) = fixture();
            let root = root.with_rewrite("/synthetic/workspace", "/synthetic/mapped");
            meta.origin_host = "machine-alpha".to_string();
            meta.root_id = "route:claude:sealed".to_string();
            discovered.size_bytes = Some(4_242_424);
            discovered.modified_at_ms = Some(1_234_567_890_123);
            (temp, safety, root, meta, discovered)
        }

        fn capture_once(
            data_dir: &Path,
            discovered: &crate::connectors::DiscoveredSourceFile,
        ) -> crate::raw_mirror::RawMirrorCaptureRecord {
            crate::raw_mirror::capture_source_file_with_identity(
                crate::raw_mirror::RawMirrorCaptureInput {
                    data_dir,
                    provider: "claude",
                    source_id: &discovered.origin.source_id,
                    origin_kind: discovered.origin.kind.as_str(),
                    origin_host: discovered.origin.host.as_deref(),
                    source_path: &discovered.source_path,
                    db_links: &[],
                },
                crate::raw_mirror::RawMirrorSessionIdentity {
                    identity_host: crate::raw_mirror::RAW_MIRROR_LOCAL_IDENTITY_HOST,
                    external_id: None,
                },
            )
            .expect("capture the source")
        }

        /// Warm the manifest once, then return a capture and its verified
        /// handle. Both the ordinary and the direct call then see the same
        /// already-present capture record.
        fn capture_and_open(
            temp: &tempfile::TempDir,
            discovered: &crate::connectors::DiscoveredSourceFile,
        ) -> (
            std::path::PathBuf,
            crate::raw_mirror::RawMirrorCaptureRecord,
            crate::raw_mirror::VerifiedRawMirrorCapture,
        ) {
            let data_dir = temp.path().join("data");
            std::fs::create_dir_all(&data_dir).expect("mkdir data");
            drop(capture_once(&data_dir, discovered));
            let capture = capture_once(&data_dir, discovered);
            let verified = crate::raw_mirror::open_verified_capture(&data_dir, &capture)
                .expect("open the verified capture");
            (data_dir, capture, verified)
        }

        fn descriptor_and_context(
            root: &crate::connectors::ScanRoot,
            discovered: &crate::connectors::DiscoveredSourceFile,
        ) -> (fad::SourceInputDescriptor, fad::SourceParserContext) {
            let role = fad::SourceInputRole::try_from(discovered.role)
                .expect("the fixture role has a sealed equivalent");
            let relative_locator =
                relative_locator_within(&discovered.scan_root, &discovered.source_path)
                    .expect("the fixture path is inside its root");
            let fad_connector = fad_connector_name("claude");
            let origin = fad::SourceOrigin {
                origin: discovered.origin.clone(),
                source_version: None,
            };
            let descriptor = fad::SourceInputDescriptor {
                connector: fad_connector.clone(),
                scan_root: discovered.scan_root.clone(),
                source_path: discovered.source_path.clone(),
                relative_locator: relative_locator.clone(),
                role,
                origin: origin.clone(),
                platform: discovered.platform,
                size_bytes: discovered.size_bytes,
                modified_at_ms: discovered.modified_at_ms,
            };
            let parser_context = fad::SourceParserContext {
                schema: "cass.source-parser-context/1".to_string(),
                connector: fad_connector,
                roots: vec![fad::SourceParserRoot {
                    path: discovered.scan_root.clone(),
                    origin,
                    platform: discovered.platform,
                    workspace_rewrites: root.workspace_rewrites.clone(),
                }],
                relative_locator,
                role,
                effective_config_digest: None,
            };
            (descriptor, parser_context)
        }

        fn prepare_direct(
            connector: &(dyn crate::connectors::Connector + Send),
            data_dir: &Path,
            safety: &Arc<FixedSafetyConfig>,
            root: &crate::connectors::ScanRoot,
            meta: &crate::indexer::scan_root_meta::ScanRootMeta,
            discovered: &crate::connectors::DiscoveredSourceFile,
            capture: &crate::raw_mirror::RawMirrorCaptureRecord,
            verified: &crate::raw_mirror::VerifiedRawMirrorCapture,
        ) -> Result<SourceInputJob, SourceIngestError> {
            let (descriptor, parser_context) = descriptor_and_context(root, discovered);
            let identity_host = crate::indexer::IngestIdentity::for_meta(meta).identity_host;
            prepare_sealed_source_input(
                connector,
                &SealedSourceInputRequest {
                    connector_name: "claude",
                    data_dir,
                    root,
                    root_id: meta.root_id.as_str(),
                    identity_namespace: &identity_host,
                    descriptor: &descriptor,
                    parser_context: &parser_context,
                    capture,
                    verified,
                    safety,
                },
            )
        }

        fn raw_mirror_snapshot(data_dir: &Path) -> Vec<(String, String)> {
            fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, String)>) {
                let mut entries: Vec<_> = std::fs::read_dir(dir)
                    .expect("read raw-mirror directory")
                    .map(|entry| entry.expect("read entry").path())
                    .collect();
                entries.sort();
                for path in entries {
                    if path.is_dir() {
                        walk(&path, base, out);
                    } else {
                        let bytes = std::fs::read(&path).expect("read raw-mirror file");
                        let relative = path
                            .strip_prefix(base)
                            .expect("inside the mirror")
                            .display()
                            .to_string();
                        out.push((relative, Sha256Digest::of(&bytes).hex()));
                    }
                }
            }
            let root = data_dir.join("raw-mirror");
            let mut out = Vec::new();
            if root.exists() {
                walk(&root, &root, &mut out);
            }
            out.sort();
            out
        }

        fn claim_count(job: &SourceInputJob) -> usize {
            job.records.iter().map(|record| record.claims.len()).sum()
        }

        fn manifest_matches(left: &SourceInputJob, right: &SourceInputJob) {
            let a = left.input.manifest();
            let b = right.input.manifest();
            assert_eq!(a.verifier_version(), b.verifier_version());
            assert_eq!(a.sealed_sha256(), b.sealed_sha256());
            assert_eq!(a.byte_len(), b.byte_len());
            assert_eq!(a.format(), b.format());
            assert_eq!(a.records(), b.records());
            assert_eq!(a.blank_lines(), b.blank_lines());
            assert_eq!(a.blank_bytes(), b.blank_bytes());
            assert_eq!(a.framing_sha256(), b.framing_sha256());
            assert_eq!(a.complete(), b.complete());
        }

        #[test]
        fn s1_ordinary_and_sealed_jobs_are_equivalent() {
            let (temp, safety, root, mut meta, mut discovered) = sealed_fixture();
            meta.origin_host = "machine-alpha".to_string();
            meta.root_id = "route:claude:sealed".to_string();
            discovered.size_bytes = Some(4_242_424);
            discovered.modified_at_ms = Some(1_234_567_890_123);
            assert_eq!(root.workspace_rewrites.len(), 1, "the rewrite is non-empty");
            assert_eq!(discovered.size_bytes, Some(4_242_424));
            assert_eq!(discovered.modified_at_ms, Some(1_234_567_890_123));
            let real_len = std::fs::metadata(&discovered.source_path)
                .expect("stat the live fixture")
                .len();
            assert_ne!(
                Some(real_len),
                discovered.size_bytes,
                "the synthetic discovery size must differ from the real blob length"
            );

            let recorder = RecordingConnector::new(claude_connector());
            let (data_dir, capture, verified) = capture_and_open(&temp, &discovered);
            let direct = prepare_direct(
                &recorder,
                &data_dir,
                &safety,
                &root,
                &meta,
                &discovered,
                &capture,
                &verified,
            )
            .expect("the direct entry prepares the same fixture");
            let ordinary = prepare_source_input(
                &recorder,
                &SourceInputRequest {
                    connector_name: "claude",
                    data_dir: &data_dir,
                    root: &root,
                    meta: &meta,
                    discovered: &discovered,
                    safety: &safety,
                },
            )
            .expect("the ordinary entry prepares the same fixture");

            // Both paths reach the real connector with the caller's discovery
            // observation, not with the blob length or the capture time.
            let seen = recorder.seen();
            assert_eq!(
                seen.len(),
                2,
                "the ordinary and the direct read both reached the connector"
            );
            for (size, modified) in seen {
                assert_eq!(
                    size,
                    Some(4_242_424),
                    "the sealed read observed the declared synthetic size"
                );
                assert_eq!(
                    modified,
                    Some(1_234_567_890_123),
                    "the sealed read observed the declared synthetic mtime"
                );
            }

            // The three identities are distinct and each has its own fixed
            // expectation; none stands in for another.
            let tuple = ordinary.input.identity_tuple();
            assert_eq!(tuple[0].as_deref(), Some("cass.source-input/2"));
            assert_eq!(tuple[1].as_deref(), Some("machine-alpha"));
            assert_eq!(
                tuple[4].as_deref(),
                Some(root.path.to_string_lossy().as_ref()),
                "identity element 4 is the physical scan root"
            );
            assert_eq!(ordinary.root_id, "route:claude:sealed");
            assert_ne!(meta.origin_host, meta.root_id);
            assert_ne!(meta.root_id, root.path.to_string_lossy());
            assert_ne!(meta.origin_host, root.path.to_string_lossy());
            assert_eq!(ordinary.root.path, root.path);
            assert_eq!(
                format!("{:?}", ordinary.root.workspace_rewrites),
                format!("{:?}", root.workspace_rewrites),
                "the job clones the root and keeps its rewrites"
            );

            // The manifest measures the sealed bytes, not the synthetic
            // discovery value.
            assert_eq!(ordinary.input.manifest().byte_len(), real_len);
            assert_ne!(ordinary.input.manifest().byte_len(), 4_242_424);

            // Persisted discovery keeps the serialized originals, and the
            // parser context keeps the non-empty rewrite. The volatile size and
            // mtime are not part of the frozen discovery wire; the connector
            // recorder above observes them at the real sealed-read boundary.
            let storage = crate::storage::sqlite::FrankenStorage::open(
                &temp.path().join("data/agent_search.db"),
            )
            .expect("open the database");
            commit_source_input(&storage, &ordinary).expect("the ordinary job commits");
            let discovery: Vec<u8> = storage
                .raw()
                .query_row_map("SELECT discovery_bin FROM source_inputs", &[], |row| {
                    row.get_typed(0)
                })
                .expect("read the stored discovery");
            let discovery = String::from_utf8_lossy(&discovery);
            assert!(
                discovery.contains(root.path.to_string_lossy().as_ref()),
                "the stored discovery keeps the physical scan root: {discovery}"
            );
            assert!(
                discovery.contains(discovered.source_path.to_string_lossy().as_ref()),
                "the stored discovery keeps the original source path: {discovery}"
            );
            let parser_context: Vec<u8> = storage
                .raw()
                .query_row_map("SELECT parser_context_bin FROM source_inputs", &[], |row| {
                    row.get_typed(0)
                })
                .expect("read the stored parser context");
            let parser_context = String::from_utf8_lossy(&parser_context);
            assert!(
                parser_context.contains("/synthetic/workspace")
                    && parser_context.contains("/synthetic/mapped"),
                "the non-empty rewrite reached the stored parser context: {parser_context}"
            );

            // Equivalence of the two jobs, field group by field group.
            assert_eq!(ordinary.connector_name, direct.connector_name);
            assert_eq!(ordinary.root_id, direct.root_id);
            assert_eq!(ordinary.data_dir, direct.data_dir);
            assert_eq!(ordinary.input.identity_tuple(), direct.input.identity_tuple());
            assert_eq!(ordinary.input.input_key(), direct.input.input_key());
            manifest_matches(&ordinary, &direct);
            assert_eq!(ordinary.normalizer_id, direct.normalizer_id);
            assert_eq!(ordinary.safety_contract_id, direct.safety_contract_id);
            assert_eq!(ordinary.finish.bytes_read, direct.finish.bytes_read);
            assert_eq!(ordinary.finish.records_seen, direct.finish.records_seen);
            assert_eq!(ordinary.finish.blank_lines, direct.finish.blank_lines);
            assert_eq!(ordinary.finish.reached_eof, direct.finish.reached_eof);
            assert_eq!(
                ordinary.finish.content_digest.value.to_string(),
                direct.finish.content_digest.value.to_string()
            );
            assert_eq!(format!("{:?}", ordinary.records), format!("{:?}", direct.records));
            assert_eq!(
                format!("{:?}", ordinary.conversations),
                format!("{:?}", direct.conversations)
            );
            assert_eq!(ordinary.records.len(), direct.records.len());
            assert_eq!(ordinary.conversations.len(), direct.conversations.len());
            assert!(!ordinary.records.is_empty(), "the fixture project records");
            assert!(claim_count(&ordinary) > 0, "the fixture carries claims");
            assert_eq!(claim_count(&ordinary), claim_count(&direct));
            assert_eq!(ordinary.root.path, direct.root.path);
            assert_eq!(
                format!("{:?}", ordinary.root.workspace_rewrites),
                format!("{:?}", direct.root.workspace_rewrites)
            );
            assert_eq!(ordinary.byte_reservation, direct.byte_reservation);
            assert_eq!(ordinary.blob_path, direct.blob_path);
            assert_eq!(ordinary.blob_blake3, direct.blob_blake3);
            assert_eq!(ordinary.original_path, direct.original_path);
        }

        #[test]
        fn s2_sealed_preparation_ignores_live_changes() {
            let (temp, safety, root, meta, discovered) = fixture();
            let connector = claude_connector();
            let (data_dir, capture, verified) = capture_and_open(&temp, &discovered);
            let before = raw_mirror_snapshot(&data_dir);
            let first = prepare_direct(
                connector.as_ref(),
                &data_dir,
                &safety,
                &root,
                &meta,
                &discovered,
                &capture,
                &verified,
            )
            .expect("the direct entry prepares while the live file exists");
            assert_eq!(raw_mirror_snapshot(&data_dir), before, "preparation never writes the mirror");

            std::fs::remove_file(&discovered.source_path).expect("remove the live source");
            assert_eq!(
                raw_mirror_snapshot(&data_dir),
                before,
                "removing the live file does not touch the mirror"
            );
            let after_delete = prepare_direct(
                connector.as_ref(),
                &data_dir,
                &safety,
                &root,
                &meta,
                &discovered,
                &capture,
                &verified,
            )
            .expect("the direct entry still prepares after the live source is gone");
            assert_eq!(raw_mirror_snapshot(&data_dir), before);

            std::fs::write(
                &discovered.source_path,
                "{\"type\":\"user\",\"uuid\":\"synthetic-live\",\"message\":{\"role\":\"user\",\"content\":\"different live bytes\"}}\n",
            )
            .expect("write different live bytes");
            let after_rewrite = prepare_direct(
                connector.as_ref(),
                &data_dir,
                &safety,
                &root,
                &meta,
                &discovered,
                &capture,
                &verified,
            )
            .expect("the direct entry still prepares after the live source changed");
            assert_eq!(
                raw_mirror_snapshot(&data_dir),
                before,
                "no mirror path or byte changed across the three calls"
            );
            assert_eq!(first.input.input_key(), after_delete.input.input_key());
            assert_eq!(first.input.input_key(), after_rewrite.input.input_key());
            assert_eq!(first.records.len(), after_rewrite.records.len());
            assert_eq!(format!("{:?}", first.records), format!("{:?}", after_rewrite.records));
            assert!(!after_rewrite.records.is_empty());
        }

        #[test]
        fn s3_after_read_mismatches_are_refused() {
            let (temp, safety, root, meta, discovered) = fixture();
            let connector = claude_connector();
            let (data_dir, capture, verified) = capture_and_open(&temp, &discovered);
            let control = prepare_direct(
                connector.as_ref(),
                &data_dir,
                &safety,
                &root,
                &meta,
                &discovered,
                &capture,
                &verified,
            )
            .expect("the untampered direct entry prepares");
            assert!(!control.records.is_empty());

            {
                let _guard = test_hooks::arm_after_read(|records, _finish| {
                    records.pop();
                });
                let error = prepare_direct(
                    connector.as_ref(),
                    &data_dir,
                    &safety,
                    &root,
                    &meta,
                    &discovered,
                    &capture,
                    &verified,
                )
                .expect_err("a read that drops a delivered record is refused");
                let text = error.to_string();
                assert!(text.contains("delivered"), "the refusal names the delivery: {text}");
                assert!(text.contains("reported"), "the refusal names the denominator: {text}");
                assert_eq!(test_hooks::hits(), vec!["after_read"]);
            }

            {
                let _guard = test_hooks::arm_after_read(|_records, finish| {
                    finish.content_digest.value = fad::Sha256Digest::of(b"tampered finish digest");
                });
                let error = prepare_direct(
                    connector.as_ref(),
                    &data_dir,
                    &safety,
                    &root,
                    &meta,
                    &discovered,
                    &capture,
                    &verified,
                )
                .expect_err("a finish digest that disagrees is refused");
                assert!(
                    error
                        .to_string()
                        .contains("independent framing expectation"),
                    "the digest refusal is the framing gate: {error}"
                );
                assert_eq!(test_hooks::hits(), vec!["after_read"]);
            }

            {
                let _guard = test_hooks::arm_after_read(|_records, finish| {
                    finish.reached_eof = false;
                });
                let error = prepare_direct(
                    connector.as_ref(),
                    &data_dir,
                    &safety,
                    &root,
                    &meta,
                    &discovered,
                    &capture,
                    &verified,
                )
                .expect_err("a read that stops before EOF is refused");
                assert!(
                    error
                        .to_string()
                        .contains("independent framing expectation"),
                    "the EOF refusal is the framing gate: {error}"
                );
                assert_eq!(test_hooks::hits(), vec!["after_read"]);
            }

            let control_again = prepare_direct(
                connector.as_ref(),
                &data_dir,
                &safety,
                &root,
                &meta,
                &discovered,
                &capture,
                &verified,
            )
            .expect("the control still prepares after every hook is cleared");
            assert_eq!(control.records.len(), control_again.records.len());
        }
    }
}

#[cfg(test)]
mod default_safety_tests {
    //! P0/C5 (2026-10-15 execution contract v2): the prepared fixed safety
    //! configuration.
    //!
    //! The automatic mode reads `XDG_CONFIG_HOME` and `HOME`, which are process
    //! state a parallel test may not set on everyone's behalf. Every case that
    //! exercises that discovery therefore re-runs itself inside a child of this
    //! same test binary, with a synthetic `HOME`/`XDG_CONFIG_HOME` and a
    //! synthetic working directory -- and the parent refuses to pass unless the
    //! child really ran the body and reported it ok.

    use super::*;

    /// Set in the child, so the same function runs its body instead of
    /// spawning another child.
    const CHILD_MARKER: &str = "CASS_TASK23_FIXED_SAFETY_CHILD";
    /// The private root the parent prepared for the child.
    const CHILD_ROOT: &str = "CASS_TASK23_FIXED_SAFETY_ROOT";

    /// The child's private root, or `None` in the parent.
    fn child_root() -> Option<PathBuf> {
        let marker = std::env::var_os(CHILD_MARKER)?;
        if marker.is_empty() {
            return None;
        }
        Some(PathBuf::from(
            std::env::var_os(CHILD_ROOT).expect("the child root is set beside the marker"),
        ))
    }

    /// Run `test_name` once in a child whose `HOME` and `XDG_CONFIG_HOME` point
    /// inside a fresh private root, then fail the parent unless that very test
    /// reported ok there.
    fn run_in_synthetic_environment(test_name: &str) {
        let root = tempfile::TempDir::new().expect("synthetic root");
        let root_path = root.path().to_path_buf();
        let binary = std::env::current_exe().expect("the test binary's own path");
        let output = std::process::Command::new(binary)
            .arg(test_name)
            .arg("--exact")
            .arg("--nocapture")
            .current_dir(&root_path)
            .env(CHILD_MARKER, "1")
            .env(CHILD_ROOT, &root_path)
            .env("XDG_CONFIG_HOME", root_path.join("xdg"))
            .env("HOME", root_path.join("home"))
            .output()
            .expect("the child test run starts");

        let stdout = String::from_utf8_lossy(&output.stdout);
        print!("{stdout}");
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "{test_name} failed in the synthetic child"
        );
        assert!(
            stdout.contains(&format!("test {test_name} ... ok")),
            "{test_name} did not run in the synthetic child"
        );
    }

    /// `<root>/xdg/cass/excluded_context_paths.toml`: the single candidate the
    /// synthetic `XDG_CONFIG_HOME` resolves to.
    fn synthetic_rule_file(root: &Path) -> PathBuf {
        root.join("xdg")
            .join("cass")
            .join("excluded_context_paths.toml")
    }

    fn write_rule_file(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().expect("rule file parent")).expect("mkdir rule file");
        std::fs::write(path, contents).expect("write rule file");
    }

    fn automatic_identity(digest_hex: &str) -> String {
        format!("cass.source-config/1:sha256:{digest_hex}")
    }

    #[test]
    fn builtin_materializes_all_four_arrays() {
        let Some(root) = child_root() else {
            run_in_synthetic_environment(
                "indexer::source_ingest::default_safety_tests::builtin_materializes_all_four_arrays",
            );
            return;
        };

        let data_dir = root.join("data");
        let safety = prepare_source_safety(&data_dir, None).expect("prepare the built-in default");

        let copy = PathBuf::from(safety.original_path());
        let directory = data_dir.join("source-configs").join("v1");
        assert!(
            copy.starts_with(&directory),
            "the copy lives in the fixed layout under the data directory"
        );
        let bytes = std::fs::read(&copy).expect("read the published copy");
        let digest = Sha256Digest::of(&bytes).hex();
        assert_eq!(digest, safety.bytes_sha256().hex());
        assert_eq!(
            copy.file_name().and_then(|name| name.to_str()),
            Some(format!("{digest}.toml").as_str()),
            "the file name is the content address"
        );

        // All four array keys really are in the generated file ...
        let text = std::str::from_utf8(&bytes).expect("the copy is UTF-8 TOML");
        let raw: toml::Value = toml::from_str(text).expect("the copy parses");
        let table = raw.as_table().expect("the copy is a TOML table");
        for key in FOUR_ARRAY_KEYS {
            assert!(
                matches!(
                    table.get(key),
                    Some(toml::Value::Array(values)) if values.iter().all(|value| value.is_str())
                ),
                "the generated copy has no {key} string array"
            );
        }

        // ... and the arrays it carries are the effective ones, in order.
        let defaults = crate::sources::config::ExcludedContextPaths::default();
        assert_eq!(safety.config().effective_four_arrays, defaults);
        let reloaded: crate::sources::config::ExcludedContextPaths =
            toml::from_str(text).expect("the copy reloads");
        assert_eq!(reloaded, defaults);

        assert_eq!(
            safety.config_source_identity(),
            automatic_identity(&digest)
        );
    }

    #[test]
    fn partial_override_freezes_effective_defaults() {
        let Some(root) = child_root() else {
            run_in_synthetic_environment(
                "indexer::source_ingest::default_safety_tests::partial_override_freezes_effective_defaults",
            );
            return;
        };

        write_rule_file(
            &synthetic_rule_file(&root),
            "memory_files = [\"CUSTOM.md\", \"SECOND.md\"]\n",
        );

        let data_dir = root.join("data");
        let safety =
            prepare_source_safety(&data_dir, None).expect("prepare the partial override");

        let bytes = std::fs::read(safety.original_path()).expect("read the published copy");
        let text = std::str::from_utf8(&bytes).expect("the copy is UTF-8 TOML");
        let defaults = crate::sources::config::ExcludedContextPaths::default();
        let effective = crate::sources::config::ExcludedContextPaths {
            memory_files: vec!["CUSTOM.md".to_string(), "SECOND.md".to_string()],
            ..defaults.clone()
        };

        assert_eq!(safety.config().effective_four_arrays, effective);
        // The copy carries the override *and* every default it did not mention,
        // in the array's own order.
        let reloaded: crate::sources::config::ExcludedContextPaths =
            toml::from_str(text).expect("the copy reloads");
        assert_eq!(reloaded, effective);
        assert_eq!(reloaded.memory_files, vec!["CUSTOM.md", "SECOND.md"]);
        assert_eq!(reloaded.injection_only_files, defaults.injection_only_files);
        assert_eq!(reloaded.workspace_scoped_files, defaults.workspace_scoped_files);
        assert_eq!(reloaded.project_read_documents, defaults.project_read_documents);
    }

    #[test]
    fn same_bytes_reuse_path() {
        let Some(root) = child_root() else {
            run_in_synthetic_environment(
                "indexer::source_ingest::default_safety_tests::same_bytes_reuse_path",
            );
            return;
        };

        let data_dir = root.join("data");
        let first = prepare_source_safety(&data_dir, None).expect("the first prepare");
        let before = std::fs::symlink_metadata(first.original_path()).expect("copy metadata");

        // A rewrite in place would move at least one of the identity fields
        // compared below; plain reuse leaves all of them alone.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let second = prepare_source_safety(&data_dir, None).expect("the second prepare");
        let after = std::fs::symlink_metadata(second.original_path()).expect("copy metadata");

        assert_eq!(first.original_path(), second.original_path());
        assert_eq!(first.bytes_sha256().hex(), second.bytes_sha256().hex());
        assert_eq!(
            first.config_source_identity(),
            second.config_source_identity()
        );
        assert_eq!(
            first.config().effective_four_arrays,
            second.config().effective_four_arrays
        );

        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(before.ino(), after.ino(), "the same copy is reused");
        assert_eq!(
            (before.mtime(), before.mtime_nsec()),
            (after.mtime(), after.mtime_nsec()),
            "reuse does not rewrite the copy"
        );
        assert_eq!(
            (before.ctime(), before.ctime_nsec()),
            (after.ctime(), after.ctime_nsec()),
            "reuse does not rewrite the copy"
        );
    }

    #[test]
    fn changed_effective_rules_keep_old_copy() {
        let Some(root) = child_root() else {
            run_in_synthetic_environment(
                "indexer::source_ingest::default_safety_tests::changed_effective_rules_keep_old_copy",
            );
            return;
        };

        let rules = synthetic_rule_file(&root);
        write_rule_file(&rules, "memory_files = [\"ONE.md\"]\n");
        let data_dir = root.join("data");
        let first = prepare_source_safety(&data_dir, None).expect("prepare the first rules");
        let first_copy = PathBuf::from(first.original_path());
        let first_bytes = std::fs::read(&first_copy).expect("read the first copy");

        write_rule_file(&rules, "memory_files = [\"TWO.md\"]\n");
        let second = prepare_source_safety(&data_dir, None).expect("prepare the changed rules");

        assert_ne!(first.original_path(), second.original_path());
        assert_ne!(first.bytes_sha256().hex(), second.bytes_sha256().hex());
        assert_eq!(
            second.config().effective_four_arrays.memory_files,
            vec!["TWO.md"]
        );
        assert_eq!(
            first.config().effective_four_arrays.memory_files,
            vec!["ONE.md"]
        );
        // The superseded copy is kept, byte for byte: nothing prunes it.
        assert!(first_copy.is_file(), "the old copy is kept");
        assert_eq!(
            std::fs::read(&first_copy).expect("re-read the old copy"),
            first_bytes
        );
    }

    #[test]
    fn cross_data_dir_keeps_auto_identity() {
        let Some(root) = child_root() else {
            run_in_synthetic_environment(
                "indexer::source_ingest::default_safety_tests::cross_data_dir_keeps_auto_identity",
            );
            return;
        };

        let first = prepare_source_safety(&root.join("data-a"), None).expect("prepare under a");
        let second = prepare_source_safety(&root.join("data-b"), None).expect("prepare under b");

        assert_eq!(
            first.config_source_identity(),
            second.config_source_identity(),
            "the same bytes keep one automatic identity"
        );
        assert_eq!(first.bytes_sha256().hex(), second.bytes_sha256().hex());
        assert_ne!(
            first.original_path(),
            second.original_path(),
            "the reading locations are still distinct"
        );
        assert_eq!(
            first.config().effective_four_arrays,
            second.config().effective_four_arrays
        );
        assert!(first
            .config_source_identity()
            .starts_with("cass.source-config/1:sha256:"));
        assert_ne!(
            first.config_source_identity(),
            first.original_path(),
            "the automatic identity is not a location"
        );
    }

    #[test]
    fn existing_bad_or_symlink_copy_is_not_repaired() {
        let Some(root) = child_root() else {
            run_in_synthetic_environment(
                "indexer::source_ingest::default_safety_tests::existing_bad_or_symlink_copy_is_not_repaired",
            );
            return;
        };

        let reference = prepare_source_safety(&root.join("reference"), None)
            .expect("prepare the reference copy");
        let name = Path::new(reference.original_path())
            .file_name()
            .and_then(|name| name.to_str())
            .expect("the copy has a UTF-8 name")
            .to_string();
        let reference_bytes =
            std::fs::read(reference.original_path()).expect("read the reference copy");

        // (a) the content-addressed name holds different bytes.
        let corrupt_dir = root.join("corrupt");
        let corrupt = corrupt_dir
            .join("source-configs")
            .join("v1")
            .join(&name);
        std::fs::create_dir_all(corrupt.parent().expect("corrupt parent")).expect("mkdir corrupt");
        std::fs::write(&corrupt, "memory_files = [\"EVIL.md\"]\n").expect("write the corrupt copy");

        let refused = prepare_source_safety(&corrupt_dir, None)
            .expect_err("a corrupt copy at the fixed name must be refused");
        assert!(
            format!("{refused}").contains("source_config_mismatch"),
            "expected a mismatch short code, got {refused}"
        );
        assert_eq!(
            std::fs::read(&corrupt).expect("re-read the corrupt copy"),
            b"memory_files = [\"EVIL.md\"]\n".to_vec(),
            "the refused copy is left exactly as it was found"
        );

        #[cfg(unix)]
        {
            // (b) the name is a symlink onto otherwise correct bytes.
            let elsewhere = root.join("elsewhere.toml");
            std::fs::write(&elsewhere, &reference_bytes).expect("write the link target");
            let linked_dir = root.join("linked");
            let linked = linked_dir.join("source-configs").join("v1").join(&name);
            std::fs::create_dir_all(linked.parent().expect("linked parent"))
                .expect("mkdir linked");
            std::os::unix::fs::symlink(&elsewhere, &linked).expect("create the symlink");

            let refused = prepare_source_safety(&linked_dir, None)
                .expect_err("a symlinked copy at the fixed name must be refused");
            assert!(
                format!("{refused}").contains("source_config_mismatch"),
                "expected a mismatch short code, got {refused}"
            );
            assert!(
                std::fs::symlink_metadata(&linked)
                    .expect("link metadata")
                    .file_type()
                    .is_symlink(),
                "the link is left in place"
            );
            assert_eq!(
                std::fs::read(&elsewhere).expect("read the link target"),
                reference_bytes,
                "the link target is untouched"
            );
        }
    }

    #[test]
    fn published_copy_has_exact_hash_and_private_mode() {
        let Some(root) = child_root() else {
            run_in_synthetic_environment(
                "indexer::source_ingest::default_safety_tests::published_copy_has_exact_hash_and_private_mode",
            );
            return;
        };

        let data_dir = root.join("data");
        let safety = prepare_source_safety(&data_dir, None).expect("prepare the fixed copy");
        let copy = PathBuf::from(safety.original_path());
        let bytes = std::fs::read(&copy).expect("read the published copy");
        let digest = Sha256Digest::of(&bytes).hex();

        assert_eq!(digest, safety.bytes_sha256().hex());
        assert_eq!(
            copy,
            data_dir
                .join("source-configs")
                .join("v1")
                .join(format!("{digest}.toml"))
        );

        // The publish left no temporary name behind.
        let directory = copy.parent().expect("copy parent");
        let mut entries: Vec<String> = std::fs::read_dir(directory)
            .expect("read the copy directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        entries.sort();
        assert_eq!(
            entries,
            vec![format!("{digest}.toml")],
            "only the published copy is left in the layout"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = |path: &Path| {
                std::fs::metadata(path)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777
            };
            assert_eq!(mode(&copy), 0o600, "the published copy is private");
            assert_eq!(mode(directory), 0o700, "the version directory is private");
            assert_eq!(
                mode(&data_dir.join("source-configs")),
                0o700,
                "the layout directory is private"
            );
        }
    }

    #[test]
    fn explicit_path_identity_stays_legacy() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let copy = temp.path().join("explicit-fixed-safety.toml");
        let bytes = include_bytes!("../../config/excluded_context_paths.toml").to_vec();
        std::fs::write(&copy, &bytes).expect("write the explicit copy");
        let absolute = std::path::absolute(&copy)
            .expect("absolute path")
            .to_str()
            .expect("UTF-8 path")
            .to_string();

        let data_dir = temp.path().join("data");
        let safety =
            prepare_source_safety(&data_dir, Some(&copy)).expect("prepare the explicit copy");

        assert_eq!(safety.original_path(), absolute);
        assert_eq!(
            safety.config_source_identity(),
            absolute,
            "an explicit copy keeps its own path as the identity"
        );
        assert_eq!(safety.bytes_sha256().hex(), Sha256Digest::of(&bytes).hex());
        assert_eq!(safety.config().fixed_config_bytes, bytes);
        assert!(
            !data_dir.exists(),
            "the explicit mode publishes no automatic copy"
        );
    }

    #[test]
    fn recheck_detects_changed_fixed_bytes() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let copy = temp.path().join("explicit-fixed-safety.toml");
        std::fs::write(&copy, include_bytes!("../../config/excluded_context_paths.toml"))
            .expect("write the explicit copy");

        let data_dir = temp.path().join("data");
        let safety =
            prepare_source_safety(&data_dir, Some(&copy)).expect("prepare the explicit copy");
        let identity = safety.config_source_identity().to_string();
        let digest = safety.bytes_sha256().hex();
        safety
            .recheck_bytes()
            .expect("an unchanged fixed copy rechecks");

        std::fs::write(&copy, "memory_files = [\"CHANGED.md\"]\n").expect("change the copy");
        let refused = safety
            .recheck_bytes()
            .expect_err("changed fixed bytes must be refused");
        assert!(
            format!("{refused}").contains("changed after it was loaded"),
            "expected the changed-copy refusal, got {refused}"
        );
        // The refusal changes neither the recorded identity nor the recorded
        // bytes, and there is no fallback to a live configuration.
        assert_eq!(safety.config_source_identity(), identity);
        assert_eq!(safety.bytes_sha256().hex(), digest);
    }

    #[test]
    fn discovery_failure_never_echoes_the_rule_file() {
        let Some(root) = child_root() else {
            run_in_synthetic_environment(
                "indexer::source_ingest::default_safety_tests::discovery_failure_never_echoes_the_rule_file",
            );
            return;
        };

        const SENTINEL: &str = "SYNTHETIC_RULE_TEXT_SENTINEL_T23";
        let rules = synthetic_rule_file(&root);

        // A syntactically broken file ...
        write_rule_file(&rules, &format!("memory_files = [\"{SENTINEL}\" [[[\n"));
        assert_no_rule_text_in_failure(&root.join("data-broken"), SENTINEL);

        // ... and a well-formed file whose key has the wrong type. Both are
        // discovered through the real entry, not through a lower-level call.
        write_rule_file(&rules, &format!("memory_files = \"{SENTINEL}\"\n"));
        assert_no_rule_text_in_failure(&root.join("data-wrong-type"), SENTINEL);
    }

    /// A refused discovery reports its short code and nothing from the file.
    fn assert_no_rule_text_in_failure(data_dir: &Path, sentinel: &str) {
        let err = prepare_source_safety(data_dir, None)
            .expect_err("a broken live rule file must refuse");
        let display = format!("{err}");
        let debug = format!("{err:?}");
        assert!(
            display.contains("source_config_load_failed"),
            "expected the load short code, got {display}"
        );
        for rendered in [&display, &debug] {
            assert!(
                !rendered.contains(sentinel),
                "the failure echoes the rule file's own text: {rendered}"
            );
            assert!(
                !rendered.contains("memory_files"),
                "the failure echoes the rule file's own key text: {rendered}"
            );
        }
    }

    /// The premise of a permission counterexample: root bypasses directory
    /// permission bits, so a case that needs a real `PermissionDenied` must
    /// fail loudly there instead of passing without exercising anything.
    #[cfg(unix)]
    fn assert_permission_bits_block() {
        let root = std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|uid| uid.trim() == "0")
            .unwrap_or(false);
        assert!(
            !root,
            "this counterexample needs directory permissions to block the caller, and root \
             bypasses those bits"
        );
    }

    #[test]
    #[cfg(unix)]
    fn publish_reports_a_failed_directory_sync() {
        use std::os::unix::fs::PermissionsExt as _;

        assert_permission_bits_block();

        let temp = tempfile::TempDir::new().expect("tempdir");
        let directory = temp.path().join("sync-locked");
        std::fs::create_dir_all(&directory).expect("mkdir the sync directory");
        let final_path = directory.join("fixed.toml");
        let temporary = directory.join("fixed.toml.tmp");

        // Write and traverse, but no read: the copy is created and linked into
        // place, and then the directory cannot be opened for the sync. That is
        // a real filesystem error, not an injected one.
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o300))
            .expect("lock the sync directory");
        let result = publish_fixed_copy_at(
            &final_path,
            b"memory_files = [\"SYNTHETIC.md\"]\n",
            &temporary,
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("unlock the sync directory");

        let err =
            result.expect_err("a directory that cannot be opened is not a successful publish");
        assert!(
            format!("{err}").contains("source_config_publish_failed"),
            "expected the publish short code, got {err}"
        );
    }

    #[test]
    fn temporary_name_collision_leaves_the_stranger_intact() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let directory = temp.path().join("layout");
        std::fs::create_dir_all(&directory).expect("mkdir the layout directory");
        let final_path = directory.join("fixed.toml");
        let temporary = directory.join("fixed.toml.tmp");
        let stranger = b"SYNTHETIC_STRANGER_MARKER\n".to_vec();
        std::fs::write(&temporary, &stranger).expect("write the stranger's file");

        let err = publish_fixed_copy_at(
            &final_path,
            b"memory_files = [\"SYNTHETIC.md\"]\n",
            &temporary,
        )
        .expect_err("a taken temporary name must refuse");

        assert!(
            format!("{err}").contains("source_config_publish_failed"),
            "expected the publish short code, got {err}"
        );
        // This call never created that name, so it is neither removed nor
        // overwritten.
        assert_eq!(
            std::fs::read(&temporary).expect("re-read the stranger's file"),
            stranger,
            "a temporary name this call did not create is left exactly as found"
        );
        assert!(
            !final_path.exists(),
            "a refused publish publishes nothing"
        );
    }
}

#[cfg(test)]
mod restore_fixed_safety_tests {
    //! Task39: restoring a frozen fixed safety configuration.
    //!
    //! Every case builds its own explicit material under a `TempDir`. None of
    //! them reads the real `HOME`/`XDG_CONFIG_HOME` or sets a process
    //! environment variable, so the default parallel run stays independent.

    use super::*;
    use crate::sources::config::ExcludedContextPaths;
    use std::collections::BTreeMap;

    /// The facts of one material set, taken from the existing strict loader
    /// and `verify` -- never from the entry under test.
    struct Material {
        arrays: ExcludedContextPaths,
        bytes: Vec<u8>,
        fixed_sha: Sha256Digest,
        arrays_sha: Sha256Digest,
        code_version: String,
    }

    fn arrays_with(rule: &str) -> ExcludedContextPaths {
        let mut arrays = ExcludedContextPaths::default();
        arrays.injection_only_files.push(rule.to_string());
        arrays
    }

    fn absolute(path: &Path) -> String {
        std::path::absolute(path)
            .expect("absolute path")
            .to_str()
            .expect("UTF-8 path")
            .to_string()
    }

    /// Write the material and take the reference facts from the existing
    /// strict loader and `verify`.
    fn material(path: &Path, arrays: &ExcludedContextPaths) -> Material {
        let bytes = toml::to_string(arrays)
            .expect("serialize the fixed material")
            .into_bytes();
        std::fs::create_dir_all(path.parent().expect("material parent")).expect("mkdir material");
        std::fs::write(path, &bytes).expect("write the fixed material");
        let loaded = load_fixed_safety_config(path).expect("the reference material loads");
        let verified = loaded
            .config()
            .verify()
            .expect("the reference material verifies");
        Material {
            arrays: arrays.clone(),
            bytes,
            fixed_sha: *loaded.bytes_sha256(),
            arrays_sha: *verified.effective_four_arrays_sha256(),
            code_version: verified.code_version().to_string(),
        }
    }

    /// Every path, link target and regular-file digest under `root`.
    fn snapshot(root: &Path) -> BTreeMap<PathBuf, String> {
        fn walk(dir: &Path, out: &mut BTreeMap<PathBuf, String>) {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(_) => return,
            };
            for entry in entries {
                let entry = entry.expect("directory entry");
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path).expect("entry metadata");
                if metadata.file_type().is_symlink() {
                    let target = std::fs::read_link(&path).expect("link target");
                    out.insert(path, format!("symlink:{}", target.display()));
                } else if metadata.is_dir() {
                    out.insert(path.clone(), "dir".to_string());
                    walk(&path, out);
                } else {
                    let digest = Sha256Digest::of(&std::fs::read(&path).expect("file bytes"));
                    out.insert(path, format!("file:{}", digest.hex()));
                }
            }
        }
        let mut out = BTreeMap::new();
        out.insert(root.to_path_buf(), "root".to_string());
        walk(root, &mut out);
        out
    }

    fn assert_safe_refusal(err: &SourceIngestError, forbidden: &[&str]) {
        match err {
            SourceIngestError::Config { detail } => assert!(
                detail.starts_with("source_restore_material_mismatch"),
                "the refusal detail has the fixed prefix: {detail}"
            ),
            other => panic!("expected a Config refusal, got {other:?}"),
        }
        let display = format!("{err}");
        let debug = format!("{err:?}");
        for needle in forbidden {
            assert!(
                !display.contains(needle),
                "the Display leaks {needle}: {display}"
            );
            assert!(!debug.contains(needle), "the Debug leaks {needle}: {debug}");
        }
    }

    fn mark(test: &str, case: &str) {
        println!("TASK39_SCENARIO test={test} case={case} result=pass");
    }

    #[test]
    fn restore_fixed_identity_preserved() {
        // auto: the frozen identity names the bytes, not the old location.
        {
            let temp = tempfile::TempDir::new().expect("tempdir");
            let arrays = arrays_with("S39_RULE_IDENTITY_AUTO");
            let original = temp.path().join("frozen").join("auto-fixed.toml");
            let reference = material(&original, &arrays);
            let identity = format!(
                "{SOURCE_CONFIG_IDENTITY_DOMAIN}:sha256:{}",
                reference.fixed_sha.hex()
            );
            let actual = temp.path().join("restored").join("auto-copy.toml");
            std::fs::create_dir_all(actual.parent().expect("actual parent"))
                .expect("mkdir actual");
            std::fs::rename(&original, &actual).expect("move the frozen material");

            let restored = load_restore_fixed_safety(
                &actual,
                &identity,
                &reference.fixed_sha,
                &reference.arrays_sha,
                &reference.code_version,
            )
            .expect("the frozen material restores");

            assert_eq!(restored.config_source_identity(), identity);
            assert_ne!(
                restored.config_source_identity(),
                restored.original_path(),
                "the automatic identity is not the new location"
            );
            assert_eq!(restored.original_path(), absolute(&actual));
            assert_eq!(restored.bytes_sha256(), &reference.fixed_sha);
            assert_eq!(restored.config().fixed_config_bytes, reference.bytes);
            assert_eq!(restored.config().effective_four_arrays, reference.arrays);
            assert_eq!(restored.config().code_version, reference.code_version);
            assert!(restored.config().desensitization_enabled);
            let verified = restored
                .config()
                .verify()
                .expect("the restored material verifies");
            assert_eq!(verified.fixed_config_sha256(), &reference.fixed_sha);
            assert_eq!(
                verified.effective_four_arrays_sha256(),
                &reference.arrays_sha
            );
            restored
                .recheck_bytes()
                .expect("the new actual copy rechecks");
            assert!(!original.exists(), "the old logical location is gone");
            mark("restore_fixed_identity_preserved", "auto");
        }

        // explicit: the full old path, including its trailing space, is kept.
        {
            let temp = tempfile::TempDir::new().expect("tempdir");
            let arrays = arrays_with("S39_RULE_IDENTITY_EXPLICIT");
            let original = temp
                .path()
                .join("frozen")
                .join("original-fixed.toml ");
            let reference = material(&original, &arrays);
            let identity = absolute(&original);
            assert!(
                identity.ends_with(' '),
                "the frozen identity really ends in a space"
            );
            assert_ne!(
                identity.trim(),
                identity.as_str(),
                "trim would change the frozen identity"
            );
            let actual = temp.path().join("restored").join("explicit-copy.toml");
            std::fs::create_dir_all(actual.parent().expect("actual parent"))
                .expect("mkdir actual");
            std::fs::rename(&original, &actual).expect("move the frozen material");

            let restored = load_restore_fixed_safety(
                &actual,
                &identity,
                &reference.fixed_sha,
                &reference.arrays_sha,
                &reference.code_version,
            )
            .expect("the frozen material restores");

            assert_eq!(restored.config_source_identity(), identity);
            assert!(restored.config_source_identity().ends_with(' '));
            assert_eq!(restored.original_path(), absolute(&actual));
            assert_eq!(restored.bytes_sha256(), &reference.fixed_sha);
            assert_eq!(restored.config().fixed_config_bytes, reference.bytes);
            assert_eq!(restored.config().effective_four_arrays, reference.arrays);
            assert_eq!(restored.config().code_version, reference.code_version);
            assert!(restored.config().desensitization_enabled);
            restored
                .recheck_bytes()
                .expect("the new actual copy rechecks");
            assert!(!original.exists(), "the old logical location is gone");
            mark("restore_fixed_identity_preserved", "explicit");
        }
    }

    fn mismatch_cell(case: &str) {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let rule = format!("S39_RULE_MISMATCH_{case}");
        let arrays = arrays_with(&rule);
        let path_sentinel = format!("s39-path-sentinel-mismatch-{case}");
        let actual = temp.path().join(&path_sentinel).join("actual-fixed.toml");
        let reference = material(&actual, &arrays);
        let identity = format!("s39-identity-sentinel-mismatch-{case}:restore");
        let forbidden: Vec<&str> = vec![rule.as_str(), identity.as_str(), path_sentinel.as_str()];

        let before = snapshot(temp.path());
        // The normal control restores with exactly the frozen facts.
        load_restore_fixed_safety(
            &actual,
            &identity,
            &reference.fixed_sha,
            &reference.arrays_sha,
            &reference.code_version,
        )
        .expect("the unchanged material restores");

        let wrong_fixed = Sha256Digest::of(b"S39_WRONG_FIXED_BYTES");
        let wrong_arrays = Sha256Digest::of(b"S39_WRONG_ARRAYS");
        let unsupported = format!("{}-S39_UNSUPPORTED", reference.code_version);
        let blank_identity = "   ";
        let refused = match case {
            "fixed_sha" => load_restore_fixed_safety(
                &actual,
                &identity,
                &wrong_fixed,
                &reference.arrays_sha,
                &reference.code_version,
            ),
            "arrays_sha" => load_restore_fixed_safety(
                &actual,
                &identity,
                &reference.fixed_sha,
                &wrong_arrays,
                &reference.code_version,
            ),
            "code_version" => load_restore_fixed_safety(
                &actual,
                &identity,
                &reference.fixed_sha,
                &reference.arrays_sha,
                &unsupported,
            ),
            "blank_identity" => load_restore_fixed_safety(
                &actual,
                blank_identity,
                &reference.fixed_sha,
                &reference.arrays_sha,
                &reference.code_version,
            ),
            other => panic!("unknown mismatch case {other}"),
        };
        let err = refused.expect_err("the single changed input must be refused");
        let mut leaks = forbidden.clone();
        if case == "code_version" {
            leaks.push("S39_UNSUPPORTED");
        }
        assert_safe_refusal(&err, &leaks);

        // The refusal published nothing and rewrote nothing.
        assert_eq!(snapshot(temp.path()), before);
        // The control still restores after the refusal.
        load_restore_fixed_safety(
            &actual,
            &identity,
            &reference.fixed_sha,
            &reference.arrays_sha,
            &reference.code_version,
        )
        .expect("the control still restores");
        mark("restore_fixed_material_mismatch", case);
    }

    #[test]
    fn restore_fixed_material_mismatch() {
        mismatch_cell("fixed_sha");
        mismatch_cell("arrays_sha");
        mismatch_cell("code_version");
        mismatch_cell("blank_identity");
    }

    fn copy_rejected_missing_key() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let rule = "S39_RULE_COPY_MISSING_KEY";
        let arrays = arrays_with(rule);
        let reference_path = temp.path().join("reference").join("reference.toml");
        let reference = material(&reference_path, &arrays);
        let path_sentinel = "s39-path-sentinel-copy-missing_key";
        let identity = "s39-identity-sentinel-copy-missing_key:restore";
        let path = temp.path().join(path_sentinel).join("bad-fixed.toml");
        std::fs::create_dir_all(path.parent().expect("copy parent")).expect("mkdir copy");

        let serialized = toml::to_string(&arrays).expect("serialize the reference arrays");
        let mut value: toml::Value = toml::from_str(&serialized).expect("parse the reference TOML");
        value
            .as_table_mut()
            .expect("a TOML table")
            .remove("memory_files");
        let bad_bytes = toml::to_string(&value)
            .expect("serialize the key-omitted copy")
            .into_bytes();
        let reparsed: ExcludedContextPaths = toml::from_str(
            std::str::from_utf8(&bad_bytes).expect("the bad copy is UTF-8"),
        )
        .expect("the omitted key defaults back");
        assert_eq!(
            reparsed, arrays,
            "the omitted key fills the real non-empty default array"
        );
        std::fs::write(&path, &bad_bytes).expect("write the key-omitted copy");

        let before = snapshot(temp.path());
        let err = load_restore_fixed_safety(
            &path,
            identity,
            &Sha256Digest::of(&bad_bytes),
            &reference.arrays_sha,
            &reference.code_version,
        )
        .expect_err("a copy without memory_files must be refused");
        assert_safe_refusal(&err, &[rule, identity, path_sentinel]);
        assert_eq!(snapshot(temp.path()), before, "the refused copy is left as found");
        mark("restore_fixed_copy_rejected", "missing_key");
    }

    fn copy_rejected_bad_toml() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let rule = "S39_RULE_COPY_BAD_TOML";
        let arrays = arrays_with(rule);
        let reference_path = temp.path().join("reference").join("reference.toml");
        let reference = material(&reference_path, &arrays);
        let path_sentinel = "s39-path-sentinel-copy-bad_toml";
        let identity = "s39-identity-sentinel-copy-bad_toml:restore";
        let path = temp.path().join(path_sentinel).join("bad-fixed.toml");
        std::fs::create_dir_all(path.parent().expect("copy parent")).expect("mkdir copy");
        let bad = format!("memory_files = [\"{rule}\" [[[\n");
        std::fs::write(&path, bad.as_bytes()).expect("write the broken TOML");

        let before = snapshot(temp.path());
        let err = load_restore_fixed_safety(
            &path,
            identity,
            &Sha256Digest::of(bad.as_bytes()),
            &reference.arrays_sha,
            &reference.code_version,
        )
        .expect_err("a copy that is not TOML must be refused");
        assert_safe_refusal(&err, &[rule, identity, path_sentinel]);
        assert_eq!(snapshot(temp.path()), before, "the refused copy is left as found");
        mark("restore_fixed_copy_rejected", "bad_toml");
    }

    fn copy_rejected_missing_file() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let rule = "S39_RULE_COPY_MISSING_FILE";
        let arrays = arrays_with(rule);
        let reference_path = temp.path().join("reference").join("reference.toml");
        let reference = material(&reference_path, &arrays);
        let path_sentinel = "s39-path-sentinel-copy-missing_file";
        let identity = "s39-identity-sentinel-copy-missing_file:restore";
        let path = temp.path().join(path_sentinel).join("absent-fixed.toml");
        std::fs::create_dir_all(path.parent().expect("copy parent")).expect("mkdir copy");
        assert!(!path.exists());

        let before = snapshot(temp.path());
        let err = load_restore_fixed_safety(
            &path,
            identity,
            &reference.fixed_sha,
            &reference.arrays_sha,
            &reference.code_version,
        )
        .expect_err("an absent copy must be refused");
        assert_safe_refusal(&err, &[rule, identity, path_sentinel]);
        assert_eq!(
            snapshot(temp.path()),
            before,
            "no missing copy was created or repaired"
        );
        mark("restore_fixed_copy_rejected", "missing_file");
    }

    #[cfg(unix)]
    fn copy_rejected_symlink() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let rule = "S39_RULE_COPY_SYMLINK";
        let arrays = arrays_with(rule);
        let target = temp.path().join("elsewhere").join("valid.toml");
        let reference = material(&target, &arrays);
        let path_sentinel = "s39-path-sentinel-copy-symlink";
        let identity = "s39-identity-sentinel-copy-symlink:restore";
        let link = temp.path().join(path_sentinel).join("linked-fixed.toml");
        std::fs::create_dir_all(link.parent().expect("link parent")).expect("mkdir link");
        std::os::unix::fs::symlink(&target, &link).expect("create the symlink");

        let before = snapshot(temp.path());
        let err = load_restore_fixed_safety(
            &link,
            identity,
            &reference.fixed_sha,
            &reference.arrays_sha,
            &reference.code_version,
        )
        .expect_err("a symlinked copy must be refused");
        assert_safe_refusal(&err, &[rule, identity, path_sentinel]);
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("link metadata")
                .file_type()
                .is_symlink(),
            "the link is left in place"
        );
        assert_eq!(
            std::fs::read(&target).expect("target bytes"),
            reference.bytes,
            "the link target is untouched"
        );
        assert_eq!(snapshot(temp.path()), before, "the refused link is left as found");
        mark("restore_fixed_copy_rejected", "symlink");
    }

    fn copy_rejected_directory() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let rule = "S39_RULE_COPY_DIRECTORY";
        let arrays = arrays_with(rule);
        let reference_path = temp.path().join("reference").join("reference.toml");
        let reference = material(&reference_path, &arrays);
        let path_sentinel = "s39-path-sentinel-copy-directory";
        let identity = "s39-identity-sentinel-copy-directory:restore";
        let path = temp.path().join(path_sentinel).join("fixed-directory");
        std::fs::create_dir_all(&path).expect("mkdir the directory copy");

        let before = snapshot(temp.path());
        let err = load_restore_fixed_safety(
            &path,
            identity,
            &reference.fixed_sha,
            &reference.arrays_sha,
            &reference.code_version,
        )
        .expect_err("a directory is not a fixed copy");
        assert_safe_refusal(&err, &[rule, identity, path_sentinel]);
        assert!(path.is_dir(), "the directory is left in place");
        assert_eq!(
            snapshot(temp.path()),
            before,
            "the refused directory is left as found"
        );
        mark("restore_fixed_copy_rejected", "directory");
    }

    #[test]
    fn restore_fixed_copy_rejected() {
        copy_rejected_missing_key();
        copy_rejected_bad_toml();
        copy_rejected_missing_file();
        #[cfg(unix)]
        copy_rejected_symlink();
        copy_rejected_directory();
    }

    fn recheck_cell(identity_mode: &str, fate: &str) {
        let case = format!("{identity_mode}_{fate}");
        let temp = tempfile::TempDir::new().expect("tempdir");
        let arrays = arrays_with(&format!("S39_RULE_RECHECK_{case}"));
        let original = temp.path().join("frozen").join("restore-original.toml");
        let reference = material(&original, &arrays);
        let identity = match identity_mode {
            "auto" => format!(
                "{SOURCE_CONFIG_IDENTITY_DOMAIN}:sha256:{}",
                reference.fixed_sha.hex()
            ),
            "explicit" => absolute(&original),
            other => panic!("unknown identity mode {other}"),
        };
        let actual = temp.path().join("restored").join("restore-actual.toml");
        std::fs::create_dir_all(actual.parent().expect("actual parent"))
            .expect("mkdir actual");
        std::fs::rename(&original, &actual).expect("move the frozen material");
        assert!(
            !original.exists(),
            "the old logical path is not a readable target"
        );

        let restored = load_restore_fixed_safety(
            &actual,
            &identity,
            &reference.fixed_sha,
            &reference.arrays_sha,
            &reference.code_version,
        )
        .expect("the frozen material restores");
        restored
            .recheck_bytes()
            .expect("the new actual copy rechecks before the change");
        let recorded_identity = restored.config_source_identity().to_string();
        let recorded_bytes = restored.config().fixed_config_bytes.clone();
        let recorded_digest = *restored.bytes_sha256();

        match fate {
            "changed" => {
                std::fs::write(&actual, b"memory_files = [\"S39_CHANGED\"]\n")
                    .expect("change the actual copy");
            }
            "missing" => std::fs::remove_file(&actual).expect("remove the actual copy"),
            other => panic!("unknown fate {other}"),
        }
        let refused = restored
            .recheck_bytes()
            .expect_err("a changed or vanished actual copy must be refused");
        assert!(
            matches!(refused, SourceIngestError::Config { .. }),
            "recheck keeps its own error: {refused:?}"
        );
        assert_eq!(restored.config_source_identity(), recorded_identity);
        assert_eq!(restored.config().fixed_config_bytes, recorded_bytes);
        assert_eq!(restored.bytes_sha256(), &recorded_digest);
        mark("restore_fixed_recheck_physical_path", &case);
    }

    #[test]
    fn restore_fixed_recheck_physical_path() {
        recheck_cell("auto", "changed");
        recheck_cell("auto", "missing");
        recheck_cell("explicit", "changed");
        recheck_cell("explicit", "missing");
    }
}

#[cfg(test)]
mod native_format_tests {
    //! The closed format-selection table (native-format addendum v2, interface
    //! rule 1).
    //!
    //! The table has no free parameters: a connector either publishes whole
    //! JSON documents under its own suffixes or it does not, and everything
    //! else falls back to the historical JSONL default. These cases pin the
    //! whole table plus its two edges -- a suffixless file and the capture's
    //! own `.raw` spelling, neither of which may select a document.

    use super::*;

    fn select(connector: &str, name: &str) -> SourceFormat {
        sealed_format_for(connector, Path::new(name))
    }

    #[test]
    fn every_closed_table_entry_selects_its_declared_format() {
        // claude: whole-document suffixes are `json` and `claude`; `jsonl`
        // stays line-oriented.
        assert_eq!(select("claude", "session.json"), SourceFormat::JsonDocument);
        assert_eq!(select("claude", "session.claude"), SourceFormat::JsonDocument);
        assert_eq!(select("claude", "session.jsonl"), SourceFormat::Jsonl);

        // codex: whole-document suffix is `json` only; `.claude` is not a
        // codex suffix and must not borrow claude's table.
        assert_eq!(
            select("codex", "rollout-2026-01-01T00-00-00-x.json"),
            SourceFormat::JsonDocument
        );
        assert_eq!(
            select("codex", "rollout-2026-01-01T00-00-00-x.jsonl"),
            SourceFormat::Jsonl
        );
        assert_eq!(select("codex", "rollout-x.claude"), SourceFormat::Jsonl);

        // The comparison ignores ASCII case, so a discovery that accepted a
        // `.JSON` file is read as the document it is.
        assert_eq!(select("claude", "session.JSON"), SourceFormat::JsonDocument);
        assert_eq!(select("claude", "session.Json"), SourceFormat::JsonDocument);
        assert_eq!(select("claude", "session.CLAUDE"), SourceFormat::JsonDocument);
        assert_eq!(select("codex", "rollout-x.JSON"), SourceFormat::JsonDocument);
        assert_eq!(select("claude", "session.JSONL"), SourceFormat::Jsonl);
        assert_eq!(select("codex", "rollout-x.JSONL"), SourceFormat::Jsonl);
        assert_eq!(select("codex", "rollout-x.JsonL"), SourceFormat::Jsonl);
    }

    #[test]
    fn every_other_connector_and_every_other_suffix_keeps_the_jsonl_default() {
        // Other connectors keep the historical default even for a `.json`
        // file; this ticket does not widen discovery or fidelity.
        assert_eq!(select("gemini", "session.json"), SourceFormat::Jsonl);
        assert_eq!(select("cursor", "session.json"), SourceFormat::Jsonl);
        assert_eq!(select("aider", "session.claude"), SourceFormat::Jsonl);

        // An inert suffix, including the capture's own `.raw` spelling, never
        // selects a document.
        assert_eq!(select("claude", "session.raw"), SourceFormat::Jsonl);
        assert_eq!(select("codex", "rollout-x.raw"), SourceFormat::Jsonl);
        assert_eq!(select("claude", "session.txt"), SourceFormat::Jsonl);

        // A suffixless file, and a dotfile whose name is the whole suffix
        // candidate, have no extension to match.
        assert_eq!(select("claude", "session"), SourceFormat::Jsonl);
        assert_eq!(select("codex", "rollout-x"), SourceFormat::Jsonl);
        assert_eq!(select("claude", ".claude"), SourceFormat::Jsonl);

        // A path is always a path, never a bare name: the extension is the
        // last component's, not any directory's.
        assert_eq!(
            select("claude", "/synthetic/project.claude/session"),
            SourceFormat::Jsonl
        );
        assert_eq!(
            select("claude", "/synthetic/project/session.claude"),
            SourceFormat::JsonDocument
        );
    }
}

#[cfg(test)]
mod source_safety_preview_tests {
    //! Task40: the read-only safety preview.
    //!
    //! Every case builds its own sealed material under a `TempDir`. The expected
    //! values come from the frozen fixture bytes, the existing independent
    //! framing scan and the existing pure SQL mapper -- never from the preview
    //! under test.

    use super::*;
    use franken_agent_detection as fad;

    const WORKSPACE_ROOT: &str = "/synthetic/preview-workspace";
    const WORKSPACE: &str = "/synthetic/preview-workspace/app";
    const MAPPED_ROOT: &str = "/synthetic/preview-mapped";
    const MAPPED: &str = "/synthetic/preview-mapped/app";
    const TWICE_ROOT: &str = "/synthetic/preview-twice";
    const TWICE: &str = "/synthetic/preview-twice/app";
    const QUESTION: &str = "S40 ordinary question";
    const ANSWER: &str = "S40 ordinary answer";
    const SECRET: &str = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
    const CLAUDE_SENTINEL: &str = "S40_CLAUDE_EXCLUDED_BODY";
    const CODEX_SENTINEL: &str = "S40_CODEX_EXCLUDED_BODY";

    const CHILD_MARKER: &str = "CASS_TASK40_PREVIEW_CHILD";
    const CHILD_CASE: &str = "CASS_TASK40_PREVIEW_CASE";
    const CHILD_ROOT: &str = "CASS_TASK40_PREVIEW_ROOT";

    const P2_NAME: &str =
        "indexer::source_ingest::source_safety_preview_tests::p2_preview_uses_safety";

    fn mark(test: &str, case: &str) {
        println!("SOURCE_SAFETY_PREVIEW_SCENARIO test={test} case={case} result=pass");
    }

    struct Fixture {
        temp: tempfile::TempDir,
        safety: Arc<FixedSafetyConfig>,
        root: crate::connectors::ScanRoot,
        meta: crate::indexer::scan_root_meta::ScanRootMeta,
        discovered: crate::connectors::DiscoveredSourceFile,
        copy: PathBuf,
        data_dir: PathBuf,
    }

    /// Write one private root, its sealed-safety copy and the discovered file.
    fn fixture(connector: &str, suffix: &str, body: &[u8]) -> Fixture {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let home = temp.path().join("home");
        let (scan_path, file_name, provider_slug) = match connector {
            "codex" => (
                home.join(".codex/sessions/2026/01"),
                format!("rollout-2026-01-01T00-00-00-s40.{suffix}"),
                "codex",
            ),
            _ => (
                home.join(".claude/projects/proj"),
                format!("session.{suffix}"),
                "claude_code",
            ),
        };
        std::fs::create_dir_all(&scan_path).expect("mkdir scan root");
        let source_path = scan_path.join(file_name);
        std::fs::write(&source_path, body).expect("write the synthetic session");

        let copy = temp.path().join("fixed-safety.toml");
        std::fs::write(&copy, include_bytes!("../../config/excluded_context_paths.toml"))
            .expect("write the fixed copy");
        let safety = Arc::new(load_fixed_safety_config(&copy).expect("load the fixed copy"));

        let root = crate::connectors::ScanRoot::local(scan_path.clone())
            .with_rewrite(WORKSPACE_ROOT, MAPPED_ROOT)
            .with_rewrite(MAPPED_ROOT, TWICE_ROOT);
        let meta = crate::indexer::scan_root_meta::ScanRootMeta {
            root_id: format!("home:{connector}:s40-preview"),
            origin_host: "local".to_string(),
            readonly: false,
            canonical_path: scan_path.clone(),
            source_name: connector.to_string(),
            watermarks_enabled: true,
            mirror_root: false,
        };
        let discovered = crate::connectors::DiscoveredSourceFile {
            provider_slug: provider_slug.to_string(),
            scan_root: scan_path,
            source_path,
            role: crate::connectors::DiscoveredSourceRole::PrimarySessionLog,
            origin: crate::connectors::Origin::local(),
            platform: None,
            required_for_reconstruction: true,
            size_bytes: None,
            modified_at_ms: None,
        };
        let data_dir = temp.path().join("data");
        Fixture { temp, safety, root, meta, discovered, copy, data_dir }
    }

    /// The ordinary sealed preparation, exactly as the production caller runs it.
    fn prepare(fixture: &Fixture) -> SourceInputJob {
        let (connector_name, connector): (&'static str, Box<dyn crate::connectors::Connector + Send>) =
            match fixture.meta.source_name.as_str() {
                "codex" => ("codex", Box::new(crate::connectors::codex::CodexConnector::new())),
                _ => (
                    "claude",
                    Box::new(crate::connectors::claude_code::ClaudeCodeConnector::new()),
                ),
            };
        std::fs::create_dir_all(&fixture.data_dir).expect("mkdir data");
        let request = SourceInputRequest {
            connector_name,
            data_dir: &fixture.data_dir,
            root: &fixture.root,
            meta: &fixture.meta,
            discovered: &fixture.discovered,
            safety: &fixture.safety,
        };
        prepare_source_input(connector.as_ref(), &request).expect("the synthetic input prepares")
    }

    fn lines_body(lines: &[serde_json::Value]) -> Vec<u8> {
        let mut body = String::new();
        for line in lines {
            body.push_str(&line.to_string());
            body.push('\n');
        }
        body.into_bytes()
    }

    fn document_body(document: &serde_json::Value) -> Vec<u8> {
        format!(
            "{}\n",
            serde_json::to_string_pretty(document).expect("pretty document")
        )
        .into_bytes()
    }

    // ------------------------------------------------------------------
    // Frozen fixture values (task-40-fixtures.json), inlined as test data.
    // ------------------------------------------------------------------

    fn claude_jsonl_lines() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "cwd": WORKSPACE, "sessionId": "preview-claude", "type": "user",
                "uuid": "preview-u",
                "message": {"role": "user", "content": QUESTION}
            }),
            serde_json::json!({
                "cwd": WORKSPACE, "sessionId": "preview-claude", "type": "assistant",
                "uuid": "preview-a",
                "message": {"role": "assistant", "content": ANSWER}
            }),
        ]
    }

    fn claude_document_value() -> serde_json::Value {
        serde_json::json!({
            "cwd": WORKSPACE,
            "sessionId": "preview-claude",
            "version": "2.0.37",
            "title": "preview native document",
            "messages": [
                {"role": "user", "content": QUESTION,
                 "timestamp": "2026-01-01T00:00:00.000Z"},
                {"role": "assistant",
                 "content": [{"type": "text", "text": ANSWER}],
                 "timestamp": "2026-01-01T00:00:01.000Z"}
            ],
            "syntheticUnknown": {"keep": 7}
        })
    }

    fn codex_jsonl_lines() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "type": "session_meta",
                "timestamp": "2026-01-01T00:00:00.000Z",
                "payload": {"id": "preview-codex", "cwd": WORKSPACE, "cli_version": "0.42.0"}
            }),
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:01.000Z",
                "type": "response_item",
                "payload": {"type": "message", "id": "preview-0", "role": "user",
                    "content": [{"type": "input_text", "text": QUESTION}]}
            }),
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:02.000Z",
                "type": "response_item",
                "payload": {"type": "message", "id": "preview-1", "role": "assistant",
                    "content": [{"type": "output_text", "text": ANSWER}]}
            }),
        ]
    }

    fn codex_document_value() -> serde_json::Value {
        serde_json::json!({
            "session": {"id": "preview-codex", "cwd": WORKSPACE, "cli_version": "0.42.0"},
            "items": [
                {"type": "message", "role": "user",
                 "content": [{"type": "input_text", "text": QUESTION}],
                 "timestamp": "2026-01-01T00:00:00.000Z"},
                {"type": "message", "role": "assistant",
                 "content": [{"type": "output_text", "text": ANSWER}],
                 "timestamp": "2026-01-01T00:00:01.000Z"}
            ],
            "syntheticUnknown": {"keep": 7}
        })
    }

    fn claude_exclusion_lines() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "cwd": WORKSPACE, "sessionId": "preview-claude-ex", "type": "assistant",
                "uuid": "ex-call",
                "message": {"role": "assistant", "content": [
                    {"type": "text", "text": format!("reading {SECRET}")},
                    {"type": "tool_use", "id": "toolu_preview_40", "name": "Read",
                     "input": {"file_path": "/synthetic/CLAUDE.local.md"}}
                ]},
                "syntheticSecretCopy": format!("copy {SECRET}")
            }),
            serde_json::json!({
                "cwd": WORKSPACE, "sessionId": "preview-claude-ex", "type": "user",
                "uuid": "ex-result",
                "message": {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_preview_40",
                     "content": CLAUDE_SENTINEL}
                ]}
            }),
        ]
    }

    fn codex_exclusion_lines() -> Vec<serde_json::Value> {
        vec![
            serde_json::json!({
                "type": "session_meta",
                "timestamp": "2026-01-01T00:00:00.000Z",
                "payload": {"id": "preview-codex", "cwd": WORKSPACE, "cli_version": "0.42.0"}
            }),
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:01.000Z",
                "type": "response_item",
                "payload": {"type": "message", "id": "preview-0", "role": "user",
                    "content": [{"type": "input_text", "text":
                        format!("<environment_context>\n<cwd>{WORKSPACE}</cwd>\n{CODEX_SENTINEL}\n</environment_context>")}]}
            }),
            serde_json::json!({
                "timestamp": "2026-01-01T00:00:02.000Z",
                "type": "response_item",
                "payload": {"type": "message", "id": "preview-1", "role": "assistant",
                    "content": [{"type": "output_text", "text": format!("ack {SECRET}")}],
                    "syntheticSecretCopy": format!("copy {SECRET}")}
            }),
        ]
    }

    fn failed_record_body() -> Vec<u8> {
        let before = serde_json::json!({
            "cwd": WORKSPACE, "sessionId": "preview-claude", "type": "user",
            "uuid": "preview-u",
            "message": {"role": "user", "content": QUESTION}
        });
        let after = serde_json::json!({
            "cwd": WORKSPACE, "sessionId": "preview-claude", "type": "assistant",
            "uuid": "preview-a",
            "message": {"role": "assistant", "content": ANSWER}
        });
        format!("{}\n{{ this line is not json\n{}\n", before, after).into_bytes()
    }

    fn native_fixture(case: &str) -> Fixture {
        match case {
            "claude_jsonl" => fixture("claude", "jsonl", &lines_body(&claude_jsonl_lines())),
            "claude_document" => {
                fixture("claude", "json", &document_body(&claude_document_value()))
            }
            "codex_jsonl" => fixture("codex", "jsonl", &lines_body(&codex_jsonl_lines())),
            "codex_document" => {
                fixture("codex", "json", &document_body(&codex_document_value()))
            }
            other => panic!("unknown native case {other}"),
        }
    }

    fn exclusion_fixture(case: &str) -> Fixture {
        match case {
            "claude_exclusion" => {
                fixture("claude", "jsonl", &lines_body(&claude_exclusion_lines()))
            }
            "codex_exclusion" => fixture("codex", "jsonl", &lines_body(&codex_exclusion_lines())),
            other => panic!("unknown exclusion case {other}"),
        }
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn canonical(value: &fad::LosslessSourceValue) -> Vec<u8> {
        let mut out = Vec::new();
        value.write_canonical(&mut out).expect("canonical bytes");
        out
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    fn framed(body: &[u8], format: SourceFormat) -> Vec<source_facts::FramedSourceRecord> {
        let mut scan = source_facts::FramingScan::new(body, format);
        let mut frames = Vec::new();
        while !scan.is_done() {
            let page = scan.next_page(64).expect("the independent framing scan");
            if page.is_empty() {
                break;
            }
            frames.extend(page);
        }
        frames
    }

    fn snapshot(root: &Path) -> std::collections::BTreeMap<PathBuf, String> {
        fn walk(dir: &Path, out: &mut std::collections::BTreeMap<PathBuf, String>) {
            let entries = match std::fs::read_dir(dir) {
                Ok(entries) => entries,
                Err(_) => return,
            };
            for entry in entries {
                let entry = entry.expect("directory entry");
                let path = entry.path();
                let metadata = std::fs::symlink_metadata(&path).expect("entry metadata");
                if metadata.file_type().is_symlink() {
                    let target = std::fs::read_link(&path).expect("link target");
                    out.insert(path, format!("symlink:{}", target.display()));
                } else if metadata.is_dir() {
                    out.insert(path.clone(), "dir".to_string());
                    walk(&path, out);
                } else {
                    let digest = Sha256Digest::of(&std::fs::read(&path).expect("file bytes"));
                    out.insert(path, format!("file:{}", digest.hex()));
                }
            }
        }
        let mut out = std::collections::BTreeMap::new();
        out.insert(root.to_path_buf(), "root".to_string());
        walk(root, &mut out);
        out
    }

    /// The full diagnostics shape, including the safe filter's own fields.
    ///
    /// `None` and `Some(empty)` are different facts and stay distinct here.
    fn diagnostics_signature(
        diagnostics: Option<&[source_facts::SafeDiagnostic]>,
    ) -> serde_json::Value {
        match diagnostics {
            None => serde_json::Value::Null,
            Some(items) => serde_json::Value::Array(
                items
                    .iter()
                    .map(|item| {
                        serde_json::json!({
                            "code": item.code,
                            "detail": item.detail,
                            "offset": item.offset,
                            "position": serde_json::to_value(&item.position)
                                .expect("a safe position serializes"),
                        })
                    })
                    .collect(),
            ),
        }
    }

    fn preview_signature(preview: &SourceSafetyPreview) -> serde_json::Value {
        serde_json::json!({
            "records": preview.records.iter().map(|record| serde_json::json!({
                "locator": [
                    record.locator().ordinal,
                    record.locator().record_pointer,
                    record.locator().byte_start,
                    record.locator().byte_end
                ],
                "expected": record.expected_raw_sha256().hex(),
                "observed": record.observed_raw_sha256().map(|d| d.hex()),
                "parse": record.parse_state().as_str(),
                "mapping": record.record_mapping_state().as_str(),
                "safety": record.safety_state().as_str(),
                "retention": record.retention_state().as_str(),
                "native_ids": record.native_ids().map(canonical),
                "safe": record.safe_value().map(canonical),
                "diagnostics": diagnostics_signature(record.diagnostics()),
            })).collect::<Vec<_>>(),
            "parse_failed": preview.parse_failed,
            "diagnostics": preview.diagnostics,
            "conversations": preview.conversations.iter().map(|item| serde_json::json!({
                "ordinal": item.ordinal,
                "prepared": serde_json::to_value(&item.prepared.conv).expect("prepared"),
                "excluded": serde_json::to_value(&item.prepared.excluded).expect("excluded"),
                "sql": serde_json::to_value(&item.sql_projection).expect("sql"),
            })).collect::<Vec<_>>(),
        })
    }

    fn projection_workspace(workspace: &Option<PathBuf>) -> Option<String> {
        workspace
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned())
    }

    fn assert_db_matches_projection(
        storage: &crate::storage::sqlite::FrankenStorage,
        projection: &crate::model::types::Conversation,
    ) {
        type ConversationRow = (
            i64,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
            Option<i64>,
            Option<i64>,
            Option<String>,
            String,
            Option<String>,
        );
        let row: ConversationRow = storage
            .raw()
            .query_row_map(
                "SELECT c.id, a.slug, w.path, c.external_id, c.title, c.source_path,
                        c.started_at, c.ended_at, c.metadata_json, c.source_id, c.origin_host
                 FROM conversations c
                 JOIN agents a ON a.id = c.agent_id
                 LEFT JOIN workspaces w ON w.id = c.workspace_id",
                &[],
                |row| {
                    Ok((
                        row.get_typed(0)?,
                        row.get_typed(1)?,
                        row.get_typed(2)?,
                        row.get_typed(3)?,
                        row.get_typed(4)?,
                        row.get_typed(5)?,
                        row.get_typed(6)?,
                        row.get_typed(7)?,
                        row.get_typed(8)?,
                        row.get_typed(9)?,
                        row.get_typed(10)?,
                    ))
                },
            )
            .expect("the installed conversation row");

        let conversation_id = row.0;
        assert_eq!(row.1, projection.agent_slug, "agent slug");
        assert_eq!(row.2, projection_workspace(&projection.workspace), "workspace");
        assert_eq!(row.3, projection.external_id, "external id");
        assert_eq!(row.4, projection.title, "title");
        assert_eq!(
            row.5,
            projection.source_path.to_string_lossy().into_owned(),
            "source path"
        );
        assert_eq!(row.6, projection.started_at, "started at");
        assert_eq!(row.7, projection.ended_at, "ended at");
        // The source-aware insert stores a non-empty metadata object as
        // msgpack in `metadata_bin`; the production reader is the authority.
        assert!(
            row.8.is_none(),
            "metadata_json stays NULL for the msgpack metadata_bin payload"
        );
        let metadata = storage
            .conversation_metadata_for_tests(conversation_id)
            .expect("the stored logical metadata");
        assert_eq!(metadata, projection.metadata_json, "logical metadata json");
        assert_eq!(row.9, projection.source_id, "source id");
        assert_eq!(row.10, projection.origin_host, "origin host");

        // `fetch_messages` is the production reader: it decodes `extra_bin`
        // msgpack and `excluded` exactly as every consumer does.
        let messages = storage
            .fetch_messages(conversation_id)
            .expect("the installed message rows");
        assert_eq!(messages.len(), projection.messages.len(), "message count");
        for (stored, expected) in messages.iter().zip(projection.messages.iter()) {
            assert!(stored.id.is_some(), "the database assigns the message id");
            assert_eq!(stored.idx, expected.idx, "message idx");
            assert_eq!(stored.role, expected.role, "role");
            assert_eq!(stored.author, expected.author, "author");
            assert_eq!(stored.created_at, expected.created_at, "created at");
            assert_eq!(stored.content, expected.content, "content");
            assert_eq!(stored.extra_json, expected.extra_json, "extra json");
            assert_eq!(stored.excluded, expected.excluded, "excluded marker");
            assert!(stored.snippets.is_empty(), "the fixture writes no snippet");
            assert!(expected.snippets.is_empty(), "the projection carries no snippet");
        }
        let snippets: i64 = storage
            .raw()
            .query_row_map("SELECT COUNT(*) FROM snippets", &[], |row| row.get_typed(0))
            .expect("count snippets");
        assert_eq!(snippets, 0, "the fixture writes no snippet rows");
    }

    /// Every column of every fact table, as the storage layer's own typed
    /// values. Blob, Text and Null stay distinct; no value is stringified.
    type Snapshot = (
        Vec<(String, Vec<Vec<crate::storage::api::Value>>)>,
        String,
    );

    fn fact_snapshot(storage: &crate::storage::sqlite::FrankenStorage) -> Snapshot {
        let db = storage.raw();
        let mut tables = Vec::new();
        for table in [
            "conversations",
            "messages",
            "source_inputs",
            "source_records",
            "source_message_links",
            "operation_commit_receipt",
        ] {
            let column_count: i64 = db
                .query_row_map(
                    &format!("SELECT COUNT(*) FROM pragma_table_info('{table}')"),
                    &[],
                    |row| row.get_typed(0),
                )
                .expect("count a table's columns");
            let columns = column_count as usize;
            let rows: Vec<Vec<crate::storage::api::Value>> = db
                .query_all_map(&format!("SELECT * FROM {table} ORDER BY rowid"), &[], |row| {
                    let mut values = Vec::with_capacity(columns);
                    for idx in 0..columns {
                        values.push(row.get_value(idx)?);
                    }
                    Ok(values)
                })
                .expect("read every business column");
            tables.push((table.to_string(), rows));
        }
        let revision: String = db
            .query_row_map(
                "SELECT COALESCE((SELECT value FROM meta WHERE key = 'source_facts_revision'), '0')",
                &[],
                |row| row.get_typed(0),
            )
            .expect("read the source facts revision");
        (tables, revision)
    }

    // ------------------------------------------------------------------
    // p1: four native cases, both projections and the real commit.
    // ------------------------------------------------------------------

    fn p1_case(case: &str) {
        let fixture = native_fixture(case);
        let body = std::fs::read(&fixture.discovered.source_path).expect("fixture bytes");
        let job = prepare(&fixture);
        assert!(!job.records.is_empty(), "{case}: the read delivered records");
        assert_eq!(job.conversations.len(), 1, "{case}: one conversation");

        let db_path = fixture.data_dir.join("agent_search.db");
        assert!(!db_path.exists(), "{case}: the preview creates no database");

        let before = snapshot(fixture.temp.path());
        let first = match preview_source_input_safety(&job) {
            Ok(preview) => preview,
            Err(error) => panic!("{case}: the preview failed: {error}"),
        };
        let after = snapshot(fixture.temp.path());
        assert_eq!(before, after, "{case}: the preview changes no material");
        assert!(!db_path.exists(), "{case}: still no database");

        let second = match preview_source_input_safety(&job) {
            Ok(preview) => preview,
            Err(error) => panic!("{case}: the second preview failed: {error}"),
        };
        assert_eq!(
            preview_signature(&first),
            preview_signature(&second),
            "{case}: the preview is repeatable"
        );

        assert_eq!(first.conversations.len(), 1, "{case}: one preview conversation");
        let conversation = &first.conversations[0];
        assert_eq!(conversation.ordinal, job.conversations[0].ordinal, "{case}: ordinal");
        assert_eq!(
            conversation.prepared.conv.workspace.as_deref(),
            Some(Path::new(MAPPED)),
            "{case}: the prepared workspace is rewritten exactly once"
        );
        assert_eq!(
            conversation.sql_projection.workspace.as_deref(),
            Some(Path::new(MAPPED)),
            "{case}: the SQL workspace is rewritten exactly once"
        );
        assert_ne!(
            conversation.prepared.conv.workspace.as_deref(),
            Some(Path::new(TWICE)),
            "{case}: the second rewrite is not chained"
        );
        for (label, metadata) in [
            ("prepared", &conversation.prepared.conv.metadata),
            ("sql", &conversation.sql_projection.metadata_json),
        ] {
            assert_eq!(
                metadata
                    .pointer("/cass/workspace_original")
                    .and_then(serde_json::Value::as_str),
                Some(WORKSPACE),
                "{case}: {label} keeps the original workspace"
            );
        }
        let texts: Vec<&str> = conversation
            .prepared
            .conv
            .messages
            .iter()
            .map(|message| message.content.as_str())
            .collect();
        assert_eq!(texts, vec![QUESTION, ANSWER], "{case}: the prepared bodies");
        let roles: Vec<&str> = conversation
            .prepared
            .conv
            .messages
            .iter()
            .map(|message| message.role.as_str())
            .collect();
        assert_eq!(roles, vec!["user", "assistant"], "{case}: the declared roles");
        assert_eq!(
            conversation.sql_projection.messages.len(),
            2,
            "{case}: both messages project"
        );
        for (projected, prepared) in conversation
            .sql_projection
            .messages
            .iter()
            .zip(conversation.prepared.conv.messages.iter())
        {
            assert_eq!(projected.content, prepared.content, "{case}: content maps");
        }
        // The SQL view is the existing pure mapper's own output; compare the
        // whole value, not just the bodies and the database projection.
        let explicit = crate::indexer::persist::map_to_internal_with_explicit_redaction(
            &conversation.prepared,
            None,
            true,
        );
        assert_eq!(
            serde_json::to_value(&conversation.sql_projection).expect("the preview SQL view"),
            serde_json::to_value(&explicit).expect("the existing explicit mapper"),
            "{case}: the SQL view equals the existing explicit mapper field for field"
        );

        let format = job.input.manifest().format();
        let frames = framed(&body, format);
        assert_eq!(frames.len(), job.records.len(), "{case}: independent framing count");
        assert_eq!(first.records.len(), frames.len(), "{case}: preview record count");
        let shared = match verify_and_judge_source_input(&job) {
            Ok(passed) => passed,
            Err(error) => panic!("{case}: the shared pass failed: {error}"),
        };
        assert_eq!(first.parse_failed, shared.staged.parse_failed, "{case}: parse count");
        assert_eq!(first.diagnostics, shared.staged.diagnostics, "{case}: diagnostics count");
        for (idx, (record, frame)) in first.records.iter().zip(frames.iter()).enumerate() {
            assert_eq!(record.locator(), frame.locator(), "{case}: locator {idx}");
            assert_eq!(
                record.expected_raw_sha256(),
                frame.raw_sha256(),
                "{case}: expected raw digest {idx}"
            );
            assert_eq!(
                record.observed_raw_sha256(),
                Some(frame.raw_sha256()),
                "{case}: observed raw digest {idx}"
            );
            assert_eq!(
                record.parse_state(),
                source_facts::ParseState::Parsed,
                "{case}: parsed {idx}"
            );
            assert_eq!(
                record.retention_state(),
                source_facts::RetentionState::PayloadPresent,
                "{case}: payload present {idx}"
            );
            assert_eq!(
                record.safety_state(),
                source_facts::SafetyState::Preserved,
                "{case}: preserved {idx}"
            );
            let oracle = &shared.staged.records[idx];
            assert_eq!(
                record.record_mapping_state(),
                oracle.record_mapping_state(),
                "{case}: mapping state {idx}"
            );
            assert_eq!(record.native_ids(), oracle.native_ids(), "{case}: native ids {idx}");
            assert_eq!(
                diagnostics_signature(record.diagnostics()),
                diagnostics_signature(oracle.diagnostics()),
                "{case}: diagnostics {idx}"
            );
            let safe = record.safe_value().expect("a parsed record keeps its safe payload");
            let safe_bytes = canonical(safe);
            assert_eq!(
                safe_bytes,
                canonical(oracle.safe_value().expect("the shared pass keeps the payload")),
                "{case}: safe payload bytes {idx}"
            );
            assert!(
                match case {
                    "claude_jsonl" => {
                        (idx == 0 && contains(&safe_bytes, QUESTION))
                            || (idx == 1 && contains(&safe_bytes, ANSWER))
                    }
                    "codex_jsonl" => {
                        (idx == 1 && contains(&safe_bytes, QUESTION))
                            || (idx == 2 && contains(&safe_bytes, ANSWER))
                            || (idx == 0 && contains(&safe_bytes, "session_meta"))
                    }
                    _ => {
                        contains(&safe_bytes, QUESTION) && contains(&safe_bytes, ANSWER)
                    }
                },
                "{case}: the safe payload keeps the declared body {idx}"
            );
        }
        if case.contains("document") {
            let safe = canonical(
                first.records[0]
                    .safe_value()
                    .expect("the document record keeps its safe payload"),
            );
            assert!(contains(&safe, "syntheticUnknown"), "{case}: unknown field kept");
            assert!(contains(&safe, "keep"), "{case}: unknown value kept");
        }
        if case == "codex_jsonl" {
            assert_eq!(first.records.len(), 3, "codex_jsonl record count");
        }

        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path)
            .expect("open the real database");
        let commit = commit_source_input(&storage, &job)
            .unwrap_or_else(|error| panic!("{case}: the real commit failed: {error}"));
        assert!(commit.outcome.is_success(), "{case}: the real commit succeeds");
        drop(storage);

        let reopened = crate::storage::sqlite::FrankenStorage::open(&db_path)
            .expect("reopen the real database");
        assert_db_matches_projection(&reopened, &conversation.sql_projection);
        let stored_workspace: Option<String> = reopened
            .raw()
            .query_row_map(
                "SELECT w.path FROM conversations c
                 JOIN workspaces w ON w.id = c.workspace_id",
                &[],
                |row| row.get_typed(0),
            )
            .expect("the stored workspace");
        assert_eq!(stored_workspace.as_deref(), Some(MAPPED), "{case}: DB workspace");
        assert_ne!(
            stored_workspace.as_deref(),
            Some(TWICE),
            "{case}: the DB never carries the twice-mapped workspace"
        );
    }

    #[test]
    fn p1_preview_matches_commit() {
        for case in ["claude_jsonl", "claude_document", "codex_jsonl", "codex_document"] {
            p1_case(case);
            mark("p1_preview_matches_commit", case);
        }
    }

    // ------------------------------------------------------------------
    // p2: the exclusion cases, each in its own same-named child.
    // ------------------------------------------------------------------

    fn child_case() -> Option<(String, PathBuf)> {
        let marker = std::env::var_os(CHILD_MARKER)?;
        if marker.is_empty() {
            return None;
        }
        let case = std::env::var(CHILD_CASE).expect("the child case is set beside the marker");
        let root = PathBuf::from(
            std::env::var_os(CHILD_ROOT).expect("the child root is set beside the marker"),
        );
        Some((case, root))
    }

    fn p2_child(case: &str, root: &Path) {
        let fixture = exclusion_fixture(case);
        let job = prepare(&fixture);
        let preview = match preview_source_input_safety(&job) {
            Ok(preview) => preview,
            Err(error) => panic!("{case}: the preview failed: {error}"),
        };
        assert_eq!(preview.conversations.len(), 1, "{case}: one conversation");
        let conversation = &preview.conversations[0];

        let mut excluded_markers = 0usize;
        let mut sentinel_in_prepared = false;
        let mut secret_in_prepared = false;
        let mut invocations = 0usize;
        for message in &conversation.prepared.conv.messages {
            if message.content.contains(CLAUDE_SENTINEL) || message.content.contains(CODEX_SENTINEL)
            {
                sentinel_in_prepared = true;
            }
            let extra = serde_json::to_string(&message.extra).expect("prepared extra");
            if extra.contains(CLAUDE_SENTINEL) || extra.contains(CODEX_SENTINEL) {
                sentinel_in_prepared = true;
            }
            if message.content.contains(SECRET) || extra.contains(SECRET) {
                secret_in_prepared = true;
            }
            invocations += message.invocations.len();
        }
        for marker in &conversation.prepared.excluded {
            if marker.is_some() {
                excluded_markers += 1;
            }
        }

        // The SQL view is the existing pure mapper's own output, field for field;
        // the redacted copy must stay in `extra` rather than disappear with it.
        let explicit = crate::indexer::persist::map_to_internal_with_explicit_redaction(
            &conversation.prepared,
            None,
            true,
        );
        assert_eq!(
            serde_json::to_value(&conversation.sql_projection).expect("the preview SQL view"),
            serde_json::to_value(&explicit).expect("the existing explicit mapper"),
            "{case}: the SQL view equals the existing explicit mapper field for field"
        );

        let mut sentinel_in_sql = false;
        let mut secret_in_sql = false;
        let mut sql_excluded = 0usize;
        let mut redacted_text = false;
        let mut extra_copy_redacted = false;
        for message in &conversation.sql_projection.messages {
            let extra = serde_json::to_string(&message.extra_json).expect("sql extra");
            if message.content.contains(CLAUDE_SENTINEL) || message.content.contains(CODEX_SENTINEL)
            {
                sentinel_in_sql = true;
            }
            if extra.contains(CLAUDE_SENTINEL) || extra.contains(CODEX_SENTINEL) {
                sentinel_in_sql = true;
            }
            if message.content.contains(SECRET) || extra.contains(SECRET) {
                secret_in_sql = true;
            }
            if message.content.contains("reading [REDACTED]")
                || message.content.contains("ack [REDACTED]")
            {
                redacted_text = true;
            }
            if extra.contains("copy [REDACTED]") {
                extra_copy_redacted = true;
            }
            if message.excluded.is_some() {
                sql_excluded += 1;
            }
        }
        assert!(!sentinel_in_prepared, "{case}: the excluded body is cleared");
        assert!(secret_in_prepared, "{case}: the non-excluded body still carries the pattern");
        assert!(!sentinel_in_sql, "{case}: the SQL view clears the excluded body");
        assert!(!secret_in_sql, "{case}: the SQL view redacts the pattern");
        assert!(redacted_text, "{case}: the SQL view carries the redaction marker");
        assert!(
            extra_copy_redacted,
            "{case}: the SQL view keeps the redacted copy in extra instead of dropping it"
        );
        assert_eq!(excluded_markers, 1, "{case}: exactly one excluded marker");
        assert_eq!(sql_excluded, 1, "{case}: the SQL view keeps the same exclusion");

        // Every non-empty record is checked on its own facts: the independent
        // framing and the shared pass are the two oracles, so a model that
        // dropped or emptied an excluded record cannot pass.
        let body = std::fs::read(&fixture.discovered.source_path).expect("fixture bytes");
        let format = job.input.manifest().format();
        let frames = framed(&body, format);
        let shared = match verify_and_judge_source_input(&job) {
            Ok(passed) => passed,
            Err(error) => panic!("{case}: the shared pass failed: {error}"),
        };
        assert_eq!(preview.records.len(), frames.len(), "{case}: record count");
        assert_eq!(shared.staged.records.len(), frames.len(), "{case}: shared record count");
        assert!(!preview.records.is_empty(), "{case}: the preview is not empty");
        let mut safe_sentinel = false;
        let mut safe_secret = false;
        let mut safe_non_sensitive = false;
        for (idx, (record, frame)) in preview.records.iter().zip(frames.iter()).enumerate() {
            assert_eq!(record.locator(), frame.locator(), "{case}: locator {idx}");
            assert_eq!(
                record.expected_raw_sha256(),
                frame.raw_sha256(),
                "{case}: expected raw digest {idx}"
            );
            assert_eq!(
                record.observed_raw_sha256(),
                Some(frame.raw_sha256()),
                "{case}: observed raw digest {idx}"
            );
            let oracle = &shared.staged.records[idx];
            assert_eq!(record.parse_state(), oracle.parse_state(), "{case}: parse {idx}");
            assert_eq!(
                record.record_mapping_state(),
                oracle.record_mapping_state(),
                "{case}: mapping {idx}"
            );
            assert_eq!(
                record.safety_state(),
                oracle.safety_state(),
                "{case}: safety {idx}"
            );
            assert_eq!(
                record.retention_state(),
                oracle.retention_state(),
                "{case}: retention {idx}"
            );
            assert_eq!(record.native_ids(), oracle.native_ids(), "{case}: native ids {idx}");
            assert_eq!(
                diagnostics_signature(record.diagnostics()),
                diagnostics_signature(oracle.diagnostics()),
                "{case}: diagnostics {idx}"
            );
            let safe = record.safe_value().expect("a parsed record keeps its safe payload");
            let safe_bytes = canonical(safe);
            assert_eq!(
                safe_bytes,
                canonical(oracle.safe_value().expect("the shared pass keeps the payload")),
                "{case}: safe payload bytes {idx}"
            );
            if contains(&safe_bytes, CLAUDE_SENTINEL) || contains(&safe_bytes, CODEX_SENTINEL) {
                safe_sentinel = true;
            }
            if contains(&safe_bytes, SECRET) {
                safe_secret = true;
            }
            if case == "claude_exclusion" && contains(&safe_bytes, "toolu_preview_40") {
                safe_non_sensitive = true;
            }
            if case == "codex_exclusion" && contains(&safe_bytes, "session_meta") {
                safe_non_sensitive = true;
            }
        }
        assert!(!safe_sentinel, "{case}: the safe records clear the excluded body");
        assert!(!safe_secret, "{case}: the safe records redact the pattern");
        assert!(safe_non_sensitive, "{case}: non-sensitive fields stay");
        if case == "claude_exclusion" {
            assert!(invocations > 0, "the real invocation is kept in the prepared view");
        }

        // `Message` has no invocation field; test the object's own keys rather
        // than searching the whole serialization, which would reject a native
        // unknown field that merely spells the word.
        let sql_value = serde_json::to_value(&conversation.sql_projection)
            .expect("sql serialization");
        let sql_invocations = sql_value.get("invocations").is_some()
            || sql_value
                .get("messages")
                .and_then(serde_json::Value::as_array)
                .is_some_and(|messages| {
                    messages
                        .iter()
                        .any(|message| message.get("invocations").is_some())
                });
        assert!(!sql_invocations, "{case}: the SQL view invents no invocation field");

        let proof = serde_json::json!({
            "case": case,
            "records": preview.records.len(),
            "conversations": preview.conversations.len(),
            "excluded_markers": excluded_markers,
            "sql_excluded": sql_excluded,
            "sentinel_in_prepared": sentinel_in_prepared,
            "secret_in_prepared": secret_in_prepared,
            "sentinel_in_sql": sentinel_in_sql,
            "secret_in_sql": secret_in_sql,
            "safe_sentinel": safe_sentinel,
            "safe_secret": safe_secret,
            "safe_non_sensitive": safe_non_sensitive,
            "invocations": invocations,
            "sql_invocations": sql_invocations,
            "redacted_text": redacted_text,
        });
        std::fs::write(
            root.join("proof.json"),
            serde_json::to_vec(&proof).expect("proof json"),
        )
        .expect("write the child proof");
        println!(
            "SOURCE_SAFETY_PREVIEW_CHILD_SCENARIO test=p2_preview_uses_safety case={case} result=pass"
        );
    }

    fn run_p2_child(case: &str) -> serde_json::Value {
        let root = tempfile::TempDir::new().expect("synthetic child root");
        let path = root.path().to_path_buf();
        // Keep the child's stdout/stderr/proof after the parent returns: the
        // child markers live only in those files.
        std::mem::forget(root);
        let binary = std::env::current_exe().expect("the test binary's own path");
        let output = std::process::Command::new(binary)
            .arg(P2_NAME)
            .arg("--exact")
            .arg("--nocapture")
            .current_dir(&path)
            .env(CHILD_MARKER, "1")
            .env(CHILD_CASE, case)
            .env(CHILD_ROOT, &path)
            .env("CASS_REDACT_SECRETS", "0")
            .env("CODING_AGENT_SEARCH_NO_UPDATE_PROMPT", "1")
            .env("HOME", path.join("home"))
            .env("XDG_CONFIG_HOME", path.join("xdg"))
            .env("CODEX_HOME", path.join("codex"))
            .output()
            .expect("the child test run starts");
        std::fs::write(path.join("child.stdout"), &output.stdout).expect("child stdout");
        std::fs::write(path.join("child.stderr"), &output.stderr).expect("child stderr");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{case}: the child failed; stdout saved under {}",
            path.display()
        );
        assert!(
            stdout.contains(&format!("test {P2_NAME} ... ok")),
            "{case}: the child really ran the exact function"
        );
        assert!(
            stdout.contains(&format!(
                "SOURCE_SAFETY_PREVIEW_CHILD_SCENARIO test=p2_preview_uses_safety case={case} result=pass"
            )),
            "{case}: the child printed its own marker"
        );
        let proof_path = path.join("proof.json");
        let proof = std::fs::read(&proof_path).unwrap_or_else(|error| {
            panic!("{case}: the child wrote no proof at {}: {error}", proof_path.display())
        });
        serde_json::from_slice(&proof).expect("the child proof is JSON")
    }

    #[test]
    fn p2_preview_uses_safety() {
        if let Some((case, root)) = child_case() {
            p2_child(&case, &root);
            return;
        }
        for (case, records) in [("claude_exclusion", 2u64), ("codex_exclusion", 3u64)] {
            let proof = run_p2_child(case);
            assert_eq!(proof["case"].as_str(), Some(case));
            assert_eq!(proof["records"].as_u64(), Some(records), "{case}: record count");
            assert_eq!(proof["conversations"].as_u64(), Some(1), "{case}: conversation count");
            assert_eq!(proof["excluded_markers"].as_u64(), Some(1), "{case}: one exclusion");
            assert_eq!(proof["sql_excluded"].as_u64(), Some(1), "{case}: SQL keeps the exclusion");
            assert_eq!(proof["sentinel_in_prepared"].as_bool(), Some(false), "{case}: prepared is clear");
            assert_eq!(proof["secret_in_prepared"].as_bool(), Some(true), "{case}: prepared keeps the pattern");
            assert_eq!(proof["sentinel_in_sql"].as_bool(), Some(false), "{case}: SQL is clear");
            assert_eq!(proof["secret_in_sql"].as_bool(), Some(false), "{case}: SQL is redacted");
            assert_eq!(proof["safe_sentinel"].as_bool(), Some(false), "{case}: safe records are clear");
            assert_eq!(proof["safe_secret"].as_bool(), Some(false), "{case}: safe records are redacted");
            assert_eq!(proof["safe_non_sensitive"].as_bool(), Some(true), "{case}: non-sensitive fields stay");
            assert_eq!(proof["redacted_text"].as_bool(), Some(true), "{case}: the redaction marker is real");
            assert_eq!(proof["sql_invocations"].as_bool(), Some(false), "{case}: SQL invents no invocation field");
            if case == "claude_exclusion" {
                assert!(
                    proof["invocations"].as_u64().unwrap_or(0) > 0,
                    "the real invocation is kept"
                );
            }
            mark("p2_preview_uses_safety", case);
        }
    }

    // ------------------------------------------------------------------
    // p3: the four material faults.
    // ------------------------------------------------------------------

    fn p3_case(case: &str) {
        let fixture = native_fixture("claude_jsonl");
        let job = prepare(&fixture);
        let first = match preview_source_input_safety(&job) {
            Ok(preview) => preview,
            Err(error) => panic!("{case}: the control preview failed: {error}"),
        };
        assert!(!first.records.is_empty(), "{case}: the control preview is non-empty");

        match case {
            "fixed_changed" => {
                std::fs::write(&fixture.copy, b"# changed after the preview\n")
                    .expect("rewrite the fixed copy");
            }
            "sealed_changed" => {
                let mut bytes = std::fs::read(&job.blob_path).expect("read the sealed blob");
                let last = bytes.len() - 1;
                bytes[last] ^= 0x01;
                std::fs::write(&job.blob_path, &bytes).expect("rewrite the sealed blob");
            }
            "sealed_missing" => {
                std::fs::remove_file(&job.blob_path).expect("remove the sealed blob");
            }
            "fixed_and_sealed_missing" => {
                std::fs::write(&fixture.copy, b"# changed after the preview\n")
                    .expect("rewrite the fixed copy");
                std::fs::remove_file(&job.blob_path).expect("remove the sealed blob");
            }
            other => panic!("unknown p3 case {other}"),
        }

        match preview_source_input_safety(&job) {
            Err(SourceIngestError::Config { .. }) if case.starts_with("fixed") => {}
            Err(SourceIngestError::Capture { .. }) if case.starts_with("sealed") => {}
            Err(other) => panic!("{case}: unexpected error: {other:?}"),
            Ok(_) => panic!("{case}: the preview accepted changed material"),
        }
        let db_path = fixture.data_dir.join("agent_search.db");
        assert!(!db_path.exists(), "{case}: a refusal creates no database");
    }

    #[test]
    fn p3_preview_rechecks_material() {
        for case in [
            "fixed_changed",
            "sealed_changed",
            "sealed_missing",
            "fixed_and_sealed_missing",
        ] {
            p3_case(case);
            mark("p3_preview_rechecks_material", case);
        }
    }

    // ------------------------------------------------------------------
    // p4: a legal empty input.
    // ------------------------------------------------------------------

    #[test]
    fn p4_preview_accepts_zero() {
        let fixture = fixture("claude", "jsonl", b"");
        let job = prepare(&fixture);
        let preview = match preview_source_input_safety(&job) {
            Ok(preview) => preview,
            Err(error) => panic!("the empty input preview failed: {error}"),
        };
        assert_eq!(preview.records.len(), 0, "zero records");
        assert_eq!(preview.conversations.len(), 0, "zero conversations");
        assert_eq!(preview.parse_failed, 0, "zero parse failures");
        assert_eq!(preview.diagnostics, 0, "zero diagnostics");
        assert!(
            !fixture.data_dir.join("agent_search.db").exists(),
            "the empty preview creates no database"
        );
        mark("p4_preview_accepts_zero", "empty_jsonl");
    }

    // ------------------------------------------------------------------
    // p5: the real commit still rechecks after a preview.
    // ------------------------------------------------------------------

    #[test]
    fn p5_commit_rechecks_after_preview() {
        let fixture = native_fixture("claude_jsonl");
        let job = prepare(&fixture);
        let db_path = fixture.data_dir.join("agent_search.db");
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path)
            .expect("open the temporary database");

        // A real completed input first: the frozen non-empty pre-state whose
        // facts and activation receipt the refused commit must not rewrite.
        let first = commit_source_input(&storage, &job)
            .expect("the pre-state commit succeeds");
        assert!(first.outcome.is_success(), "the pre-state input completes");
        let complete: i64 = storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM source_inputs WHERE state = 'complete'",
                &[],
                |row| row.get_typed(0),
            )
            .expect("count completed inputs");
        assert_eq!(complete, 1, "the pre-state input is really complete");
        let activations: i64 = storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt
                 WHERE operation = ?1 AND state = 'committed'",
                &[crate::storage::api::Value::Text(
                    source_facts::SOURCE_ACTIVATION_OPERATION.to_string(),
                )],
                |row| row.get_typed(0),
            )
            .expect("count activation receipts");
        assert!(
            activations > 0,
            "the pre-state carries a real activation receipt"
        );
        let before = fact_snapshot(&storage);
        assert!(
            before
                .0
                .iter()
                .any(|(table, rows)| table == "messages" && !rows.is_empty()),
            "the snapshot is non-empty before the preview"
        );

        match preview_source_input_safety(&job) {
            Ok(preview) => assert!(!preview.records.is_empty(), "the control preview is non-empty"),
            Err(error) => panic!("the control preview failed: {error}"),
        }

        std::fs::write(&fixture.copy, b"# changed after the preview\n")
            .expect("rewrite the fixed copy");
        match commit_source_input(&storage, &job) {
            Err(SourceIngestError::Config { .. }) => {}
            Err(other) => panic!("the commit reported an unexpected error: {other:?}"),
            Ok(_) => panic!("the commit accepted changed material after a preview"),
        }
        let after = fact_snapshot(&storage);
        assert_eq!(
            before, after,
            "the refused commit leaves every typed business column and the receipt unchanged"
        );

        // Re-open the materialized database instead of trusting the handle that
        // attempted the refused commit.
        drop(storage);
        let reopened = crate::storage::sqlite::FrankenStorage::open_readonly(&db_path)
            .expect("reopen the temporary database read-only");
        let reopened_snapshot = fact_snapshot(&reopened);
        assert_eq!(
            before, reopened_snapshot,
            "the reopened database still carries the same facts and receipt"
        );
        mark("p5_commit_rechecks_after_preview", "changed_after_preview");
    }

    // ------------------------------------------------------------------
    // p6: failed records and the component-level two-conversation view.
    // ------------------------------------------------------------------

    fn p6_failed_record() {
        let fixture = fixture("claude", "jsonl", &failed_record_body());
        let mut job = prepare(&fixture);
        assert_eq!(job.records.len(), 3, "two normal records and one bad record");
        job.records[0].diagnostics.push(fad::SourceDiagnostic::code(
            "S40_SYNTHETIC_DIAG_A",
        ));
        job.records[0].diagnostics.push(fad::SourceDiagnostic::code(
            "S40_SYNTHETIC_DIAG_B",
        ));
        let expected_diagnostics: u64 = job
            .records
            .iter()
            .map(|record| record.diagnostics.len() as u64)
            .sum();

        let preview = match preview_source_input_safety(&job) {
            Ok(preview) => preview,
            Err(error) => panic!("the failed-record preview failed: {error}"),
        };
        assert_eq!(preview.parse_failed, 1, "the bad frame is the only parse failure");
        assert_eq!(preview.diagnostics, expected_diagnostics, "diagnostics are the real sum");
        assert!(preview.diagnostics >= 3, "the bad frame and both markers are counted");
        assert_ne!(preview.diagnostics, preview.parse_failed, "diagnostics are not parse count");

        let mut failed = 0usize;
        for record in &preview.records {
            match record.parse_state() {
                source_facts::ParseState::ParseFailed => {
                    failed += 1;
                    assert_eq!(
                        record.retention_state(),
                        source_facts::RetentionState::PayloadAbsent,
                        "a failed frame carries no payload"
                    );
                    assert!(
                        record.diagnostics().is_some_and(|items| !items.is_empty()),
                        "the bad frame keeps its own diagnostic"
                    );
                }
                source_facts::ParseState::Parsed => {
                    assert_eq!(
                        record.retention_state(),
                        source_facts::RetentionState::PayloadPresent,
                        "a normal frame carries its payload"
                    );
                }
                source_facts::ParseState::Pending => panic!("a preview record is never pending"),
            }
            assert_eq!(
                record.safety_state(),
                source_facts::SafetyState::Preserved,
                "the shared pass preserves every record"
            );
        }
        let shared = match verify_and_judge_source_input(&job) {
            Ok(passed) => passed,
            Err(error) => panic!("the failed-record shared pass failed: {error}"),
        };
        assert_eq!(
            preview.diagnostics,
            shared.staged.diagnostics,
            "the preview count is the shared pass count"
        );
        for (idx, (record, oracle)) in preview
            .records
            .iter()
            .zip(shared.staged.records.iter())
            .enumerate()
        {
            assert_eq!(
                diagnostics_signature(record.diagnostics()),
                diagnostics_signature(oracle.diagnostics()),
                "record {idx}: the diagnostics match the shared pass"
            );
            for diagnostic in record.diagnostics().unwrap_or(&[]) {
                assert_eq!(
                    diagnostic.detail, None,
                    "record {idx}: the safe filter drops the detail"
                );
                assert_eq!(
                    diagnostic.offset, None,
                    "record {idx}: the safe filter drops the offset"
                );
                assert_eq!(
                    diagnostic.position, None,
                    "record {idx}: the safe filter drops the position"
                );
            }
        }
        let first_codes: Vec<&str> = preview.records[0]
            .diagnostics()
            .unwrap_or(&[])
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        for expected in ["S40_SYNTHETIC_DIAG_A", "S40_SYNTHETIC_DIAG_B"] {
            assert!(
                first_codes.contains(&expected),
                "the injected code {expected} is reported on the first normal record"
            );
        }
        let bad_index = preview
            .records
            .iter()
            .position(|record| record.parse_state() == source_facts::ParseState::ParseFailed)
            .expect("one bad frame");
        let bad_codes: Vec<&str> = preview.records[bad_index]
            .diagnostics()
            .unwrap_or(&[])
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        assert!(
            !bad_codes.is_empty(),
            "the bad frame keeps its own diagnostic code"
        );
        let shared_bad_codes: Vec<&str> = shared.staged.records[bad_index]
            .diagnostics()
            .unwrap_or(&[])
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        assert_eq!(
            bad_codes, shared_bad_codes,
            "the bad frame's code set is the shared pass's set"
        );
        assert_eq!(failed, 1, "exactly one failed frame");
    }

    fn split_claims(
        claims: Vec<fad::SourceMappingClaim>,
    ) -> (Vec<fad::SourceMappingClaim>, Vec<fad::SourceMappingClaim>) {
        let mut first = Vec::new();
        let mut second = Vec::new();
        for claim in claims {
            let mut claim = claim;
            match claim.final_message_idx {
                Some(0) => {
                    claim.conversation_ordinal = Some(41);
                    claim.final_message_idx = Some(0);
                    first.push(claim);
                }
                Some(1) => {
                    claim.conversation_ordinal = Some(7);
                    claim.final_message_idx = Some(0);
                    second.push(claim);
                }
                other => panic!("the fixture carries an unexpected claim index: {other:?}"),
            }
        }
        (first, second)
    }

    fn p6_two_conversations() {
        let fixture = native_fixture("claude_jsonl");
        let mut job = prepare(&fixture);
        assert_eq!(job.conversations.len(), 1, "the native input is one conversation");
        assert_eq!(job.conversations[0].conversation.messages.len(), 2, "two messages");

        for record in job.records.iter_mut() {
            for claim in record.claims.iter_mut() {
                match claim.final_message_idx {
                    Some(0) => {
                        claim.conversation_ordinal = Some(41);
                        claim.final_message_idx = Some(0);
                    }
                    Some(1) => {
                        claim.conversation_ordinal = Some(7);
                        claim.final_message_idx = Some(0);
                    }
                    other => panic!("the fixture carries an unexpected claim index: {other:?}"),
                }
            }
        }

        let original = job.conversations.remove(0);
        let mut first_conversation = original.conversation.clone();
        let mut second_conversation = original.conversation.clone();
        second_conversation.messages = vec![first_conversation.messages[1].clone()];
        first_conversation.messages.truncate(1);
        first_conversation.external_id = Some("preview-multi-41".to_string());
        second_conversation.external_id = Some("preview-multi-7".to_string());
        let (first_claims, second_claims) = split_claims(original.claims);
        job.conversations = vec![
            Pass1Conversation {
                ordinal: 41,
                conversation: first_conversation,
                claims: first_claims,
            },
            Pass1Conversation {
                ordinal: 7,
                conversation: second_conversation,
                claims: second_claims,
            },
        ];

        let preview = match preview_source_input_safety(&job) {
            Ok(preview) => preview,
            Err(error) => panic!("the component view preview failed: {error}"),
        };
        assert_eq!(preview.conversations.len(), 2, "exactly two component conversations");
        assert_eq!(preview.conversations[0].ordinal, 41, "the declared order is kept");
        assert_eq!(preview.conversations[1].ordinal, 7, "the declared order is kept");
        assert_eq!(
            preview.conversations[0].prepared.conv.messages[0].content,
            QUESTION,
            "the first body stays with ordinal 41"
        );
        assert_eq!(
            preview.conversations[1].prepared.conv.messages[0].content,
            ANSWER,
            "the second body stays with ordinal 7"
        );
        assert_eq!(
            preview.conversations[0].sql_projection.messages[0].content,
            QUESTION,
            "the first SQL projection matches"
        );
        assert_eq!(
            preview.conversations[1].sql_projection.messages[0].content,
            ANSWER,
            "the second SQL projection matches"
        );
        assert_ne!(
            preview.conversations[0].sql_projection.external_id,
            preview.conversations[1].sql_projection.external_id,
            "the component conversations carry distinct identities"
        );
        assert_eq!(
            job.conversations.len(),
            2,
            "the preview leaves the component job unchanged"
        );
    }

    #[test]
    fn p6_preview_keeps_metadata() {
        p6_failed_record();
        mark("p6_preview_keeps_metadata", "failed_record");
        p6_two_conversations();
        mark("p6_preview_keeps_metadata", "two_conversations");
    }
}

// ===========================================================================
// Task29 · private unit matrices (p29_03, p29_04)
//
// Every expected value is computed here from the controlled payload literal,
// the declaration and the fixed safety copy before the candidate factory runs.
// A returned job is never used to build its own expectation.
// ===========================================================================

#[cfg(test)]
mod restore_source_job_tests {
    use super::*;
    use crate::phase3_restore::SourceBindingMaterial;
    use crate::phase3_restore::source_contexts::{
        RestoreSourceContextDeclaration, RestoreSourceContextOrigin,
    };
    use crate::raw_mirror::{
        RAW_MIRROR_LOCAL_IDENTITY_HOST, RawMirrorCaptureInput, RawMirrorCaptureRecord,
        RawMirrorSessionIdentity, capture_source_file_with_identity,
    };
    use crate::storage::source_facts::{CanonicalTuple, context_digest};
    use franken_agent_detection::SourceInputRole;

    const FIXED_SAFETY_UTF8: &str = "memory_files = []\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n";
    const WRONG_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    static CLAUDE_ONE: &[u8] = br#"{"type":"user","uuid":"C44-U","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C44 question"}}
"#;
    static CLAUDE_DOCUMENT: &[u8] = br#"{
  "cwd": "/synthetic/c44-project",
  "sessionId": "C44-CLAUDE",
  "version": "2.0.37",
  "messages": [
    {
      "role": "user",
      "content": "C44 question",
      "timestamp": "2026-01-01T00:00:00.000Z"
    },
    {
      "role": "assistant",
      "content": [
        {
          "type": "text",
          "text": "C44 answer"
        }
      ],
      "timestamp": "2026-01-01T00:00:01.000Z"
    }
  ]
}
"#;
    static CODEX_JSONL: &[u8] = br#"{"timestamp":"2026-01-01T00:00:00.000Z","type":"session_meta","payload":{"id":"C44-CODEX","cwd":"/synthetic/c44-project","cli_version":"0.42.0"}}
{"timestamp":"2026-01-01T00:00:01.000Z","type":"response_item","payload":{"type":"message","id":"C44-U","role":"user","content":[{"type":"input_text","text":"C44 question"}]}}
{"timestamp":"2026-01-01T00:00:02.000Z","type":"response_item","payload":{"type":"message","id":"C44-A","role":"assistant","content":[{"type":"output_text","text":"C44 answer"}]}}
"#;
    static CODEX_DOCUMENT: &[u8] = br#"{
  "session": {
    "id": "C44-CODEX",
    "cwd": "/synthetic/c44-project",
    "cli_version": "0.42.0"
  },
  "items": [
    {
      "type": "message",
      "role": "user",
      "content": [
        {
          "type": "input_text",
          "text": "C44 question"
        }
      ],
      "timestamp": "2026-01-01T00:00:00.000Z"
    },
    {
      "type": "message",
      "role": "assistant",
      "content": [
        {
          "type": "output_text",
          "text": "C44 answer"
        }
      ],
      "timestamp": "2026-01-01T00:00:01.000Z"
    }
  ]
}
"#;
    static EMPTY_JSONL: &[u8] = b"";
    static BLANK_JSONL: &[u8] = b"\n \t\n";
    static ARRAY_ZERO: &[u8] = b"[]\n";

    struct Fixture {
        payload: &'static [u8],
        sha: &'static str,
        provider: &'static str,
        connector: &'static str,
        logical: &'static str,
        records: u64,
        conversations: usize,
        blank_lines: u64,
    }

    fn fixture(name: &str) -> Fixture {
        match name {
            "claude_one" => Fixture {
                payload: CLAUDE_ONE,
                sha: "6f202da269cbdc40d7ac4b7fc204cf3a119b09e39b6e034face1bf5316686639",
                provider: "claude",
                connector: "claude_code",
                logical: ".claude/projects/C29-ws/session.jsonl",
                records: 1,
                conversations: 1,
                blank_lines: 0,
            },
            "claude_document" => Fixture {
                payload: CLAUDE_DOCUMENT,
                sha: "2fdf8eb31971bfa0603cb64dd6d8f4305c0463504e5447266df72411bb0a2118",
                provider: "claude",
                connector: "claude_code",
                logical: ".claude/projects/C29-ws/session.json",
                records: 1,
                conversations: 1,
                blank_lines: 0,
            },
            "codex_jsonl" => Fixture {
                payload: CODEX_JSONL,
                sha: "d50dd595f1a3a3111fffc9bdb0eff1059826071ab4164a6fc878b284b7fad3c6",
                provider: "codex",
                connector: "codex",
                logical: ".codex/sessions/2026/08/rollout-c29.jsonl",
                records: 3,
                conversations: 1,
                blank_lines: 0,
            },
            "codex_document" => Fixture {
                payload: CODEX_DOCUMENT,
                sha: "b1f4f4c63f2a33b69c518c6fcab467b2d627e8df2843a7c2774f080177a01eec",
                provider: "codex",
                connector: "codex",
                logical: ".codex/sessions/2026/08/rollout-c29.json",
                records: 1,
                conversations: 1,
                blank_lines: 0,
            },
            "empty_jsonl" => Fixture {
                payload: EMPTY_JSONL,
                sha: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                provider: "claude",
                connector: "claude_code",
                logical: ".claude/projects/C29-ws/empty.jsonl",
                records: 0,
                conversations: 0,
                blank_lines: 0,
            },
            "blank_jsonl" => Fixture {
                payload: BLANK_JSONL,
                sha: "499874d2d7401738884f105a329bd7f7a1919826deeff536eedfc90db95d3b35",
                provider: "claude",
                connector: "claude_code",
                logical: ".claude/projects/C29-ws/blank.jsonl",
                records: 0,
                conversations: 0,
                blank_lines: 2,
            },
            "array_zero" => Fixture {
                payload: ARRAY_ZERO,
                sha: "37517e5f3dc66819f61f5a7bb8ace1921282415f10551d2defa5c3eb0985b570",
                provider: "claude",
                connector: "claude_code",
                logical: ".claude/projects/C29-ws/array-zero.jsonl",
                records: 1,
                conversations: 0,
                blank_lines: 0,
            },
            other => panic!("unknown fixture {other}"),
        }
    }

    fn set_unique_mtime(path: &Path) {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(1);
        let sequence = SEQ.fetch_add(1, Ordering::Relaxed);
        let stamp =
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000 + sequence);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open the fixture for mtime");
        file.set_modified(stamp)
            .expect("set a unique fixture mtime");
    }

    struct Bench {
        _tmp: tempfile::TempDir,
        data_dir: PathBuf,
        live_path: PathBuf,
        fixed_path: PathBuf,
        safety: Arc<FixedSafetyConfig>,
        capture: RawMirrorCaptureRecord,
        declaration: RestoreSourceContextDeclaration,
        expected: SourceBindingMaterial,
        fixture: Fixture,
    }

    fn independent_binding(
        safety: &FixedSafetyConfig,
        declaration: &RestoreSourceContextDeclaration,
        fixture: &Fixture,
    ) -> SourceBindingMaterial {
        let fad_connector = fad_connector_name(fixture.connector);
        let effective = serde_json::json!({
            "schema": "cass.source-parser-context/1",
            "connector": &fad_connector,
            "roots": [{
                "path": declaration.scan_root,
                "origin": {
                    "kind": declaration.origin.kind,
                    "host": declaration.origin.host,
                    "source_version": declaration.origin.source_version,
                },
                "platform": declaration.platform,
                "workspace_rewrites": declaration.workspace_rewrites,
            }],
            "role": declaration.role,
        });
        let profile =
            SourceProfile::assemble(safety, &effective).expect("assemble the independent profile");
        let wire = serde_json::json!({
            "schema": "cass.source-parser-context/1",
            "connector": &fad_connector,
            "discovery_roots": [declaration.scan_root],
            "since_ts": null,
            "relative_locator": declaration.relative_locator,
            "role": declaration.role,
            "origin": {
                "kind": declaration.origin.kind,
                "host": declaration.origin.host,
                "source_version": declaration.origin.source_version,
            },
            "platform": declaration.platform,
            "workspace_rewrites": declaration.workspace_rewrites,
            "effective_config_summary": {
                "effective_digest": profile.effective_config_digest,
            },
        });
        let lossless = fad::LosslessSourceValue::parse(
            &serde_json::to_vec(&wire).expect("encode the manual context"),
        )
        .expect("parse the manual context");
        let expected_context_digest = context_digest(&lossless)
            .expect("digest the manual context")
            .hex();
        let platform_text = declaration.platform.map(|platform| platform.to_string());
        let tuple = [
            Some("cass.source-input/2"),
            Some(declaration.identity_namespace.as_str()),
            Some(declaration.origin.source_id.as_str()),
            Some(fad_connector.as_str()),
            Some(declaration.scan_root.as_str()),
            Some(declaration.relative_locator.as_str()),
            Some(declaration.role.as_str()),
            Some(declaration.origin.kind.as_str()),
            declaration.origin.host.as_deref(),
            declaration.origin.source_version.as_deref(),
            platform_text.as_deref(),
            Some(expected_context_digest.as_str()),
            Some(fixture.sha),
            Some(profile.normalizer_id.as_str()),
            Some(profile.safety_contract_id.as_str()),
        ];
        let mut writer = CanonicalTuple::new();
        for item in &tuple {
            writer.opt_str(*item);
        }
        SourceBindingMaterial {
            declaration: declaration.clone(),
            context_digest: expected_context_digest,
            sealed_sha256: fixture.sha.to_string(),
            byte_len: u64::try_from(fixture.payload.len()).expect("payload length"),
            normalizer_id: profile.normalizer_id,
            safety_contract_id: profile.safety_contract_id,
            input_key: writer.finish_sha().hex(),
        }
    }

    fn bench(name: &str) -> Bench {
        let fixture = fixture(name);
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let fixed_path = tmp.path().join("fixed-safety.toml");
        std::fs::write(&fixed_path, FIXED_SAFETY_UTF8).expect("write the fixed copy");
        let safety = Arc::new(load_fixed_safety_config(&fixed_path).expect("load the fixed copy"));
        let live_path = tmp.path().join("home").join(fixture.logical);
        std::fs::create_dir_all(live_path.parent().expect("live parent"))
            .expect("create the live parent");
        std::fs::write(&live_path, fixture.payload).expect("write the payload");
        set_unique_mtime(&live_path);
        let data_dir = tmp.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let capture = capture_source_file_with_identity(
            RawMirrorCaptureInput {
                data_dir: &data_dir,
                provider: fixture.provider,
                source_id: "local",
                origin_kind: "local",
                origin_host: None,
                source_path: &live_path,
                db_links: &[],
            },
            RawMirrorSessionIdentity {
                identity_host: RAW_MIRROR_LOCAL_IDENTITY_HOST,
                external_id: None,
            },
        )
        .expect("capture the fixture");
        let declaration = RestoreSourceContextDeclaration {
            manifest_id: capture.manifest_id.clone(),
            identity_namespace: "C29_NAMESPACE".to_string(),
            connector: fixture.connector.to_string(),
            scan_root: live_path
                .parent()
                .expect("live parent")
                .to_string_lossy()
                .into_owned(),
            relative_locator: live_path
                .file_name()
                .expect("live name")
                .to_string_lossy()
                .into_owned(),
            role: SourceInputRole::PrimarySessionLog,
            origin: RestoreSourceContextOrigin {
                source_id: "local".to_string(),
                kind: fad::types::SourceKind::Local,
                host: None,
                source_version: None,
            },
            platform: None,
            workspace_rewrites: Vec::new(),
        };
        let expected = independent_binding(&safety, &declaration, &fixture);
        Bench {
            _tmp: tmp,
            data_dir,
            live_path,
            fixed_path,
            safety,
            capture,
            declaration,
            expected,
            fixture,
        }
    }

    fn mirror_digest(data_dir: &Path) -> String {
        fn walk(root: &Path, base: &Path, out: &mut Vec<(String, String)>) {
            let mut entries: Vec<PathBuf> = std::fs::read_dir(root)
                .expect("read the mirror directory")
                .map(|entry| entry.expect("read entry").path())
                .collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    walk(&path, base, out);
                } else {
                    let bytes = std::fs::read(&path).expect("read the mirror file");
                    out.push((
                        path.strip_prefix(base)
                            .expect("inside the mirror")
                            .to_string_lossy()
                            .into_owned(),
                        Sha256Digest::of(&bytes).hex(),
                    ));
                }
            }
        }
        let root = data_dir.join("raw-mirror");
        let mut out = Vec::new();
        if root.exists() {
            walk(&root, &root, &mut out);
        }
        out.sort();
        out.into_iter()
            .map(|(path, digest)| format!("{path}={digest}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn blob_path(bench: &Bench) -> PathBuf {
        let view = crate::raw_mirror::manifest_views(&bench.data_dir)
            .expect("read the manifest views")
            .into_iter()
            .find(|view| view.manifest_id == bench.capture.manifest_id)
            .expect("the captured manifest view");
        bench
            .data_dir
            .join("raw-mirror")
            .join("v1")
            .join(&view.blob_relative_path)
    }

    fn assert_job_binding(job: &SourceInputJob, bench: &Bench) {
        let expected = &bench.expected;
        let tuple = job.input.identity_tuple();
        let expected_connector = fad_connector_name(bench.fixture.connector);
        assert_eq!(
            tuple.get(1).cloned().flatten().as_deref(),
            Some("C29_NAMESPACE"),
            "identity namespace"
        );
        assert_eq!(
            tuple.get(2).cloned().flatten().as_deref(),
            Some("local"),
            "source id"
        );
        assert_eq!(
            tuple.get(3).cloned().flatten().as_deref(),
            Some(expected_connector.as_str()),
            "connector"
        );
        assert_eq!(
            tuple.get(4).cloned().flatten().as_deref(),
            Some(bench.declaration.scan_root.as_str()),
            "scan root"
        );
        assert_eq!(
            tuple.get(5).cloned().flatten().as_deref(),
            Some(bench.declaration.relative_locator.as_str()),
            "relative locator"
        );
        assert_eq!(
            tuple.get(6).cloned().flatten().as_deref(),
            Some(bench.declaration.role.as_str()),
            "role"
        );
        assert_eq!(
            tuple.get(7).cloned().flatten().as_deref(),
            Some(bench.declaration.origin.kind.as_str()),
            "origin kind"
        );
        assert_eq!(
            tuple.get(11).cloned().flatten(),
            Some(expected.context_digest.clone()),
            "context digest"
        );
        assert_eq!(
            tuple.get(12).cloned().flatten(),
            Some(expected.sealed_sha256.clone()),
            "sealed sha256"
        );
        assert_eq!(
            tuple.get(13).cloned().flatten(),
            Some(expected.normalizer_id.clone()),
            "normalizer id"
        );
        assert_eq!(
            tuple.get(14).cloned().flatten(),
            Some(expected.safety_contract_id.clone()),
            "safety contract id"
        );
        assert_eq!(
            job.input.manifest().sealed_sha256().hex(),
            expected.sealed_sha256,
            "manifest sealed sha256"
        );
        assert_eq!(
            job.input.manifest().byte_len(),
            expected.byte_len,
            "manifest byte length"
        );
        assert_eq!(
            job.normalizer_id, expected.normalizer_id,
            "job normalizer id"
        );
        assert_eq!(
            job.safety_contract_id, expected.safety_contract_id,
            "job safety contract id"
        );
        assert_eq!(job.input.input_key().hex(), expected.input_key, "input key");
        assert_eq!(
            job.records.len(),
            usize::try_from(bench.fixture.records).expect("record count"),
            "records"
        );
        assert_eq!(
            job.conversations.len(),
            bench.fixture.conversations,
            "conversations"
        );
        assert_eq!(
            job.finish.blank_lines, bench.fixture.blank_lines,
            "connector finish blank lines"
        );
        assert_eq!(
            job.input.expected_blank_lines(),
            bench.fixture.blank_lines,
            "manifest blank lines"
        );
        assert_eq!(
            job.input.expected_records(),
            bench.fixture.records,
            "manifest records"
        );
    }

    #[test]
    fn p29_03_job_binding_and_readonly() {
        let cases = [
            ("claude-jsonl", "claude_one"),
            ("claude-document", "claude_document"),
            ("codex-jsonl", "codex_jsonl"),
            ("codex-document", "codex_document"),
            ("empty-jsonl", "empty_jsonl"),
            ("blank-jsonl", "blank_jsonl"),
            ("nonempty-zero-message", "array_zero"),
            ("live-replaced", "claude_one"),
            ("live-deleted", "codex_jsonl"),
            ("relocated-copy-identity", "claude_one"),
        ];
        for (row, fixture_name) in cases {
            let bench = bench(fixture_name);
            let before_mirror = mirror_digest(&bench.data_dir);
            let before_fixed = std::fs::read(&bench.fixed_path).expect("read the fixed copy");
            let before_live = std::fs::read(&bench.live_path).expect("read the live source");
            let safety = match row {
                "live-replaced" => {
                    std::fs::write(
                        &bench.live_path,
                        br#"{"type":"user","uuid":"C29-LIVE","timestamp":"2026-01-01T00:00:00.000Z","message":{"role":"user","content":"C29 live replacement"}}
"#,
                    )
                    .expect("replace the live source");
                    Arc::clone(&bench.safety)
                }
                "live-deleted" => {
                    std::fs::remove_file(&bench.live_path).expect("remove the live source");
                    Arc::clone(&bench.safety)
                }
                "relocated-copy-identity" => {
                    let relocated = bench._tmp.path().join("relocated-fixed-safety.toml");
                    std::fs::rename(&bench.fixed_path, &relocated).expect("move the fixed copy");
                    let verified = bench
                        .safety
                        .config()
                        .verify()
                        .expect("the original fixed copy verifies");
                    Arc::new(
                        load_restore_fixed_safety(
                            &relocated,
                            bench.safety.config_source_identity(),
                            &verified.fixed_config_sha256(),
                            &verified.effective_four_arrays_sha256(),
                            &bench.safety.config().code_version,
                        )
                        .expect("the relocated copy keeps the logical identity"),
                    )
                }
                _ => Arc::clone(&bench.safety),
            };
            let job = prepare_restore_source_job(
                &bench.data_dir,
                &bench.capture,
                &bench.expected,
                safety,
            )
            .unwrap_or_else(|error| panic!("row {row}: the factory refused the job: {error}"));
            assert_job_binding(&job, &bench);
            assert_eq!(
                mirror_digest(&bench.data_dir),
                before_mirror,
                "row {row}: the factory must not write the mirror"
            );
            if row != "relocated-copy-identity" {
                assert_eq!(
                    std::fs::read(&bench.fixed_path).expect("read the fixed copy again"),
                    before_fixed,
                    "row {row}: the factory must not write the fixed copy"
                );
            }
            if row != "live-replaced" && row != "live-deleted" {
                assert_eq!(
                    std::fs::read(&bench.live_path).expect("read the live source again"),
                    before_live,
                    "row {row}: the factory must not write the live source directory"
                );
            }
            assert!(
                !bench.data_dir.join("candidate.sqlite").exists(),
                "row {row}: the factory must not create a database"
            );
            println!("R29_UNIT group=p29_03_job_binding_and_readonly row={row} result=pass");
        }
    }

    fn config_detail(error: SourceIngestError) -> String {
        match error {
            SourceIngestError::Config { detail } => detail,
            other => panic!("expected one Config refusal, got {other:?}"),
        }
    }

    #[test]
    fn p29_04_job_material_refusal() {
        let cases = [
            "binding-declaration",
            "binding-context_digest",
            "binding-sealed_sha256",
            "binding-byte_len",
            "binding-normalizer_id",
            "binding-safety_contract_id",
            "binding-input_key",
            "blob-truncated",
            "blob-equal-length-corrupt",
            "fixed-copy-missing",
            "fixed-copy-changed",
        ];
        for row in cases {
            let bench = bench("claude_one");
            let mut binding = bench.expected.clone();
            let safety = Arc::clone(&bench.safety);
            match row {
                "binding-declaration" => {
                    binding.declaration.identity_namespace = "C29_OTHER_NAMESPACE".to_string();
                }
                "binding-context_digest" => {
                    binding.context_digest = WRONG_HEX.to_string();
                }
                "binding-sealed_sha256" => {
                    binding.sealed_sha256 = WRONG_HEX.to_string();
                }
                "binding-byte_len" => {
                    binding.byte_len += 1;
                }
                "binding-normalizer_id" => {
                    binding.normalizer_id = WRONG_HEX.to_string();
                }
                "binding-safety_contract_id" => {
                    binding.safety_contract_id = WRONG_HEX.to_string();
                }
                "binding-input_key" => {
                    binding.input_key = WRONG_HEX.to_string();
                }
                "blob-truncated" => {
                    let blob = blob_path(&bench);
                    let mut bytes = std::fs::read(&blob).expect("read the sealed blob");
                    bytes.truncate(bytes.len().saturating_sub(1));
                    std::fs::write(&blob, bytes).expect("truncate the sealed blob");
                }
                "blob-equal-length-corrupt" => {
                    let blob = blob_path(&bench);
                    let mut bytes = std::fs::read(&blob).expect("read the sealed blob");
                    bytes[0] ^= 0xff;
                    std::fs::write(&blob, bytes).expect("corrupt the sealed blob");
                }
                "fixed-copy-missing" => {
                    std::fs::rename(
                        &bench.fixed_path,
                        bench._tmp.path().join("fixed-safety-moved.toml"),
                    )
                    .expect("move the fixed copy away");
                }
                "fixed-copy-changed" => {
                    std::fs::write(
                        &bench.fixed_path,
                        "memory_files = [\"C29_CHANGED_RULE.md\"]\ninjection_only_files = []\nworkspace_scoped_files = []\nproject_read_documents = []\n",
                    )
                    .expect("change the fixed copy bytes");
                }
                other => panic!("unhandled material refusal row {other}"),
            }
            let error =
                prepare_restore_source_job(&bench.data_dir, &bench.capture, &binding, safety)
                    .expect_err(&format!("row {row}: the factory must refuse"));
            assert_eq!(
                config_detail(error),
                "source_restore_material_mismatch",
                "row {row}: exact fixed detail"
            );
            println!("R29_UNIT group=p29_04_job_material_refusal row={row} result=pass");
        }
    }
}

/// The sixteen registered-ID boundary literals. Each row calls the same
/// private predicate the production safety pass calls; no second
/// implementation and no new public test seam are introduced.
#[cfg(test)]
mod id_body_conflict_tests {
    use super::*;

    fn conflict(
        fad_name: &str,
        format: SourceFormat,
        json: serde_json::Value,
        pointer: Option<&str>,
        body: &str,
    ) -> bool {
        let bytes = serde_json::to_vec(&json).expect("encode the literal node");
        let value =
            fad::LosslessSourceValue::parse(&bytes).expect("parse the literal lossless value");
        let events = structural_events_for_record(fad_name, format, &json, 0);
        let bodies = [ExcludedBody {
            element_pointer: pointer.map(str::to_string),
            body: body.to_string(),
        }];
        id_body_conflict_in_record(
            fad_name,
            format,
            &json,
            Some(&value),
            &events,
            &bodies,
        )
    }

    #[test]
    fn registered_id_conflict_boundaries() {
        let rows: Vec<(&str, bool)> = vec![
            (
                "v01-claude-uuid",
                conflict(
                    "claude_code",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "assistant",
                        "message": {"role": "assistant", "content": "ROOT_TEXT"},
                        "uuid": "ROOT_GUARD_BODY"
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v02-claude-request",
                conflict(
                    "claude_code",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "assistant",
                        "message": {"role": "assistant", "content": "ROOT_TEXT"},
                        "requestId": "ROOT_GUARD_BODY"
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v03-claude-message-id",
                conflict(
                    "claude_code",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "assistant",
                        "message": {
                            "role": "assistant",
                            "id": "ROOT_GUARD_BODY",
                            "content": "ROOT_TEXT"
                        }
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v04-claude-offrole-tool-id",
                conflict(
                    "claude_code",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "user",
                        "message": {
                            "role": "user",
                            "content": [{
                                "type": "tool_use",
                                "id": "ROOT_GUARD_BODY",
                                "name": "Read",
                                "input": {}
                            }]
                        }
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v05-codex-item-id",
                conflict(
                    "codex",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "id": "ROOT_GUARD_BODY",
                            "call_id": "ROOT_OTHER",
                            "output": "ROOT_GUARD_BODY"
                        }
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v06-codex-event-response-id",
                conflict(
                    "codex",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "event_msg",
                        "payload": {
                            "type": "tool_call",
                            "response_id": "ROOT_GUARD_BODY",
                            "call_id": "ROOT_OTHER",
                            "name": "project_read",
                            "arguments": "{}"
                        }
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v07-claude-document-element-id",
                conflict(
                    "claude_code",
                    SourceFormat::JsonDocument,
                    serde_json::json!({
                        "messages": [{
                            "uuid": "ROOT_GUARD_BODY",
                            "role": "user",
                            "content": "ROOT_GUARD_BODY"
                        }]
                    }),
                    Some("/messages/0"),
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v08-claude-document-tool-id",
                conflict(
                    "claude_code",
                    SourceFormat::JsonDocument,
                    serde_json::json!({
                        "messages": [{
                            "role": "user",
                            "content": [{
                                "type": "tool_result",
                                "tool_use_id": "ROOT_GUARD_BODY",
                                "content": "ROOT_GUARD_BODY"
                            }]
                        }]
                    }),
                    Some("/messages/0"),
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v09-codex-document-call-id",
                conflict(
                    "codex",
                    SourceFormat::JsonDocument,
                    serde_json::json!({
                        "items": [{
                            "type": "function_call_output",
                            "role": "user",
                            "call_id": "ROOT_GUARD_BODY",
                            "content": "ROOT_GUARD_BODY"
                        }]
                    }),
                    Some("/items/0"),
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v10-sibling-element-only",
                conflict(
                    "codex",
                    SourceFormat::JsonDocument,
                    serde_json::json!({
                        "items": [
                            {
                                "id": "ROOT_OTHER",
                                "role": "user",
                                "content": "ROOT_GUARD_BODY"
                            },
                            {
                                "id": "ROOT_GUARD_BODY",
                                "role": "assistant",
                                "content": "ROOT_OTHER"
                            }
                        ]
                    }),
                    Some("/items/0"),
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v11-generated-element-fallback",
                conflict(
                    "codex",
                    SourceFormat::JsonDocument,
                    serde_json::json!({
                        "items": [{"role": "user", "content": "element:0"}]
                    }),
                    Some("/items/0"),
                    "element:0",
                ),
            ),
            (
                "v12-cwd-not-id",
                conflict(
                    "codex",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "cwd": "ROOT_GUARD_BODY",
                            "call_id": "ROOT_OTHER",
                            "output": "ROOT_GUARD_BODY"
                        }
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v13-arguments-unknown-id-not-identity",
                conflict(
                    "claude_code",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "assistant",
                        "message": {
                            "role": "assistant",
                            "content": [{
                                "type": "tool_use",
                                "id": "ROOT_OTHER",
                                "name": "Read",
                                "input": {"id": "ROOT_GUARD_BODY"}
                            }]
                        }
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
            (
                "v14-redacted-literal-id",
                conflict(
                    "codex",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "[REDACTED]",
                            "output": "[REDACTED]"
                        }
                    }),
                    None,
                    "[REDACTED]",
                ),
            ),
            (
                "v15-whitespace-not-present-id",
                conflict(
                    "codex",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "response_item",
                        "payload": {
                            "type": "function_call_output",
                            "call_id": "   ",
                            "output": "   "
                        }
                    }),
                    None,
                    "   ",
                ),
            ),
            (
                "v16-duplicate-collection-values",
                conflict(
                    "claude_code",
                    SourceFormat::Jsonl,
                    serde_json::json!({
                        "type": "user",
                        "uuid": "ROOT_GUARD_BODY",
                        "message": {
                            "role": "user",
                            "content": [
                                {
                                    "type": "tool_result",
                                    "tool_use_id": "ROOT_GUARD_BODY",
                                    "content": "ROOT_GUARD_BODY"
                                },
                                {
                                    "type": "tool_result",
                                    "tool_use_id": "ROOT_OTHER",
                                    "content": "ROOT_GUARD_BODY"
                                }
                            ]
                        }
                    }),
                    None,
                    "ROOT_GUARD_BODY",
                ),
            ),
        ];

        let expected: std::collections::BTreeMap<&str, bool> = [
            ("v01-claude-uuid", true),
            ("v02-claude-request", true),
            ("v03-claude-message-id", true),
            // E2 controller erratum: a lone off-role tool_use emits no
            // RawEvent, so it has no registered ID in the frozen source set.
            ("v04-claude-offrole-tool-id", false),
            ("v05-codex-item-id", true),
            ("v06-codex-event-response-id", true),
            ("v07-claude-document-element-id", true),
            ("v08-claude-document-tool-id", true),
            ("v09-codex-document-call-id", true),
            ("v10-sibling-element-only", false),
            ("v11-generated-element-fallback", false),
            ("v12-cwd-not-id", false),
            ("v13-arguments-unknown-id-not-identity", false),
            ("v14-redacted-literal-id", true),
            ("v15-whitespace-not-present-id", false),
            ("v16-duplicate-collection-values", true),
        ]
        .into_iter()
        .collect();

        let mut failures = Vec::new();
        assert_eq!(rows.len(), 16, "all sixteen literal rows must run");
        for (label, observed) in rows {
            let want = expected[label];
            if observed != want {
                failures.push(format!("{label}: expected {want}, observed {observed}"));
            }
        }
        assert!(
            failures.is_empty(),
            "registered ID boundary rows failed:\n{}",
            failures.join("\n")
        );
    }

    /// E2 extra, separate from the 16 main rows: the same off-role tool_use
    /// block inside a message that also carries a real tool_result. The user
    /// result emits a structural event with the full block list, so the
    /// original block registry protects the off-role ID.
    #[test]
    fn e2_extra_mixed_offrole_register_boundary() {
        let observed = conflict(
            "claude_code",
            SourceFormat::Jsonl,
            serde_json::json!({
                "type": "user",
                "message": {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "ROOT_OTHER",
                            "content": "ROOT_GUARD_BODY"
                        },
                        {
                            "type": "tool_use",
                            "id": "ROOT_GUARD_BODY",
                            "name": "Read",
                            "input": {}
                        }
                    ]
                }
            }),
            None,
            "ROOT_GUARD_BODY",
        );
        assert!(
            observed,
            "the mixed user record emits a RawEvent and its off-role tool_use id is registered"
        );
    }
}
