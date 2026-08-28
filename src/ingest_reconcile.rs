//! `cass ingest reconcile` (plan v6 Stage C, Task C2): coverage and content-
//! conservation audit between a sealed `cass ingest manifest` output and a
//! new database.
//!
//! Four judgements, per plan (G4 + R3-B1):
//! 1. Forward coverage: every eligible manifest identity must exist in the DB
//!    (else `missing`).
//! 2. Reverse anti-join (R2-F5): every DB conversation must exist in the
//!    manifest (else `unexpected`) -- guards against a manifest that is
//!    itself incomplete producing a false "100% covered" forward pass.
//! 3. Root-set attestation (R2-F5, R4-B7): the manifest header's scan-root
//!    set must equal `--expected-roots` exactly.
//! 4. Content conservation (R3-B1): message_count and content_digest per
//!    session, recomputed from the DB, must match the manifest -- using the
//!    exact same `content_digest` function `ingest_manifest` uses, never a
//!    second copy of the formula.
//!
//! Exit contract (enforced by the caller in `src/lib.rs`): 0 = closed
//! (nothing in any of the four lists, root set matches); 1 = otherwise.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::ingest_manifest::{content_digest, identity_key};
use crate::storage::api::params;
use crate::storage::sqlite::FrankenStorage;

pub struct ReconcileArgs {
    pub manifest: PathBuf,
    pub db: PathBuf,
    pub expected_roots: PathBuf,
}

#[derive(Debug, Default, Serialize)]
pub struct ContentMismatch {
    pub identity_key: String,
    pub manifest_message_count: u64,
    pub db_message_count: u64,
    pub manifest_content_digest: String,
    pub db_content_digest: String,
}

#[derive(Debug, Default, Serialize)]
pub struct ReconcileReport {
    pub root_set_ok: bool,
    pub manifest_scan_roots: Vec<String>,
    pub expected_roots: Vec<String>,
    pub missing: Vec<String>,
    pub unexpected: Vec<String>,
    pub content_mismatch: Vec<ContentMismatch>,
}

impl ReconcileReport {
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.root_set_ok
            && self.missing.is_empty()
            && self.unexpected.is_empty()
            && self.content_mismatch.is_empty()
    }
}

#[derive(Deserialize)]
struct ManifestHeaderLine {
    scan_roots: Vec<String>,
}

#[derive(Deserialize)]
struct ManifestEntryLine {
    identity_key: String,
    eligible: bool,
    message_count: u64,
    content_digest: String,
}

pub fn run_reconcile(args: ReconcileArgs) -> Result<ReconcileReport> {
    let manifest_text = fs::read_to_string(&args.manifest)
        .with_context(|| format!("reading manifest {}", args.manifest.display()))?;
    let mut manifest_lines = manifest_text.lines().filter(|l| !l.trim().is_empty());

    let header_line = manifest_lines
        .next()
        .context("manifest is empty (missing root-set attestation header)")?;
    let header: ManifestHeaderLine = serde_json::from_str(header_line)
        .with_context(|| format!("manifest header line is not valid JSON: {header_line}"))?;

    let expected_roots_text = fs::read_to_string(&args.expected_roots)
        .with_context(|| format!("reading expected-roots {}", args.expected_roots.display()))?;
    let mut expected_roots: Vec<String> = expected_roots_text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    expected_roots.sort();

    let mut manifest_scan_roots = header.scan_roots.clone();
    manifest_scan_roots.sort();
    let root_set_ok = manifest_scan_roots == expected_roots;

    // Eligible-only: excluded (eligible=false) entries are a legal terminal
    // state (R4-N1) and never count toward the denominator or MISSING.
    let mut eligible_by_identity: HashMap<String, ManifestEntryLine> = HashMap::new();
    for line in manifest_lines {
        let entry: ManifestEntryLine = serde_json::from_str(line)
            .with_context(|| format!("manifest entry is not valid JSON: {line}"))?;
        if entry.eligible {
            eligible_by_identity.insert(entry.identity_key.clone(), entry);
        }
    }

    let storage = FrankenStorage::open_readonly(&args.db)
        .with_context(|| format!("opening db {}", args.db.display()))?;
    let conn = storage.raw();

    let conversations: Vec<(i64, String, Option<String>, Option<String>)> = conn
        .query_all_map(
            "SELECT c.id, a.slug, w.path, c.external_id \
             FROM conversations c \
             JOIN agents a ON a.id = c.agent_id \
             LEFT JOIN workspaces w ON w.id = c.workspace_id",
            &[],
            |row| {
                Ok((
                    row.get_typed::<i64>(0)?,
                    row.get_typed::<String>(1)?,
                    row.get_typed::<Option<String>>(2)?,
                    row.get_typed::<Option<String>>(3)?,
                ))
            },
        )
        .context("querying conversations for reconcile")?;

    let mut db_identities: HashSet<String> = HashSet::new();
    let mut content_mismatch = Vec::new();

    for (conversation_id, agent_slug, workspace, external_id) in conversations {
        let key = identity_key(
            &agent_slug,
            workspace.as_deref().unwrap_or(""),
            external_id.as_deref().unwrap_or(""),
        );
        db_identities.insert(key.clone());

        let Some(manifest_entry) = eligible_by_identity.get(&key) else {
            continue;
        };

        let contents: Vec<String> = conn
            .query_all_map(
                "SELECT content FROM messages WHERE conversation_id = ?1 ORDER BY idx",
                &params![conversation_id],
                |row| row.get_typed::<String>(0),
            )
            .with_context(|| format!("querying messages for conversation {conversation_id}"))?;
        let db_message_count = contents.len() as u64;
        let db_digest = content_digest(&contents);

        if db_message_count != manifest_entry.message_count || db_digest != manifest_entry.content_digest {
            content_mismatch.push(ContentMismatch {
                identity_key: key,
                manifest_message_count: manifest_entry.message_count,
                db_message_count,
                manifest_content_digest: manifest_entry.content_digest.clone(),
                db_content_digest: db_digest,
            });
        }
    }

    let mut missing: Vec<String> = eligible_by_identity
        .keys()
        .filter(|key| !db_identities.contains(*key))
        .cloned()
        .collect();
    missing.sort();

    let mut unexpected: Vec<String> = db_identities
        .iter()
        .filter(|key| !eligible_by_identity.contains_key(*key))
        .cloned()
        .collect();
    unexpected.sort();

    content_mismatch.sort_by(|a, b| a.identity_key.cmp(&b.identity_key));

    Ok(ReconcileReport {
        root_set_ok,
        manifest_scan_roots,
        expected_roots,
        missing,
        unexpected,
        content_mismatch,
    })
}
