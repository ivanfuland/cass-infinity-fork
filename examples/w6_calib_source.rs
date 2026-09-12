//! T5 (#127, third leg of PR6's Task 5): `w6_calib_source` builds the source
//! tree the cosine calibration ingests.
//!
//! It reads T3's frozen sample identity (`t3-121b-sample-identity.json`, whose
//! `conversations` are the sessions of the 5,000 sampled messages) and
//! materializes those sessions' raw-mirror blobs, in each connector's own
//! dot-directory layout, under a fake `HOME` (`--out`). It never re-samples:
//! `--sample` / `--seed` are accepted only to be cross-checked against the
//! values the identity document recorded, so a drifted invocation fails
//! loudly instead of quietly drawing a different population.
//!
//! **R5-B3 lands here** (control-plane review of #121a deferred it to T5). For
//! every selected conversation, before anything is written:
//!   1. the conversation exists in `--db` and its
//!      `(source_id, agent_slug, external_id, source_path)` equal the identity
//!      document's;
//!   2. at least one mirror manifest links that conversation, and the one
//!      chosen by the snapshot rule below has a blob file that exists and is a
//!      regular file;
//!   3. `blake3(blob bytes)` equals the manifest's declared `blob_blake3`;
//!   4. the layout path derived from `source_path` is the same path the
//!      manifest's own `original_path` derives (the mirror captured this
//!      session file, under a different root).
//! Any failure is listed (up to 20) and the process exits 1 **without writing
//! anything** -- the whole selection is validated before the first byte is
//! copied, so a failed run cannot leave a half-populated source tree.
//!
//! Two rules the task book's control plane fixed after the #0 report, both
//! deviations from the plan text and both recorded in the output document:
//!   - **snapshot rule (ruling 3)**: the blob is the mirror snapshot whose
//!     `db_links[].message_count` equals the conversation's message count in
//!     `--db`. A conversation with no such snapshot is *excluded*, never
//!     guessed at, and is listed under `excluded_ambiguous_multi_blob`.
//!   - **subset rule (ruling 5)**: the plan's "5,000 messages into a small v6
//!     library" would have been 1,188,057 messages / 84.5% of the copy corpus.
//!     Instead the eligible conversations are taken smallest-first until the
//!     cumulative message count reaches [`SUBSET_TARGET_MESSAGES`], then one
//!     smallest conversation is added for any of the three connector families
//!     (codex / claude_code / openclaw) still unrepresented.
//!
//! Read-only against its inputs: `--db` is opened through plain `rusqlite`
//! with `?immutable=1` and `SQLITE_OPEN_READ_ONLY` (deliberately not
//! `FrankenStorage::open_readonly`, which acquires a doctor guard that
//! `create_dir_all`s next to the database -- fatal against this repo's
//! read-only frozen `copy/`), and `--mirror` is only ever read. The blobs are
//! copied by value, never hard-linked: `copy/` shares inodes with the PR4 run
//! root, so a link would make one write in either tree visible in both.
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w6_calib_source -- --identity
//! <t3-sample-identity.json> --db <copy/agent_search.db> --mirror
//! <copy/raw-mirror/v1> --out <calib/src> --manifest <calib-sample.json>
//! [--sample N --seed S]`. Exit codes: 0 written; 1 R5-B3 gate failure (the
//! failing conversations are listed, nothing was written); 2 precondition
//! error (unreadable inputs, `--sample`/`--seed` disagreeing with the identity
//! document, an output that would collide with an input, or a target file that
//! already exists).

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use clap::Parser;
use rusqlite::{Connection, OpenFlags, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Ruling 5: the plan's "small v6 library" -- take eligible sessions
/// smallest-first until this many messages are in, so the calibration ingests
/// a corpus the size the plan meant rather than 84.5% of the copy corpus.
const SUBSET_TARGET_MESSAGES: usize = 20_000;

/// Ruling 5: the three connector families that must each be represented in
/// the selected subset (`agent_slug` up to its first `/`).
const REQUIRED_FAMILIES: [&str; 3] = ["codex", "claude_code", "openclaw"];

/// R5-B3: how many failing conversations to print before the summary line.
const FAILURE_PRINT_CAP: usize = 20;

const MANIFEST_KIND: &str = "cass_raw_session_mirror_v1";

fn open_readonly_immutable(path: &Path) -> anyhow::Result<Connection> {
    let uri = format!("file:{}?immutable=1", path.display());
    let conn = Connection::open_with_flags(uri, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)?;
    Ok(conn)
}

fn resolve_for_collision_check(p: &Path) -> PathBuf {
    if let Ok(c) = fs::canonicalize(p) {
        return c;
    }
    let Some(file_name) = p.file_name() else {
        return p.to_path_buf();
    };
    let parent = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    match fs::canonicalize(parent) {
        Ok(c) => c.join(file_name),
        Err(_) => p.to_path_buf(),
    }
}

/// The identity of the inode a write would truncate (`fs::metadata` follows
/// symlinks, which is what a write hits).
fn same_file(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::metadata(a), fs::metadata(b)) {
        (Ok(ma), Ok(mb)) => ma.dev() == mb.dev() && ma.ino() == mb.ino(),
        _ => false,
    }
}

/// Any file under `root` carrying this `(dev, ino)`? Catches a target that is
/// a hard link *to a mirror blob* placed outside `--mirror`, which the
/// `starts_with` containment check cannot see. A walk that cannot complete is
/// an error, never a silent "no alias" (R7-1's lesson).
fn contains_inode(root: &Path, dev: u64, ino: u64) -> anyhow::Result<bool> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).with_context(|| format!("cannot enumerate {} while checking it for hard-link aliases", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("cannot read an entry of {} while checking it for hard-link aliases", dir.display()))?;
            let md = entry.metadata().with_context(|| format!("cannot stat {} while checking it for hard-link aliases", entry.path().display()))?;
            if md.is_dir() {
                stack.push(entry.path());
            } else if md.dev() == dev && md.ino() == ino {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn refuse_output_collisions(db: &Path, mirror: &Path, out_root: &Path, manifest: &Path) -> anyhow::Result<()> {
    let db_r = resolve_for_collision_check(db);
    let mirror_r = resolve_for_collision_check(mirror);
    let out_r = resolve_for_collision_check(out_root);
    let man_r = resolve_for_collision_check(manifest);

    let mut protected: Vec<PathBuf> = vec![db_r.clone()];
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut s = db_r.as_os_str().to_owned();
        s.push(suffix);
        protected.push(PathBuf::from(s));
    }
    for (label, p) in [("--out", &out_r), ("--manifest", &man_r)] {
        if protected.iter().any(|q| same_file(q, p)) {
            anyhow::bail!("{label} {} resolves to the --db file or one of its sqlite siblings; refusing to overwrite the input database", p.display());
        }
        if p.starts_with(&mirror_r) {
            anyhow::bail!("{label} {} lies under --mirror {}; refusing to write into the source mirror", p.display(), mirror_r.display());
        }
        if let Ok(md) = fs::metadata(p) {
            if md.nlink() > 1 && contains_inode(&mirror_r, md.dev(), md.ino())? {
                anyhow::bail!("{label} {} is a hard link to a file under --mirror {}; refusing to write into the source mirror", p.display(), mirror_r.display());
            }
        }
    }
    if out_r == man_r {
        anyhow::bail!("--out and --manifest resolve to the same path {}", out_r.display());
    }
    // `--out` is a tree we populate (a directory is expected); `--manifest` is
    // one file. A directory at the manifest path, or a regular file where the
    // tree should go, is a mis-specified invocation rather than a collision.
    if let Ok(md) = fs::symlink_metadata(&out_r) {
        if md.is_symlink() {
            anyhow::bail!("--out {} is a symlink; refusing to populate a tree through it", out_r.display());
        }
        if !md.is_dir() {
            anyhow::bail!("--out {} exists and is not a directory", out_r.display());
        }
    }
    if let Ok(md) = fs::symlink_metadata(&man_r) {
        if md.is_dir() {
            anyhow::bail!("--manifest {} is a directory", man_r.display());
        }
        anyhow::bail!(
            "--manifest {} already exists; refusing to overwrite a previous selection (move it aside first)",
            man_r.display()
        );
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(name = "w6_calib_source")]
struct Cli {
    /// T3's frozen sample identity document (read, never re-derived).
    #[arg(long)]
    identity: PathBuf,
    /// The corpus database the identity document was drawn from (`copy/`),
    /// opened read-only via `?immutable=1`.
    #[arg(long)]
    db: PathBuf,
    /// The raw-mirror root itself -- the directory holding `manifests/` and
    /// `blobs/` (e.g. `copy/raw-mirror/v1`), not the data directory above it.
    #[arg(long)]
    mirror: PathBuf,
    /// The fake `HOME` to populate: each connector's own dot-directory layout
    /// is reproduced under it, so `HOME=<out> cass index` auto-discovers the
    /// sessions (see `scripts/oracle/memory_gate.sh`'s T4-F7 isolation).
    #[arg(long)]
    out: PathBuf,
    /// The selection document to write (`calib-sample.json`).
    #[arg(long)]
    manifest: PathBuf,
    /// Cross-checked against the identity document's recorded `sample_size`;
    /// this tool never draws its own sample.
    #[arg(long)]
    sample: Option<usize>,
    /// Cross-checked against the identity document's recorded `seed`.
    #[arg(long)]
    seed: Option<u64>,
}

#[derive(Deserialize)]
struct IdentityDoc {
    seed: Option<u64>,
    sample_size: usize,
    #[serde(default)]
    message_ids: Vec<i64>,
    conversations: Vec<ConvIdentity>,
}

#[derive(Deserialize, Clone)]
struct ConvIdentity {
    conversation_id: i64,
    source_id: String,
    #[serde(default)]
    agent_slug: Option<String>,
    #[serde(default)]
    external_id: Option<String>,
    source_path: String,
}

#[derive(Deserialize)]
struct ManifestDbLink {
    #[serde(default)]
    conversation_id: Option<i64>,
    #[serde(default)]
    message_count: Option<usize>,
}

#[derive(Deserialize)]
struct ManifestDoc {
    manifest_kind: String,
    blob_relative_path: String,
    blob_blake3: String,
    blob_size_bytes: u64,
    #[serde(default)]
    original_path: Option<String>,
    #[serde(default)]
    captured_at_ms: Option<i64>,
    #[serde(default)]
    db_links: Vec<ManifestDbLink>,
}

/// One mirror snapshot of one conversation.
struct Snapshot {
    manifest_id: String,
    blob_relative_path: String,
    blob_blake3: String,
    blob_size_bytes: u64,
    original_path: Option<String>,
    #[allow(dead_code)]
    captured_at_ms: Option<i64>,
    message_count: Option<usize>,
}

/// One conversation that passed every R5-B3 assertion and has a blob.
struct Candidate {
    conversation_id: i64,
    source_id: String,
    agent_slug: String,
    external_id: Option<String>,
    source_path: String,
    db_message_count: usize,
    rel_path: String,
    snapshot: Snapshot,
    blob_sha256: String,
}

#[derive(Serialize)]
struct SelectionReport {
    schema_version: u32,
    identity: String,
    db: String,
    mirror: String,
    out: String,
    seed: Option<u64>,
    sample_size: usize,
    selection_rule: String,
    snapshot_rule: String,
    target_messages: usize,
    t3_conversations_total: usize,
    eligible_conversations: usize,
    excluded_ambiguous_multi_blob: Vec<ExcludedReport>,
    selected_conversations: usize,
    selected_message_count: usize,
    target_reached: bool,
    families_selected: Vec<String>,
    t3_message_ids_total: usize,
    t3_message_ids_inside_selection: usize,
    sessions: Vec<SessionReport>,
}

#[derive(Serialize)]
struct ExcludedReport {
    conversation_id: i64,
    agent_slug: String,
    db_message_count: usize,
    link_message_counts: Vec<usize>,
}

#[derive(Serialize)]
struct SessionReport {
    conversation_id: i64,
    source_id: String,
    agent_slug: String,
    external_id: Option<String>,
    source_path: String,
    rel_path: String,
    manifest_id: String,
    blob_relative_path: String,
    blob_blake3: String,
    blob_sha256: String,
    blob_size_bytes: u64,
    db_message_count: usize,
    blob_message_count: Option<usize>,
}

/// The layout path of a session file: `source_path` from its first
/// dot-prefixed component on (`.codex/sessions/...`,
/// `.claude/projects/...`, `.openclaw/agents/<name>/sessions/...`). Returns
/// `None` when the path carries no dot component -- there is then no
/// connector root to anchor the file under, which is a hard failure, not a
/// guess.
fn layout_rel_path(source_path: &str) -> Option<String> {
    let parts: Vec<&str> = source_path.split('/').collect();
    let idx = parts.iter().position(|c| c.starts_with('.') && c.len() > 1)?;
    Some(parts[idx..].join("/"))
}

fn parse_manifests(mirror: &Path) -> anyhow::Result<HashMap<i64, Vec<Snapshot>>> {
    let dir = mirror.join("manifests");
    let md = fs::symlink_metadata(&dir).with_context(|| format!("stat {}", dir.display()))?;
    if md.file_type().is_symlink() || !md.is_dir() {
        anyhow::bail!("--mirror {} has no readable manifests/ directory (pass the raw-mirror root that holds manifests/ and blobs/, not the data directory above it)", mirror.display());
    }
    let mut by_conversation: HashMap<i64, Vec<Snapshot>> = HashMap::new();
    for entry in fs::read_dir(&dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let meta = fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        if meta.file_type().is_symlink() || !meta.is_file() {
            anyhow::bail!("refusing to read non-regular raw mirror manifest {}", path.display());
        }
        let doc: ManifestDoc = serde_json::from_slice(&fs::read(&path).with_context(|| format!("read {}", path.display()))?)
            .with_context(|| format!("parse raw mirror manifest {}", path.display()))?;
        if doc.manifest_kind != MANIFEST_KIND {
            anyhow::bail!("unexpected raw mirror manifest kind `{}` in {}", doc.manifest_kind, path.display());
        }
        let manifest_id = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_string();
        for link in &doc.db_links {
            let Some(cid) = link.conversation_id else { continue };
            by_conversation.entry(cid).or_default().push(Snapshot {
                manifest_id: manifest_id.clone(),
                blob_relative_path: doc.blob_relative_path.clone(),
                blob_blake3: doc.blob_blake3.clone(),
                blob_size_bytes: doc.blob_size_bytes,
                original_path: doc.original_path.clone(),
                captured_at_ms: doc.captured_at_ms,
                message_count: link.message_count,
            });
        }
    }
    Ok(by_conversation)
}

fn family_of(agent_slug: &str) -> &str {
    agent_slug.split('/').next().unwrap_or(agent_slug)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fail(tag: &str, conversation_id: i64, detail: String) -> String {
    format!("[{tag}] conversation {conversation_id}: {detail}")
}

fn sha256_of(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex(&hasher.finalize())
}

#[allow(clippy::too_many_lines)]
fn run(cli: &Cli) -> anyhow::Result<i32> {
    refuse_output_collisions(&cli.db, &cli.mirror, &cli.out, &cli.manifest)?;

    let identity_bytes = fs::read(&cli.identity).with_context(|| format!("read --identity {}", cli.identity.display()))?;
    let identity: IdentityDoc = serde_json::from_slice(&identity_bytes).with_context(|| format!("parse --identity {}", cli.identity.display()))?;

    // The identity document is the population; `--sample`/`--seed` exist only
    // to prove the caller meant to read the same one.
    if let Some(sample) = cli.sample {
        anyhow::ensure!(
            sample == identity.sample_size,
            "--sample {sample} disagrees with the identity document's recorded sample_size {} -- this tool reads the frozen sample and never draws its own",
            identity.sample_size
        );
    }
    if let Some(seed) = cli.seed {
        anyhow::ensure!(
            Some(seed) == identity.seed,
            "--seed {seed} disagrees with the identity document's recorded seed {:?} -- this tool reads the frozen sample and never draws its own",
            identity.seed
        );
    }

    let conn = open_readonly_immutable(&cli.db).with_context(|| format!("open --db {} read-only", cli.db.display()))?;
    let snapshots = parse_manifests(&cli.mirror)?;

    let mut failures: Vec<String> = Vec::new();
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut excluded: Vec<ExcludedReport> = Vec::new();

    for conv in &identity.conversations {
        let cid = conv.conversation_id;
        let row: Option<(String, String, Option<String>, String, usize)> = conn
            .query_row(
                "SELECT a.slug, c.source_id, c.external_id, c.source_path, \
                 (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) \
                 FROM conversations c JOIN agents a ON a.id = c.agent_id WHERE c.id = ?1",
                [cid],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)? as usize)),
            )
            .optional()
            .with_context(|| format!("read conversation {cid} from --db"))?;
        let Some((db_agent_slug, db_source_id, db_external_id, db_source_path, db_message_count)) = row else {
            failures.push(fail("identity_missing_from_db", cid, "no such conversation in --db".into()));
            continue;
        };
        let identity_agent_slug = conv.agent_slug.clone().unwrap_or_default();
        if db_source_id != conv.source_id || db_agent_slug != identity_agent_slug || db_external_id != conv.external_id || db_source_path != conv.source_path {
            failures.push(fail(
                "identity_mismatch",
                cid,
                format!(
                    "identity document says (source_id={:?}, agent_slug={:?}, external_id={:?}, source_path={:?}) but --db says ({db_source_id:?}, {db_agent_slug:?}, {db_external_id:?}, {db_source_path:?})",
                    conv.source_id, identity_agent_slug, conv.external_id, conv.source_path
                ),
            ));
            continue;
        }

        let Some(links) = snapshots.get(&cid) else {
            failures.push(fail("manifest_missing", cid, "no mirror manifest links this conversation".into()));
            continue;
        };
        let matching: Vec<&Snapshot> = links.iter().filter(|s| s.message_count == Some(db_message_count)).collect();
        if matching.is_empty() {
            excluded.push(ExcludedReport {
                conversation_id: cid,
                agent_slug: db_agent_slug.clone(),
                db_message_count,
                link_message_counts: links.iter().filter_map(|s| s.message_count).collect(),
            });
            continue;
        }
        let distinct: std::collections::BTreeSet<&str> = matching.iter().map(|s| s.blob_relative_path.as_str()).collect();
        if distinct.len() > 1 {
            failures.push(fail(
                "ambiguous_matching_snapshots",
                cid,
                format!("{} mirror snapshots carry message_count == {db_message_count} but point at different blobs: {:?}", distinct.len(), distinct),
            ));
            continue;
        }
        let snapshot = matching[0];

        let Some(rel_path) = layout_rel_path(&conv.source_path) else {
            failures.push(fail("no_connector_layout", cid, format!("source_path {:?} has no dot-prefixed component to anchor a connector layout under", conv.source_path)));
            continue;
        };
        match snapshot.original_path.as_deref().and_then(layout_rel_path) {
            Some(original_rel) if original_rel == rel_path => {}
            other => {
                failures.push(fail(
                    "original_path_layout_mismatch",
                    cid,
                    format!("source_path derives layout {rel_path:?} but the manifest's original_path {:?} derives {other:?}", snapshot.original_path),
                ));
                continue;
            }
        }

        let blob_path = cli.mirror.join(&snapshot.blob_relative_path);
        let blob_meta = match fs::symlink_metadata(&blob_path) {
            Ok(m) => m,
            Err(e) => {
                failures.push(fail("blob_missing", cid, format!("{}: {e}", blob_path.display())));
                continue;
            }
        };
        if blob_meta.file_type().is_symlink() || !blob_meta.is_file() {
            failures.push(fail("blob_not_regular", cid, format!("{} is not a regular file", blob_path.display())));
            continue;
        }
        let bytes = fs::read(&blob_path).with_context(|| format!("read blob {}", blob_path.display()))?;
        let digest = blake3::hash(&bytes).to_hex().to_string();
        if digest != snapshot.blob_blake3 {
            failures.push(fail(
                "blob_blake3_mismatch",
                cid,
                format!("{} hashes to {digest} but its manifest declares {}", blob_path.display(), snapshot.blob_blake3),
            ));
            continue;
        }
        if bytes.len() as u64 != snapshot.blob_size_bytes {
            failures.push(fail(
                "blob_size_mismatch",
                cid,
                format!("{} is {} bytes but its manifest declares {}", blob_path.display(), bytes.len(), snapshot.blob_size_bytes),
            ));
            continue;
        }

        let dest = cli.out.join(&rel_path);
        if fs::symlink_metadata(&dest).is_ok() {
            anyhow::bail!(
                "target {} already exists; refusing to overwrite a previously materialized source tree (move {} aside first)",
                dest.display(),
                cli.out.display()
            );
        }

        candidates.push(Candidate {
            conversation_id: cid,
            source_id: db_source_id,
            agent_slug: db_agent_slug,
            external_id: db_external_id,
            source_path: db_source_path,
            db_message_count,
            rel_path,
            snapshot: Snapshot {
                manifest_id: snapshot.manifest_id.clone(),
                blob_relative_path: snapshot.blob_relative_path.clone(),
                blob_blake3: snapshot.blob_blake3.clone(),
                blob_size_bytes: snapshot.blob_size_bytes,
                original_path: snapshot.original_path.clone(),
                captured_at_ms: snapshot.captured_at_ms,
                message_count: snapshot.message_count,
            },
            blob_sha256: sha256_of(&bytes),
        });
    }

    if !failures.is_empty() {
        eprintln!("w6_calib_source: R5-B3 failed for {} conversation(s); nothing was written", failures.len());
        for line in failures.iter().take(FAILURE_PRINT_CAP) {
            eprintln!("  {line}");
        }
        if failures.len() > FAILURE_PRINT_CAP {
            eprintln!("  ... and {} more", failures.len() - FAILURE_PRINT_CAP);
        }
        return Ok(1);
    }

    // Ruling 5: smallest-first until the cumulative message count reaches the
    // target (or the pool runs out), then cover any missing connector family.
    candidates.sort_by_key(|c| (c.db_message_count, c.conversation_id));
    let mut selected: Vec<usize> = Vec::new();
    let mut total = 0usize;
    for (i, c) in candidates.iter().enumerate() {
        if total >= SUBSET_TARGET_MESSAGES {
            break;
        }
        selected.push(i);
        total += c.db_message_count;
    }
    let mut families: std::collections::BTreeSet<String> = selected.iter().map(|&i| family_of(&candidates[i].agent_slug).to_string()).collect();
    for family in REQUIRED_FAMILIES {
        if families.contains(family) {
            continue;
        }
        if let Some((i, c)) = candidates.iter().enumerate().find(|(i, c)| !selected.contains(i) && family_of(&c.agent_slug) == family) {
            selected.push(i);
            total += c.db_message_count;
            families.insert(family_of(&c.agent_slug).to_string());
        }
    }
    selected.sort_unstable();

    // Report-only (ruling 5): how much of T3's own 5,000-message sample the
    // selected sessions cover. Never a pass/fail input.
    let selected_ids: std::collections::HashSet<i64> = selected.iter().map(|&i| candidates[i].conversation_id).collect();
    let mut inside = 0usize;
    for chunk in identity.message_ids.chunks(500) {
        let placeholders = vec!["?"; chunk.len()].join(",");
        let sql = format!("SELECT conversation_id FROM messages WHERE id IN ({placeholders})");
        let params: Vec<rusqlite::types::Value> = chunk.iter().map(|id| rusqlite::types::Value::Integer(*id)).collect();
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| r.get::<_, i64>(0))?;
        for row in rows {
            if selected_ids.contains(&row?) {
                inside += 1;
            }
        }
    }

    for &i in &selected {
        let c = &candidates[i];
        let dest = cli.out.join(&c.rel_path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let bytes = fs::read(cli.mirror.join(&c.snapshot.blob_relative_path)).with_context(|| format!("re-read blob {}", c.snapshot.blob_relative_path))?;
        fs::write(&dest, &bytes).with_context(|| format!("write {}", dest.display()))?;
        // Keep the materialized file as unreadable-by-others as the mirror it
        // came from; these are raw session transcripts.
        let mode = fs::metadata(cli.mirror.join(&c.snapshot.blob_relative_path)).map(|m| m.permissions().mode() & 0o777).unwrap_or(0o600);
        fs::set_permissions(&dest, fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {}", dest.display()))?;
    }

    let report = SelectionReport {
        schema_version: 1,
        identity: cli.identity.display().to_string(),
        db: cli.db.display().to_string(),
        mirror: cli.mirror.display().to_string(),
        out: cli.out.display().to_string(),
        seed: identity.seed,
        sample_size: identity.sample_size,
        selection_rule: format!(
            "eligible T3 conversations sorted by copy-db message count ascending, taken until the cumulative count reaches {SUBSET_TARGET_MESSAGES}; then the smallest not-yet-selected conversation of any of {REQUIRED_FAMILIES:?} still unrepresented (control-plane ruling 5; the plan's '5,000 messages' reading would have been 1,188,057 messages / 84.5% of the copy corpus)"
        ),
        snapshot_rule: "the mirror snapshot whose db_links[].message_count equals the conversation's message count in --db; a conversation with no such snapshot is excluded, never guessed at (control-plane ruling 3)".into(),
        target_messages: SUBSET_TARGET_MESSAGES,
        t3_conversations_total: identity.conversations.len(),
        eligible_conversations: candidates.len(),
        excluded_ambiguous_multi_blob: excluded,
        selected_conversations: selected.len(),
        selected_message_count: total,
        target_reached: total >= SUBSET_TARGET_MESSAGES,
        families_selected: families.into_iter().collect(),
        t3_message_ids_total: identity.message_ids.len(),
        t3_message_ids_inside_selection: inside,
        sessions: selected
            .iter()
            .map(|&i| {
                let c = &candidates[i];
                SessionReport {
                    conversation_id: c.conversation_id,
                    source_id: c.source_id.clone(),
                    agent_slug: c.agent_slug.clone(),
                    external_id: c.external_id.clone(),
                    source_path: c.source_path.clone(),
                    rel_path: c.rel_path.clone(),
                    manifest_id: c.snapshot.manifest_id.clone(),
                    blob_relative_path: c.snapshot.blob_relative_path.clone(),
                    blob_blake3: c.snapshot.blob_blake3.clone(),
                    blob_sha256: c.blob_sha256.clone(),
                    blob_size_bytes: c.snapshot.blob_size_bytes,
                    db_message_count: c.db_message_count,
                    blob_message_count: c.snapshot.message_count,
                }
            })
            .collect(),
    };

    let mut rendered = serde_json::to_vec_pretty(&report)?;
    rendered.push(b'\n');
    fs::write(&cli.manifest, rendered).with_context(|| format!("write --manifest {}", cli.manifest.display()))?;

    println!(
        "{{\"selected_conversations\":{},\"selected_message_count\":{},\"excluded_ambiguous_multi_blob\":{},\"eligible_conversations\":{},\"t3_message_ids_inside_selection\":{}}}",
        report.selected_conversations,
        report.selected_message_count,
        report.excluded_ambiguous_multi_blob.len(),
        report.eligible_conversations,
        report.t3_message_ids_inside_selection
    );
    Ok(0)
}

fn main() {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("w6_calib_source: {e:#}");
            std::process::exit(2);
        }
    }
}

