//! T3 (任务书 #121a): read-only metrics dump for canonicalize v3 baseline
//! measurement and the T5 cosine-calibration source. Given a population of
//! messages -- either an explicit `--ids` list, or a deterministic sample
//! drawn from the mirror-backed population of a corpus -- writes each
//! message's raw-content sha256 and the Rust `canonicalize_for_embedding`
//! output to a jsonl file, plus a read-only identity manifest recording
//! exactly which messages/conversations were selected (so a later run, e.g.
//! T5's calibration, can reproduce the same population from the same
//! `--seed`).
//!
//! Read-only: opens `--db` via a plain `rusqlite` connection with
//! `?immutable=1` and `SQLITE_OPEN_READ_ONLY`, and never writes to `--db` or
//! `--mirror`. **Deliberately does not go through
//! `FrankenStorage::open_readonly`**: that path also acquires a doctor
//! mutation-open guard, which `fs::create_dir_all`s a lock directory next to
//! the db on first open -- fine for a normal db, but fatal (`Permission
//! denied`) against a genuinely read-only frozen-copy directory (`copy/`,
//! `new/`; verified against this repo's `new/agent_search.db`, mode
//! `dr-x------`). `rusqlite` + `?immutable=1` is the other option the task
//! book names for exactly this reason.
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w6_normalize_dump -- --db <path> --mirror
//! <dir> [--require-mirror] (--ids <json-array-file> | --sample N --seed S)
//! --out <jsonl> --identity <json>`.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use clap::Parser;
use coding_agent_search::raw_mirror;
use coding_agent_search::search::canonicalize::{canonicalize_for_embedding, content_hash_hex};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;

fn open_readonly_immutable(path: &std::path::Path) -> anyhow::Result<Connection> {
    let uri = format!("file:{}?immutable=1", path.display());
    let conn = Connection::open_with_flags(uri, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI)?;
    Ok(conn)
}

#[derive(Parser, Debug)]
#[command(name = "w6_normalize_dump")]
struct Cli {
    #[arg(long)]
    db: PathBuf,
    /// The raw-mirror-bearing data directory itself (`copy/` or `new/`), not
    /// its `raw-mirror/` subdirectory -- passed straight to
    /// [`raw_mirror::manifest_views`].
    #[arg(long)]
    mirror: PathBuf,
    /// Restrict the sampling population to messages whose conversation
    /// appears in some manifest's `db_links[].conversation_id`. Ignored (and
    /// not required) in `--ids` mode.
    #[arg(long)]
    require_mirror: bool,
    #[arg(long)]
    sample: Option<usize>,
    #[arg(long)]
    seed: Option<u64>,
    /// Path to a JSON array of `message_id` integers. Mutually exclusive
    /// with `--sample`/`--seed`.
    #[arg(long)]
    ids: Option<PathBuf>,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    identity: PathBuf,
}

struct MessageRow {
    id: i64,
    conversation_id: i64,
    content: String,
}

#[derive(Serialize)]
struct ConversationIdentity {
    conversation_id: i64,
    source_id: String,
    agent_slug: String,
    external_id: Option<String>,
    source_path: String,
}

#[derive(Serialize)]
struct Identity {
    db: String,
    mirror: String,
    seed: Option<u64>,
    population_size: usize,
    sample_size: usize,
    message_ids: Vec<i64>,
    conversations: Vec<ConversationIdentity>,
}

/// splitmix64 (Vigna, 2015 public-domain construction), spelled out in full
/// here rather than pulled from a crate: T5's calibration must reproduce
/// this exact sample from the same `--seed` in a run that may not even link
/// against this binary, so the sampling algorithm is documented, not just
/// referenced by a dependency name/version that could drift.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Uniform integer in `[0, bound)` via a widening-multiply reduction
    /// (Lemire); a deterministic-sampling utility, not a cryptographic
    /// requirement, so the negligible modulo bias at extreme bounds is
    /// acceptable.
    fn next_below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        ((self.next_u64() as u128 * bound as u128) >> 64) as u64
    }
}

/// Deterministic sample-without-replacement of `k` indices from `[0, n)` via
/// partial Fisher-Yates over an implicit identity array (only the swapped
/// positions are ever materialized). Output order is the draw order, not
/// sorted -- callers that need a stable population order re-sort by
/// `message_id` afterward.
fn sample_indices(n: usize, k: usize, rng: &mut SplitMix64) -> Vec<usize> {
    assert!(k <= n, "sample size {k} exceeds population {n}");
    let mut moved: HashMap<usize, usize> = HashMap::new();
    let mut result = Vec::with_capacity(k);
    for i in 0..k {
        let remaining = (n - i) as u64;
        let j = i + rng.next_below(remaining) as usize;
        let pi = *moved.get(&i).unwrap_or(&i);
        let pj = *moved.get(&j).unwrap_or(&j);
        result.push(pj);
        moved.insert(j, pi);
    }
    result
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.ids.is_some() && (cli.sample.is_some() || cli.seed.is_some()) {
        anyhow::bail!("--ids is mutually exclusive with --sample/--seed");
    }
    if cli.ids.is_none() && (cli.sample.is_none() || cli.seed.is_none()) {
        anyhow::bail!("must give either --ids, or --sample together with --seed");
    }

    let conn = open_readonly_immutable(&cli.db)?;

    let mirror_conversation_ids: Option<HashSet<i64>> = if cli.require_mirror {
        let views = raw_mirror::manifest_views(&cli.mirror)?;
        let mut ids = HashSet::new();
        for view in &views {
            for link in &view.db_links {
                if let Some(cid) = link.conversation_id {
                    ids.insert(cid);
                }
            }
        }
        Some(ids)
    } else {
        None
    };

    // Decide *which* message_ids are wanted first, using only the light
    // `(id, conversation_id)` projection -- `content` for a 1.4M-row/37GB
    // corpus is by far the expensive column, and both `--ids` (a handful of
    // ids) and `--sample` (a few thousand out of the whole population) only
    // ever need `content` for the final selected subset.
    let (selected_ids, seed_out, population_size): (Vec<i64>, Option<u64>, usize) =
        if let Some(ids_path) = &cli.ids {
            let ids_raw = fs::read_to_string(ids_path)?;
            let wanted: Vec<i64> = serde_json::from_str(&ids_raw)?;
            let wanted_set: BTreeSet<i64> = wanted.into_iter().collect();
            let pop = wanted_set.len();
            (wanted_set.into_iter().collect(), None, pop)
        } else {
            let metas: Vec<(i64, i64)> = {
                let mut stmt = conn.prepare("SELECT id, conversation_id FROM messages ORDER BY id ASC")?;
                stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<Result<Vec<_>, rusqlite::Error>>()?
            };
            let population: Vec<i64> = match &mirror_conversation_ids {
                Some(ids) => metas.iter().filter(|(_, cid)| ids.contains(cid)).map(|(id, _)| *id).collect(),
                None => metas.iter().map(|(id, _)| *id).collect(),
            };
            let n = population.len();
            let k = cli.sample.expect("checked above");
            if k > n {
                anyhow::bail!("--sample {k} exceeds population {n}");
            }
            let seed = cli.seed.expect("checked above");
            let mut rng = SplitMix64::new(seed);
            let idxs = sample_indices(n, k, &mut rng);
            let sel: Vec<i64> = idxs.into_iter().map(|i| population[i]).collect();
            (sel, Some(seed), n)
        };

    let selected: Vec<MessageRow> = {
        let placeholders = selected_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id, conversation_id, content FROM messages WHERE id IN ({placeholders}) ORDER BY id ASC"
        );
        let mut stmt = conn.prepare(&sql)?;
        stmt.query_map(rusqlite::params_from_iter(selected_ids.iter()), |row| {
            Ok(MessageRow {
                id: row.get(0)?,
                conversation_id: row.get(1)?,
                content: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, rusqlite::Error>>()?
    };
    if selected.len() != selected_ids.len() {
        let found: HashSet<i64> = selected.iter().map(|m| m.id).collect();
        let missing: Vec<i64> = selected_ids.iter().copied().filter(|id| !found.contains(id)).collect();
        anyhow::bail!("message_id(s) not found in --db: {missing:?}");
    }

    let mut out = String::new();
    for m in &selected {
        let content_sha256 = content_hash_hex(&m.content);
        let rust_normalized = canonicalize_for_embedding(&m.content);
        let line = serde_json::json!({
            "message_id": m.id,
            "content_sha256": content_sha256,
            "rust_normalized": rust_normalized,
        });
        out.push_str(&serde_json::to_string(&line)?);
        out.push('\n');
    }
    fs::write(&cli.out, out)?;

    let conv_ids: BTreeSet<i64> = selected.iter().map(|m| m.conversation_id).collect();
    let mut conversations = Vec::new();
    if !conv_ids.is_empty() {
        let placeholders = conv_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT c.id, c.source_id, a.slug, c.external_id, c.source_path \
             FROM conversations c JOIN agents a ON a.id = c.agent_id WHERE c.id IN ({placeholders})"
        );
        let mut stmt = conn.prepare(&sql)?;
        let params: Vec<i64> = conv_ids.iter().copied().collect();
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?;
        for row in rows {
            let (conversation_id, source_id, agent_slug, external_id, source_path) = row?;
            conversations.push(ConversationIdentity {
                conversation_id,
                source_id,
                agent_slug,
                external_id,
                source_path,
            });
        }
    }

    let identity = Identity {
        db: cli.db.display().to_string(),
        mirror: cli.mirror.display().to_string(),
        seed: seed_out,
        population_size,
        sample_size: selected.len(),
        message_ids: selected.iter().map(|m| m.id).collect(),
        conversations,
    };
    fs::write(&cli.identity, serde_json::to_string_pretty(&identity)?)?;
    let mut perms = fs::metadata(&cli.identity)?.permissions();
    perms.set_mode(0o444);
    fs::set_permissions(&cli.identity, perms)?;

    println!(
        "w6_normalize_dump: population={population_size} sample={} out={} identity={}",
        selected.len(),
        cli.out.display(),
        cli.identity.display()
    );
    Ok(())
}
