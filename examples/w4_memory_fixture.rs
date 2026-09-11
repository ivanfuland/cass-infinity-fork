//! T10 (plan v5.1): `w4_memory_fixture` -- generates a raw, connector-
//! scannable session-file tree (the shape `memory_gate.sh`'s four-stage
//! ingest run consumes) plus a `sources.toml`, at one of three memory-shape
//! presets from the parameter-freeze table's "内存门" row:
//!   a) 1 message of ~512 MiB + 9,999 messages of ~1 KiB each
//!   b) 10,000 messages of ~200 KiB each
//!   c) a long-tail mixture (halving size, doubling count per bucket) that
//!      sums to ~2 GiB total
//!
//! File format is the Claude Code connector's own JSONL shape (verified by
//! an empirical probe against the real candidate binary before writing this
//! generator: a synthetic `<out>/.claude/projects/<proj>/<file>.jsonl` tree
//! is auto-discovered via `HOME=<out>`, no `sources.toml` strictly required
//! for that discovery path -- the mission still asks for one, written here
//! as an explicit local-source declaration mainly for documentation/
//! reproducibility, pointing `paths` at the same `.claude` root rather than
//! relying only on the implicit `HOME`-based default). Message content is
//! plain ASCII (`"content": "<text>"`, not the content-block-array form) so
//! its UTF-8 byte length is exactly the requested size -- comfortably above
//! `canonicalize`'s 200-char short-acknowledgement threshold, so no
//! generated message is filtered out as noise.
//!
//! Usage: `cargo run --release --no-default-features --features
//! qr,encryption,infinity --example w4_memory_fixture -- --shape a --out
//! <dir>`. Exit codes: 0 always on a completed generation (this is a data-
//! generation tool, not a pass/fail gate); 2 precondition error (bad
//! `--shape`, `--out`'s parent directory does not exist, or `--out` already
//! holds a frozen `manifest.json` -- the fixture-freeze contract from
//! #122b-1: a fixture that already has a manifest is never silently
//! overwritten with a different byte layout while `memory_gate.sh`'s P0
//! baseline still references its old `fixture_sha256`).
//!
//! #122b-1 (spec v4.5 §四.3 / plan "内存门" row): also writes
//! `<out>/manifest.json`, the frozen record `memory_gate.sh` reads instead
//! of querying a live db for `max_message_bytes` -- `{shape, messages,
//! total_bytes, max_message_bytes, fixture_sha256, stage_merge,
//! min_stage_ms}`. `fixture_sha256` is the sha256 of every `.jsonl` file
//! under `<out>` concatenated in path-sorted order (this generator emits a
//! single file per shape today; the sort-then-concatenate contract is
//! written for whenever that changes, not as speculative multi-file
//! support -- no other multi-file plumbing exists here). `stage_merge`
//! defaults to `[]` and `min_stage_ms` to 200; both are P0-collection-time
//! decisions (#122b-2/3), not decided by this generator.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use coding_agent_search::sources::config::SourceDefinition;
use sha2::{Digest, Sha256};

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;
const GIB: usize = 1024 * MIB;

#[derive(Parser, Debug)]
#[command(name = "w4_memory_fixture")]
struct Cli {
    #[arg(long)]
    shape: Shape,
    #[arg(long)]
    out: PathBuf,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    A,
    B,
    C,
}

/// #122b-1: the frozen fixture record `memory_gate.sh` reads instead of
/// querying a live db for `max_message_bytes`. `stage_merge`/`min_stage_ms`
/// are P0-collection-time decisions (#122b-2/3); this generator only writes
/// the defaults (`[]` / 200) it is authoritative for.
#[derive(serde::Serialize)]
struct FixtureManifest {
    shape: String,
    messages: usize,
    total_bytes: usize,
    max_message_bytes: usize,
    fixture_sha256: String,
    stage_merge: Vec<serde_json::Value>,
    min_stage_ms: u64,
}

/// All `.jsonl` files under `root`, sorted by path. This generator writes
/// one file per shape today; the sort is here so `fixture_sha256`'s
/// "concatenate in path-sorted order" contract holds if that ever changes,
/// not as speculative multi-file support.
fn collect_jsonl_files_sorted(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "jsonl") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn fixture_sha256(root: &Path) -> anyhow::Result<String> {
    let mut hasher = Sha256::new();
    for path in collect_jsonl_files_sorted(root) {
        hasher.update(std::fs::read(&path)?);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn write_manifest(out: &Path, shape: Shape, messages: usize, total_bytes: usize, max_message_bytes: usize) -> anyhow::Result<()> {
    let manifest = FixtureManifest {
        shape: format!("{shape:?}").to_lowercase(),
        messages,
        total_bytes,
        max_message_bytes,
        fixture_sha256: fixture_sha256(out)?,
        stage_merge: Vec::new(),
        min_stage_ms: 200,
    };
    std::fs::write(out.join("manifest.json"), serde_json::to_string_pretty(&manifest)?)?;
    Ok(())
}

/// One message's target byte length, for a batch to be written together.
struct MessagePlan {
    byte_len: usize,
    count: usize,
}

fn plan_for_shape(shape: Shape) -> Vec<MessagePlan> {
    match shape {
        Shape::A => vec![MessagePlan { byte_len: 512 * MIB, count: 1 }, MessagePlan { byte_len: 1 * KIB, count: 9_999 }],
        Shape::B => vec![MessagePlan { byte_len: 200 * KIB, count: 10_000 }],
        Shape::C => {
            // Long-tail: halve the size, double the count, each bucket:
            // 64MiB*4, 32MiB*8, 16MiB*16, ... down to a 1KiB floor, then
            // keep emitting 1KiB-bucket messages until the running total
            // reaches the 2GiB target (the tail is where nearly all the
            // *message count* -- but very little of the *byte total* --
            // lives, which is the defining shape of a long-tail mixture).
            let target_total = 2 * GIB;
            let mut plans = Vec::new();
            let mut total = 0usize;
            let mut byte_len = 64 * MIB;
            let mut count = 4usize;
            while byte_len >= KIB && total < target_total {
                let bucket_total = byte_len * count;
                if total + bucket_total > target_total {
                    let remaining = target_total - total;
                    let fit_count = (remaining / byte_len).max(1);
                    plans.push(MessagePlan { byte_len, count: fit_count });
                    total += byte_len * fit_count;
                    break;
                }
                plans.push(MessagePlan { byte_len, count });
                total += bucket_total;
                byte_len /= 2;
                count *= 2;
            }
            if total < target_total {
                let remaining = target_total - total;
                let filler_count = (remaining / KIB).max(1);
                plans.push(MessagePlan { byte_len: KIB, count: filler_count });
            }
            plans
        }
    }
}

/// Exactly `byte_len` ASCII bytes: `word-<n> ` repeated and trimmed to
/// length (never emits the short-acknowledgement-filterable strings
/// `canonicalize`/`eligibility` special-case, since every generated message
/// is well above the 200-char threshold those checks apply below).
fn make_content(byte_len: usize, seed: usize) -> String {
    let unit = format!("mem-fixture-content-word-{seed} ");
    let mut s = String::with_capacity(byte_len + unit.len());
    while s.len() < byte_len {
        s.push_str(&unit);
    }
    s.truncate(byte_len);
    s
}

/// R2 (empirical, 2026-09-05): every message for a shape is written into a
/// SINGLE session file (one conversation), not split across many small
/// files/conversations. This was tightened after an initial per-500-message
/// split empirically failed to reproduce the required "shape b's
/// `--force-rebuild` stage must fail red" self-check against the real
/// `$RUN_ROOT/cass-baseline` binary: splitting shape b's 10,000 x 200KiB
/// messages into 20 conversations let the (baseline-only, since removed by
/// this PR's T5) old 8MiB-per-conversation lexical-rebuild cap truncate
/// each conversation's buffered content early, keeping peak RSS ~190MiB --
/// comfortably inside budget. A single 2GiB conversation forces that same
/// code path to buffer the *whole* conversation's content before applying
/// the cap (confirmed via the real `original_bytes=<full size>` value in
/// that WARN log line), which is the actual memory-pressure scenario this
/// shape exists to reproduce.
fn write_shape(out: &Path, shape: Shape) -> anyhow::Result<(usize, usize, usize)> {
    let proj_dir = out.join(".claude").join("projects").join(format!("mem-fixture-{shape:?}").to_lowercase());
    std::fs::create_dir_all(&proj_dir)?;

    let plans = plan_for_shape(shape);
    let max_message_bytes = plans.iter().map(|p| p.byte_len).max().unwrap_or(0);
    let path = proj_dir.join("session-000000.jsonl");
    let mut f = std::io::BufWriter::new(std::fs::File::create(&path)?);
    let mut global_idx = 0usize;
    let mut total_messages = 0usize;
    let mut total_bytes = 0usize;

    for plan in &plans {
        for _ in 0..plan.count {
            let role = if global_idx % 2 == 0 { "user" } else { "assistant" };
            let content = make_content(plan.byte_len, global_idx);
            let ts_ms = 1_700_000_000_000i64 + global_idx as i64;
            let line = serde_json::json!({
                "type": role,
                "message": {"role": role, "content": content},
                "timestamp": chrono::DateTime::from_timestamp_millis(ts_ms).unwrap().to_rfc3339(),
            });
            serde_json::to_writer(&mut f, &line)?;
            f.write_all(b"\n")?;

            total_messages += 1;
            total_bytes += plan.byte_len;
            global_idx += 1;
        }
    }
    f.flush()?;

    Ok((total_messages, total_bytes, max_message_bytes))
}

fn write_sources_toml(out: &Path) -> anyhow::Result<()> {
    let mut source = SourceDefinition::local("mem-fixture");
    source.paths = vec![out.join(".claude").to_string_lossy().to_string()];
    let config = coding_agent_search::sources::config::SourcesConfig { sources: vec![source], disabled_agents: Vec::new() };
    let text = toml::to_string_pretty(&config)?;
    std::fs::write(out.join("sources.toml"), text)?;
    Ok(())
}

fn run(shape: Shape, out: &Path) -> (i32, String) {
    if out.join("manifest.json").is_file() {
        return (
            2,
            format!("precondition error: fixture already frozen (manifest.json exists) at {}: refusing to overwrite", out.display()),
        );
    }
    let parent_missing = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => !p.exists(),
        _ => false,
    };
    if parent_missing {
        return (2, format!("precondition error: --out's parent directory does not exist: {}", out.display()));
    }
    if let Err(e) = std::fs::create_dir_all(out) {
        return (2, format!("precondition error: creating --out directory: {e}"));
    }
    match write_shape(out, shape) {
        Err(e) => (2, format!("precondition error: {e:#}")),
        Ok((total_messages, total_bytes, max_message_bytes)) => match write_sources_toml(out) {
            Err(e) => (2, format!("precondition error writing sources.toml: {e:#}")),
            Ok(()) => match write_manifest(out, shape, total_messages, total_bytes, max_message_bytes) {
                Err(e) => (2, format!("precondition error writing manifest.json: {e:#}")),
                Ok(()) => (
                    0,
                    format!(
                        "memory_fixture: shape={shape:?} out={} messages={total_messages} total_bytes={total_bytes} ({:.2} MiB) max_message_bytes={max_message_bytes}",
                        out.display(),
                        total_bytes as f64 / MIB as f64
                    ),
                ),
            },
        },
    }
}

fn main() {
    let cli = Cli::parse();
    let (code, message) = run(cli.shape, &cli.out);
    println!("{message}");
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn shape_a_has_one_huge_message_and_9999_small_ones() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("fixture-a");
        let (code, message) = run(Shape::A, &out);
        assert_eq!(code, 0, "{message}");

        let mut sizes: Vec<usize> = Vec::new();
        for entry in walkdir_jsonl(&out) {
            let text = std::fs::read_to_string(&entry).unwrap();
            for line in text.lines() {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                let content = v["message"]["content"].as_str().unwrap();
                sizes.push(content.len());
            }
        }
        assert_eq!(sizes.len(), 10_000);
        let huge = sizes.iter().filter(|&&s| s >= 500 * MIB).count();
        assert_eq!(huge, 1, "exactly one ~512MiB message");
        let small = sizes.iter().filter(|&&s| s == KIB).count();
        assert_eq!(small, 9_999, "9,999 exactly-1KiB messages");
        assert!(out.join("sources.toml").is_file());

        let manifest = read_manifest(&out);
        assert_eq!(manifest["shape"], "a");
        assert_eq!(manifest["max_message_bytes"], 512 * MIB);
        assert_eq!(manifest["messages"], 10_000);
        assert!(manifest["fixture_sha256"].as_str().unwrap().len() == 64, "fixture_sha256 must be a hex sha256");
        assert_eq!(manifest["stage_merge"], serde_json::json!([]));
        assert_eq!(manifest["min_stage_ms"], 200);
    }

    #[test]
    fn shape_b_has_10000_messages_of_200kib() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("fixture-b");
        let (code, message) = run(Shape::B, &out);
        assert_eq!(code, 0, "{message}");

        let mut count = 0usize;
        for entry in walkdir_jsonl(&out) {
            let text = std::fs::read_to_string(&entry).unwrap();
            for line in text.lines() {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                let content = v["message"]["content"].as_str().unwrap();
                assert_eq!(content.len(), 200 * KIB);
                count += 1;
            }
        }
        assert_eq!(count, 10_000);

        let manifest = read_manifest(&out);
        assert_eq!(manifest["shape"], "b");
        assert_eq!(manifest["max_message_bytes"], 200 * KIB);
    }

    #[test]
    fn shape_c_long_tail_sums_to_approximately_2gib() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("fixture-c");
        let (code, message) = run(Shape::C, &out);
        assert_eq!(code, 0, "{message}");

        let mut total = 0usize;
        let mut distinct_sizes = std::collections::HashSet::new();
        for entry in walkdir_jsonl(&out) {
            let text = std::fs::read_to_string(&entry).unwrap();
            for line in text.lines() {
                let v: serde_json::Value = serde_json::from_str(line).unwrap();
                let content = v["message"]["content"].as_str().unwrap();
                total += content.len();
                distinct_sizes.insert(content.len());
            }
        }
        assert!(distinct_sizes.len() > 1, "a long-tail mixture must have more than one message size");
        let target = 2 * GIB;
        let tolerance = target / 20; // within 5%
        assert!(
            total.abs_diff(target) <= tolerance,
            "shape c total {total} must be within 5% of the 2GiB target {target}"
        );

        let manifest = read_manifest(&out);
        assert_eq!(manifest["shape"], "c");
        assert_eq!(manifest["max_message_bytes"], 64 * MIB);
    }

    #[test]
    fn missing_parent_directory_is_precondition_error_exit_2() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("does-not-exist").join("nested").join("fixture");
        let (code, message) = run(Shape::A, &out);
        assert_eq!(code, 2, "missing parent directory must be a precondition error: {message}");
    }

    fn walkdir_jsonl(root: &Path) -> Vec<PathBuf> {
        super::collect_jsonl_files_sorted(root)
    }

    fn read_manifest(out: &Path) -> serde_json::Value {
        let text = std::fs::read_to_string(out.join("manifest.json")).expect("manifest.json must exist after a successful run()");
        serde_json::from_str(&text).expect("manifest.json must be valid JSON")
    }

    /// #122b-1 block C: the frozen `max_message_bytes` value must match the
    /// parameter-freeze table's per-shape figure -- checked via the pure
    /// `plan_for_shape` computation (no fixture I/O), per the mission's
    /// "只测 max_message_bytes 计算函数" option, so this doesn't add a new
    /// 512MiB/2GiB generation on top of the shape_a/b/c tests below (which
    /// already pay that cost and separately assert the manifest field).
    /// Mutation: swap `.max()` for `.min()` (or hardcode a wrong constant)
    /// in `write_shape` -- this test and the shape_a/b/c manifest
    /// assertions below both go red.
    #[test]
    fn shape_max_message_bytes_matches_plan_for_all_shapes() {
        for (shape, expected) in [(Shape::A, 512 * MIB), (Shape::B, 200 * KIB), (Shape::C, 64 * MIB)] {
            let got = plan_for_shape(shape).iter().map(|p| p.byte_len).max().unwrap();
            assert_eq!(got, expected, "{shape:?} max_message_bytes must match the frozen parameter-freeze value");
        }
    }

    /// #122b-1 block C: `--out` already holding a `manifest.json` must
    /// freeze the fixture -- exit 2, no overwrite. Uses a hand-written stub
    /// manifest (not a real run()) so this test doesn't pay a second full
    /// generation just to set up the precondition.
    #[test]
    fn existing_manifest_freezes_the_fixture_and_refuses_to_overwrite() {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("frozen-fixture");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("manifest.json"), "{}").unwrap();

        let (code, message) = run(Shape::A, &out);
        assert_eq!(code, 2, "an existing manifest.json must freeze the fixture: {message}");
        assert_eq!(
            std::fs::read_dir(&out).unwrap().count(),
            1,
            "refusing the overwrite must not have written anything else into the frozen fixture dir"
        );
    }
}
