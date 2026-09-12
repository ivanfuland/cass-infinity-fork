//! R7-1 (#124, control-plane adversarial review of #123, blocker class: data
//! corruption). `examples/w6_normalize_dump.rs`'s `refuse_output_collisions`
//! refuses an `--out`/`--identity` that resolves to an existing file under
//! `--mirror`, so a hard link to a mirror blob placed *outside* `--mirror`
//! cannot be truncated by the dump's later `fs::write`. That walk used to
//! treat any `read_dir`/`metadata` failure as "not that inode" and returned
//! `false`, i.e. "unknown" was spelled "absent": a blob sitting in a
//! directory the running user cannot enumerate is exactly such an unknown,
//! and the alias passed every check.
//!
//! This test builds the real binary's situation end to end: a tempdir mirror
//! whose one blob lives in a `chmod 000` directory, `--out` hard-linked to
//! that blob from outside the mirror. Pre-fix the guard passes and the dump
//! truncates the blob inode (`fs::write`); post-fix the incomplete walk is an
//! error, the process exits non-zero, and the blob's bytes are untouched.
//!
//! `w6_normalize_dump` is an `[[example]]`, not the `[[bin]]` target `cass`,
//! so cargo injects no `CARGO_BIN_EXE_<name>` for it: `dump_binary_path` below
//! derives the path cargo actually builds examples to (a `examples/`
//! directory sibling to this test binary's own `deps/`, both under the same
//! `target/<profile>/`), the same convention
//! `tests/w6_memory_gate_selfcheck.rs` uses for `w6_memory_hog`. Build it
//! first (same mandatory env/feature flags as everything else in this PR):
//!   cargo build --example w6_normalize_dump \
//!     --no-default-features --features qr,encryption,infinity
//! before `cargo test --test w6_normalize_dump_guard ...` (matching profiles
//! matters: this test looks in ITS OWN profile's `examples/` dir).

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

const BLOB: &[u8] = b"blob-payload";

fn dump_binary_path() -> PathBuf {
    let test_exe = std::env::current_exe().expect("current_exe");
    let deps_dir = test_exe.parent().expect("deps dir has a parent");
    let profile_dir = deps_dir.parent().expect("profile dir has a parent");
    let candidate = profile_dir.join("examples").join("w6_normalize_dump");
    assert!(
        candidate.is_file(),
        "w6_normalize_dump example binary not found at {candidate:?} -- build it first: \
         cargo build --example w6_normalize_dump --no-default-features \
         --features qr,encryption,infinity (with this PR's mandatory CARGO_* env vars)"
    );
    candidate
}

/// The smallest schema `w6_normalize_dump --ids` reads end to end: the
/// `messages` projection it selects from, and the `conversations`/`agents`
/// join it runs for the identity manifest afterwards. A run that reaches the
/// write (and the join) has to exit 0, which is what makes "pre-fix the dump
/// silently truncated the blob" observable as a 0-exit run rather than as
/// some unrelated later failure.
fn write_probe_db(path: &Path) {
    let conn = rusqlite::Connection::open(path).expect("create probe sqlite db");
    conn.execute_batch(
        "CREATE TABLE agents(id INTEGER PRIMARY KEY, slug TEXT);
         CREATE TABLE conversations(id INTEGER PRIMARY KEY, agent_id INTEGER, source_id TEXT, external_id TEXT, source_path TEXT);
         CREATE TABLE messages(id INTEGER PRIMARY KEY, conversation_id INTEGER, content TEXT);
         INSERT INTO agents VALUES(1, 'claude_code');
         INSERT INTO conversations VALUES(1, 1, 'local', 'c-1', '/x.jsonl');
         INSERT INTO messages VALUES(1, 1, 'a probe message long enough to be dumped');",
    )
    .expect("seed probe sqlite db");
}

#[test]
fn dump_refuses_when_the_mirror_walk_cannot_complete() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // Not root: a `chmod 000` directory is unenumerable only for a process
    // that has to answer to the permission bits.
    if fs::metadata(tmp.path()).expect("stat tempdir").uid() == 0 {
        eprintln!(
            "SKIP dump_refuses_when_the_mirror_walk_cannot_complete: running as uid 0, where \
             chmod 000 does not make a directory unenumerable, so the R7-1 scenario cannot be \
             constructed; re-run as an unprivileged user"
        );
        return;
    }

    let mirror = tmp.path().join("mirror");
    let blob_dir = mirror.join("raw-mirror/v1/blobs/ab");
    fs::create_dir_all(&blob_dir).expect("create blob dir");
    let blob = blob_dir.join("h.blob");
    fs::write(&blob, BLOB).expect("write blob");

    // The output path is a hard link to the blob, placed *outside* --mirror:
    // the containment check cannot see it, only the identity walk can.
    let out = tmp.path().join("out.jsonl");
    fs::hard_link(&blob, &out).expect("hard link blob -> out");

    // Make the blob's directory unenumerable. The link above already exists,
    // so the dump can still write through `out` -- that is the whole point.
    fs::set_permissions(&blob_dir, fs::Permissions::from_mode(0o000)).expect("chmod 000 blob dir");

    let db = tmp.path().join("probe.db");
    write_probe_db(&db);
    let ids = tmp.path().join("ids.json");
    fs::write(&ids, "[1]").expect("write ids file");

    let output = Command::new(dump_binary_path())
        .args([
            "--db",
            db.to_str().expect("utf8 db"),
            "--mirror",
            mirror.to_str().expect("utf8 mirror"),
            "--ids",
            ids.to_str().expect("utf8 ids"),
            "--out",
            out.to_str().expect("utf8 out"),
            "--identity",
            tmp.path().join("identity.json").to_str().expect("utf8 identity"),
        ])
        .output()
        .expect("spawn w6_normalize_dump");

    // Restore before asserting so a failure still leaves a removable tempdir.
    fs::set_permissions(&blob_dir, fs::Permissions::from_mode(0o755)).expect("chmod back");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let after = fs::read(&out).expect("read the alias back");
    assert_eq!(
        after, BLOB,
        "the blob under the unenumerable mirror subdirectory must be byte-identical after the \
         run -- a walk that cannot see it is not evidence it is absent; status={:?} stdout={stdout:?} stderr={stderr:?}",
        output.status.code()
    );
    assert_ne!(
        output.status.code(),
        Some(0),
        "an output path that is a hard link to a mirror blob must refuse the run even when the \
         blob's directory cannot be enumerated; stdout={stdout:?} stderr={stderr:?}"
    );
    // The refusal must come from *this* check and name the directory it could
    // not enumerate: the alias check fails at the incomplete walk (the inode
    // itself is never reached), so the "hard link to a file under --mirror"
    // wording only appears when the walk completes and finds the alias.
    let unreadable = fs::canonicalize(&blob_dir).expect("canonicalize blob dir");
    assert!(
        stderr.contains("hard-link aliases") && stderr.contains(&unreadable.display().to_string()),
        "expected the incomplete-walk refusal naming {}, got stderr={stderr:?}",
        unreadable.display()
    );
}
