//! PR6 T6-c B01 (任务书 #131): `examples/w4_ownership_oracle.rs` writes its
//! `--json`/`--out`/`--dump-failures` documents with a final `fs::write`. A
//! path that names the input database would therefore truncate the library
//! the run just read -- after paying for the whole run, and while still
//! reporting success. The guard is "refuse before anything runs", and this
//! test pins exactly that ordering: the invocation must exit 2 with the
//! refusal on stderr, and the database must be byte-identical afterwards.
//!
//! `w4_ownership_oracle` is an `[[example]]`, not the `[[bin]]` target `cass`,
//! so cargo injects no `CARGO_BIN_EXE_<name>` for it: `oracle_binary_path`
//! derives the path cargo builds examples to (an `examples/` dir sibling to
//! this test binary's own `deps/`, both under the same `target/<profile>/`),
//! the convention `tests/w6_calib_source_guard.rs` and
//! `tests/w6_normalize_dump_guard.rs` already use. Build it first (same
//! mandatory env/feature flags as everything else in this PR):
//!   cargo build --example w4_ownership_oracle \
//!     --no-default-features --features qr,encryption,infinity

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn oracle_binary_path() -> PathBuf {
    let test_exe = std::env::current_exe().expect("current_exe");
    let deps_dir = test_exe.parent().expect("deps dir has a parent");
    let profile_dir = deps_dir.parent().expect("profile dir has a parent");
    let candidate = profile_dir.join("examples").join("w4_ownership_oracle");
    assert!(
        candidate.is_file(),
        "w4_ownership_oracle example binary not found at {candidate:?} -- build it first: \
         cargo build --example w4_ownership_oracle --no-default-features \
         --features qr,encryption,infinity (with this PR's mandatory CARGO_* env vars)"
    );
    candidate
}

/// A file that is deliberately NOT a usable library: the guard must refuse
/// before it ever reads the path, so nothing about the database's validity
/// can decide the outcome. The bytes are what the test compares afterwards.
fn plant_unreadable_db(dir: &tempfile::TempDir) -> PathBuf {
    let db = dir.path().join("agent_search.db");
    fs::write(&db, b"this is not a sqlite library, and it must survive untouched\n").expect("plant db");
    db
}

fn run_oracle(args: &[&std::ffi::OsStr]) -> std::process::Output {
    let mut cmd = Command::new(oracle_binary_path());
    cmd.args(args);
    cmd.output().expect("spawn w4_ownership_oracle")
}

#[test]
fn calibrate_out_naming_the_input_db_is_refused_before_anything_runs() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db = plant_unreadable_db(&dir);
    let before = fs::read(&db).expect("read planted db");

    let output = run_oracle(&[
        std::ffi::OsStr::new("--calibrate"),
        std::ffi::OsStr::new("--db"),
        db.as_os_str(),
        std::ffi::OsStr::new("--sample"),
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new("--seed"),
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new("--infinity"),
        std::ffi::OsStr::new("http://127.0.0.1:1"),
        std::ffi::OsStr::new("--out"),
        db.as_os_str(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "--out naming --db must be refused with exit 2 before any run; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to run, nothing was written"),
        "the refusal must say what it refused; stderr: {stderr}"
    );
    assert_eq!(
        fs::read(&db).expect("read db after refusal"),
        before,
        "the input database must be byte-identical after a refused invocation"
    );
}

#[test]
fn json_naming_the_input_db_is_refused_before_anything_runs() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db = plant_unreadable_db(&dir);
    let before = fs::read(&db).expect("read planted db");

    let output = run_oracle(&[
        std::ffi::OsStr::new("--db"),
        db.as_os_str(),
        std::ffi::OsStr::new("--sample"),
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new("--seed"),
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new("--infinity"),
        std::ffi::OsStr::new("http://127.0.0.1:1"),
        std::ffi::OsStr::new("--json"),
        db.as_os_str(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "--json naming --db must be refused with exit 2 before any run; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to run, nothing was written"),
        "the refusal must come from the guard, before any run: stderr: {stderr}"
    );
    assert_eq!(
        fs::read(&db).expect("read db after refusal"),
        before,
        "the input database must be byte-identical after a refused invocation"
    );
}

/// The sibling half of the same rule: a database reached through a symlink is
/// the same file, so naming the symlink as the output is refused too.
#[cfg(unix)]
#[test]
fn an_output_naming_a_symlink_to_the_input_db_is_refused() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db = plant_unreadable_db(&dir);
    let alias = dir.path().join("alias.db");
    std::os::unix::fs::symlink(&db, &alias).expect("symlink");
    let before = fs::read(&db).expect("read planted db");

    let output = run_oracle(&[
        std::ffi::OsStr::new("--calibrate"),
        std::ffi::OsStr::new("--db"),
        db.as_os_str(),
        std::ffi::OsStr::new("--sample"),
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new("--seed"),
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new("--infinity"),
        std::ffi::OsStr::new("http://127.0.0.1:1"),
        std::ffi::OsStr::new("--out"),
        alias.as_os_str(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "an --out that resolves onto --db must be refused; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to run, nothing was written"),
        "the refusal must come from the guard, before any run: stderr: {stderr}"
    );
    assert_eq!(fs::read(&db).expect("read db after refusal"), before, "the real database must be untouched");
}

/// R9-B01 (任务书 #132): `--db` and `--out` naming two paths that are HARD
/// LINKS to one inode. The canonical paths differ, the `(dev, ino)` pair does
/// not -- and the guard compared the whole identity tuple at once, so it read
/// them as different files, ran the calibration, and let the final
/// `fs::write` truncate the database through the other name.
#[cfg(unix)]
#[test]
fn an_output_hardlinked_to_the_input_db_is_refused() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let db = plant_unreadable_db(&dir);
    let alias = dir.path().join("report.json");
    fs::hard_link(&db, &alias).expect("hard link");
    let before = fs::read(&db).expect("read planted db");

    let output = run_oracle(&[
        std::ffi::OsStr::new("--calibrate"),
        std::ffi::OsStr::new("--db"),
        db.as_os_str(),
        std::ffi::OsStr::new("--sample"),
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new("--seed"),
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new("--infinity"),
        std::ffi::OsStr::new("http://127.0.0.1:1"),
        std::ffi::OsStr::new("--out"),
        alias.as_os_str(),
    ]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "an --out that is a hard link to --db must be refused; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("refusing to run, nothing was written"),
        "the refusal must come from the guard, before any run: stderr: {stderr}"
    );
    assert_eq!(
        fs::read(&db).expect("read db after refusal"),
        before,
        "the database must be untouched after a refused invocation"
    );
}
