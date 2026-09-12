//! R5-B3 (#127, control-plane review of #121a deferred to T5) and the two
//! control-plane rulings the #0 report produced.
//!
//! `examples/w6_calib_source.rs` copies the sampled sessions' raw-mirror
//! blobs into a fake `HOME` for the cosine calibration to ingest. Its whole
//! value is that the source tree provably *is* the corpus the identity
//! document names: the blob must exist, its bytes must hash to what the
//! manifest declares, and the conversation's identity must match the library
//! row. Every one of those has a way to be silently wrong (a dropped blob
//! reads as "no session", a stale manifest reads as "the bytes are fine"), so
//! each is pinned here by driving the built binary against a synthetic
//! two-conversation corpus and checking the exit code, the named failure, and
//! -- for the failure cases -- that **nothing was written at all**.
//!
//! `w6_calib_source` is an `[[example]]`, not the `[[bin]]` target `cass`, so
//! cargo injects no `CARGO_BIN_EXE_<name>` for it: `calib_binary_path` below
//! derives the path cargo actually builds examples to (an `examples/`
//! directory sibling to this test binary's own `deps/`, both under the same
//! `target/<profile>/`), the same convention
//! `tests/w6_normalize_dump_guard.rs` uses. Build it first (same mandatory
//! env/feature flags as everything else in this PR):
//!   cargo build --example w6_calib_source \
//!     --no-default-features --features qr,encryption,infinity
//! before `cargo test --test w6_calib_source_guard ...` (matching profiles
//! matters: this test looks in ITS OWN profile's `examples/` dir).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const CODEX_BYTES: &[u8] = b"codex rollout blob payload\n";
const CLAUDE_BYTES: &[u8] = b"claude transcript blob payload\n";
const ORPHAN_BYTES: &[u8] = b"a session whose mirror snapshot count disagrees\n";

fn calib_binary_path() -> PathBuf {
    let test_exe = std::env::current_exe().expect("current_exe");
    let deps_dir = test_exe.parent().expect("deps dir has a parent");
    let profile_dir = deps_dir.parent().expect("profile dir has a parent");
    let candidate = profile_dir.join("examples").join("w6_calib_source");
    assert!(
        candidate.is_file(),
        "w6_calib_source example binary not found at {candidate:?} -- build it first: \
         cargo build --example w6_calib_source --no-default-features \
         --features qr,encryption,infinity (with this PR's mandatory CARGO_* env vars)"
    );
    candidate
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn blob_rel(hash: &str) -> String {
    format!("blobs/blake3/{}/{hash}.raw", &hash[..2])
}

struct Fixture {
    root: tempfile::TempDir,
}

struct ConversationSpec {
    id: i64,
    agent_slug: &'static str,
    external_id: &'static str,
    source_path: &'static str,
    rel_path: &'static str,
    db_messages: usize,
    /// What the mirror manifest claims for this conversation. Equal to
    /// `db_messages` for a selectable conversation; different for one the
    /// snapshot rule must exclude.
    manifest_message_count: usize,
    bytes: &'static [u8],
}

fn specs() -> Vec<ConversationSpec> {
    vec![
        ConversationSpec {
            id: 1,
            agent_slug: "codex",
            external_id: "2026/05/28/rollout-x",
            source_path: "/fake-home/.codex/sessions/2026/05/28/rollout-x.jsonl",
            rel_path: ".codex/sessions/2026/05/28/rollout-x.jsonl",
            db_messages: 3,
            manifest_message_count: 3,
            bytes: CODEX_BYTES,
        },
        ConversationSpec {
            id: 2,
            agent_slug: "claude_code",
            external_id: "-proj/uuid-1.jsonl",
            source_path: "/fake-home/.claude/projects/-proj/uuid-1.jsonl",
            rel_path: ".claude/projects/-proj/uuid-1.jsonl",
            db_messages: 2,
            manifest_message_count: 2,
            bytes: CLAUDE_BYTES,
        },
    ]
}

/// The third conversation the snapshot rule must exclude: its mirror snapshot
/// carries a message count the library row does not have, so no blob can be
/// chosen for it.
fn orphan_spec() -> ConversationSpec {
    ConversationSpec {
        id: 3,
        agent_slug: "codex",
        external_id: "2026/05/29/rollout-orphan",
        source_path: "/fake-home/.codex/sessions/2026/05/29/rollout-orphan.jsonl",
        rel_path: ".codex/sessions/2026/05/29/rollout-orphan.jsonl",
        db_messages: 5,
        manifest_message_count: 4,
        bytes: ORPHAN_BYTES,
    }
}

impl Fixture {
    fn new(include_orphan: bool) -> Self {
        let root = tempfile::TempDir::new().expect("tempdir");
        let dir = root.path();

        let mut all = specs();
        if include_orphan {
            all.push(orphan_spec());
        }

        let conn = rusqlite::Connection::open(dir.join("db.sqlite")).expect("create fixture db");
        conn.execute_batch(
            "CREATE TABLE agents(id INTEGER PRIMARY KEY, slug TEXT NOT NULL);
             CREATE TABLE conversations(id INTEGER PRIMARY KEY, agent_id INTEGER NOT NULL, source_id TEXT NOT NULL,
                                        external_id TEXT, source_path TEXT NOT NULL);
             CREATE TABLE messages(id INTEGER PRIMARY KEY, conversation_id INTEGER NOT NULL, idx INTEGER NOT NULL, content TEXT NOT NULL);
             INSERT INTO agents VALUES(1, 'codex');
             INSERT INTO agents VALUES(2, 'claude_code');",
        )
        .expect("schema");
        let mut message_id = 0i64;
        for spec in &all {
            let agent_id = if spec.agent_slug == "codex" { 1 } else { 2 };
            conn.execute(
                "INSERT INTO conversations(id, agent_id, source_id, external_id, source_path) VALUES(?1, ?2, 'local', ?3, ?4)",
                rusqlite::params![spec.id, agent_id, spec.external_id, spec.source_path],
            )
            .expect("insert conversation");
            for idx in 0..spec.db_messages {
                message_id += 1;
                conn.execute(
                    "INSERT INTO messages(id, conversation_id, idx, content) VALUES(?1, ?2, ?3, ?4)",
                    rusqlite::params![message_id, spec.id, idx as i64, format!("message {message_id} of conversation {}", spec.id)],
                )
                .expect("insert message");
            }
        }

        let mirror = dir.join("mirror");
        fs::create_dir_all(mirror.join("manifests")).expect("manifests dir");
        for spec in &all {
            let hash = blake3_hex(spec.bytes);
            let rel = blob_rel(&hash);
            let blob_path = mirror.join(&rel);
            fs::create_dir_all(blob_path.parent().expect("blob parent")).expect("blob dir");
            fs::write(&blob_path, spec.bytes).expect("write blob");
            // The mirror's own original_path is a *different* root holding the
            // same session-relative path -- the relation R5-B3's fourth
            // assertion pins.
            let original_path = spec.source_path.replace("/fake-home", "/real-home");
            let manifest = serde_json::json!({
                "schema_version": 1,
                "manifest_kind": "cass_raw_session_mirror_v1",
                "manifest_id": format!("manifest-{}", spec.id),
                "blob_hash_algorithm": "blake3",
                "blob_relative_path": rel,
                "blob_blake3": hash,
                "blob_size_bytes": spec.bytes.len(),
                "provider": spec.agent_slug,
                "source_id": "local",
                "original_path": original_path,
                "captured_at_ms": 1_700_000_000_000i64,
                "db_links": [
                    {"conversation_id": spec.id, "message_count": spec.manifest_message_count, "source_path": spec.source_path}
                ],
            });
            fs::write(
                mirror.join("manifests").join(format!("manifest-{}.json", spec.id)),
                serde_json::to_vec_pretty(&manifest).expect("render manifest"),
            )
            .expect("write manifest");
        }

        let identity = serde_json::json!({
            "db": dir.join("db.sqlite").display().to_string(),
            "mirror": dir.display().to_string(),
            "seed": 6,
            "population_size": 1_000,
            "sample_size": 2,
            "message_ids": [1, 2],
            "conversations": all.iter().map(|s| serde_json::json!({
                "conversation_id": s.id,
                "source_id": "local",
                "agent_slug": s.agent_slug,
                "external_id": s.external_id,
                "source_path": s.source_path,
            })).collect::<Vec<_>>(),
        });
        fs::write(dir.join("identity.json"), serde_json::to_vec_pretty(&identity).expect("render identity")).expect("write identity");

        Self { root }
    }

    fn dir(&self) -> &Path {
        self.root.path()
    }

    fn run(&self, extra: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(calib_binary_path());
        cmd.arg("--identity")
            .arg(self.dir().join("identity.json"))
            .arg("--db")
            .arg(self.dir().join("db.sqlite"))
            .arg("--mirror")
            .arg(self.dir().join("mirror"))
            .arg("--out")
            .arg(self.dir().join("out"))
            .arg("--manifest")
            .arg(self.dir().join("calib-sample.json"));
        for a in extra {
            cmd.arg(a);
        }
        cmd.output().expect("spawn w6_calib_source")
    }

    fn report(&self) -> serde_json::Value {
        let bytes = fs::read(self.dir().join("calib-sample.json")).expect("calib-sample.json exists");
        serde_json::from_slice(&bytes).expect("calib-sample.json parses")
    }

    fn written_files(&self) -> Vec<String> {
        let out = self.dir().join("out");
        let mut found = Vec::new();
        let mut stack = vec![out];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else { continue };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else {
                    found.push(path.strip_prefix(self.dir()).expect("under tempdir").display().to_string());
                }
            }
        }
        found.sort();
        found
    }
}

fn stderr_of(out: &std::process::Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn copies_the_selected_sessions_into_the_connector_layout() {
    let fixture = Fixture::new(false);
    let out = fixture.run(&["--sample", "2", "--seed", "6"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_of(&out));
    assert_eq!(
        fixture.written_files(),
        vec![
            "out/.claude/projects/-proj/uuid-1.jsonl".to_string(),
            "out/.codex/sessions/2026/05/28/rollout-x.jsonl".to_string(),
        ],
        "the tree must reproduce each connector's own dot-directory layout"
    );
    let codex = fs::read(fixture.dir().join("out/.codex/sessions/2026/05/28/rollout-x.jsonl")).expect("codex blob copied");
    assert_eq!(codex, CODEX_BYTES, "the copied bytes must be the mirror blob's bytes, not a re-encode");

    let report = fixture.report();
    assert_eq!(report["selected_conversations"], 2);
    assert_eq!(report["selected_message_count"], 5);
    assert_eq!(report["excluded_ambiguous_multi_blob"].as_array().map(Vec::len), Some(0));
    let sessions = report["sessions"].as_array().expect("sessions array");
    assert_eq!(sessions.len(), 2);
    // Selection is smallest-first (ruling 5), so the 2-message claude session
    // leads; locate the codex row by identity rather than by position.
    let codex_row = sessions
        .iter()
        .find(|s| s["conversation_id"] == 1)
        .unwrap_or_else(|| panic!("no session row for conversation 1: {report}"));
    assert_eq!(sessions[0]["conversation_id"], 2, "smallest-first ordering: {report}");
    assert_eq!(codex_row["rel_path"], ".codex/sessions/2026/05/28/rollout-x.jsonl");
    assert_eq!(codex_row["conversation_id"], 1);
    assert_eq!(codex_row["blob_sha256"], sha256_hex(CODEX_BYTES));
    assert_eq!(codex_row["blob_blake3"], blake3_hex(CODEX_BYTES));
    assert_eq!(codex_row["db_message_count"], 3);
    assert_eq!(codex_row["blob_message_count"], 3);
}

#[test]
fn a_missing_blob_is_named_and_nothing_is_written() {
    let fixture = Fixture::new(false);
    let hash = blake3_hex(CODEX_BYTES);
    fs::remove_file(fixture.dir().join("mirror").join(blob_rel(&hash))).expect("remove blob");

    let out = fixture.run(&[]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_of(&out));
    let err = stderr_of(&out);
    assert!(err.contains("blob_missing"), "must name the failing assertion: {err}");
    assert!(err.contains("conversation 1"), "must name the conversation: {err}");
    assert!(
        fixture.written_files().is_empty(),
        "a failed R5-B3 gate must not leave a half-populated tree, found {:?}",
        fixture.written_files()
    );
    assert!(!fixture.dir().join("calib-sample.json").exists(), "no selection document on a failed run");
}

#[test]
fn a_manifest_whose_blake3_does_not_match_its_blob_is_refused() {
    let fixture = Fixture::new(false);
    let manifest_path = fixture.dir().join("mirror/manifests/manifest-1.json");
    let mut manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest")).expect("parse manifest");
    manifest["blob_blake3"] = serde_json::Value::String("0".repeat(64));
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).expect("render")).expect("write manifest");

    let out = fixture.run(&[]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_of(&out));
    let err = stderr_of(&out);
    assert!(err.contains("blob_blake3_mismatch"), "must name the failing assertion: {err}");
    assert!(fixture.written_files().is_empty(), "found {:?}", fixture.written_files());
}

#[test]
fn an_identity_that_disagrees_with_the_library_is_refused() {
    let fixture = Fixture::new(false);
    let identity_path = fixture.dir().join("identity.json");
    let mut identity: serde_json::Value = serde_json::from_slice(&fs::read(&identity_path).expect("read identity")).expect("parse identity");
    identity["conversations"][1]["external_id"] = serde_json::Value::String("some-other-session.jsonl".into());
    fs::write(&identity_path, serde_json::to_vec_pretty(&identity).expect("render")).expect("write identity");

    let out = fixture.run(&[]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr_of(&out));
    let err = stderr_of(&out);
    assert!(err.contains("identity_mismatch"), "must name the failing assertion: {err}");
    assert!(err.contains("conversation 2"), "must name the conversation: {err}");
    assert!(fixture.written_files().is_empty(), "found {:?}", fixture.written_files());
}

#[test]
fn a_conversation_whose_snapshot_count_disagrees_is_excluded_not_guessed() {
    let fixture = Fixture::new(true);
    let out = fixture.run(&[]);
    assert_eq!(out.status.code(), Some(0), "an unselectable conversation is not a gate failure; stderr: {}", stderr_of(&out));

    let report = fixture.report();
    let excluded = report["excluded_ambiguous_multi_blob"].as_array().expect("excluded array");
    assert_eq!(excluded.len(), 1, "exactly the conversation with no matching snapshot is excluded: {report}");
    assert_eq!(excluded[0]["conversation_id"], 3);
    assert_eq!(excluded[0]["db_message_count"], 5);
    assert_eq!(excluded[0]["link_message_counts"][0], 4);
    assert_eq!(report["selected_conversations"], 2, "the excluded conversation must not be selected");
    assert!(
        !fixture.dir().join("out/.codex/sessions/2026/05/29/rollout-orphan.jsonl").exists(),
        "the excluded conversation's blob must not be materialized"
    );
}

#[test]
fn a_sample_or_seed_that_disagrees_with_the_identity_document_is_refused() {
    let fixture = Fixture::new(false);
    let out = fixture.run(&["--sample", "3"]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr_of(&out));
    assert!(stderr_of(&out).contains("disagrees with the identity document"), "stderr: {}", stderr_of(&out));

    let out = fixture.run(&["--seed", "7"]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr_of(&out));
    assert!(stderr_of(&out).contains("disagrees with the identity document"), "stderr: {}", stderr_of(&out));

    let out = fixture.run(&["--sample", "2", "--seed", "6"]);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", stderr_of(&out));
}

#[test]
fn an_existing_manifest_is_never_silently_overwritten() {
    let fixture = Fixture::new(false);
    fs::write(fixture.dir().join("calib-sample.json"), b"{}").expect("pre-existing manifest");
    let out = fixture.run(&[]);
    assert_eq!(out.status.code(), Some(2), "stderr: {}", stderr_of(&out));
    assert!(stderr_of(&out).contains("already exists"), "stderr: {}", stderr_of(&out));
    assert_eq!(fs::read(fixture.dir().join("calib-sample.json")).expect("read"), b"{}");
}
