//! Pinned legacy-package reader and private output admission.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::types::*;
use crate::search::regression_io::{RegressionIoContext, validate_private_run_root};

const QIDS: [&str; 9] = [
    "N01", "N02", "N03", "N04", "N05", "N06", "N07", "N08", "N12",
];

fn require(condition: bool, code: &'static str) -> Result<()> {
    if !condition {
        bail!(code);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(super) fn safe_relative(value: &str) -> Result<()> {
    require(
        !value.is_empty()
            && !value.contains('\\')
            && value.split('/').all(|part| {
                !matches!(part, "" | "." | "..")
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._~+@=-".contains(&b))
            }),
        "INPUT_PATH_ESCAPE",
    )
}

fn guarded_path(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        require(
            !matches!(component, Component::ParentDir),
            "INPUT_PATH_ESCAPE",
        )?;
        prefix.push(component);
        require(
            !fs::symlink_metadata(&prefix)
                .context("INPUT_PATH_UNAVAILABLE")?
                .file_type()
                .is_symlink(),
            "INPUT_PATH_SYMLINK",
        )?;
    }
    absolute.canonicalize().context("INPUT_PATH_UNAVAILABLE")
}

struct FileRead {
    path: PathBuf,
    bytes: Vec<u8>,
    before: fs::Metadata,
    opened: fs::Metadata,
    after: fs::Metadata,
}

/// The only descriptor reader. Legacy callers retain their original policy.
fn read_file_with_evidence(path: &Path, bundle_file: bool) -> Result<FileRead> {
    let path = guarded_path(path)?;
    let before = fs::symlink_metadata(&path).context("INPUT_FILE_UNAVAILABLE")?;
    require(before.is_file(), "INPUT_FILE_NOT_REGULAR")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(!bundle_file || before.nlink() == 1, "INPUT_FILE_HARDLINK")?;
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Linux O_NOFOLLOW: do not follow a final component replaced after lstat.
        options.custom_flags(0x20000);
    }
    let mut file = options.open(&path).context("INPUT_FILE_UNAVAILABLE")?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            (before.dev(), before.ino()) == (opened.dev(), opened.ino()),
            "INPUT_FILE_CHANGED",
        )?;
    }
    guarded_path(&path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .context("INPUT_FILE_UNAVAILABLE")?;
    let after = fs::symlink_metadata(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            (before.dev(), before.ino()) == (opened.dev(), opened.ino())
                && (opened.dev(), opened.ino()) == (after.dev(), after.ino()),
            "INPUT_FILE_CHANGED",
        )?;
    }
    require(
        after.is_file()
            && !after.file_type().is_symlink()
            && bytes.len() as u64 == before.len()
            && before.len() == after.len()
            && before.modified()? == after.modified()?,
        "INPUT_FILE_CHANGED",
    )?;
    guarded_path(&path)?;
    Ok(FileRead {
        path,
        bytes,
        before,
        opened,
        after,
    })
}

fn read_file(path: &Path, bundle_file: bool) -> Result<Vec<u8>> {
    Ok(read_file_with_evidence(path, bundle_file)?.bytes)
}

fn pinned(path: &Path, sha: &str, code: &'static str, bundle_file: bool) -> Result<Vec<u8>> {
    require(valid_digest(sha), code)?;
    let bytes = read_file(path, bundle_file)?;
    require(digest(&bytes) == sha, code)?;
    Ok(bytes)
}

/// serde_json's Value accepts duplicate keys; this recursive visitor does not.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|v| StrictValue(Value::Number(v)))
                    .ok_or_else(|| E::custom("NON_FINITE_JSON"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(values.into()))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(de::Error::custom("DUPLICATE_JSON_KEY"));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn strict_json(bytes: &[u8]) -> Result<Value> {
    serde_json::from_slice::<StrictValue>(bytes)
        .map(|v| v.0)
        .map_err(|_| anyhow::anyhow!("INPUT_JSON_INVALID"))
}

/// An observed private file, not a request or a caller-constructible proof.
pub(super) struct WirePinned {
    bytes: Vec<u8>,
    value: Value,
    observed_sha256: String,
    _identity: (fs::Metadata, fs::Metadata, fs::Metadata),
}

impl WirePinned {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(super) fn value(&self) -> &Value {
        &self.value
    }
    pub(super) fn observed_file_sha256(&self) -> &str {
        &self.observed_sha256
    }
}

fn private_json(path: &Path, expected: Option<(&str, &'static str)>) -> Result<WirePinned> {
    let parent = path.parent().context("LABEL_RUN_INVALID")?;
    validate_private_run_root(parent)?;
    if let Some((sha, code)) = expected {
        require(valid_digest(sha), code)?;
    }
    let observed = read_file_with_evidence(path, false)?;
    validate_private_run_root(observed.path.parent().context("LABEL_RUN_INVALID")?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = fs::metadata("/proc/self")?.uid();
        let identity = |m: &fs::Metadata| {
            (
                m.dev(),
                m.ino(),
                m.uid(),
                m.mode(),
                m.nlink(),
                m.len(),
                m.mtime(),
                m.mtime_nsec(),
                m.ctime(),
                m.ctime_nsec(),
            )
        };
        require(
            [&observed.before, &observed.opened, &observed.after]
                .iter()
                .all(|m| m.is_file() && m.uid() == owner && m.mode() & 0o777 == 0o600),
            "LABEL_RUN_INVALID",
        )?;
        require(
            identity(&observed.before) == identity(&observed.opened)
                && identity(&observed.opened) == identity(&observed.after),
            "INPUT_FILE_CHANGED",
        )?;
    }
    let observed_sha256 = digest(&observed.bytes);
    if let Some((sha, code)) = expected {
        require(observed_sha256 == sha, code)?;
    }
    let value = strict_json(&observed.bytes)?;
    Ok(WirePinned {
        bytes: observed.bytes,
        value,
        observed_sha256,
        _identity: (observed.before, observed.opened, observed.after),
    })
}

pub(super) fn read_private_pinned_json(
    path: &Path,
    expected_sha256: &str,
    mismatch_code: &'static str,
) -> Result<WirePinned> {
    private_json(path, Some((expected_sha256, mismatch_code)))
}

pub(super) fn read_private_json(path: &Path) -> Result<WirePinned> {
    private_json(path, None)
}

fn json_lines(bytes: &[u8]) -> Result<Vec<Value>> {
    std::str::from_utf8(bytes)
        .context("INPUT_JSON_INVALID")?
        .lines()
        .map(|line| strict_json(line.as_bytes()))
        .collect()
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key].as_str().context("INPUT_SCHEMA_INVALID")
}

fn schema(value: &Value, expected: &str) -> Result<()> {
    require(value["schema"] == expected, "INPUT_SCHEMA_INVALID")
}

fn resolve<'a>(assets: &'a [Asset], reference: &str) -> Result<&'a Asset> {
    if let Some(asset) = assets.iter().find(|asset| asset.source_path == reference) {
        return Ok(asset);
    }
    let mut found = assets.iter().filter(|asset| asset.path == reference);
    let asset = found.next().context("INPUT_ASSET_UNREGISTERED")?;
    require(
        found.all(|other| other.sha256 == asset.sha256 && other.bytes == asset.bytes),
        "INPUT_ASSET_AMBIGUOUS",
    )?;
    Ok(asset)
}

fn role<'a>(assets: &'a [Asset], name: &str) -> Result<&'a Asset> {
    let mut found = assets
        .iter()
        .filter(|asset| asset.roles.iter().any(|r| r == name));
    let asset = found.next().context("INPUT_ROLE_MISSING")?;
    require(found.next().is_none(), "INPUT_ROLE_AMBIGUOUS")?;
    Ok(asset)
}

fn reference<'a>(manifest: &Value, assets: &'a [Asset], name: &str) -> Result<&'a Asset> {
    let entry = &manifest["files"][name];
    let asset = resolve(assets, string(entry, "path")?)?;
    require(
        entry["sha256"] == asset.sha256,
        "INPUT_ASSET_DIGEST_MISMATCH",
    )?;
    Ok(asset)
}

/// Re-read an admitted registry reference through the same guarded descriptor
/// and bundle pin as input admission. A historical absolute name is only a
/// registry lookup key. It never becomes a filesystem path.
pub(crate) fn read_registered_asset(inputs: &ValidatedInputs, reference: &str) -> Result<Vec<u8>> {
    let asset = resolve(&inputs.assets, reference)?;
    safe_relative(&asset.path)?;
    let bytes = pinned(
        &inputs.suite_root.join(&asset.path),
        &asset.sha256,
        "INPUT_ASSET_DIGEST_MISMATCH",
        true,
    )?;
    require(
        bytes.len() as u64 == asset.bytes,
        "INPUT_ASSET_BYTES_MISMATCH",
    )?;
    Ok(bytes)
}

/// An explicitly selected external pool-binding file is independently pinned.
/// Parse exactly the descriptor bytes that supplied the verified file hash.
pub(crate) fn read_pinned_json(path: &Path, sha: &str) -> Result<Value> {
    strict_json(&pinned(path, sha, "POOL_BINDING_MISMATCH", false)?)
}

/// Verify old physical file SHA values before constructing a readonly view.
pub(crate) fn validate_inputs(options: &InputOptions) -> Result<ValidatedInputs> {
    let root = guarded_path(&options.suite)?;
    require(root.is_dir(), "SUITE_ROOT_NOT_DIRECTORY")?;
    let suite_bytes = pinned(
        &root.join("SUITE-MANIFEST.json"),
        &options.suite_sha256,
        "SUITE_DIGEST_MISMATCH",
        true,
    )?;
    let suite = strict_json(&suite_bytes)?;
    schema(&suite, "cass.regression.suite-manifest.v1")?;
    let fields = [
        "schema",
        "suite_id",
        "stage",
        "mode",
        "source_inventory_sha256",
        "query_order",
        "candidate_slots",
        "label_counts",
        "runtime_prefix_map",
        "files",
        "limits",
    ];
    require(
        suite.as_object().is_some_and(|object| {
            object.len() == fields.len() && fields.iter().all(|key| object.contains_key(*key))
        }),
        "SUITE_FIELD_SET_INVALID",
    )?;
    require(
        suite["stage"] == "assets_only"
            && suite["candidate_slots"] == 1800
            && suite["query_order"] == json!(QIDS),
        "SUITE_IDENTITY_MISMATCH",
    )?;
    let inventory_sha = string(&suite, "source_inventory_sha256")?;
    let inventory = strict_json(&pinned(
        &root.join("SOURCE-INVENTORY.json"),
        inventory_sha,
        "SOURCE_INVENTORY_DIGEST_MISMATCH",
        true,
    )?)?;
    schema(&inventory, "cass.regression.source-inventory.v1")?;
    for (key, suite_key) in [
        ("suite_id", "suite_id"),
        ("mode", "mode"),
        ("query_order", "query_order"),
        ("candidate_slots", "candidate_slots"),
        ("labels", "label_counts"),
        ("runtime_prefix_map", "runtime_prefix_map"),
        ("files", "files"),
        ("limits", "limits"),
    ] {
        require(
            inventory[key] == suite[suite_key],
            "SOURCE_INVENTORY_IDENTITY_MISMATCH",
        )?;
    }
    let files = suite["files"].as_array().context("INPUT_SCHEMA_INVALID")?;
    let mut assets = Vec::new();
    let mut paths = BTreeMap::new();
    let mut sources = HashSet::new();
    let mut bytes_by_path = BTreeMap::new();
    for entry in files {
        require(
            entry.as_object().is_some_and(|object| {
                object.len() == 5
                    && ["source_path", "path", "sha256", "bytes", "roles"]
                        .iter()
                        .all(|key| object.contains_key(*key))
            }),
            "INPUT_ASSET_SCHEMA_INVALID",
        )?;
        let asset: Asset =
            serde_json::from_value(entry.clone()).context("INPUT_ASSET_SCHEMA_INVALID")?;
        safe_relative(&asset.path)?;
        require(
            !asset.source_path.is_empty() && valid_digest(&asset.sha256),
            "INPUT_ASSET_SCHEMA_INVALID",
        )?;
        require(
            sources.insert(asset.source_path.clone()),
            "INPUT_ASSET_AMBIGUOUS",
        )?;
        let identity = (asset.sha256.clone(), asset.bytes);
        if let Some(previous) = paths.insert(asset.path.clone(), identity.clone()) {
            require(previous == identity, "INPUT_ASSET_AMBIGUOUS")?;
        }
        let bytes = pinned(
            &root.join(&asset.path),
            &asset.sha256,
            "INPUT_ASSET_DIGEST_MISMATCH",
            true,
        )?;
        require(
            bytes.len() as u64 == asset.bytes,
            "INPUT_ASSET_BYTES_MISMATCH",
        )?;
        // Keep only the old reader's metadata, never candidate plaintext.
        if asset.roles.iter().any(|r| {
            matches!(
                r.as_str(),
                "input_manifest" | "windows" | "span_proofs" | "labels" | "labels_freeze"
            )
        }) {
            bytes_by_path.insert(asset.path.clone(), bytes);
        }
        assets.push(asset);
    }
    let metadata = |asset: &Asset| -> Result<&[u8]> {
        bytes_by_path
            .get(&asset.path)
            .map(Vec::as_slice)
            .context("INPUT_METADATA_ROLE_INVALID")
    };
    let input_asset = role(&assets, "input_manifest")?;
    let manifest = strict_json(metadata(input_asset)?)?;
    schema(&manifest, "cass.pr3.default-input.v1")?;
    require(
        manifest["query_order"] == json!(QIDS)
            && manifest["pool_limit"]
                .as_u64()
                .is_some_and(|limit| limit >= 200),
        "INPUT_MANIFEST_IDENTITY_MISMATCH",
    )?;
    let windows_asset = reference(&manifest, &assets, "windows")?;
    require(
        windows_asset.path == role(&assets, "windows")?.path,
        "INPUT_ROLE_IDENTITY_MISMATCH",
    )?;
    let spans_asset = reference(&manifest, &assets, "span_proofs")?;
    let window_values = json_lines(metadata(windows_asset)?)?;
    require(window_values.len() == 9, "WINDOW_SET_INVALID")?;
    let mut windows = Vec::new();
    for (qid, value) in QIDS.iter().zip(window_values) {
        require(
            value["items"].as_array().is_some_and(|items| {
                items.iter().all(|item| {
                    item.get("fallback_reason").is_some() && item.get("conversation_id").is_some()
                })
            }),
            "WINDOW_SCHEMA_INVALID",
        )?;
        let window: InputWindow = serde_json::from_value(value).context("WINDOW_SCHEMA_INVALID")?;
        require(
            window.qid == *qid
                && !window.query.is_empty()
                && digest(window.query.as_bytes()) == window.query_sha256,
            "WINDOW_QUERY_BINDING_MISMATCH",
        )?;
        require(window.items.len() == 200, "WINDOW_SLOT_COUNT_INVALID")?;
        let mut ids = HashSet::new();
        for (index, slot) in window.items.iter().enumerate() {
            require(slot.rank == index + 1, "WINDOW_RANK_INVALID")?;
            require(
                !matches!(&slot.message_id, MessageId::Text(s) if s.is_empty())
                    && ids.insert(slot.message_id.clone()),
                "WINDOW_MESSAGE_ID_INVALID",
            )?;
            let text = resolve(&assets, &slot.text_path)?;
            require(
                text.sha256 == slot.text_sha256
                    && text.bytes == slot.bytes
                    && valid_digest(&slot.source_sha256),
                "WINDOW_TEXT_BINDING_MISMATCH",
            )?;
            require(
                slot.original_score.as_f64().is_some_and(f64::is_finite),
                "WINDOW_SCORE_INVALID",
            )?;
        }
        windows.push(window);
    }
    let spans = json_lines(metadata(spans_asset)?)?;
    require(spans.len() == 9, "SPAN_SET_INVALID")?;
    let mut seen_spans = HashSet::new();
    for span in spans {
        let qid = string(&span, "qid")?;
        require(seen_spans.insert(qid.to_string()), "SPAN_SET_INVALID")?;
        let window = windows
            .iter()
            .find(|w| w.qid == qid)
            .context("SPAN_SET_INVALID")?;
        let items = span["items"].as_array().context("SPAN_BINDING_MISMATCH")?;
        require(items.len() == 200, "SPAN_BINDING_MISMATCH")?;
        let mut ranks = HashSet::new();
        for item in items {
            let rank = item["rank"].as_u64().context("SPAN_BINDING_MISMATCH")? as usize;
            let mid: MessageId = serde_json::from_value(item["message_id"].clone())
                .context("SPAN_BINDING_MISMATCH")?;
            require(
                ranks.insert(rank)
                    && window
                        .items
                        .get(rank.wrapping_sub(1))
                        .is_some_and(|slot| slot.message_id == mid),
                "SPAN_BINDING_MISMATCH",
            )?;
        }
    }
    let labels_asset = role(&assets, "labels")?;
    require(
        guarded_path(&options.labels)? == guarded_path(&root.join(&labels_asset.path))?
            && options.labels_sha256 == labels_asset.sha256,
        "LABEL_FILE_IDENTITY_MISMATCH",
    )?;
    let label_bytes = metadata(labels_asset)?;
    let labels = strict_json(label_bytes)?;
    schema(&labels, "cass.pr3.default-labels.v1")?;
    require(
        labels["input_manifest_sha256"] == input_asset.sha256,
        "LABEL_INPUT_BINDING_MISMATCH",
    )?;
    let policy = string(&labels, "label_policy_sha256")?;
    require(valid_digest(policy), "LABEL_POLICY_INVALID")?;
    let rows = labels["rows"].as_array().context("LABEL_ROWS_INVALID")?;
    require(rows.len() == 1800, "LABEL_COVERAGE_INVALID")?;
    let mut occupied = HashSet::new();
    let mut records = Vec::new();
    let mut keys = BTreeMap::new();
    let mut label_counts =
        BTreeMap::from([("direct", 0u64), ("partial", 0), ("none", 0), ("unsure", 0)]);
    for row in rows {
        let qid = string(row, "qid")?;
        let rank = row["rank"]
            .as_u64()
            .context("LABEL_SLOT_BINDING_MISMATCH")? as usize;
        let window = windows
            .iter()
            .find(|w| w.qid == qid)
            .context("LABEL_SLOT_BINDING_MISMATCH")?;
        let slot = window
            .items
            .get(rank.wrapping_sub(1))
            .context("LABEL_SLOT_BINDING_MISMATCH")?;
        let mid: MessageId = serde_json::from_value(row["message_id"].clone())
            .context("LABEL_SLOT_BINDING_MISMATCH")?;
        require(
            occupied.insert((qid.to_string(), rank))
                && mid == slot.message_id
                && row["query_sha256"] == window.query_sha256
                && row["text_sha256"] == slot.text_sha256,
            "LABEL_SLOT_BINDING_MISMATCH",
        )?;
        let label = string(row, "label")?;
        require(
            matches!(label, "direct" | "partial" | "none" | "unsure"),
            "LABEL_VALUE_INVALID",
        )?;
        *label_counts.get_mut(label).context("LABEL_VALUE_INVALID")? += 1;
        require(
            row.get("reason").is_some() && !row["provenance"].is_null(),
            "LABEL_PROVENANCE_INVALID",
        )?;
        require(
            slot.scoreable
                || (label == "unsure"
                    && row["provenance"]
                        .to_string()
                        .contains("structural_unscoreable")),
            "LABEL_UNSCOREABLE_INVALID",
        )?;
        let key = (window.query_sha256.clone(), slot.text_sha256.clone());
        if let Some(previous) = keys.insert(key, label.to_string()) {
            require(previous == label, "LABEL_KEY_CONFLICT")?;
        }
        records.push(LabelRecord {
            key: LabelKey {
                query_sha256: window.query_sha256.clone(),
                label_text_sha256: slot.text_sha256.clone(),
                label_policy_sha256: policy.to_string(),
            },
            value: label.to_string(),
        });
    }
    require(
        suite["label_counts"] == json!(label_counts),
        "LABEL_COUNT_MISMATCH",
    )?;
    let freeze_asset = role(&assets, "labels_freeze")?;
    let freeze = strict_json(metadata(freeze_asset)?)?;
    schema(&freeze, "cass.pr3.default-labels-freeze-manifest.v1")?;
    require(
        freeze["labels_frozen"] == true
            && freeze["labels_sha256"] == labels_asset.sha256
            && freeze["labels_bytes"] == label_bytes.len() as u64
            && freeze["labels_rows"] == 1800
            && freeze["input_manifest_sha256"] == input_asset.sha256
            && freeze["label_policy_sha256"] == policy
            && freeze["not_user_confirmed"] == true
            && freeze["not_an_independent_test_set"] == true,
        "LABEL_FREEZE_BINDING_MISMATCH",
    )?;
    Ok(ValidatedInputs {
        suite_root: root,
        suite_sha256: options.suite_sha256.clone(),
        source_inventory_sha256: inventory_sha.to_string(),
        input_manifest_sha256: input_asset.sha256.clone(),
        windows_file_sha256: windows_asset.sha256.clone(),
        labels_sha256: labels_asset.sha256.clone(),
        label_freeze_sha256: freeze_asset.sha256.clone(),
        label_policy_sha256: policy.to_string(),
        windows,
        labels: records,
        assets,
        not_user_confirmed: true,
        not_an_independent_test_set: true,
    })
}

fn output_admission(options: &OutputOptions, protected: &[PathBuf]) -> Result<PathBuf> {
    safe_relative(&options.run_id)?;
    require(!options.run_id.contains('/'), "RUN_ID_INVALID")?;
    let root = guarded_path(&options.output_root)?;
    validate_private_run_root(&root)?;
    for input in protected {
        let path = guarded_path(input)?;
        let input_root = if path.is_dir() {
            path
        } else {
            path.parent()
                .context("INPUT_PATH_UNAVAILABLE")?
                .to_path_buf()
        };
        require(!root.starts_with(input_root), "OUTPUT_INSIDE_INPUT")?;
    }
    require(
        fs::symlink_metadata(root.join(&options.run_id))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "RUN_ALREADY_EXISTS",
    )?;
    Ok(root)
}

pub(crate) fn create_run_paths(options: &OutputOptions, protected: &[PathBuf]) -> Result<RunPaths> {
    let root = output_admission(options, protected)?;
    let run_root = root.join(&options.run_id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&run_root)
            .context("RUN_CREATE_FAILED")?;
    }
    #[cfg(not(unix))]
    bail!("regression_platform_not_verified");
    validate_private_run_root(&run_root)?;
    Ok(RunPaths {
        cache_root: run_root.join("cache"),
        temp_root: run_root.join("tmp"),
        trace_root: run_root.join("trace"),
        input_report: run_root.join("input-validation.json"),
        run_root,
    })
}

fn write_private(path: &Path, value: &Value) -> Result<()> {
    validate_private_run_root(path.parent().context("OUTPUT_PATH_INVALID")?)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).context("OUTPUT_CREATE_FAILED")?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

pub(crate) fn error_code(error: &anyhow::Error) -> &'static str {
    // Never expose a source pathname, JSON fragment, query or candidate.
    const CODES: &[&str] = &[
        "REGRESSION_MODEL_API_MIGRATION",
        "SOURCE_PRODUCER_UNPROVEN",
        "SOURCE_RECEIPT_DIGEST_MISMATCH",
        "SOURCE_RECEIPT_INVALID",
        "SOURCE_RECEIPT_CLAIM_MISMATCH",
        "EXPECTED_SOURCE_MANIFEST_MISMATCH",
        "EXPECTED_BINDING_INVALID",
        "INPUT_BINDING_POLICY_MISMATCH",
        "GENERATION_BINDING_INVALID",
        "regression_database_digest_mismatch",
        "regression_input_name",
        "regression_input_format",
        "regression_wal_not_finalized",
        "regression_maintenance_lock_busy",
        "regression_maintenance_lock_unavailable",
        "regression_maintenance_lock_changed",
        "regression_input_changed",
        "INDEX_RUN_MAINTENANCE_ACTIVE",
        "INDEX_RUN_STATE_REQUIRES_RECOVERY",
        "INPUT_PATH_ESCAPE",
        "INPUT_PATH_SYMLINK",
        "INPUT_PATH_UNAVAILABLE",
        "INPUT_FILE_UNAVAILABLE",
        "INPUT_FILE_NOT_REGULAR",
        "INPUT_FILE_HARDLINK",
        "INPUT_FILE_CHANGED",
        "INPUT_JSON_INVALID",
        "INPUT_SCHEMA_INVALID",
        "SUITE_DIGEST_MISMATCH",
        "SUITE_ROOT_NOT_DIRECTORY",
        "SUITE_FIELD_SET_INVALID",
        "SUITE_IDENTITY_MISMATCH",
        "SOURCE_INVENTORY_DIGEST_MISMATCH",
        "SOURCE_INVENTORY_IDENTITY_MISMATCH",
        "INPUT_ASSET_SCHEMA_INVALID",
        "INPUT_ASSET_AMBIGUOUS",
        "INPUT_ASSET_UNREGISTERED",
        "INPUT_ASSET_DIGEST_MISMATCH",
        "INPUT_ASSET_BYTES_MISMATCH",
        "INPUT_METADATA_ROLE_INVALID",
        "INPUT_ROLE_MISSING",
        "INPUT_ROLE_AMBIGUOUS",
        "INPUT_ROLE_IDENTITY_MISMATCH",
        "INPUT_MANIFEST_IDENTITY_MISMATCH",
        "WINDOW_SET_INVALID",
        "WINDOW_SCHEMA_INVALID",
        "WINDOW_QUERY_BINDING_MISMATCH",
        "WINDOW_SLOT_COUNT_INVALID",
        "WINDOW_RANK_INVALID",
        "WINDOW_MESSAGE_ID_INVALID",
        "WINDOW_TEXT_BINDING_MISMATCH",
        "WINDOW_SCORE_INVALID",
        "SPAN_SET_INVALID",
        "SPAN_BINDING_MISMATCH",
        "LABEL_FILE_IDENTITY_MISMATCH",
        "LABEL_INPUT_BINDING_MISMATCH",
        "LABEL_POLICY_INVALID",
        "LABEL_ROWS_INVALID",
        "LABEL_COVERAGE_INVALID",
        "LABEL_COUNT_MISMATCH",
        "LABEL_SLOT_BINDING_MISMATCH",
        "LABEL_VALUE_INVALID",
        "LABEL_PROVENANCE_INVALID",
        "LABEL_UNSCOREABLE_INVALID",
        "LABEL_KEY_CONFLICT",
        "LABEL_FREEZE_BINDING_MISMATCH",
        "RUN_ID_INVALID",
        "OUTPUT_INSIDE_INPUT",
        "RUN_ALREADY_EXISTS",
        "RUN_CREATE_FAILED",
        "REQUEST_PROFILE_INVALID",
        "POOL_BINDING_MISMATCH",
        "NON_COMPARABLE_MODE",
        "COMPARE_INPUT_INVALID",
        "EXTERNAL_EXPECTED_BINDING_REQUIRED",
        "EXPECTED_BINDING_FILE_DIGEST_MISMATCH",
        "regression_output_inside_repository",
        "regression_run_root_not_private",
        "regression_platform_not_verified",
    ];
    error
        .chain()
        .find_map(|cause| {
            CODES
                .iter()
                .copied()
                .find(|code| cause.to_string() == *code)
        })
        .unwrap_or("REGRESSION_INPUT_FAILED")
}

pub(crate) fn validate_cutoffs(cutoffs: &[u32]) -> Result<()> {
    require(
        !cutoffs.is_empty()
            && cutoffs.iter().all(|c| *c > 0)
            && cutoffs.iter().collect::<HashSet<_>>().len() == cutoffs.len(),
        "REQUEST_PROFILE_INVALID",
    )
}

fn validate_pool(path: &Path, sha: &str, inputs: &ValidatedInputs) -> Result<()> {
    let pool = strict_json(&pinned(path, sha, "POOL_BINDING_MISMATCH", false)?)?;
    schema(&pool, "cass.regression-fixed-pool.v1")?;
    for (key, expected) in [
        ("suite_sha256", &inputs.suite_sha256),
        ("input_manifest_sha256", &inputs.input_manifest_sha256),
        ("windows_file_sha256", &inputs.windows_file_sha256),
        ("labels_sha256", &inputs.labels_sha256),
        ("label_freeze_sha256", &inputs.label_freeze_sha256),
        ("label_policy_sha256", &inputs.label_policy_sha256),
        ("source_inventory_sha256", &inputs.source_inventory_sha256),
    ] {
        require(pool[key] == *expected, "POOL_BINDING_MISMATCH")?;
    }
    let windows = pool["windows"]
        .as_array()
        .context("POOL_BINDING_MISMATCH")?;
    require(windows.len() == 9, "POOL_BINDING_MISMATCH")?;
    for (window, declared) in inputs.windows.iter().zip(windows) {
        require(
            declared["qid"] == window.qid
                && declared["query_sha256"] == window.query_sha256
                && declared["count"] == 200
                && declared["ordered_pool_sha256"]
                    .as_str()
                    .is_some_and(valid_digest),
            "POOL_BINDING_MISMATCH",
        )?;
    }
    // The ordered-pool byte algorithm belongs to S2-06, not input admission.
    Ok(())
}

fn input_report(mode: &str, inputs: &ValidatedInputs) -> Value {
    json!({"schema":"cass.regression-input-validation.v1", "mode":mode,
        "stage":"INPUT_VALIDATED", "quality_status":"NOT_EVALUATED",
        "suite_sha256":inputs.suite_sha256,"labels_sha256":inputs.labels_sha256,
        "input_manifest_sha256":inputs.input_manifest_sha256,
        "question_count":inputs.windows.len(),"candidate_slots":inputs.labels.len(),
        "not_user_confirmed":inputs.not_user_confirmed,
        "not_an_independent_test_set":inputs.not_an_independent_test_set,
        "dataset":"development-regression-9-small-sample",
        "search_calls":0,"rerank_calls":0,"model_calls":0,
        "ordered_pool_verification":"NOT_EVALUATED", "database_admission":"NOT_EVALUATED"})
}

pub(crate) fn prepare_fixed(
    input: &InputOptions,
    pool: &Path,
    pool_sha: &str,
) -> Result<ValidatedRun> {
    // All metadata and boundary failures precede output creation.
    output_admission(
        &input.output,
        &[
            input.suite.clone(),
            input.labels.clone(),
            pool.to_path_buf(),
        ],
    )?;
    let inputs = validate_inputs(input)?;
    validate_pool(pool, pool_sha, &inputs)?;
    let paths = create_run_paths(
        &input.output,
        &[
            inputs.suite_root.clone(),
            input.labels.clone(),
            pool.to_path_buf(),
        ],
    )?;
    Ok(ValidatedRun {
        inputs,
        paths,
        context: None,
        expected_binding: None,
        expected_binding_file_sha256: None,
        source_manifest: None,
        source_receipt_sha256: None,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceReceipt {
    schema: String,
    producer_id: String,
    verification_policy: String,
    producer_source_sha256: String,
    source_manifest_sha256: String,
    expected_file_count: u64,
    checked: u64,
    passed: bool,
    exit_code: i64,
    failure_count: u64,
    raw_evidence_sha256: String,
}

fn validate_receipt(path: &Path, sha: &str, manifest_sha: &str) -> Result<()> {
    let bytes = pinned(path, sha, "SOURCE_RECEIPT_DIGEST_MISMATCH", false)?;
    let value = strict_json(&bytes).map_err(|_| anyhow::anyhow!("SOURCE_RECEIPT_INVALID"))?;
    let receipt: SourceReceipt =
        serde_json::from_value(value).map_err(|_| anyhow::anyhow!("SOURCE_RECEIPT_INVALID"))?;
    require(
        receipt.schema == "cass.regression-source-receipt.v1"
            && receipt.producer_id == "cass.pr9.verify-corpus"
            && receipt.verification_policy == "cass.pr9.corpus-content-stable-file-v1"
            && [
                &receipt.producer_source_sha256,
                &receipt.source_manifest_sha256,
                &receipt.raw_evidence_sha256,
            ]
            .into_iter()
            .all(|sha| valid_digest(sha)),
        "SOURCE_RECEIPT_INVALID",
    )?;
    require(
        receipt.expected_file_count == 5049
            && receipt.checked == 5049
            && receipt.passed
            && receipt.exit_code == 0
            && receipt.failure_count == 0,
        "SOURCE_RECEIPT_CLAIM_MISMATCH",
    )?;
    require(
        receipt.source_manifest_sha256 == manifest_sha,
        "EXPECTED_SOURCE_MANIFEST_MISMATCH",
    )
}

/// Opens the existing readonly context and retains its lease, without a client.
pub(crate) fn prepare_full(command: &RegressionCommand) -> Result<ValidatedRun> {
    validate_full_profile(command)?;
    let RegressionCommand::FullSearch {
        input,
        database,
        expected_binding,
        expected_binding_sha256,
        source_manifest,
        source_producer_receipt,
        source_producer_receipt_sha256,
        ..
    } = command
    else {
        bail!("REQUEST_PROFILE_INVALID");
    };
    let protected = vec![
        input.suite.clone(),
        input.labels.clone(),
        database.clone(),
        expected_binding.clone(),
        source_manifest.clone(),
        source_producer_receipt.clone(),
    ];
    output_admission(&input.output, &protected)?;
    let inputs = validate_inputs(input)?;
    let manifest_bytes = read_file(source_manifest, false)?;
    let manifest_sha = digest(&manifest_bytes);
    validate_receipt(
        source_producer_receipt,
        source_producer_receipt_sha256,
        &manifest_sha,
    )?;
    // Existing load_expected re-verifies this exact pin before decoding. The
    // precheck adds duplicate-key rejection without changing its policy reader.
    let expected_bytes = pinned(
        expected_binding,
        expected_binding_sha256,
        "EXPECTED_BINDING_FILE_DIGEST_MISMATCH",
        false,
    )?;
    let expected_value = strict_json(&expected_bytes)?;
    require(
        expected_value["source_manifest_sha256"] == manifest_sha,
        "EXPECTED_SOURCE_MANIFEST_MISMATCH",
    )?;
    let paths = create_run_paths(&input.output, &protected)?;
    let admitted: Result<_> = (|| {
        let context = Arc::new(RegressionIoContext::open(database, &paths.run_root)?);
        context.forbid_output_under(&inputs.suite_root)?;
        let expected = crate::search::regression_binding::load_expected(
            expected_binding,
            expected_binding_sha256,
            &context,
        )?;
        crate::search::regression_binding::verify_source_manifest(source_manifest, &manifest_sha)?;
        let expected_db: [u8; 32] = hex::decode(&expected.database_sha256)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("EXPECTED_BINDING_INVALID"))?;
        context.verify_database_digest(&expected_db)?;
        context.admit_index_run()?;
        Ok((context, expected))
    })();
    let (context, expected) = match admitted {
        Ok(value) => value,
        Err(error) => {
            let failure = json!({"schema":"cass.regression-input-validation.v1","mode":"full-search","stage":"INPUT_REJECTED_AFTER_RUN_CREATE","quality_status":"FAILED","failure_code":error_code(&error),"search_calls":0,"rerank_calls":0,"model_calls":0});
            write_private(&paths.run_root.join("input-failure.json"), &failure)?;
            return Err(error);
        }
    };
    Ok(ValidatedRun {
        inputs,
        paths,
        context: Some(context),
        expected_binding: Some(expected),
        expected_binding_file_sha256: Some(expected_binding_sha256.clone()),
        source_manifest: Some(source_manifest.clone()),
        source_receipt_sha256: Some(source_producer_receipt_sha256.clone()),
    })
}

fn validate_full_profile(command: &RegressionCommand) -> Result<()> {
    let RegressionCommand::FullSearch {
        api,
        search_mode,
        vector_search_mode,
        rrf_limit,
        rerank,
        page_size,
        rerank_provider,
        cutoffs,
        ..
    } = command
    else {
        bail!("REQUEST_PROFILE_INVALID");
    };
    validate_cutoffs(cutoffs)?;
    require(!(api.selected() && rerank_provider.is_some()), "REGRESSION_MODEL_API_MIGRATION")?;
    let lexical = *search_mode == crate::search::query::SearchMode::Lexical;
    require(
        *rrf_limit > 0 && lexical == vector_search_mode.is_none(),
        "REQUEST_PROFILE_INVALID",
    )?;
    require(
        match rerank {
            RerankSwitch::Off => page_size.is_none() && rerank_provider.is_none() && api.rerank_profile.is_none(),
            // The local rerank provider is retired: a scored window must name
            // its service in a frozen model-API configuration. The legacy
            // selection no longer satisfies this profile, so a production run
            // without an API config is refused instead of reaching the old
            // service path.
            RerankSwitch::On => {
                page_size.is_some_and(|k| k > 0 && k <= *rrf_limit) && api.selected()
            }
        },
        "REQUEST_PROFILE_INVALID",
    )
}

pub(crate) fn run(command: &RegressionCommand) -> Result<Value> {
    match command {
        RegressionCommand::FixedCandidate {
            input,
            pool_binding,
            pool_binding_sha256,
            cutoffs,
            ..
        } => {
            validate_cutoffs(cutoffs)?;
            let run = prepare_fixed(input, pool_binding, pool_binding_sha256)?;
            let mut report = input_report("fixed-candidate", &run.inputs);
            report["request_profile"] = json!("fixed-package-v1");
            write_private(&run.paths.input_report, &report)?;
            Ok(report)
        }
        RegressionCommand::FullSearch { .. } => {
            let run = prepare_full(command)?;
            let mut report = input_report("full-search", &run.inputs);
            report["database_admission"] = json!("READONLY_CONTEXT_OPEN");
            report["complete_inventory_verification"] = json!("NOT_EVALUATED");
            report["expected_binding_file_sha256"] = json!(run.expected_binding_file_sha256);
            report["source_producer_receipt_sha256"] = json!(run.source_receipt_sha256);
            report["request_profile"] = json!("d5-fixed-filters-v1");
            report["expected_database_sha256"] =
                json!(run.expected_binding.as_ref().map(|b| &b.database_sha256));
            report["source_manifest_sha256"] = json!(
                run.expected_binding
                    .as_ref()
                    .map(|b| &b.source_manifest_sha256)
            );
            write_private(&run.paths.input_report, &report)?;
            Ok(report)
        }
        RegressionCommand::Compare {
            left,
            left_sha256,
            right,
            right_sha256,
            labels,
            labels_sha256,
            output,
            cutoffs,
            ..
        } => {
            validate_cutoffs(cutoffs)?;
            let protected = vec![left.clone(), right.clone(), labels.clone()];
            output_admission(output, &protected)?;
            let left = strict_json(&pinned(left, left_sha256, "COMPARE_INPUT_INVALID", false)?)?;
            let right = strict_json(&pinned(
                right,
                right_sha256,
                "COMPARE_INPUT_INVALID",
                false,
            )?)?;
            schema(&left, "cass.regression-run.v1")?;
            schema(&right, "cass.regression-run.v1")?;
            require(
                matches!(
                    left["mode"].as_str(),
                    Some("full-search" | "fixed-candidate")
                ) && left["mode"] == right["mode"],
                "NON_COMPARABLE_MODE",
            )?;
            let labels = strict_json(&pinned(
                labels,
                labels_sha256,
                "LABEL_FILE_IDENTITY_MISMATCH",
                false,
            )?)?;
            require(
                matches!(
                    labels["schema"].as_str(),
                    Some("cass.pr3.default-labels.v1" | "cass.regression-labels.v1")
                ),
                "INPUT_SCHEMA_INVALID",
            )?;
            require(
                left["labels_sha256"] == labels_sha256.as_str()
                    && right["labels_sha256"] == labels_sha256.as_str(),
                "LABEL_FILE_IDENTITY_MISMATCH",
            )?;
            let paths = create_run_paths(output, &protected)?;
            let report = json!({"schema":"cass.regression-input-validation.v1", "mode":"compare", "stage":"INPUT_VALIDATED", "quality_status":"NOT_EVALUATED", "comparison":"NOT_EVALUATED", "full_run_validation":"NOT_EVALUATED", "validation_scope":"pinned-files-and-mode-only", "labels_sha256":labels_sha256, "left_sha256":left_sha256, "right_sha256":right_sha256, "search_calls":0,"rerank_calls":0,"model_calls":0});
            // Complete run-schema, union and comparison gates belong to S2-08.
            write_private(&paths.input_report, &report)?;
            Ok(report)
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    struct Fixture {
        _root: tempfile::TempDir,
        input: InputOptions,
        pool: PathBuf,
        pool_sha: String,
    }

    fn fixture(fault: &str) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let suite = root.path().join("package");
        let output = root.path().join("output");
        let bindings = root.path().join("bindings");
        for path in [&suite, &output, &bindings] {
            fs::create_dir(path).unwrap();
        }
        fs::set_permissions(&output, fs::Permissions::from_mode(0o700)).unwrap();
        let mut registry = Vec::new();
        let mut add = |relative: &str, bytes: Vec<u8>, roles: &[&str]| -> Value {
            let path = suite.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, &bytes).unwrap();
            let source = format!("/synthetic-frozen/{relative}");
            registry.push(json!({"source_path":source,"path":relative,"sha256":digest(&bytes),"bytes":bytes.len(),"roles":roles}));
            json!({"path":source,"sha256":digest(&bytes)})
        };
        let mut text_refs = Vec::new();
        for index in 1..=200 {
            let text = format!("Synthetic candidate {index}. No private content.");
            let reference = add(
                &format!("assets/pr3/task-18/text/{index}.txt"),
                text.as_bytes().to_vec(),
                &["candidate_text"],
            );
            text_refs.push((reference, text.len()));
        }
        let policy = digest(b"synthetic-label-policy-v1");
        let mut windows = Vec::new();
        let mut spans = Vec::new();
        let mut rows = Vec::new();
        let mut pool_windows = Vec::new();
        for (qindex, qid) in QIDS.iter().enumerate() {
            let query = format!("Synthetic query {qid}");
            let query_sha = digest(query.as_bytes());
            let mut items = Vec::new();
            let mut span_items = Vec::new();
            for index in 1..=200 {
                let mid = if index % 2 == 0 {
                    json!(format!("synthetic-{index}"))
                } else {
                    json!(index)
                };
                let (reference, bytes) = &text_refs[index - 1];
                let item = json!({"rank":index,"message_id":mid,"conversation_id":qindex as i64,"text_path":reference["path"],"text_sha256":reference["sha256"],"bytes":bytes,"source_sha256":digest(b"synthetic-source"),"original_score":1.25,"scoreable":true,"fallback_reason":null});
                items.push(item);
                span_items.push(json!({"rank":index,"message_id":mid}));
                rows.push(json!({"qid":qid,"rank":index,"message_id":mid,"query_sha256":query_sha,"text_sha256":reference["sha256"],"label":"direct","reason":"synthetic judgement","provenance":{"kind":"synthetic"}}));
            }
            if qindex == 0 {
                match fault {
                    "missing_slot" => {
                        items.pop();
                    }
                    "duplicate_rank" => items[1]["rank"] = json!(1),
                    "duplicate_mid" => items[1]["message_id"] = items[0]["message_id"].clone(),
                    "unregistered_text" => {
                        items[0]["text_path"] = json!("/synthetic-frozen/unregistered.txt")
                    }
                    "wrong_query" => items[0]["text_sha256"] = json!(digest(b"unrelated")),
                    "wrong_span" => span_items[0]["message_id"] = json!(999999),
                    "unsure_required" => items[0]["scoreable"] = json!(false),
                    "valid_categories" => items[0]["scoreable"] = json!(false),
                    "missing_fallback" => {
                        items[0].as_object_mut().unwrap().remove("fallback_reason");
                    }
                    _ => {}
                }
            }
            windows.push(json!({"qid":qid,"query":query,"query_sha256":query_sha,"items":items}));
            spans.push(json!({"qid":qid,"items":span_items}));
            pool_windows.push(json!({"qid":qid,"query_sha256":query_sha,"count":200,"ordered_pool_sha256":digest(b"synthetic-pool-not-yet-evaluated")}));
        }
        if fault == "duplicate_qid" {
            windows[1]["qid"] = windows[0]["qid"].clone();
        }
        if fault == "wrong_label" {
            rows[0]["message_id"] = json!(999999);
        }
        if fault == "duplicate_label" {
            rows[1] = rows[0].clone();
        }
        if fault == "valid_categories" {
            rows[0]["label"] = json!("unsure");
            rows[0]["provenance"] = json!({"kind":"structural_unscoreable"});
            rows[1]["label"] = json!("partial");
            rows[2]["label"] = json!("none");
        }
        let encode_lines = |values: &[Value]| -> Vec<u8> {
            values
                .iter()
                .flat_map(|v| {
                    let mut bytes = serde_json::to_vec(v).unwrap();
                    bytes.push(b'\n');
                    bytes
                })
                .collect()
        };
        let window_ref = add(
            "assets/pr3/task-18/out/windows.jsonl",
            encode_lines(&windows),
            &["windows"],
        );
        let span_ref = add(
            "assets/pr3/task-18/out/span_proofs.jsonl",
            encode_lines(&spans),
            &["span_proofs"],
        );
        let manifest = json!({"schema":"cass.pr3.default-input.v1","query_order":QIDS,"pool_limit":200,"source_query_manifest_sha256":digest(b"synthetic-historical-identity"),"files":{"windows":window_ref,"span_proofs":span_ref}});
        let input_ref = add(
            "assets/pr3/task-18/out/INPUT-MANIFEST.json",
            serde_json::to_vec(&manifest).unwrap(),
            &["input_manifest"],
        );
        let input_sha = input_ref["sha256"].as_str().unwrap();
        let labels = json!({"schema":"cass.pr3.default-labels.v1","input_manifest_sha256":if fault == "wrong_input_identity" { digest(b"wrong") } else { input_sha.to_string() },"label_policy_sha256":policy,"rows":rows});
        let label_bytes = serde_json::to_vec(&labels).unwrap();
        let label_sha = digest(&label_bytes);
        add(
            "assets/pr3/task-19m/LABELS.json",
            label_bytes.clone(),
            &["labels"],
        );
        let freeze = json!({"schema":"cass.pr3.default-labels-freeze-manifest.v1","labels_frozen":true,"labels_sha256":label_sha,"labels_bytes":label_bytes.len(),"labels_rows":1800,"input_manifest_sha256":input_sha,"label_policy_sha256":if fault == "wrong_freeze" { digest(b"wrong") } else { policy.clone() },"not_user_confirmed":true,"not_an_independent_test_set":true});
        let freeze_ref = add(
            "assets/pr3/task-19m/LABELS-FREEZE-MANIFEST.json",
            serde_json::to_vec(&freeze).unwrap(),
            &["labels_freeze"],
        );
        drop(add);
        if fault == "asset_escape" {
            registry[0]["path"] = json!("../outside.txt");
        }
        if fault == "asset_alias" {
            let mut alias = registry[0].clone();
            alias["source_path"] = json!("/synthetic-frozen/alternate-source.txt");
            alias["roles"] = json!([]);
            registry.push(alias);
        }
        let counts = if fault == "valid_categories" {
            json!({"direct":1797,"partial":1,"none":1,"unsure":1})
        } else {
            json!({"direct":1800,"partial":0,"none":0,"unsure":0})
        };
        let inventory = json!({"schema":"cass.regression.source-inventory.v1","suite_id":"synthetic-suite-v1","mode":"synthetic","query_order":QIDS,"candidate_slots":1800,"labels":counts,"runtime_prefix_map":{},"files":registry,"limits":{}});
        let inventory_bytes = serde_json::to_vec(&inventory).unwrap();
        let inventory_sha = digest(&inventory_bytes);
        fs::write(suite.join("SOURCE-INVENTORY.json"), inventory_bytes).unwrap();
        let suite_value = json!({"schema":"cass.regression.suite-manifest.v1","suite_id":"synthetic-suite-v1","stage":"assets_only","mode":"synthetic","query_order":QIDS,"candidate_slots":1800,"label_counts":counts,"runtime_prefix_map":{},"files":registry,"limits":{},"source_inventory_sha256":inventory_sha});
        let suite_bytes = serde_json::to_vec(&suite_value).unwrap();
        fs::write(suite.join("SUITE-MANIFEST.json"), &suite_bytes).unwrap();
        let pool = bindings.join("pool.json");
        let pool_bytes = serde_json::to_vec(&json!({"schema":"cass.regression-fixed-pool.v1","suite_sha256":digest(&suite_bytes),"input_manifest_sha256":input_sha,"windows_file_sha256":window_ref["sha256"],"labels_sha256":label_sha,"label_freeze_sha256":freeze_ref["sha256"],"label_policy_sha256":policy,"source_inventory_sha256":inventory_sha,"windows":pool_windows})).unwrap();
        fs::write(&pool, &pool_bytes).unwrap();
        Fixture {
            input: InputOptions {
                suite: suite.clone(),
                suite_sha256: digest(&suite_bytes),
                labels: suite.join("assets/pr3/task-19m/LABELS.json"),
                labels_sha256: label_sha,
                output: OutputOptions {
                    output_root: output,
                    run_id: "synthetic-run".into(),
                },
            },
            pool,
            pool_sha: digest(&pool_bytes),
            _root: root,
        }
    }

    fn command(fixture: &Fixture) -> RegressionCommand {
        RegressionCommand::FixedCandidate {
            api: Default::default(),
            input: fixture.input.clone(),
            pool_binding: fixture.pool.clone(),
            pool_binding_sha256: fixture.pool_sha.clone(),
            rerank_provider: Some(crate::search::rerank::types::ProviderChoice::Qwen3Local),
            cutoffs: vec![5, 10, 20],
        }
    }

    fn full_command(f: &Fixture, fault: &str) -> RegressionCommand {
        let data = f._root.path().join("synthetic-data");
        fs::create_dir(&data).unwrap();
        fs::create_dir_all(data.join("doctor/locks")).unwrap();
        fs::write(data.join("doctor/locks/doctor-repair.lock"), b"").unwrap();
        let database = data.join("agent_search.db");
        let writer = crate::storage::testing::open_writable_for_tests(
            &database,
            crate::storage::api::Profile::Production,
        )
        .unwrap();
        writer.execute_batch("PRAGMA user_version=8; CREATE TABLE synthetic_input(id INTEGER PRIMARY KEY); PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE;").unwrap();
        drop(writer);
        let source_manifest = data.join("source-manifest.json");
        fs::write(
            &source_manifest,
            b"{\"schema\":\"cass.pr9.corpus-manifest.v1\",\"files\":[]}",
        )
        .unwrap();
        let manifest_sha = digest(&fs::read(&source_manifest).unwrap());
        let mut receipt = json!({"schema":"cass.regression-source-receipt.v1","producer_id":"cass.pr9.verify-corpus","verification_policy":"cass.pr9.corpus-content-stable-file-v1","producer_source_sha256":digest(b"synthetic-producer-source"),"source_manifest_sha256":manifest_sha,"expected_file_count":5049,"checked":5049,"passed":true,"exit_code":0,"failure_count":0,"raw_evidence_sha256":digest(b"synthetic-evidence")});
        match fault {
            "unknown_policy" => receipt["verification_policy"] = json!("unapproved-policy"),
            "wrong_schema" => receipt["schema"] = json!("unapproved-schema"),
            "partial" => receipt["checked"] = json!(5048),
            "failed" => receipt["passed"] = json!(false),
            "failed_rc" => receipt["exit_code"] = json!(1),
            "wrong_count_type" => receipt["checked"] = json!(5049.0),
            "wrong_passed_type" => receipt["passed"] = json!(1),
            "extra_field" => receipt["unapproved"] = json!(true),
            "wrong_receipt_manifest" => {
                receipt["source_manifest_sha256"] = json!(digest(b"wrong manifest"))
            }
            _ => {}
        }
        let receipt_path = data.join("source-receipt.json");
        let receipt_bytes = serde_json::to_vec(&receipt).unwrap();
        fs::write(&receipt_path, &receipt_bytes).unwrap();
        let expected = json!({"schema":"cass.regression-input.v1","schema_version":8,"database_sha256":if fault == "wrong_database" { digest(b"wrong database") } else { digest(&fs::read(&database).unwrap()) },"wal_bytes":0,"source_manifest_sha256":if fault == "wrong_expected_manifest" { digest(b"wrong source") } else { manifest_sha.clone() },"message_text_sha256":digest(b"synthetic-message"),"chunk_text_sha256":digest(b"synthetic-chunk"),"retrieval_order_sha256":digest(b"synthetic-order"),"retrieval_layout_sha256":digest(b"synthetic-layout"),"lexical_statistics_sha256":digest(b"synthetic-statistics"),"message_count":0,"conversation_count":0,"chunk_count":0,"canonicalize_version":3,"chunking_policy_version":1,"statistics_policy":"regression-fresh-v1","statistics_encoding":"lexical-stats-v1","consumed_domains":["sqlite:lex_docs/fts_lex","sqlite:active-generation/message_chunks/vec-mirrors"],"generation":{"generation_id":1,"embedder_id":"synthetic-embedder","dim":1,"fingerprint":"00","canonicalize_version":3,"chunking_policy_version":1,"byte_order":"le","vector_revision":0,"audit_status":"passed","vector_domain_instance_id":"00000000000000000000000000000001"}});
        let expected_bytes = serde_json::to_vec(&expected).unwrap();
        let expected_binding = data.join("expected.json");
        fs::write(&expected_binding, &expected_bytes).unwrap();
        RegressionCommand::FullSearch {
            api: Default::default(),
            input: f.input.clone(),
            database,
            expected_binding,
            expected_binding_sha256: if fault == "wrong_expected_pin" {
                digest(b"wrong pin")
            } else {
                digest(&expected_bytes)
            },
            source_manifest,
            source_producer_receipt: receipt_path,
            source_producer_receipt_sha256: if fault == "wrong_receipt_pin" {
                digest(b"wrong receipt")
            } else {
                digest(&receipt_bytes)
            },
            search_mode: crate::search::query::SearchMode::Lexical,
            vector_search_mode: None,
            rrf_limit: 10,
            rerank: RerankSwitch::Off,
            page_size: None,
            rerank_provider: None,
            cutoffs: vec![5, 10, 20],
        }
    }

    #[test]
    fn full_input_context_keeps_readonly_maintenance_lease_without_search() {
        let f = fixture("");
        let cmd = full_command(&f, "");
        let RegressionCommand::FullSearch { database, .. } = &cmd else {
            unreachable!();
        };
        let before = fs::read(database).unwrap();
        let validated = prepare_full(&cmd).unwrap();
        let lock = File::open(
            database
                .parent()
                .unwrap()
                .join("doctor/locks/doctor-repair.lock"),
        )
        .unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&lock).is_err());
        assert!(
            validated
                .context
                .as_ref()
                .unwrap()
                .connection()
                .unwrap()
                .execute("INSERT INTO synthetic_input VALUES(1)", &[])
                .is_err()
        );
        assert!(
            fs::read_dir(&validated.paths.run_root)
                .unwrap()
                .next()
                .is_none()
        );
        assert!(validated.expected_binding.is_some());
        drop(validated);
        fs2::FileExt::try_lock_exclusive(&lock).unwrap();
        assert_eq!(fs::read(database).unwrap(), before);
        assert!(!database.with_file_name("agent_search.db-wal").exists());
        assert!(!database.with_file_name("agent_search.db-shm").exists());
    }

    #[test]
    fn receipt_claims_pins_and_expected_source_reject_before_run_creation() {
        for (fault, code) in [
            ("wrong_receipt_pin", "SOURCE_RECEIPT_DIGEST_MISMATCH"),
            ("unknown_policy", "SOURCE_RECEIPT_INVALID"),
            ("wrong_schema", "SOURCE_RECEIPT_INVALID"),
            ("wrong_count_type", "SOURCE_RECEIPT_INVALID"),
            ("wrong_passed_type", "SOURCE_RECEIPT_INVALID"),
            ("extra_field", "SOURCE_RECEIPT_INVALID"),
            ("partial", "SOURCE_RECEIPT_CLAIM_MISMATCH"),
            ("failed", "SOURCE_RECEIPT_CLAIM_MISMATCH"),
            ("failed_rc", "SOURCE_RECEIPT_CLAIM_MISMATCH"),
            (
                "wrong_receipt_manifest",
                "EXPECTED_SOURCE_MANIFEST_MISMATCH",
            ),
            (
                "wrong_expected_manifest",
                "EXPECTED_SOURCE_MANIFEST_MISMATCH",
            ),
            (
                "wrong_expected_pin",
                "EXPECTED_BINDING_FILE_DIGEST_MISMATCH",
            ),
        ] {
            let f = fixture("");
            let cmd = full_command(&f, fault);
            let error = run(&cmd).unwrap_err();
            assert_eq!(error_code(&error), code, "fault {fault}");
            assert!(
                fs::read_dir(&f.input.output.output_root)
                    .unwrap()
                    .next()
                    .is_none()
            );
            println!("RECEIPT_CASE fault={fault} result=Err code={code} report=absent");
        }
    }

    #[test]
    fn database_identity_failure_preserves_named_partial_output() {
        let f = fixture("");
        let cmd = full_command(&f, "wrong_database");
        let error = run(&cmd).unwrap_err();
        assert_eq!(error_code(&error), "regression_database_digest_mismatch");
        let root = f.input.output.output_root.join(&f.input.output.run_id);
        assert!(!root.join("input-validation.json").exists());
        let failure = strict_json(&fs::read(root.join("input-failure.json")).unwrap()).unwrap();
        assert_eq!(failure["stage"], "INPUT_REJECTED_AFTER_RUN_CREATE");
        assert_eq!(failure["quality_status"], "FAILED");
    }

    #[test]
    fn full_dispatch_has_only_input_validated_status() {
        let f = fixture("");
        let cmd = full_command(&f, "");
        let report = run(&cmd).unwrap();
        assert_eq!(report["stage"], "INPUT_VALIDATED");
        assert_eq!(report["quality_status"], "NOT_EVALUATED");
        assert_eq!(report["complete_inventory_verification"], "NOT_EVALUATED");
        assert!(report.get("terminal").is_none());
    }

    #[test]
    fn full_request_profiles_reject_before_context_or_output() {
        let f = fixture("");
        let base = full_command(&f, "");
        for fault in [
            "zero_n",
            "lexical_vector",
            "semantic_no_vector",
            "off_page",
            "off_provider",
            "on_no_provider",
            "on_zero_k",
            "on_large_k",
            "duplicate_cutoff",
        ] {
            let mut cmd = base.clone();
            let RegressionCommand::FullSearch {
                search_mode,
                vector_search_mode,
                rrf_limit,
                rerank,
                page_size,
                rerank_provider,
                cutoffs,
                ..
            } = &mut cmd
            else {
                unreachable!();
            };
            match fault {
                "zero_n" => *rrf_limit = 0,
                "lexical_vector" => {
                    *vector_search_mode = Some(crate::search::query::VectorSearchMode::Exact)
                }
                "semantic_no_vector" => *search_mode = crate::search::query::SearchMode::Semantic,
                "off_page" => *page_size = Some(1),
                "off_provider" => {
                    *rerank_provider =
                        Some(crate::search::rerank::types::ProviderChoice::Qwen3Local)
                }
                "on_no_provider" => {
                    *rerank = RerankSwitch::On;
                    *page_size = Some(1);
                }
                "on_zero_k" | "on_large_k" => {
                    *rerank = RerankSwitch::On;
                    *page_size = Some(if fault == "on_zero_k" { 0 } else { 11 });
                    *rerank_provider =
                        Some(crate::search::rerank::types::ProviderChoice::Qwen3Local);
                }
                "duplicate_cutoff" => *cutoffs = vec![5, 5],
                _ => unreachable!(),
            }
            assert_eq!(
                error_code(&prepare_full(&cmd).err().unwrap()),
                "REQUEST_PROFILE_INVALID",
                "fault {fault}"
            );
            assert!(
                fs::read_dir(&f.input.output.output_root)
                    .unwrap()
                    .next()
                    .is_none()
            );
        }
    }

    #[test]
    fn compare_thin_entry_pins_and_modes_without_claiming_evaluation() {
        let f = fixture("");
        let left = f.pool.parent().unwrap().join("left.json");
        let right = f.pool.parent().unwrap().join("right.json");
        let bytes = serde_json::to_vec(&json!({"schema":"cass.regression-run.v1","mode":"fixed-candidate","labels_sha256":f.input.labels_sha256})).unwrap();
        fs::write(&left, &bytes).unwrap();
        fs::write(&right, &bytes).unwrap();
        let mut cmd = RegressionCommand::Compare {
            left: left.clone(),
            left_sha256: digest(&bytes),
            right: right.clone(),
            right_sha256: digest(&bytes),
            labels: f.input.labels.clone(),
            labels_sha256: f.input.labels_sha256.clone(),
            output: f.input.output.clone(),
            cutoffs: vec![5, 10, 20],
            label: Default::default(),
        };
        let mut other = strict_json(&bytes).unwrap();
        other["mode"] = json!("full-search");
        let other = serde_json::to_vec(&other).unwrap();
        fs::write(&right, &other).unwrap();
        let RegressionCommand::Compare { right_sha256, .. } = &mut cmd else {
            unreachable!();
        };
        *right_sha256 = digest(&other);
        assert_eq!(error_code(&run(&cmd).unwrap_err()), "NON_COMPARABLE_MODE");
        assert!(
            fs::read_dir(&f.input.output.output_root)
                .unwrap()
                .next()
                .is_none()
        );
        let RegressionCommand::Compare { right_sha256, .. } = &mut cmd else {
            unreachable!();
        };
        *right_sha256 = digest(&bytes);
        assert_eq!(error_code(&run(&cmd).unwrap_err()), "COMPARE_INPUT_INVALID");
        fs::write(&right, &bytes).unwrap();
        let report = run(&cmd).unwrap();
        assert_eq!(report["stage"], "INPUT_VALIDATED");
        assert_eq!(report["quality_status"], "NOT_EVALUATED");
        assert_eq!(report["full_run_validation"], "NOT_EVALUATED");
        assert!(report.get("terminal").is_none());
    }

    #[test]
    fn synthetic_legacy_9x200_preserves_file_identity_and_input_stage() {
        let f = fixture("");
        let labels_before = fs::read(&f.input.labels).unwrap();
        let suite_before = fs::read(f.input.suite.join("SUITE-MANIFEST.json")).unwrap();
        let validated = validate_inputs(&f.input).unwrap();
        assert_eq!(validated.labels.len(), 1800);
        assert!(matches!(
            validated.windows[0].items[1].message_id,
            MessageId::Text(_)
        ));
        assert_eq!(validated.labels_sha256, digest(&labels_before));
        let result = run(&command(&f)).unwrap();
        assert_eq!(result["stage"], "INPUT_VALIDATED");
        assert_eq!(result["quality_status"], "NOT_EVALUATED");
        assert!(result.get("terminal").is_none());
        assert_eq!(result["model_calls"], 0);
        let run_root = f.input.output.output_root.join(&f.input.output.run_id);
        assert_eq!(fs::metadata(&run_root).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(run_root.join("input-validation.json"))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(fs::read(&f.input.labels).unwrap(), labels_before);
        assert_eq!(
            fs::read(f.input.suite.join("SUITE-MANIFEST.json")).unwrap(),
            suite_before
        );
    }

    #[test]
    fn reader_preserves_four_label_values_and_registered_same_target_aliases() {
        let f = fixture("valid_categories");
        let inputs = validate_inputs(&f.input).unwrap();
        assert_eq!(inputs.labels[0].value, "unsure");
        assert_eq!(inputs.labels[1].value, "partial");
        assert_eq!(inputs.labels[2].value, "none");
        assert_eq!(inputs.labels[3].value, "direct");
        assert_eq!(
            serde_json::to_value(&inputs.labels[0]).unwrap()["key"]["label_policy_sha256"],
            inputs.label_policy_sha256
        );
        let f = fixture("asset_alias");
        assert_eq!(validate_inputs(&f.input).unwrap().labels.len(), 1800);
    }

    #[test]
    fn rejects_structural_and_binding_faults_before_output_creation() {
        for (fault, code) in [
            ("missing_slot", "WINDOW_SLOT_COUNT_INVALID"),
            ("missing_fallback", "WINDOW_SCHEMA_INVALID"),
            ("duplicate_rank", "WINDOW_RANK_INVALID"),
            ("duplicate_mid", "WINDOW_MESSAGE_ID_INVALID"),
            ("duplicate_qid", "WINDOW_QUERY_BINDING_MISMATCH"),
            ("unregistered_text", "INPUT_ASSET_UNREGISTERED"),
            ("wrong_query", "WINDOW_TEXT_BINDING_MISMATCH"),
            ("wrong_span", "SPAN_BINDING_MISMATCH"),
            ("wrong_label", "LABEL_SLOT_BINDING_MISMATCH"),
            ("duplicate_label", "LABEL_SLOT_BINDING_MISMATCH"),
            ("wrong_input_identity", "LABEL_INPUT_BINDING_MISMATCH"),
            ("wrong_freeze", "LABEL_FREEZE_BINDING_MISMATCH"),
            ("unsure_required", "LABEL_UNSCOREABLE_INVALID"),
            ("asset_escape", "INPUT_PATH_ESCAPE"),
        ] {
            let f = fixture(fault);
            let before = fs::read(&f.input.labels).unwrap();
            let error = run(&command(&f)).unwrap_err();
            assert_eq!(error_code(&error), code, "fault {fault}");
            println!(
                "INPUT_CASE fault={fault} result=Err code={code} report=absent input_bytes=unchanged"
            );
            assert!(
                fs::read_dir(&f.input.output.output_root)
                    .unwrap()
                    .next()
                    .is_none()
            );
            assert_eq!(fs::read(&f.input.labels).unwrap(), before);
        }
    }

    #[test]
    fn wrong_external_pins_and_changed_assets_fail_without_report() {
        let mut f = fixture("");
        f.input.suite_sha256 = digest(b"wrong suite");
        assert_eq!(
            error_code(&run(&command(&f)).unwrap_err()),
            "SUITE_DIGEST_MISMATCH"
        );
        let mut f = fixture("");
        f.input.labels_sha256 = digest(b"wrong labels");
        assert_eq!(
            error_code(&run(&command(&f)).unwrap_err()),
            "LABEL_FILE_IDENTITY_MISMATCH"
        );
        let f = fixture("");
        fs::write(
            f.input.suite.join("assets/pr3/task-18/text/1.txt"),
            b"changed synthetic bytes",
        )
        .unwrap();
        assert_eq!(
            error_code(&run(&command(&f)).unwrap_err()),
            "INPUT_ASSET_DIGEST_MISMATCH"
        );
        assert!(
            fs::read_dir(&f.input.output.output_root)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn rejects_symlinks_and_hardlinks_before_opening_assets() {
        let f = fixture("");
        let path = f.input.suite.join("assets/pr3/task-18/text/1.txt");
        let saved = path.with_extension("saved");
        fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        assert_eq!(
            error_code(&run(&command(&f)).unwrap_err()),
            "INPUT_PATH_SYMLINK"
        );
        let f = fixture("");
        fs::hard_link(
            f.input.suite.join("assets/pr3/task-18/text/1.txt"),
            f._root.path().join("hardlink.txt"),
        )
        .unwrap();
        assert_eq!(
            error_code(&run(&command(&f)).unwrap_err()),
            "INPUT_FILE_HARDLINK"
        );
    }

    #[test]
    fn external_hardlinks_preserve_approved_bytes_without_bundle_restrictions() {
        let f = fixture("");
        let cmd = full_command(&f, "");
        let RegressionCommand::FullSearch {
            expected_binding,
            source_manifest,
            source_producer_receipt,
            ..
        } = &cmd
        else {
            unreachable!();
        };
        for (index, path) in [expected_binding, source_manifest, source_producer_receipt]
            .iter()
            .enumerate()
        {
            fs::hard_link(path, f._root.path().join(format!("external-alias-{index}"))).unwrap();
            assert_eq!(fs::metadata(path).unwrap().nlink(), 2);
        }
        assert_eq!(run(&cmd).unwrap()["stage"], "INPUT_VALIDATED");

        let f = fixture("");
        fs::hard_link(&f.pool, f._root.path().join("pool-alias.json")).unwrap();
        assert_eq!(run(&command(&f)).unwrap()["stage"], "INPUT_VALIDATED");
        let left = f.pool.parent().unwrap().join("left.json");
        let right = f.pool.parent().unwrap().join("right.json");
        let labels = f.pool.parent().unwrap().join("external-labels.json");
        let bytes = serde_json::to_vec(&json!({"schema":"cass.regression-run.v1","mode":"fixed-candidate","labels_sha256":f.input.labels_sha256})).unwrap();
        fs::write(&left, &bytes).unwrap();
        fs::write(&right, &bytes).unwrap();
        fs::copy(&f.input.labels, &labels).unwrap();
        for (index, path) in [&left, &right, &labels].iter().enumerate() {
            fs::hard_link(path, f._root.path().join(format!("compare-alias-{index}"))).unwrap();
        }
        let mut output = f.input.output.clone();
        output.run_id = "external-hardlink-compare".into();
        let compare = RegressionCommand::Compare {
            left,
            left_sha256: digest(&bytes),
            right,
            right_sha256: digest(&bytes),
            labels,
            labels_sha256: f.input.labels_sha256.clone(),
            output,
            cutoffs: vec![5, 10, 20],
            label: Default::default(),
        };
        assert_eq!(run(&compare).unwrap()["stage"], "INPUT_VALIDATED");
        println!(
            "EXTERNAL_HARDLINKS full_expected/source/receipt fixed_pool compare_left/right/labels accepted; bundle_hardlink_rejection_kept"
        );
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_and_nonfinite_numbers() {
        for bytes in [
            b"{\"a\":1,\"a\":2}".as_slice(),
            b"{\"nested\":{\"a\":1,\"a\":2}}",
            b"{\"x\":NaN}",
            b"{\"x\":1e999}",
        ] {
            assert_eq!(
                error_code(&strict_json(bytes).unwrap_err()),
                "INPUT_JSON_INVALID"
            );
        }
    }

    #[test]
    fn output_boundaries_prevent_any_run_write() {
        let f = fixture("");
        let mut options = f.input.output.clone();
        for id in ["..", "../escaped", "a/b", "", "/absolute"] {
            options.run_id = id.into();
            assert!(create_run_paths(&options, &[f.input.suite.clone()]).is_err());
        }
        options.run_id = "existing".into();
        fs::create_dir(options.output_root.join("existing")).unwrap();
        assert_eq!(
            error_code(&create_run_paths(&options, &[]).unwrap_err()),
            "RUN_ALREADY_EXISTS"
        );
        options.run_id = "fresh".into();
        let linked = f._root.path().join("linked-output");
        symlink(&options.output_root, &linked).unwrap();
        options.output_root = linked;
        assert_eq!(
            error_code(&create_run_paths(&options, &[]).unwrap_err()),
            "INPUT_PATH_SYMLINK"
        );
        options.output_root = f.input.output.output_root.clone();
        fs::set_permissions(&options.output_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            error_code(&create_run_paths(&options, &[]).unwrap_err()),
            "regression_run_root_not_private"
        );
        fs::set_permissions(&options.output_root, fs::Permissions::from_mode(0o700)).unwrap();
        options.output_root = f.input.suite.clone();
        fs::set_permissions(&options.output_root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            error_code(&create_run_paths(&options, &[f.input.suite.clone()]).unwrap_err()),
            "OUTPUT_INSIDE_INPUT"
        );
        let repo = f._root.path().join("synthetic-repo");
        fs::create_dir(&repo).unwrap();
        fs::write(repo.join(".git"), b"synthetic marker").unwrap();
        fs::set_permissions(&repo, fs::Permissions::from_mode(0o700)).unwrap();
        options.output_root = repo.clone();
        assert_eq!(
            error_code(&create_run_paths(&options, &[]).unwrap_err()),
            "regression_output_inside_repository"
        );
        assert!(!repo.join("fresh").exists());
        assert!(!f.input.suite.join("fresh").exists());
    }

    #[test]
    fn nonowner_output_child() {
        let Some(root) = std::env::var_os("CASS_SYNTHETIC_OUTPUT_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        assert_ne!(
            fs::metadata(&root).unwrap().uid(),
            fs::metadata("/proc/self").unwrap().uid()
        );
        assert_eq!(fs::metadata(&root).unwrap().mode() & 0o777, 0o700);
        let options = OutputOptions {
            output_root: root,
            run_id: "must-not-create".into(),
        };
        assert_eq!(
            error_code(&create_run_paths(&options, &[]).unwrap_err()),
            "regression_run_root_not_private"
        );
        println!("NONOWNER_0700_ROOT_REJECTED_BEFORE_WRITE");
    }

    #[test]
    fn output_owner_guard_rejects_real_distinct_uid() {
        let f = fixture("");
        fs::set_permissions(f._root.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let result = std::process::Command::new("/usr/bin/bwrap")
            .args([
                "--unshare-user",
                "--uid",
                "1",
                "--gid",
                "1",
                "--ro-bind",
                "/",
                "/",
                "--ro-bind",
                "/var/lib/private",
            ])
            .arg(&f.input.output.output_root)
            .args(["--proc", "/proc", "--dev", "/dev"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "regression::input::tests::nonowner_output_child",
                "--nocapture",
            ])
            .env("CASS_SYNTHETIC_OUTPUT_ROOT", &f.input.output.output_root)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            String::from_utf8_lossy(&result.stdout)
                .contains("NONOWNER_0700_ROOT_REJECTED_BEFORE_WRITE")
        );
        assert!(
            fs::read_dir(&f.input.output.output_root)
                .unwrap()
                .next()
                .is_none()
        );
    }

    #[test]
    fn parser_requires_explicit_pins_and_rejects_fixed_search_flags() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                use clap::Parser;
                let f = fixture("");
                let args = [
                    "cass",
                    "regression",
                    "fixed-candidate",
                    "--suite",
                    f.input.suite.to_str().unwrap(),
                    "--suite-sha256",
                    &f.input.suite_sha256,
                    "--labels",
                    f.input.labels.to_str().unwrap(),
                    "--labels-sha256",
                    &f.input.labels_sha256,
                    "--output-root",
                    f.input.output.output_root.to_str().unwrap(),
                    "--run-id",
                    "synthetic-run",
                    "--pool-binding",
                    f.pool.to_str().unwrap(),
                    "--pool-binding-sha256",
                    &f.pool_sha,
                    "--rerank-provider",
                    "qwen3-local",
                ];
                let cli = crate::Cli::try_parse_from(args).unwrap();
                let Some(crate::Commands::Regression { action }) = cli.command else {
                    panic!("new regression command missing");
                };
                assert_eq!(run(&action).unwrap()["stage"], "INPUT_VALIDATED");
                assert!(
                    crate::Cli::try_parse_from(
                        args.into_iter().chain(["--database", "synthetic.db"])
                    )
                    .is_err()
                );
                assert!(crate::Cli::try_parse_from(["cass", "regression", "full-search"]).is_err());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn top_level_rejects_global_trace_before_existing_or_new_external_write() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                use std::future::Future;
                use std::task::{Context, Poll, Waker};
                for family in ["regression-input", "regression"] {
                    for preexisting in [true, false] {
                        let f = fixture("");
                        let target = f._root.path().join("external-trace.jsonl");
                        let sentinel = b"synthetic external trace sentinel\n";
                        if preexisting {
                            fs::write(&target, sentinel).unwrap();
                        }
                        let before = fs::metadata(&target)
                            .ok()
                            .map(|m| (m.len(), m.modified().unwrap(), m.mode(), m.uid(), m.ino()));
                        let mut args = vec![
                            "cass".to_string(),
                            "--trace-file".to_string(),
                            target.to_string_lossy().into_owned(),
                            family.to_string(),
                        ];
                        if family == "regression-input" {
                            args.extend([
                                "inspect".to_string(),
                                "--database".to_string(),
                                f._root
                                    .path()
                                    .join("synthetic-agent_search.db")
                                    .to_string_lossy()
                                    .into_owned(),
                                "--run-root".to_string(),
                                f.input
                                    .output
                                    .output_root
                                    .join("unused-run")
                                    .to_string_lossy()
                                    .into_owned(),
                                "--source-manifest".to_string(),
                                f.pool.to_string_lossy().into_owned(),
                                "--question-pack-root".to_string(),
                                f.input.suite.to_string_lossy().into_owned(),
                            ]);
                        } else {
                            args.extend([
                                "fixed-candidate".to_string(),
                                "--suite".to_string(),
                                f.input.suite.to_string_lossy().into_owned(),
                                "--suite-sha256".to_string(),
                                f.input.suite_sha256.clone(),
                                "--labels".to_string(),
                                f.input.labels.to_string_lossy().into_owned(),
                                "--labels-sha256".to_string(),
                                f.input.labels_sha256.clone(),
                                "--output-root".to_string(),
                                f.input.output.output_root.to_string_lossy().into_owned(),
                                "--run-id".to_string(),
                                f.input.output.run_id.clone(),
                                "--pool-binding".to_string(),
                                f.pool.to_string_lossy().into_owned(),
                                "--pool-binding-sha256".to_string(),
                                f.pool_sha.clone(),
                                "--rerank-provider".to_string(),
                                "qwen3-local".to_string(),
                            ]);
                        }
                        println!("TOP_LEVEL_ARGV {}", serde_json::to_string(&args).unwrap());
                        let parsed = crate::parse_cli(args).unwrap();
                        let mut future = std::pin::pin!(crate::run_with_parsed(parsed));
                        let Poll::Ready(result) = future
                            .as_mut()
                            .poll(&mut Context::from_waker(Waker::noop()))
                        else {
                            panic!("rejected input must complete before async work");
                        };
                        assert_eq!(result.unwrap_err().code, 2);
                        if preexisting {
                            assert_eq!(
                                digest(&fs::read(&target).unwrap()),
                                digest(sentinel),
                                "{family} trace sentinel changed"
                            );
                        } else {
                            assert!(!target.exists(), "{family} created forbidden trace");
                        }
                        let after = fs::metadata(&target)
                            .ok()
                            .map(|m| (m.len(), m.modified().unwrap(), m.mode(), m.uid(), m.ino()));
                        assert_eq!(after, before);
                        println!("TOP_LEVEL_CASE family={family} preexisting={preexisting} CliResult.code=2 trace_bytes_stat=unchanged run=absent");
                        assert!(
                            fs::read_dir(&f.input.output.output_root)
                                .unwrap()
                                .next()
                                .is_none()
                        );
                    }
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn registered_facade_maps_historical_names_and_rejects_unregistered_physical_bait() {
        let f = fixture("");
        let inputs = validate_inputs(&f.input).unwrap();
        let slot = &inputs.windows[0].items[0];
        let bytes = read_registered_asset(&inputs, &slot.text_path).unwrap();
        assert_eq!(digest(&bytes), slot.text_sha256);
        assert_eq!(bytes.len() as u64, slot.bytes);
        let bait = f._root.path().join("unregistered-absolute-bait.txt");
        fs::write(&bait, b"synthetic bait is never a registry asset").unwrap();
        assert_eq!(
            error_code(&read_registered_asset(&inputs, bait.to_str().unwrap()).unwrap_err()),
            "INPUT_ASSET_UNREGISTERED"
        );
        let asset = resolve(&inputs.assets, &slot.text_path).unwrap();
        let path = inputs.suite_root.join(&asset.path);
        let mut changed = bytes;
        changed[0] ^= 1;
        fs::write(&path, &changed).unwrap();
        assert_eq!(
            error_code(&read_registered_asset(&inputs, &slot.text_path).unwrap_err()),
            "INPUT_ASSET_DIGEST_MISMATCH"
        );
    }

    #[test]
    fn registered_facade_retains_escape_symlink_and_bundle_hardlink_guards() {
        let f = fixture("");
        let mut inputs = validate_inputs(&f.input).unwrap();
        let reference = inputs.windows[0].items[0].text_path.clone();
        let index = inputs
            .assets
            .iter()
            .position(|a| a.source_path == reference)
            .unwrap();
        inputs.assets[index].path = "../escape.txt".into();
        assert_eq!(
            error_code(&read_registered_asset(&inputs, &reference).unwrap_err()),
            "INPUT_PATH_ESCAPE"
        );

        let f = fixture("");
        let inputs = validate_inputs(&f.input).unwrap();
        let reference = &inputs.windows[0].items[0].text_path;
        let path = inputs
            .suite_root
            .join(&resolve(&inputs.assets, reference).unwrap().path);
        let saved = path.with_extension("saved");
        fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        assert_eq!(
            error_code(&read_registered_asset(&inputs, reference).unwrap_err()),
            "INPUT_PATH_SYMLINK"
        );

        let f = fixture("");
        let inputs = validate_inputs(&f.input).unwrap();
        let reference = &inputs.windows[0].items[0].text_path;
        let path = inputs
            .suite_root
            .join(&resolve(&inputs.assets, reference).unwrap().path);
        fs::hard_link(&path, f._root.path().join("bundle-link.txt")).unwrap();
        assert_eq!(
            error_code(&read_registered_asset(&inputs, reference).unwrap_err()),
            "INPUT_FILE_HARDLINK"
        );
    }

    #[test]
    fn explicit_pool_facade_pins_same_buffer_strict_json_and_allows_external_hardlinks() {
        let f = fixture("");
        fs::hard_link(&f.pool, f._root.path().join("external-pool-link.json")).unwrap();
        let pool = read_pinned_json(&f.pool, &f.pool_sha).unwrap();
        assert_eq!(pool["schema"], "cass.regression-fixed-pool.v1");
        assert_eq!(
            error_code(&read_pinned_json(&f.pool, &digest(b"wrong pin")).unwrap_err()),
            "POOL_BINDING_MISMATCH"
        );
        let duplicate = f._root.path().join("duplicate-pool.json");
        let bytes = br#"{"schema":"one","schema":"two"}"#;
        fs::write(&duplicate, bytes).unwrap();
        assert_eq!(
            error_code(&read_pinned_json(&duplicate, &digest(bytes)).unwrap_err()),
            "INPUT_JSON_INVALID"
        );
    }

    #[test]
    #[cfg(unix)]
    fn private_json_proof_retains_actual_bytes_sha_and_descriptor_identity() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("synthetic-private.json");
        let bytes = b"{\"value\":18446744073709551615}\n";
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let sha = digest(bytes);
        let wire = read_private_pinned_json(&path, &sha, "LABEL_FILE_IDENTITY_MISMATCH").unwrap();
        assert_eq!(wire.bytes(), bytes);
        assert_eq!(wire.observed_file_sha256(), sha);
        assert_eq!(wire.value()["value"].as_u64(), Some(u64::MAX));
        assert_eq!(wire._identity.0.ino(), wire._identity.1.ino());
        assert_eq!(wire._identity.1.ino(), wire._identity.2.ino());
        assert_eq!(wire._identity.1.mode() & 0o777, 0o600);
        assert!(
            read_private_pinned_json(&path, &digest(b"wrong"), "LABEL_FILE_IDENTITY_MISMATCH")
                .is_err()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_json(&path).is_err());
        // The new private requirement does not change legacy external reads.
        assert!(read_pinned_json(&path, &sha).is_ok());
    }

    #[test]
    #[cfg(unix)]
    fn private_json_keeps_strict_and_symlink_guards_without_relaxing_bundle_links() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("synthetic-private.json");
        fs::write(&path, b"{\"value\":1,\"v\\u0061lue\":2}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_private_json(&path).is_err());
        let link = root.path().join("synthetic-link.json");
        symlink(&path, &link).unwrap();
        assert!(read_private_json(&link).is_err());
        fs::write(&path, b"{\"value\":1}").unwrap();
        fs::hard_link(&path, root.path().join("synthetic-hardlink.json")).unwrap();
        assert!(read_file(&path, true).is_err());
        assert!(read_private_json(&path).is_ok());
    }
}
