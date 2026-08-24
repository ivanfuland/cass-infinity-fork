//! Phase 3 附录 `W0-0` 的 wire contract：sealed bundle 与 seal 内部状态。
//!
//! 本模块是附录 `W0-0`（`docs/projects/cass-fork/specs/appendix-w0-0.md`，含 §D 修订）
//! 在 Rust 侧的独立实现。它只依据附录文本与 `specs/vectors/w0-0/` 的 golden vectors
//! 写成，不参考任何既有实现。
//!
//! 三块内容：
//!
//! 1. **编码核**（§A）：canonical 值编码、leaf digest、Merkle 树、域分离 root、
//!    payload 的内容寻址。
//! 2. **对象校验**（§A.9 / §B.1–§B.7 / §B.8 检查序）：六个生产 `object_kind` 加保留域
//!    `test.tree`，26 个错误码。
//! 3. **bundle 读取**（§A.8）：[`verify_bundle_root`] 与 [`Bundle::read_payload`]
//!    ——**只按 hash 读，没有按活路径读的 API**。
//!
//! 另附 whole-file 处置分类器（`W0-1` §B.3/§B.4 在本模块的落点），见
//! [`classify_whole_file_paths`]。

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use unicode_normalization::is_nfc;

// ---------------------------------------------------------------------------
// §A.1 常量
// ---------------------------------------------------------------------------

/// 域根字符串（§A.1）。
pub const DOMAIN_ROOT: &str = "cass-w0-0/v1";
/// `schema_version` 字段值（§A.1）。
pub const SCHEMA_VERSION: &str = "w0-0/v1";
/// 数组下标宽度（§A.1）：十进制 6 位零填充。
pub const INDEX_WIDTH: usize = 6;
/// 数组长度上限（§A.1）：只作用于对象内带下标 key 的数组。
pub const MAX_INDEXED_ARRAY_LEN: usize = 1_000_000;
/// Claude whole-file 分支的前置守卫（`W0-1` §B.3）。
pub const WHOLE_FILE_SIZE_GUARD_BYTES: u64 = 100 * 1024 * 1024;

/// §A.7 已定义的 `object_kind` 全集。
pub const OBJECT_KIND_UNIVERSE: [&str; 7] = [
    "bundle.manifest",
    "seal.entry",
    "seal.tombstone",
    "seal.observed_after_cut",
    "seal.hold",
    "seal.result",
    "test.tree",
];

/// §B.7 的四个 `set_name`。
pub const SET_NAMES: [&str; 4] = ["entries", "tombstones", "observed_after_cut", "holds"];

/// 保留域（§A.12）：不是 schema，输入是裸 leaf 集，生产对象不得用。
pub const RESERVED_KIND: &str = "test.tree";

// ---------------------------------------------------------------------------
// 错误码（§A.11，26 个，§D-5 只扩含义不加码）
// ---------------------------------------------------------------------------

/// 附录 §A.11 的错误码全集。**取值域封闭且静态**：26 个，不多不少。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorCode {
    SchemaVersion,
    UnknownKind,
    KindForm,
    KindMismatch,
    UnknownSet,
    NullNotAllowed,
    FieldRange,
    FingerprintNull,
    Origin,
    UnknownField,
    MissingField,
    ValueForm,
    PathForm,
    KeyForm,
    DupKey,
    IndexOverflow,
    ArrayUnsorted,
    ArrayDupKey,
    HoldReason,
    HoldDetail,
    DanglingPayload,
    EmptyReason,
    SetRootMismatch,
    SetCountMismatch,
    PayloadHashMismatch,
    BundleRootMismatch,
}

impl ErrorCode {
    /// wire 上的码字面量。
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::SchemaVersion => "E-SCHEMA-VERSION",
            ErrorCode::UnknownKind => "E-UNKNOWN-KIND",
            ErrorCode::KindForm => "E-KIND-FORM",
            ErrorCode::KindMismatch => "E-KIND-MISMATCH",
            ErrorCode::UnknownSet => "E-UNKNOWN-SET",
            ErrorCode::NullNotAllowed => "E-NULL-NOT-ALLOWED",
            ErrorCode::FieldRange => "E-FIELD-RANGE",
            ErrorCode::FingerprintNull => "E-FINGERPRINT-NULL",
            ErrorCode::Origin => "E-ORIGIN",
            ErrorCode::UnknownField => "E-UNKNOWN-FIELD",
            ErrorCode::MissingField => "E-MISSING-FIELD",
            ErrorCode::ValueForm => "E-VALUE-FORM",
            ErrorCode::PathForm => "E-PATH-FORM",
            ErrorCode::KeyForm => "E-KEY-FORM",
            ErrorCode::DupKey => "E-DUP-KEY",
            ErrorCode::IndexOverflow => "E-INDEX-OVERFLOW",
            ErrorCode::ArrayUnsorted => "E-ARRAY-UNSORTED",
            ErrorCode::ArrayDupKey => "E-ARRAY-DUPKEY",
            ErrorCode::HoldReason => "E-HOLD-REASON",
            ErrorCode::HoldDetail => "E-HOLD-DETAIL",
            ErrorCode::DanglingPayload => "E-DANGLING-PAYLOAD",
            ErrorCode::EmptyReason => "E-EMPTY-REASON",
            ErrorCode::SetRootMismatch => "E-SET-ROOT-MISMATCH",
            ErrorCode::SetCountMismatch => "E-SET-COUNT-MISMATCH",
            ErrorCode::PayloadHashMismatch => "E-PAYLOAD-HASH-MISMATCH",
            ErrorCode::BundleRootMismatch => "E-BUNDLE-ROOT-MISMATCH",
        }
    }

    /// 全集，顺序与 §A.11 表一致。
    pub const ALL: [ErrorCode; 26] = [
        ErrorCode::SchemaVersion,
        ErrorCode::UnknownKind,
        ErrorCode::KindForm,
        ErrorCode::KindMismatch,
        ErrorCode::UnknownSet,
        ErrorCode::NullNotAllowed,
        ErrorCode::FieldRange,
        ErrorCode::FingerprintNull,
        ErrorCode::Origin,
        ErrorCode::UnknownField,
        ErrorCode::MissingField,
        ErrorCode::ValueForm,
        ErrorCode::PathForm,
        ErrorCode::KeyForm,
        ErrorCode::DupKey,
        ErrorCode::IndexOverflow,
        ErrorCode::ArrayUnsorted,
        ErrorCode::ArrayDupKey,
        ErrorCode::HoldReason,
        ErrorCode::HoldDetail,
        ErrorCode::DanglingPayload,
        ErrorCode::EmptyReason,
        ErrorCode::SetRootMismatch,
        ErrorCode::SetCountMismatch,
        ErrorCode::PayloadHashMismatch,
        ErrorCode::BundleRootMismatch,
    ];
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一个 wire 契约违规：码 + 可读的定位信息（`detail` 不参与任何判定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireError {
    pub code: ErrorCode,
    pub detail: String,
}

impl WireError {
    fn new(code: ErrorCode, detail: impl Into<String>) -> Self {
        WireError {
            code,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for WireError {}

/// 本模块所有 wire 级操作的返回类型。
pub type WireResult<T> = Result<T, WireError>;

fn err<T>(code: ErrorCode, detail: impl Into<String>) -> WireResult<T> {
    Err(WireError::new(code, detail))
}

// ---------------------------------------------------------------------------
// §A.2 值标签
// ---------------------------------------------------------------------------

/// §A.2 的单字符 ASCII 值标签。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// UTF-8 字符串。
    S,
    /// 绝对 POSIX 路径。
    P,
    /// 整数。
    I,
    /// 布尔。
    B,
    /// 显式 `null`（空字节串）。
    N,
    /// 32 字节摘要（64 位小写 hex）。
    X,
    /// 空数组（空字节串）。
    A,
    /// 空对象（空字节串）。§A.2：本版无对象型字段，为前向预留。
    M,
}

impl Tag {
    /// leaf preimage 里的 tag 字节。
    pub const fn byte(self) -> u8 {
        match self {
            Tag::S => b's',
            Tag::P => b'p',
            Tag::I => b'i',
            Tag::B => b'b',
            Tag::N => b'n',
            Tag::X => b'x',
            Tag::A => b'a',
            Tag::M => b'm',
        }
    }

    /// 从单字符解析（golden vectors 的 `input_tags` 用）。
    pub fn from_char(c: char) -> Option<Tag> {
        match c {
            's' => Some(Tag::S),
            'p' => Some(Tag::P),
            'i' => Some(Tag::I),
            'b' => Some(Tag::B),
            'n' => Some(Tag::N),
            'x' => Some(Tag::X),
            'a' => Some(Tag::A),
            'm' => Some(Tag::M),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// §A.4 / §A.6 / §A.7 / §A.8 编码核
// ---------------------------------------------------------------------------

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// §A.1 空树常量：`SHA-256(utf8("cass-w0-0/v1/empty"))`。
pub fn empty_tree_hash() -> [u8; 32] {
    sha256(&[format!("{DOMAIN_ROOT}/empty").as_bytes()])
}

/// §A.4 的 leaf preimage。长度前缀而不是分隔符，编码是单射的。
pub fn leaf_preimage(key: &str, tag: Tag, value_bytes: &[u8]) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut out = Vec::with_capacity(
        DOMAIN_ROOT.len() + 6 + 1 + 4 + key_bytes.len() + 1 + 4 + value_bytes.len(),
    );
    out.extend_from_slice(format!("{DOMAIN_ROOT}/leaf").as_bytes());
    out.push(0x00);
    out.extend_from_slice(&(key_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(key_bytes);
    out.push(tag.byte());
    out.extend_from_slice(&(value_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(value_bytes);
    out
}

/// §A.4 的 leaf digest。
pub fn leaf_digest(key: &str, tag: Tag, value_bytes: &[u8]) -> [u8; 32] {
    sha256(&[&leaf_preimage(key, tag, value_bytes)])
}

/// §A.6 的树构造。
///
/// **第 0 层就是调用方给定的 canonical 序列，本函数自己不排序**——排序由调用方按
/// §A.5（对象 leaf 按 key 字节序）或 §A.3.1（sidecar 按排序键）负责。
pub fn tree_hash(level0: &[[u8; 32]]) -> [u8; 32] {
    if level0.is_empty() {
        return empty_tree_hash();
    }
    let node_domain = format!("{DOMAIN_ROOT}/node");
    let mut level: Vec<[u8; 32]> = level0.to_vec();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(sha256(&[
                node_domain.as_bytes(),
                &[0x00],
                &level[i],
                &level[i + 1],
            ]));
            i += 2;
        }
        if i < level.len() {
            // 落单的最后一个节点原样上提：不复制、不与自身配对、不填充零。
            next.push(level[i]);
        }
        level = next;
    }
    level[0]
}

/// §A.6 的逐层中间值（golden vectors 的 `levels` 断言用）。
pub fn tree_levels(level0: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let node_domain = format!("{DOMAIN_ROOT}/node");
    let mut levels = vec![level0.to_vec()];
    if level0.is_empty() {
        return levels;
    }
    let mut level: Vec<[u8; 32]> = level0.to_vec();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(sha256(&[
                node_domain.as_bytes(),
                &[0x00],
                &level[i],
                &level[i + 1],
            ]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        levels.push(next.clone());
        level = next;
    }
    levels
}

/// §A.7 的 `object_kind` 命名约束。裸拼接的域串靠这三条把「碰巧不撞」升成「撞上必炸」。
fn check_kind_form(kind: &str) -> WireResult<()> {
    let b = kind.as_bytes();
    let charset_ok = !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'.' || *c == b'-'
        });
    if !charset_ok {
        return err(
            ErrorCode::KindForm,
            format!("object_kind {kind:?} 不匹配 ^[a-z][a-z0-9_.-]*$"),
        );
    }
    if !kind.contains('.') {
        return err(
            ErrorCode::KindForm,
            format!("object_kind {kind:?} 不含 `.`"),
        );
    }
    // 防御冗余：第 3 条的字符集里没有 `/`，本条永远不会独立触发（§A.7）。
    if kind.starts_with("set/") {
        return err(
            ErrorCode::KindForm,
            format!("object_kind {kind:?} 以 `set/` 开头"),
        );
    }
    Ok(())
}

fn check_kind_known(kind: &str) -> WireResult<()> {
    if OBJECT_KIND_UNIVERSE.contains(&kind) {
        Ok(())
    } else {
        err(
            ErrorCode::UnknownKind,
            format!("object_kind {kind:?} 不在 §A.7 全集内"),
        )
    }
}

/// §A.7 的 root：`SHA-256(utf8("cass-w0-0/v1/root/" ‖ object_kind) ‖ 0x00 ‖ tree_hash)`。
///
/// 构造 root 前先验 `object_kind`（§A.7 要求做成运行时断言）。
pub fn object_root(object_kind: &str, tree: [u8; 32]) -> WireResult<[u8; 32]> {
    check_kind_form(object_kind)?;
    check_kind_known(object_kind)?;
    Ok(sha256(&[
        format!("{DOMAIN_ROOT}/root/{object_kind}").as_bytes(),
        &[0x00],
        &tree,
    ]))
}

/// §B.7 的 set root。`item_roots` 必须已按该集合的排序键排好（**不按 item_root 字节序**）。
pub fn set_root(set_name: &str, item_roots: &[[u8; 32]]) -> WireResult<[u8; 32]> {
    check_set_name(set_name)?;
    let tree = tree_hash(item_roots);
    Ok(sha256(&[
        format!("{DOMAIN_ROOT}/root/set/{set_name}").as_bytes(),
        &[0x00],
        &tree,
    ]))
}

fn check_set_name(set_name: &str) -> WireResult<()> {
    let b = set_name.as_bytes();
    let form_ok = !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_');
    if !form_ok || !SET_NAMES.contains(&set_name) {
        return err(
            ErrorCode::UnknownSet,
            format!("set_name {set_name:?} 不在 §B.7 四值内或形态违规"),
        );
    }
    Ok(())
}

/// §A.8 的内容寻址：`SHA-256(utf8("cass-w0-0/v1/payload") ‖ 0x00 ‖ payload_bytes)`。
pub fn payload_hash(payload_bytes: &[u8]) -> [u8; 32] {
    sha256(&[
        format!("{DOMAIN_ROOT}/payload").as_bytes(),
        &[0x00],
        payload_bytes,
    ])
}

// ---------------------------------------------------------------------------
// §A.3 leaf key 语法
// ---------------------------------------------------------------------------

fn member_name_ok(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn check_member_name(name: &str) -> WireResult<()> {
    if member_name_ok(name) {
        Ok(())
    } else {
        err(
            ErrorCode::KeyForm,
            format!("成员名 {name:?} 不匹配 ^[a-z][a-z0-9_]*$"),
        )
    }
}

/// §A.3：数组元素 key = 父 key + `[` + 6 位零填充下标 + `]` + `.` + 成员名。
fn element_leaf_key(array_name: &str, index: usize, member: &str) -> String {
    format!("{}[{:0w$}].{}", array_name, index, member, w = INDEX_WIDTH)
}

// ---------------------------------------------------------------------------
// 输入模型
// ---------------------------------------------------------------------------

/// 一个对象的标量成员序列（也用作数组元素的字段集）。
///
/// 用**有序 Vec** 而不是 map：JSON 层面的重复成员名必须能被观察到（§A.5 第 2 条），
/// map 会静默 last-wins。
pub type ScalarFields = Vec<(String, JsonValue)>;

/// 对象的一个成员：标量，或对象内的 set 语义数组（本附录只有 `payloads[]`）。
#[derive(Debug, Clone)]
pub enum RawField {
    Scalar(JsonValue),
    Array(Vec<ScalarFields>),
}

/// 一个待校验对象的成员序列。
pub type RawObject = Vec<(String, RawField)>;

/// 一次对象校验的产物。
#[derive(Debug, Clone)]
pub struct ObjectOutcome {
    pub root: [u8; 32],
    pub tree_hash: [u8; 32],
    pub sorted_keys: Vec<String>,
}

// ---------------------------------------------------------------------------
// schema 字段表（§A.9 / §B.1–§B.7）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct FieldSpec {
    name: &'static str,
    tag: Tag,
    nullable: bool,
    /// 字段级取值范围 `>= 0`（§A.11 的 `E-FIELD-RANGE` 穷举表）。
    non_negative: bool,
}

const fn f(name: &'static str, tag: Tag) -> FieldSpec {
    FieldSpec {
        name,
        tag,
        nullable: false,
        non_negative: false,
    }
}

const fn f_null(name: &'static str, tag: Tag) -> FieldSpec {
    FieldSpec {
        name,
        tag,
        nullable: true,
        non_negative: false,
    }
}

const fn f_nonneg(name: &'static str) -> FieldSpec {
    FieldSpec {
        name,
        tag: Tag::I,
        nullable: false,
        non_negative: true,
    }
}

#[derive(Debug, Clone, Copy)]
struct ArraySpec {
    name: &'static str,
    elements: &'static [FieldSpec],
}

#[derive(Debug, Clone, Copy)]
struct Schema {
    /// §A.10：只有两个「信封级」对象带 `schema_version`。
    has_schema_version: bool,
    fields: &'static [FieldSpec],
    arrays: &'static [ArraySpec],
}

const PAYLOAD_ELEMENTS: &[FieldSpec] = &[f("payload_hash", Tag::X), f_nonneg("byte_length")];

const BUNDLE_MANIFEST: Schema = Schema {
    has_schema_version: true,
    fields: &[
        f("object_kind", Tag::S),
        f("schema_version", Tag::S),
        f("seal_result_root", Tag::X),
        f_null("mirror_fingerprint", Tag::X),
        f("promotable", Tag::B),
    ],
    arrays: &[ArraySpec {
        name: "payloads",
        elements: PAYLOAD_ELEMENTS,
    }],
};

const SEAL_RESULT: Schema = Schema {
    has_schema_version: true,
    fields: &[
        f("object_kind", Tag::S),
        f("schema_version", Tag::S),
        f("entries_root", Tag::X),
        f_nonneg("entries_count"),
        f("tombstones_root", Tag::X),
        f_nonneg("tombstones_count"),
        f("observed_after_cut_root", Tag::X),
        f_nonneg("observed_after_cut_count"),
        f("holds_root", Tag::X),
        f_nonneg("holds_count"),
    ],
    arrays: &[],
};

const SEAL_ENTRY: Schema = Schema {
    has_schema_version: false,
    fields: &[
        f("object_kind", Tag::S),
        f("origin", Tag::S),
        f("canonical_path", Tag::P),
        f_nonneg("boundary_t"),
        f("prefix_digest", Tag::X),
        f("payload_hash", Tag::X),
        f_null("session_id", Tag::S),
        f_null("empty_reason", Tag::S),
        // §D-2：dev / ino 允许负值，只受 int64 约束。
        f("dev", Tag::I),
        f("ino", Tag::I),
    ],
    arrays: &[],
};

const SEAL_TOMBSTONE: Schema = Schema {
    has_schema_version: false,
    fields: &[
        f("object_kind", Tag::S),
        f("origin", Tag::S),
        f("canonical_path", Tag::P),
        f("base_payload_hash", Tag::X),
        f_nonneg("observed_missing_at_ms"),
    ],
    arrays: &[],
};

const SEAL_OBSERVED_AFTER_CUT: Schema = Schema {
    has_schema_version: false,
    fields: &[
        f("object_kind", Tag::S),
        f("origin", Tag::S),
        f("canonical_path", Tag::P),
        f_nonneg("observed_at_ms"),
    ],
    arrays: &[],
};

const SEAL_HOLD: Schema = Schema {
    has_schema_version: false,
    fields: &[
        f("object_kind", Tag::S),
        f("origin", Tag::S),
        f("canonical_path", Tag::P),
        f("reason", Tag::S),
        f_null("detail", Tag::S),
    ],
    arrays: &[],
};

fn schema_for(kind: &str) -> Option<&'static Schema> {
    match kind {
        "bundle.manifest" => Some(&BUNDLE_MANIFEST),
        "seal.result" => Some(&SEAL_RESULT),
        "seal.entry" => Some(&SEAL_ENTRY),
        "seal.tombstone" => Some(&SEAL_TOMBSTONE),
        "seal.observed_after_cut" => Some(&SEAL_OBSERVED_AFTER_CUT),
        "seal.hold" => Some(&SEAL_HOLD),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 闭世界枚举（§B.1 / §B.5 / §B.5.1）
// ---------------------------------------------------------------------------

/// §B.1 的 `origin` 三值，闭世界。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Origin {
    ClaudeCode,
    Codex,
    Openclaw,
}

impl Origin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Origin::ClaudeCode => "claude_code",
            Origin::Codex => "codex",
            Origin::Openclaw => "openclaw",
        }
    }

    pub fn parse(s: &str) -> Option<Origin> {
        match s {
            "claude_code" => Some(Origin::ClaudeCode),
            "codex" => Some(Origin::Codex),
            "openclaw" => Some(Origin::Openclaw),
            _ => None,
        }
    }
}

/// §B.1 的 `empty_reason` 两值，闭世界。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmptyReason {
    ZeroByteFile,
    NoCompleteRecord,
}

impl EmptyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            EmptyReason::ZeroByteFile => "zero-byte-file",
            EmptyReason::NoCompleteRecord => "no-complete-record",
        }
    }

    pub fn parse(s: &str) -> Option<EmptyReason> {
        match s {
            "zero-byte-file" => Some(EmptyReason::ZeroByteFile),
            "no-complete-record" => Some(EmptyReason::NoCompleteRecord),
            _ => None,
        }
    }
}

/// §B.5 的 sealer HOLD taxonomy，六类，闭世界（与 restore 四类分立）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HoldReason {
    Unreadable,
    FdUnavailable,
    PrefixRewritten,
    StabilityTimeout,
    PathReincarnation,
    OutOfScopeFormat,
}

impl HoldReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            HoldReason::Unreadable => "unreadable",
            HoldReason::FdUnavailable => "fd-unavailable",
            HoldReason::PrefixRewritten => "prefix-rewritten",
            HoldReason::StabilityTimeout => "stability-timeout",
            HoldReason::PathReincarnation => "path-reincarnation",
            HoldReason::OutOfScopeFormat => "out-of-scope-format",
        }
    }

    pub fn parse(s: &str) -> Option<HoldReason> {
        match s {
            "unreadable" => Some(HoldReason::Unreadable),
            "fd-unavailable" => Some(HoldReason::FdUnavailable),
            "prefix-rewritten" => Some(HoldReason::PrefixRewritten),
            "stability-timeout" => Some(HoldReason::StabilityTimeout),
            "path-reincarnation" => Some(HoldReason::PathReincarnation),
            "out-of-scope-format" => Some(HoldReason::OutOfScopeFormat),
            _ => None,
        }
    }
}

/// §B.5.1 第六类 HOLD 的 `detail` bucket，闭世界五值。
///
/// **变体顺序 = 各自字面量的 UTF-8 字节升序**，`BTreeSet` 的迭代序因此直接就是
/// §D-6 要求的 canonical 串序。`enum_order_matches_byte_order` 测试把这条钉死。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OutOfScopeBucket {
    ClaudeLegacyEmitting,
    CodexRolloutJson,
    FilenameCaseVariant,
    TypeDrift,
    UnknownWholeFileSchema,
}

impl OutOfScopeBucket {
    pub const ALL: [OutOfScopeBucket; 5] = [
        OutOfScopeBucket::ClaudeLegacyEmitting,
        OutOfScopeBucket::CodexRolloutJson,
        OutOfScopeBucket::FilenameCaseVariant,
        OutOfScopeBucket::TypeDrift,
        OutOfScopeBucket::UnknownWholeFileSchema,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            OutOfScopeBucket::ClaudeLegacyEmitting => "claude-legacy-emitting",
            OutOfScopeBucket::CodexRolloutJson => "codex-rollout-json",
            OutOfScopeBucket::FilenameCaseVariant => "filename-case-variant",
            OutOfScopeBucket::TypeDrift => "type-drift",
            OutOfScopeBucket::UnknownWholeFileSchema => "unknown-whole-file-schema",
        }
    }

    pub fn parse(s: &str) -> Option<OutOfScopeBucket> {
        OutOfScopeBucket::ALL.into_iter().find(|b| b.as_str() == s)
    }
}

/// §D-6：把一个非空 bucket 子集拼成 canonical `detail` 串
/// ——按 UTF-8 字节升序、单逗号连接、无空白无重复。
pub fn canonical_out_of_scope_detail(buckets: &BTreeSet<OutOfScopeBucket>) -> Option<String> {
    if buckets.is_empty() {
        return None;
    }
    Some(
        buckets
            .iter()
            .map(|b| b.as_str())
            .collect::<Vec<_>>()
            .join(","),
    )
}

/// §D-6 的 `detail` 校验：按 `,` 切分；每段在五值表内；段序严格升序；不得有空段。
fn check_out_of_scope_detail(detail: &str) -> WireResult<()> {
    let mut prev: Option<&str> = None;
    for seg in detail.split(',') {
        if seg.is_empty() {
            return err(ErrorCode::HoldDetail, "detail 含空段");
        }
        if OutOfScopeBucket::parse(seg).is_none() {
            return err(
                ErrorCode::HoldDetail,
                format!("detail 段 {seg:?} 不在 §B.5.1 五值表内"),
            );
        }
        if let Some(p) = prev
            && p.as_bytes() >= seg.as_bytes()
        {
            return err(
                ErrorCode::HoldDetail,
                format!("detail 段序非严格字节升序：{p:?} 之后是 {seg:?}"),
            );
        }
        prev = Some(seg);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// §A.2 值校验
// ---------------------------------------------------------------------------

fn check_text(value: &str, what: &str) -> WireResult<()> {
    if value.contains('\u{0000}') {
        return err(ErrorCode::ValueForm, format!("{what} 含 U+0000"));
    }
    if !is_nfc(value) {
        return err(ErrorCode::ValueForm, format!("{what} 未 NFC 规范化"));
    }
    Ok(())
}

/// §A.2 + §D-1 的 `p` 路径判据：**按段判**，切的是去掉开头那一个 `/` 之后的余串。
fn check_path_form(value: &str) -> WireResult<()> {
    check_text(value, "路径")?;
    let Some(rest) = value.strip_prefix('/') else {
        return err(ErrorCode::PathForm, format!("路径 {value:?} 非绝对"));
    };
    if rest.is_empty() {
        // 根路径 `/`：余串切出恰好一个空段，显式放行。
        return Ok(());
    }
    for seg in rest.split('/') {
        if seg.is_empty() {
            return err(ErrorCode::PathForm, format!("路径 {value:?} 出现空段"));
        }
        if seg == "." || seg == ".." {
            return err(
                ErrorCode::PathForm,
                format!("路径 {value:?} 出现 {seg:?} 段"),
            );
        }
    }
    Ok(())
}

fn hex32(value: &str) -> WireResult<[u8; 32]> {
    let ok = value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !ok {
        return err(
            ErrorCode::ValueForm,
            format!("x 标签值 {value:?} 不匹配 ^[0-9a-f]{{64}}$"),
        );
    }
    let mut out = [0u8; 32];
    for (i, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (chunk[1] as char).to_digit(16).unwrap_or(0) as u8;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// 一个已校验的标量值：tag + canonical value bytes（+ 判定用的原值投影）。
#[derive(Debug, Clone)]
struct Encoded {
    tag: Tag,
    bytes: Vec<u8>,
    int: Option<i64>,
    text: Option<String>,
    hex: Option<[u8; 32]>,
    is_null: bool,
}

/// §A.2：按**声明的 tag** 算 canonical value bytes。唯一由运行时值决定 tag 的例外是显式 `null`。
fn encode_scalar(
    spec_tag: Tag,
    nullable: bool,
    value: &JsonValue,
    what: &str,
) -> WireResult<Encoded> {
    if value.is_null() {
        if !nullable {
            return err(
                ErrorCode::NullNotAllowed,
                format!("{what} 不可空却装了显式 null"),
            );
        }
        return Ok(Encoded {
            tag: Tag::N,
            bytes: Vec::new(),
            int: None,
            text: None,
            hex: None,
            is_null: true,
        });
    }
    match spec_tag {
        Tag::S => {
            let JsonValue::String(s) = value else {
                return err(
                    ErrorCode::ValueForm,
                    format!("{what} 的 s 标签值不是字符串"),
                );
            };
            check_text(s, what)?;
            Ok(Encoded {
                tag: Tag::S,
                bytes: s.as_bytes().to_vec(),
                int: None,
                text: Some(s.clone()),
                hex: None,
                is_null: false,
            })
        }
        Tag::P => {
            let JsonValue::String(s) = value else {
                return err(
                    ErrorCode::ValueForm,
                    format!("{what} 的 p 标签值不是字符串"),
                );
            };
            check_path_form(s)?;
            Ok(Encoded {
                tag: Tag::P,
                bytes: s.as_bytes().to_vec(),
                int: None,
                text: Some(s.clone()),
                hex: None,
                is_null: false,
            })
        }
        Tag::I => {
            let JsonValue::Number(n) = value else {
                return err(
                    ErrorCode::ValueForm,
                    format!("{what} 的 i 标签值不是 JSON 整数字面量"),
                );
            };
            // 布尔在 serde_json 里是 Bool，走不到这里；浮点与超 int64 的整数 as_i64() 为 None。
            let Some(v) = n.as_i64() else {
                return err(
                    ErrorCode::ValueForm,
                    format!("{what} 的 i 标签值不是 int64 范围内的整数：{n}"),
                );
            };
            Ok(Encoded {
                tag: Tag::I,
                bytes: v.to_string().into_bytes(),
                int: Some(v),
                text: None,
                hex: None,
                is_null: false,
            })
        }
        Tag::B => {
            let JsonValue::Bool(b) = value else {
                return err(
                    ErrorCode::ValueForm,
                    format!("{what} 的 b 标签值不是 JSON 布尔"),
                );
            };
            Ok(Encoded {
                tag: Tag::B,
                bytes: if *b {
                    b"true".to_vec()
                } else {
                    b"false".to_vec()
                },
                int: None,
                text: None,
                hex: None,
                is_null: false,
            })
        }
        Tag::X => {
            let JsonValue::String(s) = value else {
                return err(
                    ErrorCode::ValueForm,
                    format!("{what} 的 x 标签值不是字符串"),
                );
            };
            let h = hex32(s)?;
            Ok(Encoded {
                tag: Tag::X,
                bytes: h.to_vec(),
                int: None,
                text: Some(s.clone()),
                hex: Some(h),
                is_null: false,
            })
        }
        Tag::A => {
            let JsonValue::Array(a) = value else {
                return err(ErrorCode::ValueForm, format!("{what} 的 a 标签值不是数组"));
            };
            if !a.is_empty() {
                return err(
                    ErrorCode::ValueForm,
                    format!("{what} 的 a 标签只用于空数组"),
                );
            }
            Ok(Encoded {
                tag: Tag::A,
                bytes: Vec::new(),
                int: None,
                text: None,
                hex: None,
                is_null: false,
            })
        }
        Tag::M => {
            let JsonValue::Object(o) = value else {
                return err(ErrorCode::ValueForm, format!("{what} 的 m 标签值不是对象"));
            };
            if !o.is_empty() {
                return err(
                    ErrorCode::ValueForm,
                    format!("{what} 的 m 标签只用于空对象"),
                );
            }
            Ok(Encoded {
                tag: Tag::M,
                bytes: Vec::new(),
                int: None,
                text: None,
                hex: None,
                is_null: false,
            })
        }
        Tag::N => {
            // 声明 tag 为 n 而值非 null：只在保留域的 input_tags 上可能出现。
            err(
                ErrorCode::ValueForm,
                format!("{what} 声明 n 标签但值不是 null"),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// §B.8 检查序：生产对象
// ---------------------------------------------------------------------------

/// 按 §B.8 校验一个生产对象并算出它的 root。
///
/// `domain_kind` 是**算 root 用的域标签**；对象自己的 `object_kind` 字段值与它不等即
/// `E-KIND-MISMATCH`（§A.7 的两条防线）。
pub fn compute_object_root(domain_kind: &str, object: &RawObject) -> WireResult<ObjectOutcome> {
    // ---- 第一层 · 信封 ----
    // 第 1 步：带 schema_version 的对象先判版本，版本不对时后面每条检查的语义都不确定。
    if let Some(schema) = schema_for(domain_kind)
        && schema.has_schema_version
        && let Some((_, RawField::Scalar(JsonValue::String(v)))) =
            object.iter().find(|(k, _)| k == "schema_version")
        && v != SCHEMA_VERSION
    {
        return err(
            ErrorCode::SchemaVersion,
            format!("schema_version {v:?} != {SCHEMA_VERSION}，不做兼容读"),
        );
    }

    // 第 2 步：object_kind。三个码之间有序（§B.8 第 2 步内部）。
    check_kind_form(domain_kind)?;
    check_kind_known(domain_kind)?;
    // §D-5：保留域被当作生产 object_kind 用。
    if domain_kind == RESERVED_KIND {
        return err(
            ErrorCode::UnknownKind,
            format!("保留域 {RESERVED_KIND} 不得用作生产 object_kind（§A.12 / §D-5）"),
        );
    }
    if let Some((_, RawField::Scalar(JsonValue::String(field_kind)))) =
        object.iter().find(|(k, _)| k == "object_kind")
    {
        check_kind_form(field_kind)?;
        if field_kind != domain_kind {
            return err(
                ErrorCode::KindMismatch,
                format!("object_kind 字段值 {field_kind:?} != 域标签 {domain_kind:?}"),
            );
        }
    }

    let schema = schema_for(domain_kind).ok_or_else(|| {
        WireError::new(
            ErrorCode::UnknownKind,
            format!("object_kind {domain_kind:?} 没有字段表"),
        )
    })?;

    // ---- 第二层 · key ----
    // §D-3：E-INDEX-OVERFLOW 钉在 key 生成期，展开任何元素 key **之前** 判。
    for (name, field) in object {
        if let RawField::Array(items) = field
            && items.len() > MAX_INDEXED_ARRAY_LEN
        {
            return err(
                ErrorCode::IndexOverflow,
                format!(
                    "数组 {name} 长度 {} 超过上限 {MAX_INDEXED_ARRAY_LEN}",
                    items.len()
                ),
            );
        }
    }

    // 第 4 步：leaf key 形态。
    for (name, field) in object {
        check_member_name(name)?;
        if let RawField::Array(items) = field {
            for item in items {
                for (member, _) in item {
                    check_member_name(member)?;
                }
            }
        }
    }

    // 第 5 步：闭世界与必填。
    for (name, field) in object {
        let declared_scalar = schema.fields.iter().any(|s| s.name == *name);
        let declared_array = schema.arrays.iter().any(|s| s.name == *name);
        if !declared_scalar && !declared_array {
            return err(
                ErrorCode::UnknownField,
                format!("{domain_kind} 未声明字段 {name}"),
            );
        }
        if let RawField::Array(items) = field {
            let Some(aspec) = schema.arrays.iter().find(|s| s.name == *name) else {
                return err(
                    ErrorCode::UnknownField,
                    format!("{domain_kind} 的 {name} 不是数组字段"),
                );
            };
            for item in items {
                for (member, _) in item {
                    if !aspec.elements.iter().any(|s| s.name == *member) {
                        return err(
                            ErrorCode::UnknownField,
                            format!("{domain_kind}.{name}[] 未声明元素字段 {member}"),
                        );
                    }
                }
                for spec in aspec.elements {
                    if !item.iter().any(|(m, _)| m == spec.name) {
                        return err(
                            ErrorCode::MissingField,
                            format!("{domain_kind}.{name}[] 缺元素字段 {}", spec.name),
                        );
                    }
                }
            }
        }
    }
    for spec in schema.fields {
        if !object.iter().any(|(k, _)| k == spec.name) {
            return err(
                ErrorCode::MissingField,
                format!("{domain_kind} 缺必填字段 {}", spec.name),
            );
        }
    }
    for aspec in schema.arrays {
        if !object.iter().any(|(k, _)| k == aspec.name) {
            return err(
                ErrorCode::MissingField,
                format!("{domain_kind} 缺必填字段 {}", aspec.name),
            );
        }
    }

    // 第 6 步：leaf key 重复。
    for i in 0..object.len() {
        for j in (i + 1)..object.len() {
            if object[i].0 == object[j].0 {
                return err(
                    ErrorCode::DupKey,
                    format!("leaf key {} 出现两次", object[i].0),
                );
            }
        }
    }

    // ---- 第三层 · 值 ----
    let mut leaves: Vec<(String, [u8; 32])> = Vec::new();
    let mut encoded_fields: Vec<(&str, Encoded)> = Vec::new();
    let mut payloads_len: Option<usize> = None;
    let mut payload_hashes: Vec<[u8; 32]> = Vec::new();

    for spec in schema.fields {
        let Some((_, field)) = object.iter().find(|(k, _)| k == spec.name) else {
            unreachable!("必填字段在第 5 步已保证存在");
        };
        let RawField::Scalar(value) = field else {
            return err(
                ErrorCode::ValueForm,
                format!("{domain_kind}.{} 是标量字段却给了数组", spec.name),
            );
        };
        let enc = encode_scalar(spec.tag, spec.nullable, value, spec.name)?;
        leaves.push((
            spec.name.to_string(),
            leaf_digest(spec.name, enc.tag, &enc.bytes),
        ));
        encoded_fields.push((spec.name, enc));
    }

    for aspec in schema.arrays {
        let Some((_, field)) = object.iter().find(|(k, _)| k == aspec.name) else {
            unreachable!("必填字段在第 5 步已保证存在");
        };
        let RawField::Array(items) = field else {
            return err(
                ErrorCode::ValueForm,
                format!("{domain_kind}.{} 是数组字段却给了标量", aspec.name),
            );
        };
        payloads_len = Some(items.len());
        if items.is_empty() {
            // §A.3：空容器在容器自己的 key 上产生一个 a leaf。
            leaves.push((aspec.name.to_string(), leaf_digest(aspec.name, Tag::A, &[])));
            continue;
        }
        payload_hashes.reserve(items.len());
        for (idx, item) in items.iter().enumerate() {
            for spec in aspec.elements {
                let Some((_, value)) = item.iter().find(|(m, _)| m == spec.name) else {
                    unreachable!("元素必填字段在第 5 步已保证存在");
                };
                let key = element_leaf_key(aspec.name, idx, spec.name);
                let enc = encode_scalar(spec.tag, spec.nullable, value, &key)?;
                if spec.non_negative
                    && let Some(v) = enc.int
                    && v < 0
                {
                    return err(ErrorCode::FieldRange, format!("{key} = {v} < 0"));
                }
                if spec.name == "payload_hash"
                    && let Some(h) = enc.hex
                {
                    payload_hashes.push(h);
                }
                let digest = leaf_digest(&key, enc.tag, &enc.bytes);
                leaves.push((key, digest));
            }
        }
    }

    // 第 8 步：字段级取值范围。
    for (name, enc) in &encoded_fields {
        let spec = schema
            .fields
            .iter()
            .find(|s| s.name == *name)
            .expect("字段表内");
        if spec.non_negative
            && let Some(v) = enc.int
            && v < 0
        {
            return err(ErrorCode::FieldRange, format!("{name} = {v} < 0"));
        }
    }

    // 第 9 步：闭世界枚举。
    let field_text = |name: &str| -> Option<&str> {
        encoded_fields
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, e)| e.text.as_deref())
    };
    let field_is_null = |name: &str| -> bool {
        encoded_fields
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, e)| e.is_null)
            .unwrap_or(false)
    };
    let field_int = |name: &str| -> Option<i64> {
        encoded_fields
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, e)| e.int)
    };

    if let Some(origin) = field_text("origin")
        && Origin::parse(origin).is_none()
    {
        return err(
            ErrorCode::Origin,
            format!("origin {origin:?} 不在 §B.1 三值内"),
        );
    }
    if let Some(reason) = field_text("reason")
        && HoldReason::parse(reason).is_none()
    {
        return err(
            ErrorCode::HoldReason,
            format!("reason {reason:?} 不在 §B.5 六类内"),
        );
    }
    if domain_kind == "seal.entry" {
        let boundary_zero = field_int("boundary_t") == Some(0);
        let reason_null = field_is_null("empty_reason");
        if let Some(reason) = field_text("empty_reason")
            && EmptyReason::parse(reason).is_none()
        {
            return err(
                ErrorCode::EmptyReason,
                format!("empty_reason {reason:?} 不在两类内"),
            );
        }
        if boundary_zero == reason_null {
            return err(
                ErrorCode::EmptyReason,
                format!(
                    "boundary_t == 0（{boundary_zero}）与 empty_reason != null（{}）不满足当且仅当关系",
                    !reason_null
                ),
            );
        }
    }

    // 第 10 步：跨字段一致性。
    if domain_kind == "bundle.manifest" {
        let payloads_empty = payloads_len == Some(0);
        let fingerprint_null = field_is_null("mirror_fingerprint");
        if payloads_empty != fingerprint_null {
            return err(
                ErrorCode::FingerprintNull,
                format!(
                    "mirror_fingerprint == null（{fingerprint_null}）与 payloads 为空（{payloads_empty}）不满足当且仅当关系"
                ),
            );
        }
    }
    if domain_kind == "seal.hold"
        && field_text("reason") == Some(HoldReason::OutOfScopeFormat.as_str())
    {
        match field_text("detail") {
            None => {
                return err(
                    ErrorCode::HoldDetail,
                    "out-of-scope-format 的 detail 为 null（本类下不可空）",
                );
            }
            Some(detail) => check_out_of_scope_detail(detail)?,
        }
    }

    // ---- 第四层 · 集合与 root ----
    // 第 11 步：set 语义数组的排序与去重。
    for w in payload_hashes.windows(2) {
        if w[0] == w[1] {
            return err(
                ErrorCode::ArrayDupKey,
                "payloads[] 的 payload_hash 排序键重复",
            );
        }
        if w[0] > w[1] {
            return err(
                ErrorCode::ArrayUnsorted,
                "payloads[] 未按 payload_hash 的 32 原始字节升序落盘",
            );
        }
    }

    finish_leaves(domain_kind, leaves)
}

/// §A.5 + §A.6 + §A.7：排序、查重、算树、算 root。
fn finish_leaves(
    domain_kind: &str,
    mut leaves: Vec<(String, [u8; 32])>,
) -> WireResult<ObjectOutcome> {
    leaves.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    for w in leaves.windows(2) {
        if w[0].0 == w[1].0 {
            return err(ErrorCode::DupKey, format!("leaf key {} 出现两次", w[0].0));
        }
    }
    let digests: Vec<[u8; 32]> = leaves.iter().map(|(_, d)| *d).collect();
    let tree = tree_hash(&digests);
    let root = object_root(domain_kind, tree)?;
    Ok(ObjectOutcome {
        root,
        tree_hash: tree,
        sorted_keys: leaves.into_iter().map(|(k, _)| k).collect(),
    })
}

// ---------------------------------------------------------------------------
// §A.12 保留域：裸 leaf 集
// ---------------------------------------------------------------------------

/// 保留域 `test.tree` 的输入：裸 leaf 集（key、tag、值），**不带信封、不产生 `object_kind` leaf**。
///
/// 裸 key 同样受 §A.3 的 key 语法约束——不给编码器开第二条 key 校验路径。
pub fn compute_bare_leaf_root(
    domain_kind: &str,
    leaves: &[(String, Tag, JsonValue)],
) -> WireResult<ObjectOutcome> {
    check_kind_form(domain_kind)?;
    check_kind_known(domain_kind)?;
    for (key, _, _) in leaves {
        check_member_name(key)?;
    }
    let mut out: Vec<(String, [u8; 32])> = Vec::with_capacity(leaves.len());
    for (key, tag, value) in leaves {
        let enc = encode_scalar(*tag, matches!(tag, Tag::N), value, key)?;
        let digest = leaf_digest(key, enc.tag, &enc.bytes);
        out.push((key.clone(), digest));
    }
    finish_leaves(domain_kind, out)
}

// ---------------------------------------------------------------------------
// §B.7 sidecar 集合
// ---------------------------------------------------------------------------

/// 四个 `set_name` 各自的 item `object_kind`。
pub fn set_item_kind(set_name: &str) -> WireResult<&'static str> {
    match set_name {
        "entries" => Ok("seal.entry"),
        "tombstones" => Ok("seal.tombstone"),
        "observed_after_cut" => Ok("seal.observed_after_cut"),
        "holds" => Ok("seal.hold"),
        _ => err(
            ErrorCode::UnknownSet,
            format!("set_name {set_name:?} 不在 §B.7 四值内"),
        ),
    }
}

fn scalar_fields_to_object(fields: &ScalarFields) -> RawObject {
    fields
        .iter()
        .map(|(k, v)| (k.clone(), RawField::Scalar(v.clone())))
        .collect()
}

/// 单条 sidecar item 的 `item_root`（§B.7）。
pub fn item_root(item_kind: &str, fields: &ScalarFields) -> WireResult<[u8; 32]> {
    Ok(compute_object_root(item_kind, &scalar_fields_to_object(fields))?.root)
}

/// §A.3.1 的排序键：`origin`，同则 `canonical_path`，`holds` 再同则 `reason`。
fn item_sort_key(set_name: &str, fields: &ScalarFields) -> WireResult<Vec<String>> {
    let take = |name: &str| -> WireResult<String> {
        match fields.iter().find(|(k, _)| k == name) {
            Some((_, JsonValue::String(s))) => Ok(s.clone()),
            Some((_, _)) => err(
                ErrorCode::ValueForm,
                format!("排序键字段 {name} 不是字符串"),
            ),
            None => err(ErrorCode::MissingField, format!("排序键字段 {name} 缺失")),
        }
    };
    let mut key = vec![take("origin")?, take("canonical_path")?];
    if set_name == "holds" {
        key.push(take("reason")?);
    }
    Ok(key)
}

/// 一次 set 校验的产物。
#[derive(Debug, Clone)]
pub struct SetVerification {
    pub set_root: [u8; 32],
    pub item_roots: Vec<[u8; 32]>,
}

/// 按 sidecar 恢复出的 item 序列重算 set root（§B.7）。
///
/// **消费方不许静默重排、也不许静默去重**：未按排序键升序报 `E-ARRAY-UNSORTED`，
/// 排序键重复报 `E-ARRAY-DUPKEY`，两者都在算 `set_root` **之前**判。
pub fn verify_set(set_name: &str, items: &[ScalarFields]) -> WireResult<SetVerification> {
    check_set_name(set_name)?;
    let item_kind = set_item_kind(set_name)?;

    let mut item_roots = Vec::with_capacity(items.len());
    let mut sort_keys = Vec::with_capacity(items.len());
    for fields in items {
        item_roots.push(item_root(item_kind, fields)?);
        sort_keys.push(item_sort_key(set_name, fields)?);
    }
    for w in sort_keys.windows(2) {
        if w[0] == w[1] {
            return err(
                ErrorCode::ArrayDupKey,
                format!("{set_name} 排序键重复：{:?}", w[0]),
            );
        }
        if w[0] > w[1] {
            return err(
                ErrorCode::ArrayUnsorted,
                format!("{set_name} 未按排序键升序：{:?} 在 {:?} 之前", w[0], w[1]),
            );
        }
    }
    let root = set_root(set_name, &item_roots)?;
    Ok(SetVerification {
        set_root: root,
        item_roots,
    })
}

/// §B.8 第 13 步：声明的 set root / 计数与按 sidecar 重算的比对。
pub fn verify_declared_set(
    set_name: &str,
    items: &[ScalarFields],
    declared_root: [u8; 32],
    declared_count: i64,
) -> WireResult<[u8; 32]> {
    let v = verify_set(set_name, items)?;
    if declared_count != items.len() as i64 {
        return err(
            ErrorCode::SetCountMismatch,
            format!(
                "{set_name}_count 声明 {declared_count}，item 数 {}",
                items.len()
            ),
        );
    }
    if declared_root != v.set_root {
        return err(
            ErrorCode::SetRootMismatch,
            format!(
                "{set_name}_root 声明 {}，重算 {}",
                hex_lower(&declared_root),
                hex_lower(&v.set_root)
            ),
        );
    }
    Ok(v.set_root)
}

/// §B.8 第 12 步的引用完整性。**反向不查**：manifest 列了而无人引用的 payload 合法。
pub fn check_referential_integrity(
    manifest_payload_hashes: &[[u8; 32]],
    sidecar_refs: &[([u8; 32], String)],
) -> WireResult<()> {
    for (h, what) in sidecar_refs {
        if !manifest_payload_hashes.contains(h) {
            return err(
                ErrorCode::DanglingPayload,
                format!("{what} 引用的 {} 不在 manifest payloads[] 内", hex_lower(h)),
            );
        }
    }
    Ok(())
}

/// 32 字节摘要写成 64 位小写 hex。
pub fn hex_lower(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
    }
    s
}

// ---------------------------------------------------------------------------
// 落盘形态与 bundle 读取（§A.8 / §A.11 / §D-7）
// ---------------------------------------------------------------------------

/// bundle 目录里 manifest 的文件名。
pub const MANIFEST_FILE: &str = "manifest.json";
/// bundle 目录里 `seal.result` 的文件名。
pub const SEAL_RESULT_FILE: &str = "seal-result.json";
/// bundle 目录里 payload 的子目录名。
pub const PAYLOAD_DIR: &str = "payloads";

/// 四个 sidecar 的文件名（`sidecar-<set_name>.json`）。
pub fn sidecar_file_name(set_name: &str) -> String {
    format!("sidecar-{set_name}.json")
}

/// 打开 / 校验 bundle 时可能出的错。
///
/// **wire 契约违规与 I/O、落盘形态问题分立**：§D-7 第 2/3 条明确把「没有 manifest」与
/// 「按不在 manifest 内的 hash 读」划在本附录的错误码空间之外。
#[derive(Debug)]
pub enum BundleError {
    /// 一条 §A.11 的错误码。
    Wire(WireError),
    /// I/O 失败（§D-7 第 2 条：不在码空间内）。
    Io { path: PathBuf, source: io::Error },
    /// 落盘形态不可解（§D-7 第 2 条）。
    Malformed { path: PathBuf, detail: String },
    /// 调用方按一个不在 manifest 内的 hash 读（§D-7 第 3 条：调用方用法错误）。
    UnknownPayload { payload_hash: String },
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleError::Wire(e) => write!(f, "{e}"),
            BundleError::Io { path, source } => write!(f, "I/O 失败 {}: {source}", path.display()),
            BundleError::Malformed { path, detail } => {
                write!(f, "落盘形态不可解 {}: {detail}", path.display())
            }
            BundleError::UnknownPayload { payload_hash } => {
                write!(f, "payload_hash {payload_hash} 不在 manifest payloads[] 内")
            }
        }
    }
}

impl std::error::Error for BundleError {}

impl From<WireError> for BundleError {
    fn from(e: WireError) -> Self {
        BundleError::Wire(e)
    }
}

impl BundleError {
    /// 若本错误是一条 wire 码则返回它，否则 `None`。
    pub fn wire_code(&self) -> Option<ErrorCode> {
        match self {
            BundleError::Wire(e) => Some(e.code),
            _ => None,
        }
    }
}

/// manifest 里 `payloads[]` 的一条。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadRef {
    pub payload_hash: [u8; 32],
    pub byte_length: i64,
}

/// 把落盘 JSON 对象还原成 [`RawObject`]。**读取适配层**，不参与任何 root 计算。
///
/// 数组字段接受**两种等价落盘形态**，两者 canonical 化到同一字段集、因而同一 root：
///
/// 1. **扁平 leaf key**（golden vectors 的 `input` 形态）：
///    `"payloads[000000].payload_hash"`。下标必须是 6 位零填充且从 `000000` 起连续，
///    否则 `E-KEY-FORM`。
/// 2. **嵌套对象数组**（Stage D5 产物的落盘形态）：
///    `"payloads": [{"payload_hash": …, "byte_length": …}, …]`，顺序即下标序。
///
/// §A.11 与 §B.7 都明写落盘格式不由附录规定，附录只规定「字段集 → root」这条映射；
/// 所以两种形态之间没有对错之分，读取层两种都得认。**同一个数组名同时以两种形态出现即拒**
/// （`E-VALUE-FORM`）——那是无法判定顺序的畸形输入，不是可合并的两半。
pub fn raw_object_from_flat_map(map: &serde_json::Map<String, JsonValue>) -> WireResult<RawObject> {
    let mut scalars: Vec<(String, RawField)> = Vec::new();
    let mut arrays: Vec<(String, Vec<(usize, ScalarFields)>)> = Vec::new();
    // 记下每个数组名是由哪种形态供给的，用来拒绝两种形态混用。
    let mut nested_arrays: Vec<String> = Vec::new();
    let mut indexed_arrays: Vec<String> = Vec::new();

    for (key, value) in map {
        let Some(open) = key.find('[') else {
            if let JsonValue::Array(items) = value {
                nested_arrays.push(key.clone());
                let mut elements: Vec<(usize, ScalarFields)> = Vec::with_capacity(items.len());
                for (idx, item) in items.iter().enumerate() {
                    let JsonValue::Object(fields) = item else {
                        return err(ErrorCode::ValueForm, format!("{key}[{idx}] 不是 JSON 对象"));
                    };
                    elements.push((
                        idx,
                        fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                    ));
                }
                arrays.push((key.clone(), elements));
            } else {
                scalars.push((key.clone(), RawField::Scalar(value.clone())));
            }
            continue;
        };
        let name = &key[..open];
        let rest = &key[open + 1..];
        let Some(close) = rest.find(']') else {
            return err(ErrorCode::KeyForm, format!("leaf key {key:?} 缺 `]`"));
        };
        let idx_text = &rest[..close];
        if idx_text.len() != INDEX_WIDTH || !idx_text.bytes().all(|b| b.is_ascii_digit()) {
            return err(
                ErrorCode::KeyForm,
                format!("leaf key {key:?} 的下标不是 {INDEX_WIDTH} 位零填充十进制"),
            );
        }
        let Ok(idx) = idx_text.parse::<usize>() else {
            return err(ErrorCode::KeyForm, format!("leaf key {key:?} 的下标不可解"));
        };
        let Some(member) = rest[close + 1..].strip_prefix('.') else {
            return err(
                ErrorCode::KeyForm,
                format!("leaf key {key:?} 的 `]` 之后不是 `.`"),
            );
        };
        if !indexed_arrays.iter().any(|n| n == name) {
            indexed_arrays.push(name.to_string());
        }
        let slot = match arrays.iter_mut().find(|(n, _)| n == name) {
            Some(s) => s,
            None => {
                arrays.push((name.to_string(), Vec::new()));
                arrays.last_mut().expect("刚 push")
            }
        };
        match slot.1.iter_mut().find(|(i, _)| *i == idx) {
            Some((_, fields)) => fields.push((member.to_string(), value.clone())),
            None => slot
                .1
                .push((idx, vec![(member.to_string(), value.clone())])),
        }
    }

    for name in &indexed_arrays {
        if nested_arrays.contains(name) {
            return err(
                ErrorCode::ValueForm,
                format!("数组 {name} 同时以嵌套形态与带下标 leaf key 形态出现，无法判定顺序"),
            );
        }
    }

    let mut out = scalars;
    for (name, mut indexed) in arrays {
        indexed.sort_by_key(|(i, _)| *i);
        for (expected, (got, _)) in indexed.iter().map(|(i, f)| (*i, f)).enumerate() {
            if expected != got {
                return err(
                    ErrorCode::KeyForm,
                    format!("数组 {name} 的下标不连续：期望 {expected}，实得 {got}"),
                );
            }
        }
        out.push((
            name,
            RawField::Array(indexed.into_iter().map(|(_, f)| f).collect()),
        ));
    }
    Ok(out)
}

/// 从一个已校验的 `bundle.manifest` 对象里取出 `payloads[]`。
pub fn manifest_payloads(object: &RawObject) -> WireResult<Vec<PayloadRef>> {
    let Some((_, RawField::Array(items))) = object.iter().find(|(k, _)| k == "payloads") else {
        return err(
            ErrorCode::MissingField,
            "bundle.manifest 缺 payloads".to_string(),
        );
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let hash = match item.iter().find(|(k, _)| k == "payload_hash") {
            Some((_, JsonValue::String(s))) => hex32(s)?,
            _ => {
                return err(
                    ErrorCode::MissingField,
                    "payloads[] 元素缺 payload_hash".to_string(),
                );
            }
        };
        let byte_length = match item.iter().find(|(k, _)| k == "byte_length") {
            Some((_, JsonValue::Number(n))) => n.as_i64().ok_or_else(|| {
                WireError::new(ErrorCode::ValueForm, "byte_length 不是 int64".to_string())
            })?,
            _ => {
                return err(
                    ErrorCode::MissingField,
                    "payloads[] 元素缺 byte_length".to_string(),
                );
            }
        };
        out.push(PayloadRef {
            payload_hash: hash,
            byte_length,
        });
    }
    Ok(out)
}

/// 一次 `verify_bundle_root` **实际验到了什么**。
///
/// bundle 目录里 `seal.result` 与四个集合 sidecar 是否在场，取决于产出方的落盘选择
/// （D5 的产物就只有 manifest / payloads / candidate-db sidecar 三项）。「不在场就跳过」
/// 如果不留痕，就是一次静默降级——调用方会以为验了全套。**所以跳过必须是可观测的**：
/// 本结构把每一项是否真跑过如实记下来，由调用方决定这个覆盖面够不够。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationScope {
    /// manifest 的字段集校验与 root 重算。恒为 `true`——它是 `verify_bundle_root` 的前提。
    pub manifest_verified: bool,
    /// 是否按 `seal.result` 重算并比对了 `seal_result_root`（盘上有该文件才做）。
    pub seal_result_verified: bool,
    /// 是否按四个 sidecar 重算了 set root / 计数并查了引用完整性（四份都在场才做）。
    pub sidecars_verified: bool,
    /// 是否逐个重算了 payload 的 hash 与长度。
    pub payload_bytes_verified: bool,
}

/// `verify_bundle_root` 的可选行为。
#[derive(Debug, Clone, Copy)]
pub struct VerifyOptions {
    /// 是否逐个重算 payload 的 hash。
    ///
    /// 关掉它**不会**让内容寻址失守：[`Bundle::read_payload`] 每次读仍然重算，
    /// 检查只是从「打开时一次性全量」移到「读到哪条验哪条」。数 GB 级 bundle 上全量重算
    /// 要读完整个语料，多数调用方并不需要。关掉时 [`VerificationScope`] 会如实记下来。
    pub verify_payload_bytes: bool,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        VerifyOptions {
            verify_payload_bytes: true,
        }
    }
}

/// 一个已通过 root 校验的 bundle。
///
/// **只按 hash 读**（§A.8）：没有按活路径读的 API，[`Bundle::read_payload`] 是唯一读取入口。
#[derive(Debug)]
pub struct Bundle {
    dir: PathBuf,
    root: [u8; 32],
    payloads: Vec<PayloadRef>,
    scope: VerificationScope,
}

impl Bundle {
    /// 通过校验的 bundle root（= snapshot root）。
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// manifest 声明的 payload 清单。
    pub fn payloads(&self) -> &[PayloadRef] {
        &self.payloads
    }

    /// 这次校验**实际覆盖到了哪些项**。
    pub fn scope(&self) -> VerificationScope {
        self.scope
    }

    /// §A.8 的唯一读取入口：按内容寻址读一份 payload。
    ///
    /// **每次读都重算 hash 再交出去**——payload 的身份是内容摘要而不是路径，所以两次访问
    /// 之间盘上的文件被换绑（unlink 后同名重建、符号链接改指）必然被这一步抓住，
    /// 不需要也不应该依赖路径的稳定性。
    pub fn read_payload(&self, payload_hash: &[u8; 32]) -> Result<Vec<u8>, BundleError> {
        let Some(declared) = self
            .payloads
            .iter()
            .find(|p| p.payload_hash == *payload_hash)
        else {
            // §D-7 第 3 条：调用方用法错误，不在本附录的错误码空间内。
            return Err(BundleError::UnknownPayload {
                payload_hash: hex_lower(payload_hash),
            });
        };
        let path = self.dir.join(PAYLOAD_DIR).join(hex_lower(payload_hash));
        let bytes = read_payload_file(&path)?;
        verify_payload_bytes(&path, declared, &bytes)?;
        Ok(bytes)
    }
}

/// §D-7 第 1 条：manifest 列了、而盘上该 payload 不存在或不可读 → `E-PAYLOAD-HASH-MISMATCH`。
/// 对消费者而言两者后果相同：manifest 声称的那份字节拿不到。
fn read_payload_file(path: &Path) -> Result<Vec<u8>, BundleError> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) => Err(BundleError::Wire(WireError::new(
            ErrorCode::PayloadHashMismatch,
            format!("payload {} 不存在或不可读：{e}", path.display()),
        ))),
    }
}

fn verify_payload_bytes(
    path: &Path,
    declared: &PayloadRef,
    bytes: &[u8],
) -> Result<(), BundleError> {
    // §A.9：长度不符一律由 E-PAYLOAD-HASH-MISMATCH 覆盖，没有独立错误码。
    if declared.byte_length < 0 || bytes.len() as i64 != declared.byte_length {
        return Err(BundleError::Wire(WireError::new(
            ErrorCode::PayloadHashMismatch,
            format!(
                "payload {} 长度声明 {}，实得 {}",
                path.display(),
                declared.byte_length,
                bytes.len()
            ),
        )));
    }
    let actual = payload_hash(bytes);
    if actual != declared.payload_hash {
        return Err(BundleError::Wire(WireError::new(
            ErrorCode::PayloadHashMismatch,
            format!(
                "payload {} 重算 {}，manifest 声明 {}",
                path.display(),
                hex_lower(&actual),
                hex_lower(&declared.payload_hash)
            ),
        )));
    }
    Ok(())
}

/// 与 `JsonValue` 等价的解析结果，但**对象里出现重复键就报错**，不折叠。
///
/// `serde_json` 的 `Value` 把 `{"a":1,"a":2}` 读成 `{"a":2}` —— 后者覆盖前者，静悄悄。
/// 于是 wire 层那道 `E-DUP-KEY`（`finish_leaves` / 第 6 步）**对真实 JSON 文件形同虚设**：
/// 它查的是一个已经没有重复键的结构，永远查不出东西（R2 第 14 条 / R-E-98 H3）。
///
/// 危害不止「少报一个错」：`{"a":1,"a":2}` 与 `{"a":2}` 会被读成同一份内容，
/// 而在一个按**字节**摘要定身份的系统里，两份不同字节读出同一份含义 = 身份判据被绕过。
///
/// 查重放在解析器里而不是解析后扫一遍，是因为**解析后就已经晚了**：那时重复键已经没了。
/// 深度不限：折叠发生在解析器里，不分顶层还是嵌套，所以数组元素里的对象也一并覆盖。
struct StrictJson(JsonValue);

impl<'de> serde::Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> serde::de::Visitor<'de> for StrictVisitor {
            type Value = JsonValue;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("任意 JSON 值")
            }

            fn visit_unit<E>(self) -> Result<JsonValue, E> {
                Ok(JsonValue::Null)
            }
            fn visit_none<E>(self) -> Result<JsonValue, E> {
                Ok(JsonValue::Null)
            }
            fn visit_some<D>(self, d: D) -> Result<JsonValue, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                <StrictJson as serde::Deserialize>::deserialize(d).map(|s| s.0)
            }
            fn visit_bool<E>(self, v: bool) -> Result<JsonValue, E> {
                Ok(JsonValue::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<JsonValue, E> {
                Ok(JsonValue::from(v))
            }
            fn visit_u64<E>(self, v: u64) -> Result<JsonValue, E> {
                Ok(JsonValue::from(v))
            }
            fn visit_f64<E>(self, v: f64) -> Result<JsonValue, E> {
                Ok(JsonValue::from(v))
            }
            fn visit_str<E>(self, v: &str) -> Result<JsonValue, E> {
                Ok(JsonValue::String(v.to_string()))
            }
            fn visit_string<E>(self, v: String) -> Result<JsonValue, E> {
                Ok(JsonValue::String(v))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<JsonValue, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(StrictJson(v)) = seq.next_element()? {
                    out.push(v);
                }
                Ok(JsonValue::Array(out))
            }

            fn visit_map<A>(self, mut map: A) -> Result<JsonValue, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut out = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let StrictJson(value) = map.next_value()?;
                    if out.contains_key(&key) {
                        return Err(serde::de::Error::custom(format!(
                            "E-DUP-KEY: 键 {key} 在同一个对象里出现两次"
                        )));
                    }
                    out.insert(key, value);
                }
                Ok(JsonValue::Object(out))
            }
        }

        deserializer.deserialize_any(StrictVisitor).map(StrictJson)
    }
}

fn read_json_object(path: &Path) -> Result<serde_json::Map<String, JsonValue>, BundleError> {
    let text = fs::read_to_string(path).map_err(|e| BundleError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    // happy path 只解析一次。出错时才回头用 `JsonValue` 再解一次，**只为分辨**
    // 「根本不是合法 JSON」与「合法但顶层不是对象」这两句既有诊断措辞 —— 那两句是
    // 操作者认路用的，不该因为换了解析器就变。
    let value = match serde_json::from_str::<StrictJson>(&text) {
        Ok(StrictJson(v)) => v,
        Err(strict_err) => {
            return Err(BundleError::Malformed {
                path: path.to_path_buf(),
                detail: match serde_json::from_str::<JsonValue>(&text) {
                    Ok(other) if !matches!(other, JsonValue::Object(_)) => {
                        format!("顶层不是 JSON 对象，实得 {}", json_type_name(&other))
                    }
                    // 宽松解析器读得出来、严格解析器读不出来 —— 差别只可能是重复键。
                    _ => format!("JSON 不可解：{strict_err}"),
                },
            });
        }
    };
    match value {
        JsonValue::Object(m) => Ok(m),
        other => Err(BundleError::Malformed {
            path: path.to_path_buf(),
            detail: format!("顶层不是 JSON 对象，实得 {}", json_type_name(&other)),
        }),
    }
}

fn json_type_name(v: &JsonValue) -> &'static str {
    match v {
        JsonValue::Null => "null",
        JsonValue::Bool(_) => "bool",
        JsonValue::Number(_) => "number",
        JsonValue::String(_) => "string",
        JsonValue::Array(_) => "array",
        JsonValue::Object(_) => "object",
    }
}

fn read_sidecar_items(path: &Path) -> Result<Vec<ScalarFields>, BundleError> {
    let map = read_json_object(path)?;
    let Some(JsonValue::Array(items)) = map.get("items") else {
        return Err(BundleError::Malformed {
            path: path.to_path_buf(),
            detail: "缺 items 数组".to_string(),
        });
    };
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let JsonValue::Object(fields) = item else {
            return Err(BundleError::Malformed {
                path: path.to_path_buf(),
                detail: format!("items[{i}] 不是 JSON 对象"),
            });
        };
        out.push(
            fields
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect::<ScalarFields>(),
        );
    }
    Ok(out)
}

fn declared_hex_field(
    object: &RawObject,
    name: &str,
    path: &Path,
) -> Result<[u8; 32], BundleError> {
    match object.iter().find(|(k, _)| k == name) {
        Some((_, RawField::Scalar(JsonValue::String(s)))) => Ok(hex32(s)?),
        _ => Err(BundleError::Malformed {
            path: path.to_path_buf(),
            detail: format!("缺 {name} 或它不是 hex 字符串"),
        }),
    }
}

fn declared_int_field(object: &RawObject, name: &str, path: &Path) -> Result<i64, BundleError> {
    match object.iter().find(|(k, _)| k == name) {
        Some((_, RawField::Scalar(JsonValue::Number(n)))) => {
            n.as_i64().ok_or_else(|| BundleError::Malformed {
                path: path.to_path_buf(),
                detail: format!("{name} 不是 int64"),
            })
        }
        _ => Err(BundleError::Malformed {
            path: path.to_path_buf(),
            detail: format!("缺 {name} 或它不是整数"),
        }),
    }
}

/// 打开一个 bundle 目录，按 §B.8 全序校验，并与**外部给定的期望 root** 比对。
///
/// `expected_root_hex` 就是 §A.11 说的那个「manifest 之外的权威副本」——它来自 seal 编排
/// 事务的 read-receipt 或 W4 marker 的 `snapshot_root`，不可能装在 manifest 自己里（自指）。
///
/// 用默认 [`VerifyOptions`]（逐个重算 payload hash）。数 GB 级 bundle 上想跳过那一步用
/// [`verify_bundle_root_with`]，跳过与否会记进 [`Bundle::scope`]。
pub fn verify_bundle_root(
    bundle_dir: &Path,
    expected_root_hex: &str,
) -> Result<Bundle, BundleError> {
    verify_bundle_root_with(bundle_dir, expected_root_hex, VerifyOptions::default())
}

/// 同 [`verify_bundle_root`]，但由调用方指定可选行为。
pub fn verify_bundle_root_with(
    bundle_dir: &Path,
    expected_root_hex: &str,
    options: VerifyOptions,
) -> Result<Bundle, BundleError> {
    let expected_root = hex32(expected_root_hex)?;
    let mut scope = VerificationScope {
        manifest_verified: false,
        seal_result_verified: false,
        sidecars_verified: false,
        payload_bytes_verified: false,
    };

    // ---- manifest ----
    let manifest_path = bundle_dir.join(MANIFEST_FILE);
    let manifest_map = read_json_object(&manifest_path)?;
    let manifest = raw_object_from_flat_map(&manifest_map)?;
    let manifest_outcome = compute_object_root("bundle.manifest", &manifest)?;
    let payloads = manifest_payloads(&manifest)?;
    scope.manifest_verified = true;

    // ---- seal.result（可选：产出方可以只在 manifest 里留 seal_result_root 哈希引用）----
    let seal_result_path = bundle_dir.join(SEAL_RESULT_FILE);
    let seal_result = if seal_result_path.exists() {
        let seal_result_map = read_json_object(&seal_result_path)?;
        let seal_result = raw_object_from_flat_map(&seal_result_map)?;
        let seal_result_outcome = compute_object_root("seal.result", &seal_result)?;

        let declared_seal_result_root =
            declared_hex_field(&manifest, "seal_result_root", &manifest_path)?;
        if declared_seal_result_root != seal_result_outcome.root {
            // 附录没有为这一条给码（§B.8 只到 set root 与 payload），故按 §D-7 第 2 条的同款处置
            // 走非 E-* 错误：它是落盘形态的内部不一致，不是本附录定义的对象校验失败。
            return Err(BundleError::Malformed {
                path: manifest_path,
                detail: format!(
                    "seal_result_root 声明 {}，按盘上 {SEAL_RESULT_FILE} 重算 {}",
                    hex_lower(&declared_seal_result_root),
                    hex_lower(&seal_result_outcome.root)
                ),
            });
        }
        scope.seal_result_verified = true;
        Some(seal_result)
    } else {
        None
    };

    // ---- 四个 sidecar（可选，且必须四份齐全：缺一份就没有「全套集合」可谈）----
    if let Some(seal_result) = &seal_result {
        let present: Vec<bool> = SET_NAMES
            .iter()
            .map(|n| bundle_dir.join(sidecar_file_name(n)).exists())
            .collect();
        if present.iter().all(|p| *p) {
            let mut sidecar_refs: Vec<([u8; 32], String)> = Vec::new();
            for set_name in SET_NAMES {
                let path = bundle_dir.join(sidecar_file_name(set_name));
                let items = read_sidecar_items(&path)?;
                let declared_root = declared_hex_field(
                    seal_result,
                    &format!("{set_name}_root"),
                    &seal_result_path,
                )?;
                let declared_count = declared_int_field(
                    seal_result,
                    &format!("{set_name}_count"),
                    &seal_result_path,
                )?;
                verify_declared_set(set_name, &items, declared_root, declared_count)?;

                // §B.8 第 12 步的引用来源。
                let ref_field = match set_name {
                    "entries" => Some("payload_hash"),
                    "tombstones" => Some("base_payload_hash"),
                    _ => None,
                };
                if let Some(field) = ref_field {
                    for (i, fields) in items.iter().enumerate() {
                        match fields.iter().find(|(k, _)| k == field) {
                            Some((_, JsonValue::String(s))) => {
                                sidecar_refs.push((hex32(s)?, format!("{set_name}[{i}].{field}")));
                            }
                            _ => {
                                return Err(BundleError::Malformed {
                                    path,
                                    detail: format!("items[{i}] 缺 {field}"),
                                });
                            }
                        }
                    }
                }
            }

            // ---- 第 12 步：引用完整性 ----
            let manifest_hashes: Vec<[u8; 32]> = payloads.iter().map(|p| p.payload_hash).collect();
            check_referential_integrity(&manifest_hashes, &sidecar_refs)?;
            scope.sidecars_verified = true;
        } else if present.iter().any(|p| *p) {
            // 部分在场：这是残缺输入，不是「产出方选择不落 sidecar」。不许当没看见。
            return Err(BundleError::Malformed {
                path: bundle_dir.to_path_buf(),
                detail: "四个集合 sidecar 只有部分在场，无法按集合口径校验".to_string(),
            });
        }
    }

    // ---- 第 14 步：payload 重算 ----
    if options.verify_payload_bytes {
        for declared in &payloads {
            let path = bundle_dir
                .join(PAYLOAD_DIR)
                .join(hex_lower(&declared.payload_hash));
            let bytes = read_payload_file(&path)?;
            verify_payload_bytes(&path, declared, &bytes)?;
        }
        scope.payload_bytes_verified = true;
    }

    // ---- 第 15 步：与外部期望 root 比对 ----
    if manifest_outcome.root != expected_root {
        return Err(BundleError::Wire(WireError::new(
            ErrorCode::BundleRootMismatch,
            format!(
                "外部期望 root {}，按盘上 manifest 重算 {}",
                hex_lower(&expected_root),
                hex_lower(&manifest_outcome.root)
            ),
        )));
    }

    Ok(Bundle {
        dir: bundle_dir.to_path_buf(),
        root: manifest_outcome.root,
        payloads,
        scope,
    })
}

// ---------------------------------------------------------------------------
// whole-file 处置（`W0-1` §B.3/§B.4 在本模块的落点）
// ---------------------------------------------------------------------------

/// Claude whole-file 已知 metadata 形态的**必需键**。
///
/// 判据是「必需键齐全」，**不是完整键集组合白名单**——3 个可选键有 8 种组合，只枚举实测
/// 见过的那几种，正是「新出现一个可选键就炸门」那个洞的成因。
pub const KNOWN_METADATA_REQUIRED_KEYS: [&str; 4] =
    ["agentType", "description", "spawnDepth", "toolUseId"];

/// 实测见过的可选键。**只用于构造正向用例，不参与判定**——判定只看必需键是否齐全，
/// 因此一个从没见过的新可选键不会把已知 metadata 判成未知。
pub const KNOWN_METADATA_OBSERVED_OPTIONAL_KEYS: [&str; 3] =
    ["model", "parentAgentId", "stoppedByUser"];

/// pin parser 解析失败。`W0-1` §B.3：claude whole-file 分支解析失败是 debug + continue，
/// 不是错误上抛。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinParseError {
    pub detail: String,
}

/// 注入点：**只回答「这份 whole-file 文档里有几条消息」**的窄接口。
///
/// 真实实现由 connector 侧提供；本模块只依赖这一个问题的答案，因此测试可以用受控替身
/// 精确控制「≥1 条」与「0 条」这条二分。
pub trait WholeFileMessageCounter {
    fn count_messages(&self, path: &Path, bytes: &[u8]) -> Result<usize, PinParseError>;
}

/// 一条 whole-file 候选的处置。**每条路径都必须落到本枚举的某个变体上**——
/// 没有「静默跳过」这个出口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WholeFileDisposition {
    /// 立即 HOLD（§B.5）。第六类带 canonical `detail` 串，其余类 `detail` 可空。
    Hold {
        reason: HoldReason,
        detail: Option<String>,
    },
    /// 零消息 + 已知 metadata 形态：记 `excluded_known_metadata`，**不得 HOLD**。
    ExcludedKnownMetadata,
    /// 精确小写 `.jsonl`：逐行 record 家族，归 §B.1 那条路，不由本分类器处置。
    NotWholeFile,
    /// 前置守卫命中：`> 100 MiB` 的 whole-file 文档直接跳过。
    SkippedOversize { byte_len: u64 },
    /// pin parser 解析失败：debug + continue。
    SkippedUnparsable { detail: String },
}

impl WholeFileDisposition {
    fn hold_bucket(bucket: OutOfScopeBucket) -> Self {
        let mut set = BTreeSet::new();
        set.insert(bucket);
        WholeFileDisposition::Hold {
            reason: HoldReason::OutOfScopeFormat,
            detail: canonical_out_of_scope_detail(&set),
        }
    }

    fn hold_buckets(buckets: BTreeSet<OutOfScopeBucket>) -> Self {
        WholeFileDisposition::Hold {
            reason: HoldReason::OutOfScopeFormat,
            detail: canonical_out_of_scope_detail(&buckets),
        }
    }

    /// 本处置是否计入 `excluded_known_metadata`。
    pub fn is_excluded_known_metadata(&self) -> bool {
        matches!(self, WholeFileDisposition::ExcludedKnownMetadata)
    }

    /// 本处置是否是一条 HOLD。
    pub fn is_hold(&self) -> bool {
        matches!(self, WholeFileDisposition::Hold { .. })
    }
}

/// 一条待分类的 whole-file 候选。
#[derive(Debug, Clone)]
pub struct WholeFileInput {
    pub origin: Origin,
    pub path: PathBuf,
}

/// 一条候选的裁定结果。
#[derive(Debug, Clone)]
pub struct WholeFileVerdict {
    pub origin: Origin,
    pub path: PathBuf,
    pub disposition: WholeFileDisposition,
}

/// 一批候选的裁定台账。
#[derive(Debug, Clone)]
pub struct WholeFileReport {
    pub verdicts: Vec<WholeFileVerdict>,
}

impl WholeFileReport {
    /// `excluded_known_metadata` 的计数——F-6 要求它有真实构造点，这就是那个口径。
    pub fn excluded_known_metadata_count(&self) -> usize {
        self.verdicts
            .iter()
            .filter(|v| v.disposition.is_excluded_known_metadata())
            .count()
    }

    /// HOLD 计数。
    pub fn hold_count(&self) -> usize {
        self.verdicts
            .iter()
            .filter(|v| v.disposition.is_hold())
            .count()
    }
}

fn ext_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase())
}

fn ext_exact(path: &Path, want: &str) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some(want)
}

/// 判定一份 whole-file 候选的处置。
///
/// `bytes` 是该路径的完整内容；100 MiB 前置守卫由调用方在 [`classify_whole_file_paths`] 里
/// 先于读取施加，本函数对已读进来的字节再判一次，两处一致。
pub fn classify_whole_file(
    origin: Origin,
    path: &Path,
    bytes: &[u8],
    counter: &dyn WholeFileMessageCounter,
) -> WholeFileDisposition {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        // 文件名不是合法 UTF-8：拿不到形态判据，按未知 whole-file schema 处置（fail-loud）。
        return WholeFileDisposition::hold_bucket(OutOfScopeBucket::UnknownWholeFileSchema);
    };

    if bytes.len() as u64 > WHOLE_FILE_SIZE_GUARD_BYTES {
        return WholeFileDisposition::SkippedOversize {
            byte_len: bytes.len() as u64,
        };
    }

    match origin {
        Origin::Codex => {
            let lower = name.to_ascii_lowercase();
            if !lower.starts_with("rollout-") {
                return if ext_exact(path, "jsonl") {
                    WholeFileDisposition::NotWholeFile
                } else {
                    WholeFileDisposition::hold_bucket(OutOfScopeBucket::UnknownWholeFileSchema)
                };
            }
            let mut buckets: BTreeSet<OutOfScopeBucket> = BTreeSet::new();
            // 上位 §8.1：`rollout-*` 的大小写变体走 excluded_legacy 门（计数须为 0 → 实际即 HOLD）。
            if name != lower {
                buckets.insert(OutOfScopeBucket::FilenameCaseVariant);
            }
            // 上位 §2.2：**任意** Codex `rollout-*.json`，不问内容。
            if lower.ends_with(".json") {
                buckets.insert(OutOfScopeBucket::CodexRolloutJson);
            }
            if buckets.is_empty() {
                // 精确小写 `rollout-*.jsonl`：逐行 record，不归本分类器。
                //
                // 这里此前是 `debug_assert!(lower.ends_with(".jsonl"))`，而
                // **`debug_assert!` 在 release 里被整条编译掉**（R2 第 15 条 / R-E-98 H3）：
                // 小写的 `rollout-x.txt` / `.yaml` / 无扩展名走到这一格时被判 `NotWholeFile`
                // 当逐行 record 处理，**从闭世界分类里逃了出去**。而 release 恰恰是唯一
                // 会真跑语料的档（debug 跑批量嵌入是被明令禁止的），于是那道断言在
                // 唯一要紧的档里等于不存在。
                //
                // **断言是判断，不是防线。** 一旦分类结论依赖它，它就必须是真分支。
                if !lower.ends_with(".jsonl") {
                    return WholeFileDisposition::hold_bucket(
                        OutOfScopeBucket::UnknownWholeFileSchema,
                    );
                }
                WholeFileDisposition::NotWholeFile
            } else {
                WholeFileDisposition::hold_buckets(buckets)
            }
        }
        Origin::ClaudeCode => {
            if ext_exact(path, "jsonl") {
                return WholeFileDisposition::NotWholeFile;
            }
            let is_whole_file = matches!(ext_lower(path).as_deref(), Some("json") | Some("claude"));
            if !is_whole_file {
                return WholeFileDisposition::hold_bucket(OutOfScopeBucket::UnknownWholeFileSchema);
            }
            match counter.count_messages(path, bytes) {
                Err(e) => WholeFileDisposition::SkippedUnparsable { detail: e.detail },
                Ok(n) if n >= 1 => {
                    // `W0-1` §B.3：产消息的 Claude legacy / Desktop sidecar → 立即 HOLD。
                    WholeFileDisposition::hold_bucket(OutOfScopeBucket::ClaudeLegacyEmitting)
                }
                Ok(_) => classify_zero_message_document(bytes),
            }
        }
        Origin::Openclaw => {
            // `W0-1` §B.3：openclaw 无 whole-file 分支。
            if ext_exact(path, "jsonl") {
                WholeFileDisposition::NotWholeFile
            } else {
                WholeFileDisposition::hold_bucket(OutOfScopeBucket::UnknownWholeFileSchema)
            }
        }
    }
}

/// 零消息的 whole-file 文档：已知 metadata 形态 → `excluded_known_metadata`；否则 HOLD。
fn classify_zero_message_document(bytes: &[u8]) -> WholeFileDisposition {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return WholeFileDisposition::hold_bucket(OutOfScopeBucket::UnknownWholeFileSchema);
    };
    let Ok(value) = serde_json::from_str::<JsonValue>(text) else {
        return WholeFileDisposition::SkippedUnparsable {
            detail: "零消息文档不可解为 JSON".to_string(),
        };
    };
    let JsonValue::Object(map) = value else {
        // 顶层不是对象：类型漂移。
        return WholeFileDisposition::hold_bucket(OutOfScopeBucket::TypeDrift);
    };
    if KNOWN_METADATA_REQUIRED_KEYS
        .iter()
        .all(|k| map.contains_key(*k))
    {
        WholeFileDisposition::ExcludedKnownMetadata
    } else {
        WholeFileDisposition::hold_bucket(OutOfScopeBucket::UnknownWholeFileSchema)
    }
}

/// 批量分类：**每条路径都给出一个明确处置**，不吞任何一条。
///
/// 读取用「先开 fd、再对该 fd 取 metadata」的顺序，不做 stat-then-open：
/// 大小守卫与内容读取都作用在同一个已打开的文件上，路径在两次访问之间被换绑也影响不到它。
/// 打不开或读不动的候选落到 `unreadable` HOLD，而不是被过滤掉。
pub fn classify_whole_file_paths(
    inputs: &[WholeFileInput],
    counter: &dyn WholeFileMessageCounter,
) -> WholeFileReport {
    use std::io::Read;

    let mut verdicts = Vec::with_capacity(inputs.len());
    for input in inputs {
        let disposition = match fs::File::open(&input.path) {
            Err(e) => WholeFileDisposition::Hold {
                reason: HoldReason::Unreadable,
                detail: Some(format!("打不开：{e}")),
            },
            Ok(mut file) => match file.metadata() {
                Err(e) => WholeFileDisposition::Hold {
                    reason: HoldReason::Unreadable,
                    detail: Some(format!("取不到 metadata：{e}")),
                },
                Ok(meta) if meta.len() > WHOLE_FILE_SIZE_GUARD_BYTES => {
                    WholeFileDisposition::SkippedOversize {
                        byte_len: meta.len(),
                    }
                }
                Ok(_) => {
                    let mut bytes = Vec::new();
                    match file.read_to_end(&mut bytes) {
                        Err(e) => WholeFileDisposition::Hold {
                            reason: HoldReason::Unreadable,
                            detail: Some(format!("读失败：{e}")),
                        },
                        Ok(_) => classify_whole_file(input.origin, &input.path, &bytes, counter),
                    }
                }
            },
        };
        verdicts.push(WholeFileVerdict {
            origin: input.origin,
            path: input.path.clone(),
            disposition,
        });
    }
    WholeFileReport { verdicts }
}

// ===========================================================================
// golden vectors 移植（附录 §C）
// ===========================================================================

#[cfg(test)]
mod w0_0_vector_tests {
    use super::*;
    use serde_json::{Map, Value};
    use std::collections::{BTreeMap, BTreeSet};

    // -- fixture 装载 ------------------------------------------------------

    fn fixture_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/phase3/w0-0")
    }

    fn load_json(name: &str) -> Value {
        let path = fixture_dir().join(name);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读不到 fixture {}: {e}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|e| panic!("fixture {} 不可解: {e}", path.display()))
    }

    fn index() -> Map<String, Value> {
        match load_json("index.json") {
            Value::Object(m) => m,
            _ => panic!("index.json 顶层不是对象"),
        }
    }

    fn vector_files() -> Vec<String> {
        let idx = index();
        idx.get("vector_files")
            .and_then(|v| v.as_array())
            .expect("index.json 缺 vector_files")
            .iter()
            .map(|v| v.as_str().expect("vector_files 元素不是字符串").to_string())
            .collect()
    }

    fn all_cases() -> Vec<(String, Map<String, Value>)> {
        let mut out = Vec::new();
        for file in vector_files() {
            let doc = load_json(&file);
            let cases = doc
                .get("cases")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("{file} 缺 cases 数组"));
            for c in cases {
                let obj = c
                    .as_object()
                    .unwrap_or_else(|| panic!("{file} 的 case 不是对象"));
                out.push((file.clone(), obj.clone()));
            }
        }
        out
    }

    // -- 用例键的闭世界（§C 第 4 道机器断言）--------------------------------

    /// 用例顶层允许出现的键。附录 §C 的两张表（输入形态 + 伴随键）加标准用例元数据。
    const ALLOWED_CASE_KEYS: &[&str] = &[
        // 元数据
        "case_id",
        "expect",
        "expected",
        "expected_error",
        "expected_error_any_of",
        "note",
        "object_kind",
        "set_name",
        "set_names",
        // 输入形态
        "input",
        "input_leaf",
        "input_leaf_list",
        "input_generator",
        "input_items",
        "input_scenario",
        "input_case_refs",
        // 伴随键
        "input_tags",
        // 用例自带的旁证（不是输入，只被断言消费）
        "live_file_len",
        "insertion_order_payload_hashes",
    ];

    /// `input_scenario` 的 `op` 与其内嵌键（附录 §C 表，闭世界）。
    fn scenario_allowed_keys(op: &str) -> &'static [&'static str] {
        match op {
            "set_root" => &["op", "set_name", "item_roots"],
            "set_verify" => &["op", "set_name", "declared_root", "declared_count", "items"],
            "referential_integrity" => &["op", "manifest_payload_hashes", "sidecar_items"],
            "open_bundle" => &[
                "op",
                "declared_payload_hash",
                "actual_payload_bytes_hex",
                "expected_root_arg",
                "manifest_case_ref",
            ],
            _ => panic!("input_scenario.op {op:?} 不在附录 §C 的闭世界表内"),
        }
    }

    #[test]
    fn case_keys_are_closed_world() {
        for (file, case) in all_cases() {
            let id = case_id(&case);
            for key in case.keys() {
                assert!(
                    ALLOWED_CASE_KEYS.contains(&key.as_str()),
                    "{file} / {id}: 用例键 {key:?} 不在附录 §C 的闭世界表内"
                );
            }
            assert!(
                !(case.contains_key("expected_error")
                    && case.contains_key("expected_error_any_of")),
                "{file} / {id}: expected_error 与 expected_error_any_of 互斥"
            );
            if let Some(Value::Object(sc)) = case.get("input_scenario") {
                let op = sc
                    .get("op")
                    .and_then(|v| v.as_str())
                    .unwrap_or_else(|| panic!("{id}: input_scenario 缺 op"));
                let allowed = scenario_allowed_keys(op);
                for key in sc.keys() {
                    assert!(
                        allowed.contains(&key.as_str()),
                        "{file} / {id}: input_scenario 内嵌键 {key:?} 不在 op={op} 的闭世界表内"
                    );
                }
            }
            if let (Some(Value::Object(input)), Some(Value::Object(tags))) =
                (case.get("input"), case.get("input_tags"))
            {
                let ik: BTreeSet<&String> = input.keys().collect();
                let tk: BTreeSet<&String> = tags.keys().collect();
                assert_eq!(
                    ik, tk,
                    "{file} / {id}: input 与 input_tags 键集必须完全相同"
                );
            }
        }
    }

    // -- 用例执行 ----------------------------------------------------------

    fn case_id(case: &Map<String, Value>) -> String {
        case.get("case_id")
            .and_then(|v| v.as_str())
            .unwrap_or("<无 case_id>")
            .to_string()
    }

    fn hexs(h: &[u8; 32]) -> Value {
        Value::String(hex_lower(h))
    }

    fn parse_hex(s: &str) -> [u8; 32] {
        hex32(s).unwrap_or_else(|e| panic!("{s:?} 不是合法 hex: {e}"))
    }

    fn flat_input(case: &Map<String, Value>) -> &Map<String, Value> {
        match case.get("input") {
            Some(Value::Object(m)) => m,
            _ => panic!("{}: input 不是对象", case_id(case)),
        }
    }

    fn bare_leaves(case: &Map<String, Value>) -> Vec<(String, Tag, Value)> {
        let input = flat_input(case);
        let tags = match case.get("input_tags") {
            Some(Value::Object(m)) => m,
            _ => panic!("{}: 缺 input_tags", case_id(case)),
        };
        input
            .iter()
            .map(|(k, v)| {
                let t = tags
                    .get(k)
                    .and_then(|t| t.as_str())
                    .unwrap_or_else(|| panic!("{}: input_tags 缺 {k}", case_id(case)));
                let mut chars = t.chars();
                let c = chars.next().unwrap_or('?');
                assert!(chars.next().is_none(), "input_tags 必须是单字符 tag");
                let tag = Tag::from_char(c).unwrap_or_else(|| panic!("未知 tag {c:?}"));
                (k.clone(), tag, v.clone())
            })
            .collect()
    }

    fn scalar_fields_from(map: &Map<String, Value>) -> ScalarFields {
        map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }

    /// 一条用例跑出来的事实集，键名与向量 `expected` 的键名一一对应。
    type Facts = BTreeMap<String, Value>;

    fn object_facts(domain: &str, outcome: &ObjectOutcome) -> Facts {
        let mut f = Facts::new();
        f.insert("root".into(), hexs(&outcome.root));
        f.insert("tree_hash".into(), hexs(&outcome.tree_hash));
        f.insert(
            "sorted_keys".into(),
            Value::Array(
                outcome
                    .sorted_keys
                    .iter()
                    .map(|k| Value::String(k.clone()))
                    .collect(),
            ),
        );
        f.insert("leaf_count".into(), Value::from(outcome.sorted_keys.len()));
        f.insert(
            "root_domain".into(),
            Value::String(format!("{DOMAIN_ROOT}/root/{domain}")),
        );
        f
    }

    /// 生成式用例（§C 的 `input_generator`）：按 `payload_bytes_rule` 造 manifest。
    fn generated_manifest(payload_count: usize) -> RawObject {
        let mut refs: Vec<([u8; 32], usize)> = Vec::with_capacity(payload_count);
        for i in 0..payload_count {
            let bytes = i.to_string().into_bytes();
            refs.push((payload_hash(&bytes), bytes.len()));
        }
        refs.sort_by_key(|r| r.0);
        let items: Vec<ScalarFields> = refs
            .into_iter()
            .map(|(h, len)| {
                vec![
                    ("payload_hash".to_string(), Value::String(hex_lower(&h))),
                    ("byte_length".to_string(), Value::from(len)),
                ]
            })
            .collect();
        vec![
            (
                "object_kind".into(),
                RawField::Scalar(Value::String("bundle.manifest".into())),
            ),
            (
                "schema_version".into(),
                RawField::Scalar(Value::String(SCHEMA_VERSION.into())),
            ),
            (
                "seal_result_root".into(),
                RawField::Scalar(Value::String(SEAL_RESULT_EMPTY_ROOT.into())),
            ),
            (
                "mirror_fingerprint".into(),
                RawField::Scalar(Value::String(MIRROR_FINGERPRINT_SAMPLE.into())),
            ),
            ("promotable".into(), RawField::Scalar(Value::Bool(false))),
            ("payloads".into(), RawField::Array(items)),
        ]
    }

    const SEAL_RESULT_EMPTY_ROOT: &str =
        "05f778e463412b238dbfd9a7fbd12a70f935e9135e8c18cc628580ce8b9b0687";
    const MIRROR_FINGERPRINT_SAMPLE: &str =
        "27b9515405b9e7236a33d5174a6dcb27c6770c66cc506e554956681e0ca72f41";

    /// 跑一条用例，返回「事实集」或它撞上的错误码。
    fn run_case(
        case: &Map<String, Value>,
        roots_by_case: &BTreeMap<String, [u8; 32]>,
    ) -> Result<Facts, ErrorCode> {
        let id = case_id(case);

        // §A.4 的 leaf 级用例。
        if let Some(Value::Object(leaf)) = case.get("input_leaf") {
            let key = leaf
                .get("key")
                .and_then(|v| v.as_str())
                .expect("input_leaf.key");
            let tag_s = leaf
                .get("tag")
                .and_then(|v| v.as_str())
                .expect("input_leaf.tag");
            let tag = Tag::from_char(tag_s.chars().next().expect("tag 非空")).expect("已知 tag");
            let value = leaf.get("value").expect("input_leaf.value");
            let enc = encode_scalar(tag, matches!(tag, Tag::N), value, key).map_err(|e| e.code)?;
            let pre = leaf_preimage(key, enc.tag, &enc.bytes);
            let mut f = Facts::new();
            f.insert(
                "preimage_hex".into(),
                Value::String(pre.iter().map(|b| format!("{b:02x}")).collect::<String>()),
            );
            f.insert(
                "leaf_digest".into(),
                hexs(&leaf_digest(key, enc.tag, &enc.bytes)),
            );
            return Ok(f);
        }

        // JSON 对象表达不了的输入：同一 leaf key 出现两次。
        if let Some(Value::Array(list)) = case.get("input_leaf_list") {
            let domain = case
                .get("object_kind")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{id}: input_leaf_list 用例缺 object_kind"));
            let leaves: Vec<(String, Tag, Value)> = list
                .iter()
                .map(|e| {
                    let a = e.as_array().expect("input_leaf_list 元素是三元组");
                    let key = a[0].as_str().expect("key").to_string();
                    let tag =
                        Tag::from_char(a[1].as_str().expect("tag").chars().next().expect("非空"))
                            .expect("已知 tag");
                    (key, tag, a[2].clone())
                })
                .collect();
            return compute_bare_leaf_root(domain, &leaves)
                .map(|o| object_facts(domain, &o))
                .map_err(|e| e.code);
        }

        // 元素数以百万计的生成式用例。
        if let Some(Value::Object(generator)) = case.get("input_generator") {
            let kind = generator
                .get("kind")
                .and_then(|v| v.as_str())
                .expect("generator.kind");
            let count = generator
                .get("payload_count")
                .and_then(|v| v.as_u64())
                .expect("generator.payload_count") as usize;
            assert!(
                generator.contains_key("payload_bytes_rule"),
                "{id}: input_generator 必须给生成规则"
            );
            let object = generated_manifest(count);
            return compute_object_root(kind, &object)
                .map(|o| {
                    let mut f = Facts::new();
                    f.insert("root".into(), hexs(&o.root));
                    f
                })
                .map_err(|e| e.code);
        }

        // 集合级用例。
        if let Some(Value::Array(items)) = case.get("input_items") {
            let fields: Vec<ScalarFields> = items
                .iter()
                .map(|i| scalar_fields_from(i.as_object().expect("item 是对象")))
                .collect();
            if let Some(Value::Array(names)) = case.get("set_names") {
                let mut roots = Map::new();
                for n in names {
                    let name = n.as_str().expect("set_names 元素是字符串");
                    let v = verify_set(name, &fields).map_err(|e| e.code)?;
                    roots.insert(name.to_string(), hexs(&v.set_root));
                }
                let mut f = Facts::new();
                f.insert("set_roots".into(), Value::Object(roots));
                return Ok(f);
            }
            let name = case
                .get("set_name")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{id}: input_items 用例缺 set_name / set_names"));
            let v = verify_set(name, &fields).map_err(|e| e.code)?;
            let mut f = Facts::new();
            f.insert("holds_set_root".into(), hexs(&v.set_root));
            f.insert(
                "item_roots".into(),
                Value::Array(v.item_roots.iter().map(hexs).collect()),
            );
            f.insert("count".into(), Value::from(fields.len()));
            let keys: Vec<Vec<String>> = fields
                .iter()
                .map(|x| item_sort_key(name, x).expect("排序键"))
                .collect();
            f.insert(
                "sort_key_tuples".into(),
                Value::Array(
                    keys.iter()
                        .map(|k| Value::Array(k.iter().map(|s| Value::String(s.clone())).collect()))
                        .collect(),
                ),
            );
            f.insert(
                "sort_key_order".into(),
                Value::Array(
                    keys.iter()
                        .map(|k| Value::String(k.last().cloned().unwrap_or_default()))
                        .collect(),
                ),
            );
            return Ok(f);
        }

        // 跨对象用例。
        if let Some(Value::Object(sc)) = case.get("input_scenario") {
            return run_scenario(&id, sc, roots_by_case).map(|_| Facts::new());
        }

        // 纯派生断言。
        if let Some(Value::Array(refs)) = case.get("input_case_refs") {
            let mut f = Facts::new();
            let roots: Vec<[u8; 32]> = refs
                .iter()
                .map(|r| {
                    let rid = r.as_str().expect("case_ref 是字符串");
                    *roots_by_case
                        .get(rid)
                        .unwrap_or_else(|| panic!("{id}: 引用的用例 {rid} 没有 root"))
                })
                .collect();
            f.insert("must_differ".into(), Value::Bool(roots[0] != roots[1]));
            f.insert("zero_byte_root".into(), hexs(&roots[0]));
            f.insert("no_complete_record_root".into(), hexs(&roots[1]));
            return Ok(f);
        }

        // 单对象用例。
        let domain = case
            .get("object_kind")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{id}: 缺 object_kind"));

        // §C.1 ①（按向量语料修正的可执行读法）：只有保留域 test.tree 且 input_tags 在场
        // 才走裸 leaf 路径；其余 object_kind 一律走字段表，input_tags 只是冗余声明。
        if domain == RESERVED_KIND && case.contains_key("input_tags") {
            let leaves = bare_leaves(case);
            let outcome = compute_bare_leaf_root(domain, &leaves).map_err(|e| e.code)?;
            let mut f = object_facts(domain, &outcome);
            let mut ordered: Vec<(String, [u8; 32])> = leaves
                .iter()
                .map(|(k, t, v)| {
                    let enc = encode_scalar(*t, matches!(t, Tag::N), v, k).expect("已通过校验");
                    (k.clone(), leaf_digest(k, enc.tag, &enc.bytes))
                })
                .collect();
            ordered.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            let digests: Vec<[u8; 32]> = ordered.iter().map(|(_, d)| *d).collect();
            f.insert(
                "levels".into(),
                Value::Array(
                    tree_levels(&digests)
                        .into_iter()
                        .map(|lvl| Value::Array(lvl.iter().map(hexs).collect()))
                        .collect(),
                ),
            );
            // 域分离对照：同一 leaf 集在两个域下的 root。
            f.insert(
                "root_test_tree".into(),
                hexs(&object_root(RESERVED_KIND, outcome.tree_hash).expect("合法 kind")),
            );
            let other = object_root("seal.entry", outcome.tree_hash).expect("合法 kind");
            f.insert("root_seal_entry".into(), hexs(&other));
            f.insert(
                "roots_must_differ".into(),
                Value::Bool(other != outcome.root),
            );
            f.insert("tree_hash_equal".into(), Value::Bool(true));
            return Ok(f);
        }

        let object = raw_object_from_flat_map(flat_input(case)).map_err(|e| e.code)?;
        let outcome = compute_object_root(domain, &object).map_err(|e| e.code)?;
        let mut f = object_facts(domain, &outcome);

        if let Some(live_len) = case.get("live_file_len").and_then(|v| v.as_i64()) {
            let boundary = flat_input(case)
                .get("boundary_t")
                .and_then(|v| v.as_i64())
                .expect("boundary_t");
            f.insert(
                "boundary_t_ne_len".into(),
                Value::Bool(boundary != live_len),
            );
        }
        if domain == "bundle.manifest" {
            let payloads = manifest_payloads(&object).map_err(|e| e.code)?;
            f.insert(
                "payloads_sorted_order".into(),
                Value::Array(payloads.iter().map(|p| hexs(&p.payload_hash)).collect()),
            );
        }
        // 追加用例：与前一次 seal 的 root 必须不同。
        if let Some(prior) = case
            .get("expected")
            .and_then(|e| e.get("prior_root"))
            .and_then(|v| v.as_str())
        {
            let prior_hash = parse_hex(prior);
            f.insert("prior_root".into(), Value::String(prior.to_string()));
            f.insert(
                "must_differ".into(),
                Value::Bool(prior_hash != outcome.root),
            );
        }
        Ok(f)
    }

    fn run_scenario(
        id: &str,
        sc: &Map<String, Value>,
        roots_by_case: &BTreeMap<String, [u8; 32]>,
    ) -> Result<(), ErrorCode> {
        let op = sc.get("op").and_then(|v| v.as_str()).expect("op");
        match op {
            "set_root" => {
                let name = sc
                    .get("set_name")
                    .and_then(|v| v.as_str())
                    .expect("set_name");
                let roots: Vec<[u8; 32]> = sc
                    .get("item_roots")
                    .and_then(|v| v.as_array())
                    .expect("item_roots")
                    .iter()
                    .map(|r| parse_hex(r.as_str().expect("hex")))
                    .collect();
                set_root(name, &roots).map(|_| ()).map_err(|e| e.code)
            }
            "set_verify" => {
                let name = sc
                    .get("set_name")
                    .and_then(|v| v.as_str())
                    .expect("set_name");
                let declared_root = parse_hex(
                    sc.get("declared_root")
                        .and_then(|v| v.as_str())
                        .expect("declared_root"),
                );
                let declared_count = sc
                    .get("declared_count")
                    .and_then(|v| v.as_i64())
                    .expect("declared_count");
                let items: Vec<ScalarFields> = sc
                    .get("items")
                    .and_then(|v| v.as_array())
                    .expect("items")
                    .iter()
                    .map(|i| scalar_fields_from(i.as_object().expect("item 是对象")))
                    .collect();
                verify_declared_set(name, &items, declared_root, declared_count)
                    .map(|_| ())
                    .map_err(|e| e.code)
            }
            "referential_integrity" => {
                let manifest: Vec<[u8; 32]> = sc
                    .get("manifest_payload_hashes")
                    .and_then(|v| v.as_array())
                    .expect("manifest_payload_hashes")
                    .iter()
                    .map(|h| parse_hex(h.as_str().expect("hex")))
                    .collect();
                let mut refs: Vec<([u8; 32], String)> = Vec::new();
                for (i, item) in sc
                    .get("sidecar_items")
                    .and_then(|v| v.as_array())
                    .expect("sidecar_items")
                    .iter()
                    .enumerate()
                {
                    let o = item.as_object().expect("sidecar_item 是对象");
                    let kind = o.get("kind").and_then(|v| v.as_str()).expect("kind");
                    let field = match kind {
                        "seal.entry" => "payload_hash",
                        "seal.tombstone" => "base_payload_hash",
                        other => panic!("{id}: sidecar_item kind {other} 不引用 payload"),
                    };
                    let h = o.get(field).and_then(|v| v.as_str()).expect("引用字段");
                    refs.push((parse_hex(h), format!("sidecar_items[{i}].{field}")));
                }
                check_referential_integrity(&manifest, &refs)
                    .map(|_| ())
                    .map_err(|e| e.code)
            }
            "open_bundle" => run_open_bundle_scenario(id, sc, roots_by_case),
            other => panic!("{id}: 未知 op {other}"),
        }
    }

    fn run_open_bundle_scenario(
        id: &str,
        sc: &Map<String, Value>,
        roots_by_case: &BTreeMap<String, [u8; 32]>,
    ) -> Result<(), ErrorCode> {
        let tmp = tempfile::tempdir().expect("建临时 bundle 目录");
        let dir = tmp.path();

        if let Some(declared) = sc.get("declared_payload_hash").and_then(|v| v.as_str()) {
            // 盘上 payload 字节被改：manifest 声明一个 hash，盘上放的是另一批字节。
            let actual_hex = sc
                .get("actual_payload_bytes_hex")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{id}: 缺 actual_payload_bytes_hex"));
            let bytes = decode_hex_bytes(actual_hex);
            let declared_hash = parse_hex(declared);
            write_bundle(
                dir,
                &[(declared_hash, bytes.len() as i64, bytes.clone())],
                MIRROR_FINGERPRINT_SAMPLE,
            );
            let manifest = read_manifest_object(dir);
            let root = compute_object_root("bundle.manifest", &manifest)
                .expect("manifest 自身合法")
                .root;
            return verify_bundle_root(dir, &hex_lower(&root))
                .map(|_| ())
                .map_err(|e| {
                    e.wire_code()
                        .unwrap_or_else(|| panic!("{id}: 非 wire 错误 {e}"))
                });
        }

        // 外部期望 root 与盘上 manifest 重算不等。
        let case_ref = sc
            .get("manifest_case_ref")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{id}: 缺 manifest_case_ref"));
        assert!(
            roots_by_case.contains_key(case_ref),
            "{id}: 引用的 manifest 用例 {case_ref} 未跑出 root"
        );
        let payloads = v09_payloads();
        write_bundle(dir, &payloads, MIRROR_FINGERPRINT_SAMPLE);
        let expected_arg = sc
            .get("expected_root_arg")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("{id}: 缺 expected_root_arg"));
        verify_bundle_root(dir, expected_arg)
            .map(|_| ())
            .map_err(|e| {
                e.wire_code()
                    .unwrap_or_else(|| panic!("{id}: 非 wire 错误 {e}"))
            })
    }

    fn decode_hex_bytes(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex 长度必须是偶数");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("合法 hex"))
            .collect()
    }

    /// `v09` 三条 payload 的真实字节（入库序 a/b/c）。
    fn v09_payloads() -> Vec<([u8; 32], i64, Vec<u8>)> {
        [
            b"{\"a\":1}\n".to_vec(),
            b"{\"b\":2}\n".to_vec(),
            b"{\"c\":3}\n".to_vec(),
        ]
        .into_iter()
        .map(|b| (payload_hash(&b), b.len() as i64, b))
        .collect()
    }

    /// 把一批 payload 写成一个最小但完整的 bundle 目录（落盘格式由本模块自定，§A.11）。
    fn write_bundle(dir: &Path, payloads: &[([u8; 32], i64, Vec<u8>)], fingerprint: &str) {
        fs::create_dir_all(dir.join(PAYLOAD_DIR)).expect("建 payloads 目录");
        for (h, _, bytes) in payloads {
            fs::write(dir.join(PAYLOAD_DIR).join(hex_lower(h)), bytes).expect("写 payload");
        }
        let mut empty_roots = Map::new();
        for name in SET_NAMES {
            empty_roots.insert(
                format!("{name}_root"),
                Value::String(hex_lower(&set_root(name, &[]).expect("空 set root"))),
            );
            empty_roots.insert(format!("{name}_count"), Value::from(0));
            fs::write(
                dir.join(sidecar_file_name(name)),
                serde_json::to_string_pretty(&serde_json::json!({ "items": [] })).expect("序列化"),
            )
            .expect("写 sidecar");
        }
        let mut seal_result = empty_roots;
        seal_result.insert("object_kind".into(), Value::String("seal.result".into()));
        seal_result.insert(
            "schema_version".into(),
            Value::String(SCHEMA_VERSION.into()),
        );
        let seal_result_object =
            raw_object_from_flat_map(&seal_result).expect("seal.result 扁平形态可还原");
        let seal_result_root = compute_object_root("seal.result", &seal_result_object)
            .expect("seal.result 合法")
            .root;
        fs::write(
            dir.join(SEAL_RESULT_FILE),
            serde_json::to_string_pretty(&Value::Object(seal_result)).expect("序列化"),
        )
        .expect("写 seal-result");

        let mut sorted: Vec<&([u8; 32], i64, Vec<u8>)> = payloads.iter().collect();
        sorted.sort_by_key(|r| r.0);
        let mut manifest = Map::new();
        manifest.insert(
            "object_kind".into(),
            Value::String("bundle.manifest".into()),
        );
        manifest.insert(
            "schema_version".into(),
            Value::String(SCHEMA_VERSION.into()),
        );
        manifest.insert(
            "seal_result_root".into(),
            Value::String(hex_lower(&seal_result_root)),
        );
        manifest.insert(
            "mirror_fingerprint".into(),
            if sorted.is_empty() {
                Value::Null
            } else {
                Value::String(fingerprint.to_string())
            },
        );
        manifest.insert("promotable".into(), Value::Bool(false));
        if sorted.is_empty() {
            manifest.insert("payloads".into(), Value::Array(vec![]));
        } else {
            for (i, (h, len, _)) in sorted.iter().enumerate() {
                manifest.insert(
                    format!("payloads[{i:06}].payload_hash"),
                    Value::String(hex_lower(h)),
                );
                manifest.insert(format!("payloads[{i:06}].byte_length"), Value::from(*len));
            }
        }
        fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_string_pretty(&Value::Object(manifest)).expect("序列化"),
        )
        .expect("写 manifest");
    }

    fn read_manifest_object(dir: &Path) -> RawObject {
        let text = fs::read_to_string(dir.join(MANIFEST_FILE)).expect("读 manifest");
        let Value::Object(m) = serde_json::from_str::<Value>(&text).expect("manifest 可解")
        else {
            panic!("manifest 顶层不是对象");
        };
        raw_object_from_flat_map(&m).expect("manifest 扁平形态可还原")
    }

    // -- 主判据：73 条用例逐条 accept/reject + 码 + root 三项相等 -------------

    #[test]
    fn golden_vectors_all_pass() {
        let mut roots_by_case: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        let cases = all_cases();
        let mut executed = 0usize;

        // 两遍：第一遍**真跑**单对象 accept 用例并收下算出来的 root（派生用例与 open_bundle
        // 要引用它们）；第二遍全判。收的是**算出来的**值而不是 expected 里那串，
        // 否则派生断言会退化成「expected == expected」的自证。
        {
            let empty = BTreeMap::new();
            for (_, case) in &cases {
                if case.get("expect").and_then(|v| v.as_str()) != Some("accept") {
                    continue;
                }
                if !case.contains_key("input") {
                    continue;
                }
                // 带 prior_root 的用例要引用第一遍的产物，留到第二遍再跑。
                if case
                    .get("expected")
                    .and_then(|e| e.get("prior_root"))
                    .is_some()
                {
                    continue;
                }
                if let Ok(facts) = run_case(case, &empty)
                    && let Some(Value::String(r)) = facts.get("root")
                {
                    roots_by_case.insert(case_id(case), parse_hex(r));
                }
            }
        }

        for (file, case) in &cases {
            let id = case_id(case);
            let expect = case
                .get("expect")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{file} / {id}: 缺 expect"));
            let outcome = run_case(case, &roots_by_case);
            executed += 1;

            match expect {
                "reject" => {
                    let want = case
                        .get("expected_error")
                        .and_then(|v| v.as_str())
                        .unwrap_or_else(|| panic!("{file} / {id}: reject 用例缺 expected_error"));
                    match outcome {
                        Ok(_) => panic!("{file} / {id}: 期望 {want}，实得 accept"),
                        Err(code) => assert_eq!(code.as_str(), want, "{file} / {id}: 错误码不符"),
                    }
                }
                "accept" => {
                    if let Some(v) = case.get("expected_error") {
                        assert!(
                            v.is_null(),
                            "{file} / {id}: accept 用例的 expected_error 必须缺失或为 null"
                        );
                    }
                    let facts = match outcome {
                        Ok(f) => f,
                        Err(code) => panic!("{file} / {id}: 期望 accept，实得 {code}"),
                    };
                    if let Some(Value::Object(expected)) = case.get("expected") {
                        for (key, want) in expected {
                            let got = facts.get(key).unwrap_or_else(|| {
                                panic!("{file} / {id}: expected 键 {key} 没有被任何断言消费")
                            });
                            assert_eq!(got, want, "{file} / {id}: {key} 不符");
                        }
                    }
                }
                other => panic!("{file} / {id}: expect 只能是 accept / reject，实得 {other}"),
            }
        }

        // 非循环判据：`prior_root` 必须是本语料里**另一条用例真算出来的** root，
        // 不能只是一串与自己相等的 hex。放在全语料跑完之后判，因为它需要完整的引用表。
        for (file, case) in &cases {
            if let Some(prior) = case
                .get("expected")
                .and_then(|e| e.get("prior_root"))
                .and_then(|v| v.as_str())
            {
                let prior_hash = parse_hex(prior);
                assert!(
                    roots_by_case.values().any(|r| *r == prior_hash),
                    "{file} / {}: prior_root 不是本语料里任何一条用例算出来的 root",
                    case_id(case)
                );
            }
        }

        let declared = index()
            .get("case_count")
            .and_then(|v| v.as_u64())
            .expect("index.json 缺 case_count") as usize;
        assert_eq!(
            executed, declared,
            "跑过的用例数与 index.json 的 case_count 不符"
        );
    }

    // -- index.json 的元数据判据 --------------------------------------------

    #[test]
    fn index_constants_match_implementation() {
        let idx = index();
        let c = idx
            .get("constants")
            .and_then(|v| v.as_object())
            .expect("constants");
        assert_eq!(
            c.get("empty_tree_hash").and_then(|v| v.as_str()),
            Some(hex_lower(&empty_tree_hash()).as_str())
        );
        assert_eq!(
            c.get("empty_payload_hash").and_then(|v| v.as_str()),
            Some(hex_lower(&payload_hash(&[])).as_str())
        );
        assert_eq!(
            c.get("index_width").and_then(|v| v.as_u64()),
            Some(INDEX_WIDTH as u64)
        );
        assert_eq!(
            c.get("index_max_length").and_then(|v| v.as_u64()),
            Some(MAX_INDEXED_ARRAY_LEN as u64)
        );
        assert_eq!(
            idx.get("domain_root").and_then(|v| v.as_str()),
            Some(DOMAIN_ROOT)
        );
        assert_eq!(
            idx.get("schema_version").and_then(|v| v.as_str()),
            Some(SCHEMA_VERSION)
        );
        assert_eq!(idx.get("hash").and_then(|v| v.as_str()), Some("SHA-256"));

        let kinds: BTreeSet<String> = idx
            .get("object_kinds")
            .and_then(|v| v.as_array())
            .expect("object_kinds")
            .iter()
            .map(|v| v.as_str().expect("字符串").to_string())
            .collect();
        assert_eq!(
            kinds,
            OBJECT_KIND_UNIVERSE.iter().map(|s| s.to_string()).collect()
        );

        let sets: BTreeSet<String> = idx
            .get("set_names")
            .and_then(|v| v.as_array())
            .expect("set_names")
            .iter()
            .map(|v| v.as_str().expect("字符串").to_string())
            .collect();
        assert_eq!(sets, SET_NAMES.iter().map(|s| s.to_string()).collect());
    }

    #[test]
    fn index_error_code_universe_matches_implementation() {
        let idx = index();
        let declared: BTreeSet<String> = idx
            .get("error_code_universe")
            .and_then(|v| v.as_array())
            .expect("error_code_universe")
            .iter()
            .map(|v| v.as_str().expect("字符串").to_string())
            .collect();
        let mine: BTreeSet<String> = ErrorCode::ALL
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        assert_eq!(declared, mine, "错误码全集不符");
        assert_eq!(ErrorCode::ALL.len(), 26, "§D-8：错误码全集仍是 26 个");
        assert_eq!(mine.len(), 26, "码字面量不得重复");

        let uncovered = idx
            .get("error_codes_uncovered")
            .and_then(|v| v.as_array())
            .expect("error_codes_uncovered");
        assert!(uncovered.is_empty(), "error_codes_uncovered 必须为空");
    }

    /// §C 的第 5 道：每个声称已覆盖的码都必须至少有一条**确定性**用例
    /// （单值 `expected_error`，不带 `expected_error_any_of`），且那条用例必须带可执行输入。
    #[test]
    fn every_covered_error_code_has_a_deterministic_executable_case() {
        let input_forms = [
            "input",
            "input_leaf",
            "input_leaf_list",
            "input_generator",
            "input_items",
            "input_scenario",
            "input_case_refs",
        ];
        let mut deterministic: BTreeSet<String> = BTreeSet::new();
        for (file, case) in all_cases() {
            let Some(code) = case.get("expected_error").and_then(|v| v.as_str()) else {
                continue;
            };
            assert!(
                !case.contains_key("expected_error_any_of"),
                "{file} / {}: 确定性用例不得带 any_of",
                case_id(&case)
            );
            assert!(
                input_forms.iter().any(|k| case.contains_key(*k)),
                "{file} / {}: 只有 expected_error 而没有输入的用例不算覆盖",
                case_id(&case)
            );
            deterministic.insert(code.to_string());
        }
        let covered: BTreeSet<String> = index()
            .get("error_codes_covered")
            .and_then(|v| v.as_array())
            .expect("error_codes_covered")
            .iter()
            .map(|v| v.as_str().expect("字符串").to_string())
            .collect();
        let missing: Vec<&String> = covered.difference(&deterministic).collect();
        assert!(
            missing.is_empty(),
            "这些码没有确定性可执行用例：{missing:?}"
        );
    }

    #[test]
    fn anchor_roots_are_reproduced() {
        // 锚点名 → 产出它的用例（`set/holds-3seg` 走 set root，其余走对象 root）。
        const ANCHOR_CASES: &[(&str, &str, &str)] = &[
            (
                "bundle.manifest/three-payloads",
                "v09.bundle-three-payloads",
                "root",
            ),
            (
                "bundle.manifest/zero-payload",
                "v02.bundle-zero-payload",
                "root",
            ),
            ("seal.result/empty", "v02.seal-result-empty", "root"),
            ("seal.entry/v03", "v03.single", "root"),
            ("seal.entry/v04-append", "v04.append", "root"),
            ("seal.entry/zero-byte", "v03b.zero-byte", "root"),
            (
                "seal.entry/no-complete-record",
                "v03b.no-complete-record",
                "root",
            ),
            ("seal.tombstone/v05", "v05.tombstone", "root"),
            ("seal.hold/path-reincarnation", "v06.reincarnation", "root"),
            (
                "seal.hold/out-of-scope-format",
                "v07.hold.out-of-scope-format",
                "root",
            ),
            (
                "seal.observed_after_cut/v10",
                "v10.observed-after-cut",
                "root",
            ),
            ("set/holds-3seg", "v07.holds-set-3seg", "holds_set_root"),
            ("test.tree/ordering", "v01.ordering", "root"),
            ("seal.hold/root-unreadable", "v11.root-unreadable", "root"),
            ("seal.hold/merged-detail", "v12.d6.merged-detail", "root"),
        ];

        let cases = all_cases();
        let empty = BTreeMap::new();
        let mut computed: BTreeMap<String, Facts> = BTreeMap::new();
        for (_, case) in &cases {
            if case.get("expect").and_then(|v| v.as_str()) != Some("accept") {
                continue;
            }
            let id = case_id(case);
            if !ANCHOR_CASES.iter().any(|(_, cid, _)| *cid == id) {
                continue;
            }
            let facts =
                run_case(case, &empty).unwrap_or_else(|e| panic!("{id}: 期望 accept，实得 {e}"));
            computed.insert(id, facts);
        }

        let idx = index();
        let anchors = idx
            .get("anchor_roots")
            .and_then(|v| v.as_object())
            .expect("anchor_roots");
        assert_eq!(anchors.len(), ANCHOR_CASES.len(), "anchor 条数不符");
        for (anchor, case_ref, fact_key) in ANCHOR_CASES {
            let want = anchors
                .get(*anchor)
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("index.json 缺 anchor {anchor}"));
            let facts = computed
                .get(*case_ref)
                .unwrap_or_else(|| panic!("锚点 {anchor} 的用例 {case_ref} 没跑出来"));
            let got = facts
                .get(*fact_key)
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("{case_ref} 没有 {fact_key}"));
            assert_eq!(got, want, "anchor {anchor} 复现不符");
        }
    }

    // -- §C.1 ① 的可执行读法：钉死「带 input_tags 的生产对象仍走字段表」-------

    #[test]
    fn production_object_with_input_tags_still_uses_field_table() {
        // v03b.reject.empty-reason-on-nonzero 带 input_tags 且 object_kind 是 seal.entry。
        // 照 §C.1 ① 的字面（「带 input_tags 的 input 是裸 leaf 集」）实现会把它 accept，
        // 因为跨字段的当且仅当关系是字段表级校验，裸 leaf 路径根本做不出来。
        let doc = load_json("v03b-empty-record-entries.json");
        let case = doc
            .get("cases")
            .and_then(|v| v.as_array())
            .expect("cases")
            .iter()
            .find(|c| {
                c.get("case_id").and_then(|v| v.as_str())
                    == Some("v03b.reject.empty-reason-on-nonzero")
            })
            .expect("找得到该用例")
            .as_object()
            .expect("对象");
        assert!(
            case.contains_key("input_tags"),
            "前提：该用例确实带 input_tags"
        );
        let object = raw_object_from_flat_map(flat_input(case)).expect("扁平形态可还原");
        let e = compute_object_root("seal.entry", &object).expect_err("必须被拒");
        assert_eq!(e.code, ErrorCode::EmptyReason);

        // 反面：同一份输入若真按裸 leaf 集处理，就会 accept —— 这正是那条读法的可观测后果。
        let leaves = bare_leaves(case);
        assert!(
            compute_bare_leaf_root("seal.entry", &leaves).is_ok(),
            "裸 leaf 路径确实不做跨字段校验（故不能用它处理生产对象）"
        );
    }
}

// ===========================================================================
// 自撰测试：七类失败面、死枚举发射点、bundle 读取、F-6 whole-file 处置
// ===========================================================================

#[cfg(test)]
mod w0_0_surface_tests {
    use super::*;
    use serde_json::{Value, json};

    fn scalar(kv: &[(&str, Value)]) -> RawObject {
        kv.iter()
            .map(|(k, v)| (k.to_string(), RawField::Scalar(v.clone())))
            .collect()
    }

    fn sample_entry_fields() -> ScalarFields {
        vec![
            ("object_kind".into(), json!("seal.entry")),
            ("origin".into(), json!("claude_code")),
            ("canonical_path".into(), json!("/a/b.jsonl")),
            ("boundary_t".into(), json!(8)),
            (
                "prefix_digest".into(),
                json!("e346432021b04179518d9614f3560ccd71354a4ee101ddcb893d6959a9d6301c"),
            ),
            (
                "payload_hash".into(),
                json!(hex_lower(&payload_hash(b"{\"a\":1}\n"))),
            ),
            ("session_id".into(), json!("s")),
            ("empty_reason".into(), Value::Null),
            ("dev".into(), json!(1)),
            ("ino".into(), json!(2)),
        ]
    }

    // ---- 取值域封闭且静态 -------------------------------------------------

    #[test]
    fn error_code_literals_are_unique_and_static() {
        let mut seen = std::collections::BTreeSet::new();
        for c in ErrorCode::ALL {
            assert!(seen.insert(c.as_str()), "码字面量重复：{c}");
            assert!(c.as_str().starts_with("E-"), "码字面量形态：{c}");
        }
        assert_eq!(seen.len(), 26);
    }

    #[test]
    fn out_of_scope_bucket_enum_order_matches_byte_order() {
        // §D-6：canonical 串按 **UTF-8 字节升序**，不按 §B.5.1 表的行序。
        // BTreeSet 的迭代序 = 变体声明序，所以这两者必须一致，否则 canonical 串会拼错。
        let by_decl: Vec<&str> = OutOfScopeBucket::ALL.iter().map(|b| b.as_str()).collect();
        let mut by_bytes = by_decl.clone();
        by_bytes.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(by_decl, by_bytes);
        // 表序陷阱的正面记录：末两行照抄表序就是非法串。
        assert!(check_out_of_scope_detail("type-drift,unknown-whole-file-schema").is_ok());
        assert_eq!(
            check_out_of_scope_detail("unknown-whole-file-schema,type-drift")
                .unwrap_err()
                .code,
            ErrorCode::HoldDetail
        );
    }

    #[test]
    fn every_closed_world_enum_variant_round_trips() {
        for o in [Origin::ClaudeCode, Origin::Codex, Origin::Openclaw] {
            assert_eq!(Origin::parse(o.as_str()), Some(o));
        }
        for e in [EmptyReason::ZeroByteFile, EmptyReason::NoCompleteRecord] {
            assert_eq!(EmptyReason::parse(e.as_str()), Some(e));
        }
        for h in [
            HoldReason::Unreadable,
            HoldReason::FdUnavailable,
            HoldReason::PrefixRewritten,
            HoldReason::StabilityTimeout,
            HoldReason::PathReincarnation,
            HoldReason::OutOfScopeFormat,
        ] {
            assert_eq!(HoldReason::parse(h.as_str()), Some(h));
        }
        for b in OutOfScopeBucket::ALL {
            assert_eq!(OutOfScopeBucket::parse(b.as_str()), Some(b));
        }
        assert_eq!(Origin::parse("gemini_cli"), None);
        assert_eq!(HoldReason::parse("no-record-boundary"), None);
    }

    /// E-7 死枚举：`Tag` 的每个变体都要有构造点。`a` / `m` 在生产字段表里不可达
    /// （§A.2 明说 `m` 是前向预留），故在这里给它们各一个真实的编码断言。
    #[test]
    fn every_tag_variant_encodes() {
        let cases: [(Tag, Value, &[u8]); 8] = [
            (Tag::S, json!("x"), b"x"),
            (Tag::P, json!("/x"), b"/x"),
            (Tag::I, json!(-7), b"-7"),
            (Tag::B, json!(true), b"true"),
            (Tag::N, Value::Null, b""),
            (
                Tag::X,
                json!("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
                &[
                    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
                    0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
                    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                ],
            ),
            (Tag::A, json!([]), b""),
            (Tag::M, json!({}), b""),
        ];
        for (tag, value, want) in cases {
            let enc = encode_scalar(tag, matches!(tag, Tag::N), &value, "k")
                .unwrap_or_else(|e| panic!("{tag:?} 应可编码：{e}"));
            assert_eq!(enc.bytes, want, "{tag:?} 的 value bytes");
            assert_eq!(Tag::from_char(tag.byte() as char), Some(tag));
            // 四种空形态互不相等（§A.7）：n / a / m 的 value bytes 都是空串，
            // 但 tag 字节不同，故 leaf digest 必不同。
            let _ = leaf_digest("k", enc.tag, &enc.bytes);
        }
        let n = leaf_digest("k", Tag::N, &[]);
        let a = leaf_digest("k", Tag::A, &[]);
        let m = leaf_digest("k", Tag::M, &[]);
        assert_ne!(n, a);
        assert_ne!(a, m);
        assert_ne!(n, m);
        assert_eq!(Tag::from_char('?'), None);
    }

    // ---- 每一层以自己的名义拒绝：断言具体错误类型与文本，不宽接 ----------

    #[test]
    fn rejections_carry_their_own_code_and_a_locating_detail() {
        let bad_kind = compute_object_root("sealentry", &scalar(&[])).unwrap_err();
        assert_eq!(bad_kind.code, ErrorCode::KindForm);
        assert!(
            bad_kind.detail.contains("sealentry"),
            "detail 要能定位：{bad_kind}"
        );

        let bad_set = set_root("payloads", &[]).unwrap_err();
        assert_eq!(bad_set.code, ErrorCode::UnknownSet);
        assert!(bad_set.detail.contains("payloads"));

        let bad_path =
            compute_bare_leaf_root("test.tree", &[("a".into(), Tag::P, json!("relative/x"))])
                .unwrap_err();
        assert_eq!(bad_path.code, ErrorCode::PathForm);
        assert!(bad_path.detail.contains("relative/x"));
    }

    // ---- E-2：外部数据形状未校验 -----------------------------------------

    #[test]
    fn e2_external_shapes_are_validated_not_coerced() {
        // 字符串塞给 i 标签、浮点塞给 i 标签、超 int64 的整数：全部报 E-VALUE-FORM，
        // 没有任何一条走 as / unwrap 的隐式转换。
        for bad in [
            json!("8"),
            json!(8.5),
            json!(9223372036854775808u64),
            json!(true),
        ] {
            let e = encode_scalar(Tag::I, false, &bad, "boundary_t").unwrap_err();
            assert_eq!(e.code, ErrorCode::ValueForm, "输入 {bad:?}");
        }
        // 负值只在字段级穷举表上报 E-FIELD-RANGE；tag 级不拦（§D-2）。
        assert!(encode_scalar(Tag::I, false, &json!(-1), "dev").is_ok());
    }

    #[test]
    fn e2_hex_is_not_normalized() {
        let upper = "E346432021B04179518D9614F3560CCD71354A4EE101DDCB893D6959A9D6301C";
        assert_eq!(hex32(upper).unwrap_err().code, ErrorCode::ValueForm);
    }

    // ---- E-1 / E-3 / E-4 / E-6：bundle 读取面 ----------------------------

    fn build_bundle(dir: &Path, payloads: &[Vec<u8>]) -> [u8; 32] {
        fs::create_dir_all(dir.join(PAYLOAD_DIR)).expect("建 payloads 目录");
        let mut refs: Vec<([u8; 32], usize)> = Vec::new();
        for bytes in payloads {
            let h = payload_hash(bytes);
            fs::write(dir.join(PAYLOAD_DIR).join(hex_lower(&h)), bytes).expect("写 payload");
            refs.push((h, bytes.len()));
        }
        refs.sort_by_key(|r| r.0);

        let mut seal_result = serde_json::Map::new();
        seal_result.insert("object_kind".into(), json!("seal.result"));
        seal_result.insert("schema_version".into(), json!(SCHEMA_VERSION));
        for name in SET_NAMES {
            seal_result.insert(
                format!("{name}_root"),
                json!(hex_lower(&set_root(name, &[]).expect("空 set root"))),
            );
            seal_result.insert(format!("{name}_count"), json!(0));
            fs::write(
                dir.join(sidecar_file_name(name)),
                serde_json::to_string(&json!({"items": []})).expect("序列化"),
            )
            .expect("写 sidecar");
        }
        let seal_result_object =
            raw_object_from_flat_map(&seal_result).expect("seal.result 可还原");
        let seal_result_root = compute_object_root("seal.result", &seal_result_object)
            .expect("seal.result 合法")
            .root;
        fs::write(
            dir.join(SEAL_RESULT_FILE),
            serde_json::to_string(&Value::Object(seal_result)).expect("序列化"),
        )
        .expect("写 seal-result");

        let mut manifest = serde_json::Map::new();
        manifest.insert("object_kind".into(), json!("bundle.manifest"));
        manifest.insert("schema_version".into(), json!(SCHEMA_VERSION));
        manifest.insert(
            "seal_result_root".into(),
            json!(hex_lower(&seal_result_root)),
        );
        manifest.insert("promotable".into(), json!(false));
        if refs.is_empty() {
            manifest.insert("mirror_fingerprint".into(), Value::Null);
            manifest.insert("payloads".into(), json!([]));
        } else {
            manifest.insert(
                "mirror_fingerprint".into(),
                json!("27b9515405b9e7236a33d5174a6dcb27c6770c66cc506e554956681e0ca72f41"),
            );
            for (i, (h, len)) in refs.iter().enumerate() {
                manifest.insert(
                    format!("payloads[{i:06}].payload_hash"),
                    json!(hex_lower(h)),
                );
                manifest.insert(format!("payloads[{i:06}].byte_length"), json!(*len));
            }
        }
        let manifest_object = raw_object_from_flat_map(&manifest).expect("manifest 可还原");
        let root = compute_object_root("bundle.manifest", &manifest_object)
            .expect("manifest 合法")
            .root;
        fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_string(&Value::Object(manifest)).expect("序列化"),
        )
        .expect("写 manifest");
        root
    }

    /// E-1 短读：大 payload 必须原样读回，不能停在第一次 `read` 返回的那一段。
    #[test]
    fn e1_large_payload_round_trips_whole() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let big: Vec<u8> = (0..512 * 1024u32).map(|i| (i % 251) as u8).collect();
        let root = build_bundle(tmp.path(), std::slice::from_ref(&big));
        let bundle = verify_bundle_root(tmp.path(), &hex_lower(&root)).expect("校验通过");
        let got = bundle
            .read_payload(&payload_hash(&big))
            .expect("按 hash 读得到");
        assert_eq!(got.len(), big.len());
        assert_eq!(got, big);
    }

    /// E-4 路径换绑：payload 的身份是内容 hash，所以每次读都重验；
    /// 盘上文件被换掉之后再读必须报 `E-PAYLOAD-HASH-MISMATCH`，而不是把新字节交出去。
    #[test]
    fn e4_payload_swapped_after_verify_is_caught_on_read() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let original = b"{\"a\":1}\n".to_vec();
        let root = build_bundle(tmp.path(), std::slice::from_ref(&original));
        let bundle = verify_bundle_root(tmp.path(), &hex_lower(&root)).expect("校验通过");
        let h = payload_hash(&original);
        assert_eq!(bundle.read_payload(&h).expect("首次读"), original);

        // unlink 后同名重建（inode 变了、路径没变）。
        let path = tmp.path().join(PAYLOAD_DIR).join(hex_lower(&h));
        fs::remove_file(&path).expect("删旧文件");
        fs::write(&path, b"{\"a\":9}\n").expect("同名重建");
        let e = bundle.read_payload(&h).expect_err("必须被抓住");
        assert_eq!(e.wire_code(), Some(ErrorCode::PayloadHashMismatch));
    }

    /// E-6：I/O 与落盘形态问题不得逃成一个 `E-*` 码。
    #[test]
    fn e6_io_errors_do_not_escape_as_wire_codes() {
        let tmp = tempfile::tempdir().expect("临时目录");
        // §D-7 第 2 条：bundle_dir 里没有 manifest → 不在本附录的错误码空间内。
        let e = verify_bundle_root(tmp.path(), &hex_lower(&[0u8; 32])).expect_err("必须失败");
        assert_eq!(e.wire_code(), None, "实得 {e}");
        assert!(matches!(e, BundleError::Io { .. }));

        // §D-7 第 3 条：按不在 manifest 内的 hash 读 → 调用方用法错误，同样不是 E-*。
        let dir = tempfile::tempdir().expect("临时目录");
        let root = build_bundle(dir.path(), &[b"{\"a\":1}\n".to_vec()]);
        let bundle = verify_bundle_root(dir.path(), &hex_lower(&root)).expect("校验通过");
        let e = bundle.read_payload(&[7u8; 32]).expect_err("必须失败");
        assert_eq!(e.wire_code(), None, "实得 {e}");
        assert!(matches!(e, BundleError::UnknownPayload { .. }));
    }

    /// §D-7 第 1 条：manifest 列了、盘上没有 → `E-PAYLOAD-HASH-MISMATCH`。
    #[test]
    fn d7_missing_payload_file_is_a_hash_mismatch() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let bytes = b"{\"a\":1}\n".to_vec();
        let root = build_bundle(tmp.path(), std::slice::from_ref(&bytes));
        fs::remove_file(
            tmp.path()
                .join(PAYLOAD_DIR)
                .join(hex_lower(&payload_hash(&bytes))),
        )
        .expect("删 payload");
        let e = verify_bundle_root(tmp.path(), &hex_lower(&root)).expect_err("必须失败");
        assert_eq!(e.wire_code(), Some(ErrorCode::PayloadHashMismatch));
    }

    /// 零 payload 的 bundle 也要能过：`payloads` 产 `a` leaf、`mirror_fingerprint` 为 null。
    #[test]
    fn empty_bundle_verifies() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let root = build_bundle(tmp.path(), &[]);
        let bundle = verify_bundle_root(tmp.path(), &hex_lower(&root)).expect("校验通过");
        assert!(bundle.payloads().is_empty());
        assert_eq!(bundle.root(), root);
    }

    /// 引用完整性：sidecar 引用了一个 manifest 里没有的 payload。
    #[test]
    fn dangling_payload_reference_is_caught_end_to_end() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let bytes = b"{\"a\":1}\n".to_vec();
        build_bundle(tmp.path(), std::slice::from_ref(&bytes));

        // 往 entries sidecar 里塞一条引用了别的 hash 的 entry，并把 seal.result 对齐。
        let mut fields = sample_entry_fields();
        for (k, v) in fields.iter_mut() {
            if k == "payload_hash" {
                *v = json!(hex_lower(&payload_hash(b"never-added")));
            }
        }
        let item: serde_json::Map<String, Value> = fields.iter().cloned().collect();
        fs::write(
            tmp.path().join(sidecar_file_name("entries")),
            serde_json::to_string(&json!({"items": [Value::Object(item)]})).expect("序列化"),
        )
        .expect("写 sidecar");

        let entries_root = verify_set("entries", std::slice::from_ref(&fields))
            .expect("单条 entry 合法")
            .set_root;
        let text = fs::read_to_string(tmp.path().join(SEAL_RESULT_FILE)).expect("读 seal-result");
        let Value::Object(mut sr) = serde_json::from_str::<Value>(&text).expect("可解") else {
            panic!("顶层不是对象");
        };
        sr.insert("entries_root".into(), json!(hex_lower(&entries_root)));
        sr.insert("entries_count".into(), json!(1));
        let sr_object = raw_object_from_flat_map(&sr).expect("可还原");
        let sr_root = compute_object_root("seal.result", &sr_object)
            .expect("合法")
            .root;
        fs::write(
            tmp.path().join(SEAL_RESULT_FILE),
            serde_json::to_string(&Value::Object(sr)).expect("序列化"),
        )
        .expect("写 seal-result");

        // manifest 的 seal_result_root 也要跟上，否则先撞落盘形态不一致。
        let mtext = fs::read_to_string(tmp.path().join(MANIFEST_FILE)).expect("读 manifest");
        let Value::Object(mut mf) = serde_json::from_str::<Value>(&mtext).expect("可解") else {
            panic!("顶层不是对象");
        };
        mf.insert("seal_result_root".into(), json!(hex_lower(&sr_root)));
        let mf_object = raw_object_from_flat_map(&mf).expect("可还原");
        let new_root = compute_object_root("bundle.manifest", &mf_object)
            .expect("合法")
            .root;
        fs::write(
            tmp.path().join(MANIFEST_FILE),
            serde_json::to_string(&Value::Object(mf)).expect("序列化"),
        )
        .expect("写 manifest");

        let e = verify_bundle_root(tmp.path(), &hex_lower(&new_root)).expect_err("必须失败");
        assert_eq!(e.wire_code(), Some(ErrorCode::DanglingPayload));
    }

    // ---- 读取适配层：两种落盘形态 canonical 化到同一字段集 -----------------

    /// 合成的 D5 profile manifest（嵌套 `payloads` 对象数组）。
    fn nested_manifest_json(payloads: &[(String, i64)]) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        m.insert("object_kind".into(), json!("bundle.manifest"));
        m.insert("schema_version".into(), json!(SCHEMA_VERSION));
        m.insert(
            "seal_result_root".into(),
            json!("05f778e463412b238dbfd9a7fbd12a70f935e9135e8c18cc628580ce8b9b0687"),
        );
        if payloads.is_empty() {
            m.insert("mirror_fingerprint".into(), Value::Null);
        } else {
            m.insert(
                "mirror_fingerprint".into(),
                json!("27b9515405b9e7236a33d5174a6dcb27c6770c66cc506e554956681e0ca72f41"),
            );
        }
        m.insert("promotable".into(), json!(false));
        m.insert(
            "payloads".into(),
            Value::Array(
                payloads
                    .iter()
                    .map(|(h, len)| json!({"payload_hash": h, "byte_length": len}))
                    .collect(),
            ),
        );
        m
    }

    fn flat_manifest_json(payloads: &[(String, i64)]) -> serde_json::Map<String, Value> {
        let mut m = nested_manifest_json(payloads);
        m.remove("payloads");
        if payloads.is_empty() {
            m.insert("payloads".into(), json!([]));
        } else {
            for (i, (h, len)) in payloads.iter().enumerate() {
                m.insert(format!("payloads[{i:06}].payload_hash"), json!(h));
                m.insert(format!("payloads[{i:06}].byte_length"), json!(len));
            }
        }
        m
    }

    /// 三条 payload，已按 32 原始字节升序（与合成字节的真实 hash 一致）。
    fn synthetic_sorted_payloads() -> Vec<(Vec<u8>, String, i64)> {
        let mut v: Vec<(Vec<u8>, String, i64)> = [
            b"{\"a\":1}\n".to_vec(),
            b"{\"b\":2}\n".to_vec(),
            b"{\"c\":3}\n".to_vec(),
        ]
        .into_iter()
        .map(|b| {
            let h = payload_hash(&b);
            let len = b.len() as i64;
            (b, hex_lower(&h), len)
        })
        .collect();
        v.sort_by(|a, b| a.1.cmp(&b.1));
        v
    }

    /// 嵌套形态与扁平形态必须 canonical 化到同一字段集，因而同一 root。
    #[test]
    fn nested_and_flat_payload_forms_produce_the_same_root() {
        let refs: Vec<(String, i64)> = synthetic_sorted_payloads()
            .into_iter()
            .map(|(_, h, len)| (h, len))
            .collect();

        let nested =
            raw_object_from_flat_map(&nested_manifest_json(&refs)).expect("嵌套形态可还原");
        let flat = raw_object_from_flat_map(&flat_manifest_json(&refs)).expect("扁平形态可还原");

        let a = compute_object_root("bundle.manifest", &nested).expect("合法");
        let b = compute_object_root("bundle.manifest", &flat).expect("合法");
        assert_eq!(a.root, b.root, "两种落盘形态的 root 必须相同");
        assert_eq!(
            a.sorted_keys, b.sorted_keys,
            "两种形态的 leaf key 集必须相同"
        );
        // 空数组两种形态同样等价（都产容器自身的 a leaf）。
        let empty_nested = raw_object_from_flat_map(&nested_manifest_json(&[])).expect("可还原");
        let empty_flat = raw_object_from_flat_map(&flat_manifest_json(&[])).expect("可还原");
        assert_eq!(
            compute_object_root("bundle.manifest", &empty_nested)
                .expect("合法")
                .root,
            compute_object_root("bundle.manifest", &empty_flat)
                .expect("合法")
                .root
        );
    }

    #[test]
    fn mixed_payload_forms_are_rejected() {
        let refs: Vec<(String, i64)> = synthetic_sorted_payloads()
            .into_iter()
            .map(|(_, h, len)| (h, len))
            .collect();
        let mut mixed = nested_manifest_json(&refs);
        mixed.insert("payloads[000000].payload_hash".into(), json!(refs[0].0));
        let e = raw_object_from_flat_map(&mixed).expect_err("两种形态混用必须被拒");
        assert_eq!(e.code, ErrorCode::ValueForm);
        assert!(e.detail.contains("payloads"), "detail 要能定位：{e}");
    }

    #[test]
    fn nested_array_element_must_be_an_object() {
        let mut bad = nested_manifest_json(&[]);
        bad.insert("payloads".into(), json!([1, 2, 3]));
        let e = raw_object_from_flat_map(&bad).expect_err("元素不是对象必须被拒");
        assert_eq!(e.code, ErrorCode::ValueForm);
    }

    /// D5 profile：目录里只有 `manifest.json`（嵌套形态）、`payloads/`，
    /// 外加一个本附录不认识的 candidate-db sidecar。没有 `seal-result.json`、
    /// 没有四个集合 sidecar——`seal.result` 只以 `seal_result_root` 哈希引用存在。
    #[test]
    fn d5_profile_bundle_verifies_and_reports_its_scope() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let dir = tmp.path();
        fs::create_dir_all(dir.join(PAYLOAD_DIR)).expect("建 payloads 目录");

        let payloads = synthetic_sorted_payloads();
        for (bytes, h, _) in &payloads {
            fs::write(dir.join(PAYLOAD_DIR).join(h), bytes).expect("写 payload");
        }
        let refs: Vec<(String, i64)> = payloads.iter().map(|(_, h, l)| (h.clone(), *l)).collect();
        let manifest_map = nested_manifest_json(&refs);
        fs::write(
            dir.join(MANIFEST_FILE),
            serde_json::to_string(&Value::Object(manifest_map.clone())).expect("序列化"),
        )
        .expect("写 manifest");
        // 产出方自己的 sidecar：本附录不认识它，读取层也不该因为它在场就改变行为。
        fs::write(
            dir.join("sidecar.candidate-db.json"),
            serde_json::to_string(&json!({
                "name": "candidate.db",
                "object_kind": "d5.candidate_db",
                "payload": refs[0].0,
                "snapshot_root": "00000000000000000000000000000000000000000000000000000000000000ff"
            }))
            .expect("序列化"),
        )
        .expect("写 candidate-db sidecar");

        let expected = compute_object_root(
            "bundle.manifest",
            &raw_object_from_flat_map(&manifest_map).expect("可还原"),
        )
        .expect("合法")
        .root;

        let bundle = verify_bundle_root(dir, &hex_lower(&expected)).expect("D5 profile 必须能开");
        assert_eq!(bundle.root(), expected);
        assert_eq!(bundle.payloads().len(), 3);

        // **跳过必须是可观测的**：没有 seal.result / sidecar 就如实记 false，不静默降级。
        let scope = bundle.scope();
        assert!(scope.manifest_verified);
        assert!(scope.payload_bytes_verified);
        assert!(
            !scope.seal_result_verified,
            "盘上没有 seal.result，不得声称验过"
        );
        assert!(
            !scope.sidecars_verified,
            "盘上没有四个 sidecar，不得声称验过"
        );

        // 只按 hash 读仍然照常工作。
        let got = bundle
            .read_payload(&payload_hash(&payloads[0].0))
            .expect("按 hash 读得到");
        assert_eq!(got, payloads[0].0);

        // 期望 root 不对时照样报 E-BUNDLE-ROOT-MISMATCH。
        let e = verify_bundle_root(dir, &hex_lower(&[0u8; 32])).expect_err("必须失败");
        assert_eq!(e.wire_code(), Some(ErrorCode::BundleRootMismatch));
    }

    /// 四个 sidecar 只到场一部分 = 残缺输入，必须报错而不是当没看见。
    #[test]
    fn partial_sidecar_set_is_rejected_not_skipped() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let root = build_bundle(tmp.path(), &[b"{\"a\":1}\n".to_vec()]);
        fs::remove_file(tmp.path().join(sidecar_file_name("holds"))).expect("删一份 sidecar");
        let e = verify_bundle_root(tmp.path(), &hex_lower(&root)).expect_err("必须失败");
        assert_eq!(e.wire_code(), None);
        assert!(matches!(e, BundleError::Malformed { .. }), "实得 {e}");
    }

    /// 关掉全量 payload 重算不削弱内容寻址：检查只是移到读时，且跳过被如实记下来。
    #[test]
    fn skipping_bulk_payload_verification_is_recorded_and_read_still_verifies() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let bytes = b"{\"a\":1}\n".to_vec();
        let root = build_bundle(tmp.path(), std::slice::from_ref(&bytes));
        let h = payload_hash(&bytes);

        // 先把盘上的字节换掉：全量重算档必须当场报错。
        fs::write(
            tmp.path().join(PAYLOAD_DIR).join(hex_lower(&h)),
            b"{\"a\":9}\n",
        )
        .expect("换字节");
        let e = verify_bundle_root(tmp.path(), &hex_lower(&root)).expect_err("全量档必须抓住");
        assert_eq!(e.wire_code(), Some(ErrorCode::PayloadHashMismatch));

        // 跳过档能开，但 scope 如实记 false，且读到那条时仍然报错。
        let bundle = verify_bundle_root_with(
            tmp.path(),
            &hex_lower(&root),
            VerifyOptions {
                verify_payload_bytes: false,
            },
        )
        .expect("跳过档可以开");
        assert!(!bundle.scope().payload_bytes_verified);
        let e = bundle.read_payload(&h).expect_err("读时必须抓住");
        assert_eq!(e.wire_code(), Some(ErrorCode::PayloadHashMismatch));
    }
}

// ===========================================================================
// F-6：whole-file 处置（pin parser 二分 + known metadata 形态 + 批量对账）
// ===========================================================================

#[cfg(test)]
mod h3_read_json_object_tests {
    use super::*;

    fn write(dir: &std::path::Path, name: &str, text: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        p
    }

    // ── H3 · #14（R-E-98 H3 / R2 第 14 条）──────────────────────────
    //
    // 落盘读取先 `serde_json::from_str` 进 `Value::Object`，**重复键在那一步就被
    // 后者覆盖前者地折叠掉了**，于是 wire 层那道 `E-DUP-KEY` 对真实 JSON 文件形同虚设：
    // 它查的是一个**已经没有重复键**的结构，永远查不出东西来。
    //
    // 危害不是「少报一个错」：`{"a":1,"a":2}` 与 `{"a":2}` 会被读成同一份内容，
    // 而在一个按字节摘要定身份的系统里，两份不同字节读出同一份含义 = 身份判据被绕过。
    #[test]
    fn h3_read_json_object_rejects_duplicate_keys_instead_of_folding_them() {
        let tmp = tempfile::TempDir::new().unwrap();

        let dup = write(tmp.path(), "dup.json", r#"{"a": 1, "b": 2, "a": 3}"#);
        let err = read_json_object(&dup).expect_err("顶层重复键必须被拒，不能静默折叠");
        let text = format!("{err:?}");
        assert!(
            text.contains("E-DUP-KEY"),
            "必须以具名错误码拒，实得：{text}"
        );
        assert!(text.contains('a'), "错误要点出是哪个键：{text}");

        // 嵌套层同样不许折叠 —— 折叠发生在解析器里，不分深浅。
        let nested = write(tmp.path(), "nested.json", r#"{"outer": {"k": 1, "k": 2}}"#);
        let err = read_json_object(&nested).expect_err("嵌套对象里的重复键同样必须被拒");
        assert!(
            format!("{err:?}").contains("E-DUP-KEY"),
            "嵌套层也必须走同一个具名错误码"
        );

        // 数组元素里的对象也一样（sidecar 的 items[] 正是这个形状）。
        let in_array = write(
            tmp.path(),
            "array.json",
            r#"{"items": [{"id": 1, "id": 2}]}"#,
        );
        assert!(
            format!(
                "{:?}",
                read_json_object(&in_array).expect_err("数组里的对象同样不许折叠")
            )
            .contains("E-DUP-KEY")
        );

        // 阳性对照 1：没有重复键的正常文件必须照常读得出来，且值没被动过。
        let clean = write(
            tmp.path(),
            "clean.json",
            r#"{"a": 1, "nested": {"k": [1, 2, {"z": true}]}, "s": "x", "f": 1.5, "n": null}"#,
        );
        let map = read_json_object(&clean).expect("干净文件必须照常读出来");
        assert_eq!(map.get("a").unwrap(), &serde_json::json!(1));
        assert_eq!(
            map.get("nested").unwrap(),
            &serde_json::json!({"k": [1, 2, {"z": true}]})
        );
        assert_eq!(map.get("f").unwrap(), &serde_json::json!(1.5));
        assert!(map.get("n").unwrap().is_null());

        // 阳性对照 2：两条既有的诊断措辞不能被这次改动带跑偏。
        let not_object = write(tmp.path(), "arr.json", "[1, 2, 3]");
        assert!(
            format!(
                "{:?}",
                read_json_object(&not_object).expect_err("顶层不是对象必须拒")
            )
            .contains("顶层不是 JSON 对象")
        );
        let broken = write(tmp.path(), "broken.json", "{not json");
        assert!(
            format!(
                "{:?}",
                read_json_object(&broken).expect_err("坏 JSON 必须拒")
            )
            .contains("JSON 不可解")
        );
    }
}

#[cfg(test)]
mod whole_file_disposition_tests {
    use super::*;
    use serde_json::{Value, json};

    /// 受控替身：消息条数由用例直接给定，用来精确控制「≥1 条 / 0 条」这条二分。
    struct FixedCounter(usize);
    impl WholeFileMessageCounter for FixedCounter {
        fn count_messages(&self, _path: &Path, _bytes: &[u8]) -> Result<usize, PinParseError> {
            Ok(self.0)
        }
    }

    /// 受控替身：解析失败（`W0-1` §B.3 的 debug + continue 分支）。
    struct FailingCounter;
    impl WholeFileMessageCounter for FailingCounter {
        fn count_messages(&self, _path: &Path, _bytes: &[u8]) -> Result<usize, PinParseError> {
            Err(PinParseError {
                detail: "from_str 失败".to_string(),
            })
        }
    }

    /// 更接近真实的替身：真读文档，数顶层 `messages` 数组的长度。
    struct JsonMessagesCounter;
    impl WholeFileMessageCounter for JsonMessagesCounter {
        fn count_messages(&self, _path: &Path, bytes: &[u8]) -> Result<usize, PinParseError> {
            let text = std::str::from_utf8(bytes).map_err(|e| PinParseError {
                detail: format!("非 UTF-8：{e}"),
            })?;
            let value: Value = serde_json::from_str(text).map_err(|e| PinParseError {
                detail: format!("JSON 不可解：{e}"),
            })?;
            match value.get("messages") {
                Some(Value::Array(a)) => Ok(a.len()),
                _ => Ok(0),
            }
        }
    }

    // ── H3 · #15（R-E-98 H3 / R2 第 15 条）──────────────────────────
    //
    // 小写 `rollout-*` 分支的收尾处此前是 `debug_assert!(lower.ends_with(".jsonl"))`。
    // **`debug_assert!` 在 release 里被整条编译掉** —— 于是小写的 `rollout-x.txt` /
    // `.yaml` / 无扩展名走到这里时，判成 `NotWholeFile` 当作逐行 record 处理，
    // **从闭世界分类里逃了出去**。而 release 正是唯一会真跑语料的档
    //（debug 跑批量嵌入是被明令禁止的）。
    //
    // 断言是**判断**不是防线：它只在开发档存在，一旦被当成分类逻辑的一部分，
    // 生产档就是无门。
    #[test]
    fn h3_lowercase_rollout_with_a_foreign_extension_stays_inside_the_closed_world() {
        let counter = FixedCounter(0);
        for name in [
            "rollout-2026-08-20.txt",
            "rollout-2026-08-20.yaml",
            "rollout-2026-08-20",
            "rollout-2026-08-20.jsonl.bak",
        ] {
            let d = classify_whole_file(
                Origin::Codex,
                Path::new(name),
                b"not really jsonl\n",
                &counter,
            );
            assert!(
                matches!(d, WholeFileDisposition::Hold { .. }),
                "{name}：小写 rollout-* 但扩展名不是 .jsonl，必须留在闭世界里（HOLD），\
                 实得 {d:?}"
            );
        }

        // 阳性对照：真正的小写 `rollout-*.jsonl` 仍须照常判 NotWholeFile，
        // 否则上面那条可能只是把整个分支改成了恒 HOLD。
        let d = classify_whole_file(
            Origin::Codex,
            Path::new("rollout-2026-08-20.jsonl"),
            b"{}\n",
            &counter,
        );
        assert!(
            matches!(d, WholeFileDisposition::NotWholeFile),
            "精确小写 rollout-*.jsonl 必须仍然走逐行 record 路径，实得 {d:?}"
        );
    }

    fn hold_detail(d: &WholeFileDisposition) -> Option<&str> {
        match d {
            WholeFileDisposition::Hold { detail, .. } => detail.as_deref(),
            _ => None,
        }
    }

    fn hold_reason(d: &WholeFileDisposition) -> Option<HoldReason> {
        match d {
            WholeFileDisposition::Hold { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// 五种实测键集形状（Stage D 全量实测的分布：733 / 103 / 24 / 4 / 1）。
    fn known_metadata_shapes() -> Vec<(&'static str, usize, Value)> {
        vec![
            (
                "base",
                733,
                json!({"agentType":"x","description":"d","spawnDepth":0,"toolUseId":"t"}),
            ),
            (
                "with-model",
                103,
                json!({"agentType":"x","description":"d","model":"m","spawnDepth":0,"toolUseId":"t"}),
            ),
            (
                "with-parent",
                24,
                json!({"agentType":"x","description":"d","parentAgentId":"p","spawnDepth":1,"toolUseId":"t"}),
            ),
            (
                "with-model-stopped",
                4,
                json!({"agentType":"x","description":"d","model":"m","spawnDepth":0,"stoppedByUser":true,"toolUseId":"t"}),
            ),
            (
                "with-parent-stopped",
                1,
                json!({"agentType":"x","description":"d","parentAgentId":"p","spawnDepth":1,"stoppedByUser":false,"toolUseId":"t"}),
            ),
        ]
    }

    /// F6-1 的二分：≥1 条消息 → 立即 HOLD；0 条且形态已知 → `excluded_known_metadata`，不 HOLD。
    #[test]
    fn f6_1_pin_parser_bisects_on_message_count() {
        let path = Path::new("/x/.claude/projects/p/legacy.json");
        let doc = json!({"agentType":"x","description":"d","spawnDepth":0,"toolUseId":"t"});
        let bytes = serde_json::to_vec(&doc).expect("序列化");

        let emitting = classify_whole_file(Origin::ClaudeCode, path, &bytes, &FixedCounter(1));
        assert_eq!(hold_reason(&emitting), Some(HoldReason::OutOfScopeFormat));
        assert_eq!(
            hold_detail(&emitting),
            Some(OutOfScopeBucket::ClaudeLegacyEmitting.as_str())
        );

        let quiet = classify_whole_file(Origin::ClaudeCode, path, &bytes, &FixedCounter(0));
        assert_eq!(quiet, WholeFileDisposition::ExcludedKnownMetadata);
        assert!(!quiet.is_hold(), "零消息的已知 metadata 不得 HOLD");

        // `.claude` 扩展名走同一条分支。
        let claude_ext = Path::new("/x/.claude/projects/p/legacy.claude");
        assert_eq!(
            classify_whole_file(Origin::ClaudeCode, claude_ext, &bytes, &FixedCounter(0)),
            WholeFileDisposition::ExcludedKnownMetadata
        );
    }

    /// F6-2：五种真实键集形状全部判 known metadata。
    #[test]
    fn f6_2_all_five_observed_shapes_are_known_metadata() {
        let path = Path::new("/x/.claude/projects/p/meta.json");
        for (name, _, doc) in known_metadata_shapes() {
            let bytes = serde_json::to_vec(&doc).expect("序列化");
            let d = classify_whole_file(Origin::ClaudeCode, path, &bytes, &JsonMessagesCounter);
            assert_eq!(
                d,
                WholeFileDisposition::ExcludedKnownMetadata,
                "形状 {name} 应判 known metadata"
            );
        }
        // 声明侧封闭且静态：必需键与实测可选键各自成表，不是一张完整组合白名单。
        assert_eq!(KNOWN_METADATA_REQUIRED_KEYS.len(), 4);
        assert_eq!(KNOWN_METADATA_OBSERVED_OPTIONAL_KEYS.len(), 3);
        for (_, _, doc) in known_metadata_shapes() {
            let map = doc.as_object().expect("对象");
            for k in KNOWN_METADATA_REQUIRED_KEYS {
                assert!(map.contains_key(k), "实测形状必须含必需键 {k}");
            }
            for k in map.keys() {
                assert!(
                    KNOWN_METADATA_REQUIRED_KEYS.contains(&k.as_str())
                        || KNOWN_METADATA_OBSERVED_OPTIONAL_KEYS.contains(&k.as_str()),
                    "实测形状出现了两张表之外的键 {k}"
                );
            }
        }
    }

    /// F6-3：判据是「必需键齐全」，不是完整键集组合白名单——一个从没见过的新可选键
    /// 不得把已知 metadata 判成未知；缺一个必需键才判未知。
    #[test]
    fn f6_3_unseen_optional_key_does_not_break_known_metadata() {
        let path = Path::new("/x/.claude/projects/p/meta.json");

        let unseen = json!({
            "agentType":"x","description":"d","spawnDepth":0,"toolUseId":"t",
            "brandNewOptionalKey":"未来才出现的可选键"
        });
        let d = classify_whole_file(
            Origin::ClaudeCode,
            path,
            &serde_json::to_vec(&unseen).expect("序列化"),
            &JsonMessagesCounter,
        );
        assert_eq!(
            d,
            WholeFileDisposition::ExcludedKnownMetadata,
            "未见过的新可选键不得破坏 known metadata 判定"
        );

        // 同时带实测可选键与新可选键，一样成立。
        let mixed = json!({
            "agentType":"x","description":"d","spawnDepth":0,"toolUseId":"t",
            "model":"m","parentAgentId":"p","stoppedByUser":true,"anotherNewKey":1
        });
        assert_eq!(
            classify_whole_file(
                Origin::ClaudeCode,
                path,
                &serde_json::to_vec(&mixed).expect("序列化"),
                &JsonMessagesCounter
            ),
            WholeFileDisposition::ExcludedKnownMetadata
        );

        // 反面：少一个必需键 → 未知 whole-file schema，判 HOLD。
        let missing = json!({"agentType":"x","description":"d","spawnDepth":0});
        let d = classify_whole_file(
            Origin::ClaudeCode,
            path,
            &serde_json::to_vec(&missing).expect("序列化"),
            &JsonMessagesCounter,
        );
        assert_eq!(
            hold_detail(&d),
            Some(OutOfScopeBucket::UnknownWholeFileSchema.as_str())
        );
    }

    /// F6-4：`excluded_known_metadata` 有真实构造点——在真实形态分布的语料上计数 > 0。
    #[test]
    fn f6_4_excluded_known_metadata_count_is_positive_on_real_shape_corpus() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let root = tmp.path().join("claude-projects");
        fs::create_dir_all(&root).expect("建目录");

        let mut inputs = Vec::new();
        let mut expected_known = 0usize;
        for (name, count, doc) in known_metadata_shapes() {
            let bytes = serde_json::to_vec(&doc).expect("序列化");
            for i in 0..count {
                let p = root.join(format!("{name}-{i}.json"));
                fs::write(&p, &bytes).expect("写 fixture");
                inputs.push(WholeFileInput {
                    origin: Origin::ClaudeCode,
                    path: p,
                });
            }
            expected_known += count;
        }
        assert_eq!(expected_known, 865, "实测分布合计");

        let report = classify_whole_file_paths(&inputs, &JsonMessagesCounter);
        assert!(
            report.excluded_known_metadata_count() > 0,
            "真实形态语料上 excluded_known_metadata 必须 > 0"
        );
        assert_eq!(report.excluded_known_metadata_count(), 865);
        assert_eq!(report.hold_count(), 0, "已知 metadata 一条都不该 HOLD");
    }

    /// F6-5：接口接受一批路径，**对每一条给出明确处置**，不吞任何一条。
    #[test]
    fn f6_5_batch_gives_every_path_an_explicit_disposition() {
        let tmp = tempfile::tempdir().expect("临时目录");
        let dir = tmp.path();

        let known = dir.join("meta.json");
        fs::write(
            &known,
            serde_json::to_vec(
                &json!({"agentType":"x","description":"d","spawnDepth":0,"toolUseId":"t"}),
            )
            .expect("序列化"),
        )
        .expect("写");

        let emitting = dir.join("legacy.json");
        fs::write(
            &emitting,
            serde_json::to_vec(&json!({"messages":[{"role":"system"}]})).expect("序列化"),
        )
        .expect("写");

        let jsonl = dir.join("live.jsonl");
        fs::write(&jsonl, b"{\"a\":1}\n").expect("写");

        let rollout = dir.join("rollout-x.json");
        fs::write(&rollout, b"{}").expect("写");

        let broken = dir.join("broken.json");
        fs::write(&broken, b"{ not json").expect("写");

        let missing = dir.join("gone.json");

        let inputs = vec![
            WholeFileInput {
                origin: Origin::ClaudeCode,
                path: known.clone(),
            },
            WholeFileInput {
                origin: Origin::ClaudeCode,
                path: emitting.clone(),
            },
            WholeFileInput {
                origin: Origin::ClaudeCode,
                path: jsonl.clone(),
            },
            WholeFileInput {
                origin: Origin::Codex,
                path: rollout.clone(),
            },
            WholeFileInput {
                origin: Origin::ClaudeCode,
                path: broken.clone(),
            },
            WholeFileInput {
                origin: Origin::ClaudeCode,
                path: missing.clone(),
            },
        ];
        let report = classify_whole_file_paths(&inputs, &JsonMessagesCounter);

        // 逐条对账：输入几条就必须有几条裁定，且顺序与路径一一对应。
        assert_eq!(report.verdicts.len(), inputs.len(), "不得吞掉任何一条");
        for (i, v) in report.verdicts.iter().enumerate() {
            assert_eq!(v.path, inputs[i].path);
        }

        assert_eq!(
            report.verdicts[0].disposition,
            WholeFileDisposition::ExcludedKnownMetadata
        );
        assert_eq!(
            hold_detail(&report.verdicts[1].disposition),
            Some(OutOfScopeBucket::ClaudeLegacyEmitting.as_str())
        );
        assert_eq!(
            report.verdicts[2].disposition,
            WholeFileDisposition::NotWholeFile
        );
        assert_eq!(
            hold_detail(&report.verdicts[3].disposition),
            Some(OutOfScopeBucket::CodexRolloutJson.as_str())
        );
        assert!(matches!(
            report.verdicts[4].disposition,
            WholeFileDisposition::SkippedUnparsable { .. }
        ));
        // E-3 / E-5：路径消失也必须落到一条明确处置上，而不是被过滤掉。
        assert_eq!(
            hold_reason(&report.verdicts[5].disposition),
            Some(HoldReason::Unreadable)
        );
    }

    /// §D-6 的合并形态在分类器侧真的会被构造出来，且拼出来的串过 `E-HOLD-DETAIL` 校验。
    #[test]
    fn merged_bucket_detail_is_produced_and_valid() {
        let path = Path::new("/x/.codex/sessions/Rollout-x.json");
        let d = classify_whole_file(Origin::Codex, path, b"{}", &FixedCounter(0));
        let detail = hold_detail(&d).expect("必须是 HOLD 并带 detail");
        assert_eq!(detail, "codex-rollout-json,filename-case-variant");
        check_out_of_scope_detail(detail).expect("合并串必须过闭世界校验");

        // 只有大小写变体、扩展名是 .jsonl：只命中一个 bucket。
        let case_only = classify_whole_file(
            Origin::Codex,
            Path::new("/x/.codex/sessions/Rollout-x.jsonl"),
            b"",
            &FixedCounter(0),
        );
        assert_eq!(
            hold_detail(&case_only),
            Some(OutOfScopeBucket::FilenameCaseVariant.as_str())
        );

        // 精确小写 rollout-*.json：只命中 codex-rollout-json（与 v07 的用例同形）。
        let lower_json = classify_whole_file(
            Origin::Codex,
            Path::new("/x/.codex/sessions/rollout-legacy.json"),
            b"",
            &FixedCounter(0),
        );
        assert_eq!(
            hold_detail(&lower_json),
            Some(OutOfScopeBucket::CodexRolloutJson.as_str())
        );

        // 精确小写 rollout-*.jsonl：逐行 record 家族，不归本分类器。
        assert_eq!(
            classify_whole_file(
                Origin::Codex,
                Path::new("/x/.codex/sessions/rollout-ok.jsonl"),
                b"",
                &FixedCounter(0)
            ),
            WholeFileDisposition::NotWholeFile
        );
    }

    #[test]
    fn type_drift_and_unparsable_and_oversize_have_construction_points() {
        let path = Path::new("/x/.claude/projects/p/meta.json");

        // 类型漂移：零消息、但顶层不是对象。
        let drift = classify_whole_file(Origin::ClaudeCode, path, b"[1,2,3]", &FixedCounter(0));
        assert_eq!(
            hold_detail(&drift),
            Some(OutOfScopeBucket::TypeDrift.as_str())
        );

        // pin parser 解析失败：debug + continue。
        let unparsable = classify_whole_file(Origin::ClaudeCode, path, b"{}", &FailingCounter);
        assert!(matches!(
            unparsable,
            WholeFileDisposition::SkippedUnparsable { .. }
        ));

        // 100 MiB 前置守卫。
        let oversize = vec![b'{'; WHOLE_FILE_SIZE_GUARD_BYTES as usize + 1];
        assert_eq!(
            classify_whole_file(Origin::ClaudeCode, path, &oversize, &FixedCounter(1)),
            WholeFileDisposition::SkippedOversize {
                byte_len: WHOLE_FILE_SIZE_GUARD_BYTES + 1
            },
            "守卫必须先于 pin parser 生效"
        );

        // openclaw 无 whole-file 分支。
        assert_eq!(
            classify_whole_file(
                Origin::Openclaw,
                Path::new("/x/.openclaw/sessions/s.jsonl"),
                b"",
                &FixedCounter(0)
            ),
            WholeFileDisposition::NotWholeFile
        );
        assert_eq!(
            hold_detail(&classify_whole_file(
                Origin::Openclaw,
                Path::new("/x/.openclaw/sessions/s.json"),
                b"{}",
                &FixedCounter(0)
            )),
            Some(OutOfScopeBucket::UnknownWholeFileSchema.as_str())
        );
    }

    /// 分类器产出的 HOLD 必须能原样进 `seal.hold` 对象并算出 root
    /// ——处置面与 wire 面接得上，不是两套各自为政的枚举。
    #[test]
    fn classifier_hold_encodes_as_a_valid_seal_hold_object() {
        let d = classify_whole_file(
            Origin::Codex,
            Path::new("/x/.codex/sessions/Rollout-x.json"),
            b"{}",
            &FixedCounter(0),
        );
        let WholeFileDisposition::Hold { reason, detail } = d else {
            panic!("应是 HOLD");
        };
        let object: RawObject = vec![
            ("object_kind".into(), RawField::Scalar(json!("seal.hold"))),
            (
                "origin".into(),
                RawField::Scalar(json!(Origin::Codex.as_str())),
            ),
            (
                "canonical_path".into(),
                RawField::Scalar(json!("/x/.codex/sessions/Rollout-x.json")),
            ),
            ("reason".into(), RawField::Scalar(json!(reason.as_str()))),
            (
                "detail".into(),
                RawField::Scalar(match &detail {
                    Some(s) => json!(s),
                    None => Value::Null,
                }),
            ),
        ];
        compute_object_root("seal.hold", &object).expect("分类器产出的 HOLD 必须是合法 seal.hold");
    }
}
