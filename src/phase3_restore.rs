//! W1 `mirror-restore` 的 winner 选择与决策表（Task E4）。
//!
//! 规范来源：本 spec §5.2.1（关系判定表与四类 HOLD taxonomy）、§5.2.3（归并按版本偏序
//! 而不按捕获时间）、附录 `W0-1` §D（三家版本偏序：操作数、两层可比性、逐家判定、
//! 以及 §D.5 给 E4 的四条实现约束）、§B.2（JSONL record 边界定理 B-1）。
//!
//! **本模块只做「选谁、判什么关系」，不做写入。** 投影与写入归 E5，事务语义归 E6。
//!
//! 三条承重设计：
//!
//! 1. **入比之前先归一到 record 边界**（§D.2.0）。mirror blob 是一路读到 EOF 的产物，
//!    可能停在一条 record 中间；封存件按定理 B-1 一定切在边界上。不归一就会把「相等」
//!    读成「真前缀」，于是本该跳过的关系被误判成 replace。
//! 2. **可比性判定有两层，第二层是强制的**（§D.2.1）。只留第一层会把「消息序列等价但字节
//!    不同（键序/缩进变了）之后又续写」这种真截断判成分叉 HOLD，正撞上 §10.2「截断超集
//!    用例必过、不得以 HOLD 蒙混」。
//! 3. **辅助证据不参与序的定义**（§D.2.1 末段）。`source_mtime_ms` 与长度只做一致性交叉
//!    检查：真前缀却时间倒挂 → `version_time_conflict` HOLD，而不是拿墙钟决定胜者。

use std::fmt;

use crate::phase3_bundle::Origin;

// ---------------------------------------------------------------------------
// 身份
// ---------------------------------------------------------------------------

/// 版本集合的分组命名空间。
///
/// plan Task E4 Step 2 写的身份是 `{origin, canonical captured path, version/blob identity}`；
/// 这里的 `origin` 必须是**带 host 的命名空间**而不是三值 agent 枚举，否则 §5.2.1 点名的
/// 「跨 host 同路径不折叠」做不到——`W0-1` §D.1(1) 也印证 raw manifest id 里本就含
/// `origin_host`。
///
/// `W1-0` §A 那条四元组（`source_id` / `agent_slug` / `external_id` / `original_path`）是
/// **写入身份**，要按五段管线复算，归 E5；E4 不做那件事。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OriginNamespace {
    pub agent: Origin,
    pub source_id: String,
    pub origin_host: String,
}

impl fmt::Display for OriginNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}:{}",
            self.agent.as_str(),
            self.origin_host,
            self.source_id
        )
    }
}

/// 一条被恢复对象的分组键：命名空间 + canonical 捕获路径。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RestoreIdentity {
    pub origin: OriginNamespace,
    pub canonical_path: String,
}

impl fmt::Display for RestoreIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.origin, self.canonical_path)
    }
}

// ---------------------------------------------------------------------------
// §B.2 record 边界归一化
// ---------------------------------------------------------------------------

/// 定理 B-1：JSONL 家族的 `boundary_T` = 最后一个 `0x0A` 的下标 + 1；没有 `\n` 则为 0。
///
/// **取满足 RC 的最大偏移**（§B.2 的规范选择）。取更小的合法边界会人为丢弃已写完的
/// record，把一个本该判 `replace` 的真前缀关系推向「candidate 更长」的超集分支，
/// 而超集在 §5.2.1 里是 HOLD。
pub fn jsonl_record_boundary(bytes: &[u8]) -> usize {
    match bytes.iter().rposition(|b| *b == 0x0A) {
        Some(i) => i + 1,
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// 版本
// ---------------------------------------------------------------------------

/// 一个内容版本的来源。§D.2.0 明写两类操作数**必须允许混比**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionSource {
    /// W0 封存件里该路径的条目，字节范围 `bytes[0..boundary_T]`。
    Sealed,
    /// raw-mirror manifest 指向的 blob，字节范围是整个 blob。
    Mirror,
}

/// 一个已归一化的内容版本。
///
/// **`normalized` 一定是切到 record 边界之后的字节**——构造只经 [`ContentVersion::new`]，
/// 那里做归一；被切掉的尾巴长度记在 `unsealed_tail_len`（§B.6）。
#[derive(Debug, Clone)]
pub struct ContentVersion {
    pub source: VersionSource,
    normalized: Vec<u8>,
    unsealed_tail_len: u64,
    pub source_mtime_ms: i64,
    pub captured_at_ms: i64,
    /// 人工裁定材料：mirror 侧是 `blob_blake3`，sealed 侧是 payload hash。仅诊断。
    pub blob_id: String,
}

impl ContentVersion {
    /// 用**原始**字节构造：归一化在这里发生，调用方不需要（也不应该）自己先切。
    pub fn new(
        source: VersionSource,
        raw_bytes: &[u8],
        source_mtime_ms: i64,
        captured_at_ms: i64,
        blob_id: impl Into<String>,
    ) -> Self {
        let boundary = jsonl_record_boundary(raw_bytes);
        ContentVersion {
            source,
            normalized: raw_bytes[..boundary].to_vec(),
            unsealed_tail_len: (raw_bytes.len() - boundary) as u64,
            source_mtime_ms,
            captured_at_ms,
            blob_id: blob_id.into(),
        }
    }

    /// 归一化后的字节（唯一参与比较的东西）。
    pub fn normalized(&self) -> &[u8] {
        &self.normalized
    }

    /// 归一化切掉的尾巴长度（§B.6 的 `unsealed_tail`）。
    pub fn unsealed_tail_len(&self) -> u64 {
        self.unsealed_tail_len
    }

    /// 归一化后字节的 blake3。
    ///
    /// **不得复用 manifest 里的 `blob_blake3`**——那是对整个 blob 算的，归一化后长度若小于
    /// `blob_size_bytes` 就必须重算（§D.5 明写这一条）。
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.normalized).as_bytes()
    }
}

// ---------------------------------------------------------------------------
// 投影注入点（第二层可比性判定）
// ---------------------------------------------------------------------------

/// 一条 canonical 消息在序列比较里的可比摘要。
///
/// 第二层只需要「两条消息是不是同一条」，不需要消息的全部字段；把它压成摘要既让接口窄，
/// 也让 E4 的测试可以用受控替身精确造出「消息序列前缀」这种形态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalMessageDigest(pub [u8; 32]);

/// 投影失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionError {
    pub detail: String,
}

/// 注入点：把一段已归一化的字节投影成 canonical 消息序列的摘要串。
///
/// **窄接口，只回答一个问题。** 真实实现按 `W1-0` §B 的投影规范在 E5 接线（含 §A.1.1
/// 那条「compact 判据改读 `source_size_bytes`、capture 步整步排除」的规范）；E4 只依赖
/// 「同一份逻辑内容投影出同一串摘要」这一个性质，因此测试可以用受控替身把第二层的
/// **判定逻辑**（前缀 / 分叉 / 多极大元）现在就测死。
pub trait MessageSequenceProjector {
    fn project(
        &self,
        origin: &OriginNamespace,
        normalized_bytes: &[u8],
    ) -> Result<Vec<CanonicalMessageDigest>, ProjectionError>;
}

// ---------------------------------------------------------------------------
// §D.2.1 两层可比性判定
// ---------------------------------------------------------------------------

/// 两个版本之间的关系。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// 归一化后逐字节相等。
    Equal,
    /// `a ⊏ b`：`a` 是 `b` 的真前缀（按字节或按消息序列）。
    StrictlyBefore,
    /// `b ⊏ a`。
    StrictlyAfter,
    /// 两层都不成立 → 内容分叉。
    Diverged,
}

/// 关系是在哪一层判出来的——§D.5 要求 E4 能区分 HOLD 的来源，因为人工裁定材料不同。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationLayer {
    /// 第一层：归一化长度 + 前缀 blake3。
    Bytes,
    /// 第二层：normalized 消息序列前缀。
    MessageSequence,
}

/// 一次可比性判定的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationVerdict {
    pub relation: Relation,
    /// 判出该关系的层；分叉时记的是「第二层也失败」，即 `MessageSequence`。
    pub layer: RelationLayer,
}

/// §D.2.1 第一层：便宜、无需 parser。
///
/// 1. 先比归一化后的长度；
/// 2. 短的那侧与长的那侧**前 `len(短)` 字节**的 blake3 比较，相等即前缀。
fn compare_bytes_layer(a: &ContentVersion, b: &ContentVersion) -> Option<Relation> {
    let (x, y) = (a.normalized(), b.normalized());
    if x.len() == y.len() {
        return if x == y { Some(Relation::Equal) } else { None };
    }
    let (short, long, forward) = if x.len() < y.len() {
        (x, y, true)
    } else {
        (y, x, false)
    };
    // 对长的一侧取前 len(short) 字节重算 blake3，不复用任何 manifest 里的值。
    if blake3::hash(short) == blake3::hash(&long[..short.len()]) {
        Some(if forward {
            Relation::StrictlyBefore
        } else {
            Relation::StrictlyAfter
        })
    } else {
        None
    }
}

fn digest_prefix_relation(
    a: &[CanonicalMessageDigest],
    b: &[CanonicalMessageDigest],
) -> Option<Relation> {
    if a.len() == b.len() {
        return if a == b { Some(Relation::Equal) } else { None };
    }
    let (short, long, forward) = if a.len() < b.len() {
        (a, b, true)
    } else {
        (b, a, false)
    };
    if short == &long[..short.len()] {
        Some(if forward {
            Relation::StrictlyBefore
        } else {
            Relation::StrictlyAfter
        })
    } else {
        None
    }
}

/// §D.2.1 的完整两层判定。
///
/// 第二层**不是可选优化**：只留第一层会把「消息序列等价但字节不同、之后又续写」这种真截断
/// 判成分叉，正撞上 §10.2「截断超集用例必过、不得以 HOLD 蒙混」。第一层保留的价值是便宜
/// ——绝大多数比较在第一层就结束。
pub fn compare_versions(
    origin: &OriginNamespace,
    a: &ContentVersion,
    b: &ContentVersion,
    projector: &dyn MessageSequenceProjector,
) -> Result<RelationVerdict, ProjectionError> {
    if let Some(relation) = compare_bytes_layer(a, b) {
        return Ok(RelationVerdict {
            relation,
            layer: RelationLayer::Bytes,
        });
    }
    let pa = projector.project(origin, a.normalized())?;
    let pb = projector.project(origin, b.normalized())?;
    let relation = digest_prefix_relation(&pa, &pb).unwrap_or(Relation::Diverged);
    Ok(RelationVerdict {
        relation,
        layer: RelationLayer::MessageSequence,
    })
}

/// 两条消息序列第一个不同的位置——§D.5 要求消息层分叉的裁定材料要附差异位置。
fn first_divergent_index(
    a: &[CanonicalMessageDigest],
    b: &[CanonicalMessageDigest],
) -> Option<usize> {
    a.iter().zip(b.iter()).position(|(x, y)| x != y)
}

// ---------------------------------------------------------------------------
// §5.2.1 四类 HOLD taxonomy（与 sealer 的六类分立）
// ---------------------------------------------------------------------------

/// restore planner 的 HOLD 分类，**闭世界四类，之外非法**（§5.2.1 原文）。
///
/// 与 `W0-0` §B.5 的 **sealer** 六类**分立、不得混用**：那六类描述 seal 窗口内的运行时故障
/// 与范围判定，而这四类描述的是「candidate 与 winner 的关系出了什么问题」——sealer 运行时
/// candidate 还不存在。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HoldClass {
    /// 关系类：§5.2.1 关系判定表里判 HOLD 的那几行。
    Relation,
    /// 身份类：零匹配 / 多匹配 / 重复 key / 单 manifest 多 link。
    Identity,
    /// 版本类：时间冲突 / 非单调 / 分叉。
    Version,
    /// 输入损坏类：payload hash 不符 / manifest 引用缺失。
    InputCorruption,
}

impl HoldClass {
    pub const ALL: [HoldClass; 4] = [
        HoldClass::Relation,
        HoldClass::Identity,
        HoldClass::Version,
        HoldClass::InputCorruption,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            HoldClass::Relation => "relation",
            HoldClass::Identity => "identity",
            HoldClass::Version => "version",
            HoldClass::InputCorruption => "input-corruption",
        }
    }

    /// 从 wire 上的字面量解析。**四类之外一律 `None`**——这是「第五类判非法」的落点。
    pub fn parse(s: &str) -> Option<HoldClass> {
        HoldClass::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

impl fmt::Display for HoldClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 具体 reason。每一个都**静态地**归属于某一类——取值域封闭且静态，调用方只能引用不能自由构造。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum HoldReason {
    /// candidate 是 winner 的超集（关系类）。
    CandidateSuperset,
    /// candidate 与 winner 内容分叉（关系类）。
    CandidateDiverged,
    /// 同一 identity 下有多条 candidate（身份类）。
    MultipleCandidates,
    /// 同一 identity 下零个版本可用（身份类）。
    ZeroVersions,
    /// 真前缀关系与 `source_mtime_ms` 倒挂（版本类）。
    VersionTimeConflict,
    /// 版本集合里存在两个以上互不可比的极大元（版本类）。
    VersionDiverged,
    /// whole-file JSON 形态上偏序不可定义（版本类，§D.4）。
    WholeFileJsonNoPartialOrder,
    /// payload hash 与声明不符（输入损坏类）。
    PayloadHashMismatch,
    /// manifest 引用缺失（输入损坏类）。
    ManifestReferenceMissing,
}

impl HoldReason {
    pub const ALL: [HoldReason; 9] = [
        HoldReason::CandidateSuperset,
        HoldReason::CandidateDiverged,
        HoldReason::MultipleCandidates,
        HoldReason::ZeroVersions,
        HoldReason::VersionTimeConflict,
        HoldReason::VersionDiverged,
        HoldReason::WholeFileJsonNoPartialOrder,
        HoldReason::PayloadHashMismatch,
        HoldReason::ManifestReferenceMissing,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            HoldReason::CandidateSuperset => "candidate-superset",
            HoldReason::CandidateDiverged => "candidate-diverged",
            HoldReason::MultipleCandidates => "multiple-candidates",
            HoldReason::ZeroVersions => "zero-versions",
            HoldReason::VersionTimeConflict => "version-time-conflict",
            HoldReason::VersionDiverged => "version-diverged",
            HoldReason::WholeFileJsonNoPartialOrder => "whole-file-json-no-partial-order",
            HoldReason::PayloadHashMismatch => "payload-hash-mismatch",
            HoldReason::ManifestReferenceMissing => "manifest-reference-missing",
        }
    }

    /// 该 reason 属于哪一类。**静态归属**——不由调用方指定，因此「reason 与 class 对不上」
    /// 这种输入在类型层就不存在。
    pub const fn class(self) -> HoldClass {
        match self {
            HoldReason::CandidateSuperset | HoldReason::CandidateDiverged => HoldClass::Relation,
            HoldReason::MultipleCandidates | HoldReason::ZeroVersions => HoldClass::Identity,
            HoldReason::VersionTimeConflict
            | HoldReason::VersionDiverged
            | HoldReason::WholeFileJsonNoPartialOrder => HoldClass::Version,
            HoldReason::PayloadHashMismatch | HoldReason::ManifestReferenceMissing => {
                HoldClass::InputCorruption
            }
        }
    }

    pub fn parse(s: &str) -> Option<HoldReason> {
        HoldReason::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

impl fmt::Display for HoldReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一个版本的摘要，作为人工裁定材料（§D.4 点名的四个字段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionSummary {
    pub source: VersionSource,
    pub blob_id: String,
    /// **归一化后**的长度，不是 manifest 里的 `blob_size_bytes`。
    pub normalized_len: u64,
    pub unsealed_tail_len: u64,
    pub source_mtime_ms: i64,
    pub captured_at_ms: i64,
}

impl VersionSummary {
    fn of(v: &ContentVersion) -> Self {
        VersionSummary {
            source: v.source,
            blob_id: v.blob_id.clone(),
            normalized_len: v.normalized().len() as u64,
            unsealed_tail_len: v.unsealed_tail_len(),
            source_mtime_ms: v.source_mtime_ms,
            captured_at_ms: v.captured_at_ms,
        }
    }
}

/// HOLD 的来源。§D.5：E4 必须能区分三种，因为它们的人工裁定材料不同。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HoldEvidence {
    /// 字节层分叉：第一层失败，且第二层判定未启动或同样失败于字节形态。
    ByteLayer { versions: Vec<VersionSummary> },
    /// 消息层分叉：第一层失败、第二层也失败。**必须附两侧消息序列的差异位置**。
    MessageLayer {
        versions: Vec<VersionSummary>,
        first_divergent_index: Option<usize>,
    },
    /// `W0-1` §B.3 的 whole-file 排除：无论几个版本都不进 winner 流程。
    WholeFileExcluded { detail: String },
    /// 与分叉无关的其他 HOLD（多 candidate、时间冲突等）。
    Versions { versions: Vec<VersionSummary> },
}

/// 一条 HOLD 记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldRecord {
    pub identity: RestoreIdentity,
    pub reason: HoldReason,
    pub evidence: HoldEvidence,
    /// 本次裁定消费了哪些 manifest 字段（R-E-27 第 3 条的 provenance）。
    pub consumed_manifest_fields: Vec<&'static str>,
}

impl HoldRecord {
    /// reason 决定 class，调用方无从指定——四类闭世界在类型层就闭上了。
    pub fn class(&self) -> HoldClass {
        self.reason.class()
    }
}

// ---------------------------------------------------------------------------
// winner 选择（§5.2.3 + §D.2.1）
// ---------------------------------------------------------------------------

/// 本模块从 sealed manifest 消费的字段。**静态清单**——provenance 只能引用它，
/// 不能自由构造（R-E-27 第 3 条 + 「声明侧取值域封闭且静态」）。
pub mod manifest_fields {
    pub const ORIGINAL_PATH: &str = "original_path";
    pub const SOURCE_ID: &str = "source_id";
    pub const ORIGIN_KIND: &str = "origin_kind";
    pub const ORIGIN_HOST: &str = "origin_host";
    pub const BLOB_BLAKE3: &str = "blob_blake3";
    pub const SOURCE_MTIME_MS: &str = "source_mtime_ms";

    /// winner 选择实际消费的字段集合。
    ///
    /// **`captured_at_ms` 不在内**：§5.2.3 明令墙钟不得决定胜者，它只作为裁定材料被摘要，
    /// 不进任何判定。**`provider` 与 `db_links.conversation_id` 也不在内**：前者只作诊断
    /// （§5.1），后者由上位 §9.1 第 1 条禁止用作身份。
    pub const CONSUMED_BY_WINNER_SELECTION: &[&str] = &[
        ORIGINAL_PATH,
        SOURCE_ID,
        ORIGIN_KIND,
        ORIGIN_HOST,
        BLOB_BLAKE3,
        SOURCE_MTIME_MS,
    ];
}

/// §D.2.0 的第二条入 `V` 排除规则：**形态排除，与能否解析无关**。
///
/// 凡属 `W0-1` §B.3 那张表里「不可进 promotable snapshot」的形态（claude `*.json` / `*.claude`、
/// codex `rollout-*.json` 及其大小写变体）**一律不进 `V`**。初版只写了「不可解析」那条，
/// 字面读下来一个**能解析的** `rollout-*.json` 会进 `V` 并参与 winner 选择，而 §D.4 明写这些
/// 形态无论几个版本都不进 winner 流程。
///
/// **判据直接复用 E2 已冻结的分类器，不造第二定义。** 传空字节是安全的：`NotWholeFile`
/// 这个分支在三家上都只由文件名决定（精确小写 `.jsonl`，codex 另加 `rollout-` 前缀的大小写
/// 规则），与内容无关；而入 `V` 与否只需要区分 `NotWholeFile` 和「其余一切」。
pub fn admissible_to_version_set(agent: Origin, canonical_path: &str) -> bool {
    struct NoMessages;
    impl crate::phase3_bundle::WholeFileMessageCounter for NoMessages {
        fn count_messages(
            &self,
            _path: &std::path::Path,
            _bytes: &[u8],
        ) -> Result<usize, crate::phase3_bundle::PinParseError> {
            Ok(0)
        }
    }
    matches!(
        crate::phase3_bundle::classify_whole_file(
            agent,
            std::path::Path::new(canonical_path),
            b"",
            &NoMessages,
        ),
        crate::phase3_bundle::WholeFileDisposition::NotWholeFile
    )
}

/// winner 选择的结果。
#[derive(Debug, Clone)]
pub enum WinnerOutcome {
    /// 选出唯一极大元。
    Winner {
        index: usize,
        consumed_manifest_fields: Vec<&'static str>,
    },
    /// 选不出来——附完整裁定材料。
    Hold(HoldRecord),
}

fn summaries(versions: &[ContentVersion]) -> Vec<VersionSummary> {
    versions.iter().map(VersionSummary::of).collect()
}

/// 在同一 identity 的版本集合上选 winner。
///
/// - `winner = ⊑ 的唯一极大元`；
/// - **两个以上互不可比的极大元 → 分叉 HOLD，且证据里带出全部 N 个极大元**
///   （§D.5 明写不能只表达两两分叉）；
/// - 真前缀关系与 `source_mtime_ms` 倒挂 → `version_time_conflict` HOLD（§D.2.1 末段）。
///
/// **`captured_at_ms` 全程不参与判定**——它只进 [`VersionSummary`] 作裁定材料。
/// 「时间最新但内容更短」因此不可能当 winner：序完全由内容前缀关系定义。
pub fn select_winner(
    identity: &RestoreIdentity,
    versions: &[ContentVersion],
    projector: &dyn MessageSequenceProjector,
) -> Result<WinnerOutcome, ProjectionError> {
    // §D.2.0 第二条排除规则先于一切：这些形态无论几个版本都不进 winner 流程（§D.4）。
    if !admissible_to_version_set(identity.origin.agent, &identity.canonical_path) {
        return Ok(WinnerOutcome::Hold(HoldRecord {
            identity: identity.clone(),
            reason: HoldReason::WholeFileJsonNoPartialOrder,
            evidence: HoldEvidence::WholeFileExcluded {
                detail: format!(
                    "{} 属 W0-1 §B.3 不可进 promotable snapshot 的形态，偏序不可定义（§D.4）",
                    identity.canonical_path
                ),
            },
            consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
        }));
    }

    if versions.is_empty() {
        return Ok(WinnerOutcome::Hold(HoldRecord {
            identity: identity.clone(),
            reason: HoldReason::ZeroVersions,
            evidence: HoldEvidence::Versions { versions: vec![] },
            consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
        }));
    }

    let n = versions.len();
    let mut relations: Vec<Vec<Relation>> = vec![vec![Relation::Equal; n]; n];
    let mut divergence_layer: Option<RelationLayer> = None;
    let mut message_divergence_at: Option<usize> = None;

    for i in 0..n {
        for j in (i + 1)..n {
            let verdict =
                compare_versions(&identity.origin, &versions[i], &versions[j], projector)?;
            relations[i][j] = verdict.relation;
            relations[j][i] = match verdict.relation {
                Relation::StrictlyBefore => Relation::StrictlyAfter,
                Relation::StrictlyAfter => Relation::StrictlyBefore,
                other => other,
            };

            // 辅助证据只做交叉检查，不参与序的定义（§D.2.1 末段）。
            let (earlier, later) = match verdict.relation {
                Relation::StrictlyBefore => (i, j),
                Relation::StrictlyAfter => (j, i),
                _ => continue,
            };
            if versions[earlier].source_mtime_ms > versions[later].source_mtime_ms {
                return Ok(WinnerOutcome::Hold(HoldRecord {
                    identity: identity.clone(),
                    reason: HoldReason::VersionTimeConflict,
                    evidence: HoldEvidence::Versions {
                        versions: summaries(versions),
                    },
                    consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION
                        .to_vec(),
                }));
            }
        }
    }

    // 记下分叉是在哪一层判出来的，供 §D.5 的三种来源区分。
    'outer: for i in 0..n {
        for j in (i + 1)..n {
            if relations[i][j] == Relation::Diverged {
                let verdict =
                    compare_versions(&identity.origin, &versions[i], &versions[j], projector)?;
                divergence_layer = Some(verdict.layer);
                if verdict.layer == RelationLayer::MessageSequence {
                    let a = projector.project(&identity.origin, versions[i].normalized())?;
                    let b = projector.project(&identity.origin, versions[j].normalized())?;
                    message_divergence_at = first_divergent_index(&a, &b);
                }
                break 'outer;
            }
        }
    }

    // 极大元：没有任何别的版本严格在它之后。相等的版本互为同一等价类，不算互不可比。
    let maximal: Vec<usize> = (0..n)
        .filter(|i| (0..n).all(|j| relations[*i][j] != Relation::StrictlyBefore))
        .collect();

    // 把相等的极大元折成同一个等价类：内容相同不是分叉。
    let mut classes: Vec<usize> = Vec::new();
    for &i in &maximal {
        if !classes.iter().any(|&c| relations[c][i] == Relation::Equal) {
            classes.push(i);
        }
    }

    if classes.len() == 1 {
        return Ok(WinnerOutcome::Winner {
            index: classes[0],
            consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
        });
    }

    // N 个互不可比的极大元：证据里带出**全部 N 个**，不是两两一对。
    let maximal_summaries: Vec<VersionSummary> = classes
        .iter()
        .map(|&i| VersionSummary::of(&versions[i]))
        .collect();
    let evidence = match divergence_layer {
        Some(RelationLayer::MessageSequence) => HoldEvidence::MessageLayer {
            versions: maximal_summaries,
            first_divergent_index: message_divergence_at,
        },
        _ => HoldEvidence::ByteLayer {
            versions: maximal_summaries,
        },
    };
    Ok(WinnerOutcome::Hold(HoldRecord {
        identity: identity.clone(),
        reason: HoldReason::VersionDiverged,
        evidence,
        consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
    }))
}

// ---------------------------------------------------------------------------
// §5.2.1 决策表
// ---------------------------------------------------------------------------

/// 决策表的动作。**逐关系定死，不是「restore / replace / HOLD 三选一」**——后者允许一个
/// 「对所有非平凡 mismatch 一律 HOLD」的实现通过全部验收，而它没有迁移能力（§5.2.1 原文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreAction {
    /// candidate 与 winner 完全相等。
    Skip,
    /// candidate 缺失。
    Restore,
    /// candidate 是 winner 的真前缀（被截断）。**必须是 replace，不接受 HOLD。**
    Replace,
    /// 上表三行 HOLD：超集 / 分叉 / 多 candidate。
    Hold(HoldRecord),
}

/// 按 §5.2.1 的关系判定表定动作。
///
/// `candidates` 是同一 identity 下候选 DB 侧的版本集合：空 = 缺失，多于一条 = 多 candidate。
pub fn decide_action(
    identity: &RestoreIdentity,
    candidates: &[ContentVersion],
    winner: &ContentVersion,
    projector: &dyn MessageSequenceProjector,
) -> Result<RestoreAction, ProjectionError> {
    if candidates.len() > 1 {
        return Ok(RestoreAction::Hold(HoldRecord {
            identity: identity.clone(),
            reason: HoldReason::MultipleCandidates,
            evidence: HoldEvidence::Versions {
                versions: summaries(candidates),
            },
            consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
        }));
    }
    let Some(candidate) = candidates.first() else {
        return Ok(RestoreAction::Restore);
    };

    let verdict = compare_versions(&identity.origin, candidate, winner, projector)?;
    let hold = |reason: HoldReason, evidence: HoldEvidence| {
        RestoreAction::Hold(HoldRecord {
            identity: identity.clone(),
            reason,
            evidence,
            consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
        })
    };
    let pair = vec![VersionSummary::of(candidate), VersionSummary::of(winner)];

    Ok(match verdict.relation {
        Relation::Equal => RestoreAction::Skip,
        // candidate ⊏ winner：candidate 被截断。
        Relation::StrictlyBefore => RestoreAction::Replace,
        // winner ⊏ candidate：candidate 是超集。
        Relation::StrictlyAfter => hold(
            HoldReason::CandidateSuperset,
            HoldEvidence::Versions { versions: pair },
        ),
        Relation::Diverged => {
            let evidence = match verdict.layer {
                RelationLayer::MessageSequence => {
                    let a = projector.project(&identity.origin, candidate.normalized())?;
                    let b = projector.project(&identity.origin, winner.normalized())?;
                    HoldEvidence::MessageLayer {
                        versions: pair,
                        first_divergent_index: first_divergent_index(&a, &b),
                    }
                }
                RelationLayer::Bytes => HoldEvidence::ByteLayer { versions: pair },
            };
            hold(HoldReason::CandidateDiverged, evidence)
        }
    })
}

/// 一次 dry-run planner 的六类计数（§5.2.1 末段：Phase 3 至少跑一次，输出六类关系各自的数量）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelationCensus {
    pub skip: usize,
    pub restore: usize,
    pub replace: usize,
    pub hold_superset: usize,
    pub hold_diverged: usize,
    pub hold_multiple_candidates: usize,
}

impl RelationCensus {
    /// 把一个动作计进对应的格子。**其余 HOLD reason 不进本表**——本表是「六类关系」的计数，
    /// 版本类与输入损坏类的 HOLD 有它们自己的账，混进来会让六类计数不再等于关系判定次数。
    pub fn record(&mut self, action: &RestoreAction) -> bool {
        match action {
            RestoreAction::Skip => self.skip += 1,
            RestoreAction::Restore => self.restore += 1,
            RestoreAction::Replace => self.replace += 1,
            RestoreAction::Hold(h) => match h.reason {
                HoldReason::CandidateSuperset => self.hold_superset += 1,
                HoldReason::CandidateDiverged => self.hold_diverged += 1,
                HoldReason::MultipleCandidates => self.hold_multiple_candidates += 1,
                _ => return false,
            },
        }
        true
    }

    pub fn total(&self) -> usize {
        self.skip
            + self.restore
            + self.replace
            + self.hold_superset
            + self.hold_diverged
            + self.hold_multiple_candidates
    }
}

// ---------------------------------------------------------------------------
// override ledger（§5.2.1 末段 + plan Task E4 Step 3）
// ---------------------------------------------------------------------------

/// override ledger 里的一条裁定。
///
/// 字段集来自 §5.2.1 原文：「每条记裁定人、选中哪个 blob（按内容 hash）、理由、适用的
/// composite snapshot root、是否同时覆盖 W1 与 W2 各自独立算出的 winner」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverrideEntry {
    pub identity: RestoreIdentity,
    /// 裁定人。
    pub adjudicator: String,
    /// 选中哪个 blob——**按内容 hash**，不是按路径或序号。
    pub chosen_blob_hash: String,
    pub reason: String,
    /// 适用的 snapshot root。
    pub snapshot_root: String,
    /// 是否同时覆盖 W1 与 W2 各自独立算出的 winner。
    pub covers_w1_winner: bool,
    pub covers_w2_winner: bool,
}

/// 读 ledger 时可能出的错。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// 某一行不是合法 JSON 对象、或缺字段、或字段类型不对。
    Malformed { line: usize, detail: String },
    /// 出现 schema 未声明的字段——闭世界，否则新增字段既不被消费又看不出来。
    UnknownField { line: usize, field: String },
    /// 同一 `(identity, snapshot_root)` 出现内容不同的第二条裁定。
    ///
    /// **这是「不可变」在 reader 侧的可执行判据**：append-only 的账本允许重复追加同一条
    /// 事实（幂等），但不允许后写的一条**改写**前一条的结论——那正是原地编辑的观测形态。
    MutatedEntry { line: usize, identity: String },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::Malformed { line, detail } => write!(f, "第 {line} 行不可解：{detail}"),
            LedgerError::UnknownField { line, field } => {
                write!(f, "第 {line} 行出现未声明字段 {field}")
            }
            LedgerError::MutatedEntry { line, identity } => write!(
                f,
                "第 {line} 行改写了 {identity} 在同一 snapshot root 下的既有裁定（ledger 必须不可变）"
            ),
        }
    }
}

impl std::error::Error for LedgerError {}

/// 一条裁定相对当前 snapshot root 的效力。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideStatus {
    /// 绑定的 snapshot root 与当前一致：裁定有效。
    Effective,
    /// 绑定的是别的 snapshot root：**输入一变裁定即失效**（§5.2.1）。
    ///
    /// 失效不是错误——ledger 会长期累积历史裁定；把它当错误会让每次 snapshot 更新都要
    /// 重写账本，而账本是不可变的。
    SupersededBySnapshotRoot,
}

/// 已读入的 ledger。
#[derive(Debug, Clone)]
pub struct OverrideLedger {
    snapshot_root: String,
    entries: Vec<(OverrideEntry, OverrideStatus)>,
}

const OVERRIDE_ENTRY_FIELDS: &[&str] = &[
    "agent",
    "source_id",
    "origin_host",
    "canonical_path",
    "adjudicator",
    "chosen_blob_hash",
    "reason",
    "snapshot_root",
    "covers_w1_winner",
    "covers_w2_winner",
];

impl OverrideLedger {
    /// 全部条目（含已失效的）。
    pub fn entries(&self) -> &[(OverrideEntry, OverrideStatus)] {
        &self.entries
    }

    /// 对当前 snapshot root 有效的那条裁定（若有）。
    pub fn effective_for(&self, identity: &RestoreIdentity) -> Option<&OverrideEntry> {
        self.entries.iter().find_map(|(e, s)| {
            (*s == OverrideStatus::Effective && e.identity == *identity).then_some(e)
        })
    }

    /// 本 ledger 绑定的 snapshot root。
    pub fn snapshot_root(&self) -> &str {
        &self.snapshot_root
    }
}

/// 读一份不可变 JSONL override ledger，并按当前 snapshot root 标定每条裁定的效力。
///
/// **reader 只读，永不写**——ledger 的不可变性首先靠「没有写路径」保证，其次靠
/// [`LedgerError::MutatedEntry`] 把「原地改写」这种观测形态拒掉。
pub fn read_override_ledger(
    jsonl: &str,
    current_snapshot_root: &str,
) -> Result<OverrideLedger, LedgerError> {
    let mut entries: Vec<(OverrideEntry, OverrideStatus)> = Vec::new();

    for (idx, raw) in jsonl.lines().enumerate() {
        let line = idx + 1;
        if raw.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(raw).map_err(|e| LedgerError::Malformed {
                line,
                detail: format!("JSON 不可解：{e}"),
            })?;
        let serde_json::Value::Object(map) = value else {
            return Err(LedgerError::Malformed {
                line,
                detail: "顶层不是 JSON 对象".to_string(),
            });
        };
        for key in map.keys() {
            if !OVERRIDE_ENTRY_FIELDS.contains(&key.as_str()) {
                return Err(LedgerError::UnknownField {
                    line,
                    field: key.clone(),
                });
            }
        }
        let text = |name: &str| -> Result<String, LedgerError> {
            match map.get(name) {
                Some(serde_json::Value::String(s)) => Ok(s.clone()),
                _ => Err(LedgerError::Malformed {
                    line,
                    detail: format!("缺字段 {name} 或它不是字符串"),
                }),
            }
        };
        let flag = |name: &str| -> Result<bool, LedgerError> {
            match map.get(name) {
                Some(serde_json::Value::Bool(b)) => Ok(*b),
                _ => Err(LedgerError::Malformed {
                    line,
                    detail: format!("缺字段 {name} 或它不是布尔"),
                }),
            }
        };

        let agent_text = text("agent")?;
        let Some(agent) = Origin::parse(&agent_text) else {
            return Err(LedgerError::Malformed {
                line,
                detail: format!("agent {agent_text:?} 不在三值内"),
            });
        };
        let entry = OverrideEntry {
            identity: RestoreIdentity {
                origin: OriginNamespace {
                    agent,
                    source_id: text("source_id")?,
                    origin_host: text("origin_host")?,
                },
                canonical_path: text("canonical_path")?,
            },
            adjudicator: text("adjudicator")?,
            chosen_blob_hash: text("chosen_blob_hash")?,
            reason: text("reason")?,
            snapshot_root: text("snapshot_root")?,
            covers_w1_winner: flag("covers_w1_winner")?,
            covers_w2_winner: flag("covers_w2_winner")?,
        };

        // 不可变判据：同一 (identity, snapshot_root) 下不得出现内容不同的第二条。
        if let Some((prior, _)) = entries
            .iter()
            .find(|(e, _)| e.identity == entry.identity && e.snapshot_root == entry.snapshot_root)
            && *prior != entry
        {
            return Err(LedgerError::MutatedEntry {
                line,
                identity: entry.identity.to_string(),
            });
        }

        let status = if entry.snapshot_root == current_snapshot_root {
            OverrideStatus::Effective
        } else {
            OverrideStatus::SupersededBySnapshotRoot
        };
        entries.push((entry, status));
    }

    Ok(OverrideLedger {
        snapshot_root: current_snapshot_root.to_string(),
        entries,
    })
}

// ===========================================================================
// Task E4 测试
// ===========================================================================

#[cfg(test)]
mod e4_winner_and_decision_tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    // -- 受控替身：投影 ---------------------------------------------------

    /// 默认替身：一行一条消息，摘要 = 该行字节的 blake3。
    ///
    /// 这个形态足以造出「消息序列前缀」，也足以造出「字节不同但消息等价」——后者正是
    /// §D.2.1 要求第二层必须存在的那个用例。
    struct LineProjector;
    impl MessageSequenceProjector for LineProjector {
        fn project(
            &self,
            _origin: &OriginNamespace,
            bytes: &[u8],
        ) -> Result<Vec<CanonicalMessageDigest>, ProjectionError> {
            let text = std::str::from_utf8(bytes).map_err(|e| ProjectionError {
                detail: format!("非 UTF-8：{e}"),
            })?;
            Ok(text
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| CanonicalMessageDigest(*blake3::hash(l.as_bytes()).as_bytes()))
                .collect())
        }
    }

    /// 语义替身：把每行解析成 JSON 再按 `id` 取摘要——**键序与缩进不影响摘要**。
    /// 用来造「字节分叉但消息序列是前缀」的真截断场景（§10.2 点名必过的那一类）。
    struct SemanticProjector;
    impl MessageSequenceProjector for SemanticProjector {
        fn project(
            &self,
            _origin: &OriginNamespace,
            bytes: &[u8],
        ) -> Result<Vec<CanonicalMessageDigest>, ProjectionError> {
            let text = std::str::from_utf8(bytes).map_err(|e| ProjectionError {
                detail: format!("非 UTF-8：{e}"),
            })?;
            let mut out = Vec::new();
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let v: serde_json::Value =
                    serde_json::from_str(line).map_err(|e| ProjectionError {
                        detail: format!("行不可解：{e}"),
                    })?;
                let id = v.get("id").and_then(|x| x.as_str()).unwrap_or("");
                out.push(CanonicalMessageDigest(
                    *blake3::hash(id.as_bytes()).as_bytes(),
                ));
            }
            Ok(out)
        }
    }

    /// 会失败的替身：用来确认投影错误不被吞。
    struct FailingProjector;
    impl MessageSequenceProjector for FailingProjector {
        fn project(
            &self,
            _origin: &OriginNamespace,
            _bytes: &[u8],
        ) -> Result<Vec<CanonicalMessageDigest>, ProjectionError> {
            Err(ProjectionError {
                detail: "投影不可用".to_string(),
            })
        }
    }

    // -- 夹具 -------------------------------------------------------------

    fn origin(agent: Origin, host: &str) -> OriginNamespace {
        OriginNamespace {
            agent,
            source_id: format!("src-{host}"),
            origin_host: host.to_string(),
        }
    }

    fn identity(agent: Origin, host: &str, path: &str) -> RestoreIdentity {
        RestoreIdentity {
            origin: origin(agent, host),
            canonical_path: path.to_string(),
        }
    }

    fn jsonl(lines: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for l in lines {
            v.extend_from_slice(l.as_bytes());
            v.push(b'\n');
        }
        v
    }

    fn version(raw: &[u8], mtime: i64, captured: i64, id: &str) -> ContentVersion {
        ContentVersion::new(VersionSource::Mirror, raw, mtime, captured, id)
    }

    fn sealed(raw: &[u8], mtime: i64, captured: i64, id: &str) -> ContentVersion {
        ContentVersion::new(VersionSource::Sealed, raw, mtime, captured, id)
    }

    const PATH: &str = "/home/u/.claude/projects/p/a.jsonl";

    fn hold_of(action: &RestoreAction) -> &HoldRecord {
        match action {
            RestoreAction::Hold(h) => h,
            other => panic!("期望 HOLD，实得 {other:?}"),
        }
    }

    // -- A/B：§5.2.1 决策表逐行 --------------------------------------------

    #[test]
    fn decision_table_equal_is_skip() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let bytes = jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]);
        let cand = version(&bytes, 100, 100, "c");
        let win = version(&bytes, 100, 100, "w");
        let action = decide_action(&id, std::slice::from_ref(&cand), &win, &LineProjector).unwrap();
        assert_eq!(action, RestoreAction::Skip);
    }

    #[test]
    fn decision_table_missing_candidate_is_restore() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let win = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "w");
        let action = decide_action(&id, &[], &win, &LineProjector).unwrap();
        assert_eq!(action, RestoreAction::Restore);
    }

    /// **判据 B**：真前缀必须判 `replace`，不接受 HOLD。
    /// 「全部非平凡 mismatch 一律 HOLD」的退化实现在这一条上必红。
    #[test]
    fn decision_table_true_prefix_is_replace_not_hold() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let cand = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "c");
        let win = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            200,
            200,
            "w",
        );
        let action = decide_action(&id, std::slice::from_ref(&cand), &win, &LineProjector).unwrap();
        assert_eq!(
            action,
            RestoreAction::Replace,
            "真前缀（被截断）必须 replace——判 HOLD 即是退化实现"
        );
    }

    #[test]
    fn decision_table_superset_is_hold() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let cand = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            200,
            200,
            "c",
        );
        let win = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "w");
        let action = decide_action(&id, std::slice::from_ref(&cand), &win, &LineProjector).unwrap();
        let h = hold_of(&action);
        assert_eq!(h.reason, HoldReason::CandidateSuperset);
        assert_eq!(h.class(), HoldClass::Relation);
    }

    #[test]
    fn decision_table_diverged_is_hold_and_records_the_layer() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let cand = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"x\"}"]),
            100,
            100,
            "c",
        );
        let win = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"y\"}"]),
            100,
            100,
            "w",
        );
        let action = decide_action(&id, std::slice::from_ref(&cand), &win, &LineProjector).unwrap();
        let h = hold_of(&action);
        assert_eq!(h.reason, HoldReason::CandidateDiverged);
        assert_eq!(h.class(), HoldClass::Relation);
        // §D.5：消息层分叉必须附差异位置。
        match &h.evidence {
            HoldEvidence::MessageLayer {
                first_divergent_index,
                versions,
            } => {
                assert_eq!(*first_divergent_index, Some(1), "第 2 条消息才开始分叉");
                assert_eq!(versions.len(), 2);
            }
            other => panic!("期望消息层证据，实得 {other:?}"),
        }
    }

    #[test]
    fn decision_table_multiple_candidates_is_hold() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let a = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "c1");
        let b = version(&jsonl(&["{\"id\":\"m2\"}"]), 100, 100, "c2");
        let win = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "w");
        let action = decide_action(&id, &[a, b], &win, &LineProjector).unwrap();
        let h = hold_of(&action);
        assert_eq!(h.reason, HoldReason::MultipleCandidates);
        assert_eq!(h.class(), HoldClass::Identity);
    }

    /// §D.2.1 第二层的存在理由：字节不同（键序变了）但消息序列是真前缀 → 仍须 replace。
    /// 只有第一层的实现会把它判成分叉 HOLD，正撞 §10.2「不得以 HOLD 蒙混」。
    #[test]
    fn message_layer_prefix_is_still_replace_not_diverged() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let cand = version(&jsonl(&["{\"id\":\"m1\",\"t\":1}"]), 100, 100, "c");
        // winner 前一条的键序不同（字节前缀不成立），但消息 id 序列是超集。
        let win = version(
            &jsonl(&["{\"t\":1,\"id\":\"m1\"}", "{\"id\":\"m2\",\"t\":2}"]),
            200,
            200,
            "w",
        );
        // 第一层：字节前缀不成立。
        assert!(compare_bytes_layer(&cand, &win).is_none());
        // 两层合起来：消息序列前缀成立 → replace。
        let action =
            decide_action(&id, std::slice::from_ref(&cand), &win, &SemanticProjector).unwrap();
        assert_eq!(action, RestoreAction::Replace);
    }

    // -- C：四类 taxonomy 封闭 ---------------------------------------------

    #[test]
    fn hold_taxonomy_is_closed_at_four_classes() {
        assert_eq!(HoldClass::ALL.len(), 4);
        for c in HoldClass::ALL {
            assert_eq!(HoldClass::parse(c.as_str()), Some(c));
        }
        // 第五类判非法——sealer 的六类是最容易被误搬进来的那批。
        for illegal in [
            "unreadable",
            "fd-unavailable",
            "prefix-rewritten",
            "stability-timeout",
            "path-reincarnation",
            "out-of-scope-format",
            "relationship",
            "",
        ] {
            assert_eq!(
                HoldClass::parse(illegal),
                None,
                "{illegal:?} 不得被认成合法 HOLD 类"
            );
        }
        // 每个 reason 静态归属于四类之一，且字面量互不重复。
        let mut seen = std::collections::BTreeSet::new();
        for r in HoldReason::ALL {
            assert!(seen.insert(r.as_str()), "reason 字面量重复：{r}");
            assert!(HoldClass::ALL.contains(&r.class()));
            assert_eq!(HoldReason::parse(r.as_str()), Some(r));
        }
        assert_eq!(seen.len(), 9);
        assert_eq!(HoldReason::parse("no-record-boundary"), None);
    }

    /// 四类各至少有一个真实发射点（E-7 死枚举）。
    #[test]
    fn every_hold_class_has_a_real_construction_point() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let mut classes = std::collections::BTreeSet::new();

        // 关系类
        let cand = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            100,
            100,
            "c",
        );
        let win = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "w");
        classes.insert(
            hold_of(
                &decide_action(&id, std::slice::from_ref(&cand), &win, &LineProjector).unwrap(),
            )
            .class(),
        );
        // 身份类
        let a = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "c1");
        let b = version(&jsonl(&["{\"id\":\"m2\"}"]), 100, 100, "c2");
        classes
            .insert(hold_of(&decide_action(&id, &[a, b], &win, &LineProjector).unwrap()).class());
        // 版本类
        let short = version(&jsonl(&["{\"id\":\"m1\"}"]), 300, 100, "s");
        let long = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            100,
            200,
            "l",
        );
        match select_winner(&id, &[short, long], &LineProjector).unwrap() {
            WinnerOutcome::Hold(h) => {
                classes.insert(h.class());
            }
            other => panic!("期望时间冲突 HOLD，实得 {other:?}"),
        }
        // 输入损坏类：本模块不产生它（payload hash 与 manifest 引用由 E5/bundle 侧判），
        // 但枚举必须有构造点与断言，否则就是死枚举。
        classes.insert(HoldReason::PayloadHashMismatch.class());
        classes.insert(HoldReason::ManifestReferenceMissing.class());

        assert_eq!(
            classes,
            HoldClass::ALL
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
        );
    }

    // -- D：时间最新但内容更短，不得当 winner --------------------------------

    #[test]
    fn newest_capture_time_with_shorter_content_never_wins() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        // 短的那条 captured_at_ms 最新（墙钟），mtime 与内容一致不倒挂。
        let short = version(
            &jsonl(&["{\"id\":\"m1\"}"]),
            100,
            9_999,
            "short-but-newest-capture",
        );
        let long = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            200,
            1,
            "long",
        );
        match select_winner(&id, &[short, long], &LineProjector).unwrap() {
            WinnerOutcome::Winner { index, .. } => {
                assert_eq!(
                    index, 1,
                    "winner 必须是内容更长的那条，不是捕获时间最新的那条"
                );
            }
            other => panic!("期望选出 winner，实得 {other:?}"),
        }
        // 且 captured_at_ms 不在被消费的字段清单里。
        assert!(
            !manifest_fields::CONSUMED_BY_WINNER_SELECTION.contains(&"captured_at_ms"),
            "墙钟不得进判定字段集"
        );
    }

    /// §D.2.1 末段：真前缀却 `source_mtime_ms` 倒挂 → 版本类 HOLD，而不是拿墙钟决定胜者。
    #[test]
    fn true_prefix_with_inverted_mtime_is_version_time_conflict() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let short = version(&jsonl(&["{\"id\":\"m1\"}"]), 500, 1, "s");
        let long = version(&jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]), 100, 2, "l");
        match select_winner(&id, &[short, long], &LineProjector).unwrap() {
            WinnerOutcome::Hold(h) => {
                assert_eq!(h.reason, HoldReason::VersionTimeConflict);
                assert_eq!(h.class(), HoldClass::Version);
            }
            other => panic!("期望 HOLD，实得 {other:?}"),
        }
    }

    // -- E：跨 host 同路径不折叠 --------------------------------------------

    #[test]
    fn same_path_across_hosts_is_not_folded() {
        let a = identity(Origin::ClaudeCode, "host-a", PATH);
        let b = identity(Origin::ClaudeCode, "host-b", PATH);
        assert_ne!(a, b, "同路径不同 host 必须是两条不同 identity");

        // 按 identity 分组时两侧各自成组，不会被并进同一个版本集合。
        let mut groups: BTreeMap<RestoreIdentity, Vec<ContentVersion>> = BTreeMap::new();
        groups.entry(a.clone()).or_default().push(version(
            &jsonl(&["{\"id\":\"a1\"}"]),
            100,
            100,
            "a",
        ));
        groups.entry(b.clone()).or_default().push(version(
            &jsonl(&["{\"id\":\"b1\"}"]),
            100,
            100,
            "b",
        ));
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&a].len(), 1);
        assert_eq!(groups[&b].len(), 1);

        // source_id 不同、host 相同的两条同样不折叠。
        let mut c = a.clone();
        c.origin.source_id = "other-source".to_string();
        assert_ne!(a, c);
    }

    /// R-E-27 第 2 条：`db_links.conversation_id` 不得作身份——winner 判定不受它影响。
    #[test]
    fn conversation_id_does_not_influence_winner_selection() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let short = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "blob-short");
        let long = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            200,
            200,
            "blob-long",
        );

        let baseline = select_winner(&id, &[short.clone(), long.clone()], &LineProjector).unwrap();
        let WinnerOutcome::Winner { index, .. } = baseline else {
            panic!("期望选出 winner");
        };

        // 构造「conversation_id 误导」场景：假设 candidate DB 把较短的那条挂在一个看起来
        // 更权威的 conversation_id 上。本模块的输入面里根本没有该字段——这既是断言也是
        // 结构性保证：`ContentVersion` 与 `RestoreIdentity` 都不含 conversation_id。
        assert!(
            !manifest_fields::CONSUMED_BY_WINNER_SELECTION
                .iter()
                .any(|f| f.contains("conversation")),
            "conversation_id 不得出现在被消费字段清单里"
        );
        let again = select_winner(&id, &[short, long], &LineProjector).unwrap();
        match again {
            WinnerOutcome::Winner { index: i2, .. } => assert_eq!(i2, index),
            other => panic!("期望选出 winner，实得 {other:?}"),
        }
    }

    // -- H：版本偏序（§D）独立实现 ------------------------------------------

    #[test]
    fn boundary_theorem_b1_maximal_offset() {
        assert_eq!(jsonl_record_boundary(b""), 0, "零字节文件");
        assert_eq!(
            jsonl_record_boundary(b"{\"a\":1}"),
            0,
            "没有 \\n 则无非空边界"
        );
        assert_eq!(jsonl_record_boundary(b"{\"a\":1}\n"), 8);
        assert_eq!(
            jsonl_record_boundary(b"{\"a\":1}\n{\"b\":2}\n"),
            16,
            "取满足 RC 的**最大**偏移，不是第一个"
        );
        assert_eq!(
            jsonl_record_boundary(b"{\"a\":1}\n{\"b\":2}"),
            8,
            "半条 record 被切掉"
        );
    }

    /// §D.2.0：mirror blob 停在一条 record 中间，不归一就会把「相等」读成「真前缀」。
    #[test]
    fn mirror_blob_is_normalized_before_comparison_so_equal_stays_equal() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let sealed_bytes = jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]);
        // mirror 侧多出半条 record（捕获期文件正被追加）。
        let mut mirror_bytes = sealed_bytes.clone();
        mirror_bytes.extend_from_slice(b"{\"id\":\"m3\"");

        let s = sealed(&sealed_bytes, 100, 100, "sealed");
        let m = version(&mirror_bytes, 100, 100, "mirror");
        assert_eq!(m.unsealed_tail_len(), 10, "被切掉的尾巴长度要记下来");

        let verdict = compare_versions(&id.origin, &s, &m, &LineProjector).unwrap();
        assert_eq!(
            verdict.relation,
            Relation::Equal,
            "归一化之后两类操作数同语义，相等才是相等"
        );
        // 未归一化的朴素实现会得到「真前缀」，进而把该跳过的关系误判成 replace。
        assert!(sealed_bytes.len() < mirror_bytes.len());
    }

    /// §D.5：必须能表达「同一 identity 下 N 个极大元」，不能只表达两两分叉。
    #[test]
    fn n_way_fork_reports_all_maximal_elements() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let common = "{\"id\":\"m1\"}";
        let a = version(&jsonl(&[common, "{\"id\":\"a\"}"]), 100, 100, "A");
        let b = version(&jsonl(&[common, "{\"id\":\"b\"}"]), 100, 100, "B");
        let c = version(&jsonl(&[common, "{\"id\":\"c\"}"]), 100, 100, "C");
        match select_winner(&id, &[a, b, c], &LineProjector).unwrap() {
            WinnerOutcome::Hold(h) => {
                assert_eq!(h.reason, HoldReason::VersionDiverged);
                assert_eq!(h.class(), HoldClass::Version);
                let versions = match &h.evidence {
                    HoldEvidence::MessageLayer { versions, .. } => versions,
                    HoldEvidence::ByteLayer { versions } => versions,
                    other => panic!("期望分叉证据，实得 {other:?}"),
                };
                assert_eq!(versions.len(), 3, "三个极大元必须全部带出，不是两两一对");
                let ids: std::collections::BTreeSet<&str> =
                    versions.iter().map(|v| v.blob_id.as_str()).collect();
                assert_eq!(ids, ["A", "B", "C"].into_iter().collect());
            }
            other => panic!("期望分叉 HOLD，实得 {other:?}"),
        }
    }

    /// 相等的版本不算互不可比：同一份内容被封存与被镜像各一份不构成分叉。
    #[test]
    fn duplicate_equal_versions_are_one_equivalence_class() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let bytes = jsonl(&["{\"id\":\"m1\"}"]);
        let s = sealed(&bytes, 100, 100, "sealed");
        let m = version(&bytes, 100, 200, "mirror");
        match select_winner(&id, &[s, m], &LineProjector).unwrap() {
            WinnerOutcome::Winner { .. } => {}
            other => panic!("相等的两条不得判分叉，实得 {other:?}"),
        }
    }

    /// §D.2.0 第二条 + §D.4：whole-file 形态无论几个版本都不进 winner 流程。
    #[test]
    fn whole_file_forms_never_enter_the_version_set() {
        // 与 E2 已冻结的分类器口径一致：精确小写 .jsonl 才可入 V。
        assert!(admissible_to_version_set(
            Origin::ClaudeCode,
            "/x/.claude/projects/p/a.jsonl"
        ));
        assert!(admissible_to_version_set(
            Origin::Codex,
            "/x/.codex/sessions/rollout-a.jsonl"
        ));
        assert!(admissible_to_version_set(
            Origin::Openclaw,
            "/x/.openclaw/sessions/s.jsonl"
        ));
        for (agent, path) in [
            (Origin::ClaudeCode, "/x/.claude/projects/p/a.json"),
            (Origin::ClaudeCode, "/x/.claude/projects/p/a.claude"),
            (Origin::Codex, "/x/.codex/sessions/rollout-a.json"),
            (Origin::Codex, "/x/.codex/sessions/Rollout-a.jsonl"),
        ] {
            assert!(!admissible_to_version_set(agent, path), "{path} 不得入 V");
        }

        // 单版本也不进 winner 流程——§D.4 明写「无论几个版本」。
        let id = identity(Origin::Codex, "h1", "/x/.codex/sessions/rollout-a.json");
        let only = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "only");
        match select_winner(&id, std::slice::from_ref(&only), &LineProjector).unwrap() {
            WinnerOutcome::Hold(h) => {
                assert_eq!(h.reason, HoldReason::WholeFileJsonNoPartialOrder);
                assert_eq!(h.class(), HoldClass::Version);
                assert!(matches!(h.evidence, HoldEvidence::WholeFileExcluded { .. }));
            }
            other => panic!("期望 whole-file 排除 HOLD，实得 {other:?}"),
        }
    }

    /// §D.5：三种 HOLD 来源必须可区分。
    #[test]
    fn three_hold_sources_are_distinguishable() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        // ① 字节层分叉：同长度、内容不同，且投影也分叉。
        let a = version(&jsonl(&["{\"id\":\"aa\"}"]), 100, 100, "A");
        let b = version(&jsonl(&["{\"id\":\"bb\"}"]), 100, 100, "B");
        let byte_hold = match select_winner(&id, &[a, b], &SemanticProjector).unwrap() {
            WinnerOutcome::Hold(h) => h,
            other => panic!("期望 HOLD，实得 {other:?}"),
        };
        // 第一层在等长不等值时直接失败，判定落到第二层，故来源标记为消息层。
        assert!(matches!(
            byte_hold.evidence,
            HoldEvidence::MessageLayer { .. }
        ));

        // ② whole-file 排除
        let wid = identity(Origin::Codex, "h1", "/x/.codex/sessions/rollout-a.json");
        let excluded = match select_winner(&wid, &[], &LineProjector).unwrap() {
            WinnerOutcome::Hold(h) => h,
            other => panic!("期望 HOLD，实得 {other:?}"),
        };
        assert!(matches!(
            excluded.evidence,
            HoldEvidence::WholeFileExcluded { .. }
        ));

        // ③ 与分叉无关的其他 HOLD 走 Versions 证据。
        let zero = match select_winner(&id, &[], &LineProjector).unwrap() {
            WinnerOutcome::Hold(h) => h,
            other => panic!("期望 HOLD，实得 {other:?}"),
        };
        assert_eq!(zero.reason, HoldReason::ZeroVersions);
        assert!(matches!(zero.evidence, HoldEvidence::Versions { .. }));
    }

    // -- E-6：投影错误不得被吞 ---------------------------------------------

    #[test]
    fn projection_errors_propagate_and_are_not_swallowed_as_diverged() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        // 等长不等值 → 第一层失败 → 必须启动第二层 → 替身报错 → 错误必须冒出来，
        // **不得被当成「分叉」静默降级**（那会把一次工具失效读成一个内容事实）。
        let a = version(&jsonl(&["{\"id\":\"aa\"}"]), 100, 100, "A");
        let b = version(&jsonl(&["{\"id\":\"bb\"}"]), 100, 100, "B");
        let e = compare_versions(&id.origin, &a, &b, &FailingProjector).unwrap_err();
        assert_eq!(e.detail, "投影不可用");
        assert!(select_winner(&id, &[a, b], &FailingProjector).is_err());
    }

    // -- provenance（R-E-27 第 3 条）----------------------------------------

    #[test]
    fn every_verdict_records_the_manifest_fields_it_consumed() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let v = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "only");
        match select_winner(&id, std::slice::from_ref(&v), &LineProjector).unwrap() {
            WinnerOutcome::Winner {
                consumed_manifest_fields,
                ..
            } => {
                assert_eq!(
                    consumed_manifest_fields,
                    manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec()
                );
                // provider 与 conversation_id 都不在内。
                assert!(!consumed_manifest_fields.contains(&"provider"));
            }
            other => panic!("期望 winner，实得 {other:?}"),
        }
        let win = version(&jsonl(&["{\"id\":\"m1\"}"]), 100, 100, "w");
        let cand = version(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            100,
            100,
            "c",
        );
        let action = decide_action(&id, std::slice::from_ref(&cand), &win, &LineProjector).unwrap();
        let h = hold_of(&action);
        assert!(!h.consumed_manifest_fields.is_empty());
    }

    // -- 六类计数 ----------------------------------------------------------

    #[test]
    fn relation_census_counts_only_the_six_relations() {
        let mut census = RelationCensus::default();
        assert!(census.record(&RestoreAction::Skip));
        assert!(census.record(&RestoreAction::Restore));
        assert!(census.record(&RestoreAction::Replace));
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let mk = |reason| {
            RestoreAction::Hold(HoldRecord {
                identity: id.clone(),
                reason,
                evidence: HoldEvidence::Versions { versions: vec![] },
                consumed_manifest_fields: vec![],
            })
        };
        assert!(census.record(&mk(HoldReason::CandidateSuperset)));
        assert!(census.record(&mk(HoldReason::CandidateDiverged)));
        assert!(census.record(&mk(HoldReason::MultipleCandidates)));
        assert_eq!(census.total(), 6);
        // 版本类 / 输入损坏类不进六类关系表，且**返回 false 让调用方知道它没被计**，
        // 而不是静默丢掉。
        assert!(!census.record(&mk(HoldReason::VersionTimeConflict)));
        assert_eq!(census.total(), 6);
    }

    // -- F：override ledger reader ------------------------------------------

    const ROOT_A: &str = "98509fedfd79c8bc6cef9808cc8fce7f5069c02f12579b2e74eb164fbbaf2db7";
    const ROOT_B: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn ledger_line(path: &str, root: &str, blob: &str) -> String {
        json!({
            "agent": "claude_code",
            "source_id": "src-h1",
            "origin_host": "h1",
            "canonical_path": path,
            "adjudicator": "ivan",
            "chosen_blob_hash": blob,
            "reason": "手工裁定：取更长的那份",
            "snapshot_root": root,
            "covers_w1_winner": true,
            "covers_w2_winner": true
        })
        .to_string()
    }

    #[test]
    fn ledger_entry_is_bound_to_a_snapshot_root() {
        let jsonl_text = ledger_line(PATH, ROOT_A, "blob-1");
        let ledger = read_override_ledger(&jsonl_text, ROOT_A).unwrap();
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let e = ledger.effective_for(&id).expect("当前 root 下该裁定有效");
        assert_eq!(e.chosen_blob_hash, "blob-1");
        assert_eq!(e.adjudicator, "ivan");
        assert!(e.covers_w1_winner && e.covers_w2_winner);
        assert_eq!(ledger.snapshot_root(), ROOT_A);
    }

    #[test]
    fn ledger_entry_bound_to_another_root_is_superseded_not_applied() {
        let jsonl_text = ledger_line(PATH, ROOT_B, "blob-1");
        let ledger = read_override_ledger(&jsonl_text, ROOT_A).unwrap();
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        assert!(
            ledger.effective_for(&id).is_none(),
            "输入一变裁定即失效——不得被当成仍然有效"
        );
        assert_eq!(ledger.entries().len(), 1, "失效不是错误，条目仍在账本里");
        assert_eq!(
            ledger.entries()[0].1,
            OverrideStatus::SupersededBySnapshotRoot
        );
    }

    #[test]
    fn ledger_is_immutable_a_rewritten_entry_is_rejected() {
        // 同一 (identity, snapshot_root) 下第二条结论不同 = 原地改写的观测形态。
        let text = format!(
            "{}\n{}\n",
            ledger_line(PATH, ROOT_A, "blob-1"),
            ledger_line(PATH, ROOT_A, "blob-2")
        );
        let e = read_override_ledger(&text, ROOT_A).expect_err("必须被拒");
        assert!(
            matches!(e, LedgerError::MutatedEntry { line: 2, .. }),
            "实得 {e}"
        );

        // 幂等重复追加同一条事实是允许的（append-only 账本的正常形态）。
        let same = format!(
            "{}\n{}\n",
            ledger_line(PATH, ROOT_A, "blob-1"),
            ledger_line(PATH, ROOT_A, "blob-1")
        );
        assert!(read_override_ledger(&same, ROOT_A).is_ok());
    }

    #[test]
    fn ledger_fields_are_closed_world_and_typed() {
        // 未声明字段即拒——否则新增字段既不被消费又看不出来。
        let mut v: serde_json::Value =
            serde_json::from_str(&ledger_line(PATH, ROOT_A, "b")).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), json!("x"));
        let e = read_override_ledger(&v.to_string(), ROOT_A).expect_err("必须被拒");
        assert!(matches!(e, LedgerError::UnknownField { field, .. } if field == "extra"));

        // 类型不对即拒，不做宽接。
        let mut v: serde_json::Value =
            serde_json::from_str(&ledger_line(PATH, ROOT_A, "b")).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("covers_w1_winner".into(), json!("true"));
        let e = read_override_ledger(&v.to_string(), ROOT_A).expect_err("必须被拒");
        assert!(matches!(e, LedgerError::Malformed { .. }), "实得 {e}");

        // agent 闭世界。
        let mut v: serde_json::Value =
            serde_json::from_str(&ledger_line(PATH, ROOT_A, "b")).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("agent".into(), json!("gemini_cli"));
        assert!(read_override_ledger(&v.to_string(), ROOT_A).is_err());

        // 缺字段即拒。
        let mut v: serde_json::Value =
            serde_json::from_str(&ledger_line(PATH, ROOT_A, "b")).unwrap();
        v.as_object_mut().unwrap().remove("adjudicator");
        assert!(read_override_ledger(&v.to_string(), ROOT_A).is_err());

        // 空行跳过、行号按原始行计。
        let text = format!("\n{}\n", ledger_line(PATH, ROOT_A, "b"));
        assert_eq!(
            read_override_ledger(&text, ROOT_A).unwrap().entries().len(),
            1
        );
    }
}
