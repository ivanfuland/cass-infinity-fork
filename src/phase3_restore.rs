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

// ===========================================================================
// E5 · 封存投影（sealed projection）
//
// 规范来源：附录 `W1-0` §A.1.1（restore 的投影是纯变换）、§B.0（两段投影管线与六个符号
// 锚）、§B.0.1（范围门，凌驾 B.2–B.4 的分支表）；控制面裁定 **R-E-34**（投影定义域三样
// + `since_ts = None`）。
//
// ## 为什么定义域是三样而不是附录字面的两样（R-E-34）
//
// 附录 §A.1.1 写的是「定义域只有 sealed bundle 里的两样东西：blob bytes 与 manifest 的
// `source_size_bytes`」。**按字面实现会让 §B.0.1 的范围门整个失效**，因为 pin parser 的
// 入口是**路径**不是字节：
//
// - `FAD: connectors/mod.rs::Connector` 只有 `scan(&ScanContext)` 与
//   `scan_with_callback(...)`，没有任何吃 `&[u8]` 的入口；
// - `FAD: connectors/scan.rs::ScanContext` 三个字段 `data_dir` / `scan_roots` / `since_ts`，
//   解析对象一律靠 roots 走文件系统发现；
// - 多处分支**由路径决定**：`FAD: claude_code.rs::path_is_desktop_sidecar` 按**路径分量**
//   判 Desktop sidecar、`FAD: codex.rs::is_rollout_file` 按文件名判、whole-file 与 JSONL 的
//   分野按扩展名。
//
// 于是一个用随机临时名物化的投影会把 `rollout-*.json` 当普通 JSONL、让 sidecar 检测永不
// 触发。**裁定 R-E-34 采纳的读法**：定义域 = `{blob bytes, manifest.original_path 的
// canonical 形状, manifest.source_size_bytes}`，实现约束 `since_ts = None`。
// 本注释是该裁定的实现侧落点；附录不重开，勘误挂 plan H2 第 10 条。
//
// ## `since_ts` 必须钉死 `None`
//
// `ScanContext.since_ts` 经 `FAD: utils.rs::file_modified_since` 按 **mtime** 过滤。物化
// 文件的 mtime 是我们造出来的、与封存内容无关；不钉死就是把投影结果挂到「物化那一刻的
// 时钟」上——与环境失败矩阵 E-4 那条「`st_mtime_ns` 不得进身份元组」同源。
//
// ## compact 判据怎么换源（§A.1.1 第 2 条）
//
// 附录要求把 CASS 侧 `should_compact_connector_extra` 与 FAD 侧两家同名私有方法的
// `Option<u64>` 入参换成 manifest 的 `source_size_bytes`。FAD 是 pin 死的外部 crate，
// **改不了也不该改**。本实现改用等价且可断言的路线：
//
// - **物化的字节就是封存的字节**，故物化文件的 `metadata().len()` 恒等于
//   `source_size_bytes` —— 这不是假设，是 [`materialize_sealed_blob`] 里一条硬断言
//   （[`ProjectionFault::SealedSizeMismatch`]）的直接后果，两侧不等即拒绝投影；
// - CASS 侧不走读活路径的 `compact_large_connector_extras`，改走已存在的
//   `compact_large_connector_extras_for_size(_, _, Some(sealed_size))`，**显式传封存值**。
//
// 净效果与附录要求的语义相同：判据来自封存值，不来自「投影时刻文件系统长什么样」。
// 差异是机制而非语义，记入 E9 的类②表。
// ===========================================================================

use std::path::{Component, Path, PathBuf};

use franken_agent_detection::types::NormalizedConversation;

/// 一条被恢复对象的封存输入 —— **这就是投影的定义域**（R-E-34）。
///
/// 三个字段全部来自 sealed manifest 与它引用的 blob，**没有任何一项来自活文件系统**。
#[derive(Debug, Clone, Copy)]
pub struct SealedSource<'a> {
    /// 三家之一。决定用哪个 pin parser、以及 §B.0.1 的哪一行范围门。
    pub agent: Origin,
    /// manifest 的 `original_path`（canonical 捕获路径）。**形状进定义域**：
    /// 文件名决定 whole-file/JSONL 与 rollout 判别，祖先分量决定 Desktop sidecar 判别。
    pub canonical_original_path: &'a str,
    /// manifest 的 `source_size_bytes`。**`u64` 非 `Option`**——§A.1.1 明写 restore 侧
    /// 不存在「取不到大小 → 不 compact」这条分支。
    pub source_size_bytes: u64,
    /// 封存的 blob 字节。
    pub blob: &'a [u8],
}

// **本结构体刻意只有这三样，不吸收 manifest 的 provenance 字段**（控制面确认，R-E-37）：
// 它表达的是**投影的定义域**。`manifest_id` / `blob_blake3` / `captured_at_ms` 这些不参与
// 投影、只是要被记录下来的出处，混进来会让读定义域的人以为它们也影响投影结果。
// provenance 走 [`provenance_from_manifest_view`] 产出的独立入参。**别顺手合并。**

/// 把一份 manifest 的只读投影转成 `metadata.cass.raw_mirror` 的写入载荷。
///
/// **唯一的转换点。** 那八个键的形状由 `indexer::attach_raw_mirror_metadata` 单独定义，
/// 本函数只负责把字段搬过去，不重拼 JSON。
///
/// `already_present` 填 `true` 并**不声称发生过一次 capture** —— restore 全程不调
/// `capture_source_file`（§A.1.1 第 3 条）。它在这里的含义只是「该 blob 已在 mirror 里」，
/// 这是封存事实；而且 `attach_raw_mirror_metadata` 写的八个键里根本不含它，故它对落盘内容
/// 零影响。留 `true` 而不是 `false` 是为了让任何将来去读它的人不会得到「这次 restore 新建了
/// 一份 blob」这个错觉。
pub fn provenance_from_manifest_view(
    view: &crate::raw_mirror::RawMirrorManifestView,
) -> crate::raw_mirror::RawMirrorCaptureRecord {
    crate::raw_mirror::RawMirrorCaptureRecord {
        manifest_id: view.manifest_id.clone(),
        manifest_relative_path: view.manifest_relative_path.clone(),
        blob_relative_path: view.blob_relative_path.clone(),
        blob_blake3: view.blob_blake3.clone(),
        blob_size_bytes: view.blob_size_bytes,
        captured_at_ms: view.captured_at_ms,
        source_mtime_ms: view.source_mtime_ms,
        already_present: true,
    }
}

/// 投影过程中的硬失败。**每一层以自己的名义拒绝**，不靠下层兜住（七类矩阵 E-6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionFault {
    /// blob 长度与 manifest 记的 `source_size_bytes` 不等。
    ///
    /// 这一条同时是 compact 判据换源的**承重断言**：两者相等，物化文件的 `len()` 才
    /// 恒等于封存值。不等即拒绝投影，而不是「取小的那个继续跑」。
    SealedSizeMismatch { manifest: u64, blob: u64 },
    /// `original_path` 不可用于重建形状（空、含 `..` 等）。
    UnsafeOriginalPath { detail: String },
    /// 物化到 scratch 根时的 I/O 失败。**不与其他 I/O 合并归类**（E-6）。
    Materialize { detail: String },
    /// pin parser 报错。
    ParserFailed { detail: String },
    /// 一个 source 文件投影出的会话数不是 1。
    ///
    /// 三家的现代生产 JSONL 都是「一个文件一个会话」；不是 1 说明形态超出 §B.0.1 的
    /// 有效定义域，**硬失败而不是取第一个**。
    UnexpectedConversationCount { count: usize },
    /// pin parser 扫出来的会话，其 `source_path` 不是我们物化的那个文件。
    ///
    /// 这一条防的是「聚合忽略旁路残缺项」（七类矩阵 E-5）的一个具体形态：scratch 根里出现
    /// 了预期外的文件（上一次投影的残留、connector 的默认根兜底逻辑捡到别处的文件），
    /// 于是投影出的会话根本不是被恢复的那一份，而后续每一步都自洽。
    /// **判据是「扫到的就是刚物化的那一个」，不是「扫到了至少一个」。**
    ScannedDifferentFile { expected: String, got: String },
}

impl fmt::Display for ProjectionFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SealedSizeMismatch { manifest, blob } => write!(
                f,
                "sealed size mismatch: manifest source_size_bytes={manifest} but blob is {blob} bytes"
            ),
            Self::UnsafeOriginalPath { detail } => {
                write!(f, "unsafe canonical original_path: {detail}")
            }
            Self::Materialize { detail } => write!(f, "materializing sealed blob failed: {detail}"),
            Self::ParserFailed { detail } => write!(f, "pinned parser failed: {detail}"),
            Self::UnexpectedConversationCount { count } => write!(
                f,
                "sealed source projected {count} conversations; exactly 1 is required"
            ),
            Self::ScannedDifferentFile { expected, got } => write!(
                f,
                "pinned parser scanned {got} but the materialized sealed blob is {expected}"
            ),
        }
    }
}

impl std::error::Error for ProjectionFault {}

/// Claude Desktop sidecar 的路径分量判据。
///
/// **与 `FAD: claude_code.rs::path_is_desktop_sidecar` 同构，逐字对齐它的两个分量字面量。**
/// 之所以要在本层再判一次而不是靠 parser：§B.0.1 第一行要求这类输入**立即 HOLD 并另立
/// 范围**，而 pin parser 对它是正常产消息的分支——靠下层兜住等于这一层没有守卫。
///
/// **判的是分量不是子串**：`claude-code-sessions-backup/` 这种名字不该命中。
fn path_is_claude_desktop_sidecar(path: &Path) -> bool {
    path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some("claude-code-sessions" | "local-agent-mode-sessions")
        )
    })
}

/// 把 canonical 原始路径重建成 scratch 根下的相对形状。
///
/// **物化根本身不进任何判定**（R-E-34 条件 2）：本函数只把 `original_path` 的分量序列
/// 原样接到根后面，绝对路径的前导 `/` 被剥掉。拒绝 `..`——否则物化会逃出 scratch 根。
fn rebuild_relative_shape(canonical_original_path: &str) -> Result<PathBuf, ProjectionFault> {
    let raw = Path::new(canonical_original_path);
    let mut rebuilt = PathBuf::new();
    for component in raw.components() {
        match component {
            // 绝对路径的前导 `/` 与盘符：剥掉，形状从它后面开始。
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                return Err(ProjectionFault::UnsafeOriginalPath {
                    detail: format!("`..` component in {canonical_original_path:?}"),
                });
            }
            Component::Normal(part) => rebuilt.push(part),
        }
    }
    if rebuilt.as_os_str().is_empty() {
        return Err(ProjectionFault::UnsafeOriginalPath {
            detail: format!("no usable component in {canonical_original_path:?}"),
        });
    }
    Ok(rebuilt)
}

/// 把封存的 blob 物化到 scratch 根下、按 `original_path` 重建的位置。
///
/// 返回物化后的绝对路径。**长度断言做两次，且判据是「落盘后的最终字节数」**
/// （控制面裁定 R-E-35 的附加条件）：
///
/// 1. **落盘前**比 `blob.len()` 与 `source_size_bytes` —— 入参侧的第一道拒绝。
///    `SealedSource.blob` 的契约是**解压后的最终字节**；若上游把压缩形态的 blob 原样递
///    进来（manifest 的 `compression` 不是 `none` 而没走解压路径），这里立刻 `SealedSizeMismatch`，
///    而不是让一个短了的文件混过去让 compact 判据读到错的大小。
/// 2. **落盘后**回读 `metadata().len()` 再比一次 —— 防的是短写（`ENOSPC`、被截断）。
///    只比入参不比产物，等于把「写成功了」当成「写全了」，正是七类矩阵 E-1
///    「短读 / 部分读当完整」的写侧同构。
fn materialize_sealed_blob(
    scratch_root: &Path,
    input: &SealedSource<'_>,
) -> Result<PathBuf, ProjectionFault> {
    let blob_len = input.blob.len() as u64;
    if blob_len != input.source_size_bytes {
        return Err(ProjectionFault::SealedSizeMismatch {
            manifest: input.source_size_bytes,
            blob: blob_len,
        });
    }
    let relative = rebuild_relative_shape(input.canonical_original_path)?;
    let target = scratch_root.join(&relative);
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|err| ProjectionFault::Materialize {
            detail: format!("create_dir_all {}: {err}", parent.display()),
        })?;
    }
    std::fs::write(&target, input.blob).map_err(|err| ProjectionFault::Materialize {
        detail: format!("write {}: {err}", target.display()),
    })?;

    let written = std::fs::metadata(&target)
        .map_err(|err| ProjectionFault::Materialize {
            detail: format!("stat back {}: {err}", target.display()),
        })?
        .len();
    if written != input.source_size_bytes {
        return Err(ProjectionFault::SealedSizeMismatch {
            manifest: input.source_size_bytes,
            blob: written,
        });
    }
    Ok(target)
}

/// 一次封存投影的处置。
///
/// **范围门那几档直接转达 E2 已冻结分类器的结论，不做第二定义**（同 R-E-28 的理由）。
///
/// **刻意不 derive `PartialEq`**：`NormalizedConversation` 是 pin 死的上游类型、没有
/// `PartialEq`，而「为了下游方便去给冻结的上游加 trait」正是 E4 记档过的那个口子
/// （消费者的便利不构成动上游的理由）。测试用模式匹配比对，不用 `==`。
#[derive(Debug, Clone)]
pub enum SealedProjection {
    /// 落在有效定义域内（三家的现代生产 JSONL），投影完成。
    Projected(Box<NormalizedConversation>),
    /// §B.0.1 命中：立即 HOLD 并另立范围。**census 侧仍须枚举它**，这里只管处置。
    Held {
        reason: crate::phase3_bundle::HoldReason,
        detail: Option<String>,
    },
    /// 零消息 + 已知 metadata 形态：记 `excluded_known_metadata`，**不得 HOLD**。
    ExcludedKnownMetadata,
    /// whole-file 前置守卫命中（> 100 MiB）。
    SkippedOversize { byte_len: u64 },
    /// pin parser 对 whole-file 解析失败：debug + continue。
    SkippedUnparsable { detail: String },
}

/// 用 pin parser 数一份 whole-file 文档里的消息条数（E2 那个注入点的真实实现）。
///
/// **它扫的是已物化的 scratch 根**，不是活路径：投影的定义域里没有活文件系统。
struct PinnedWholeFileCounter<'a> {
    materialized: &'a Path,
    agent: Origin,
}

impl crate::phase3_bundle::WholeFileMessageCounter for PinnedWholeFileCounter<'_> {
    fn count_messages(
        &self,
        _path: &Path,
        _bytes: &[u8],
    ) -> Result<usize, crate::phase3_bundle::PinParseError> {
        let conversations =
            scan_materialized_file(self.materialized, self.agent).map_err(|fault| {
                crate::phase3_bundle::PinParseError {
                    detail: fault.to_string(),
                }
            })?;
        Ok(conversations
            .iter()
            .map(|conv| conv.messages.len())
            .sum::<usize>())
    }
}

/// 三家 pin parser 的 connector name（`canonicalize_claude_external_id` 等按它分支）。
const fn connector_name_for(agent: Origin) -> &'static str {
    match agent {
        Origin::ClaudeCode => "claude",
        Origin::Codex => "codex",
        Origin::Openclaw => "openclaw",
    }
}

/// 拿 pin parser 扫**恰好一个已物化的文件**。
///
/// **root 指到文件本身而不是 scratch 目录**，三家都支持这条显式文件路径
/// （`FAD: claude_code.rs:451 explicit_file_root` / `codex.rs:311 explicit_file` /
/// `openclaw.rs:276`）。这样 scratch 目录里若有别的残留文件也进不来——把「扫到别人的会话」
/// 这一整类（E-5）从结构上消掉，而不是靠事后比对兜。
///
/// **注意这条显式文件路径同时是 `external_id` 推导的依据**：三家都要从该文件往上找各自的
/// 根（`projects_root_for_explicit_file` / `sessions_dir_for_explicit_file`），再取相对路径。
/// 这是裁定 R-E-34「祖先形状进定义域」的又一处机械依据——祖先没重建对，`external_id` 就错。
///
/// **`since_ts` 恒为 `None`**（R-E-34 的实现约束）：`ScanContext.since_ts` 经
/// `FAD: utils.rs::file_modified_since` 按 mtime 过滤，而物化文件的 mtime 是我们造出来的、
/// 与封存内容无关。给它任何非 `None` 值，投影结果就挂到了「物化那一刻的时钟」上。
fn scan_materialized_file(
    materialized: &Path,
    agent: Origin,
) -> Result<Vec<NormalizedConversation>, ProjectionFault> {
    use crate::connectors::{Connector, ScanContext, ScanRoot};

    let data_dir = materialized.parent().unwrap_or(materialized).to_path_buf();
    let root = ScanRoot::local(materialized.to_path_buf());
    let ctx = ScanContext::with_roots(data_dir, vec![root], None);

    let connector: Box<dyn Connector + Send> = match agent {
        Origin::ClaudeCode => Box::new(crate::connectors::claude_code::ClaudeCodeConnector::new()),
        Origin::Codex => Box::new(crate::connectors::codex::CodexConnector::new()),
        Origin::Openclaw => Box::new(crate::connectors::openclaw::OpenClawConnector::new()),
    };

    connector
        .scan(&ctx)
        .map_err(|err| ProjectionFault::ParserFailed {
            detail: format!("{err:#}"),
        })
}

/// E4 第二层的**真实**投影实现（必接⑤ / 裁定 R-E-26 的兑现）。
///
/// E4 只依赖「同一份逻辑内容投影出同一串摘要」这一个性质，因此它当时用受控替身把判定逻辑
/// （前缀 / 分叉 / 多极大元）先测死了，并把状态记成「逻辑闭、投影挂」。本结构体把挂着的
/// 那一半接上：**摘要由 pin parser 的真实投影产出**。
///
/// 构造它需要 canonical 路径，而 trait 只给 [`OriginNamespace`] —— 这不是接口设计失误，是
/// 裁定 R-E-34 的直接后果：**路径形状进投影定义域**（parser 按路径分支）。故路径由本结构体
/// 在构造时持有，一个 identity 一个 projector。
///
/// # 摘要口径：对 compact **不变**（这是一处有意识的解释，不是附录原文直述）
///
/// 附录 §D.2.1 只说第二层比「消息序列」，没定义「同一条消息」的判据。若把整条
/// `NormalizedMessage`（含 `extra` 全部键）纳入摘要，会撞上一个真实的误判：
///
/// - 版本 A 是版本 B 的真前缀，但 A 只有 12 MiB 而 B 有 18 MiB；
/// - codex 的 compact 阈值是 16 MiB（`CODEX_INDEXER_EXTRA_COMPACT_THRESHOLD_BYTES`），
///   于是 **B 的每条消息被 compact 掉了重复的原始 payload，而 A 的没有**；
/// - 两侧共享前缀的同一条消息因此摘要不同 → 第二层判 `Diverged` → HOLD。
///
/// 那正是 §10.2 点名「截断超集用例必过、不得以 HOLD 蒙混」要挡的东西，只是成因从「字节
/// 层键序差异」换成了「compact 阈值跨越」。故摘要**只取 compact 永远不会动的那些面**：
/// `role` / `author` / `created_at` / `content` / `invocations`，加上
/// `FRANKEN_NORMALIZED_EXTRA_KEYS` 那五个 —— compact 的实现明令**不得**丢它们
/// （`indexer/mod.rs` 那个常量的 doc 原话：「Compaction drops the duplicated raw payload
/// but must never drop these」）。
///
/// **`idx` 不进摘要**：序列比较本来就是按位置的，把位置再编进摘要只会让「同一条消息挪了
/// 位置」变成两条不同消息，对前缀判定毫无帮助。
///
/// **`snippets` 也不进摘要**（裁定 R-E-38 要求把理由写在这里）：它是从 `content` **派生**的
/// 预览物。把派生物放进等价判据，等于让同一份内容因为派生时机 / 派生实现不同而判不等价 ——
/// 与全量 `extra` 同病。**这条注释同时是重议触发器**：若上游哪天给 `snippets` 灌**非派生**
/// 的内容（即它开始携带 `content` 里没有的信息），本条排除就必须重新裁定。
/// 当前三家的所有 push 点都是 `snippets: Vec::new()`（§B.11 的 P12），故排除它零信息损失。
pub struct SealedMessageProjector<'a> {
    /// 物化用的隔离根。**不进任何判定**（R-E-34 条件 2）。
    pub scratch_root: &'a Path,
    /// 该 identity 的 canonical 捕获路径。**形状进定义域**。
    pub canonical_original_path: &'a str,
    /// 三家之一。
    pub agent: Origin,
    /// 该版本对应 manifest 的 `source_size_bytes`，喂给 compact 判据。
    ///
    /// **注意它对摘要不产生影响**（摘要口径对 compact 不变），保留它是为了让这条投影链
    /// 与 restore 侧**逐字同构**——两条链若在 compact 输入上分叉，将来任何一处改动都会让
    /// 「E5 与 F1 的投影差异只可能来自实现 bug」这句话失效。
    pub sealed_source_size_bytes: u64,
}

/// compact 明令不得丢的五个 `extra` 顶层键。
///
/// 值取自 `indexer::FRANKEN_NORMALIZED_EXTRA_KEYS`（该常量私有，故此处是同值副本，
/// 未改其可见性）。**同步不靠人记得**：`compact_criterion_reads_the_sealed_size_not_the_filesystem`
/// 里有一条正向断言——跨过 compact 阈值之后，这五个键**仍然在场**。基线哪天真把其中一个
/// 丢掉，那条断言会红；只做「compact 后剩下的键 ⊆ 允许集」这种反向断言是锁不住的
/// （少掉一个键照样满足子集关系）。
const COMPACT_INVARIANT_EXTRA_KEYS: [&str; 5] = [
    "encrypted_content",
    "raw_role",
    "tool_call_args",
    "tool_call_id",
    "unpaired",
];

/// 一条 canonical 消息的 compact 不变摘要。
fn compact_invariant_message_digest(
    message: &franken_agent_detection::types::NormalizedMessage,
) -> CanonicalMessageDigest {
    let mut hasher = blake3::Hasher::new();
    let mut field = |label: &str, bytes: &[u8]| {
        // 长度前缀，避免相邻字段拼接产生歧义（`"ab"+"c"` 与 `"a"+"bc"` 必须不同摘要）。
        hasher.update(label.as_bytes());
        hasher.update(&(bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };
    field("role", message.role.as_bytes());
    field("author", message.author.as_deref().unwrap_or("").as_bytes());
    field(
        "created_at",
        &message.created_at.unwrap_or(i64::MIN).to_le_bytes(),
    );
    field("content", message.content.as_bytes());
    for key in COMPACT_INVARIANT_EXTRA_KEYS {
        // 键**缺失**与键**值为 null** 必须可区分：前者写 `-`，后者写 `null` 的 JSON 文本。
        match message.extra.get(key) {
            None => field(key, b"-"),
            Some(value) => field(
                key,
                serde_json::to_string(value).unwrap_or_default().as_bytes(),
            ),
        }
    }
    field(
        "invocations",
        serde_json::to_string(&message.invocations)
            .unwrap_or_default()
            .as_bytes(),
    );
    CanonicalMessageDigest(*hasher.finalize().as_bytes())
}

impl MessageSequenceProjector for SealedMessageProjector<'_> {
    fn project(
        &self,
        _origin: &OriginNamespace,
        normalized_bytes: &[u8],
    ) -> Result<Vec<CanonicalMessageDigest>, ProjectionError> {
        // 每次投影落在一个由**字节内容**定名的子目录里。
        //
        // **诚实说明其力度**：当前调用形态是「物化 → 立刻扫 → 返回摘要」，即使两个版本共用
        // 一条重建路径也不会串味（后写的覆盖先写的，但扫描紧跟其后）。所以这不是在修一个
        // 现存 bug，而是把「两个版本的物化件同时存在且互不覆盖」变成结构性事实——将来若有人
        // 把物化与扫描拆开、或并发投影两个版本，共用路径就会让二者互相覆盖，而覆盖的表现是
        // 「两个版本读到同一份字节」= 差异被抹平成相等，属于最难发现的一类静默错误。
        // 用内容定名而不是序号，顺带让同一份字节的重复投影命中同一个目录。
        let slot = self
            .scratch_root
            .join(format!("v-{}", blake3::hash(normalized_bytes).to_hex()));

        let input = SealedSource {
            agent: self.agent,
            canonical_original_path: self.canonical_original_path,
            // 这里必须用**本次被投影字节**的长度：`materialize_sealed_blob` 的长度断言比的是
            // 落盘字节，而归一化后的字节比封存 blob 短（尾巴被切掉）。
            source_size_bytes: normalized_bytes.len() as u64,
            blob: normalized_bytes,
        };
        let materialized =
            materialize_sealed_blob(&slot, &input).map_err(|fault| ProjectionError {
                detail: fault.to_string(),
            })?;

        let conversations =
            scan_materialized_file(&materialized, self.agent).map_err(|fault| ProjectionError {
                detail: fault.to_string(),
            })?;
        if conversations.len() != 1 {
            return Err(ProjectionError {
                detail: format!(
                    "sealed projection produced {} conversations; exactly 1 is required",
                    conversations.len()
                ),
            });
        }
        let mut conv = conversations.into_iter().next().expect("len checked above");

        // 与 restore 侧走**同一条**准备链（含 compact 判据取封存值），差异只可能来自实现 bug。
        // provenance 在比较场景无意义，用一份指向本次被投影版本的最小记录。
        let provenance = crate::raw_mirror::RawMirrorCaptureRecord {
            manifest_id: String::new(),
            manifest_relative_path: String::new(),
            blob_relative_path: String::new(),
            blob_blake3: blake3::hash(normalized_bytes).to_hex().to_string(),
            blob_size_bytes: normalized_bytes.len() as u64,
            captured_at_ms: 0,
            source_mtime_ms: None,
            already_present: true,
        };
        crate::indexer::prepare_conversation_for_restore(
            connector_name_for(self.agent),
            &franken_agent_detection::types::Origin::local(),
            None,
            self.sealed_source_size_bytes,
            &provenance,
            &mut conv,
        );

        Ok(conv
            .messages
            .iter()
            .map(compact_invariant_message_digest)
            .collect())
    }
}

/// 把一条封存输入投影成 canonical 会话 —— **E5 投影的唯一入口**。
///
/// 步骤顺序不可交换，每一步的理由见各自注释：
///
/// 1. **物化**（含两道长度断言）——后面每一步都建立在「盘上的字节就是封存的字节」之上；
/// 2. **Desktop sidecar 路径门**——§B.0.1 第一行，判据是路径分量，必须先于 parser；
/// 3. **whole-file 形态分类**——复用 E2 冻结的分类器，零第二定义；
/// 4. **JSONL 主路径**：pin parser 扫 → 恰好一个会话 → 跑 restore 侧的 ③。
pub fn project_sealed_source(
    scratch_root: &Path,
    input: &SealedSource<'_>,
    consumed_manifest: &crate::raw_mirror::RawMirrorCaptureRecord,
) -> Result<SealedProjection, ProjectionFault> {
    let materialized = materialize_sealed_blob(scratch_root, input)?;
    project_from_materialized(&materialized, input, consumed_manifest)
}

/// [`project_sealed_source`] 的后半段：输入是**已经物化好的**那个文件。
///
/// 拆出来的理由是可测性，而且这个可测性是必须的：`since_ts = None` 那条约束要被真正验到，
/// 测试必须能在「物化之后、扫描之前」插手改 mtime。若只暴露一体的
/// [`project_sealed_source`]，任何改 mtime 的尝试都会被它内部的重新物化覆盖掉 —— 那样的
/// 测试会绿，但它什么都没测（本函数的存在就是为了让那种失效探针不可能写出来）。
fn project_from_materialized(
    materialized: &Path,
    input: &SealedSource<'_>,
    consumed_manifest: &crate::raw_mirror::RawMirrorCaptureRecord,
) -> Result<SealedProjection, ProjectionFault> {
    use crate::phase3_bundle::{HoldReason, WholeFileDisposition, classify_whole_file};

    // §B.0.1 第一行：会发消息的 Claude Desktop sidecar 立即 HOLD 并另立范围。
    // **必须先于 parser**——parser 对它是正常产消息的分支，靠下层兜住等于本层没有守卫。
    if matches!(input.agent, Origin::ClaudeCode)
        && path_is_claude_desktop_sidecar(Path::new(input.canonical_original_path))
    {
        return Ok(SealedProjection::Held {
            reason: HoldReason::OutOfScopeFormat,
            detail: Some("claude-desktop-sidecar".to_owned()),
        });
    }

    let counter = PinnedWholeFileCounter {
        materialized,
        agent: input.agent,
    };
    match classify_whole_file(
        input.agent,
        Path::new(input.canonical_original_path),
        input.blob,
        &counter,
    ) {
        WholeFileDisposition::Hold { reason, detail } => {
            return Ok(SealedProjection::Held { reason, detail });
        }
        WholeFileDisposition::ExcludedKnownMetadata => {
            return Ok(SealedProjection::ExcludedKnownMetadata);
        }
        WholeFileDisposition::SkippedOversize { byte_len } => {
            return Ok(SealedProjection::SkippedOversize { byte_len });
        }
        WholeFileDisposition::SkippedUnparsable { detail } => {
            return Ok(SealedProjection::SkippedUnparsable { detail });
        }
        // 精确小写 `.jsonl`：落到下面的 JSONL 主路径。
        WholeFileDisposition::NotWholeFile => {}
    }

    let mut conversations = scan_materialized_file(materialized, input.agent)?;
    if conversations.len() != 1 {
        return Err(ProjectionFault::UnexpectedConversationCount {
            count: conversations.len(),
        });
    }
    let mut conv = conversations.remove(0);

    // 扫到的必须**就是刚物化的那一个文件**。「扫到了至少一个」不构成证据：scratch 根里
    // 出现预期外的文件时，投影出的会话会是别人的，而后续每一步都自洽（E-5）。
    if conv.source_path != materialized {
        return Err(ProjectionFault::ScannedDifferentFile {
            expected: materialized.display().to_string(),
            got: conv.source_path.display().to_string(),
        });
    }

    // `source_path` 必须是**封存记的那条**，不是我们物化出来的 scratch 路径。
    // 附录 §A.4 与 plan Step 1 都点名「`source_path` 逐条 == manifest `original_path`」。
    conv.source_path = PathBuf::from(input.canonical_original_path);

    crate::indexer::prepare_conversation_for_restore(
        connector_name_for(input.agent),
        &franken_agent_detection::types::Origin::local(),
        None,
        input.source_size_bytes,
        consumed_manifest,
        &mut conv,
    );

    Ok(SealedProjection::Projected(Box::new(conv)))
}

#[cfg(test)]
mod e5_materialization_tests {
    use super::*;

    /// 这几条**是实现先于测试**写的（物化脚手架，不是 plan Step 1 点名的逐字段判据）。
    /// 故它们的断言力**不以「先红后绿」背书**，而由 E5 台账里的变异对照单独证明。
    /// Step 1 点名的那批（逐字段比对 / `source_path` / `external_id` 重推导）与范围门
    /// 三件套一律红相在先。
    const _DISCIPLINE_NOTE: () = ();

    fn scratch(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("cc-cass-e5-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        base
    }

    fn source<'a>(path: &'a str, blob: &'a [u8]) -> SealedSource<'a> {
        SealedSource {
            agent: Origin::ClaudeCode,
            canonical_original_path: path,
            source_size_bytes: blob.len() as u64,
            blob,
        }
    }

    #[test]
    fn rebuild_shape_strips_absolute_prefix_and_keeps_every_component() {
        let rebuilt = rebuild_relative_shape("/home/u/.claude/projects/ws/abc.jsonl").unwrap();
        assert_eq!(
            rebuilt,
            // **只剥前导 `/`，一个分量都不许多剥。** 祖先分量进定义域（R-E-34 条件 1③），
            // 而 sidecar 判据正是靠祖先分量 —— 「顺手把 home/u 也去掉」会让
            // `/home/u/claude-code-sessions/...` 这类路径失去它的判据分量。
            PathBuf::from("home/u/.claude/projects/ws/abc.jsonl"),
            "前导 `/` 剥掉，其余分量必须逐个原样保留 —— 祖先分量进定义域（R-E-34 条件 1③）"
        );
    }

    #[test]
    fn rebuild_shape_rejects_parent_dir_escape_by_its_own_name() {
        let err = rebuild_relative_shape("/a/../../etc/passwd").unwrap_err();
        match err {
            ProjectionFault::UnsafeOriginalPath { detail } => {
                assert!(
                    detail.contains(".."),
                    "拒绝理由要指名 `..`，不用宽接：{detail}"
                );
            }
            other => panic!("期望 UnsafeOriginalPath，实得 {other:?}"),
        }
    }

    #[test]
    fn rebuild_shape_rejects_component_less_path() {
        assert!(matches!(
            rebuild_relative_shape("/").unwrap_err(),
            ProjectionFault::UnsafeOriginalPath { .. }
        ));
        assert!(matches!(
            rebuild_relative_shape("").unwrap_err(),
            ProjectionFault::UnsafeOriginalPath { .. }
        ));
    }

    #[test]
    fn materialize_refuses_when_blob_length_disagrees_with_sealed_size() {
        let root = scratch("sizecheck");
        let blob = b"{}\n";
        let input = SealedSource {
            agent: Origin::ClaudeCode,
            canonical_original_path: "/home/u/s.jsonl",
            // manifest 说 99 字节，blob 只有 3 —— compact 判据换源的承重断言必须在这里咬住。
            source_size_bytes: 99,
            blob,
        };
        let err = materialize_sealed_blob(&root, &input).unwrap_err();
        assert_eq!(
            err,
            ProjectionFault::SealedSizeMismatch {
                manifest: 99,
                blob: 3
            }
        );
        assert!(
            !root.join("home/u/s.jsonl").exists(),
            "长度不一致时必须在落盘之前拒绝，不得先写再报"
        );
    }

    #[test]
    fn materialize_refuses_a_compressed_blob_handed_in_without_decompression() {
        // R-E-35 附加条件：断言对象是「落盘的最终字节」，故上游若把压缩形态的 blob 原样
        // 递进来（manifest 的 compression 不是 none 却没走解压），必须在这里被咬住。
        // 合成一个：source_size_bytes 记的是**解压后**的大小，blob 是压缩后的短字节串。
        let root = scratch("compressed");
        let uncompressed_len: u64 = 4096;
        let compressed_blob = b"\x28\xb5\x2f\xfd\x00\x58\x2d\x00\x00compressed-payload";
        let input = SealedSource {
            agent: Origin::ClaudeCode,
            canonical_original_path: "/home/u/.claude/projects/ws/big.jsonl",
            source_size_bytes: uncompressed_len,
            blob: compressed_blob,
        };
        let err = materialize_sealed_blob(&root, &input).unwrap_err();
        assert_eq!(
            err,
            ProjectionFault::SealedSizeMismatch {
                manifest: uncompressed_len,
                blob: compressed_blob.len() as u64,
            },
            "压缩形态未解压就递进来必须被拒；放过它 = compact 判据读到压缩后的大小"
        );
        assert!(!root.join("home/u/.claude/projects/ws/big.jsonl").exists());
    }

    #[test]
    fn materialize_writes_exact_bytes_so_file_len_equals_sealed_size() {
        let root = scratch("exactbytes");
        let blob = b"{\"a\":1}\n{\"b\":2}\n";
        let input = source("/home/u/.claude/projects/ws/abc.jsonl", blob);
        let path = materialize_sealed_blob(&root, &input).unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), blob);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            input.source_size_bytes,
            "物化文件的 len() 必须恒等于封存值 —— 这是 compact 判据换源成立的全部依据"
        );
    }

    #[test]
    fn materialization_root_prefix_does_not_leak_into_the_rebuilt_shape() {
        // R-E-34 条件 2：物化根本身不进任何判定。两个不同的根，重建出的**相对**形状必须逐字节同。
        let blob = b"x\n";
        let input = source("/home/u/.claude/projects/ws/abc.jsonl", blob);
        let root_a = scratch("root-a");
        let root_b = scratch("root-b-with-a-much-longer-name");

        let a = materialize_sealed_blob(&root_a, &input).unwrap();
        let b = materialize_sealed_blob(&root_b, &input).unwrap();

        assert_eq!(
            a.strip_prefix(&root_a).unwrap(),
            b.strip_prefix(&root_b).unwrap()
        );
        assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    }

    /// 一份真实形状的 Claude 现代生产 JSONL（形状取自 pin 侧 `claude_code.rs` 的真语料样本，
    /// 不是我凭想象编的键集）。
    const CLAUDE_JSONL: &[u8] = br#"{"type":"user","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"Hello Claude"}}
{"type":"assistant","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","content":"Hello! How can I help?"}}
"#;

    fn claude_source<'a>(path: &'a str, blob: &'a [u8]) -> SealedSource<'a> {
        SealedSource {
            agent: Origin::ClaudeCode,
            canonical_original_path: path,
            source_size_bytes: blob.len() as u64,
            blob,
        }
    }

    /// 一份**取值全部互不相同**的 manifest 只读投影，经唯一转换点变成 provenance 载荷。
    ///
    /// 取值刻意各不相同（不同长度、不同前缀、`source_mtime_ms` 与 `captured_at_ms` 不等）：
    /// 逐键断言若把两个键接错，用值相同的 fixture 是看不出来的。
    fn test_manifest_view() -> crate::raw_mirror::RawMirrorManifestView {
        crate::raw_mirror::RawMirrorManifestView {
            manifest_id: "mid-7f3a".to_owned(),
            manifest_relative_path: "manifests/7f/3a/mid-7f3a.json".to_owned(),
            blob_relative_path: "blobs/ab/cd/abcd1234.bin".to_owned(),
            blob_blake3: "abcd1234".repeat(8),
            blob_size_bytes: CLAUDE_JSONL.len() as u64,
            provider: "claude_code".to_owned(),
            source_id: "local".to_owned(),
            origin_kind: "local".to_owned(),
            origin_host: None,
            original_path: "/home/u/.claude/projects/myapp/x.jsonl".to_owned(),
            original_path_blake3: "ffff0000".repeat(8),
            captured_at_ms: 1_766_000_000_111,
            source_size_bytes: CLAUDE_JSONL.len() as u64,
            source_mtime_ms: Some(1_755_000_000_222),
            db_links: Vec::new(),
            manifest_blake3: Some("9999aaaa".repeat(8)),
        }
    }

    fn test_provenance() -> crate::raw_mirror::RawMirrorCaptureRecord {
        provenance_from_manifest_view(&test_manifest_view())
    }

    // -----------------------------------------------------------------------
    // R-E-34 条件 1：同一份字节、三种路径形状 → 三种处置。
    //
    // 这三条焊的是「路径形状进投影定义域」这个裁定本身。任何把物化优化成「只保文件名」
    // 或「用随机临时名」的改动都会让其中至少一条转红。
    // -----------------------------------------------------------------------

    #[test]
    fn same_bytes_as_codex_rollout_json_is_held_out_of_scope() {
        let root = scratch("shape-rollout");
        let input = SealedSource {
            agent: Origin::Codex,
            canonical_original_path: "/home/u/.codex/sessions/rollout-2025-12-01T10-00-00.json",
            source_size_bytes: CLAUDE_JSONL.len() as u64,
            blob: CLAUDE_JSONL,
        };
        match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Held { reason, .. } => assert_eq!(
                reason,
                crate::phase3_bundle::HoldReason::OutOfScopeFormat,
                "任意 codex `rollout-*.json` 按 §B.0.1 第三行立即 HOLD 并另立范围"
            ),
            other => panic!("期望 Held(out-of-scope-format)，实得 {other:?}"),
        }
    }

    #[test]
    fn same_bytes_as_plain_jsonl_projects_normally() {
        let root = scratch("shape-jsonl");
        let input = claude_source(
            "/home/u/.claude/projects/myapp/11111111-2222-3333-4444-555555555555.jsonl",
            CLAUDE_JSONL,
        );
        match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Projected(conv) => {
                assert_eq!(conv.messages.len(), 2, "两条消息都要在");
            }
            other => panic!("精确小写 `.jsonl` 是 JSONL 主路径，期望 Projected，实得 {other:?}"),
        }
    }

    #[test]
    fn same_bytes_under_a_desktop_sidecar_ancestor_component_is_held() {
        // R-E-34 条件 1③：sidecar 判据靠的是**祖先分量**不是文件名。文件名与上一条完全同，
        // 只有祖先分量不同 —— 处置必须不同。把物化改成「只保文件名」时这条会红。
        let root = scratch("shape-sidecar");
        let input = claude_source(
            "/home/u/Library/Application Support/Claude/claude-code-sessions/11111111-2222-3333-4444-555555555555.jsonl",
            CLAUDE_JSONL,
        );
        match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Held { reason, detail } => {
                assert_eq!(reason, crate::phase3_bundle::HoldReason::OutOfScopeFormat);
                assert_eq!(detail.as_deref(), Some("claude-desktop-sidecar"));
            }
            other => panic!("期望 Held(claude-desktop-sidecar)，实得 {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // 纯变换对照三条（§A.1.1 + R-E-34 条件 2/3）
    // -----------------------------------------------------------------------

    #[test]
    fn projection_is_invariant_to_the_materialization_root() {
        // R-E-34 条件 2：物化根不进任何判定。两个不同的根，投影结果的所有可观察字段必须同。
        let path = "/home/u/.claude/projects/myapp/aaaa1111-2222-3333-4444-555555555555.jsonl";
        let a = project_sealed_source(
            &scratch("inv-root-a"),
            &claude_source(path, CLAUDE_JSONL),
            &test_provenance(),
        )
        .unwrap();
        let b = project_sealed_source(
            &scratch("inv-root-b-considerably-longer"),
            &claude_source(path, CLAUDE_JSONL),
            &test_provenance(),
        )
        .unwrap();

        let (a, b) = match (a, b) {
            (SealedProjection::Projected(a), SealedProjection::Projected(b)) => (a, b),
            other => panic!("两侧都该 Projected，实得 {other:?}"),
        };
        assert_eq!(a.source_path, b.source_path);
        assert_eq!(a.external_id, b.external_id);
        assert_eq!(a.workspace, b.workspace);
        assert_eq!(a.agent_slug, b.agent_slug);
        assert_eq!(a.messages.len(), b.messages.len());
        for (x, y) in a.messages.iter().zip(b.messages.iter()) {
            assert_eq!(
                (&x.role, &x.content, &x.extra),
                (&y.role, &y.content, &y.extra)
            );
        }
    }

    #[test]
    fn projection_is_invariant_to_the_materialized_file_mtime() {
        // R-E-34 条件 3：`since_ts = None` 必须真的把时钟摘出去。
        //
        // **这条测试的写法本身有一段账**：第一版是「物化 → 改 mtime → 调
        // `project_sealed_source`」，它绿了，但它什么都没测 —— `project_sealed_source`
        // 内部会重新物化、把刚设的 mtime 覆盖成「现在」。故必须走
        // `project_from_materialized`，才能真的把手插在「物化之后、扫描之前」。
        let path = "/home/u/.claude/projects/myapp/bbbb1111-2222-3333-4444-555555555555.jsonl";
        let input = claude_source(path, CLAUDE_JSONL);
        let root = scratch("mtime-invariance");
        let materialized = materialize_sealed_blob(&root, &input).unwrap();

        let mut seen = Vec::new();
        for mtime in [1_000_000_000i64, 1_900_000_000] {
            std::fs::File::options()
                .write(true)
                .open(&materialized)
                .and_then(|f| f.set_times(filetime_like(mtime)))
                .expect("set mtime");
            assert_eq!(
                std::fs::metadata(&materialized)
                    .unwrap()
                    .modified()
                    .unwrap()
                    .duration_since(std::time::SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                u64::try_from(mtime).unwrap(),
                "先证明 mtime 真的被改了 —— 不然这条测试又是个失效探针"
            );
            match project_from_materialized(&materialized, &input, &test_provenance()).unwrap() {
                SealedProjection::Projected(conv) => seen.push(conv),
                other => panic!("期望 Projected，实得 {other:?}"),
            }
        }
        let (a, b) = (&seen[0], &seen[1]);
        assert_eq!(a.external_id, b.external_id);
        assert_eq!(a.messages.len(), b.messages.len());
        for (x, y) in a.messages.iter().zip(b.messages.iter()) {
            assert_eq!(
                (&x.role, &x.content, &x.created_at),
                (&y.role, &y.content, &y.created_at),
                "投影结果不得随物化文件的 mtime 变化"
            );
        }
    }

    /// **这条是 R-E-35 那条等价性论证的唯一承重测试。**
    ///
    /// 论证是：「物化的字节就是封存的字节，所以读物化文件的 `len()` 与读 manifest 的
    /// `source_size_bytes` 等价」。但那个论证只在**物化文件真的是 compact 判据的读取对象**
    /// 时才需要；本实现选的是**显式传封存值**，所以真正要证的是「传进去的那个值就是判据」。
    ///
    /// 手法：同一个已物化的文件（字节完全不变、只物化一次），用两个不同的
    /// `source_size_bytes` 各投影一次 —— 唯一变量就是那个值。跨过 16 MiB 阈值的那次必须
    /// compact，没跨过的那次必须不 compact。
    ///
    /// **它同时是「不跑活路径版本」的守卫**：活路径版本读的是
    /// `fs::metadata(&conv.source_path)`，而 restore 侧 `conv.source_path` 已被改写成
    /// manifest 的 `original_path`（那条路径在恢复现场根本不存在）→ `None` → **compact 静默
    /// 不执行**，正是附录 §A.1.1 点名的第一个后果。改回活路径版本，本条立刻转红。
    #[test]
    fn compact_criterion_reads_the_sealed_size_not_the_filesystem() {
        const THRESHOLD: u64 = 16 * 1024 * 1024;
        // 允许出现在 compact 之后的 extra 顶层键：`cass` 加上 franken 归一化出来的那五个
        // （`FRANKEN_NORMALIZED_EXTRA_KEYS`，compact 明令不得丢它们）。
        const KEPT: &[&str] = &[
            "cass",
            "tool_call_id",
            "tool_call_args",
            "encrypted_content",
            "raw_role",
            "unpaired",
        ];

        let mut blob = Vec::with_capacity(THRESHOLD as usize + 4096);
        blob.extend_from_slice(
            br#"{"timestamp":"2026-01-01T00:00:00Z","type":"session_meta","payload":{"cwd":"/tmp/codex-demo"}}
"#,
        );
        let mut i = 0u64;
        while (blob.len() as u64) < THRESHOLD {
            blob.extend_from_slice(
                format!(
                    r#"{{"timestamp":"2026-01-01T00:00:0{}Z","type":"response_item","payload":{{"type":"message","role":"user","content":[{{"type":"input_text","text":"filler {} {}"}}]}}}}
"#,
                    i % 10,
                    i,
                    "x".repeat(512)
                )
                .as_bytes(),
            );
            i += 1;
        }
        assert!(blob.len() as u64 >= THRESHOLD);

        let path = "/home/u/.codex/sessions/2026/01/01/rollout-not-a-json.jsonl";
        let root = scratch("compact-sealed-size");
        let big = SealedSource {
            agent: Origin::Codex,
            canonical_original_path: path,
            source_size_bytes: blob.len() as u64,
            blob: &blob,
        };
        // 只物化一次；后面两次投影读的是同一个文件、同一批字节。
        let materialized = materialize_sealed_blob(&root, &big).unwrap();

        let extras_outside_kept = |proj: SealedProjection| -> usize {
            match proj {
                SealedProjection::Projected(conv) => conv
                    .messages
                    .iter()
                    .filter_map(|m| m.extra.as_object())
                    .flat_map(|o| o.keys())
                    .filter(|k| !KEPT.contains(&k.as_str()))
                    .count(),
                other => panic!("期望 Projected，实得 {other:?}"),
            }
        };

        let below = SealedSource {
            source_size_bytes: 1024,
            ..big
        };
        let kept_when_below = extras_outside_kept(
            project_from_materialized(&materialized, &below, &test_provenance()).unwrap(),
        );
        assert!(
            kept_when_below > 0,
            "先证探针有分辨力：封存值低于阈值时，extra 里必须仍留着会被 compact 丢掉的键；\
             一个都没有说明这份语料压根不产可 compact 的 extra，本测试就分不出两种行为"
        );

        // 正向断言：compact 之后那五个「明令不得丢」的键**仍然在场**。
        // 只做反向的「剩下的键 ⊆ 允许集」锁不住基线——少掉一个键照样满足子集关系。
        // 本断言同时是 `COMPACT_INVARIANT_EXTRA_KEYS` 与基线私有常量的同步锁。
        let above = project_from_materialized(&materialized, &big, &test_provenance()).unwrap();
        if let SealedProjection::Projected(conv) = &above {
            let present: std::collections::BTreeSet<&str> = conv
                .messages
                .iter()
                .filter_map(|m| m.extra.as_object())
                .flat_map(|o| o.keys().map(String::as_str))
                .collect();
            assert!(
                COMPACT_INVARIANT_EXTRA_KEYS
                    .iter()
                    .any(|k| present.contains(k)),
                "compact 之后 `FRANKEN_NORMALIZED_EXTRA_KEYS` 里的键必须仍在场；实得 {present:?}"
            );
        }

        let kept_when_above = extras_outside_kept(above);
        assert_eq!(
            kept_when_above, 0,
            "封存值跨过 16 MiB 阈值时必须 compact —— 判据是传进去的封存值，\
             不是 `fs::metadata(conv.source_path)`（那条路径在恢复现场不存在，会静默不 compact）"
        );
    }

    fn filetime_like(secs: i64) -> std::fs::FileTimes {
        let ts = std::time::SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(u64::try_from(secs).unwrap());
        std::fs::FileTimes::new().set_modified(ts).set_accessed(ts)
    }

    /// **红相在先（plan Step 1 / 附录 §B.11 的 P15 末条）**：`metadata.cass.raw_mirror` 必须
    /// 指向**本次被消费的那份 manifest**。
    ///
    /// §A.1.1 第 3 条把 `attach_raw_mirror_capture` 整步排除（它会 `capture_source_file` 产生
    /// 文件系统写副作用），同时明写「`metadata.cass.raw_mirror` 由 restore 按被消费的那份
    /// manifest 直接填写，字段取值以该 manifest 为准」。**当前实现只做了前半句**——排除了
    /// capture，却没有填那个字段，于是恢复出来的会话查不出它来自哪份 manifest。
    ///
    /// 这条测试现在应当是红的；转绿要靠把 provenance 接进投影（见 E5 台账 Phase 1 待批项）。
    #[test]
    fn projected_conversation_records_the_consumed_manifest_provenance() {
        let root = scratch("provenance");
        let input = claude_source(
            "/home/u/.claude/projects/myapp/cccc1111-2222-3333-4444-555555555555.jsonl",
            CLAUDE_JSONL,
        );
        let conv = match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Projected(conv) => conv,
            other => panic!("期望 Projected，实得 {other:?}"),
        };

        let rm = conv
            .metadata
            .get("cass")
            .and_then(|c| c.get("raw_mirror"))
            .unwrap_or_else(|| {
                panic!(
                    "metadata.cass.raw_mirror 必须在场（§A.1.1 第 3 条）；实得 metadata = {}",
                    conv.metadata
                )
            });

        // R-E-37 条件 2：把「指向本次被消费的那份」从语义要求变成**逐键断言**。
        // 八个键与 `attach_raw_mirror_metadata` 写出的形状逐一对齐 —— 不另造第二套形状。
        let view = test_manifest_view();
        assert_eq!(rm.get("schema_version").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(
            rm.get("manifest_id").and_then(|v| v.as_str()),
            Some(view.manifest_id.as_str())
        );
        assert_eq!(
            rm.get("manifest_relative_path").and_then(|v| v.as_str()),
            Some(view.manifest_relative_path.as_str())
        );
        assert_eq!(
            rm.get("blob_relative_path").and_then(|v| v.as_str()),
            Some(view.blob_relative_path.as_str())
        );
        assert_eq!(
            rm.get("blob_blake3").and_then(|v| v.as_str()),
            Some(view.blob_blake3.as_str())
        );
        assert_eq!(
            rm.get("blob_size_bytes").and_then(|v| v.as_u64()),
            Some(view.blob_size_bytes)
        );
        assert_eq!(
            rm.get("captured_at_ms").and_then(|v| v.as_i64()),
            Some(view.captured_at_ms)
        );
        assert_eq!(
            rm.get("source_mtime_ms").and_then(|v| v.as_i64()),
            view.source_mtime_ms,
            "`source_mtime_ms` 必须取自 manifest 的封存值 —— 写 null 会伪装成\
             「这份 manifest 本来就没记」，比缺键更难发现（R-E-37(a) 的立条理由）"
        );
        // 封存长度与 provenance 记的 blob 长度是同一个事实的两处表达，必须一致。
        assert_eq!(view.blob_size_bytes, input.source_size_bytes);
    }

    // =======================================================================
    // 必接⑤（裁定 R-E-26）：用**真实投影**重跑 E4 第二层的关系判定
    //
    // E4 当时用受控替身把判定逻辑测死了，状态记作「逻辑闭、投影挂」。这一组把挂着的那半
    // 接上：同样的关系形态，改由 pin parser 的真实投影产出摘要。
    //
    // 造第二层用例的手法：**同样的逻辑消息、不同的字节**（键序不同）。字节层因此判不出
    // 关系（既不相等也不是字节前缀），必须落到第二层；而第二层若实现正确，应当把它们看成
    // 同一批消息。这正是 §D.2.1 说「第二层不是可选优化」的那个场景。
    // =======================================================================

    fn ns() -> OriginNamespace {
        OriginNamespace {
            agent: Origin::ClaudeCode,
            source_id: "local".to_owned(),
            origin_host: "h1".to_owned(),
        }
    }

    const CLAUDE_PATH: &str =
        "/home/u/.claude/projects/myapp/dddd1111-2222-3333-4444-555555555555.jsonl";

    /// 同一条消息的两种字节写法：键序不同，逻辑内容相同。
    fn line_key_order_a(text: &str, ts: &str) -> String {
        format!(
            r#"{{"type":"user","timestamp":"{ts}","message":{{"role":"user","content":"{text}"}}}}"#
        )
    }
    fn line_key_order_b(text: &str, ts: &str) -> String {
        format!(
            r#"{{"message":{{"content":"{text}","role":"user"}},"timestamp":"{ts}","type":"user"}}"#
        )
    }

    fn version(bytes: &[u8], mtime: i64, blob_id: &str) -> ContentVersion {
        ContentVersion::new(
            VersionSource::Mirror,
            bytes,
            mtime,
            1_700_000_000_000,
            blob_id,
        )
    }

    #[test]
    fn real_projection_resolves_a_message_layer_prefix_as_strictly_before() {
        let root = scratch("real-prefix");
        let projector = SealedMessageProjector {
            scratch_root: &root,
            canonical_original_path: CLAUDE_PATH,
            agent: Origin::ClaudeCode,
            sealed_source_size_bytes: 4096,
        };

        let a_bytes = format!(
            "{}\n{}\n",
            line_key_order_a("one", "2025-12-01T10:00:00Z"),
            line_key_order_a("two", "2025-12-01T10:00:01Z")
        );
        // B：同样两条消息但键序不同（故字节层判不出前缀），再多一条。
        let b_bytes = format!(
            "{}\n{}\n{}\n",
            line_key_order_b("one", "2025-12-01T10:00:00Z"),
            line_key_order_b("two", "2025-12-01T10:00:01Z"),
            line_key_order_b("three", "2025-12-01T10:00:02Z")
        );

        let a = version(a_bytes.as_bytes(), 1_000, "blob-a");
        let b = version(b_bytes.as_bytes(), 2_000, "blob-b");

        // 先证明这一对**确实落到第二层**：字节层必须判不出来，否则本用例测的是字节层。
        assert!(
            !b_bytes.as_bytes().starts_with(a_bytes.as_bytes()),
            "构造失误：B 的字节以 A 开头，那样第一层就结束了，第二层根本不会被调用"
        );

        let verdict = compare_versions(&ns(), &a, &b, &projector).unwrap();
        assert_eq!(verdict.relation, Relation::StrictlyBefore);
        assert_eq!(
            verdict.layer,
            RelationLayer::MessageSequence,
            "必须由第二层判出——落在字节层说明用例没造对"
        );

        // 决策表：真前缀 → replace，不是 HOLD（§5.2.1 与 §10.2 都点名这条）。
        let identity = RestoreIdentity {
            origin: ns(),
            canonical_path: CLAUDE_PATH.to_owned(),
        };
        let action = decide_action(&identity, &[a], &b, &projector).unwrap();
        assert!(
            matches!(action, RestoreAction::Replace { .. }),
            "真前缀必须判 replace，实得 {action:?}"
        );
    }

    #[test]
    fn real_projection_treats_different_bytes_with_equal_message_sequences_as_equal() {
        let root = scratch("real-equal");
        let projector = SealedMessageProjector {
            scratch_root: &root,
            canonical_original_path: CLAUDE_PATH,
            agent: Origin::ClaudeCode,
            sealed_source_size_bytes: 4096,
        };
        let a_bytes = format!("{}\n", line_key_order_a("same", "2025-12-01T10:00:00Z"));
        let b_bytes = format!("{}\n", line_key_order_b("same", "2025-12-01T10:00:00Z"));
        assert_ne!(a_bytes, b_bytes, "两侧字节必须不同，否则测的是字节层");

        let a = version(a_bytes.as_bytes(), 1_000, "blob-a");
        let b = version(b_bytes.as_bytes(), 2_000, "blob-b");
        let verdict = compare_versions(&ns(), &a, &b, &projector).unwrap();
        assert_eq!(verdict.relation, Relation::Equal);
        assert_eq!(verdict.layer, RelationLayer::MessageSequence);
    }

    #[test]
    fn real_projection_reports_genuine_content_divergence_as_diverged() {
        let root = scratch("real-diverged");
        let projector = SealedMessageProjector {
            scratch_root: &root,
            canonical_original_path: CLAUDE_PATH,
            agent: Origin::ClaudeCode,
            sealed_source_size_bytes: 4096,
        };
        let a_bytes = format!(
            "{}\n{}\n",
            line_key_order_a("one", "2025-12-01T10:00:00Z"),
            line_key_order_a("left", "2025-12-01T10:00:01Z")
        );
        let b_bytes = format!(
            "{}\n{}\n",
            line_key_order_b("one", "2025-12-01T10:00:00Z"),
            line_key_order_b("right", "2025-12-01T10:00:01Z")
        );
        let a = version(a_bytes.as_bytes(), 1_000, "blob-a");
        let b = version(b_bytes.as_bytes(), 2_000, "blob-b");
        let verdict = compare_versions(&ns(), &a, &b, &projector).unwrap();
        assert_eq!(
            verdict.relation,
            Relation::Diverged,
            "第二条消息内容真的不同 —— 这必须是分叉，不能被摘要口径抹平"
        );
    }

    #[test]
    fn real_projection_n_way_fork_reports_every_maximal_element() {
        let root = scratch("real-fork");
        let projector = SealedMessageProjector {
            scratch_root: &root,
            canonical_original_path: CLAUDE_PATH,
            agent: Origin::ClaudeCode,
            sealed_source_size_bytes: 4096,
        };
        let base = line_key_order_a("shared", "2025-12-01T10:00:00Z");
        let mk = |tail: &str| {
            format!(
                "{base}\n{}\n",
                line_key_order_b(tail, "2025-12-01T10:00:01Z")
            )
        };
        let (x, y, z) = (mk("alpha"), mk("beta"), mk("gamma"));
        let identity = RestoreIdentity {
            origin: ns(),
            canonical_path: CLAUDE_PATH.to_owned(),
        };
        let versions = vec![
            version(x.as_bytes(), 1_000, "blob-x"),
            version(y.as_bytes(), 2_000, "blob-y"),
            version(z.as_bytes(), 3_000, "blob-z"),
        ];
        match select_winner(&identity, &versions, &projector).unwrap() {
            WinnerOutcome::Hold(record) => {
                assert_eq!(record.class(), HoldClass::Version);
                // §D.5：证据必须带出**全部** N 个极大元，不能只表达两两分叉。
                let text = format!("{record:?}");
                for id in ["blob-x", "blob-y", "blob-z"] {
                    assert!(text.contains(id), "分叉证据缺极大元 {id}：{text}");
                }
            }
            other => panic!("三路互不可比必须判 content fork HOLD，实得 {other:?}"),
        }
    }

    /// **这条是「摘要口径对 compact 不变」这个解释的承重测试。**
    ///
    /// 附录 §D.2.1 只说第二层比「消息序列」，没定义「同一条消息」的判据。若把整条
    /// `NormalizedMessage`（含 `extra` 全部键）编进摘要，就会出现这样一对：A 是 B 的真前缀，
    /// 但 A 只有 12 MiB、B 有 18 MiB，于是 **B 被 compact 而 A 没有**，两侧共享前缀的同一条
    /// 消息摘要不同 → 第二层判分叉 → HOLD。那正是 §10.2 点名「截断超集用例必过、不得以
    /// HOLD 蒙混」要挡的东西，只是成因从字节层键序换成了 compact 阈值跨越。
    ///
    /// 手法：**同一份字节投影两次**，唯一变量是喂给 compact 判据的封存值（一次低于 16 MiB
    /// 阈值、一次高于），断言两次的摘要串逐条相同。先证探针有分辨力：两次投影的
    /// `extra` 键集必须真的不同，否则这条测试没测到 compact 发生与否。
    #[test]
    fn message_digests_are_invariant_across_the_compact_threshold() {
        const THRESHOLD: u64 = 16 * 1024 * 1024;
        let mut blob = Vec::with_capacity(THRESHOLD as usize + 8192);
        blob.extend_from_slice(
            br#"{"timestamp":"2026-01-01T00:00:00Z","type":"session_meta","payload":{"cwd":"/tmp/codex-demo"}}
"#,
        );
        let mut i = 0u64;
        while (blob.len() as u64) < THRESHOLD {
            blob.extend_from_slice(
                format!(
                    r#"{{"timestamp":"2026-01-01T00:00:0{}Z","type":"response_item","payload":{{"type":"message","role":"user","content":[{{"type":"input_text","text":"pad {} {}"}}]}}}}
"#,
                    i % 10,
                    i,
                    "y".repeat(512)
                )
                .as_bytes(),
            );
            i += 1;
        }

        // 文件名必须是 codex 认得的 `rollout-*` 形态（`.jsonl` 故走 JSONL 主路径，不是
        // whole-file），且**全小写**：用普通名字 connector 扫出 0 个会话，带大写字母则被 E2
        // 的分类器判 `filename-case-variant` 而 HOLD（§B.0.1「及其大小写变体」）。
        // 两次都是「路径形状进投影定义域」（R-E-34）的实证，代价是两次红。
        let path = "/home/u/.codex/sessions/2026/01/01/rollout-2026-01-01t00-00-00.jsonl";
        let root = scratch("digest-compact-invariance");

        let digests_at = |sealed: u64, tag: &str| -> Vec<CanonicalMessageDigest> {
            let projector = SealedMessageProjector {
                scratch_root: &root.join(tag),
                canonical_original_path: path,
                agent: Origin::Codex,
                sealed_source_size_bytes: sealed,
            };
            projector.project(&ns(), &blob).expect("projection")
        };

        // 分辨力前置：先证「compact 到底有没有发生」这件事在两侧真的不同。
        let extras_at = |sealed: u64, tag: &str| -> usize {
            let slot = root.join(tag);
            let input = SealedSource {
                agent: Origin::Codex,
                canonical_original_path: path,
                source_size_bytes: blob.len() as u64,
                blob: &blob,
            };
            let m = materialize_sealed_blob(&slot, &input).unwrap();
            let below = SealedSource {
                source_size_bytes: sealed,
                ..input
            };
            match project_from_materialized(&m, &below, &test_provenance()).unwrap() {
                SealedProjection::Projected(conv) => conv
                    .messages
                    .iter()
                    .filter_map(|m| m.extra.as_object())
                    .map(serde_json::Map::len)
                    .sum(),
                other => panic!("期望 Projected，实得 {other:?}"),
            }
        };
        let keys_below = extras_at(1024, "probe-below");
        let keys_above = extras_at(THRESHOLD, "probe-above");
        assert!(
            keys_below > keys_above,
            "探针无分辨力：跨阈值前后 extra 键总数没变（{keys_below} vs {keys_above}），\
             说明这份语料压根没被 compact，本测试证明不了摘要对 compact 不变"
        );

        let below = digests_at(1024, "below");
        let above = digests_at(THRESHOLD, "above");
        assert_eq!(
            below.len(),
            above.len(),
            "compact 不该改变消息条数（它只动 extra）"
        );
        assert_eq!(
            below, above,
            "摘要必须对 compact 不变 —— 否则一对跨 16 MiB 阈值的真前缀会被第二层误判成分叉，\
             撞上 §10.2「截断超集用例必过、不得以 HOLD 蒙混」"
        );
    }

    // =======================================================================
    // §B.11 逐字段 checklist —— **契约验证，不是 TDD 红转绿**
    //
    // 这一组锁的是「经 E5 这条投影链看过去，pin parser 的行为符合附录 §B.2 分支表」。
    // 绝大多数判据是 **parser 既有的行为**，不是本任务新写的逻辑，故它们的绿**不构成
    // 「我实现对了」的证据**，只构成「这条链没有把 parser 的正确行为破坏掉，且将来 pin
    // 升级若改了这些行为会被立刻发现」。台账按契约验证记账，与红转绿分开。
    //
    // 覆盖面按 §B.11 的编号标注；**P10 与 P15 的 11 个 token 汇总列不在本组**——它们要
    // 落库之后才能断言，归写入半（Phase 2）。Phase 1 收口时出分项表，不写裸的「B.11 已过」。
    // =======================================================================

    /// 一份把 §B.2 四种 content 块一次走全的真实形状样本。
    ///
    /// 结构取自附录 §B.2 分支表：assistant envelope 里放 text / tool_use / thinking 三块，
    /// user envelope 里放 tool_result（表里明写 `role != "user"` 时 ToolResult 块被跳过，
    /// 故必须分两个 envelope）。
    const CLAUDE_ALL_BLOCKS: &str = concat!(
        r#"{"type":"user","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"kick off"}}"#,
        "\n",
        r#"{"type":"assistant","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","model":"claude-opus-5","content":[{"type":"text","text":"let me look"},{"type":"thinking","thinking":"weighing options"},{"type":"tool_use","id":"toolu_01","name":"Read","input":{"path":"/x"}}]}}"#,
        "\n",
        r#"{"type":"user","timestamp":"2025-12-01T10:00:02Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01","content":"file body"}]}}"#,
        "\n",
    );

    fn project_all_blocks(tag: &str) -> Box<NormalizedConversation> {
        let root = scratch(tag);
        let bytes = CLAUDE_ALL_BLOCKS.as_bytes();
        let input = claude_source(CLAUDE_PATH, bytes);
        match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Projected(conv) => conv,
            other => panic!("期望 Projected，实得 {other:?}"),
        }
    }

    /// P1 `idx` 连续 `0..N`；P2 role 取值在 6-role 内且 `assistant`/`agent` 不混、
    /// `tool_call`/`tool_result`/`reasoning` 以字面串存。
    #[test]
    fn contract_p1_p2_idx_is_dense_and_roles_are_canonical() {
        let conv = project_all_blocks("b11-p1p2");
        let idxs: Vec<i64> = conv.messages.iter().map(|m| m.idx).collect();
        assert_eq!(
            idxs,
            (0..idxs.len() as i64).collect::<Vec<_>>(),
            "P1：块拆分后 idx 必须重编成连续 0..N"
        );

        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        const SIX_ROLE: [&str; 6] = [
            "user",
            "assistant",
            "tool_call",
            "tool_result",
            "reasoning",
            "system",
        ];
        for role in &roles {
            assert!(SIX_ROLE.contains(role), "P2：role `{role}` 不在 6-role 内");
        }
        assert!(
            !roles.contains(&"agent"),
            "P2：`agent` 是非规范 role，只出现在已被范围门 HOLD 的 `.json` 路径上"
        );
        // 四种块各产出了它该产的那条。
        for expected in ["user", "assistant", "reasoning", "tool_call", "tool_result"] {
            assert!(
                roles.contains(&expected),
                "样本应覆盖 role `{expected}`，实得 {roles:?}"
            );
        }
    }

    /// P3 `raw_role`：**每条** retained 消息都有、是 string、同 envelope 多消息值相同。
    #[test]
    fn contract_p3_every_retained_message_carries_a_string_raw_role() {
        let conv = project_all_blocks("b11-p3");
        for m in &conv.messages {
            let rr = m.extra.get("raw_role").unwrap_or_else(|| {
                panic!(
                    "P3：消息 idx={} 缺 extra.raw_role（上位 §3.6 无例外）",
                    m.idx
                )
            });
            assert!(rr.is_string(), "P3：raw_role 必须是 string，实得 {rr}");
        }
        // 同 envelope 拆出的多条复制同一个 raw_role：assistant envelope 拆出
        // text / reasoning / tool_call 三条，raw_role 应当都是 "assistant"。
        let from_assistant_envelope: Vec<&str> = conv
            .messages
            .iter()
            .filter(|m| matches!(m.role.as_str(), "assistant" | "reasoning" | "tool_call"))
            .filter_map(|m| m.extra.get("raw_role").and_then(|v| v.as_str()))
            .collect();
        assert!(
            from_assistant_envelope.iter().all(|r| *r == "assistant"),
            "P3：同一 envelope 拆出的消息必须复制同一个 raw_role，实得 {from_assistant_envelope:?}"
        );
    }

    /// P7 tool args **两处表示不同**：`extra.tool_call_args` 键始终存在（缺失写 JSON null）；
    /// `invocations[0].arguments` 缺失时**键不存在**（`skip_serializing_if`）。
    /// P11 tool_call 消息有一条 invocation，`kind="tool"`、`name`、`call_id` 齐。
    #[test]
    fn contract_p7_p11_tool_args_have_two_distinct_representations() {
        let conv = project_all_blocks("b11-p7p11");
        let call = conv
            .messages
            .iter()
            .find(|m| m.role == "tool_call")
            .expect("样本里有一个 tool_use 块");

        assert!(
            call.extra.get("tool_call_args").is_some(),
            "P7：`extra.tool_call_args` 键必须始终存在（args 缺失时值为 JSON null）"
        );
        assert_eq!(
            call.invocations.len(),
            1,
            "P11：tool_call 消息应恰有一条 invocation"
        );
        let inv = &call.invocations[0];
        assert_eq!(inv.kind, "tool");
        assert_eq!(inv.name, "Read");
        assert_eq!(inv.call_id.as_deref(), Some("toolu_01"));
        // args 非缺失时两处是同一个 JSON 值。
        assert_eq!(
            call.extra.get("tool_call_args"),
            inv.arguments.as_ref(),
            "P7：args 非缺失时 `extra.tool_call_args` 与 `invocations[0].arguments` 必须同值"
        );
    }

    /// P8 pairing：`extra.tool_call_id` 与 `extra.unpaired` **恰有一个**存在。
    #[test]
    fn contract_p8_pairing_has_exactly_one_of_id_or_unpaired() {
        let conv = project_all_blocks("b11-p8");
        for m in conv
            .messages
            .iter()
            .filter(|m| matches!(m.role.as_str(), "tool_call" | "tool_result"))
        {
            let has_id = m.extra.get("tool_call_id").is_some();
            let has_unpaired = m.extra.get("unpaired").is_some();
            assert!(
                has_id ^ has_unpaired,
                "P8：idx={} 的 pairing 键必须恰有一个（id={has_id}, unpaired={has_unpaired}）：{}",
                m.idx,
                m.extra
            );
        }
    }

    /// P5 author 符合 §B.2 表：`assistant` 取 `message.model`；`user` / `tool_result` 为空；
    /// **不伪造模型**。P6 `created_at` 由 `parse_timestamp` 得出、非空。
    #[test]
    fn contract_p5_p6_author_and_timestamps_follow_the_branch_table() {
        let conv = project_all_blocks("b11-p5p6");
        for m in &conv.messages {
            match m.role.as_str() {
                "user" | "tool_result" => assert!(
                    m.author.is_none(),
                    "P5：role={} 的 author 必须为空，实得 {:?}",
                    m.role,
                    m.author
                ),
                "assistant" | "reasoning" | "tool_call" => assert_eq!(
                    m.author.as_deref(),
                    Some("claude-opus-5"),
                    "P5：assistant envelope 拆出的消息 author 取 message.model"
                ),
                other => panic!("样本不该产出 role={other}"),
            }
            assert!(
                m.created_at.is_some(),
                "P6：样本每行都有 timestamp，created_at 不该为空"
            );
        }
    }

    /// P12 `snippets` 三家均产空 —— **restore 场景下为空不是漏字段**。
    #[test]
    fn contract_p12_snippets_are_empty_by_construction_not_by_omission() {
        let conv = project_all_blocks("b11-p12");
        assert!(
            conv.messages.iter().all(|m| m.snippets.is_empty()),
            "P12：三家所有 push 点都是 `snippets: Vec::new()`，非空说明形态超出附录定义域"
        );
    }

    /// §B.2 的两个非对称之一：**空 thinking 保留、空 prose 丢弃**。
    /// 这条是上位 §3.5 / §16.4 的锚点，也是 §D.2.1 第二层存在意义的语料来源。
    #[test]
    fn contract_empty_thinking_is_kept_while_empty_prose_is_dropped() {
        let root = scratch("b11-empty-asym");
        let bytes = concat!(
            r#"{"type":"assistant","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","content":[{"type":"text","text":"   "},{"type":"thinking","thinking":""}]}}"#,
            "\n",
        )
        .as_bytes();
        let input = claude_source(CLAUDE_PATH, bytes);
        let conv = match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Projected(conv) => conv,
            other => panic!("期望 Projected，实得 {other:?}"),
        };
        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        assert!(
            roles.contains(&"reasoning"),
            "空 thinking 必须保留（不做 trim 判空），实得 {roles:?}"
        );
        assert!(
            !roles.contains(&"assistant"),
            "只有空白的 text 块 trim 后为空，必须不产消息，实得 {roles:?}"
        );
    }

    // ---- §B.3 Codex 家族的契约批 -------------------------------------------
    //
    // 同样是**契约验证**。选这几条是因为它们是三家差异最大、也最容易被实现者「顺手统一」
    // 掉的地方——统一了就会静默改变 canonical 语料的构成。

    const CODEX_PATH: &str = "/home/u/.codex/sessions/2026/01/01/rollout-2026-01-01t00-00-00.jsonl";

    /// 一份走全 §B.3.1/§B.3.2 主要分支的 codex 样本。
    const CODEX_ALL_BRANCHES: &str = concat!(
        r#"{"timestamp":"2026-01-01T00:00:00Z","type":"session_meta","payload":{"cwd":"/w/repo"}}"#,
        "\n",
        r#"{"timestamp":"2026-01-01T00:00:01Z","type":"turn_context","payload":{"model":"gpt-5.5"}}"#,
        "\n",
        // developer：§B.3.1 明写整条 continue（上位 §5.2「developer 整条永久 drop」）
        r#"{"timestamp":"2026-01-01T00:00:02Z","type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"you are codex"}]}}"#,
        "\n",
        r#"{"timestamp":"2026-01-01T00:00:03Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"list files"}]}}"#,
        "\n",
        r#"{"timestamp":"2026-01-01T00:00:04Z","type":"response_item","payload":{"type":"reasoning","summary":[{"type":"summary_text","text":"plan it"}]}}"#,
        "\n",
        r#"{"timestamp":"2026-01-01T00:00:05Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"call_1","arguments":"{\"cmd\":\"ls\"}"}}"#,
        "\n",
        r#"{"timestamp":"2026-01-01T00:00:06Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call_1","output":"a.txt"}}"#,
        "\n",
        // event_msg 的 agent_message：§B.3.2 第一行，最先判、直接 continue（去重）
        r#"{"timestamp":"2026-01-01T00:00:07Z","type":"event_msg","payload":{"type":"agent_message","message":"dup of response_item"}}"#,
        "\n",
    );

    fn project_codex(tag: &str, bytes: &[u8]) -> Box<NormalizedConversation> {
        let root = scratch(tag);
        let input = SealedSource {
            agent: Origin::Codex,
            canonical_original_path: CODEX_PATH,
            source_size_bytes: bytes.len() as u64,
            blob: bytes,
        };
        match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Projected(conv) => conv,
            other => panic!("期望 Projected，实得 {other:?}"),
        }
    }

    /// §B.3.1：`role=developer` 的 message **整条不产消息**。
    ///
    /// 这条不是「过滤噪声」这种可商量的优化，是上位 §5.2 的硬约束由 parser 的 guard 实现。
    /// 若哪天它开始产消息，canonical 语料会静默多出一整类系统提示词，而下游画像会把它
    /// 当成用户内容——正是上位那条约束要防的东西。

    // =======================================================================
    // §B.11 P4 · content 的**字节级**格式（§B.1.1）
    //
    // 仍是契约验证，不是红转绿。P4 的判据是「与 §B.1.1 钉死的字节格式逐字节相等
    // （含 compact JSON 的 `Display` 形式与 `\n` 连接规则）」，所以这一组一律断言
    // **完整字符串**，不写 `contains`。
    // =======================================================================

    /// 一条 tool_use，`input` 的键在源文本里是 `zebra` 在前、`alpha` 在后。
    ///
    /// **这份样本的键序是刻意反字典序的**：§B.1.1 明写 object 键序 = 源 JSON 文本里的
    /// 出现顺序（插入序），而这一点**由 `serde_json` 的 `preserve_order` feature 决定**
    /// —— 附录同时警告「若将来某次构建把该 feature 解析掉，`Display` 会**静默**改回
    /// 字典序、content 字节随之全变」。字典序下这条会渲染成 `{"alpha":2,"zebra":1}`，
    /// 于是本用例立刻转红。**这就是给那条 feature 依赖装的机器守卫。**
    const CLAUDE_TOOL_ARGS_KEY_ORDER: &str = concat!(
        r#"{"type":"assistant","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","model":"claude-opus-5","content":[{"type":"tool_use","id":"toolu_key","name":"Grep","input":{"zebra":1,"alpha":2}}]}}"#,
        "\n",
    );

    /// `input` 为 JSON `null` 的 tool_use：§B.1.1 规定「args 是 null」与「无 args」
    /// 渲染结果相同 —— 都是 bare name。
    const CLAUDE_TOOL_NULL_ARGS: &str = concat!(
        r#"{"type":"assistant","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","model":"claude-opus-5","content":[{"type":"tool_use","id":"toolu_null","name":"Bash","input":null}]}}"#,
        "\n",
    );

    /// **tool_result** 的 content 数组里夹一个空片段与一个非白名单块。
    ///
    /// 走的是 `render_tool_result_content(Some(Array)) → flatten_content(该数组)` 这条路
    /// （§B.1.1 点名），于是「丢弃 `None` 与空串、其余用**单个** `\n` 连接」这条规则
    /// 才是本用例的判据。
    ///
    /// **⚠ 这里刻意不用 user 消息的 content 数组**：那条路走的是
    /// `split_content_blocks` 的 typed 分支，不是 `flatten_content`，两者对空片段的
    /// 处置不同（本棒第一版就把样本放在 user 消息上，实测拿到 `"first\n\nsecond"`
    /// —— 差点据此报「附录写错了」，回去读 pin 上的 `flatten_content` 才发现它确实
    /// 丢空串，是我把判据挂到了另一个函数上）。
    const CLAUDE_FLATTEN_JOIN: &str = concat!(
        r#"{"type":"assistant","timestamp":"2025-12-01T10:00:00Z","message":{"role":"assistant","model":"claude-opus-5","content":[{"type":"tool_use","id":"toolu_fl","name":"Read","input":{"path":"/x"}}]}}"#,
        "\n",
        r#"{"type":"user","timestamp":"2025-12-01T10:00:01Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_fl","content":[{"type":"text","text":"first"},{"type":"text","text":""},{"type":"image","source":{"data":"zz"}},{"type":"text","text":"second"}]}]}}"#,
        "\n",
    );

    fn project_claude_bytes(tag: &str, raw: &str) -> Box<NormalizedConversation> {
        let root = scratch(tag);
        let bytes = raw.as_bytes();
        let input = claude_source(CLAUDE_PATH, bytes);
        match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Projected(conv) => conv,
            other => panic!("期望 Projected，实得 {other:?}"),
        }
    }

    #[test]
    fn contract_p4_tool_call_content_is_compact_json_in_source_key_order() {
        let conv = project_claude_bytes("b11-p4-keyorder", CLAUDE_TOOL_ARGS_KEY_ORDER);
        let tool_calls: Vec<&_> = conv
            .messages
            .iter()
            .filter(|m| m.role == "tool_call")
            .collect();
        assert_eq!(
            tool_calls.len(),
            1,
            "前置断言：样本必须恰好产一条 tool_call，否则下面断的可能是别的消息"
        );
        assert_eq!(
            tool_calls[0].content, r#"Grep({"zebra":1,"alpha":2})"#,
            "content 必须是 `name(compact JSON)`，且 object 键序 = **源文本出现顺序**。\
             读到 `{{\"alpha\":2,\"zebra\":1}}` 说明 `serde_json` 的 `preserve_order` \
             feature 在本次构建里没生效 —— 那会让全部 content 字节静默改变，\
             此前算出的 content hash 全部作废（§B.1.1 明写该规则是 feature 的函数）"
        );
    }

    #[test]
    fn contract_p4_null_args_render_as_the_bare_name() {
        let conv = project_claude_bytes("b11-p4-nullargs", CLAUDE_TOOL_NULL_ARGS);
        let tool_calls: Vec<&_> = conv
            .messages
            .iter()
            .filter(|m| m.role == "tool_call")
            .collect();
        assert_eq!(tool_calls.len(), 1, "前置断言：恰一条 tool_call");
        assert_eq!(
            tool_calls[0].content, "Bash",
            "`args` 为 JSON `null` 时必须渲染成 bare name（与「无 args」同形）；\
             渲染成 `Bash(null)` 即违反 §B.1.1"
        );
    }

    #[test]
    fn contract_p4_flatten_content_joins_with_a_single_newline_and_drops_empties() {
        let conv = project_claude_bytes("b11-p4-flatten", CLAUDE_FLATTEN_JOIN);
        let results: Vec<&_> = conv
            .messages
            .iter()
            .filter(|m| m.role == "tool_result")
            .collect();
        assert_eq!(results.len(), 1, "前置断言：恰一条 tool_result 消息");
        assert_eq!(
            results[0].content, "first\nsecond",
            "空串片段与非白名单块（`image`）必须被丢弃，其余用**单个** `\\n` 连接；\
             读到 `first\\n\\nsecond` 说明空片段没丢，读到 `first second` 说明连接符不对"
        );
    }

    #[test]
    fn contract_codex_developer_role_produces_no_message() {
        let conv = project_codex("b11-codex-dev", CODEX_ALL_BRANCHES.as_bytes());
        let contents: Vec<&str> = conv.messages.iter().map(|m| m.content.as_str()).collect();
        assert!(
            !contents.iter().any(|c| c.contains("you are codex")),
            "§B.3.1：developer 整条 drop，实得 {contents:?}"
        );
        // 先证探针有分辨力：同一份样本里**其他**分支确实产出了消息。
        assert!(
            contents.iter().any(|c| c.contains("list files")),
            "样本没产出任何消息，本断言就分不出「被 drop」与「压根没解析」"
        );
    }

    /// §B.3.1/§B.3.2：`raw_role` 是**分支名**而不是 canonical role —— 三家里只有 codex 这样，
    /// 把它「顺手统一成 canonical role」会让 W2 侧再也认不出这条消息出自哪个分支。
    #[test]
    fn contract_codex_raw_role_records_the_branch_not_the_canonical_role() {
        let conv = project_codex("b11-codex-rawrole", CODEX_ALL_BRANCHES.as_bytes());
        let pairs: Vec<(&str, &str)> = conv
            .messages
            .iter()
            .map(|m| {
                (
                    m.role.as_str(),
                    m.extra
                        .get("raw_role")
                        .and_then(|v| v.as_str())
                        .unwrap_or("<missing>"),
                )
            })
            .collect();

        for (role, raw) in &pairs {
            assert_ne!(
                *raw, "<missing>",
                "P3：codex 侧同样每条都要有 raw_role：{pairs:?}"
            );
            match *role {
                "tool_call" => assert_eq!(
                    *raw, "function_call",
                    "§B.3.1：`function_call` 的 raw_role 是分支名，不是 canonical role"
                ),
                "tool_result" => assert_eq!(*raw, "function_call_output"),
                "reasoning" => assert_eq!(*raw, "reasoning"),
                _ => {}
            }
        }
        assert!(
            pairs.iter().any(|(r, _)| *r == "tool_call"),
            "样本应覆盖 function_call 分支：{pairs:?}"
        );
    }

    /// §B.3.2 第一行：`event_msg` 的 `agent_message` **最先判、直接 continue**。
    ///
    /// 它与 `response_item` 的可见回复是同一条内容的两次出现；不去重就会让每条 assistant
    /// 回复在 canonical 语料里出现两遍。
    #[test]
    fn contract_codex_event_msg_agent_message_is_deduplicated() {
        let conv = project_codex("b11-codex-dedup", CODEX_ALL_BRANCHES.as_bytes());
        let dup_hits = conv
            .messages
            .iter()
            .filter(|m| m.content.contains("dup of response_item"))
            .count();
        assert_eq!(
            dup_hits, 0,
            "§B.3.2：event_msg 的 agent_message 必须被丢弃（与 response_item 重复）"
        );
    }

    /// §B.3.3：`turn_context.model` 是**滚动值** —— 它之后的 assistant / reasoning /
    /// tool_call 的 author 全靠它；`session_meta.cwd` 成为 workspace。
    #[test]
    fn contract_codex_rolling_model_and_session_cwd_become_author_and_workspace() {
        let conv = project_codex("b11-codex-rolling", CODEX_ALL_BRANCHES.as_bytes());
        assert_eq!(
            conv.workspace.as_deref(),
            Some(std::path::Path::new("/w/repo")),
            "§B.3.3：session_meta 的 cwd 成为 workspace"
        );
        for m in conv
            .messages
            .iter()
            .filter(|m| matches!(m.role.as_str(), "reasoning" | "tool_call"))
        {
            assert_eq!(
                m.author.as_deref(),
                Some("gpt-5.5"),
                "§B.3.3：turn_context 之后的消息 author 取滚动的 current_model（idx={}）",
                m.idx
            );
        }
        // user 侧不得被伪造成模型。
        for m in conv.messages.iter().filter(|m| m.role == "user") {
            assert!(
                m.author.is_none(),
                "§B.3.1：user 的 author 为 None，不伪造模型"
            );
        }
    }

    /// §B.3.1 里最锋利的一条不对称：**`function_call` 的 id 回退 `call_id → id`，
    /// 而 `function_call_output` 的配对 id 只认 `call_id`、不回退 `id`。**
    ///
    /// 附录点名这条是因为它看起来像笔误、极易被「顺手对齐成一样」。真对齐了会发生什么：
    /// 一条只带 `id` 的 output 会被配上一个**它并不对应**的 tool_call，于是 pairing 从
    /// 「诚实的 unpaired」变成「错误的已配对」——后者在任何下游都不会再报警。
    #[test]
    fn contract_codex_tool_output_pairing_does_not_fall_back_to_id() {
        let bytes = concat!(
            r#"{"timestamp":"2026-01-01T00:00:00Z","type":"turn_context","payload":{"model":"gpt-5.5"}}"#,
            "\n",
            r#"{"timestamp":"2026-01-01T00:00:01Z","type":"response_item","payload":{"type":"function_call","name":"shell","id":"only_id_1","arguments":"{}"}}"#,
            "\n",
            r#"{"timestamp":"2026-01-01T00:00:02Z","type":"response_item","payload":{"type":"function_call_output","id":"only_id_1","output":"done"}}"#,
            "\n",
        )
        .as_bytes();
        let conv = project_codex("b11-codex-pairing", bytes);

        let call = conv
            .messages
            .iter()
            .find(|m| m.role == "tool_call")
            .expect("样本含一个 function_call");
        assert_eq!(
            call.extra.get("tool_call_id").and_then(|v| v.as_str()),
            Some("only_id_1"),
            "§B.3.1：function_call 的 id 回退到 `id`（`call_id` 缺失时）"
        );

        let output = conv
            .messages
            .iter()
            .find(|m| m.role == "tool_result")
            .expect("样本含一个 function_call_output");
        assert!(
            output.extra.get("tool_call_id").is_none(),
            "§B.3.1：function_call_output **只认 `call_id`**，不得回退到 `id`；\
             回退会把「诚实的 unpaired」变成「错误的已配对」，实得 {}",
            output.extra
        );
        assert!(
            output.extra.get("unpaired").is_some(),
            "配不上时必须显式标 unpaired（P8 的异或另一侧），实得 {}",
            output.extra
        );
    }

    // ---- §B.4 OpenClaw 家族的契约批 ----------------------------------------
    //
    // 附录点名了「与 Claude 的三处对照差异」，那三处正是逐字段验收时最容易写错的地方：
    // ① Claude 的 ToolCall/ToolResult/Thinking 各有一道 `role != …` guard，**OpenClaw 三者
    //    都没有**；② Claude 的 tool_call author 沿用 envelope 算出的 author（只在 assistant
    //    时非空），**OpenClaw 直接用 `message.model`**，user envelope 里的 toolCall 也带
    //    author；③ `type=session` 的 timestamp 是**赋值**而非取 min。
    //
    // 另外 OpenClaw 是三家里历史最脏的一个：上位 §16 那条 thinking 缺陷就出在它身上
    // （只认 `text`，而真实语料 3713 个 thinking 块里带 `text` 的是 0 个），已在 pin
    // `068f423b` 修掉。故本批把「thinking 真的产出 reasoning」当成必须成立的判据。

    /// **会话文件必须直接躺在一个名叫 `sessions` 的目录下**，且整条路径含 `openclaw`：
    /// `session_root_from_candidate` 要求候选目录的 `file_name()` 恰为 `sessions`（或其下有
    /// `sessions/` 子目录），`looks_like_openclaw_storage` 再要求路径同时含 `openclaw` 与
    /// `sessions`。把文件放进 `sessions/<日期>/` 这种多一层的形状会让 root 集为空、
    /// **扫出 0 个会话**（本批第一版就是这么红的）。这是「路径形状进投影定义域」（R-E-34）
    /// 的第五处机械依据。
    const OPENCLAW_PATH: &str = "/home/u/.openclaw/agents/main/sessions/sess-1.jsonl";

    const OPENCLAW_ALL_BRANCHES: &str = concat!(
        r#"{"type":"session","timestamp":"2026-01-01T00:00:00Z","cwd":"/w/oc"}"#,
        "\n",
        r#"{"type":"message","timestamp":"2026-01-01T00:00:01Z","message":{"role":"assistant","model":"oc-model-1","content":[{"type":"text","text":"working"},{"type":"thinking","thinking":"deliberating"},{"type":"toolCall","name":"bash","id":"tc_1","arguments":{"cmd":"ls"}}]}}"#,
        "\n",
        // user envelope 里同样放 toolCall 与 thinking —— Claude 侧这两块会被 role guard 跳过，
        // OpenClaw 侧必须产出。这一行就是对照差异 ① 与 ② 的载体。
        r#"{"type":"message","timestamp":"2026-01-01T00:00:02Z","message":{"role":"user","model":"oc-model-1","content":[{"type":"toolCall","name":"grep","id":"tc_2","arguments":{"q":"x"}},{"type":"thinking","thinking":"user side"}]}}"#,
        "\n",
        r#"{"type":"message","timestamp":"2026-01-01T00:00:03Z","message":{"role":"toolResult","id":"tc_1","content":[{"type":"toolResult","id":"tc_1","text":"a.txt"}]}}"#,
        "\n",
        // role 缺失：上位 §5.4「缺 role 不再默认成 assistant」，整条 continue。
        r#"{"type":"message","timestamp":"2026-01-01T00:00:04Z","message":{"model":"oc-model-1","content":[{"type":"text","text":"roleless line"}]}}"#,
        "\n",
        // 白名单丢弃项之一。
        r#"{"type":"model_change","timestamp":"2026-01-01T00:00:05Z","model":"oc-model-2"}"#,
        "\n",
        r#"{"type":"compaction","timestamp":"2026-01-01T00:00:06Z","summary":"rolled up"}"#,
        "\n",
    );

    fn project_openclaw(tag: &str, bytes: &[u8]) -> Box<NormalizedConversation> {
        let root = scratch(tag);
        let input = SealedSource {
            agent: Origin::Openclaw,
            canonical_original_path: OPENCLAW_PATH,
            source_size_bytes: bytes.len() as u64,
            blob: bytes,
        };
        match project_sealed_source(&root, &input, &test_provenance()).unwrap() {
            SealedProjection::Projected(conv) => conv,
            other => panic!("期望 Projected，实得 {other:?}"),
        }
    }

    /// 对照差异 ①：OpenClaw 的 ToolCall / Thinking **没有 role guard** ——
    /// user envelope 里的这两块同样产消息。照 Claude 的写法加 guard 会静默丢掉它们。

    // =======================================================================
    // §B.11 P9 · reasoning 的**三种空值语义**（§B.7）各造一个样本
    //
    // §B.7 明写这三种语义各不相同，「这是 §10.2 逐字段验收里必须各造一个样本的三个点」：
    //   1. Claude `thinking` 块           → **保留**（无 trim 判空）
    //   2. Codex `response_item/reasoning` → summary 空且**无** `encrypted_content` → 跳过；
    //                                        **encrypted-only → 保留空结构消息**
    //   3. Codex `event_msg/agent_reasoning` → **trim 后**为空 → 跳过
    //
    // 第 1 种已由 `contract_empty_thinking_is_kept_while_empty_prose_is_dropped` 覆盖；
    // 本组补齐 codex 侧的两支三态。仍是契约验证，不是红转绿。
    // =======================================================================

    /// 三条 reasoning，逐条对应 §B.7 的一种空值形态；末尾放一条普通 user 消息，
    /// 让「整份样本产了几条消息」这件事有个稳定的锚。
    const CODEX_REASONING_EMPTY_FORMS: &str = concat!(
        r#"{"timestamp":"2026-01-01T00:00:00Z","type":"session_meta","payload":{"cwd":"/w/repo"}}"#,
        "\n",
        r#"{"timestamp":"2026-01-01T00:00:01Z","type":"turn_context","payload":{"model":"gpt-5.5"}}"#,
        "\n",
        // (a) response_item/reasoning：summary 空、**无** encrypted_content → 跳过
        r#"{"timestamp":"2026-01-01T00:00:02Z","type":"response_item","payload":{"type":"reasoning","summary":[]}}"#,
        "\n",
        // (b) response_item/reasoning：summary 空、**有** encrypted_content → 保留空结构消息
        r#"{"timestamp":"2026-01-01T00:00:03Z","type":"response_item","payload":{"type":"reasoning","summary":[],"encrypted_content":"BASE64BLOB"}}"#,
        "\n",
        // (c) event_msg/agent_reasoning：text 只有空白 → trim 后为空 → 跳过
        r#"{"timestamp":"2026-01-01T00:00:04Z","type":"event_msg","payload":{"type":"agent_reasoning","text":"   "}}"#,
        "\n",
        r#"{"timestamp":"2026-01-01T00:00:05Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"锚"}]}}"#,
        "\n",
    );

    #[test]
    fn contract_p9_codex_reasoning_three_empty_forms_behave_differently() {
        let conv = project_codex("b11-p9", CODEX_REASONING_EMPTY_FORMS.as_bytes());
        let reasoning: Vec<&_> = conv
            .messages
            .iter()
            .filter(|m| m.role == "reasoning")
            .collect();

        // 三条 reasoning 形态里只有 (b) 该活下来 —— 若三种语义被实现成同一种，
        // 这里要么是 0 条（全跳过）要么是 3 条（全保留），两种都会红。
        assert_eq!(
            reasoning.len(),
            1,
            "§B.7 的三种空值语义必须**各不相同**：只有 encrypted-only 那条保留。\
             实得 {} 条：{:?}",
            reasoning.len(),
            reasoning.iter().map(|m| &m.content).collect::<Vec<_>>()
        );
        assert_eq!(
            reasoning[0].content, "",
            "encrypted-only 保留的是一条**空结构消息**：内容为空但消息在，\
             它承载的是「这一轮有加密推理」这个事实"
        );

        // 分辨力前置：整份样本确实被解析出来了（否则「只有 1 条 reasoning」可能是
        // 因为整份都没扫出来）。
        let users: Vec<&_> = conv.messages.iter().filter(|m| m.role == "user").collect();
        assert_eq!(
            users.len(),
            1,
            "前置断言：锚消息必须在，否则本用例可能是在一份空投影上做断言"
        );
    }

    #[test]
    fn contract_openclaw_tool_call_and_thinking_have_no_role_guard() {
        let conv = project_openclaw("b11-oc-noguard", OPENCLAW_ALL_BRANCHES.as_bytes());
        let has = |content: &str| conv.messages.iter().any(|m| m.content.contains(content));

        // 分辨力前置：assistant envelope 侧的块确实产出了，说明解析本身没坏。
        assert!(has("working"), "样本没产出任何消息，后面的断言分不出成因");

        let user_tool_call = conv
            .messages
            .iter()
            .find(|m| m.role == "tool_call" && m.content.contains("grep"));
        assert!(
            user_tool_call.is_some(),
            "对照差异 ①：user envelope 里的 toolCall 必须产消息（OpenClaw 无 role guard）"
        );
        assert!(
            has("user side"),
            "对照差异 ①：user envelope 里的 thinking 必须产消息（OpenClaw 无 role guard）"
        );
    }

    /// 对照差异 ②：tool_call 的 author 直接取 `message.model`，**不看 envelope 是 user
    /// 还是 assistant**。Claude 侧 user envelope 的 tool_call author 会是空。
    #[test]
    fn contract_openclaw_tool_call_author_comes_from_message_model_even_in_user_envelope() {
        let conv = project_openclaw("b11-oc-author", OPENCLAW_ALL_BRANCHES.as_bytes());
        let user_call = conv
            .messages
            .iter()
            .find(|m| m.role == "tool_call" && m.content.contains("grep"))
            .expect("user envelope 里的 toolCall");
        assert_eq!(
            user_call.author.as_deref(),
            Some("oc-model-1"),
            "对照差异 ②：OpenClaw 的 tool_call author 取 `message.model`，与 envelope role 无关"
        );
    }

    /// 上位 §16 那条历史缺陷的守卫：**thinking 必须真的产出 `reasoning`**。
    ///
    /// 该缺陷（只认 `text`、而真实语料里带 `text` 的 thinking 块是 0 个）已在 pin
    /// `068f423b` 修掉；本条钉住它不再回归。**若它红了，先看分辨力前置**——同一样本里
    /// 别的分支若也没产出，那是样本问题；别的分支产出了而只有 reasoning 没有，那是回归。
    #[test]
    fn contract_openclaw_thinking_block_yields_reasoning() {
        let conv = project_openclaw("b11-oc-thinking", OPENCLAW_ALL_BRANCHES.as_bytes());
        let roles: Vec<&str> = conv.messages.iter().map(|m| m.role.as_str()).collect();
        assert!(
            roles.contains(&"assistant") || roles.contains(&"tool_call"),
            "分辨力前置：样本别的分支也没产出，说明是样本问题不是 reasoning 回归：{roles:?}"
        );
        // **断言到具体内容，不止「存在某个 reasoning」。** 样本里有两个 thinking 块
        // （assistant 与 user envelope 各一），只断言 role 存在时，改坏其中一个另一个仍能
        // 让断言通过 —— 扰动对照 FX9 实测正是这样溜过去的，故收紧到逐块。
        let reasoning_bodies: Vec<&str> = conv
            .messages
            .iter()
            .filter(|m| m.role == "reasoning")
            .map(|m| m.content.as_str())
            .collect();
        for expected in ["deliberating", "user side"] {
            assert!(
                reasoning_bodies.iter().any(|b| b.contains(expected)),
                "OpenClaw 的 thinking 块必须逐块产出 reasoning（上位 §16 的历史缺陷已在 pin \
                 修掉）：缺 `{expected}`，实得 {reasoning_bodies:?}"
            );
        }
        let _ = &roles;
    }

    /// 上位 §5.4：`message.role` **缺失或不在白名单**时整条 `continue` ——
    /// 不再默认成 assistant。默认化会把一整类来源不明的内容混进 assistant 语料。
    #[test]
    fn contract_openclaw_missing_role_drops_the_whole_line() {
        let conv = project_openclaw("b11-oc-norole", OPENCLAW_ALL_BRANCHES.as_bytes());
        assert!(
            !conv
                .messages
                .iter()
                .any(|m| m.content.contains("roleless line")),
            "上位 §5.4：缺 role 的行整条 drop，不得默认成 assistant"
        );
        // 白名单丢弃项同样不该留下痕迹。
        assert!(
            !conv
                .messages
                .iter()
                .any(|m| m.content.contains("oc-model-2")),
            "`model_change` 属白名单丢弃项"
        );
    }

    /// `type=compaction` 且 `summary` 非空白 → `assistant` 消息、`raw_role = "compaction"`。
    /// 这是三家里唯一一个 canonical role 与 raw_role 完全不同源的分支。
    #[test]
    fn contract_openclaw_compaction_becomes_assistant_with_its_own_raw_role() {
        let conv = project_openclaw("b11-oc-compaction", OPENCLAW_ALL_BRANCHES.as_bytes());
        let compaction = conv
            .messages
            .iter()
            .find(|m| m.content.contains("rolled up"))
            .expect("compaction 行应产出一条消息");
        assert_eq!(compaction.role, "assistant");
        assert_eq!(
            compaction.extra.get("raw_role").and_then(|v| v.as_str()),
            Some("compaction")
        );
    }

    /// §B.4 末条 + P12/P3 在 OpenClaw 侧的复核：workspace 来自 `type=session` 的 `cwd`；
    /// 每条 retained 消息仍有 string 型 `raw_role`。
    #[test]
    fn contract_openclaw_session_cwd_and_raw_role_hold_across_the_family() {
        let conv = project_openclaw("b11-oc-session", OPENCLAW_ALL_BRANCHES.as_bytes());
        assert_eq!(
            conv.workspace.as_deref(),
            Some(std::path::Path::new("/w/oc")),
            "§B.4：`type=session` 的 `cwd` 成为 workspace"
        );
        for m in &conv.messages {
            let rr = m.extra.get("raw_role");
            assert!(
                rr.and_then(|v| v.as_str()).is_some(),
                "P3 在 OpenClaw 侧同样无例外：idx={} 缺 string 型 raw_role，extra={}",
                m.idx,
                m.extra
            );
        }
    }

    /// §B.11 P14 · compact 面：**OpenClaw 未被 compact**。
    ///
    /// `should_compact_connector_extra` 的最后一行是
    /// `connector_name == "codex" || conv.agent_slug == "codex"` —— 门只对 codex 开。
    /// 本用例把同一份 OpenClaw 语料分别按「阈值以下」与「阈值以上」的封存大小投影，
    /// 断言两侧 extra 完全一样。
    ///
    /// **对照物**：codex 侧的 `..._reads_the_sealed_size_not_the_filesystem` 与摘要
    /// 不变性用例已经证明「阈值以上时 extra 确实会缩水」。所以这里的「两侧相等」
    /// 不是因为 compact 对谁都不生效，而是因为它对 OpenClaw 不生效。
    ///
    /// 断言对象刻意选**非白名单键**（`payload`）：compact 只保 `cass` / `model` /
    /// `attachments` 那几样，`payload` 一旦被 compact 就会消失。P14 同时要求
    /// 「断言不依赖 `payload` / `response` 存活」—— 那句话约束的是 **codex 侧**的
    /// 断言（compact 之后它们本就该没了）；OpenClaw 侧恰恰相反，它们必须还在。
    #[test]
    fn contract_p14_openclaw_extras_survive_a_size_above_the_codex_compact_threshold() {
        const THRESHOLD: u64 = 16 * 1024 * 1024;
        let bytes = OPENCLAW_ALL_BRANCHES.as_bytes();
        let root = scratch("b11-p14-oc");
        let input = SealedSource {
            agent: Origin::Openclaw,
            canonical_original_path: OPENCLAW_PATH,
            source_size_bytes: bytes.len() as u64,
            blob: bytes,
        };
        // 物化一次，之后只改「封存大小」这一个入参 —— 与 codex 侧那组用例同法，
        // 免得 `SealedSizeMismatch` 把用例挡在门外。
        let materialized = materialize_sealed_blob(&root, &input).unwrap();

        let extras_at = |sealed: u64| -> Vec<serde_json::Value> {
            let sized = SealedSource {
                source_size_bytes: sealed,
                ..input
            };
            match project_from_materialized(&materialized, &sized, &test_provenance()).unwrap() {
                SealedProjection::Projected(conv) => {
                    conv.messages.iter().map(|m| m.extra.clone()).collect()
                }
                other => panic!("期望 Projected，实得 {other:?}"),
            }
        };

        let below = extras_at(1024);
        let above = extras_at(THRESHOLD);

        // 分辨力前置：样本里必须真有**非白名单**键，否则「两侧相等」是空转 ——
        // 一份只含 `cass` 的 extra 在 compact 前后本来就一样。
        let non_allowlist_keys = below
            .iter()
            .filter_map(serde_json::Value::as_object)
            .flat_map(|o| o.keys())
            .filter(|k| !matches!(k.as_str(), "cass" | "model" | "attachments"))
            .count();
        assert!(
            non_allowlist_keys > 0,
            "分辨力前置断言：样本的 extra 必须含非白名单键，否则本用例证明不了「没被 compact」"
        );

        assert_eq!(
            below, above,
            "OpenClaw 的 extra 在跨过 codex 的 compact 阈值之后必须**逐字不变** —— \
             compact 门只对 codex 开（`should_compact_connector_extra` 末行），\
             对 OpenClaw 生效就是把另一家的语料按 codex 的口径削了"
        );
    }

    #[test]
    fn desktop_sidecar_detection_matches_components_not_substrings() {
        assert!(path_is_claude_desktop_sidecar(Path::new(
            "/home/u/claude-code-sessions/ws/x.jsonl"
        )));
        assert!(path_is_claude_desktop_sidecar(Path::new(
            "/home/u/local-agent-mode-sessions/x.jsonl"
        )));
        // 子串命中但分量不等 —— 必须**不**命中，否则一个正常会话会被误判成 sidecar 而 HOLD。
        assert!(!path_is_claude_desktop_sidecar(Path::new(
            "/home/u/claude-code-sessions-backup/ws/x.jsonl"
        )));
        assert!(!path_is_claude_desktop_sidecar(Path::new(
            "/home/u/.claude/projects/ws/x.jsonl"
        )));
    }
}

// ---------------------------------------------------------------------------
// E5 Phase 3.0 · 封存 blob 的读取接线
// ---------------------------------------------------------------------------

/// 从 mirror 读一份封存 blob 的三分结论。
///
/// **三分而不是 `Result` 两分，是因为中间那一档的处置完全不同**：manifest 指到的 blob
/// 不在 mirror 里，说明**这份候选不合格**（封存不完整 / 被裁剪过），要按输入损坏类
/// 产 HOLD 交人；而校验和不符、路径不安全、manifest 未 verified 这些是**读不动**，
/// 归另一支。把两者并成一个 `Err(String)` 会让调用方只能按错误文本分流 —— 那正是
/// 本项目一路在拒绝的判据形态。
#[derive(Debug)]
// ⚠ 与 `sqlite.rs` 的 replace 函数同一记账：下面三个符号在非测试构建里还没有调用方，
// 故显式 `allow(dead_code)`。**staged landing 的记账，不是把死代码放行。**
//
// **移除义务已从 E6 改挂 E8**（本棒实测更正）：E6 落了编排之后这三个符号**仍然**不可达
// —— dead-code 从可达根传递判定，而编排自己也还没有调用方。真正的根是 E8 把
// `mirror-restore --apply` 的 CLI 接上那一刻。
#[allow(dead_code)]
pub(crate) enum SealedBlobOutcome {
    /// 读到了，且已通过 doctor 侧的强校验（blake3 + 长度）。
    Loaded(Vec<u8>),
    /// manifest 在、它指的 blob 不在。→ `manifest-reference-missing`。
    ReferenceMissing,
    /// 其余读取/校验失败。`detail` 原样保留 doctor 侧的措辞，不二次归类。
    Unreadable { detail: String },
}

/// 扫出 `data_dir` 下 raw mirror 的全部 manifest 报告（含强校验结论）。
///
/// 复用 doctor 侧的收集器而不是自己走一遍目录：manifest 的磁盘格式、校验口径、
/// 「什么叫 verified」这三件事只能有一个定义。
#[allow(dead_code)]
pub(crate) fn collect_sealed_manifest_reports(
    data_dir: &Path,
) -> Vec<crate::DoctorRawMirrorManifestReport> {
    crate::collect_doctor_raw_mirror_report(data_dir).manifests
}

/// 按一份 manifest 报告读回封存 blob。
///
/// blob 的定位、路径安全检查与强校验全部复用
/// `doctor_candidate_read_verified_raw_mirror_blob`（plan Task E5 Step 2 点名复用的那个）。
/// 本函数只做一件它做不了的事：**把「blob 不在」从它那个扁平的 `Err(String)` 里分出来**。
/// 分法不是匹配错误文本，而是读 doctor 校验阶段已经定好的 `blob_checksum_status`
/// —— 缺 blob 在那一层就是一个具名状态（`Missing` + `status = "missing_blob"`）。
#[allow(dead_code)]
pub(crate) fn read_sealed_blob(
    data_dir: &Path,
    manifest: &crate::DoctorRawMirrorManifestReport,
) -> SealedBlobOutcome {
    if manifest.blob_checksum_status == crate::DoctorArtifactChecksumStatus::Missing {
        return SealedBlobOutcome::ReferenceMissing;
    }
    match crate::doctor_candidate_read_verified_raw_mirror_blob(data_dir, manifest) {
        Ok(bytes) => SealedBlobOutcome::Loaded(bytes),
        Err(detail) => SealedBlobOutcome::Unreadable { detail },
    }
}

/// `manifest-reference-missing` 的发射点（第二棒交接件 §2.3 挂在 E5 名下的那一条）。
///
/// E4 侧只定义了这个 reason，**零发射**；发射点在这里，因为只有读 blob 的这一步才
/// 知道「manifest 指到的内容不在了」。`versions` 由调用方给出（可能为空 —— 读不到
/// blob 时本来就摘不出版本摘要），`class` 由 reason 静态决定，调用方无从指定。
pub fn hold_for_manifest_reference_missing(
    identity: RestoreIdentity,
    versions: Vec<VersionSummary>,
) -> HoldRecord {
    HoldRecord {
        identity,
        reason: HoldReason::ManifestReferenceMissing,
        evidence: HoldEvidence::Versions { versions },
        // 这条裁定读的是「`blob_blake3` 指向的内容还在不在」，以及用于定位身份的
        // `original_path`。**清单是静态的，不自由构造**（R-E-27 第 3 条）。
        consumed_manifest_fields: vec![
            manifest_fields::BLOB_BLAKE3,
            manifest_fields::ORIGINAL_PATH,
        ],
    }
}

// ===========================================================================
// E5 Phase 3.0 · 封存 blob 的读取接线与 `manifest-reference-missing` 的真实发射点
//
// 第二棒交接件 §2.3 明写：「输入损坏类在 E4 侧零发射，`manifest-reference-missing`
// 归 E5，你负责给它真实发射点。」本组测试锁的就是那个发射点：**blob 不在 mirror 里
// 是「这份候选不合格」，不是「这台机器出毛病了」**，所以它产 HOLD 而不是 Err 冒泡。
// ===========================================================================
#[cfg(test)]
mod e5_p30_blob_read_tests {
    use super::*;
    use frankensqlite::compat::{
        ConnectionExt, OptionalExtension, ParamValue, RowExt, TransactionExt,
    };
    use serial_test::serial;
    use tempfile::TempDir;

    /// 用**真的** `raw_mirror::capture_source_file` 造 mirror，不手写 manifest JSON。
    /// 手写等于对 manifest 磁盘格式造第二定义 —— 这正是本项目一路在拒绝的东西，
    /// 而且格式一旦漂移，手写的 fixture 会「一直绿着」。
    fn capture(data_dir: &Path, source: &Path) -> crate::raw_mirror::RawMirrorCaptureRecord {
        crate::raw_mirror::capture_source_file(crate::raw_mirror::RawMirrorCaptureInput {
            data_dir,
            provider: "codex",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: source,
            db_links: &[],
        })
        .expect("capture source into raw mirror")
    }

    fn write_session(root: &Path, name: &str, session_id: &str) -> std::path::PathBuf {
        // 合成根（裁定 (c)）：前缀刻意不像真实家目录，但**进定义域的形状片段一个不少**
        // —— `.codex/sessions/<日期分段>/rollout-*.jsonl`，因为 codex 的 whole-file 判别
        // 靠文件名前缀与扩展名，`external_id` 推导又要往上找 `sessions` 根。
        let dir = root.join(".codex").join("sessions").join("2026").join("08");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        // 内容必须逐份不同：blob 是**内容寻址**的，两份字节相同的源会共用同一个 blob，
        // 于是「删掉其中一份的 blob」实际上把两条身份的 blob 一起删了。
        // 只放 `session_meta` 会扫出 0 个会话（codex 的消息来自 `response_item`），
        // 于是投影会以 `UnexpectedConversationCount { count: 0 }` 硬失败 —— 本棒实测撞过。
        std::fs::write(
            &path,
            format!(
                "{{\"timestamp\":\"2026-08-18T00:00:00.000Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{session_id}\",\"cwd\":\"/fixtures/ws\"}}}}\n\
                 {{\"timestamp\":\"2026-08-18T00:00:01.000Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"user\",\"content\":[{{\"type\":\"input_text\",\"text\":\"{session_id} 的第一条消息\"}}]}}}}\n\
                 {{\"timestamp\":\"2026-08-18T00:00:02.000Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"user\",\"content\":[{{\"type\":\"input_text\",\"text\":\"{session_id} 的第二条消息\"}}]}}}}\n\
                 {{\"timestamp\":\"2026-08-18T00:00:03.000Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"user\",\"content\":[{{\"type\":\"input_text\",\"text\":\"{session_id} 的第三条消息\"}}]}}}}\n"
            ),
        )
        .unwrap();
        path
    }

    fn manifest_report_for<'a>(
        reports: &'a [crate::DoctorRawMirrorManifestReport],
        manifest_id: &str,
    ) -> &'a crate::DoctorRawMirrorManifestReport {
        reports
            .iter()
            .find(|r| r.manifest_id == manifest_id)
            .unwrap_or_else(|| panic!("no doctor report for manifest {manifest_id}"))
    }

    #[test]
    fn e5_p30_reads_a_present_blob_and_reports_a_missing_one_as_reference_missing() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let live = tmp.path().join("live");

        let kept = capture(
            &data_dir,
            &write_session(&live, "rollout-kept.jsonl", "kept"),
        );
        let dropped = capture(
            &data_dir,
            &write_session(&live, "rollout-dropped.jsonl", "dropped"),
        );
        assert_ne!(
            kept.manifest_id, dropped.manifest_id,
            "前置断言：两份 manifest 必须是不同的两条身份"
        );
        // ⚠ 承重的前置断言是这一条，不是上面那条。blob 内容寻址：两份字节相同的源
        // **共用同一个 blob**，manifest_id 不同也没用 —— 删一份就把两条一起删了。
        // 本棒实测：第一版只断言 manifest_id 不同，结果「blob 还在」的那份也被判
        // ReferenceMissing，因为两份 fixture 内容一模一样。
        assert_ne!(
            kept.blob_relative_path, dropped.blob_relative_path,
            "前置断言：两条身份必须落在不同的 blob 上，否则删一份等于删两份"
        );

        // 删掉其中一份的 blob（manifest 留着）—— 这就是「mirror 里 manifest 指到的
        // 内容不在了」这个形态。
        // 不复刻路径规则：用 doctor 侧那个**唯一**的根函数定位（读 blob 的那条链
        // 用的也是它），再拼 manifest 自己记的相对路径。
        let dropped_blob =
            crate::doctor_raw_mirror_root(&data_dir).join(&dropped.blob_relative_path);
        assert!(dropped_blob.is_file(), "前置断言：删之前那份 blob 确实在");
        std::fs::remove_file(&dropped_blob).unwrap();

        let reports = collect_sealed_manifest_reports(&data_dir);
        let kept_report = manifest_report_for(&reports, &kept.manifest_id);
        let dropped_report = manifest_report_for(&reports, &dropped.manifest_id);

        match read_sealed_blob(&data_dir, kept_report) {
            SealedBlobOutcome::Loaded(bytes) => {
                assert_eq!(
                    bytes.len() as u64,
                    kept.blob_size_bytes,
                    "读回的字节数必须等于 manifest 记的 blob_size_bytes"
                );
            }
            other => panic!("blob 在的那份应当读得回来，实得 {other:?}"),
        }

        assert!(
            matches!(
                read_sealed_blob(&data_dir, dropped_report),
                SealedBlobOutcome::ReferenceMissing
            ),
            "blob 被删的那份必须判 ReferenceMissing —— 判成 Unreadable 会把\
             「候选不合格」误报成「本机读不动」，两者的处置完全不同"
        );
    }

    #[test]
    fn e5_p30_emits_a_manifest_reference_missing_hold_in_the_input_corruption_class() {
        let identity = RestoreIdentity {
            origin: OriginNamespace {
                agent: Origin::Codex,
                source_id: "local".to_owned(),
                origin_host: "fixture-host".to_owned(),
            },
            canonical_path: "/fixtures/.codex/sessions/2026/08/rollout-x.jsonl".to_owned(),
        };
        let hold = hold_for_manifest_reference_missing(identity.clone(), Vec::new());

        assert_eq!(hold.reason, HoldReason::ManifestReferenceMissing);
        assert_eq!(hold.identity, identity);
        assert_eq!(
            hold.class(),
            HoldReason::ManifestReferenceMissing.class(),
            "class 由 reason 静态决定，调用方无从指定"
        );
        assert!(
            hold.consumed_manifest_fields
                .contains(&manifest_fields::BLOB_BLAKE3),
            "provenance 必须记下这条裁定读了 blob_blake3 —— 缺 blob 的判定正是靠它\
             所指向的内容不在了"
        );
    }

    // -----------------------------------------------------------------------
    // Step 3 ·「839 缩微版」隔离小库演练
    //
    // plan Task E5 Step 3 原文：「mirror 有、live 无 → restore；删掉一份 blob → 必须报出」。
    //
    // **写入口的分派按裁定 R-E-44**：库里没有这条会话 = 全新会话，走基线
    // `insert_conversations_batched`；E5 新增的 replace 专用函数只服务「真前缀替换」
    // 那一支（它的五条硬语义全都以「已有一个 conversation 行」为前提，
    // 「保留 conversation ID」在新建场景下根本无定义）。**两支的分派归 E6 编排**，
    // 本演练在测试里手工分派。
    // -----------------------------------------------------------------------
    #[test]
    fn e5_p31_mini_drill_restores_from_mirror_and_reports_the_missing_blob() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let live = tmp.path().join("live");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();

        let kept_live = write_session(&live, "rollout-kept.jsonl", "drill-kept");
        let dropped_live = write_session(&live, "rollout-dropped.jsonl", "drill-dropped");
        let kept = capture(&data_dir, &kept_live);
        let dropped = capture(&data_dir, &dropped_live);
        assert_ne!(
            kept.blob_relative_path, dropped.blob_relative_path,
            "前置断言：两条身份必须落在不同 blob 上（内容寻址，同字节会共用）"
        );

        std::fs::remove_file(
            crate::doctor_raw_mirror_root(&data_dir).join(&dropped.blob_relative_path),
        )
        .unwrap();

        // 「live 无」做到字面：把两个活文件都删掉。投影的定义域里没有活文件系统，
        // 所以恢复必须在源文件已经不存在时照样走得通 —— 若哪一步偷偷回读活路径，
        // 这里就会红。
        std::fs::remove_file(&kept_live).unwrap();
        std::fs::remove_file(&dropped_live).unwrap();

        let db_path = data_dir.join("drill.sqlite");
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
        let conv_count = |s: &crate::storage::sqlite::FrankenStorage| -> i64 {
            s.raw()
                .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| {
                    row.get_typed(0)
                })
                .unwrap()
        };
        assert_eq!(
            conv_count(&storage),
            0,
            "前置断言：演练开始时库里必须是空的 —— 否则「恢复成功」可能只是它本来就在"
        );

        let views = crate::raw_mirror::manifest_views(&data_dir).unwrap();
        let reports = collect_sealed_manifest_reports(&data_dir);
        assert_eq!(views.len(), 2, "前置断言：mirror 里应当恰有两份 manifest");
        let original_path_of = |manifest_id: &str| -> String {
            views
                .iter()
                .find(|v| v.manifest_id == manifest_id)
                .expect("manifest 应当在 view 列表里")
                .original_path
                .clone()
        };
        let kept_original = original_path_of(&kept.manifest_id);
        let dropped_original = original_path_of(&dropped.manifest_id);

        let mut holds: Vec<HoldRecord> = Vec::new();
        let mut restored = 0usize;

        for view in &views {
            let report = reports
                .iter()
                .find(|r| r.manifest_id == view.manifest_id)
                .expect("每份 manifest 都应有一份 doctor 报告");

            let identity = RestoreIdentity {
                origin: OriginNamespace {
                    agent: Origin::Codex,
                    source_id: view.source_id.clone(),
                    origin_host: view.origin_host.clone().unwrap_or_else(|| "local".into()),
                },
                canonical_path: view.original_path.clone(),
            };

            let blob = match read_sealed_blob(&data_dir, report) {
                SealedBlobOutcome::Loaded(bytes) => bytes,
                SealedBlobOutcome::ReferenceMissing => {
                    holds.push(hold_for_manifest_reference_missing(identity, Vec::new()));
                    continue;
                }
                SealedBlobOutcome::Unreadable { detail } => {
                    panic!("本演练里不应出现读不动的 blob：{detail}")
                }
            };

            let provenance = provenance_from_manifest_view(view);
            let sealed = SealedSource {
                agent: Origin::Codex,
                canonical_original_path: &view.original_path,
                source_size_bytes: view.source_size_bytes,
                blob: &blob,
            };
            let projected = match project_sealed_source(&scratch, &sealed, &provenance) {
                Ok(SealedProjection::Projected(conv)) => *conv,
                other => panic!("封存投影未产出会话：{other:?}"),
            };

            // 裁定 R-E-44：新建走基线入口。
            let internal = crate::indexer::persist::map_to_internal(&projected);
            let agent_id = storage
                .ensure_agent(&crate::model::types::Agent {
                    id: None,
                    slug: internal.agent_slug.clone(),
                    name: internal.agent_slug.clone(),
                    version: None,
                    kind: crate::model::types::AgentKind::Cli,
                })
                .unwrap();
            let workspace_id = internal
                .workspace
                .as_ref()
                .map(|ws| storage.ensure_workspace(ws, None).unwrap());
            storage
                .insert_conversations_batched(&[(agent_id, workspace_id, &internal)])
                .unwrap();
            restored += 1;
        }

        assert_eq!(restored, 1, "blob 还在的那一条必须被恢复");
        assert_eq!(conv_count(&storage), 1, "库里应当恰多出一条会话");
        assert_eq!(
            holds.len(),
            1,
            "blob 被删的那一条必须**报出来**，不是静默跳过"
        );
        assert_eq!(holds[0].reason, HoldReason::ManifestReferenceMissing);
        assert_eq!(
            holds[0].identity.canonical_path, dropped_original,
            "报出来的必须是 blob 被删的**那一条**身份，不是随便一条"
        );

        let (source_path, metadata_json, metadata_bin): (String, String, Option<Vec<u8>>) = storage
            .raw()
            .query_row_map(
                "SELECT source_path, COALESCE(metadata_json, ''), metadata_bin FROM conversations",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
            )
            .unwrap();
        assert_eq!(
            source_path, kept_original,
            "恢复出来的 source_path 必须逐字等于 manifest 记的 original_path"
        );
        // metadata 走 msgpack 落 `metadata_bin` 时 `metadata_json` 是空的，所以两列都要看。
        // **在 Rust 侧判子串，不在 SQL 里 `CAST(... AS TEXT)`** —— msgpack 里的 NUL 会让
        // SQL 侧的字符串比较提前截断（这条坑本仓已经栽过一次）。
        let metadata_blob = String::from_utf8_lossy(metadata_bin.as_deref().unwrap_or(&[]));
        assert!(
            metadata_json.contains("raw_mirror") || metadata_blob.contains("raw_mirror"),
            "恢复出来的会话必须带 metadata.cass.raw_mirror 的出处；\
             metadata_json={metadata_json:?} metadata_bin_len={}",
            metadata_bin.as_deref().unwrap_or(&[]).len()
        );
    }

    // -----------------------------------------------------------------------
    // Step 4 · 重放去重实测（§15.1 升级为必测）
    //
    // plan 原文：「对已 restore 的会话把对应 live 源文件重新过一遍 connector 增量索引
    // （模拟上位 §9.4 watermark 置 0 的 cutover 后全量 rescan），断言不产生重复
    // conversation/消息、tail 定位正确」，且「用例必须覆盖 `conversation_tail_state`
    // 命中与未命中（回落 `conversations` 三列）**两条路径**」。
    //
    // **走真 `run_index`**（裁定 (b)）：不走真入口的话，「重放去重」测的就只是我自己
    // 拼出来的 Conversation，而 plan 特意点名这一步的被测对象是新函数「两处都重置 tail」
    // 与 connector 增量路径的**配合**。
    // -----------------------------------------------------------------------

    fn index_opts(data_dir: &Path, session: &Path, full: bool) -> crate::indexer::IndexOptions {
        crate::indexer::IndexOptions {
            full,
            watch: false,
            force_rebuild: false,
            watch_once_paths: Some(vec![session.to_path_buf()]),
            db_path: data_dir.join("db.sqlite"),
            data_dir: data_dir.to_path_buf(),
            semantic: false,
            build_hnsw: false,
            embedder: "fastembed".to_string(),
            progress: None,
            watch_interval_secs: 30,
        }
    }

    fn counts(storage: &crate::storage::sqlite::FrankenStorage) -> (i64, i64) {
        let conn = storage.raw();
        (
            conn.query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| {
                row.get_typed(0)
            })
            .unwrap(),
            conn.query_row_map("SELECT COUNT(*) FROM messages", &[], |row| row.get_typed(0))
                .unwrap(),
        )
    }

    /// 把 live 文件的字节当封存 blob 过一遍**同一条投影链**，产出 restore 侧会写进库的
    /// 那份会话。这样「replace 写进去的内容」与「connector 从同一个文件读出来的内容」
    /// 同源，重放去重才是在测去重，而不是在测两份内容碰巧不一样。
    fn projected_from_live(
        scratch: &Path,
        live: &Path,
        keep_lines: usize,
    ) -> crate::model::types::Conversation {
        // `keep_lines` 用来造**真前缀**：restore 的触发条件就是「候选是 winner 的真前缀」，
        // 所以恢复写进去的内容比库里现有的**短**。拿全量去 replace 等于把这一步测成
        // 「内容没变」，那样 tail 重置有没有生效根本看不出来。
        let full = std::fs::read_to_string(live).unwrap();
        let blob: Vec<u8> = full
            .lines()
            .take(keep_lines)
            .flat_map(|l| l.as_bytes().iter().copied().chain(std::iter::once(b'\n')))
            .collect();
        let provenance = crate::raw_mirror::RawMirrorCaptureRecord {
            manifest_id: "p32-manifest".into(),
            manifest_relative_path: "manifests/p32.json".into(),
            blob_relative_path: "blobs/p32.bin".into(),
            blob_blake3: "0".repeat(64),
            blob_size_bytes: blob.len() as u64,
            captured_at_ms: 1_770_551_400_000,
            source_mtime_ms: Some(1_770_551_400_000),
            already_present: true,
        };
        let canonical = live.display().to_string();
        let sealed = SealedSource {
            agent: Origin::Codex,
            canonical_original_path: &canonical,
            source_size_bytes: blob.len() as u64,
            blob: &blob,
        };
        match project_sealed_source(scratch, &sealed, &provenance) {
            Ok(SealedProjection::Projected(conv)) => {
                crate::indexer::persist::map_to_internal(&conv)
            }
            other => panic!("live 文件的投影未产出会话：{other:?}"),
        }
    }

    /// 公共骨架：建库 → 索引一遍 → 用 replace 函数替换该会话 →（可选）删热表行 →
    /// 对同一个 live 文件再跑一遍索引 → 返回收尾状态。
    fn replay_after_replace(drop_hot_tail_row: bool) -> (i64, i64, Option<i64>, Option<i64>) {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let live = write_session(&tmp.path().join("live"), "rollout-replay.jsonl", "replay");

        crate::indexer::run_index(index_opts(&data_dir, &live, false), None).unwrap();

        let db_path = data_dir.join("db.sqlite");
        let (conv_id, agent_id, old_global_max) = {
            let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
            let (convs, msgs) = counts(&storage);
            assert_eq!(convs, 1, "前置断言：第一遍索引后应当恰有一条会话");
            assert_eq!(msgs, 3, "前置断言：第一遍索引后应当有 3 条消息");
            let row: (i64, i64, i64) = storage
                .raw()
                .query_row_map(
                    "SELECT c.id, c.agent_id, (SELECT COALESCE(MAX(id), 0) FROM messages)
                     FROM conversations c",
                    &[],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
                )
                .unwrap();
            row
        };

        // 模拟 restore 落库：走 E5 的 replace 专用存储函数（两处 tail 重置、
        // 新 message id 越过全局 max）。
        let replacement = projected_from_live(&scratch, &live, 3);
        assert_eq!(
            replacement.messages.len(),
            2,
            "前置断言：替换内容必须是**真前缀**（2 条 < 库里的 3 条）——\
             等长替换测不出 tail 重置有没有生效"
        );
        {
            let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
            let pricing =
                crate::storage::sqlite::PricingTable::franken_load(storage.raw()).unwrap();
            let mut tx = storage.raw().transaction().unwrap();
            crate::storage::sqlite::franken_replace_conversation_messages_in_tx(
                &tx,
                conv_id,
                agent_id,
                None,
                &replacement,
                &pricing,
            )
            .unwrap();
            tx.commit().unwrap();

            let new_min: i64 = storage
                .raw()
                .query_row_map(
                    "SELECT MIN(id) FROM messages WHERE conversation_id = ?1",
                    &[ParamValue::from(conv_id)],
                    |row| row.get_typed(0),
                )
                .unwrap();
            assert!(
                new_min > old_global_max,
                "前置断言：replace 之后的 message id 必须越过旧全局 max（{old_global_max}），\
                 否则这一遍重放测不到「id 移动之后还能去重」"
            );

            if drop_hot_tail_row {
                storage
                    .raw()
                    .execute_compat(
                        "DELETE FROM conversation_tail_state WHERE conversation_id = ?1",
                        &[ParamValue::from(conv_id)],
                    )
                    .unwrap();
                let hot: i64 = storage
                    .raw()
                    .query_row_map(
                        "SELECT COUNT(*) FROM conversation_tail_state WHERE conversation_id = ?1",
                        &[ParamValue::from(conv_id)],
                        |row| row.get_typed(0),
                    )
                    .unwrap();
                assert_eq!(
                    hot, 0,
                    "分辨力前置断言：这一支必须真的走回落路径，热表里不能还留着行"
                );
            }
        }

        // 重放前把 scan watermark 清空 —— 这正是 plan 要模拟的东西：上位 §9.4 的
        // cutover 会把 watermark 置 0，随后是一次全量 rescan。不清的话第二遍索引会
        // 因为「这个文件自上次扫描以来没变过」直接跳过，那样本用例测的就只是
        // 「跳过了所以没重复」，与去重逻辑无关。
        {
            let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
            storage.restore_scan_watermarks(&[]).unwrap();
            let left: i64 = storage
                .raw()
                .query_row_map(
                    "SELECT COUNT(*) FROM meta
                     WHERE key = 'last_scan_ts' OR key LIKE 'last_scan_ts:connector:%'",
                    &[],
                    |row| row.get_typed(0),
                )
                .unwrap();
            assert_eq!(left, 0, "分辨力前置断言：watermark 必须真的被清空");
        }

        // 让这一趟真的重读那个文件：增量档会因为「自上次索引以来没变过」整趟跳过
        // （`should_skip_unchanged_explicit_watch_once_paths`），跳过的话本用例测的
        // 就是「跳过了所以没重复」，与去重逻辑无关。
        //
        // **不用 `full: true` 去绕过那道跳过**：`full` 会离开 targeted-watch-once，
        // 走 `build_watch_roots` → 每个 connector 的 `detect()`，而 detect 是按
        // **真实家目录**找根的（`dirs::home_dir()`）—— `CASS_DATA_DIR` / `XDG_DATA_HOME`
        // 管的是产物落在哪，管不住输入从哪来。本棒实测过一次：那趟开始扫真实会话目录，
        // 十分钟被 timeout 掐掉时临时库已经 3.3G。
        //
        // 改为把 mtime 往前推：内容一个字节不改，只让扫描器认为这个文件需要重看。
        // plan 那句「watermark 置 0 后全量 rescan」按**语义**实现（让它被真正重读一遍），
        // 不按 `full` 这个开关的字面实现 —— 字面实现的代价是扫全机。
        {
            let f = std::fs::File::options().write(true).open(&live).unwrap();
            let ahead = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
            f.set_times(std::fs::FileTimes::new().set_modified(ahead))
                .unwrap();
        }
        crate::indexer::run_index(index_opts(&data_dir, &live, false), None).unwrap();

        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
        let (convs, msgs) = counts(&storage);
        // 两处 tail 分开取：热表是缓存，`conversations` 三列是回落源。回落用例里
        // 热表本来就该继续空着（重放没有新消息可插，也就没有什么会去重建那行缓存），
        // 「tail 定位正确」在那一支上必须由**回落源**作证。
        let hot_tail_idx: Option<i64> = storage
            .raw()
            .query_row_map(
                "SELECT last_message_idx FROM conversation_tail_state WHERE conversation_id = ?1",
                &[ParamValue::from(conv_id)],
                |row| row.get_typed(0),
            )
            .optional()
            .unwrap()
            .flatten();
        let legacy_tail_idx: Option<i64> = storage
            .raw()
            .query_row_map(
                "SELECT last_message_idx FROM conversations WHERE id = ?1",
                &[ParamValue::from(conv_id)],
                |row| row.get_typed(0),
            )
            .unwrap();
        (convs, msgs, hot_tail_idx, legacy_tail_idx)
    }

    #[test]
    #[serial]
    fn e5_p32_replay_after_restore_dedupes_on_the_hot_tail_path() {
        let (convs, msgs, hot_tail_idx, legacy_tail_idx) = replay_after_replace(false);
        assert_eq!(convs, 1, "重放不得产生重复 conversation");
        assert_eq!(
            msgs, 3,
            "重放应当把 replace 掉的那条尾部消息**恰好补回一条**：少了是丢数据，多了是重复"
        );
        assert_eq!(
            hot_tail_idx,
            Some(2),
            "热表 tail 必须定位在补录之后的最后一条消息 idx 上；定位错会让下一次 append 插错位置"
        );
        assert_eq!(legacy_tail_idx, Some(2), "回落源同样必须是正确的 tail");
    }

    #[test]
    #[serial]
    fn e5_p32_replay_after_restore_dedupes_on_the_legacy_fallback_tail_path() {
        // 热表无行 → 读取器回落读 `conversations` 三列。**这一支是承重的**：
        // 若 replace 只重置了热表而没重置 legacy 三列，回落读到的就是陈旧 tail，
        // 重放会按错误的游标规划，去重随之失效。
        let (convs, msgs, hot_tail_idx, legacy_tail_idx) = replay_after_replace(true);
        assert_eq!(convs, 1, "回落路径上同样不得产生重复 conversation");
        assert_eq!(
            msgs, 3,
            "回落路径上同样应当恰好补回一条 —— 若 legacy 三列没被重置，回落读到的是\
             replace 之前的旧 tail，重放会判「已经到尾了」而**静默丢掉**那条补录"
        );
        // 走过回落之后，重放确实插了一条新消息，于是热表缓存被重建 —— 这是对的，
        // 不该断言它「仍为空」。**这一支走没走回落，由 helper 里那条事前断言作证**
        // （replace 之后、重放之前，热表计数必须为 0）；事后再去要求热表为空，
        // 等于要求重放什么都别做，那正好和本用例要证的事情相反。
        assert_eq!(
            hot_tail_idx,
            Some(2),
            "补录之后热表缓存应当被重建到正确的 tail"
        );
        assert_eq!(
            legacy_tail_idx,
            Some(2),
            "回落源（`conversations` 三列）必须是补录之后的正确 tail —— 若 replace 只重置了\
             热表、legacy 三列留着陈旧值，这里读到的就是那个陈旧值，重放随之按错游标规划"
        );
    }

    /// 陈旧 / legacy 形态的 tail 之下，重放的去重仍然成立。
    ///
    /// **记账为契约验证，不是 TDD 红转绿**（与 §B.11 那三批同一口径）：它锁的是**基线**
    /// 的两道结构性保证，不是本棒实现的行为 ——
    ///
    /// 1. `messages` 有 `UNIQUE(conversation_id, idx)`，而 append 路径走
    ///    `franken_insert_new_message_ignore_duplicate` —— 重复行**结构上插不进去**；
    /// 2. 两个 no-op 捷径（`collect_existing_conversation_noop_from_idx_tail` 与
    ///    `..._from_conversation_ended_at`）对**非空**会话一律返回 `None`，源码注释写明
    ///    「一个 max idx / 一个会话级 ended_at 都不能证明更早的行还在」，于是必然落到
    ///    逐条比对既有消息行的 bounded lookup。
    ///
    /// 两条合起来：陈旧 tail 能让规划器**挑错捷径**，但既不会重复插入（① 挡住），
    /// 也不会静默漏插（② 兜住）。本用例把这个结论钉成回归门 —— 将来基线若把 ② 那条
    /// 兜底去掉，或把 ① 的 UNIQUE / ignore-duplicate 改掉，这条会红。
    ///
    /// **模拟手法**：手工把 tail 行的 `last_message_created_at` 与 `ended_at` 置 NULL、
    /// `last_message_idx` 留在**陈旧的高位**，模拟一条只记了 idx 的 legacy tail 行。
    /// 真实来源假设：生产库跨多个 schema 版本迁移攒成，早期版本的 tail 列不齐全；
    /// 这不是本棒代码会写出来的形态，所以只能手工造。
    #[test]
    #[serial]
    fn e5_p33_replay_still_dedupes_under_a_stale_legacy_tail_row() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&scratch).unwrap();
        let live = write_session(&tmp.path().join("live"), "rollout-legacy.jsonl", "legacy");

        crate::indexer::run_index(index_opts(&data_dir, &live, false), None).unwrap();
        let db_path = data_dir.join("db.sqlite");

        let (conv_id, agent_id) = {
            let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
            storage
                .raw()
                .query_row_map("SELECT id, agent_id FROM conversations", &[], |row| {
                    Ok((row.get_typed(0)?, row.get_typed(1)?))
                })
                .unwrap()
        };

        let replacement = projected_from_live(&scratch, &live, 3);
        assert_eq!(replacement.messages.len(), 2, "前置断言：替换内容是真前缀");

        {
            let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
            let pricing =
                crate::storage::sqlite::PricingTable::franken_load(storage.raw()).unwrap();
            let mut tx = storage.raw().transaction().unwrap();
            crate::storage::sqlite::franken_replace_conversation_messages_in_tx(
                &tx,
                conv_id,
                agent_id,
                None,
                &replacement,
                &pricing,
            )
            .unwrap();
            tx.commit().unwrap();

            // 造 legacy 形态：热表清掉（逼回落），legacy 三列只留一个**陈旧高位** idx。
            let conn = storage.raw();
            conn.execute_compat(
                "DELETE FROM conversation_tail_state WHERE conversation_id = ?1",
                &[ParamValue::from(conv_id)],
            )
            .unwrap();
            conn.execute_compat(
                "UPDATE conversations
                 SET last_message_idx = 99, last_message_created_at = NULL, ended_at = NULL
                 WHERE id = ?1",
                &[ParamValue::from(conv_id)],
            )
            .unwrap();

            // 分辨力前置断言：形态确实造出来了 —— 热表无行（必然回落）、legacy 三列
            // 只剩一个陈旧高位 idx。读取器本身是 `sqlite.rs` 的私有函数，这里不为了
            // 测试方便去给它开一个 pub 口子（消费者的便利不构成动既有代码的理由）；
            // 「热表无行时会回落读这三列」这条基线行为已由上面那条回落用例立住。
            let hot_rows: i64 = conn
                .query_row_map(
                    "SELECT COUNT(*) FROM conversation_tail_state WHERE conversation_id = ?1",
                    &[ParamValue::from(conv_id)],
                    |row| row.get_typed(0),
                )
                .unwrap();
            assert_eq!(hot_rows, 0, "分辨力前置断言：热表必须为空，否则走不到回落");
            let legacy: (Option<i64>, Option<i64>, Option<i64>) = conn
                .query_row_map(
                    "SELECT last_message_idx, last_message_created_at, ended_at
                     FROM conversations WHERE id = ?1",
                    &[ParamValue::from(conv_id)],
                    |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
                )
                .unwrap();
            assert_eq!(
                legacy,
                (Some(99), None, None),
                "分辨力前置断言：legacy 行必须是「只记了一个陈旧 idx」的形态"
            );
        }

        {
            let f = std::fs::File::options().write(true).open(&live).unwrap();
            let ahead = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
            f.set_times(std::fs::FileTimes::new().set_modified(ahead))
                .unwrap();
        }
        crate::indexer::run_index(index_opts(&data_dir, &live, false), None).unwrap();

        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
        let (convs, msgs) = counts(&storage);
        assert_eq!(
            convs, 1,
            "陈旧 legacy tail 之下同样不得产生重复 conversation"
        );
        assert_eq!(
            msgs, 3,
            "陈旧 legacy tail 之下同样应当**恰好**补回一条：重复插不进去（UNIQUE + \
             ignore-duplicate），漏插被 bounded lookup 兜住"
        );
        let idxs: Vec<i64> = storage
            .raw()
            .query_map_collect(
                "SELECT idx FROM messages WHERE conversation_id = ?1 ORDER BY idx",
                &[ParamValue::from(conv_id)],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(idxs, vec![0, 1, 2], "idx 必须是 0..2 各恰一条，不重不漏");
    }
}

// ---------------------------------------------------------------------------
// E6 · replace 编排（plan Task E6 Step 1 的 Replace 支）
//
// 本节只做**时序与分派**；每一次落盘都经 `storage::sqlite` 的原语（裁定 R-E-48）。
// 序列与归属见 run root 的 `e6-dispatch-interface.md` §2；这里只重复承重的三条：
//   · 外层事务由**调用方**给（与 E5 的语义① 同一条纪律：编排自己也不开事务，
//     这样 E7 的 journal 才能把「DB 动作」与「journal 状态推进」放进同一个边界）；
//   · receipt 与 DB 动作**同事务**；
//   · 五张累加型物化聚合表**不在这里**——按 E6 Step 1b 在事务提交之后重算。
// ---------------------------------------------------------------------------

/// `commit_replace_in_tx` 的入参。
// ⚠ 移除义务在 **E8**，不在 E6：dead-code 是从**可达根**传递判定的，而 E6 只是又加了
// 一层编排 —— 编排本身在非测试构建里仍无调用方，于是它下面整条链（含 E5 那四个符号）
// 依旧不可达。真正的根是 E8 把 `mirror-restore --apply` 的 CLI 接上那一刻。
// 判据仍是「删掉 allow 之后 clippy 不报 never-used」，不是「删掉能编译」。
#[allow(dead_code)]
pub(crate) struct ReplaceCommitInput<'a> {
    /// 被替换的会话，**ID 保留**（§5.2.4 首行）。
    pub conversation_id: i64,
    pub agent_id: i64,
    pub workspace_id: Option<i64>,
    /// 投影产物（已过 `map_to_internal`）。
    pub conv: &'a crate::model::types::Conversation,
    /// 用于构造幂等 key 的身份。
    pub identity: &'a RestoreIdentity,
    /// 本次消费的封存件根，进幂等 key —— 换一批封存件重跑不得被误判「已提交」。
    pub snapshot_root: &'a str,
    /// 本次 restore 推进到的内容代际。
    pub generation: &'a str,
}

/// `commit_replace_in_tx` 的产出。
#[allow(dead_code)]
pub(crate) struct ReplaceCommitOutcome {
    /// 本次写入 receipt 用的幂等 key；恢复器据它判「已提交」。
    pub idempotency_key: String,
    /// 新插入的 message id（按 `conv.messages` 顺序）。
    pub inserted_message_ids: Vec<i64>,
}

/// replace 分支的 `operation` 取值。**字面量集中在一处**，避免写 receipt 与查 receipt
/// 两侧各写一份字符串。
#[allow(dead_code)]
pub(crate) const REPLACE_OPERATION: &str = "mirror-restore-replace";

/// 幂等 key = `{operation}:{snapshot_root}:{identity}`。
///
/// 三条约束（接口说明 §3）：同一 identity 重跑命中同一 key；不同 snapshot root 不得
/// 共用；**必须能由崩溃后的全新进程只读重算出来** —— 所以三个组成部分全部来自入参，
/// 没有任何一项依赖内存状态或墙钟。
///
/// `RestoreIdentity` 的 `Display` 已经把 `{agent}@{host}:{source_id} {canonical_path}`
/// 拼好，这里直接用它，不在第二处重拼身份的字符串形式。
#[allow(dead_code)]
pub(crate) fn replace_idempotency_key(snapshot_root: &str, identity: &RestoreIdentity) -> String {
    format!("{REPLACE_OPERATION}:{snapshot_root}:{identity}")
}

/// 在**调用方给的事务**里跑完 replace 的整条序列。
///
/// 步骤（编号对齐接口说明 §2 的表）：
/// 2–7 交给 E5 的 `franken_replace_conversation_messages_in_tx`（两处 tail 重置、
/// 删旧、插新、两张派生表、11 列重算、tail 回写）；
/// 8 重建第三处 tail 载体；9 conversation 级字段按 §B.1.2；10 推进 generation；
/// 11 写 receipt。
#[allow(dead_code)]
pub(crate) fn commit_replace_in_tx(
    tx: &frankensqlite::compat::Transaction<'_>,
    input: &ReplaceCommitInput<'_>,
    pricing: &crate::storage::sqlite::PricingTable,
    committed_at_ms: i64,
) -> anyhow::Result<ReplaceCommitOutcome> {
    // 2–7
    let replaced = crate::storage::sqlite::franken_replace_conversation_messages_in_tx(
        tx,
        input.conversation_id,
        input.agent_id,
        input.workspace_id,
        input.conv,
        pricing,
    )?;

    // 8 · 第三处 tail 载体
    crate::storage::sqlite::franken_rebuild_external_conversation_tail_lookup_in_tx(
        tx,
        input.agent_id,
        input.conv,
    )?;

    // 9 · conversation 级字段（§B.1.2）
    crate::storage::sqlite::franken_update_conversation_projection_fields_in_tx(
        tx,
        input.conversation_id,
        input.workspace_id,
        input.conv,
    )?;

    // 10 · 推进 generation
    crate::storage::sqlite::franken_set_source_content_generation_in_tx(tx, input.generation)?;

    // 11 · receipt（同事务）
    let idempotency_key = replace_idempotency_key(input.snapshot_root, input.identity);
    crate::storage::sqlite::franken_insert_operation_commit_receipt_in_tx(
        tx,
        &idempotency_key,
        REPLACE_OPERATION,
        "committed",
        Some(input.snapshot_root),
        committed_at_ms,
        None,
    )?;

    Ok(ReplaceCommitOutcome {
        idempotency_key,
        inserted_message_ids: replaced.inserted_message_ids,
    })
}

/// Step 1b · 五张累加型物化聚合表的**提交后**重算。
///
/// 名单与顺序：`daily_stats` / `token_daily_stats`（各有既有的全量重建入口）+
/// 三张 usage rollup（走 E6 新增的、只碰这三张的重算）。
///
/// **为什么在事务之外**：它们是提交后重算的对象（plan Task E6 Step 1b），而不是
/// replace 事务的一部分。「提交与重算之间的崩溃窗」归 E7 的 journal 状态机覆盖 ——
/// 恢复器按幂等 key 查到 receipt 判「已提交」并**补做**这一步，
/// **不得靠「刚好没崩」成立**。
///
/// **必须绕开 `rebuild_analytics`**（裁定 D-A3-4）：它会把 `message_metrics` 的 DELETE
/// 与三张 rollup 的 DELETE 捆进同一次全量重建，而 `message_metrics` 是事务内逐消息写、
/// 用另一套分桶公式的表 —— 照字面调用会让它被两套公式各写一遍。
#[allow(dead_code)]
pub(crate) fn recompute_materialized_aggregates_after_commit(
    storage: &crate::storage::sqlite::FrankenStorage,
) -> anyhow::Result<()> {
    storage.rebuild_daily_stats()?;
    storage.rebuild_token_daily_stats()?;
    crate::storage::sqlite::franken_recompute_usage_rollups_from_message_metrics(storage)?;
    Ok(())
}

/// 新建分支的 `operation` 取值。与 replace 分支分开，两者的幂等 key 不得互相碰撞。
#[allow(dead_code)]
pub(crate) const RESTORE_NEW_OPERATION: &str = "mirror-restore-new";

/// 新建分支的幂等 key，构成与 replace 支同型（三个分量全部来自入参）。
#[allow(dead_code)]
pub(crate) fn restore_new_idempotency_key(
    snapshot_root: &str,
    identity: &RestoreIdentity,
) -> String {
    format!("{RESTORE_NEW_OPERATION}:{snapshot_root}:{identity}")
}

/// `commit_restore_new` 的入参。**没有 `conversation_id`** —— 这一支的会话还不存在，
/// 「保留原 ID」在这里无定义（裁定 R-E-44）。
#[allow(dead_code)]
pub(crate) struct RestoreNewCommitInput<'a> {
    pub agent_id: i64,
    pub workspace_id: Option<i64>,
    pub conv: &'a crate::model::types::Conversation,
    pub identity: &'a RestoreIdentity,
    pub snapshot_root: &'a str,
    pub generation: &'a str,
}

/// `commit_restore_new` 的产出。
#[allow(dead_code)]
pub(crate) struct RestoreNewCommitOutcome {
    pub idempotency_key: String,
    /// `true` = 本次真的写了；`false` = 查到 receipt，判「已提交」直接短路。
    pub applied: bool,
}

/// 新建分支：candidate 缺失 → 建一条会话。
///
/// **原子边界是「一条会话」，不是「整批」**（裁定 R-E-47 选 (a)）。理由是这一支按
/// R-E-44 走基线 `insert_conversations_batched`，而**那个入口自己开事务**，塞不进
/// 外层事务；给新建另写一个收外部 tx 的存储函数会引入第二份派生行构造，代价更大。
///
/// **崩溃窗与它为什么安全**：插入已提交、receipt 未写之间存在一个窗。安全性不来自
/// 「窗很窄」，而来自**重做幂等**：恢复时按幂等 key 查不到 receipt → 判未提交 →
/// 重走一遍插入 → 既有行被 tail 规划器与 `UNIQUE(conversation_id, idx)` +
/// ignore-duplicate 收敛，不重不漏。新建这一支**没有「删旧」那一半**，所以不存在
/// replace 那种「旧的已删、新的没进」的半截状态。
///
/// 与 replace 支的另一处不同：**receipt 与插入不在同一个事务里**（做不到，见上），
/// 所以这里先查 receipt 再动手 —— 幂等靠**先查后做**，不靠「重复写入被吞掉」。
#[allow(dead_code)]
pub(crate) fn commit_restore_new(
    storage: &crate::storage::sqlite::FrankenStorage,
    input: &RestoreNewCommitInput<'_>,
    committed_at_ms: i64,
) -> anyhow::Result<RestoreNewCommitOutcome> {
    let idempotency_key = restore_new_idempotency_key(input.snapshot_root, input.identity);

    if crate::storage::sqlite::franken_operation_commit_receipt_exists(
        storage.raw(),
        &idempotency_key,
    )? {
        return Ok(RestoreNewCommitOutcome {
            idempotency_key,
            applied: false,
        });
    }

    // 第一个原子步：基线入口自带事务。重跑时既有行被去重路径收敛。
    storage.insert_conversations_batched(&[(input.agent_id, input.workspace_id, input.conv)])?;

    // 第二个原子步：generation 与 receipt 一起提交 —— 它们之间不能再有窗，
    // 否则会出现「代际已推进、却查不到 receipt」这种更难判读的状态。
    use frankensqlite::compat::TransactionExt as _;
    let mut tx = storage.raw().transaction()?;
    crate::storage::sqlite::franken_set_source_content_generation_in_tx(&tx, input.generation)?;
    crate::storage::sqlite::franken_insert_operation_commit_receipt_in_tx(
        &tx,
        &idempotency_key,
        RESTORE_NEW_OPERATION,
        "committed",
        Some(input.snapshot_root),
        committed_at_ms,
        None,
    )?;
    tx.commit()?;

    Ok(RestoreNewCommitOutcome {
        idempotency_key,
        applied: true,
    })
}

// ===========================================================================
// E6 · replace 编排（plan Task E6 Step 1 的 Replace 支）
//
// 编排负责的是**时序与分派**，存储写点仍在 `storage::sqlite`。本组测试锁的是
// plan Task E6 Step 1 点名的那条事务序列里，**E5 没做、由 E6 补上的四件事**：
//   ⑧ 第三处 tail 载体 `conversation_external_tail_lookup` 的重建；
//   ⑨ conversation 级字段按附录 §B.1.2 的逐行动作；
//   ⑩ 推进 generation（`meta` 的 `source_content_generation`）；
//   ⑪ 写 receipt（`operation_commit_receipt`），与 DB 动作**同事务**。
// 外加整条序列的原子性：无孤儿断言失败 → 整事务回滚。
// ===========================================================================
#[cfg(test)]
mod e6_replace_commit_tests {
    use super::*;
    use frankensqlite::compat::{
        ConnectionExt, OptionalExtension, ParamValue, RowExt, TransactionExt,
    };
    use tempfile::TempDir;

    use crate::model::types::{Agent, AgentKind, Conversation, Message, MessageRole};
    use crate::storage::sqlite::{FrankenStorage, PricingTable};
    use serial_test::serial;

    const TS: i64 = 1_770_551_400_000;
    const EXTERNAL_ID: &str = "e6-conv-1";

    fn message(idx: i64, role: MessageRole, content: &str) -> Message {
        Message {
            id: None,
            idx,
            role,
            author: None,
            created_at: Some(TS + idx * 1_000),
            content: content.into(),
            extra_json: serde_json::Value::Null,
            snippets: vec![],
        }
    }

    fn conversation_titled(title: &str, messages: Vec<Message>) -> Conversation {
        let ended = messages.iter().filter_map(|m| m.created_at).max();
        Conversation {
            id: None,
            agent_slug: "codex".into(),
            workspace: None,
            external_id: Some(EXTERNAL_ID.into()),
            title: Some(title.to_owned()),
            source_path: std::path::PathBuf::from("/fixtures/e6.jsonl"),
            started_at: messages.iter().filter_map(|m| m.created_at).min(),
            ended_at: ended,
            approx_tokens: Some(999), // 必须被置 NULL（§B.1.2 末行）
            metadata_json: serde_json::json!({"source": "rollout"}),
            messages,
            source_id: "local".into(),
            origin_host: None,
        }
    }

    fn open(dir: &TempDir) -> (FrankenStorage, i64) {
        let storage = FrankenStorage::open(&dir.path().join("e6.sqlite")).unwrap();
        let agent_id = storage
            .ensure_agent(&Agent {
                id: None,
                slug: "codex".into(),
                name: "codex".into(),
                version: None,
                kind: AgentKind::Cli,
            })
            .unwrap();
        (storage, agent_id)
    }

    fn identity() -> RestoreIdentity {
        RestoreIdentity {
            origin: OriginNamespace {
                agent: Origin::Codex,
                source_id: "local".into(),
                origin_host: "fixture-host".into(),
            },
            canonical_path: "/fixtures/e6.jsonl".into(),
        }
    }

    fn scalar_i64(storage: &FrankenStorage, sql: &str, id: i64) -> Option<i64> {
        storage
            .raw()
            .query_row_map(sql, &[ParamValue::from(id)], |row| row.get_typed(0))
            .optional()
            .unwrap()
            .flatten()
    }

    /// 建一条已索引的三消息会话，并**证明第三处 tail 载体确实有行**（否则 ⑧ 的断言空转）。
    fn seed(storage: &FrankenStorage, agent_id: i64) -> i64 {
        let first = conversation_titled(
            "旧标题",
            vec![
                message(0, MessageRole::User, "旧 0"),
                message(1, MessageRole::Assistant, "旧 1"),
            ],
        );
        storage
            .insert_conversations_batched(&[(agent_id, None, &first)])
            .unwrap();
        // 第二批走 append 分支，这一步才会写 `conversation_external_tail_lookup`。
        let grown = conversation_titled(
            "旧标题",
            vec![
                message(0, MessageRole::User, "旧 0"),
                message(1, MessageRole::Assistant, "旧 1"),
                message(2, MessageRole::User, "旧 2"),
            ],
        );
        storage
            .insert_conversations_batched(&[(agent_id, None, &grown)])
            .unwrap();

        let conv_id: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM conversations WHERE external_id = ?1",
                &[ParamValue::from(EXTERNAL_ID)],
                |row| row.get_typed(0),
            )
            .unwrap();
        let tail_idx = scalar_i64(
            storage,
            "SELECT last_message_idx FROM conversation_external_tail_lookup
             WHERE conversation_id = ?1",
            conv_id,
        );
        assert_eq!(
            tail_idx,
            Some(2),
            "前置断言：第三处 tail 载体必须有一行且停在 idx 2，否则 ⑧ 的断言是空转"
        );
        conv_id
    }

    fn replacement() -> Conversation {
        // 真前缀：2 条 < 库里的 3 条，于是三处 tail 都必须**降**下来。
        // title 由 connector 侧的规则推导，**E6 不重推导**（重推导即第二定义）——
        // 它写的是投影产物里的那个值。判据因此是「旧标题被换掉」，不是「E6 算得对」。
        conversation_titled(
            "新标题",
            vec![
                message(0, MessageRole::User, "新 0"),
                message(1, MessageRole::Assistant, "新 1"),
            ],
        )
    }

    #[test]
    fn e6_replace_commit_rebuilds_the_third_tail_carrier_and_writes_receipt() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);
        let conv_id = seed(&storage, agent_id);
        let new_conv = replacement();
        let id = identity();
        let pricing = PricingTable::franken_load(storage.raw()).unwrap();

        let outcome = {
            let mut tx = storage.raw().transaction().unwrap();
            let out = commit_replace_in_tx(
                &tx,
                &ReplaceCommitInput {
                    conversation_id: conv_id,
                    agent_id,
                    workspace_id: None,
                    conv: &new_conv,
                    identity: &id,
                    snapshot_root: "snap-root-abc",
                    generation: "gen-e6-0001",
                },
                &pricing,
                TS + 60_000,
            )
            .unwrap();
            tx.commit().unwrap();
            out
        };

        // ⑧ 第三处 tail 载体必须降到新内容的 max idx。既有的两个写入器都是单调抬高，
        // 所以「降下来了」本身就是「重建过」的证据。
        assert_eq!(
            scalar_i64(
                &storage,
                "SELECT last_message_idx FROM conversation_external_tail_lookup
                 WHERE conversation_id = ?1",
                conv_id
            ),
            Some(1),
            "第三处 tail 载体留旧值会让下一次 append 插错位置（plan E6 Step 1 点名）"
        );

        // ⑨ conversation 级字段按 §B.1.2：`approx_tokens` 置 NULL、`ended_at` 重算。
        assert_eq!(
            scalar_i64(
                &storage,
                "SELECT approx_tokens FROM conversations WHERE id = ?1",
                conv_id
            ),
            None,
            "`approx_tokens` 必须被置 NULL（§B.1.2 末行：与 ingest 行为一致）"
        );
        assert_eq!(
            scalar_i64(
                &storage,
                "SELECT ended_at FROM conversations WHERE id = ?1",
                conv_id
            ),
            Some(TS + 1_000),
            "`ended_at` 必须按**新**消息集重算（旧值 TS+2000 留着即为未重算）"
        );
        let title: Option<String> = storage
            .raw()
            .query_row_map(
                "SELECT title FROM conversations WHERE id = ?1",
                &[ParamValue::from(conv_id)],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(
            title.as_deref(),
            Some("新标题"),
            "`title` 必须换成投影产物的值（§B.1.2 首行「重算」）；留着「旧标题」\
             即为没更新 —— 注意判据是「换掉了」，E6 不负责重新推导标题那条规则"
        );

        // ⑩ generation 推进。
        let generation: Option<String> = storage
            .raw()
            .query_row_map(
                "SELECT value FROM meta WHERE key = ?1",
                &[ParamValue::from(
                    crate::storage::sqlite::SOURCE_CONTENT_GENERATION_META_KEY,
                )],
                |row| row.get_typed(0),
            )
            .optional()
            .unwrap()
            .flatten();
        assert_eq!(generation.as_deref(), Some("gen-e6-0001"));

        // ⑪ receipt 与 DB 动作同事务，且幂等 key 三要素齐（operation / snapshot_root /
        // identity）—— 缺 snapshot_root 会让换一批封存件重跑被误判「已提交」。
        let (key, operation, state, root): (String, String, String, Option<String>) = storage
            .raw()
            .query_row_map(
                "SELECT idempotency_key, operation, state, snapshot_root
                 FROM operation_commit_receipt",
                &[],
                |row| {
                    Ok((
                        row.get_typed(0)?,
                        row.get_typed(1)?,
                        row.get_typed(2)?,
                        row.get_typed(3)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(key, outcome.idempotency_key);
        assert!(
            key.contains("snap-root-abc") && key.contains(&id.canonical_path),
            "幂等 key 必须同时含 snapshot_root 与 identity，实得 {key}"
        );
        assert_eq!(operation, "mirror-restore-replace");
        assert_eq!(state, "committed");
        assert_eq!(root.as_deref(), Some("snap-root-abc"));
    }

    #[test]
    fn e6_replace_commit_is_undone_whole_by_an_outer_rollback() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);
        let conv_id = seed(&storage, agent_id);
        let new_conv = replacement();
        let id = identity();
        let pricing = PricingTable::franken_load(storage.raw()).unwrap();

        {
            let mut tx = storage.raw().transaction().unwrap();
            commit_replace_in_tx(
                &tx,
                &ReplaceCommitInput {
                    conversation_id: conv_id,
                    agent_id,
                    workspace_id: None,
                    conv: &new_conv,
                    identity: &id,
                    snapshot_root: "snap-root-abc",
                    generation: "gen-e6-0001",
                },
                &pricing,
                TS + 60_000,
            )
            .unwrap();
            tx.rollback().unwrap();
        }

        // 整条序列必须一起回滚 —— 任何一件留下来，都说明它逃出了外层事务。
        let msgs = scalar_i64(
            &storage,
            "SELECT COUNT(*) FROM messages WHERE conversation_id = ?1",
            conv_id,
        );
        assert_eq!(msgs, Some(3), "消息集必须回到 replace 之前的 3 条");
        assert_eq!(
            scalar_i64(
                &storage,
                "SELECT last_message_idx FROM conversation_external_tail_lookup
                 WHERE conversation_id = ?1",
                conv_id
            ),
            Some(2),
            "第三处 tail 载体必须回到旧值"
        );
        let receipts = scalar_i64(
            &storage,
            "SELECT COUNT(*) FROM operation_commit_receipt WHERE id >= ?1",
            0,
        );
        assert_eq!(
            receipts,
            Some(0),
            "receipt 必须一起回滚 —— 它与 DB 动作同事务"
        );
        let generation: Option<String> = storage
            .raw()
            .query_row_map(
                "SELECT value FROM meta WHERE key = ?1",
                &[ParamValue::from(
                    crate::storage::sqlite::SOURCE_CONTENT_GENERATION_META_KEY,
                )],
                |row| row.get_typed(0),
            )
            .optional()
            .unwrap()
            .flatten();
        assert_eq!(generation, None, "generation 必须一起回滚");
    }

    // -------------------------------------------------------------------
    // Restore（新建）支 —— 裁定 R-E-47 走 (a)：每会话独立事务
    // -------------------------------------------------------------------

    #[test]
    fn e6_restore_new_creates_the_conversation_and_records_generation_and_receipt() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);
        let conv = conversation_titled(
            "新建标题",
            vec![
                message(0, MessageRole::User, "新建 0"),
                message(1, MessageRole::Assistant, "新建 1"),
            ],
        );
        let id = identity();

        let before: Option<i64> = storage
            .raw()
            .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| {
                row.get_typed(0)
            })
            .unwrap();
        assert_eq!(
            before,
            Some(0),
            "前置断言：库里必须是空的，这一支是「新建」"
        );

        let outcome = commit_restore_new(
            &storage,
            &RestoreNewCommitInput {
                agent_id,
                workspace_id: None,
                conv: &conv,
                identity: &id,
                snapshot_root: "snap-root-new",
                generation: "gen-e6-new-1",
            },
            TS + 60_000,
        )
        .unwrap();
        assert!(outcome.applied, "第一次必须真的写");

        let (convs, msgs): (i64, i64) = storage
            .raw()
            .query_row_map(
                "SELECT (SELECT COUNT(*) FROM conversations), (SELECT COUNT(*) FROM messages)",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )
            .unwrap();
        assert_eq!((convs, msgs), (1, 2));

        let (key, operation): (String, String) = storage
            .raw()
            .query_row_map(
                "SELECT idempotency_key, operation FROM operation_commit_receipt",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )
            .unwrap();
        assert_eq!(key, outcome.idempotency_key);
        assert_eq!(
            operation, "mirror-restore-new",
            "新建支的 operation 必须与 replace 支分开 —— 两支的幂等 key 不得碰撞"
        );
    }

    /// 崩溃窗的**状态级**证据（裁定 R-E-47 的条件）。
    ///
    /// **它证到什么、没证到什么，写清楚**：本用例构造的是崩溃**留下的状态**
    /// （插入已提交、receipt 未写），证的是**重做幂等** —— 重跑之后不重不漏、
    /// receipt 恰一条。它**没有**证「恢复器判窗正确」：那需要真 `SIGKILL` + 全新进程
    /// 只读 journal 与 receipt 做判断，而恢复器本身是 **plan Task E7** 的交付，
    /// E6 阶段还没有它可跑。**「Restore 支的 SIGKILL 注入」已作为具名用例登记进
    /// E7 的电池清单**，不要因为本用例是绿的就以为那一半也证完了。
    #[test]
    fn e6_restore_new_redo_after_a_lost_receipt_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);
        let conv = conversation_titled(
            "新建标题",
            vec![
                message(0, MessageRole::User, "新建 0"),
                message(1, MessageRole::Assistant, "新建 1"),
            ],
        );
        let id = identity();
        let input = || RestoreNewCommitInput {
            agent_id,
            workspace_id: None,
            conv: &conv,
            identity: &id,
            snapshot_root: "snap-root-new",
            generation: "gen-e6-new-1",
        };

        commit_restore_new(&storage, &input(), TS + 60_000).unwrap();

        // 造崩溃窗留下的状态：插入已提交，receipt 没写成。
        storage
            .raw()
            .execute_compat("DELETE FROM operation_commit_receipt", &[])
            .unwrap();
        let receipts: Option<i64> = storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt",
                &[],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(
            receipts,
            Some(0),
            "分辨力前置断言：必须真的处在「插入已提交、receipt 未写」这个状态"
        );

        // 恢复：查不到 receipt → 判未提交 → 重做。
        let redo = commit_restore_new(&storage, &input(), TS + 120_000).unwrap();
        assert!(redo.applied, "查不到 receipt 就必须重做，不能当已完成跳过");

        let (convs, msgs, receipts): (i64, i64, i64) = storage
            .raw()
            .query_row_map(
                "SELECT (SELECT COUNT(*) FROM conversations),
                        (SELECT COUNT(*) FROM messages),
                        (SELECT COUNT(*) FROM operation_commit_receipt)",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?, row.get_typed(2)?)),
            )
            .unwrap();
        assert_eq!(convs, 1, "重做不得建出第二条会话");
        assert_eq!(msgs, 2, "重做不得重复插入消息，也不得漏掉");
        assert_eq!(receipts, 1, "重做之后 receipt 恰一条");
    }

    #[test]
    fn e6_restore_new_short_circuits_when_the_receipt_is_already_there() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);
        let conv = conversation_titled("新建标题", vec![message(0, MessageRole::User, "新建 0")]);
        let id = identity();
        let input = || RestoreNewCommitInput {
            agent_id,
            workspace_id: None,
            conv: &conv,
            identity: &id,
            snapshot_root: "snap-root-new",
            generation: "gen-e6-new-1",
        };

        let first = commit_restore_new(&storage, &input(), TS + 60_000).unwrap();
        assert!(first.applied);
        let second = commit_restore_new(&storage, &input(), TS + 120_000).unwrap();
        assert!(
            !second.applied,
            "receipt 在就必须短路 —— 幂等靠**先查后做**，不靠重复写入被吞掉"
        );

        let receipts: Option<i64> = storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt",
                &[],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(receipts, Some(1));
    }

    // -------------------------------------------------------------------
    // Step 1b · 五张累加型物化聚合表的提交后重算
    // -------------------------------------------------------------------

    fn message_metrics_digest(storage: &FrankenStorage) -> Vec<String> {
        storage
            .raw()
            .query_map_collect(
                "SELECT CAST(message_id AS TEXT) || '|' || CAST(hour_id AS TEXT) || '|'
                        || CAST(day_id AS TEXT) || '|' || agent_slug || '|'
                        || CAST(content_tokens_est AS TEXT) || '|' || api_data_source
                        || '|' || provider
                 FROM message_metrics ORDER BY message_id",
                &[],
                |row| row.get_typed::<String>(0),
            )
            .unwrap()
    }

    fn rollup_digest(storage: &FrankenStorage, table: &str) -> Vec<String> {
        storage
            .raw()
            .query_map_collect(
                &format!(
                    "SELECT agent_slug || '|' || CAST(message_count AS TEXT) || '|'
                            || CAST(user_message_count AS TEXT) || '|'
                            || CAST(assistant_message_count AS TEXT) || '|'
                            || CAST(api_tokens_total AS TEXT)
                     FROM {table} ORDER BY agent_slug, message_count"
                ),
                &[],
                |row| row.get_typed::<String>(0),
            )
            .unwrap()
    }

    #[test]
    #[serial]
    fn e6_step1b_recomputes_the_five_tables_without_touching_message_metrics() {
        // ⚠ 「基线入口会不会顺手写三张 rollup」由一个**进程级默认开关**决定，而
        // `run_index` 会把它翻成「延后」。本用例第一版没管这个开关：单独跑绿、
        // 跟着全量 `--lib phase3_` 跑就红（前置断言读到空的 usage_hourly）——
        // 典型的**依赖执行顺序**的脆弱用例。处置是把开关**显式钉死**，不靠环境巧合；
        // `#[serial]` 只是额外的一道保险，不是判据本身。
        let _analytics_inline =
            crate::storage::sqlite::default_defer_analytics_updates_guard(false);
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);
        let conv_id = seed(&storage, agent_id);
        let new_conv = replacement();
        let id = identity();
        let pricing = PricingTable::franken_load(storage.raw()).unwrap();

        {
            let mut tx = storage.raw().transaction().unwrap();
            commit_replace_in_tx(
                &tx,
                &ReplaceCommitInput {
                    conversation_id: conv_id,
                    agent_id,
                    workspace_id: None,
                    conv: &new_conv,
                    identity: &id,
                    snapshot_root: "snap-root-abc",
                    generation: "gen-e6-0001",
                },
                &pricing,
                TS + 60_000,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        // ⚠ 「没被触碰」这件事，光比**值**是判不出来的：另一条路径（`rebuild_analytics`）
        // 会重写 message_metrics，但在这份语料上两套分桶公式给出的值恰好相同，
        // 于是「值没变」既可能是「没写」也可能是「写了一样的」——本棒实测过，
        // 照字面调 `rebuild_analytics` 的变异**不转红**。
        // 处置：往其中一行打一个**篡改标记**（`provider` 置哨兵值）。任何重写都会把它
        // 覆盖掉，于是「没被触碰」从「值相等」变成了可观测的事实。
        storage
            .raw()
            .execute_compat(
                "UPDATE message_metrics SET provider = 'sentinel-untouched'
                 WHERE message_id = (SELECT MIN(message_id) FROM message_metrics)",
                &[],
            )
            .unwrap();

        // ② 的取证面：重算**前**的 message_metrics 摘要。replace 的事务里它已经被
        // 逐消息重写过一遍（E5 语义④），这里取的是那之后的状态。
        let metrics_before = message_metrics_digest(&storage);
        assert_eq!(
            metrics_before.len(),
            2,
            "前置断言：replace 之后 message_metrics 应当是新内容的 2 行"
        );

        // 重算前三张 rollup 里还留着**旧内容**贡献的行（replace 的事务不碰它们），
        // 先证这一点，否则「重算后对了」可能只是它本来就对。
        let hourly_before = rollup_digest(&storage, "usage_hourly");
        assert!(
            hourly_before
                .iter()
                .any(|row| row.contains("|3|") || row.contains("|1|2|")),
            "前置断言：重算前 usage_hourly 应当还带着旧内容（3 条消息）的贡献，实得 {hourly_before:?}"
        );

        recompute_materialized_aggregates_after_commit(&storage).unwrap();

        // ① 五张表按新内容重算：新内容是 2 条消息（1 user + 1 assistant）。
        let hourly_after = rollup_digest(&storage, "usage_hourly");
        assert_eq!(
            hourly_after,
            vec!["codex|2|1|1|0".to_string()],
            "usage_hourly 必须只反映新内容：2 条消息 = 1 user + 1 assistant，\
             且旧内容那一条的贡献必须被**扣掉**（累加型表的重算判据就在这个「扣掉」上）"
        );
        assert_eq!(
            rollup_digest(&storage, "usage_daily"),
            vec!["codex|2|1|1|0".to_string()],
            "usage_daily 同理"
        );
        let daily_rows: Vec<String> = storage
            .raw()
            .query_map_collect(
                "SELECT CAST(day_id AS TEXT) || '/' || agent_slug || '/' || source_id || '='
                        || CAST(session_count AS TEXT) || ',' || CAST(message_count AS TEXT)
                 FROM daily_stats ORDER BY day_id, agent_slug, source_id",
                &[],
                |row| row.get_typed::<String>(0),
            )
            .unwrap();
        // `daily_stats` 是**带汇总维度**的：同一天同时有 `agent/source`、`agent/all`、
        // `all/source`、`all/all` 四行（所以不能拿 SUM 当判据 —— 那会把同一份数据数四遍，
        // 本棒第一版正是这么写的，读到 8 才发现）。逐行断言四个维度都重算到 2。
        assert_eq!(
            daily_rows,
            vec![
                "2230/all/all=1,2".to_string(),
                "2230/all/local=1,2".to_string(),
                "2230/codex/all=1,2".to_string(),
                "2230/codex/local=1,2".to_string(),
            ],
            "`daily_stats` 的四个汇总维度都必须重算到 2 条消息；留在 3 即为旧贡献没被扣掉"
        );

        // ② 全程 message_metrics 不被触碰。
        assert_eq!(
            message_metrics_digest(&storage),
            metrics_before,
            "重算全程 `message_metrics` 必须逐行不变（含那个哨兵值）—— 它是事务内逐消息写、\
             用另一套分桶公式的表，被重算路径顺手重写就等于让它被两套公式各写一遍"
        );
    }
}
