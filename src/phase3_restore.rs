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
    /// **manifest 侧的原始 provider 串**，保真到实例（如 `openclaw/<agent>`）。
    ///
    /// 这里**刻意不存 [`Origin`]**（R3 #1 / 裁定 R-E-103）。闭世界三族是为**分类可判**
    /// 存在的：`openclaw/<agent>` 折成 `Openclaw` 让 parser 选得出来。但一旦这个折叠值
    /// 被拿去当「身份的一维」参与**相等比较**，折叠掉的实例信息就变成**静默的不匹配**——
    /// manifest 侧交出 `"openclaw"`，而 DB 侧 `agents.slug` 存的是连接器契约产的
    /// `"openclaw/<inst>"`，两边永不相等。真语料实测 **1025/9488** 份 manifest 落在这个
    /// 形态上，且它们**全部带着有效 `db_links`**，`relink --apply` 会把它们清空。
    ///
    /// **存字符串、按需派生枚举**，而不是两个字段并存：并存就多一个「两者不一致」的缺陷面，
    /// 而派生让它**构造上不可能**；同时 `PartialEq`/`Ord` 自动只比字符串，
    /// **枚举从类型上就进不了相等比较**——这比靠纪律约束强一档。
    pub agent_slug: String,
    pub source_id: String,
    pub origin_host: String,
}

impl OriginNamespace {
    /// 闭世界三族，**只用于分类判定**（选 parser、判 admissible），
    /// **绝不参与任何相等比较**。未知 provider 返回 `None`（不猜、不兜底）。
    pub fn family(&self) -> Option<Origin> {
        normalize_provider_to_origin(&self.agent_slug)
    }
}

impl fmt::Display for OriginNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}@{}:{}",
            self.agent_slug, self.origin_host, self.source_id
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
    /// **候选 DB 侧**由 `reconstruct_source_jsonl_for_conversation` 重建出来的字节
    /// （裁定 R-E-57）。
    ///
    /// 加这一格而不是复用 `Sealed`/`Mirror`：本字段只作诊断（`compare_bytes_layer`
    /// 与 `select_winner` 都不读它），但**诊断字段说谎的代价会在歧义表被人读的时候才付**
    /// —— 一条标着 `Mirror` 的 DB 侧版本，会让读表的人去 mirror 里找一个不存在的东西。
    CandidateDb,
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
    /// 封存时记录的源文件 mtime；`None` = **这份 manifest 落盘时就没记**。
    ///
    /// 是 `Option` 而不是「用 0 表示没有」：`unwrap_or_default()` 把「未知」变成
    /// 一个**看起来完全正常的时刻**（epoch 0），而 winner 选择拿它判时间倒挂 ——
    /// 于是缺 mtime 的新版本被判成「比旧版本早」，合法前缀链被拒成 HOLD
    /// （R3 第 11 条 / 裁定 R-E-103 J3）。**未知就是未知，不作证据。**
    pub source_mtime_ms: Option<i64>,
    pub captured_at_ms: i64,
    /// 人工裁定材料：mirror 侧是 `blob_blake3`，sealed 侧是 payload hash。仅诊断。
    pub blob_id: String,
}

impl ContentVersion {
    /// 用**原始**字节构造：归一化在这里发生，调用方不需要（也不应该）自己先切。
    pub fn new(
        source: VersionSource,
        raw_bytes: &[u8],
        source_mtime_ms: Option<i64>,
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
    /// 下层已经**具名**的故障，原样透上来（R-E-68）。
    ///
    /// 在这一格存在之前，`SealedMessageProjector::project` 把 [`ProjectionFault`] 拍成
    /// `fault.to_string()` 就扔了，于是上层想区分「零会话投影」与其他投影失败，只剩下
    /// 匹配错误文案一条路——而错误文案是写给人看的、随时会被改写，拿它做控制流等于把
    /// 行为挂在措辞上。`mirror_seal` 分 HOLD 时为同一理由拒绝按文本分类，改读校验阶段
    /// **已经定好的具名状态**；这里是同一条纪律：下层早就具名了，别在上层重新猜一遍。
    ///
    /// `None` 表示这个投影实现没有具名故障可给（E4 的受控替身就是这样），**不表示
    /// 「没出错」**——它出现在 `Err` 里。
    pub fault: Option<ProjectionFault>,
}

impl ProjectionError {
    /// 没有具名故障可透的投影失败。
    pub fn other(detail: impl Into<String>) -> Self {
        ProjectionError {
            detail: detail.into(),
            fault: None,
        }
    }

    /// 把下层的具名故障原样带上来。`detail` 由它自己的 `Display` 产生，人机各读一格。
    pub fn from_fault(fault: ProjectionFault) -> Self {
        ProjectionError {
            detail: fault.to_string(),
            fault: Some(fault),
        }
    }

    /// 投影结果为**零**会话——`projection-empty` HOLD 的唯一判据。
    ///
    /// 只认 0。会话数为 2 是另一回事（一个文件里有多条会话），压成同一个判据会让接住它的
    /// 人以为自己在处理「这份文件不是会话」。
    pub fn is_empty_projection(&self) -> bool {
        matches!(
            self.fault,
            Some(ProjectionFault::UnexpectedConversationCount { count: 0 })
        )
    }
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
    /// winner 的字节投影出**零**条会话（输入损坏类，R-E-68）。
    ///
    /// 归到「输入损坏类」是四类闭世界（§5.2.1，第五类判非法）下的最近落点，**但类名比事实
    /// 重**：绝大多数这样的 blob 并没有坏，它们是会话树里的**非会话文件**（备份、迁移残留、
    /// agent 状态、图片）——D3 封存侧把同一批东西判成 `out-of-scope-format` HOLD（该次实测
    /// 3008 条，其中 2745 条 origin=openclaw），而 raw-mirror 捕获侧照收不误。所以真正的
    /// 根因是**捕获口径宽于处理口径**，不是字节损坏。看到这条 HOLD 的人该去核的是
    /// 「这份文件本来就不该进 mirror」，不是「磁盘坏了」。
    ProjectionEmpty,
}

impl HoldReason {
    pub const ALL: [HoldReason; 10] = [
        HoldReason::CandidateSuperset,
        HoldReason::CandidateDiverged,
        HoldReason::MultipleCandidates,
        HoldReason::ZeroVersions,
        HoldReason::VersionTimeConflict,
        HoldReason::VersionDiverged,
        HoldReason::WholeFileJsonNoPartialOrder,
        HoldReason::PayloadHashMismatch,
        HoldReason::ManifestReferenceMissing,
        HoldReason::ProjectionEmpty,
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
            HoldReason::ProjectionEmpty => "projection-empty",
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
            HoldReason::PayloadHashMismatch
            | HoldReason::ManifestReferenceMissing
            | HoldReason::ProjectionEmpty => HoldClass::InputCorruption,
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
    /// `None` = 未知。人读这份裁定材料时，「未知」与「1970-01-01」必须长得不一样。
    pub source_mtime_ms: Option<i64>,
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
    /// 输入读不动：`detail` **原样**保留读取层的措辞。
    ///
    /// 单开一档而不是塞进 `Versions { versions: vec![] }`：读不动时本来就摘不出版本
    /// 摘要，于是那一档交出的是一个**空证据**，而空证据与「查过了，没发现什么」
    /// 长得一模一样。操作者要的恰恰是那句 detail（是哪一份、哪里不对）
    /// —— R3 第 12 条点名的「丢弃 detail」就是这条（裁定 R-E-103 J3）。
    InputUnreadable { detail: String },
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
    // 分类判定用 family（这是闭世界枚举**唯一**该出现的地方）；
    // 未知 provider 走不到这里（planner 侧已按 R-E-67 具名 HOLD），保守起见按不可进处理。
    let admissible = identity
        .origin
        .family()
        .is_some_and(|family| admissible_to_version_set(family, &identity.canonical_path));
    if !admissible {
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
            // **两侧都有值才比较**（R3 第 11 条）。缺 mtime 不是「更早」的证据，
            // 它什么也不是 —— 这条交叉检查因此对它保持沉默，而不是替它编一个时刻。
            if let (Some(earlier_ms), Some(later_ms)) = (
                versions[earlier].source_mtime_ms,
                versions[later].source_mtime_ms,
            ) && earlier_ms > later_ms
            {
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
    /// 裁定人的**角色标识**。
    ///
    /// ⚠ **不得落真实人名**（R2 Finding 16）：这个字段的值会随 manifest / 台账进入
    /// **公开仓**的 diff 与测试 fixture。本仓曾在这里落过一个真名，9 条模式的隐私扫描
    /// 没抓到——因为那几条模式锚在**路径**与**账号**面，裸名不在集合里。
    /// **洞在字段不在那一次的值**：口径没钉住，下一次同样会有人顺手填真名。
    /// 用角色标识（`adj-1` / `release-owner` 这类），不用人名。
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
        // 台账里记的是**原始 provider 串**（R-E-103）：只要求它能归一到三族（分类可判），
        // 但存进身份的是原串本身，不是归一结果。
        if normalize_provider_to_origin(&agent_text).is_none() {
            return Err(LedgerError::Malformed {
                line,
                detail: format!("agent {agent_text:?} 归一不到三族"),
            });
        }
        let entry = OverrideEntry {
            identity: RestoreIdentity {
                origin: OriginNamespace {
                    agent_slug: agent_text,
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
            let text = std::str::from_utf8(bytes)
                .map_err(|e| ProjectionError::other(format!("非 UTF-8：{e}")))?;
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
            let text = std::str::from_utf8(bytes)
                .map_err(|e| ProjectionError::other(format!("非 UTF-8：{e}")))?;
            let mut out = Vec::new();
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                let v: serde_json::Value = serde_json::from_str(line)
                    .map_err(|e| ProjectionError::other(format!("行不可解：{e}")))?;
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
            Err(ProjectionError::other("投影不可用"))
        }
    }

    // -- 夹具 -------------------------------------------------------------

    fn origin(agent: Origin, host: &str) -> OriginNamespace {
        OriginNamespace {
            agent_slug: agent.as_str().to_string(),
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
        ContentVersion::new(VersionSource::Mirror, raw, Some(mtime), captured, id)
    }

    fn sealed(raw: &[u8], mtime: i64, captured: i64, id: &str) -> ContentVersion {
        ContentVersion::new(VersionSource::Sealed, raw, Some(mtime), captured, id)
    }

    /// 允许把 `source_mtime_ms` 说成**未知**的构造器（R3 第 11 条）。
    ///
    /// 单开一个而不是去改上面那两个：它们有几十个调用点，
    /// **机械改名会静默改变测试语义**，而改对的重命名和改坏的重命名长得一样。
    fn version_opt(raw: &[u8], mtime: Option<i64>, captured: i64, id: &str) -> ContentVersion {
        ContentVersion::new(VersionSource::Mirror, raw, mtime, captured, id)
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
        // 9 → 10：R-E-68 加了 `projection-empty`。**类数仍是四**（§5.2.1 的闭世界没动，
        // 新 reason 归到 input-corruption），变的只是 reason 全集的大小。这条断言是
        // 覆盖面自检，它红在这里正是它该做的事——加 reason 的人必须来这里说明一次。
        assert_eq!(seen.len(), 10);
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

    // ── R3 第 11 条 / 裁定 R-E-103 J3：**未知就是未知，不作证据** ──────
    //
    // 修前：`view.source_mtime_ms.unwrap_or_default()` 把「这份 manifest 落盘时就没记
    // mtime」变成 `0`，而 winner 选择拿它判时间倒挂 —— 于是一个**缺 mtime 的新版本**
    // 被判成「比旧版本早」，一条合法的前缀链被拒成 HOLD。
    //
    // 而 `RawMirrorManifestView::source_mtime_ms` 的 doc 明写它
    // 「**不进任何身份元组**，只作裁定材料」—— 现在它进了**判定**。按 doc 原义修：
    // `Option` 一路带到判定处，**两侧都有值才比较**。
    #[test]
    fn a_missing_mtime_on_the_later_version_is_not_read_as_an_inversion() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        // 短的（真前缀）记了 mtime；长的（后继）那份 manifest 落盘时没记。
        let short = version_opt(&jsonl(&["{\"id\":\"m1\"}"]), Some(500), 1, "s");
        let long = version_opt(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            None,
            2,
            "l",
        );
        match select_winner(&id, &[short, long], &LineProjector).unwrap() {
            // 索引 1 是那个真后继 —— 缺 mtime 不该改变序。
            WinnerOutcome::Winner { index, .. } => assert_eq!(
                index, 1,
                "winner 必须是那个真后继（索引 1），缺 mtime 不该改变序"
            ),
            other => panic!("缺 mtime 不是「时间倒挂」的证据，不得据此 HOLD，实得 {other:?}"),
        }
    }

    /// 对称的一侧：**较早那一份**缺 mtime 时同样不得判倒挂。
    #[test]
    fn a_missing_mtime_on_the_earlier_version_is_not_read_as_an_inversion() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let short = version_opt(&jsonl(&["{\"id\":\"m1\"}"]), None, 1, "s");
        let long = version_opt(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            Some(100),
            2,
            "l",
        );
        assert!(
            matches!(
                select_winner(&id, &[short, long], &LineProjector).unwrap(),
                WinnerOutcome::Winner { .. }
            ),
            "另一侧缺 mtime 同样不得被读成倒挂"
        );
    }

    /// 反方向臂：**两侧都有值**且真倒挂时，那条 HOLD 必须照旧打出来。
    /// 只把比较改成 `Option` 而忘了保留「都有值就比」，会把一道真守卫悄悄拆掉。
    #[test]
    fn a_real_inversion_with_both_mtimes_present_still_holds() {
        let id = identity(Origin::ClaudeCode, "h1", PATH);
        let short = version_opt(&jsonl(&["{\"id\":\"m1\"}"]), Some(500), 1, "s");
        let long = version_opt(
            &jsonl(&["{\"id\":\"m1\"}", "{\"id\":\"m2\"}"]),
            Some(100),
            2,
            "l",
        );
        match select_winner(&id, &[short, long], &LineProjector).unwrap() {
            WinnerOutcome::Hold(h) => assert_eq!(h.reason, HoldReason::VersionTimeConflict),
            other => panic!("两侧都有值的真倒挂必须仍然 HOLD，实得 {other:?}"),
        }
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
            "adjudicator": "adj-1",
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
        assert_eq!(e.adjudicator, "adj-1");
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
/// R-E-84 (c) 的写后前缀断言，**单独一个函数**是为了能被直接进入。
///
/// 这一格只有在 (a) 漏判时才会被走到（(a) 逐分量拒 symlink，正常形态到不了这里），
/// 所以经由 `materialize_sealed_blob` 去构造它需要一个竞态窗——那没法做成确定性判据。
/// 抽出来之后，用例可以拿一个真的「根外文件」直接问它，走的仍是生产这一条分支。
fn assert_materialized_inside_root(
    canonical_root: &Path,
    canonical_target: &Path,
) -> Result<(), ProjectionFault> {
    if canonical_target.starts_with(canonical_root) {
        return Ok(());
    }
    // **只判，不删**（R2 第 1 条 / R-E-98 H2）。原先这里 `remove_file` 掉那个文件，
    // 而 canonicalize 之后的它就是**受害者真身** —— 于是「覆盖」被升级成「覆盖+删除」。
    // 删了也换不回什么：覆盖若已发生，发生在这条断言之前（见 (c) 自己的说明），
    // 删除只是在既成损失上再加一笔，还抹掉了操作者据以定损的现场。
    Err(ProjectionFault::UnsafeOriginalPath {
        detail: format!(
            "E-SCRATCH-SYMLINK-ESCAPE: materialized file resolved to {} which is outside the \
             scratch root {} — refusing; the file was left as-is on purpose (it may not be ours, \
             and it is the evidence of what this run touched)",
            canonical_target.display(),
            canonical_root.display()
        ),
    })
}

/// 一个 inode 现在有几个名字。**非 unix 恒 1** —— 那边没有硬链接这个概念，
/// 返回 1 等于「这条判据在该平台上不发射」，而不是假装它通过了。
#[cfg(unix)]
fn hard_link_count(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;
    meta.nlink()
}

#[cfg(not(unix))]
fn hard_link_count(_meta: &std::fs::Metadata) -> u64 {
    1
}

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

    // ── R-E-84 (a)：逐分量拒 symlink ────────────────────────────────────
    //
    // `rebuild_relative_shape` 拒的是**路径字符串里的 `..`**；这里拒的是
    // **文件系统里的 symlink**。两者是两层：字符串再干净，只要落地的某一级分量是
    // 指向外面的 symlink，`create_dir_all` 与 `std::fs::write` 都会跟着走出去，
    // 而后者带截断语义——实测一次 dry-run 把 scratch 之外的既有文件
    // 从 61 字节覆盖成 378367 字节（R1 Finding 11）。
    //
    // 为什么校验从**根**开始逐级下降而不是只看最后一级：中间任何一级是 symlink
    // 就已经出去了，最后一级看起来仍然「在根下」。
    create_private_dir_all(scratch_root).map_err(|err| ProjectionFault::Materialize {
        detail: format!("create_dir_all {}: {err}", scratch_root.display()),
    })?;
    let canonical_root =
        std::fs::canonicalize(scratch_root).map_err(|err| ProjectionFault::Materialize {
            detail: format!(
                "canonicalize scratch root {}: {err}",
                scratch_root.display()
            ),
        })?;
    let mut walk = canonical_root.clone();
    let last_index = relative.components().count().saturating_sub(1);
    for (index, component) in relative.components().enumerate() {
        walk.push(component);
        let is_target = index == last_index;
        match std::fs::symlink_metadata(&walk) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(ProjectionFault::UnsafeOriginalPath {
                    detail: format!(
                        "E-SCRATCH-SYMLINK-ESCAPE: component {} under the scratch root is a \
                         symlink — refusing to materialize through it (following it would write, \
                         and possibly truncate, a file outside {})",
                        walk.display(),
                        canonical_root.display()
                    ),
                });
            }
            // ── R4 第 1 条 / 裁定 R-E-110 K1：**只拒 symlink 不够** ─────────
            //
            // `is_symlink()` 对**硬链接**报 false —— 它在 `symlink_metadata` 眼里就是一个
            // 普通文件，于是写路径的 `truncate(true)` 直接截断**共享 inode**。
            // 实测：一次 dry-run 把硬链接指向的候选库截掉并改写，**返回 Ok、零告警**。
            //
            // **比 symlink 那一支更糟**：R-E-84 (c) 的写后前缀断言拦不住它 ——
            // `canonicalize` 对硬链接返回的就是落点自己，`starts_with` 成立、断言通过。
            // symlink 至少会被这里拒或被 (c) 发现，**硬链接是完全静默的**。
            //
            // 判据用 `nlink > 1` 而不是「与受保护输入比 `(dev,ino)`」：物化路径**没有任何
            // 正当理由**写进一个被多处引用的 inode，而按受保护清单比对只挡得住清单里那几个
            // —— **漏挡一条 = 毁掉那个文件，误挡一条 = 让操作者把那个硬链接删掉**，
            // 两侧代价不对称。（`--out` / `--journal` 那条路上用的是 `(dev,ino)`，
            // 因为那里的写目标是操作者指定的、本来就该允许指向既有文件。）
            Ok(meta) if is_target && !meta.file_type().is_file() => {
                return Err(ProjectionFault::UnsafeOriginalPath {
                    detail: format!(
                        "E-SCRATCH-NOT-REGULAR-FILE: materialization target {} exists but is not \
                         a regular file ({:?}) — refusing to write through it",
                        walk.display(),
                        meta.file_type()
                    ),
                });
            }
            Ok(meta) if is_target && hard_link_count(&meta) > 1 => {
                return Err(ProjectionFault::UnsafeOriginalPath {
                    detail: format!(
                        "E-SCRATCH-NOT-REGULAR-FILE: materialization target {} is a hard link \
                         (nlink={}) — writing it would truncate every other name for that same \
                         inode, and the post-write prefix assertion cannot see that happen",
                        walk.display(),
                        hard_link_count(&meta)
                    ),
                });
            }
            // 中间分量必须是目录：既有的 symlink 判拦不住 fifo / socket / 设备节点，
            // 而 `create_dir_all` 撞上它们只会给出一句与真因隔了一层的 I/O 错。
            Ok(meta) if !is_target && !meta.file_type().is_dir() => {
                return Err(ProjectionFault::UnsafeOriginalPath {
                    detail: format!(
                        "E-SCRATCH-NOT-REGULAR-FILE: component {} under the scratch root exists \
                         but is not a directory ({:?}) — refusing to materialize through it",
                        walk.display(),
                        meta.file_type()
                    ),
                });
            }
            // 不存在 = 本轮要新建，正常；其他 stat 错误一并放行给后面的 create/write 去报，
            // 那里的错误信息更贴近真正失败的那一步。
            _ => {}
        }
    }

    let target = canonical_root.join(&relative);
    if let Some(parent) = target.parent() {
        create_private_dir_all(parent).map_err(|err| ProjectionFault::Materialize {
            detail: format!("create_dir_all {}: {err}", parent.display()),
        })?;
    }

    // ── R3 第 6 条 (belt)：逐级收紧既有目录 ─────────────────────────────
    //
    // 上面那句只管**新建**的目录。scratch 复用时，slot 目录早就在盘上了 ——
    // 它们是上一轮（或操作者自己）按 umask 建的，`mode()` 一个字节也管不到。
    // 走的是与 (a) 同一条分量序列，所以这里不会碰到根外的东西。
    {
        let mut walk = canonical_root.clone();
        tighten_dir_to_owner_only(&walk).map_err(|err| ProjectionFault::Materialize {
            detail: format!("tighten {}: {err}", walk.display()),
        })?;
        if let Some(rel_parent) = relative.parent() {
            for component in rel_parent.components() {
                walk.push(component);
                tighten_dir_to_owner_only(&walk).map_err(|err| ProjectionFault::Materialize {
                    detail: format!("tighten {}: {err}", walk.display()),
                })?;
            }
        }
    }

    write_private_scratch_file(&target, input.blob).map_err(|err| {
        ProjectionFault::Materialize {
            detail: format!("write {}: {err}", target.display()),
        }
    })?;

    // ── R-E-84 (c)：写后前缀断言兜底 ────────────────────────────────────
    //
    // (a) 是判断，判断可能有漏（竞态、我没想到的形态）。这一层直接问文件系统
    // 「刚写的这个东西最终在哪」，不在根下就删掉再拒——**兜的是 (a) 的判断漏，
    // 不是替代它**：覆盖若已发生，发生在这条断言之前，所以两层必须合用。
    let canonical_target =
        std::fs::canonicalize(&target).map_err(|err| ProjectionFault::Materialize {
            detail: format!("canonicalize materialized {}: {err}", target.display()),
        })?;
    assert_materialized_inside_root(&canonical_root, &canonical_target)?;

    let written = std::fs::metadata(&canonical_target)
        .map_err(|err| ProjectionFault::Materialize {
            detail: format!("stat back {}: {err}", canonical_target.display()),
        })?
        .len();
    if written != input.source_size_bytes {
        return Err(ProjectionFault::SealedSizeMismatch {
            manifest: input.source_size_bytes,
            blob: written,
        });
    }
    Ok(canonical_target)
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
/// 摘要的字段范围。**两侧必须用同一个 scope 才可比。**
///
/// 存在的理由是一个结构性事实（裁定 R-E-59）：**候选 DB 里没有 `invocations` 这一格**
/// —— `crate::model::types::Message` 的字段集是
/// `{id, idx, role, author, created_at, content, extra_json, snippets}`，
/// `map_to_internal` 在那一步就把 `invocations` 丢了。拿它做比较等于比一个
/// **双方都无法表达**的字段，含工具调用的会话会被判成假分叉，污染六类计数。
///
/// **`invocations` 不参与比较，损失的到底是什么（R-E-59 义务 ④）**：
/// invocation 的身份**大部分经由 `extra` 幸存** —— `COMPACT_INVARIANT_EXTRA_KEYS`
/// 里含 `tool_call_args` 与 `tool_call_id`，两者都进摘要，且 E5 的契约用例 P7 断言
/// 「args 非缺失时 `extra.tool_call_args` 与 `invocations[0].arguments` 是同一个 JSON 值」。
/// 真正落在比较之外的只有 **`kind` 与 `name`** 这一层粒度。
/// **所以这句不能被读宽成「工具调用不比了」** —— 调用参数与 call_id 照比不误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestScope {
    /// 投影侧全字段（含 `invocations`），W1-0 §B 的完整口径。
    Projection,
    /// 候选 DB 可复原的字段集：全字段**减去** `invocations`。
    CandidateComparable,
}

/// **唯一的摘要定义**（R-E-59 义务 ①）：两个 scope 共用这一个函数体，
/// 差别只有末尾那一格进不进。复制一份「候选侧专用实现」就是第二定义，
/// 而两份实现「算得一样」本身还要再验一次。
fn compact_invariant_message_digest_scoped(
    message: &franken_agent_detection::types::NormalizedMessage,
    scope: DigestScope,
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
    if matches!(scope, DigestScope::Projection) {
        field(
            "invocations",
            serde_json::to_string(&message.invocations)
                .unwrap_or_default()
                .as_bytes(),
        );
    }
    CanonicalMessageDigest(*hasher.finalize().as_bytes())
}

impl SealedMessageProjector<'_> {
    /// 投影并按指定 scope 出摘要。**trait 入口与候选可比入口共用这一条路径**
    /// —— 分解点选在这里，是为了不动本结构体的公开字段（冻结面零改动）。
    fn project_with_scope(
        &self,
        normalized_bytes: &[u8],
        scope: DigestScope,
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
            materialize_sealed_blob(&slot, &input).map_err(ProjectionError::from_fault)?;

        let conversations = scan_materialized_file(&materialized, self.agent)
            .map_err(ProjectionError::from_fault)?;
        if conversations.len() != 1 {
            // 同一个条件在下层已经具名为 `UnexpectedConversationCount`；这里复用它而不是
            // 再造一个平行说法，否则「会话数不为 1」在同一个文件里就有两套词汇。
            return Err(ProjectionError::from_fault(
                ProjectionFault::UnexpectedConversationCount {
                    count: conversations.len(),
                },
            ));
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
            .map(|m| compact_invariant_message_digest_scoped(m, scope))
            .collect())
    }
}

impl MessageSequenceProjector for SealedMessageProjector<'_> {
    fn project(
        &self,
        _origin: &OriginNamespace,
        normalized_bytes: &[u8],
    ) -> Result<Vec<CanonicalMessageDigest>, ProjectionError> {
        self.project_with_scope(normalized_bytes, DigestScope::Projection)
    }
}

/// 与候选 DB 可比的投影器：同一条投影路径，只是摘要按
/// [`DigestScope::CandidateComparable`] 取（裁定 R-E-59）。
///
/// **不是另一个投影实现**——它转调 [`SealedMessageProjector::project_with_scope`]，
/// 差别只有一个 scope 值。
pub(crate) struct CandidateComparableProjector<'a>(pub SealedMessageProjector<'a>);

impl MessageSequenceProjector for CandidateComparableProjector<'_> {
    fn project(
        &self,
        _origin: &OriginNamespace,
        normalized_bytes: &[u8],
    ) -> Result<Vec<CanonicalMessageDigest>, ProjectionError> {
        self.0
            .project_with_scope(normalized_bytes, DigestScope::CandidateComparable)
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

    /// 三个权限位取自 `symlink_metadata`（不跟随链接）：跟随链接量到的是别人的模式。
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::symlink_metadata(path)
            .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o777
    }

    /// 从 `target` 的父目录一路上溯到 `croot`，对每一级调 `f`。
    ///
    /// `include_root` 分开两个用途，**因为这两级由两套机制负责**：
    /// - **严格在根之下**的那些目录是**工具本轮新建**的 → 由「门」（`DirBuilderExt::mode`）负责；
    /// - **根自己**通常是操作者或上一轮留下的既有目录 → 只能由「belt」（事后收紧）负责。
    ///
    /// 合成一条断言会让两套机制**互相掩护**：撤掉门，belt 兜住，判据照绿。
    fn for_each_dir(target: &Path, croot: &Path, include_root: bool, mut f: impl FnMut(&Path)) {
        let mut cur = target.parent().expect("物化落点必须有父目录").to_path_buf();
        loop {
            if cur != croot || include_root {
                f(&cur);
            }
            if cur == croot {
                return;
            }
            cur = cur
                .parent()
                .expect("必须能一路上溯到 scratch 根 —— 上溯不到说明落点根本不在根下")
                .to_path_buf();
        }
    }

    // ── R3 第 6 条 / 裁定 R-E-103 J2：scratch **出生即私有** ──────────────
    //
    // R-E-90 那一轮把报告 / journal / marker 都改成「出生即 0600」，
    // **scratch 不在那张清单里** —— 而 scratch 装的恰恰是**完整会话原文**，
    // 比报告更敏感。物化用的是 `create_dir_all` + `std::fs::write`，全程不设模式，
    // 于是默认 dry-run 就按 umask（本机 0002 → 文件 0664、目录 0775）
    // 把原文写到盘上**并留存**。
    //
    // **目录一并管**：`home/u/.claude/projects/ws/` 这几级**目录名本身**就是
    // 家目录全路径与工作区名，只把文件收紧、留一棵世界可读的目录树，等于没收紧。
    // ── R4 第 1 条 / 裁定 R-E-110 K1：**只拒 symlink 不拒硬链接** ──────
    //
    // 预检用 `symlink_metadata().file_type().is_symlink()` 判，而**硬链接在它眼里
    // 就是一个普通文件** —— 于是 `create(true).truncate(true)` 直接截断**共享 inode**。
    //
    // **比 symlink 那一支更糟**：R-E-84 (c) 的写后前缀断言拦不住它 ——
    // `canonicalize` 对硬链接返回的就是落点自己，`starts_with(canonical_root)` 成立，
    // 断言通过、**整轮零错误**。symlink 至少会被 (a) 拒或被 (c) 发现，硬链接是**完全静默**的。
    //
    // 这是同族第三张脸：symlink（R1 #11 / R-E-84）→ 别名（R3 #4/#5）→ **硬链接**。
    // J2 加的 `(dev,ino)` 判只挂在 `--out` / `--journal` 的写路径校验上，
    // **物化这条路上没有同等防护**。
    //
    // **判据形状**：不止断言「返回了 Err」——断言受害文件的**字节逐位不变**。
    #[test]
    fn materialize_refuses_a_hard_linked_target_and_leaves_the_victim_byte_identical() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = scratch("r4-hardlink");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let blob = b"{\"role\":\"user\",\"text\":\"a full session transcript\"}\n";
        let input = source("/home/u/.claude/projects/ws/s.jsonl", blob);

        // 第一轮正常物化，拿到真实落点。**scratch 复用是常态**，slot 名第一轮之后
        // 就都在盘上了 —— 可达性与 R1 #11 那次完全同源。
        let target = materialize_sealed_blob(&root, &input).unwrap();

        // 受害者：scratch **之外**的一个「候选库」。
        let outside = std::env::temp_dir().join(format!(
            "cc-cass-r4-hardlink-outside-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("agent_search.db");
        let original = b"SQLite format 3\x00-- candidate db bytes that must survive a dry run --\n";
        std::fs::write(&victim, original).unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();

        // 把落点换成指向候选库的**硬链接**。
        std::fs::remove_file(&target).unwrap();
        std::fs::hard_link(&victim, &target).unwrap();
        assert!(
            !std::fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink(),
            "前置断言：硬链接在 symlink_metadata 眼里**不是** symlink —— \
             这正是既有预检漏掉它的原因，也是这条用例要证的东西"
        );

        // 第二轮：**不给 `--apply`**，这就是 dry-run 的物化那一步。
        let err = materialize_sealed_blob(&root, &input).expect_err("落点是硬链接时必须拒绝物化");
        match &err {
            ProjectionFault::UnsafeOriginalPath { detail } => assert!(
                detail.contains("E-SCRATCH-NOT-REGULAR-FILE"),
                "必须以具名错误码拒，实得：{detail}"
            ),
            other => panic!("必须走 UnsafeOriginalPath 这一档，实得 {other:?}"),
        }

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            &original[..],
            "候选库必须逐位不变 —— 拒之前已经截断了，和没拒是一回事"
        );
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644,
            "候选库的**权限**也必须不变：写路径按 fd `set_permissions(0o600)` 收紧，\
             在硬链接这条路上会作用到别人的 inode 上"
        );
        let _ = std::fs::remove_dir_all(&outside);
    }

    /// 落点存在、但**不是普通文件**（这里用目录）：必须以**具名**错误拒。
    ///
    /// 没有这道判也会失败 —— 但失败在 `open` 的 `EISDIR` 上，变成一句 `Materialize`
    /// I/O 错。**「拒了」与「以自己的名义拒」是两回事**：前者让操作者去查磁盘，
    /// 后者告诉他落点被别的东西占了。
    #[test]
    fn materialize_refuses_a_target_that_is_not_a_regular_file() {
        let root = scratch("r4-not-regular");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let blob = b"{\"role\":\"user\"}\n";
        let input = source("/home/u/.claude/projects/ws/s.jsonl", blob);

        let target = materialize_sealed_blob(&root, &input).unwrap();
        std::fs::remove_file(&target).unwrap();
        std::fs::create_dir(&target).unwrap();

        let err = materialize_sealed_blob(&root, &input).expect_err("落点是目录时必须拒");
        match &err {
            ProjectionFault::UnsafeOriginalPath { detail } => assert!(
                detail.contains("E-SCRATCH-NOT-REGULAR-FILE"),
                "必须具名拒，实得：{detail}"
            ),
            other => panic!("必须走 UnsafeOriginalPath 这一档，实得 {other:?}"),
        }
    }

    /// 落点是 **Unix 域套接字**：`nlink == 1` 且**不是**普通文件 ——
    /// 这一形态**只有**「落点必须是普通文件」那一臂挡得住。
    ///
    /// 为什么单开这一条：变异矩阵的 U2 臂（撤掉那道类型判）**没红**，复核发现
    /// **目录的 `nlink` 是 2**，于是它被隔壁那道 `nlink > 1` 顺手接住了 ——
    /// 目录用例证明不了「落点类型判」自己有牙。
    ///
    /// 为什么用套接字而不是 FIFO（**这条是被咬出来的**）：第一版用 `mkfifo`，
    /// 结果撤掉判据的那一臂**直接挂住** —— 以写打开一个没有读者的 FIFO 会阻塞，
    /// 而那正是这道判要防的危害之一。**判据本身不能是个会挂住的东西**：
    /// 一条挂住的用例与一条跑得慢的用例在报表上长得一模一样。
    /// 套接字给出同样的鉴别力（非普通文件、`nlink == 1`），而 `open` 对它
    /// **立刻**以 `ENXIO` 失败，不阻塞。
    #[test]
    fn materialize_refuses_a_socket_target() {
        let root = scratch("r4-socket");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let blob = b"{\"role\":\"user\"}\n";
        let input = source("/home/u/.claude/projects/ws/s.jsonl", blob);

        let target = materialize_sealed_blob(&root, &input).unwrap();
        std::fs::remove_file(&target).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(&target)
            .expect("必须能在落点上建出一个 Unix 域套接字");

        let meta = std::fs::symlink_metadata(&target).unwrap();
        assert!(
            !meta.file_type().is_file() && hard_link_count(&meta) == 1,
            "前置断言：套接字必须是「非普通文件且 nlink == 1」—— \
             否则它会被隔壁那道 nlink 判接住，这条用例就不鉴别任何东西了"
        );

        let err = materialize_sealed_blob(&root, &input).expect_err("落点是套接字时必须拒");
        match &err {
            ProjectionFault::UnsafeOriginalPath { detail } => assert!(
                detail.contains("E-SCRATCH-NOT-REGULAR-FILE"),
                "必须具名拒，实得：{detail}"
            ),
            other => panic!("必须走 UnsafeOriginalPath 这一档，实得 {other:?}"),
        }
    }

    /// **中间分量**存在、但不是目录（这里用普通文件）：同样要具名拒。
    ///
    /// 既有的 symlink 判拦不住这一形态，而 `create_dir_all` 撞上它只会给出一句
    /// 与真因隔了一层的 `NotADirectory`。
    #[test]
    fn materialize_refuses_a_non_directory_intermediate_component() {
        let root = scratch("r4-bad-component");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let blob = b"{\"role\":\"user\"}\n";
        let input = source("/home/u/.claude/projects/ws/s.jsonl", blob);

        let target = materialize_sealed_blob(&root, &input).unwrap();
        // 把 `ws` 那一级换成普通文件。
        let ws = target.parent().unwrap().to_path_buf();
        std::fs::remove_dir_all(&ws).unwrap();
        std::fs::write(&ws, b"not a directory\n").unwrap();

        let err = materialize_sealed_blob(&root, &input).expect_err("中间分量不是目录时必须拒");
        match &err {
            ProjectionFault::UnsafeOriginalPath { detail } => assert!(
                detail.contains("E-SCRATCH-NOT-REGULAR-FILE"),
                "必须具名拒，实得：{detail}"
            ),
            other => panic!("必须走 UnsafeOriginalPath 这一档，实得 {other:?}"),
        }
    }

    /// 反方向臂：**普通的复用落点**（`nlink == 1` 的既有普通文件）必须照常物化。
    /// 把「非常规文件即拒」写宽成「既有文件即拒」，会把 scratch 复用整个判死。
    #[test]
    fn materialize_still_rewrites_an_ordinary_reused_target() {
        let root = scratch("r4-hardlink-reverse");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let blob = b"{\"role\":\"user\",\"text\":\"a full session transcript\"}\n";
        let input = source("/home/u/.claude/projects/ws/s.jsonl", blob);

        let first = materialize_sealed_blob(&root, &input).unwrap();
        let again = materialize_sealed_blob(&root, &input)
            .expect("普通的复用落点必须照常物化 —— scratch 复用是文档写明的常态");
        assert_eq!(first, again, "内容寻址：两轮必须落在同一个位置");
        assert_eq!(std::fs::read(&again).unwrap(), &blob[..]);
    }

    #[test]
    fn materialize_writes_owner_only_files_and_dirs() {
        let root = scratch("private-birth");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let blob = b"{\"role\":\"user\",\"text\":\"a full session transcript\"}\n";
        let input = source("/home/u/.claude/projects/ws/s.jsonl", blob);
        let target = materialize_sealed_blob(&root, &input).unwrap();

        // 前置断言：内容必须真落盘了，否则下面的权限断言是在替一个空动作背书。
        assert_eq!(
            std::fs::read(&target).unwrap(),
            &blob[..],
            "前置断言：物化必须真把原文写进去了"
        );
        assert_eq!(
            mode_of(&target),
            0o600,
            "会话原文必须 owner-only，实得 {:#o}",
            mode_of(&target)
        );

        // 只断言**严格在根之下**的目录：它们是本轮由工具新建的，归「门」管。
        // 根自己归 belt 管，由下一条用例断言 —— 合在一起两套机制会互相掩护。
        let croot = std::fs::canonicalize(&root).unwrap();
        for_each_dir(&target, &croot, false, |dir| {
            assert_eq!(
                mode_of(dir),
                0o700,
                "工具新建的 scratch 目录必须**出生即** 0700（目录名本身就是家目录全路径）：\
                 {} 实得 {:#o}",
                dir.display(),
                mode_of(dir)
            );
        });
    }

    /// 阳性对照：**复用一棵被放宽过的旧 scratch**。
    ///
    /// 这条比「把 umask 调宽」更硬，走的也正是 `.mode()` **管不到**的那条路 ——
    /// `OpenOptions::mode()` 只在**真正创建**时生效，既有文件走 `truncate`
    /// 复用的是它自己的模式。而 scratch 复用是常态（物化件按内容定名，
    /// slot 目录第一轮之后就都在盘上了）。
    ///
    /// 不去动 umask 是有意的：umask 是**进程级全局状态**，在 `--lib`
    /// 这种多测试并发的二进制里改它，就是 FIND-12 那一族竞态的第三个载体。
    #[test]
    fn materialize_tightens_a_reused_scratch_left_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;
        let root = scratch("private-birth-reuse");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let blob = b"{\"role\":\"user\",\"text\":\"a full session transcript\"}\n";
        let input = source("/home/u/.claude/projects/ws/s.jsonl", blob);
        let target = materialize_sealed_blob(&root, &input).unwrap();
        let croot = std::fs::canonicalize(&root).unwrap();

        // 造出「上一轮留下的宽权限现场」。
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
        for_each_dir(&target, &croot, true, |dir| {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        });
        assert_eq!(
            mode_of(&target),
            0o666,
            "前置断言：放宽必须真生效，否则这条用例没有分辨力"
        );

        let again = materialize_sealed_blob(&root, &input).unwrap();
        assert_eq!(
            again, target,
            "前置断言：内容寻址 —— 第二轮必须落在同一个位置，否则测的不是复用"
        );

        assert_eq!(
            mode_of(&target),
            0o600,
            "复用既有文件时也必须收紧到 0600，实得 {:#o}",
            mode_of(&target)
        );
        for_each_dir(&target, &croot, true, |dir| {
            assert_eq!(
                mode_of(dir),
                0o700,
                "复用的目录同样必须收紧（这一条含 scratch 根本身 —— 它是 belt 的辖区）：\
                 {} 实得 {:#o}",
                dir.display(),
                mode_of(dir)
            );
        });
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

    // ── R-E-84 / R1 Finding 11：symlink 越界写 ────────────────────────────
    //
    // `rebuild_relative_shape` 只拒 `..`，注释还明写「否则物化会逃出 scratch 根」——
    // **但它防的是路径里的 `..`，防不了文件系统里的 symlink**。
    // `create_dir_all` 与 `std::fs::write` 都跟随 symlink，后者还带截断语义：
    // **路径清洗做在字符串层，逃逸发生在 inode 层。**
    //
    // 实测（修前）：一次 dry-run 把 scratch 之外的一个既有文件从 61 字节
    // **覆盖成 378367 字节**，退出码 0、无任何警告。
    //
    // 可达性：物化根是 `scratch/v-<内容 blake3>/`，所以在 `scratch/` 顶层放 symlink 打不中。
    // **但 slot 名在第一轮之后就都在盘上了**——scratch 复用时，把某个已知 slot 里的
    // 分量换成 symlink，下一轮就跟着走出去。scratch 复用是常态。
    #[test]
    fn materialize_refuses_to_follow_a_symlink_out_of_the_scratch_root() {
        let root = scratch("symlink-escape");
        let outside = std::env::temp_dir().join(format!(
            "cc-cass-e5-symlink-escape-outside-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();

        // scratch 之外的一个**既有**文件 —— 没有它就只能证「写出去了」，
        // 证不了更重的那半：「把别人的东西盖掉了」。
        let victim = outside.join("u").join("s.jsonl");
        std::fs::create_dir_all(victim.parent().unwrap()).unwrap();
        let original = b"outside content that must survive\n";
        std::fs::write(&victim, original).unwrap();

        // 把 scratch 里的 `home` 分量换成指向外部的 symlink（模拟复用残留）。
        let planted = root.join("home");
        let _ = std::fs::remove_dir_all(&planted);
        let _ = std::fs::remove_file(&planted);
        std::os::unix::fs::symlink(&outside, &planted).unwrap();

        let blob = b"{\"role\":\"user\"}\n";
        let input = SealedSource {
            agent: Origin::ClaudeCode,
            canonical_original_path: "/home/u/s.jsonl",
            source_size_bytes: blob.len() as u64,
            blob,
        };
        let err = materialize_sealed_blob(&root, &input)
            .expect_err("路径经由 symlink 走出 scratch 根时必须拒绝");
        match &err {
            ProjectionFault::UnsafeOriginalPath { detail } => {
                assert!(
                    detail.contains("E-SCRATCH-SYMLINK-ESCAPE"),
                    "必须以具名错误码拒，实得：{detail}"
                );
                assert!(
                    detail.contains("home"),
                    "错误要点出**是哪个分量**是 symlink，否则操作者无从下手：{detail}"
                );
            }
            other => panic!("期望 UnsafeOriginalPath，实得 {other:?}"),
        }

        // **最要紧的一条**：外部既有文件必须逐字节不变。
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            original,
            "scratch 之外的既有文件被改动 —— 这正是本条要防的事"
        );
        // 也不许在外面新建东西。
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            1,
            "scratch 之外不得多出任何条目"
        );

        std::fs::remove_file(&planted).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    // ── H2 · #1c（R-E-98 H2 / R2 第 1 条新增的那半）────────────────────
    //
    // (c) 兜底在判出逃逸时**不得删掉那个文件**。
    //
    // R-E-84 议过 TOCTOU 要不要修（裁不修，记已知加固项），**没议过兜底那句
    // `remove_file`**：它删的是 canonicalize 之后的**受害者真身**，于是「覆盖」被升级成
    // 「覆盖+删除」。而且删了也换不回什么——覆盖若已发生，发生在这条断言之前（(c) 自己
    // 的注释就这么写着），删除只是在已经造成的损失上再加一笔，还抹掉了操作者据以定损的现场。
    #[test]
    fn materialize_postwrite_assertion_refuses_without_deleting_the_victim() {
        let root = scratch("postwrite-assert");
        let canonical_root = std::fs::canonicalize(&root).unwrap();
        let outside = std::env::temp_dir().join(format!(
            "cc-cass-h2-postwrite-outside-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).unwrap();
        let victim = outside.join("victim.jsonl");
        let original = b"victim content that must survive the refusal\n";
        std::fs::write(&victim, original).unwrap();
        let canonical_victim = std::fs::canonicalize(&victim).unwrap();

        let err = assert_materialized_inside_root(&canonical_root, &canonical_victim)
            .expect_err("落在根外时必须拒");
        match &err {
            ProjectionFault::UnsafeOriginalPath { detail } => assert!(
                detail.contains("E-SCRATCH-SYMLINK-ESCAPE"),
                "必须以具名错误码拒，实得：{detail}"
            ),
            other => panic!("期望 UnsafeOriginalPath，实得 {other:?}"),
        }

        // **本条的判据**：受害者必须还在，且逐字节不变。
        assert!(
            canonical_victim.exists(),
            "兜底把受害者的文件删了 —— 那是把「覆盖」升级成「覆盖+删除」"
        );
        assert_eq!(
            std::fs::read(&canonical_victim).unwrap(),
            original,
            "受害者文件的字节被动过"
        );

        // 阳性对照：根内的目标必须放行，否则上面那条可能是恒拒的假绿。
        let inside = canonical_root.join("inside.jsonl");
        std::fs::write(&inside, b"x").unwrap();
        assert_materialized_inside_root(&canonical_root, &std::fs::canonicalize(&inside).unwrap())
            .expect("根内的目标必须放行");

        std::fs::remove_dir_all(&outside).ok();
    }

    /// 正常路径不受影响：没有 symlink 时照常物化（否则上面那条可能是恒拒的假绿）。
    #[test]
    fn materialize_still_works_when_no_component_is_a_symlink() {
        let root = scratch("symlink-negative");
        let blob = b"{\"role\":\"user\"}\n";
        let input = SealedSource {
            agent: Origin::ClaudeCode,
            canonical_original_path: "/home/u/plain.jsonl",
            source_size_bytes: blob.len() as u64,
            blob,
        };
        let target = materialize_sealed_blob(&root, &input).expect("无 symlink 时必须照常物化");
        assert!(target.starts_with(&root), "物化件必须落在 scratch 根下");
        assert_eq!(std::fs::read(&target).unwrap(), blob);
        // 复用同一 slot 再来一次也必须照常（复用是常态，不能被防护误伤）。
        materialize_sealed_blob(&root, &input).expect("复用同一 scratch 必须仍然可用");
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
            agent_slug: Origin::ClaudeCode.as_str().to_string(),
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
            Some(mtime),
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
pub(crate) enum SealedBlobOutcome {
    /// 读到了，且已通过 doctor 侧的强校验（blake3 + 长度）。
    Loaded(Vec<u8>),
    /// manifest 在、它指的 blob 不在。→ `manifest-reference-missing`。
    ReferenceMissing,
    /// blob **在**，但它的字节与 manifest 记的身份对不上 → `payload-hash-mismatch`。
    ///
    /// 与 `ReferenceMissing` 分开是因为**操作者的下一步动作不同**：一个是去找丢失的
    /// 内容，一个是这份 mirror 本身已经不可信（R3 第 12 条 / 裁定 R-E-103 J3）。
    PayloadHashMismatch { detail: String },
    /// 其余读取/校验失败。`detail` 原样保留 doctor 侧的措辞，不二次归类。
    ///
    /// ⚠ **已披露的分桶边界**：判据取自 doctor 扫描期定好的 `blob_checksum_status`，
    /// 所以「扫描时校验通过、读取时才发现字节变了」这个 TOCTOU 形态会落到这里，
    /// 而不是 `PayloadHashMismatch`。**丢的只是桶名，不是信息** —— `detail` 原样
    /// 说明发生了什么，而按错误文本反推桶名是本仓一路在拒绝的那种脆判据。
    Unreadable { detail: String },
}

/// 扫出 `data_dir` 下 raw mirror 的全部 manifest 报告（含强校验结论）。
///
/// 复用 doctor 侧的收集器而不是自己走一遍目录：manifest 的磁盘格式、校验口径、
/// 「什么叫 verified」这三件事只能有一个定义。
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
pub(crate) fn read_sealed_blob(
    data_dir: &Path,
    manifest: &crate::DoctorRawMirrorManifestReport,
) -> SealedBlobOutcome {
    if manifest.blob_checksum_status == crate::DoctorArtifactChecksumStatus::Missing {
        return SealedBlobOutcome::ReferenceMissing;
    }
    match crate::doctor_candidate_read_verified_raw_mirror_blob(data_dir, manifest) {
        Ok(bytes) => SealedBlobOutcome::Loaded(bytes),
        // 分桶同样**不匹配错误文本**，读的是 doctor 校验阶段已经定好的具名状态
        // （与上面那句分出 `ReferenceMissing` 用的是同一个字段、同一条理由）。
        Err(detail)
            if manifest.blob_checksum_status == crate::DoctorArtifactChecksumStatus::Mismatched =>
        {
            SealedBlobOutcome::PayloadHashMismatch { detail }
        }
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

/// 读不动（而不是「不在」）的封存 blob 的 HOLD 发射点（R3 第 12 条）。
///
/// 与 [`hold_for_manifest_reference_missing`] 分开的理由写在 `SealedBlobOutcome`
/// 那两个变体上：**读不到 ≠ 不存在**，两者的下一步动作不同。`reason` 由调用方从
/// 读取层的具名结论转达（`payload-hash-mismatch` / 其余输入损坏），
/// `class` 仍由 reason 静态决定，调用方无从指定。
pub fn hold_for_unreadable_sealed_blob(
    identity: RestoreIdentity,
    reason: HoldReason,
    detail: String,
) -> HoldRecord {
    debug_assert_eq!(
        reason.class(),
        HoldClass::InputCorruption,
        "这个发射点只发输入损坏类"
    );
    HoldRecord {
        identity,
        reason,
        evidence: HoldEvidence::InputUnreadable { detail },
        // 与 `manifest-reference-missing` 消费同一组字段：这条裁定读的仍是
        // 「`blob_blake3` 指向的内容」与用于定位身份的 `original_path`。
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
    use crate::storage::api::Value as ParamValue;
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

    // ── R4 第 4 条 / 裁定 R-E-110 K1：资格门绕过了规范校验器 ──────────
    //
    // `verify_mirror_blobs` 用 `std::fs::metadata`（**跟随符号链接**），不判文件类型；
    // 而**规范校验器** `raw_mirror::verify_existing_file` 明确用 `symlink_metadata`
    // 并拒 symlink blob。**同一件事在两条路径上两套口径** —— 与 R4 第 1 条同族：
    // 「一条路上有的检查，兄弟路上没有」。
    //
    // 后果：把 blob 换成指向外部同长度文件的符号链接，默认档资格照过；
    // 外部文件字节若也相同，**深度档一样照过** —— 而这份 mirror 一搬走就散了。
    #[test]
    fn qualification_refuses_a_symlinked_mirror_blob() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        let live = tmp.path().join("live");
        std::fs::create_dir_all(&data_dir).unwrap();

        let source_file = write_session(&live, "rollout-symlinked.jsonl", "drill-symlinked");
        let captured = capture(&data_dir, &source_file);

        let blob = crate::doctor_raw_mirror_root(&data_dir).join(&captured.blob_relative_path);
        let bytes = std::fs::read(&blob).unwrap();

        // 外部同长度、同字节的替身 —— 连深度档都骗得过。
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let decoy = outside.join("decoy.bin");
        std::fs::write(&decoy, &bytes).unwrap();

        std::fs::remove_file(&blob).unwrap();
        std::os::unix::fs::symlink(&decoy, &blob).unwrap();
        assert!(
            std::fs::symlink_metadata(&blob)
                .unwrap()
                .file_type()
                .is_symlink(),
            "前置断言：落点必须真是符号链接"
        );

        for depth in [MirrorVerifyDepth::Default, MirrorVerifyDepth::Deep] {
            let err = verify_mirror_blobs(&data_dir, depth)
                .expect_err("符号链接 blob 必须被资格门拒掉，与规范校验器同口径");
            assert_eq!(
                err.code(),
                "E-MIRROR-BLOB-NOT-REGULAR",
                "必须具名拒（{depth:?} 档），实得：{err}"
            );
        }
    }

    /// 反方向臂：**普通 blob** 在两档下都必须照常过，别把整道门判死。
    #[test]
    fn qualification_still_accepts_ordinary_mirror_blobs() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        let live = tmp.path().join("live");
        std::fs::create_dir_all(&data_dir).unwrap();
        let ordinary = write_session(&live, "rollout-ordinary.jsonl", "drill-ordinary");
        capture(&data_dir, &ordinary);

        for depth in [MirrorVerifyDepth::Default, MirrorVerifyDepth::Deep] {
            let v = verify_mirror_blobs(&data_dir, depth)
                .unwrap_or_else(|e| panic!("普通 blob 必须过（{depth:?} 档），实得 {e}"));
            assert!(
                v.manifests_checked >= 1,
                "前置断言：必须真检查过至少一份 manifest，否则这条臂在对空树说话"
            );
        }
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
                agent_slug: Origin::Codex.as_str().to_string(),
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
                    agent_slug: Origin::Codex.as_str().to_string(),
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
                SealedBlobOutcome::PayloadHashMismatch { detail }
                | SealedBlobOutcome::Unreadable { detail } => {
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
                    .execute(
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
            .query_opt_map(
                "SELECT last_message_idx FROM conversation_tail_state WHERE conversation_id = ?1",
                &[ParamValue::from(conv_id)],
                |row| row.get_typed(0),
            )
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
            conn.execute(
                "DELETE FROM conversation_tail_state WHERE conversation_id = ?1",
                &[ParamValue::from(conv_id)],
            )
            .unwrap();
            conn.execute(
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
            .query_all_map(
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
pub(crate) struct ReplaceCommitOutcome {
    /// 本次写入 receipt 用的幂等 key；恢复器据它判「已提交」。
    pub idempotency_key: String,
    /// 新插入的 message id（按 `conv.messages` 顺序）。
    pub inserted_message_ids: Vec<i64>,
    /// 删旧那一半的条数。**与插入条数一起进 `--apply` 的输出** ——
    /// 「替换了什么」对操作者不是可选信息。
    pub deleted_message_count: usize,
}

/// replace 分支的 `operation` 取值。**字面量集中在一处**，避免写 receipt 与查 receipt
/// 两侧各写一份字符串。
/// 幂等 key 的**版本前缀**。key 的构成一变就必须换代（R-E-103）——
/// 不换代的话，旧 receipt 与新算出来的 key 对不上会被读成「这条还没做过」而重做一遍，
/// 或者反过来被 marker 的逐项比对读成「候选被人动过」（R-E-91 立的那条理由）。
pub(crate) const IDEMPOTENCY_KEY_VERSION: &str = "v2";

/// 把一串分量拼成**无歧义**的 key 片段：每段前置它的字节长度。
///
/// R3 #2：原来的构成是 `{OP}:{snapshot_root}:{agent}@{host}:{source_id} {path}`，
/// 分隔符不转义也不框长度，于是 `(host="a:b", source_id="c")` 与
/// `(host="a", source_id="b:c")` 拼出同一个串 —— 两条不同身份共用一个幂等 key，
/// 一条的 receipt 会把另一条短路掉。带长度框之后这个面从构成上消失。
pub(crate) fn framed_key_parts(parts: &[&str]) -> String {
    let mut out = String::new();
    for part in parts {
        out.push_str(&part.len().to_string());
        out.push(':');
        out.push_str(part);
        out.push('|');
    }
    out
}

pub(crate) const REPLACE_OPERATION: &str = "mirror-restore-replace";

/// 幂等 key = `{operation}:{snapshot_root}:{identity}`。
///
/// 三条约束（接口说明 §3）：同一 identity 重跑命中同一 key；不同 snapshot root 不得
/// 共用；**必须能由崩溃后的全新进程只读重算出来** —— 所以三个组成部分全部来自入参，
/// 没有任何一项依赖内存状态或墙钟。
///
/// `RestoreIdentity` 的 `Display` 已经把 `{agent}@{host}:{source_id} {canonical_path}`
/// 拼好，这里直接用它，不在第二处重拼身份的字符串形式。
pub(crate) fn replace_idempotency_key(snapshot_root: &str, identity: &RestoreIdentity) -> String {
    format!(
        "{REPLACE_OPERATION}:{IDEMPOTENCY_KEY_VERSION}:{}",
        framed_key_parts(&[
            snapshot_root,
            &identity.origin.agent_slug,
            &identity.origin.origin_host,
            &identity.origin.source_id,
            &identity.canonical_path,
        ])
    )
}

/// 在**调用方给的事务**里跑完 replace 的整条序列。
///
/// 步骤（编号对齐接口说明 §2 的表）：
/// 2–7 交给 E5 的 `franken_replace_conversation_messages_in_tx`（两处 tail 重置、
/// 删旧、插新、两张派生表、11 列重算、tail 回写）；
/// 8 重建第三处 tail 载体；9 conversation 级字段按 §B.1.2；10 推进 generation；
/// 11 写 receipt。
pub(crate) fn commit_replace_in_tx(
    tx: &crate::storage::api::Tx<'_>,
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
        input.conversation_id,
        input.conv,
    )?;

    // 9 · conversation 级字段（§B.1.2）
    crate::storage::sqlite::franken_update_conversation_projection_fields_in_tx(
        tx,
        input.conversation_id,
        input.agent_id,
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
        deleted_message_count: replaced.deleted_message_count,
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
pub(crate) fn recompute_materialized_aggregates_after_commit(
    storage: &crate::storage::sqlite::FrankenStorage,
) -> anyhow::Result<()> {
    storage.rebuild_daily_stats()?;
    storage.rebuild_token_daily_stats()?;
    crate::storage::sqlite::franken_recompute_usage_rollups_from_message_metrics(storage)?;
    Ok(())
}

/// 新建分支的 `operation` 取值。与 replace 分支分开，两者的幂等 key 不得互相碰撞。
pub(crate) const RESTORE_NEW_OPERATION: &str = "mirror-restore-new";

/// 新建分支的幂等 key，构成与 replace 支同型（三个分量全部来自入参）。
pub(crate) fn restore_new_idempotency_key(
    snapshot_root: &str,
    identity: &RestoreIdentity,
) -> String {
    format!(
        "{RESTORE_NEW_OPERATION}:{IDEMPOTENCY_KEY_VERSION}:{}",
        framed_key_parts(&[
            snapshot_root,
            &identity.origin.agent_slug,
            &identity.origin.origin_host,
            &identity.origin.source_id,
            &identity.canonical_path,
        ])
    )
}

/// `commit_restore_new` 的入参。**没有 `conversation_id`** —— 这一支的会话还不存在，
/// 「保留原 ID」在这里无定义（裁定 R-E-44）。
pub(crate) struct RestoreNewCommitInput<'a> {
    pub agent_id: i64,
    pub workspace_id: Option<i64>,
    pub conv: &'a crate::model::types::Conversation,
    pub identity: &'a RestoreIdentity,
    pub snapshot_root: &'a str,
    pub generation: &'a str,
}

/// `commit_restore_new` 的产出。
///
/// **三态，不是两态**（FIND-7 / 裁定 R-E-76）：修前只有一格 `applied`，值是
/// 「receipt 查不到」的同义反复 —— 它描述的是**本函数决定去做什么**，而不是
/// **库里实际发生了什么**。存储层按内容判定这条会话已经在库里、一行都没插时，
/// 修前照样报 `applied: true`，编排层据此报出没发生过的工作量。
pub(crate) struct RestoreNewCommitOutcome {
    pub idempotency_key: String,
    /// `true` = 本次真的**在库里新建了一条会话行**（据
    /// `InsertOutcome::conversation_inserted` 判）。
    ///
    /// **这一格是库侧事实，不是流程状态。** 它回答的是「库里多了一行吗」，
    /// **不是**「这次没走短路 / 流程跑完了吗」—— 后者是修前的旧语义，也正是
    /// FIND-7 的病根：流程走完 ≠ 工作发生。想知道「本次有没有真的动手」，
    /// 看 `applied || deduplicated`；想知道「这条恢复动作做完了没有」，
    /// 看 receipt，不看这里。
    pub applied: bool,
    /// `true` = 插入调用**真的执行了**，但存储层按**内容**判定这条会话已在库里，
    /// 一条会话行都没新建。
    ///
    /// **与 `applied` 互斥**。两者同为 `false` 的唯一情形是 receipt 已存在的短路
    /// —— 那时连插入调用都没发生。
    pub deduplicated: bool,
    /// 本次**真实插入**的消息条数（`InsertOutcome::inserted_indices` 的长度），
    /// **不是 `conv.messages.len()`**。去重命中时通常为 0；但「会话已在库、尾部
    /// 有新消息」时可以非 0，那些是真写进去的行。
    pub messages_inserted: usize,
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
            deduplicated: false,
            messages_inserted: 0,
        });
    }

    // 第一个原子步：基线入口自带事务。重跑时既有行被去重路径收敛。
    //
    // **返回值必须接住**（FIND-7 / R-E-76）：这个入口对「会话已在库」的处理是
    // **按内容去重后收敛**，而不是报错 —— 所以「调用没出错」离「库里多了一行」
    // 还差一整个判断。`conversation_inserted` 与 `inserted_indices` 才是库侧
    // 实际发生了什么的唯一凭据。
    let insert_outcomes = storage.insert_conversations_batched(&[(
        input.agent_id,
        input.workspace_id,
        input.conv,
    )])?;
    let insert_outcome = insert_outcomes.first().ok_or_else(|| {
        anyhow::anyhow!(
            "insert_conversations_batched returned no outcome for a one-conversation batch \
             — refusing to report a restore that cannot be accounted for"
        )
    })?;
    let conversation_inserted = insert_outcome.conversation_inserted;
    let messages_inserted = insert_outcome.inserted_indices.len();

    // ── E7 的崩溃注入点（env 门控，生产路径 env 未设即 no-op；形态同 E3 的
    // `relink_pause_if_requested`，裁定放行）───────────────────────────────
    //
    // **这个位置就是本支唯一的真实崩溃窗**：插入已提交、receipt 还没写。注入点只能在
    // 函数体内部 —— 让编排层把这两半拆开自己调，等于给 E6 的语义造第二份定义。
    // 本行不改变任何语义，只让「插了没记」这个窗可以被真 SIGKILL 打中。
    restore_pause_if_requested("restore-new-inserted-not-receipted");

    // 第二个原子步：generation 与 receipt 一起提交 —— 它们之间不能再有窗，
    // 否则会出现「代际已推进、却查不到 receipt」这种更难判读的状态。
    let tx = storage.raw().transaction()?;
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
        applied: conversation_inserted,
        deduplicated: !conversation_inserted,
        messages_inserted,
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
    use crate::storage::api::Value as ParamValue;
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
                agent_slug: Origin::Codex.as_str().to_string(),
                source_id: "local".into(),
                origin_host: "fixture-host".into(),
            },
            canonical_path: "/fixtures/e6.jsonl".into(),
        }
    }

    fn scalar_i64(storage: &FrankenStorage, sql: &str, id: i64) -> Option<i64> {
        storage
            .raw()
            .query_opt_map(sql, &[ParamValue::from(id)], |row| row.get_typed(0))
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

    /// 与 `conversation_titled` 同形，但**外部 id 可指定** —— K2 的两条用例
    /// 全靠「投影重算出的 `external_id` 与库里旧值不同」这一形态。
    fn conversation_with_external_id(
        external_id: &str,
        title: &str,
        messages: Vec<Message>,
    ) -> Conversation {
        let mut conv = conversation_titled(title, messages);
        conv.external_id = Some(external_id.to_owned());
        conv
    }

    fn lookup_keys_for(storage: &FrankenStorage, conversation_id: i64) -> Vec<String> {
        storage
            .raw()
            .query_all_map(
                "SELECT lookup_key FROM conversation_external_tail_lookup \
                 WHERE conversation_id = ?1 ORDER BY lookup_key",
                &[ParamValue::from(conversation_id)],
                |row| row.get_typed(0),
            )
            .unwrap()
    }

    // ── R4 第 2 条 / 裁定 R-E-110 K2：身份的一部分没跟着走 ────────────
    //
    // Replace 重算了整份投影，却**从不把重算出来的 `external_id` 写回**：
    // `franken_update_conversation_projection_fields_in_tx` 的 `UPDATE` 列表里没有它。
    // 而 `phase3_restore.rs` 开头明写 `external_id` 是**写入身份四元组**之一
    // （`source_id` / `agent_slug` / `external_id` / `original_path`）。
    //
    // 后果：库里留着**旧**的外部 id，下一次正常摄入按**新**的 id 去查 —— 查不到，
    // 于是插一条重复的。与 R2 第 4 条「查候选绑三维、发布只绑一维」同型。
    #[test]
    fn e6_replace_writes_back_the_recomputed_external_id() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);

        // 库里那条是「旧口径」的外部 id。
        let legacy = conversation_with_external_id(
            "projects/ws/legacy-uuid.jsonl",
            "旧标题",
            vec![
                message(0, MessageRole::User, "旧 0"),
                message(1, MessageRole::Assistant, "旧 1"),
            ],
        );
        storage
            .insert_conversations_batched(&[(agent_id, None, &legacy)])
            .unwrap();
        let conv_id: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM conversations WHERE external_id = ?1",
                &[ParamValue::from("projects/ws/legacy-uuid.jsonl")],
                |row| row.get_typed(0),
            )
            .unwrap();

        // 投影重算出的是「现口径」的 id。
        let projected = conversation_with_external_id(
            "ws/legacy-uuid.jsonl",
            "新标题",
            vec![
                message(0, MessageRole::User, "新 0"),
                message(1, MessageRole::Assistant, "新 1"),
            ],
        );

        let pricing = PricingTable::franken_load(storage.raw()).unwrap();
        {
            let mut tx = storage.raw().transaction().unwrap();
            commit_replace_in_tx(
                &tx,
                &ReplaceCommitInput {
                    conversation_id: conv_id,
                    agent_id,
                    workspace_id: None,
                    conv: &projected,
                    identity: &identity(),
                    snapshot_root: "k2-root",
                    generation: "k2-gen",
                },
                &pricing,
                TS,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let stored: Option<String> = storage
            .raw()
            .query_row_map(
                "SELECT external_id FROM conversations WHERE id = ?1",
                &[ParamValue::from(conv_id)],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(
            stored.as_deref(),
            Some("ws/legacy-uuid.jsonl"),
            "重算出来的 external_id 必须写回 —— 它是写入身份四元组之一，\
             留旧值会让下一次正常摄入查不到这行、插一条重复的"
        );
    }

    /// 反方向臂 ①：投影**没有**外部 id 时，库里既有的值**不得被抹成 NULL**。
    ///
    /// 这条缺陷说的是「别留旧的」，不是「宁可没有」——把已有的身份信息抹掉，
    /// 是在让下一次摄入更查不到，而不是更查得到。
    #[test]
    fn e6_replace_does_not_wipe_an_existing_external_id_when_the_projection_has_none() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);
        let legacy = conversation_with_external_id(
            "projects/ws/keep-me.jsonl",
            "旧标题",
            vec![
                message(0, MessageRole::User, "旧 0"),
                message(1, MessageRole::Assistant, "旧 1"),
            ],
        );
        storage
            .insert_conversations_batched(&[(agent_id, None, &legacy)])
            .unwrap();
        let conv_id: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM conversations WHERE external_id = ?1",
                &[ParamValue::from("projects/ws/keep-me.jsonl")],
                |row| row.get_typed(0),
            )
            .unwrap();

        let mut projected = conversation_titled(
            "新标题",
            vec![
                message(0, MessageRole::User, "新 0"),
                message(1, MessageRole::Assistant, "新 1"),
            ],
        );
        projected.external_id = None;

        let pricing = PricingTable::franken_load(storage.raw()).unwrap();
        {
            let mut tx = storage.raw().transaction().unwrap();
            commit_replace_in_tx(
                &tx,
                &ReplaceCommitInput {
                    conversation_id: conv_id,
                    agent_id,
                    workspace_id: None,
                    conv: &projected,
                    identity: &identity(),
                    snapshot_root: "k2-root",
                    generation: "k2-gen",
                },
                &pricing,
                TS,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let stored: Option<String> = storage
            .raw()
            .query_row_map(
                "SELECT external_id FROM conversations WHERE id = ?1",
                &[ParamValue::from(conv_id)],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(
            stored.as_deref(),
            Some("projects/ws/keep-me.jsonl"),
            "投影没有外部 id 时不得抹掉库里既有的值"
        );
    }

    /// 反方向臂 ②：新 id 被**另一行**占着时，必须死在一句说得清的话上。
    ///
    /// `UNIQUE(source_id, agent_id, external_id)` 会挡住它，但裸的约束错误
    /// 让操作者分不出「哪两行在抢」。两行同时声称一份写入身份是**数据完整性状况**，
    /// 不是这次 replace 可以顺手糊过去的东西。
    #[test]
    fn e6_replace_refuses_to_take_an_external_id_another_row_already_holds() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);

        let mut squatter = conversation_with_external_id(
            "ws/contested.jsonl",
            "占位的那条",
            vec![message(0, MessageRole::User, "占位")],
        );
        squatter.source_path = std::path::PathBuf::from("/fixtures/e6-squatter.jsonl");
        let legacy = conversation_with_external_id(
            "projects/ws/contested.jsonl",
            "旧标题",
            vec![
                message(0, MessageRole::User, "旧 0"),
                message(1, MessageRole::Assistant, "旧 1"),
            ],
        );
        storage
            .insert_conversations_batched(&[(agent_id, None, &squatter), (agent_id, None, &legacy)])
            .unwrap();
        let conv_id: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM conversations WHERE external_id = ?1",
                &[ParamValue::from("projects/ws/contested.jsonl")],
                |row| row.get_typed(0),
            )
            .unwrap();

        let projected = conversation_with_external_id(
            "ws/contested.jsonl",
            "新标题",
            vec![
                message(0, MessageRole::User, "新 0"),
                message(1, MessageRole::Assistant, "新 1"),
            ],
        );
        let pricing = PricingTable::franken_load(storage.raw()).unwrap();
        let mut tx = storage.raw().transaction().unwrap();
        let err = commit_replace_in_tx(
            &tx,
            &ReplaceCommitInput {
                conversation_id: conv_id,
                agent_id,
                workspace_id: None,
                conv: &projected,
                identity: &identity(),
                snapshot_root: "k2-root",
                generation: "k2-gen",
            },
            &pricing,
            TS,
        )
        .err()
        .expect("外部 id 被别的行占着时必须拒");
        assert!(
            err.to_string().contains("E-EXTERNAL-ID-CLASH"),
            "必须以具名错误码拒，实得：{err}"
        );
        drop(tx);
    }

    /// 外部键缓存里那条挂在**旧键**上的行必须被清掉。
    ///
    /// 留着它不是「多一行缓存」：日后若有另一条会话正当地取到那个旧 id，
    /// 它会从这张表里读到**别人的** tail 状态 —— 一个**错的答案**，
    /// 而不是一次回落。
    #[test]
    fn e6_replace_drops_the_stale_external_tail_lookup_row() {
        let dir = TempDir::new().unwrap();
        let (storage, agent_id) = open(&dir);

        let legacy = conversation_with_external_id(
            "projects/ws/legacy-uuid.jsonl",
            "旧标题",
            vec![
                message(0, MessageRole::User, "旧 0"),
                message(1, MessageRole::Assistant, "旧 1"),
            ],
        );
        storage
            .insert_conversations_batched(&[(agent_id, None, &legacy)])
            .unwrap();
        // 第二批走 append 分支，这一步才会写 `conversation_external_tail_lookup`。
        let grown = conversation_with_external_id(
            "projects/ws/legacy-uuid.jsonl",
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
                &[ParamValue::from("projects/ws/legacy-uuid.jsonl")],
                |row| row.get_typed(0),
            )
            .unwrap();
        let before = lookup_keys_for(&storage, conv_id);
        assert!(
            before
                .iter()
                .any(|k| k.contains("projects/ws/legacy-uuid.jsonl")),
            "前置断言：旧键那一行必须先真的在，否则这条用例在对空表说话。实得 {before:?}"
        );

        let projected = conversation_with_external_id(
            "ws/legacy-uuid.jsonl",
            "新标题",
            vec![
                message(0, MessageRole::User, "新 0"),
                message(1, MessageRole::Assistant, "新 1"),
            ],
        );
        let pricing = PricingTable::franken_load(storage.raw()).unwrap();
        {
            let mut tx = storage.raw().transaction().unwrap();
            commit_replace_in_tx(
                &tx,
                &ReplaceCommitInput {
                    conversation_id: conv_id,
                    agent_id,
                    workspace_id: None,
                    conv: &projected,
                    identity: &identity(),
                    snapshot_root: "k2-root",
                    generation: "k2-gen",
                },
                &pricing,
                TS,
            )
            .unwrap();
            tx.commit().unwrap();
        }

        let after = lookup_keys_for(&storage, conv_id);
        assert!(
            !after
                .iter()
                .any(|k| k.contains("projects/ws/legacy-uuid.jsonl")),
            "挂在旧外部 id 上的缓存行必须被清掉 —— 留着它会给日后正当取到那个 id 的\
             另一条会话一个**错的答案**。实得 {after:?}"
        );
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
            .query_opt_map(
                "SELECT value FROM meta WHERE key = ?1",
                &[ParamValue::from(
                    crate::storage::sqlite::SOURCE_CONTENT_GENERATION_META_KEY,
                )],
                |row| row.get_typed(0),
            )
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
            .query_opt_map(
                "SELECT value FROM meta WHERE key = ?1",
                &[ParamValue::from(
                    crate::storage::sqlite::SOURCE_CONTENT_GENERATION_META_KEY,
                )],
                |row| row.get_typed(0),
            )
            .unwrap()
            .flatten();
        assert_eq!(generation, None, "generation 必须一起回滚");
    }

    // ── R-E-80′ / R1 Finding 3：身份必须整条参与候选查询 ──────────────────
    //
    // 缺陷原样：`candidate_versions_from_db` 只绑 `canonical_path`，把 `identity.origin`
    // 整个丢掉。而 `OriginNamespace` 的 doc 正上方就写着「必须是**带 host 的命名空间**，
    // 否则 §5.2.1 点名的『跨 host 同路径不折叠』做不到」——**类型被特意设计成带 host 的
    // 命名空间，用的时候却只取了路径那一半。**
    //
    // 可达性不是假想：真语料 5491 个去重路径里有 **83 个**带多于一个 origin，
    // 且 83/83 差在 **agent** 这一维。最重的后果是跨来源静默覆盖
    // （A 的行被当成 B 的候选，判成 replace 后用 B 的内容盖掉 A）。
    #[test]
    fn e6_candidate_lookup_does_not_fold_two_agents_sharing_one_path() {
        let dir = TempDir::new().unwrap();
        let storage = FrankenStorage::open(&dir.path().join("fold.sqlite")).unwrap();

        // 同一条 source_path、同一个 source_id，**两个不同 agent** 各一条会话。
        const SHARED_PATH: &str = "/fixtures/shared-by-two-agents.jsonl";
        let mut ids = Vec::new();
        for (slug, agent) in [
            ("codex", Origin::Codex),
            ("claude_code", Origin::ClaudeCode),
        ] {
            let agent_id = storage
                .ensure_agent(&Agent {
                    id: None,
                    slug: slug.into(),
                    name: slug.into(),
                    version: None,
                    kind: AgentKind::Cli,
                })
                .unwrap();
            let conv = {
                let mut c = conversation_titled(
                    slug,
                    vec![message(0, MessageRole::User, &format!("{slug} 的内容"))],
                );
                c.agent_slug = slug.into();
                c.external_id = Some(format!("{slug}-external"));
                c.source_path = std::path::PathBuf::from(SHARED_PATH);
                c
            };
            storage
                .insert_conversations_batched(&[(agent_id, None, &conv)])
                .unwrap();
            ids.push((agent, slug));
        }

        // 前置断言：库里确实是**两条**共用同一路径 —— 否则本用例在测一个不存在的形态。
        let at_path: Option<i64> = storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM conversations WHERE source_path = ?1",
                &[ParamValue::from(SHARED_PATH)],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(
            at_path,
            Some(2),
            "前置断言：必须真有两条会话共用同一路径，否则折叠测不出来"
        );

        // 每个 agent 的身份都只该取到**自己那一条**。
        for (agent, slug) in ids {
            let identity = RestoreIdentity {
                origin: OriginNamespace {
                    agent_slug: agent.as_str().to_string(),
                    source_id: "local".into(),
                    origin_host: "fixture-host".into(),
                },
                canonical_path: SHARED_PATH.into(),
            };
            let got = candidate_versions_from_db(&storage, &identity).unwrap();
            assert_eq!(
                got.len(),
                1,
                "{slug} 的身份必须恰取到它自己那一条；取到 2 条 = 两个 agent 被折叠成了一条身份"
            );
        }
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
            .execute("DELETE FROM operation_commit_receipt", &[])
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
        // `applied` 修后据实判「库里真新建了一行」（FIND-7 / R-E-76），而重做撞上的
        // 正是**去重收敛**那条路径：插入调用真的又跑了一遍，存储层按内容判定这条会话
        // 已经在库里。所以这里断言的是 `deduplicated` —— 它同时证到两件事：
        // ① **没有**走 receipt 短路（短路时 `applied` 与 `deduplicated` 同为 false）；
        // ② 重做没有建出第二条会话。下面三条计数断言把「不重不漏」补完。
        assert!(
            !redo.applied && redo.deduplicated,
            "查不到 receipt 就必须重做（不能当已完成跳过），而重做必然被内容去重收敛 —— \
             实得 applied={} deduplicated={}",
            redo.applied,
            redo.deduplicated
        );
        assert_eq!(
            redo.messages_inserted, 0,
            "重做一条消息都不该真插入 —— 报数必须与库侧实际发生的事一致"
        );

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
        // 三态的不变量（FIND-7 / R-E-76）：短路 = 连插入调用都没发生，
        // 所以 `deduplicated` 也必须是 false。把它写成 `!applied` 的话这条即红 ——
        // 那样会让「什么都没做」被报成「去重收敛了一条」，又是一次凭空的工作量。
        assert!(
            !second.deduplicated,
            "短路态不是去重态：一次插入调用都没发生，不许占 `deduplicated` 这一格"
        );
        assert_eq!(second.messages_inserted, 0, "短路态不许报出插入条数");

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
            .query_all_map(
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
            .query_all_map(
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
            .execute(
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
            .query_all_map(
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

// ===========================================================================
// E7 · restore 的七态 journal 与恢复器（plan Task E7 Step 1/2）
//
// 状态集 = spec §5.2.5 的七态，**不新增第八态**：`closure-verified` 即终态，
// 写 commit marker 是它之上的幂等动作（Step 3）。
//
// 三条承重纪律（详见 run root 的 `e7-journal-state-machine.md`）：
//   · **journal 是「计划与进度」的真源，receipt 是「DB 事务是否已提交」的真源**；
//     两者合起来才唯一确定恢复动作。
//   · `planned` **且无 receipt** → **重放事务**（§5.2.5 原文）。⚠ 与 E3 relink 的
//     「不做半步恢复」**相反**，不得跨任务搬运：relink 崩在计划态什么都不做也不丢东西，
//     restore 的计划是**还没做的写库工作**，不重放 = 把这批会话永久丢掉。
//   · 状态已过 `db-committed` 却查不到 receipt = 两个真源互相矛盾 → **硬失败，不猜**。
//
// journal 落 run root 之外由调用方指定的文件（0600），**不落库**；落库的只有 receipt，
// 且与 DB 动作同事务（replace 支）或紧随其后的小事务（restore-new 支，见 R-E-47）。
// ---------------------------------------------------------------------------

/// §5.2.5 七态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RestoreJournalState {
    Planned,
    DbCommitted,
    ReadinessInvalidated,
    EmbeddingsInvalidated,
    AnalyticsRebuilt,
    ManifestPartial,
    ClosureVerified,
}

impl RestoreJournalState {
    /// 单调序号。恢复器用它判「这一格做没做过」，**不用来定义状态集**。
    fn rank(self) -> u8 {
        match self {
            RestoreJournalState::Planned => 0,
            RestoreJournalState::DbCommitted => 1,
            RestoreJournalState::ReadinessInvalidated => 2,
            RestoreJournalState::EmbeddingsInvalidated => 3,
            RestoreJournalState::AnalyticsRebuilt => 4,
            RestoreJournalState::ManifestPartial => 5,
            RestoreJournalState::ClosureVerified => 6,
        }
    }
}

/// 计划里每条身份的动作。**由 planner 决定并落进 journal**——恢复器**不重新判定**：
/// 恢复时库已经变了（部分已提交），重跑关系判定会把已完成项判成 `Skip` 而静默丢工作。
/// journal 是「计划与进度」的真源，计划本身就该在里面。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub(crate) enum PlannedAction {
    RestoreNew,
    Replace { conversation_id: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RestorePlanItem {
    /// 只存 manifest_id：**写什么**由磁盘上的封存件重新推导，不在 journal 里落第二份。
    pub manifest_id: String,
    pub action: PlannedAction,
}

/// 一次 restore 运行的计划（planner 产出，E8 的 CLI 是它未来的真调用方）。
pub(crate) struct RestoreRunPlan {
    pub operation_id: String,
    pub data_dir: PathBuf,
    pub scratch_dir: PathBuf,
    pub db_path: PathBuf,
    /// W1 commit marker 的落点。**文件单源**（裁定 R-E-51）；DB 侧不落第二份。
    pub marker_path: PathBuf,
    pub snapshot_root: String,
    pub generation: String,
    pub planned: Vec<RestorePlanItem>,
    /// 本轮的 HOLD 条数与 origin-unmapped 条数（R-E-79 (a) 条件 4）。
    /// **来源必须是同一次 run 的 report**，不是事后另数一遍——另数一遍就是第二定义，
    /// 而两份「数得一样」本身还要再验一次。
    pub holds_count: i64,
    pub origin_unmapped_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RestoreJournal {
    /// 先于一切字段被校验（见 `restore_journal_read`）。
    pub schema_version: i64,
    pub operation_id: String,
    pub state: RestoreJournalState,
    pub data_dir: PathBuf,
    pub scratch_dir: PathBuf,
    pub db_path: PathBuf,
    pub marker_path: PathBuf,
    pub snapshot_root: String,
    pub generation: String,
    pub planned: Vec<RestorePlanItem>,
    /// 随计划一起落盘的两个计数（R-E-79 (a)）。**不给 `serde(default)`**：
    /// 缺省会把旧 journal 读成「零 HOLD」，与 marker 那边同一个理由。
    /// 代价是跨版本恢复一份旧 journal 会解析失败——那是**要的**行为，
    /// 静默报零比明确失败糟得多。
    pub holds_count: i64,
    pub origin_unmapped_count: i64,
    /// 已确认提交的 manifest_id（进度）。
    pub committed: Vec<String>,
    /// 已完成 db_links publish 的 manifest 相对路径（差集续做用）。
    pub published: Vec<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RestoreRunOutcome {
    /// 真的在库里**新建了会话行**的条数。
    pub restored: usize,
    /// 插入真的执行了、但被存储层按**内容**去重的条数（FIND-7 / R-E-76）。
    /// **绝不并入 `restored`** —— 并进去就等于报出没发生过的工作量。
    pub deduplicated: usize,
    /// 本轮**跳过**的条数：查到 receipt，判「已提交」直接短路（R-E-83 / R1 Finding 9）。
    ///
    /// 加这一格的理由与 `deduplicated` 同源：**处置的种类比计数器的格子多。**
    /// 修前这条分支 `continue` 时 `outcome` 一格没动，于是归宿守恒式
    /// `restored + replaced + deduplicated == planned` 在**恢复路径上直接断裂**
    /// ——恢复一轮全是已提交项时左边是 0、右边是 planned。
    /// 而那条等式正是 runbook 给操作者的对账判据，**恢复路径恰恰是最需要对账的时候**。
    pub already_committed: usize,
    pub replaced: usize,
    pub published: usize,
    /// 发布出去了、但**没能给它配上 backlink** 的份数（R-E-98 H1 / R2 第 4 条）。
    ///
    /// 加这一格与 `deduplicated` / `already_committed` 同源：**处置的种类比计数器的
    /// 格子多**。查不到候选行本身不必然是错 —— 内容去重把行收敛到另一条 `source_path`
    /// 上时就查不到，而那是 FIND-7 / R-E-76 已裁定的合法归宿。所以口径不是硬失败，
    /// 是记账：修前这种情形照发布、照计入 `published`，操作者读到的是「都发布好了」，
    /// 而那几份 manifest 的回链其实是空的。
    pub published_without_backlink: usize,
    /// 本次写下的 receipt 幂等 key。**操作者据它去 DB 里对账**，
    /// 也是「哪几条真的提交了」的唯一可查凭据。
    pub receipt_keys: Vec<String>,
    pub messages_inserted: usize,
    pub messages_deleted: usize,
}

pub(crate) fn restore_journal_from_plan(plan: RestoreRunPlan) -> RestoreJournal {
    RestoreJournal {
        schema_version: RESTORE_JOURNAL_SCHEMA_VERSION,
        operation_id: plan.operation_id,
        state: RestoreJournalState::Planned,
        data_dir: plan.data_dir,
        scratch_dir: plan.scratch_dir,
        db_path: plan.db_path,
        marker_path: plan.marker_path,
        snapshot_root: plan.snapshot_root,
        generation: plan.generation,
        planned: plan.planned,
        holds_count: plan.holds_count,
        origin_unmapped_count: plan.origin_unmapped_count,
        committed: Vec::new(),
        published: Vec::new(),
    }
}

// ── fsync 顺序的可观测化 ────────────────────────────────────────────────
//
// §5.2.5 写死：写临时文件 → `fsync` 文件 → `rename` → `fsync` 目录 → 再推进 journal。
// 顺序在进程内不可观测（strace 旁证按 R-E-18 移到 E9 的 CLI 真跑），所以在写路径上
// 埋一条 **cfg(test) 记录带**：release 下是 `#[inline]` 空函数，零成本；测试下推进
// 线程局部序列，用例逐项断言。被断言的就是生产路径自己走过的那几步，不是影子实现。

#[cfg(test)]
thread_local! {
    static RESTORE_JOURNAL_TRACE: std::cell::RefCell<Vec<&'static str>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn journal_trace(step: &'static str) {
    RESTORE_JOURNAL_TRACE.with(|t| t.borrow_mut().push(step));
}

#[cfg(not(test))]
#[inline]
fn journal_trace(_step: &'static str) {}

#[cfg(test)]
pub(crate) fn journal_trace_take() -> Vec<&'static str> {
    RESTORE_JOURNAL_TRACE.with(|t| std::mem::take(&mut *t.borrow_mut()))
}

/// 本进程内单调递增的临时文件序号（FIND-10 / 裁定 R-E-87）。
static PRIVATE_TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 给 `final_path` 造一个**本次调用独占**的同目录临时路径。
///
/// 修前是 `final_path.with_extension("tmp")` —— **固定且可预测**：
/// ① 两个并发写者会写进同一个 inode，`write_all` 交错出撕裂的字节
///    （实测 2000 轮里 63% 的「成功」发布，盘上是不可解析的内容）；
/// ② 一个与本操作毫无关系、只是恰好同名的既有文件会被 `File::create` 无条件截断并
///    rename 走，字节不可恢复。
///
/// 名字里同时带 **pid** 与**进程内序号**：前者分开不同进程，后者分开同进程内的并发调用。
pub(crate) fn unique_sibling_tmp_path(final_path: &Path) -> anyhow::Result<PathBuf> {
    let name = final_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("cannot derive a tmp path for {}", final_path.display()))?
        .to_string_lossy()
        .into_owned();
    let seq = PRIVATE_TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(final_path.with_file_name(format!("{name}.tmp.{}.{seq}", std::process::id())))
}

/// **创建时即私有**地新建一个文件（FIND-14 / 裁定 R-E-90）。
///
/// 修前的形态是「先建、先写满、再 chmod 0600」，于是产物在窗口里以 umask 决定的模式
/// 挂在盘上（本机 umask 0002 → **0664，同组可读可写、其他人可读**）。
/// **「窗口很短」不是辩护**：POSIX 的权限检查发生在 `open()` 那一刻，之后只认描述符 ——
/// 窗口里被 open 到的 fd **不会因为随后的 chmod 或 rename 而失效**，而 rename 不换 inode，
/// 那个 fd 指的就是最终产物。所以唯一站得住的修法是创建时就带上 0600。
///
/// `create_new` 同时兑现 R-E-87 的另一半：**不复用、也不截断任何既有文件**。
/// 目录**出生即私有**（R3 第 6 条 / 裁定 R-E-103 J2）。
///
/// R-E-90 那一轮只覆盖了报告 / journal / marker 三件产物，**scratch 不在那张清单里** ——
/// 而 scratch 装的是**完整会话原文**，连 `home/u/.claude/projects/<ws>/` 这几级
/// 目录名本身都是家目录全路径与工作区名。
///
/// 与 `lib.rs` 的 `doctor_forensic_create_private_dir_all` **不是误重复**：那一份只收紧
/// **末级**目录并拒 symlink（取证目录是一层），这里要的是**逐级**（物化路径有好几级，
/// 而中间任何一级宽着，目录名就摊开给别人看了），拒 symlink 那半也已由
/// `materialize_sealed_blob` 的 R-E-84 (a) 逐分量预检负责，不在这里做第二定义。
fn create_private_dir_all(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(path)
}

/// **belt**：把一个**既有**目录收紧到 0700。
///
/// `DirBuilder::mode()` 只在真正创建时生效 —— 而 scratch 复用是常态
/// （物化件按内容定名，slot 目录第一轮之后就都在盘上了），那条路上
/// 「出生即 0700」对既有目录根本不成立。**belt 不是门**：门是 `mode(0o700)`。
///
/// 落点是符号链接时**原地返回**：`set_permissions` 会跟随链接，跟着走就是去改别人的模式。
#[cfg(unix)]
fn tighten_dir_to_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_dir() || meta.permissions().mode() & 0o777 == 0o700 {
        return Ok(());
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn tighten_dir_to_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

/// scratch 物化件的写入：**出生即 0600**，复用既有文件时在**写内容之前**收紧。
///
/// 顺序是有讲究的，不是随手排的：`OpenOptions::mode()` 只在真正创建时生效，既有文件
/// 走 `truncate` 复用的是它自己的模式。所以先 open+truncate（**此刻文件是空的**）、
/// 再按 fd 收紧、最后才写内容 —— 宽权限的窗口里泄不出一个字节的原文。
/// 按 fd 而不是按路径收紧，顺带免掉一次 TOCTOU。
///
/// 这里**不**做 symlink 预检：调用方 `materialize_sealed_blob` 已经从根逐分量拒过
/// symlink（R-E-84 (a)），再判一次是第二定义。
fn write_private_scratch_file(target: &Path, blob: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut file = opts.open(target)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(blob)
}

pub(crate) fn create_private_new(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// 一轮 `mirror-restore` 里**不能被写坏的那些输入**，打成一包传。
///
/// 打包而不是散着传三个 `&Path`：写路径校验要在**每一个**写目标上问同一组问题，
/// 散着传会让下一个写目标少问一个（R3 第 4/5 条正是「某个写目标漏问了」）。
pub(crate) struct RestoreProtectedInputs<'a> {
    /// `--candidate-db`：dry-run 只读它，任何写目标指到它都是毁灭性的。
    pub db_path: &'a Path,
    /// W1 commit marker 的落点（默认与候选库同居）。
    pub marker_path: &'a Path,
    /// mirror 面的根 —— 受保护的是它底下的 raw-mirror 树，不是整个 `--data-dir`。
    pub data_dir: &'a Path,
}

/// 把一个写目标归约成**可比较的身份**。
///
/// 两件事都必须做，缺一条校验就形同虚设：
/// ① **绝对化 + 词法归并** `.` / `..` —— `--out ../candidate/x.sqlite` 与
///    `--out /abs/candidate/x.sqlite` 是同一个文件，字面比较认不出；
/// ② 对**最长的既有前缀**做 `canonicalize`，余下的按字面接上 —— 直接
///    `canonicalize` 整条路径不行，写目标**通常还不存在**，而 `canonicalize`
///    对不存在的路径直接失败，那样校验会在最需要它的那一刻缺席。
fn restore_write_path_key(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut lexical = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    };
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                lexical.pop();
            }
            Component::RootDir => lexical.push(Component::RootDir.as_os_str()),
            other => lexical.push(other.as_os_str()),
        }
    }

    let mut prefix = lexical.clone();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(resolved) = std::fs::canonicalize(&prefix) {
            let mut key = resolved;
            for name in tail.iter().rev() {
                key.push(name);
            }
            return key;
        }
        match prefix.file_name() {
            Some(name) => {
                tail.push(name.to_os_string());
                if !prefix.pop() {
                    return lexical;
                }
            }
            None => return lexical,
        }
    }
}

/// 两条路径是不是**同一个 inode**。
///
/// 跟随符号链接是**故意的**：一条指向候选库的链接就是候选库的别名。
/// 这一格抓的是路径归约抓不到的那类别名（硬链接、以及落点自己是链接）。
#[cfg(unix)]
fn same_existing_file(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn same_existing_file(_a: &Path, _b: &Path) -> bool {
    false
}

/// 写路径互异性校验（R3 第 4/5 条 / 裁定 R-E-103 J2）。
///
/// 三条同根的缺陷是一句话：**写路径不校验它要写的是不是别人的东西**。
/// `restore_journal_write` 一律 `rename(tmp, path)`，`--out` 走 `write_private_file`
/// 也是同目录临时件 + `rename` —— 两者对一个**普通文件**的别名目标都是毁灭性的
/// （前者换 inode、后者原地截断，对操作者是一回事：候选库没了）。
///
/// ⚠ **别指望写函数兜**：`write_private_file` 防的是**符号链接**
/// （`symlink_metadata` 预检 + `rename` 顶上），**它不防别名**。所以这道校验必须
/// 在调用写函数**之前**、在拿得到全部输入的那一层做。
///
/// 两类拒绝**各以自己的名义**（每层以自己的名义拒绝）：
/// - `E-RESTORE-WRITE-PATH-ALIAS`：写目标解析到某个受保护输入；
/// - `E-RESTORE-WRITE-PATH-COLLISION`：两个写目标互撞（后写的顶掉先写的，
///   而两边都以为自己写成了）。
///
/// **全或无**：任何一个写目标不合格，这一组一件都不许写 —— 留下半份产物比一件
/// 都没写更难对账。
pub(crate) fn validate_restore_write_targets(
    protected: &RestoreProtectedInputs<'_>,
    targets: &[(&str, &Path)],
) -> Result<(), String> {
    let guarded: [(&str, &Path); 2] = [
        ("--candidate-db", protected.db_path),
        ("the W1 commit marker", protected.marker_path),
    ];
    let mirror_key = restore_write_path_key(&crate::doctor_raw_mirror_root(protected.data_dir));
    let db_dir_key = protected.db_path.parent().map(restore_write_path_key);
    let db_name = protected
        .db_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned);

    for (label, target) in targets {
        let key = restore_write_path_key(target);

        for (guard_label, guard) in guarded.iter() {
            if key == restore_write_path_key(guard) || same_existing_file(target, guard) {
                return Err(format!(
                    "E-RESTORE-WRITE-PATH-ALIAS: {label} ({}) resolves to {guard_label} ({}) —                      refusing before anything is written. This run would have replaced it: a                      rename over a plain file destroys it just as surely as a truncating write.",
                    target.display(),
                    guard.display()
                ));
            }
        }

        // 候选库的 sidecar：**同目录、以候选库文件名打头**的任何名字。
        //
        // 用前缀规则而不是一张后缀白名单是有意的：本仓的 frankensqlite 自己就会产出
        // 白名单里没有的 sidecar 族，而两侧代价不对称 —— **漏挡一条 = 毁库，
        // 误挡一条 = 换个报告名**。误挡时错误信息会把出路直接说出来。
        if let (Some(dir_key), Some(db)) = (db_dir_key.as_ref(), db_name.as_ref()) {
            let same_dir = key.parent() == Some(dir_key.as_path());
            let name = key.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if same_dir && name != db.as_str() && name.starts_with(db.as_str()) {
                return Err(format!(
                    "E-RESTORE-WRITE-PATH-ALIAS: {label} ({}) sits on a sidecar of                      --candidate-db ({db}) — anything named `{db}*` beside the candidate database                      belongs to that database, and writing it corrupts the database just as                      surely as writing the main file. Give this output a name that does not                      start with `{db}`.",
                    target.display()
                ));
            }
        }

        if key.starts_with(&mirror_key) {
            return Err(format!(
                "E-RESTORE-WRITE-PATH-ALIAS: {label} ({}) lands inside the raw-mirror tree at {}                  — that tree is this run's input; writing into it would overwrite the very                  manifests being read. Put run outputs outside it (the rest of --data-dir is                  fine).",
                target.display(),
                mirror_key.display()
            ));
        }
    }

    for (i, (label_a, a)) in targets.iter().enumerate() {
        for (label_b, b) in targets.iter().skip(i + 1) {
            if restore_write_path_key(a) == restore_write_path_key(b) || same_existing_file(a, b) {
                return Err(format!(
                    "E-RESTORE-WRITE-PATH-COLLISION: {label_a} and {label_b} are the same file                      ({} / {}) — the later write would silently replace the earlier one while                      both report success.",
                    a.display(),
                    b.display()
                ));
            }
        }
    }

    Ok(())
}

pub(crate) fn restore_journal_write(path: &Path, journal: &RestoreJournal) -> anyhow::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // 唯一 tmp 名 + 创建时即私有（裁定 R-E-87 / R-E-90）。
    let tmp = unique_sibling_tmp_path(path)?;
    {
        let mut file = create_private_new(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(journal)?)?;
        journal_trace("write-tmp");
        file.sync_all()?;
        journal_trace("fsync-file");
    }
    std::fs::rename(&tmp, path)?;
    journal_trace("rename");
    if let Some(parent) = path.parent() {
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;
    }
    journal_trace("fsync-dir");
    Ok(())
}

pub(crate) fn restore_journal_read(path: &Path) -> anyhow::Result<Option<RestoreJournal>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    // ── 先验版本，后进字段解析（R-E-79 补充裁定）────────────────────────
    //
    // **每层以自己的名义拒绝。** 若直接 `serde_json::from_slice` 进结构体，一份旧版
    // journal 会死在「缺字段 `holds_count`」上——那是**错误的层在说话**：操作者读到
    // 字段解析错会去查文件损坏，而真相是版本不对。所以版本这一层自己先开口。
    //
    // 这一层买的是**错误的可读性**，不是兼容性：旧 journal 照样不能用，只是死得明白。
    let probe: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| anyhow::anyhow!("restore journal at {} is not JSON: {e}", path.display()))?;
    let got = probe.get("schema_version").and_then(|v| v.as_i64());
    match got {
        Some(v) if v == RESTORE_JOURNAL_SCHEMA_VERSION => {}
        other => {
            anyhow::bail!(
                "E-JOURNAL-SCHEMA-MISMATCH: restore journal at {} declares schema version {} \
                 but this binary requires {} — refusing to read it (a journal written before \
                 the hold-count fields existed would otherwise be read as if it had zero HOLDs)",
                path.display(),
                match other {
                    Some(v) => v.to_string(),
                    None => "<absent>".to_string(),
                },
                RESTORE_JOURNAL_SCHEMA_VERSION
            );
        }
    }

    Ok(Some(serde_json::from_slice(&bytes)?))
}

/// 推进一格：**先把新状态落盘并 fsync，再让它对后续动作生效**。
fn restore_journal_advance(
    journal: &mut RestoreJournal,
    path: &Path,
    state: RestoreJournalState,
) -> anyhow::Result<()> {
    journal.state = state;
    restore_journal_write(path, journal)?;
    journal_trace("state-visible");
    Ok(())
}

/// 崩溃注入用的**确定性握手点**：到达边界时写哨兵文件，然后原地阻塞等父进程 SIGKILL。
/// **不用 sleep 赌时序** —— 时序赌博会让注入点漂移，测的就不是那个边界了。
/// 生产路径上 env 未设即 no-op（形态与 E3 的 `relink_pause_if_requested` 一致）。
pub(crate) fn restore_pause_if_requested(boundary: &str) {
    let Ok(target) = std::env::var("CASS_RESTORE_PAUSE_AT") else {
        return;
    };
    if target != boundary {
        return;
    }
    if let Ok(sentinel) = std::env::var("CASS_RESTORE_PAUSE_SENTINEL") {
        let _ = std::fs::write(&sentinel, boundary.as_bytes());
    }
    loop {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// 从 manifest view 推出恢复身份。**只有这一处定义**——测试与恢复器都用它，
/// 免得「首跑算出来的 key」与「恢复算出来的 key」两处各写一份而悄悄分叉。
/// raw-mirror 的 `provider` → `W0-0` §B 的 origin 三族。**归一的唯一定义**（R-E-67）。
///
/// 两侧值空间本来就不一样，这不是命名手误：raw-mirror 捕获侧存的是 CASS 的 **agent slug**
/// （`src/indexer/mod.rs` 那三个捕获点，其中一个直接传 `&conv.agent_slug`），按 agent 实例
/// 细分、开放集合；而 `Origin` 是 `W0-0` §B 的**封闭三族**，封存侧（D3/D5）早已按三族归一。
/// 实测这个 9488 份 manifest 的真语料，**3443 份（36.3%）的 provider 不在三族里**，九个取值
/// 见 run root 的 `evidence/find-2-provider-space.txt`；而在此之前 `Origin::parse` 直接 `None`
/// → 调用方 `bail`，**撞上第一份就打死整轮**，planner 在真语料上一条都判不出来。
///
/// 三条映射，之外一律不归一：
/// * 三个正名 `claude_code` / `codex` / `openclaw` 恒等（走 `Origin::parse`，不在这里抄一遍）；
/// * `claude` → `ClaudeCode`（同一家的另一个 slug 写法）；
/// * `openclaw/<agent>` 前缀 → `Openclaw`（`main` / `wood` / `javich` … 是同一家的 agent 实例）。
///
/// **未知 slug 返回 `None`，不猜、不兜底。** `pi_agent` 与 `gemini` 落在这里且**是定案**
/// （2026-08-19 上位裁定确认）：它们不属受保护资产的三家，永久具名 HOLD，不入三族。
/// 放宽 `Origin` 本身的取值空间是被否掉的路（R-E-67 (a)）——那是为读侧方便去改封存契约。
pub(crate) fn normalize_provider_to_origin(provider: &str) -> Option<Origin> {
    if let Some(origin) = Origin::parse(provider) {
        return Some(origin);
    }
    match provider {
        "claude" => Some(Origin::ClaudeCode),
        other if other.starts_with("openclaw/") => Some(Origin::Openclaw),
        _ => None,
    }
}

/// manifest 侧 `origin_host: None` 归一到的那个值。
///
/// `restore_identity_from_view` 与 `conversation_ids_for_identity` **必须用同一个**
/// ——两处各写一个字面量就是第二定义，而这一维正是 R2 第 5 条咬人的地方。
pub(crate) const RESTORE_LOCAL_ORIGIN_HOST: &str = "local";

/// 按**整条身份**把候选行捞出来：`source_path` + `source_id` + agent + `origin_host`。
///
/// **候选查询与 publish 的 backlink 查询共用这一处定义。** 此前它们是两条各写各的 SQL：
/// 一条绑三维（漏 `origin_host`，R2 第 5 条），一条只绑路径（R2 第 4 条）——同一个问题
/// 两个答案。「同一份身份，查的时候是一回事、发布的时候是另一回事」正是那两条 finding
/// 的共同形状，所以修法也只有一个：让它们问同一句话。
///
/// # host 这一维怎么比：按**它存进去会长什么样**比，不按 manifest 上的字面量比
///
/// 直接拿 `identity.origin.origin_host` 去等值比对是错的，而且错得会**丢候选**：
/// 存储层落盘前跑 `normalized_storage_source_parts`，而那个归一化里
/// **`source_id` 是本机时，`origin_host` 会被丢成 `NULL`**（实测：`(local, "h1")`
/// 存进去是 `(local, NULL)`；`(work-laptop, "h1"/"h2")` 则原样保留、互相可分）。
/// 于是一份 `source_id=local, origin_host=Some("h1")` 的 manifest 若按字面量比，
/// 永远匹配不上它自己那一行 → 判成 `RestoreNew` → 重复插入。**比漏绑更糟。**
///
/// 所以这里先用**生产那一个**归一化函数把身份换算成「存储层会存的那个 host」，
/// 再与列比对。零第二定义：那个函数就是 `insert_conversations_batched` 落盘走的那个。
///
/// **由此而来的一条真实边界，明写在这里**：本机源（`source_id` 归一后为 local）的
/// host 存储层根本不保留，所以这一维**对本机源不具区分力**。这与原注释说的
/// 「没有对应列」不是一回事 —— 列在，能绑，只是本机那一档的信息在写库时就没了。
///
/// `ORDER BY c.id` 不是装饰：多行命中时调用方要么全要（候选侧），要么取头一条
/// （publish 侧），无序会让后者在同一份数据上给出不同答案。
fn conversation_ids_for_identity(
    storage: &crate::storage::sqlite::FrankenStorage,
    identity: &RestoreIdentity,
) -> anyhow::Result<Vec<i64>> {
    use crate::storage::api::Value as ParamValue;

    // manifest 侧 `origin_host: None` 在身份里被写成 `RESTORE_LOCAL_ORIGIN_HOST`
    // 这个哨兵；换算回 `Option` 再喂给生产归一化，别让哨兵被当成一个真的主机名。
    let raw_host = if identity.origin.origin_host == RESTORE_LOCAL_ORIGIN_HOST {
        None
    } else {
        Some(identity.origin.origin_host.as_str())
    };
    let (_, _, stored_host) = crate::storage::sqlite::normalized_storage_source_parts(
        Some(identity.origin.source_id.as_str()),
        None,
        raw_host,
    );

    let host_clause = match stored_host {
        Some(_) => "AND TRIM(COALESCE(c.origin_host, '')) = ?4",
        None => "AND TRIM(COALESCE(c.origin_host, '')) = ''",
    };
    let sql = format!(
        "SELECT c.id FROM conversations c JOIN agents a ON a.id = c.agent_id \
         WHERE c.source_path = ?1 AND c.source_id = ?2 AND a.slug = ?3 {host_clause} \
         ORDER BY c.id"
    );
    let mut params = vec![
        ParamValue::from(identity.canonical_path.as_str()),
        ParamValue::from(identity.origin.source_id.as_str()),
        ParamValue::from(identity.origin.agent_slug.as_str()),
    ];
    if let Some(host) = stored_host.as_deref() {
        params.push(ParamValue::from(host));
    }
    let ids: Vec<i64> = storage
        .raw()
        .query_all_map(&sql, &params, |row| row.get_typed(0))?;
    Ok(ids)
}

pub(crate) fn restore_identity_from_view(
    view: &crate::raw_mirror::RawMirrorManifestView,
) -> anyhow::Result<RestoreIdentity> {
    // 仍然要求 provider 能归一 —— 那是**分类可判**的前提（未知 slug 具名 HOLD，R-E-67）。
    // 但身份里存的是**原始串**，不是归一结果（R-E-103）。
    normalize_provider_to_origin(&view.provider)
        .ok_or_else(|| anyhow::anyhow!("unknown provider in manifest: {}", view.provider))?;
    Ok(RestoreIdentity {
        origin: OriginNamespace {
            agent_slug: view.provider.clone(),
            source_id: view.source_id.clone(),
            origin_host: view
                .origin_host
                .clone()
                .unwrap_or_else(|| RESTORE_LOCAL_ORIGIN_HOST.to_string()),
        },
        canonical_path: view.original_path.clone(),
    })
}

fn restore_idempotency_key_for(
    action: PlannedAction,
    snapshot_root: &str,
    identity: &RestoreIdentity,
) -> String {
    match action {
        PlannedAction::RestoreNew => restore_new_idempotency_key(snapshot_root, identity),
        PlannedAction::Replace { .. } => replace_idempotency_key(snapshot_root, identity),
    }
}

fn restore_now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 把一条计划项从磁盘重新推导成可落库的会话。
///
/// **首跑与恢复共用这一个函数** —— 「恢复做的事与首跑一致」不是靠两处代码写得像来保证的，
/// 是靠只有一处代码来保证的。
fn restore_project_plan_item(
    journal: &RestoreJournal,
    view: &crate::raw_mirror::RawMirrorManifestView,
) -> anyhow::Result<crate::model::types::Conversation> {
    let reports = collect_sealed_manifest_reports(&journal.data_dir);
    let report = reports
        .iter()
        .find(|r| r.manifest_id == view.manifest_id)
        .ok_or_else(|| anyhow::anyhow!("no doctor report for manifest {}", view.manifest_id))?;
    let blob = match read_sealed_blob(&journal.data_dir, report) {
        SealedBlobOutcome::Loaded(bytes) => bytes,
        SealedBlobOutcome::ReferenceMissing => {
            anyhow::bail!("sealed blob missing for manifest {}", view.manifest_id)
        }
        SealedBlobOutcome::PayloadHashMismatch { detail }
        | SealedBlobOutcome::Unreadable { detail } => {
            anyhow::bail!("sealed blob unreadable for {}: {detail}", view.manifest_id)
        }
    };
    let agent = normalize_provider_to_origin(&view.provider)
        .ok_or_else(|| anyhow::anyhow!("unknown provider in manifest: {}", view.provider))?;
    let provenance = provenance_from_manifest_view(view);
    let sealed = SealedSource {
        agent,
        canonical_original_path: &view.original_path,
        source_size_bytes: view.source_size_bytes,
        blob: &blob,
    };
    match project_sealed_source(&journal.scratch_dir, &sealed, &provenance) {
        Ok(SealedProjection::Projected(conv)) => {
            Ok(crate::indexer::persist::map_to_internal(&conv))
        }
        Ok(other) => anyhow::bail!("sealed projection produced no conversation: {other:?}"),
        Err(err) => anyhow::bail!("sealed projection failed: {err:?}"),
    }
}

/// DB 阶段：逐条**先查 receipt 再做**。
fn restore_run_db_phase(
    journal: &mut RestoreJournal,
    outcome: &mut RestoreRunOutcome,
) -> anyhow::Result<()> {
    let views = crate::raw_mirror::manifest_views(&journal.data_dir)?;
    let storage = crate::storage::sqlite::FrankenStorage::open(&journal.db_path)
        .map_err(|e| anyhow::anyhow!("open candidate db {}: {e}", journal.db_path.display()))?;
    let pricing = crate::storage::sqlite::PricingTable::franken_load(storage.raw())?;

    for item in journal.planned.clone() {
        let view = views
            .iter()
            .find(|v| v.manifest_id == item.manifest_id)
            .ok_or_else(|| {
                anyhow::anyhow!("planned manifest {} not in mirror", item.manifest_id)
            })?;
        let identity = restore_identity_from_view(view)?;
        let key = restore_idempotency_key_for(item.action, &journal.snapshot_root, &identity);

        // 先查后做：查到 receipt = 这一条已提交，跳过（幂等的定义）。
        if crate::storage::sqlite::franken_operation_commit_receipt_exists(storage.raw(), &key)? {
            if !journal.committed.contains(&item.manifest_id) {
                journal.committed.push(item.manifest_id.clone());
            }
            // ── R-E-83：跳过也是一种**处置**，必须计数 ──────────────────
            // 修前这里直接 `continue`，`outcome` 一格没动，于是归宿守恒式在恢复
            // 路径上断裂（全是已提交项时左边为 0、右边为 planned）。
            // receipt key 也一并带出：receipt 明明在库里，摘要不报的话操作者连
            // 对账的凭据都拿不到。
            outcome.already_committed += 1;
            outcome.receipt_keys.push(key);
            continue;
        }

        let conv = restore_project_plan_item(journal, view)?;
        let agent_id = storage.ensure_agent(&crate::model::types::Agent {
            id: None,
            slug: conv.agent_slug.clone(),
            name: conv.agent_slug.clone(),
            version: None,
            kind: crate::model::types::AgentKind::Cli,
        })?;
        let workspace_id = match conv.workspace.as_ref() {
            Some(ws) => Some(storage.ensure_workspace(ws, None)?),
            None => None,
        };

        match item.action {
            PlannedAction::RestoreNew => {
                let out = commit_restore_new(
                    &storage,
                    &RestoreNewCommitInput {
                        agent_id,
                        workspace_id,
                        conv: &conv,
                        identity: &identity,
                        snapshot_root: &journal.snapshot_root,
                        generation: &journal.generation,
                    },
                    restore_now_ms(),
                )?;
                // 三态各计各的格；`messages_inserted` 用存储层报的真实条数，
                // 不用 `conv.messages.len()`（FIND-7 / R-E-76）。
                if out.applied {
                    outcome.restored += 1;
                } else if out.deduplicated {
                    outcome.deduplicated += 1;
                }
                outcome.messages_inserted += out.messages_inserted;
                outcome.receipt_keys.push(out.idempotency_key);
            }
            PlannedAction::Replace { conversation_id } => {
                let tx = storage.raw().transaction()?;
                let replaced = commit_replace_in_tx(
                    &tx,
                    &ReplaceCommitInput {
                        conversation_id,
                        agent_id,
                        workspace_id,
                        conv: &conv,
                        identity: &identity,
                        snapshot_root: &journal.snapshot_root,
                        generation: &journal.generation,
                    },
                    &pricing,
                    restore_now_ms(),
                )?;
                tx.commit()?;
                outcome.replaced += 1;
                outcome.messages_inserted += replaced.inserted_message_ids.len();
                outcome.messages_deleted += replaced.deleted_message_count;
                outcome.receipt_keys.push(replaced.idempotency_key);
            }
        }
        journal.committed.push(item.manifest_id.clone());
    }
    Ok(())
}

/// 过了 `db-committed` 的状态必须有 receipt 佐证；没有就是两个真源矛盾。
/// 只断言、**不记账**的那个入口。
///
/// `restore_verify_closure` 要的就是「每条计划项都有 receipt」这一句断言，它跑在同一轮
/// 的更后面一格 —— 让它也往 outcome 里加数，同一批已提交项就会被计两遍。
/// 两个入口分开写，是为了让「谁记账」这件事在调用点上看得见，而不是靠调用顺序心照不宣。
fn restore_assert_receipts_present(journal: &RestoreJournal) -> anyhow::Result<()> {
    let mut discarded = RestoreRunOutcome::default();
    restore_account_receipts_present(journal, &mut discarded)
}

/// 断言 + 记账：post-`db-committed` 的恢复走这一个。
fn restore_account_receipts_present(
    journal: &RestoreJournal,
    outcome: &mut RestoreRunOutcome,
) -> anyhow::Result<()> {
    let views = crate::raw_mirror::manifest_views(&journal.data_dir)?;
    let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(&journal.db_path)
        .map_err(|e| anyhow::anyhow!("open candidate db readonly: {e}"))?;
    let mut missing = Vec::new();
    for item in &journal.planned {
        let Some(view) = views.iter().find(|v| v.manifest_id == item.manifest_id) else {
            missing.push(item.manifest_id.clone());
            continue;
        };
        let identity = restore_identity_from_view(view)?;
        let key = restore_idempotency_key_for(item.action, &journal.snapshot_root, &identity);
        if crate::storage::sqlite::franken_operation_commit_receipt_exists(storage.raw(), &key)? {
            // 这一格此前只 assert 不记账（R2 第 8 条）：崩在 `db-committed` 之后再
            // `--recover`，四格全 0、`receipt_keys` 空——而那正是操作者对账用的东西。
            // R-E-83 修的是 `Planned` 支**内部**那一分支，**这一支从没被覆盖**。
            //
            // 归到 `already_committed`：receipt 是「这条身份的恢复动作做完了」的唯一
            // 持久凭据，它回答不了「当初是新建还是去重」，所以也不许往那两格里猜。
            outcome.already_committed += 1;
            outcome.receipt_keys.push(key);
        } else {
            missing.push(item.manifest_id.clone());
        }
    }
    storage.close_best_effort_in_place();
    if !missing.is_empty() {
        anyhow::bail!(
            "restore journal at state {:?} but no operation receipt for {} — refusing to guess",
            journal.state,
            missing.join(", ")
        );
    }
    Ok(())
}

/// 索引 / embedding 状态属于**被改的那个库所在的那棵树**，不属于 mirror 的 `--data-dir`。
///
/// CLI 把 `--data-dir`（mirror 面的根）与 `--candidate-db`（候选库的稳定副本）定义成
/// 两个独立参数——拆开跑不是异常形态，是设计用法。而 readiness / embedding 这两格
/// 作废的对象是「谁在自称对当前指纹新鲜」，那份状态按 cass 自己的目录约定躺在
/// **库所在的那棵树**里（`default_db_path() = default_data_dir()/agent_search.db`；
/// `doctor_recover::resolve_db_path` 同形；本文件的 `plan_for` 取 marker 路径时
/// 用的也早就是 `db_path.parent()`）。
///
/// 修前两格都读 `journal.data_dir`（R2 第 3 条）：拆开跑时**清掉的是 mirror 那棵树**
/// ——在真实操作里那往往就是生产 data_dir——而**被改的候选库那棵树照旧自称新鲜**，
/// 于是资格门（它不看索引产物）照过不误。
///
/// 拿不到父目录时**停手不猜**：本文件对「两个真源互相矛盾 / 手上材料不足以判定」
/// 的一贯口径就是硬失败，不是挑一个默认值继续。
fn restore_index_root(journal: &RestoreJournal) -> anyhow::Result<&Path> {
    journal
        .db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "candidate db path {} has no parent directory — cannot locate the index and \
                 embedding state that belongs to it, refusing to guess",
                journal.db_path.display()
            )
        })
}

/// 第 2 格 · readiness 失效（幂等）。
///
/// 删掉词法重建 checkpoint = 让索引不再自称「对当前指纹新鲜」。入口是既有的
/// `clear_lexical_rebuild_state`（R-E-50-b 只放宽可见性、函数体逐字节不变），
/// 路径用 `expected_index_dir`（纯拼接、**无副作用**）——不用会创建目录的 `index_dir`，
/// 恢复器不该自己产副作用。
fn restore_invalidate_readiness(journal: &RestoreJournal) -> anyhow::Result<()> {
    let index_dir = crate::search::tantivy::expected_index_dir(restore_index_root(journal)?);
    crate::indexer::clear_lexical_rebuild_state(&index_dir)
}

/// 第 3 格 · embedding 作废（幂等）。
///
/// 走的是**生产唯一写者那条链**（`src/indexer/semantic.rs` 的
/// `load_or_default → replace_shards_for_generation → save`），零第二定义。
fn restore_invalidate_embeddings(journal: &RestoreJournal) -> anyhow::Result<()> {
    use crate::search::semantic_manifest::{SemanticManifest, SemanticShardManifest};
    let data_dir = restore_index_root(journal)?;

    if let Some(mut shard) = SemanticShardManifest::load(data_dir)
        .map_err(|e| anyhow::anyhow!("load semantic shard manifest: {e}"))?
    {
        let triples: Vec<(_, String, String)> = shard
            .shards
            .iter()
            .map(|s| (s.tier, s.embedder_id.clone(), s.db_fingerprint.clone()))
            .collect();
        let mut seen = std::collections::BTreeSet::new();
        for (tier, embedder, fingerprint) in triples {
            if !seen.insert((tier.as_str(), embedder.clone(), fingerprint.clone())) {
                continue;
            }
            shard.replace_shards_for_generation(tier, &embedder, &fingerprint, Vec::new());
        }
        shard
            .save(data_dir)
            .map_err(|e| anyhow::anyhow!("save semantic shard manifest: {e}"))?;
    }

    if let Some(mut manifest) = SemanticManifest::load(data_dir)
        .map_err(|e| anyhow::anyhow!("load semantic manifest: {e}"))?
    {
        manifest.fast_tier = None;
        manifest.quality_tier = None;
        manifest.hnsw = None;
        manifest.clear_checkpoint();
        manifest
            .save(data_dir)
            .map_err(|e| anyhow::anyhow!("save semantic manifest: {e}"))?;
    }
    Ok(())
}

/// 第 4 格 · analytics 失效并重算（幂等）。**直接用 E6 Step 1b 那个函数**，
/// 不在这里另写一份重算（它已经处理了「绕开 `rebuild_analytics`」那条裁定）。
fn restore_rebuild_analytics(journal: &RestoreJournal) -> anyhow::Result<()> {
    let storage = crate::storage::sqlite::FrankenStorage::open(&journal.db_path)
        .map_err(|e| anyhow::anyhow!("open candidate db for analytics: {e}"))?;
    recompute_materialized_aggregates_after_commit(&storage)
}

/// 第 5/6 格 · manifest publish，**按差集续做**。
fn restore_publish_manifests(
    journal: &mut RestoreJournal,
    journal_path: &Path,
    outcome: &mut RestoreRunOutcome,
) -> anyhow::Result<()> {
    let views = crate::raw_mirror::manifest_views(&journal.data_dir)?;
    let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(&journal.db_path)
        .map_err(|e| anyhow::anyhow!("open candidate db for publish: {e}"))?;

    for item in journal.planned.clone() {
        let view = views
            .iter()
            .find(|v| v.manifest_id == item.manifest_id)
            .ok_or_else(|| {
                anyhow::anyhow!("planned manifest {} not in mirror", item.manifest_id)
            })?;
        if journal.published.contains(&view.manifest_relative_path) {
            continue;
        }
        let conversation_id = match item.action {
            PlannedAction::Replace { conversation_id } => Some(conversation_id),
            PlannedAction::RestoreNew => {
                // 绑**整条身份**，与候选侧同一处定义（R2 第 4 条 / 第 5 条互为镜像）。
                // 修前这里只绑 `source_path`：库里另一条同路径、异来源的会话会先被选中，
                // 于是 manifest 的 backlink 指向一条根本不是它的会话，且指错了不报错。
                let identity = restore_identity_from_view(view)?;
                conversation_ids_for_identity(&storage, &identity)?
                    .into_iter()
                    .next()
            }
        };
        let link = crate::raw_mirror::RawMirrorDbLink {
            conversation_id,
            message_count: None,
            source_path: Some(view.original_path.clone()),
            started_at_ms: None,
        };
        crate::raw_mirror::merge_manifest_db_links(
            &journal.data_dir,
            &view.manifest_relative_path,
            std::slice::from_ref(&link),
        )?;
        journal.published.push(view.manifest_relative_path.clone());
        outcome.published += 1;
        if conversation_id.is_none() {
            // 查不到候选行本身不必然是错——内容去重把行收敛到另一条 `source_path` 上时
            // 就查不到，那是 FIND-7 / R-E-76 已裁定的合法归宿。所以口径不是硬失败，
            // 是**记账**：修前这种情形照发布、照计入 `published`，操作者读到的是
            // 「都发布好了」，而那几份 manifest 的回链其实是空的。
            outcome.published_without_backlink += 1;
        }
        restore_journal_advance(journal, journal_path, RestoreJournalState::ManifestPartial)?;
        restore_pause_if_requested("manifest-partial");
    }
    storage.close_best_effort_in_place();
    Ok(())
}

/// 第 7 格前的闭合校验：每条计划项都要有 receipt、且 manifest 已 publish。
///
/// # ⚠ 边界：**closure 绿 ≠ 库里新增了行**（FIND-7 / 裁定 R-E-76）
///
/// 本函数核的是两件事：**每条计划项都有 receipt**、**每份 manifest 都已 publish**。
/// 它**不核库侧存在性** —— 一条会话被存储层按内容去重（内容早已在库）时，receipt
/// 照写、manifest 照 publish，于是这道闭合校验、以及依赖它的 `--qualify`，
/// **全都是绿的，而库里一行没多**。
///
/// 这不是缺陷，是分工：receipt 回答的是「这条身份的恢复动作**做完了**」（幂等凭据），
/// 不是「这次**写进去了多少**」。工作量的真相在 `RestoreRunOutcome` 的分格数字里 ——
/// `restored`（真新建）与 `deduplicated`（去重收敛）是两个数，别读成一个。
///
/// **操作者的真验证法 —— 用归宿守恒等式，不要用「重跑 dry-run 看它归零」**
/// （FIND-8 / R3 第 16 条 / 裁定 R-E-103 J3）：
///
/// ```text
/// restored + replaced + deduplicated + already_committed == planned
/// ```
///
/// 读法：本轮每一条计划项都有归宿 —— 落库、替换、被去重收敛，或本来就已提交。
///
/// **为什么不能用那个归零信号**：planner 按**路径锚定的身份**判「库里有没有」
/// （manifest 的 `original_path` ↔ 库里的 `source_path`），而插入器按**内容合并键**
/// 去重（与路径无关）—— 两侧各自忠实于自己的契约。于是一条会话若已在库、却挂在
/// **另一个路径**下（项目目录改名、家目录迁移、会话文件被复制），planner 每轮都规划、
/// 插入器每轮都去重，**它永远规划不完**。那不是没修好，是这两个口径本来就不同一。
///
/// 工作量的真相仍在分格数字里：`restored`（真新建）与 `deduplicated`（去重收敛）
/// 是两个数，别读成一个。也不要拿 closure 或 `--qualify` 的绿去回答「库里多了多少」。
fn restore_verify_closure(journal: &RestoreJournal) -> anyhow::Result<()> {
    restore_assert_receipts_present(journal)?;
    let views = crate::raw_mirror::manifest_views(&journal.data_dir)?;
    for item in &journal.planned {
        let view = views
            .iter()
            .find(|v| v.manifest_id == item.manifest_id)
            .ok_or_else(|| {
                anyhow::anyhow!("planned manifest {} not in mirror", item.manifest_id)
            })?;
        if !journal.published.contains(&view.manifest_relative_path) {
            anyhow::bail!(
                "closure verification failed: manifest {} not published",
                view.manifest_relative_path
            );
        }
    }
    Ok(())
}

/// 首跑：写计划 → 驱动。
pub(crate) fn restore_apply_journaled(
    plan: RestoreRunPlan,
    journal_path: &Path,
) -> anyhow::Result<RestoreRunOutcome> {
    // ── 写路径校验必须发生在**第一次写之前**（R3 第 4 条 / 裁定 R-E-103 J2）──
    //
    // 修前：`--journal <候选库路径>` 在 DB 阶段打开候选库**之前**就把它替换成一份
    // JSON —— 规划阶段读得通、第一次写 journal 当场毁库。
    validate_restore_write_targets(
        &RestoreProtectedInputs {
            db_path: &plan.db_path,
            marker_path: &plan.marker_path,
            data_dir: &plan.data_dir,
        },
        &[("--journal", journal_path)],
    )
    .map_err(|detail| anyhow::anyhow!(detail))?;

    // ── 首跑要求**一个还没被占用的路径**（R3 第 4 条的第二种形态）───────
    //
    // 上一轮崩在 DB 提交之后、publish 之前时，盘上那份 journal 是那一轮**唯一的记录**。
    // 无条件写一份全新的 `planned` journal 上去就把它抹了 —— 于是新 planner 可能认为
    // 库侧内容已相等而略过该项，让新 marker attest 一轮**从没修好那条 backlink** 的运行。
    //
    // 用 `symlink_metadata` 而不是 `exists()`：断链的符号链接也算占用
    // （`rename` 顶得掉它，但那同样是在动别人放在那儿的东西）。
    if std::fs::symlink_metadata(journal_path).is_ok() {
        anyhow::bail!(
            "E-JOURNAL-PATH-OCCUPIED: something already exists at {} — refusing to start a new \
             --apply on top of it. If that is the journal of a run that crashed part-way, it is \
             that run's only record: continue that run with `--recover --journal {}`. If that run \
             is finished and you want a fresh one, point --journal at a new path.",
            journal_path.display(),
            journal_path.display()
        );
    }

    let mut journal = restore_journal_from_plan(plan);
    restore_journal_write(journal_path, &journal)?;
    journal_trace("state-visible");
    restore_pause_if_requested("planned");
    restore_drive(&mut journal, journal_path)
}

/// 崩溃恢复：**入参只有 journal 路径**，其余一切从磁盘取（R-E-19 第三条）。
pub(crate) fn restore_recover(journal_path: &Path) -> anyhow::Result<RestoreRunOutcome> {
    let Some(mut journal) = restore_journal_read(journal_path)? else {
        anyhow::bail!("no restore journal at {}", journal_path.display());
    };
    restore_drive(&mut journal, journal_path)
}

/// 首跑与恢复的**同一条驱动路径**。每一格都先判「做没做过」再做，故重跑幂等。
fn restore_drive(
    journal: &mut RestoreJournal,
    journal_path: &Path,
) -> anyhow::Result<RestoreRunOutcome> {
    let mut outcome = RestoreRunOutcome::default();

    if journal.state.rank() == RestoreJournalState::Planned.rank() {
        // §5.2.5：`planned` 时按幂等 key 查 receipt —— 无则重放事务，有则等同 db-committed。
        // 逐条判在 `restore_run_db_phase` 内部（先查后做），所以两种情形共用一条路径。
        restore_run_db_phase(journal, &mut outcome)?;
        restore_journal_advance(journal, journal_path, RestoreJournalState::DbCommitted)?;
        restore_pause_if_requested("db-committed");
    } else {
        restore_account_receipts_present(journal, &mut outcome)?;
    }

    if journal.state.rank() < RestoreJournalState::ReadinessInvalidated.rank() {
        restore_invalidate_readiness(journal)?;
        restore_journal_advance(
            journal,
            journal_path,
            RestoreJournalState::ReadinessInvalidated,
        )?;
        restore_pause_if_requested("readiness-invalidated");
    }
    if journal.state.rank() < RestoreJournalState::EmbeddingsInvalidated.rank() {
        restore_invalidate_embeddings(journal)?;
        restore_journal_advance(
            journal,
            journal_path,
            RestoreJournalState::EmbeddingsInvalidated,
        )?;
        restore_pause_if_requested("embeddings-invalidated");
    }
    if journal.state.rank() < RestoreJournalState::AnalyticsRebuilt.rank() {
        restore_rebuild_analytics(journal)?;
        restore_journal_advance(journal, journal_path, RestoreJournalState::AnalyticsRebuilt)?;
        restore_pause_if_requested("analytics-rebuilt");
    }

    restore_publish_manifests(journal, journal_path, &mut outcome)?;

    if journal.state.rank() < RestoreJournalState::ClosureVerified.rank() {
        restore_verify_closure(journal)?;
        restore_journal_advance(journal, journal_path, RestoreJournalState::ClosureVerified)?;
        restore_pause_if_requested("closure-verified");
    }

    // 第 7 格 · 「直接写 commit marker」（§5.2.5）。**无条件调用、靠先查后做幂等**：
    // 恢复器会在终态上被反复唤醒，marker 已存在且内容相同即 no-op，不同则硬失败不覆盖。
    let marker = build_w1_commit_marker(journal, journal_path)?;
    write_w1_commit_marker(&marker, &journal.marker_path)?;
    Ok(outcome)
}

// ===========================================================================
// E7 Step 3 · W1 commit marker 与**解析级**资格门
//
// wire 说明见 run root 的 `e7-w1-commit-marker-wire.md`（裁定 R-E-51 落点单源、
// R-E-53 编码走 canonical JSON + 单 BLAKE3、**有意不与 A5 同构**，理由三条在说明 §5）。
//
// 承重的一句话：**资格门不是文件存在判定**。marker 说「我提交了这些」，
// receipt 说「这些确实提交过」—— 两个独立真源对上才算数。
// ===========================================================================

/// restore journal 的 schema 版本（R-E-79 补充裁定）。
///
/// **2** = 随 marker 一起加了 `holds_count` / `origin_unmapped_count` 两格。
/// 这个常量存在的理由不是兼容性（rehearsal 之前没有生产 journal），
/// 而是**错误的可读性**：没有它，一份旧 journal 会死在 serde 的字段解析上，
/// 那是错误的层在说话——操作者会去查文件损坏，而真相是版本不对。
pub(crate) const RESTORE_JOURNAL_SCHEMA_VERSION: i64 = 3;

pub(crate) const W1_COMMIT_MARKER_SCHEMA: &str = "marker.w1-commit";
/// **3**（R-E-91）：字段全集没变，变的是 `mirror_identity.manifest_root` 的**派生定义**
/// —— 它现在把每份 manifest 的**文件字节摘要**也摘进去（见 [`W1MirrorIdentity`]）。
///
/// **为什么派生定义变了也要升版号**：schema 2 的 marker 里那个 `manifest_root` 是按旧口径
/// 算的，拿新口径重算必然不等。不升版号的话，一份完全正常的旧候选会以
/// `E-IDENTITY-MISMATCH` 被拒 —— 那是把「版本旧」报成「候选被人动过」，是最坏的一种
/// 错误归因：操作者会去查安全事件，而真相是升级。**版本差异必须由版本号来说话。**
///
/// **2**（R-E-79 (a)）：新增 `holds_count` / `origin_unmapped_count` 两格。
///
/// 升版而不是「加两个可选字段」：可选就等于**今天可缺省、明天成旁路**——
/// 一份没有这两格的 marker 会被读成「零 HOLD」，而那恰好是本次要杜绝的谎。
/// 闭世界解析对缺字段报 `MissingField`，所以升版之后旧 marker **必然被拒**，
/// 这是有意的（同 R-E-55 的反滥用形状）。
pub(crate) const W1_COMMIT_MARKER_SCHEMA_VERSION: i64 = 4;
// ⚠ staged landing 记账（同 E5/E6 惯例，不是把死代码放行）：非测试构建里它的调用方
// 要到 **E8 接 `mirror-restore` CLI** 那一刻才出现（解析 marker 落点）。判据仍是
// 「删掉 allow 之后 clippy 不报 never-used」，移除义务挂在 E8 验收面。
pub(crate) const W1_COMMIT_MARKER_FILENAME: &str = "w1-commit-marker.json";

/// 候选 DB 稳定副本的强身份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct W1DbIdentity {
    pub sqlite_digest: String,
    pub sqlite_size_bytes: u64,
    pub schema_version: i64,
    pub generation: String,
}

/// mirror 工作树的身份。**与 DB 侧一起才构成绑定**：只钉一侧时换掉另一侧照样过门，
/// 而 manifest 恰恰是 W1 自己的写对象之一（relink 写的就是它）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct W1MirrorIdentity {
    pub manifest_count: u64,
    /// **schema 3 的派生定义**（R-E-91）：每份 manifest 出一行
    /// `<相对路径> US <声明的 blob_blake3> US <manifest 文件字节的 blake3>`，
    /// 升序排序后以 RS 分隔逐行喂进一个 BLAKE3。
    ///
    /// 第三样是 schema 3 新加的，理由见 R1 Finding 7：schema 2 只摘前两样，而那两样
    /// **全都是 manifest 自己声称的东西**——改 manifest 的内容（`db_links` 清空、
    /// `original_path` 换掉）而不动路径与声明哈希，重算出的根值**一位都不变**。
    /// 摘文件字节的成本接近零（这些文件刚被读过一遍），却把「被声称的东西还是不是那个
    /// 东西」这一整类改动纳入了视野。
    ///
    /// **它仍然不覆盖 blob 的真实字节**——那是[`verify_mirror_blobs`]的职责，分两档：
    /// 默认档只验存在性与大小，`--deep-verify` 才全读重算。
    pub manifest_root: String,
}

/// W1 提交标记：候选侧「这次恢复走完了」的可移植凭据。
///
/// # ⚠ 它证到什么、**没有**证到什么（FIND-7 / 裁定 R-E-76）
///
/// marker 里的 `closure_verdict` / `planned_count` / `receipt_keys` 说的是
/// **计划项都拿到了 receipt、manifest 都已 publish**。它们**不表示库里新增了行**：
/// 一条会话的内容早已在库时，存储层按内容去重，receipt 照写、marker 照齐全，
/// 而库侧一行没多。`planned_count` 是**计划了几条**，不是**写进去几条**。
///
/// 想知道这次实际写了多少，看 apply/recover 摘要里的 `restored`（真新建）与
/// `deduplicated`（去重收敛）两个**分格**数字，别把它们读成一个。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct W1CommitMarker {
    pub schema: String,
    pub schema_version: i64,
    pub operation_id: String,
    pub snapshot_root: String,
    pub content_generation: String,
    pub journal_state: String,
    pub journal_digest: String,
    pub closure_verdict: String,
    pub planned_count: i64,
    /// 本轮判为 HOLD 的身份条数（R-E-79 (a)）。
    ///
    /// **为什么它必须在证书里**：修前 marker 与 journal 里 HOLD 零痕迹，于是一份
    /// `qualified: true` 的候选可以静默携带成百上千条未解决身份——rehearsal 交出去的
    /// 两份各带 12 条，而证书上看不出来。**`qualified` 的判定不因这一格改变**
    /// （带 HOLD 的部分恢复可以是合法的，硬拒会误杀），但消费者有权看见它再自己决定。
    pub holds_count: i64,
    /// 本轮 provider 未能映射到 origin 的记录条数（R-E-79 (a)）。同上，只报不判。
    pub origin_unmapped_count: i64,
    /// **升序去重**（set 语义）：否则同一批内容因枚举顺序不同算出不同摘要。
    pub receipt_keys: Vec<String>,
    pub db_identity: W1DbIdentity,
    pub mirror_identity: W1MirrorIdentity,
}

/// 资格门的拒绝理由。**每层以自己的名义拒绝**，错误码沿用 A5 的 `E-*` 命名，
/// 好让 F4 的实现者在两族之间迁移直觉。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum W1MarkerError {
    MarkerMissing,
    Unparsable(String),
    UnknownField(String),
    MissingField(String),
    TypeMismatch(String),
    /// **两个版本都带**（同 R-E-88 给 restore journal 立的口径）：只报「见到的」，
    /// 操作者不知道该升到哪一版；两个都给，`E-SCHEMA-MISMATCH` 才是可行动的错误。
    SchemaMismatch {
        got: String,
        expected: String,
    },
    JournalNotTerminal {
        detail: String,
    },
    ClosureNotPass {
        got: String,
    },
    IdentityMismatch {
        field: String,
    },
    ReceiptMissing {
        key: String,
    },
    GenerationMismatch {
        marker: String,
        db: String,
    },
    /// 档 2（R-E-91）：manifest 指向的 blob 文件根本不在盘上。
    MirrorBlobMissing {
        manifest_relative_path: String,
        blob_relative_path: String,
    },
    /// 档 2（R-E-91）：blob 在，但盘上的字节数与 manifest 声称的 `blob_size_bytes` 不符。
    MirrorBlobSizeMismatch {
        blob_relative_path: String,
        declared: u64,
        actual: u64,
    },
    /// 档 3（R-E-91，只在 `--deep-verify` 下可能出现）：blob 的**真实字节**重算出的
    /// blake3 与 manifest 声称的 `blob_blake3` 不符。
    MirrorBlobChecksumMismatch {
        blob_relative_path: String,
        declared: String,
        actual: String,
    },
    /// 档 2（R4 第 4 条 / 裁定 R-E-110 K1）：blob 在，但它**不是一个普通文件**。
    ///
    /// 与上面三条分开的理由同上：这既不是「不在」也不是「字节不对」，
    /// 而是**这份 mirror 的内容不在它自己声称的地方** —— 一搬走就散。
    MirrorBlobNotRegularFile {
        blob_relative_path: String,
        detail: String,
    },
    /// 读 mirror 时的 I/O 失败。**与上面三条分开**：读不动是环境问题，读到了但不对是
    /// 完整性问题，混在一码里会让操作者按错方向排查（同「退出码分档不许非 0 即 FAIL」）。
    MirrorUnreadable(String),
}

impl W1MarkerError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            W1MarkerError::MarkerMissing => "E-MARKER-MISSING",
            W1MarkerError::Unparsable(_) => "E-MARKER-UNPARSABLE",
            W1MarkerError::UnknownField(_) => "E-UNKNOWN-FIELD",
            W1MarkerError::MissingField(_) => "E-MISSING-FIELD",
            W1MarkerError::TypeMismatch(_) => "E-TYPE-MISMATCH",
            W1MarkerError::SchemaMismatch { .. } => "E-SCHEMA-MISMATCH",
            W1MarkerError::JournalNotTerminal { .. } => "E-JOURNAL-NOT-TERMINAL",
            W1MarkerError::ClosureNotPass { .. } => "E-CLOSURE-NOT-PASS",
            W1MarkerError::IdentityMismatch { .. } => "E-IDENTITY-MISMATCH",
            W1MarkerError::ReceiptMissing { .. } => "E-RECEIPT-MISSING",
            W1MarkerError::GenerationMismatch { .. } => "E-GENERATION-MISMATCH",
            W1MarkerError::MirrorBlobMissing { .. } => "E-MIRROR-BLOB-MISSING",
            W1MarkerError::MirrorBlobSizeMismatch { .. } => "E-MIRROR-BLOB-SIZE-MISMATCH",
            W1MarkerError::MirrorBlobChecksumMismatch { .. } => "E-MIRROR-BLOB-CHECKSUM-MISMATCH",
            W1MarkerError::MirrorBlobNotRegularFile { .. } => "E-MIRROR-BLOB-NOT-REGULAR",
            W1MarkerError::MirrorUnreadable(_) => "E-MIRROR-UNREADABLE",
        }
    }
}

impl std::fmt::Display for W1MarkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}", self.code(), self)
    }
}

// ── canonical bytes（wire 说明 §5.1，形制钉死）─────────────────────────────
//
// UTF-8 无 BOM / 键按字节序升序 / 零多余空白 / 仅整数十进制 / 非 ASCII 不转义 /
// 无 null / 结尾无换行。**摘要的意义完全取决于这套形制的唯一性**，所以它有一条
// vector 式固定测试：期望字节与期望摘要是手工钉死的常量，不由编码器自己算。

fn canon_push_str(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn canon_kv_str(out: &mut String, key: &str, value: &str, first: &mut bool) {
    if !*first {
        out.push(',');
    }
    *first = false;
    canon_push_str(out, key);
    out.push(':');
    canon_push_str(out, value);
}

fn canon_kv_int(out: &mut String, key: &str, value: i64, first: &mut bool) {
    if !*first {
        out.push(',');
    }
    *first = false;
    canon_push_str(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}

impl W1CommitMarker {
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = String::new();
        out.push('{');
        let mut first = true;
        canon_kv_str(
            &mut out,
            "closure_verdict",
            &self.closure_verdict,
            &mut first,
        );
        canon_kv_str(
            &mut out,
            "content_generation",
            &self.content_generation,
            &mut first,
        );
        // db_identity
        out.push(',');
        canon_push_str(&mut out, "db_identity");
        out.push_str(":{");
        {
            let mut inner = true;
            canon_kv_str(
                &mut out,
                "generation",
                &self.db_identity.generation,
                &mut inner,
            );
            canon_kv_int(
                &mut out,
                "schema_version",
                self.db_identity.schema_version,
                &mut inner,
            );
            canon_kv_str(
                &mut out,
                "sqlite_digest",
                &self.db_identity.sqlite_digest,
                &mut inner,
            );
            canon_kv_int(
                &mut out,
                "sqlite_size_bytes",
                self.db_identity.sqlite_size_bytes as i64,
                &mut inner,
            );
        }
        out.push('}');
        canon_kv_int(&mut out, "holds_count", self.holds_count, &mut first);
        canon_kv_str(&mut out, "journal_digest", &self.journal_digest, &mut first);
        canon_kv_str(&mut out, "journal_state", &self.journal_state, &mut first);
        // mirror_identity
        out.push(',');
        canon_push_str(&mut out, "mirror_identity");
        out.push_str(":{");
        {
            let mut inner = true;
            canon_kv_int(
                &mut out,
                "manifest_count",
                self.mirror_identity.manifest_count as i64,
                &mut inner,
            );
            canon_kv_str(
                &mut out,
                "manifest_root",
                &self.mirror_identity.manifest_root,
                &mut inner,
            );
        }
        out.push('}');
        canon_kv_str(&mut out, "operation_id", &self.operation_id, &mut first);
        canon_kv_int(
            &mut out,
            "origin_unmapped_count",
            self.origin_unmapped_count,
            &mut first,
        );
        canon_kv_int(&mut out, "planned_count", self.planned_count, &mut first);
        // receipt_keys（set 语义：升序去重由构造方保证，这里只做序列化）
        out.push(',');
        canon_push_str(&mut out, "receipt_keys");
        out.push_str(":[");
        for (i, key) in self.receipt_keys.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            canon_push_str(&mut out, key);
        }
        out.push(']');
        canon_kv_str(&mut out, "schema", &self.schema, &mut first);
        canon_kv_int(&mut out, "schema_version", self.schema_version, &mut first);
        canon_kv_str(&mut out, "snapshot_root", &self.snapshot_root, &mut first);
        out.push('}');
        out.into_bytes()
    }

    /// 闭世界解析：未声明字段 → `E-UNKNOWN-FIELD`；缺字段 → `E-MISSING-FIELD`。
    pub(crate) fn parse(bytes: &[u8]) -> Result<W1CommitMarker, W1MarkerError> {
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| W1MarkerError::Unparsable(e.to_string()))?;
        let obj = value
            .as_object()
            .ok_or_else(|| W1MarkerError::Unparsable("top level is not an object".into()))?;

        const TOP: &[&str] = &[
            "closure_verdict",
            "content_generation",
            "db_identity",
            "holds_count",
            "journal_digest",
            "journal_state",
            "mirror_identity",
            "operation_id",
            "origin_unmapped_count",
            "planned_count",
            "receipt_keys",
            "schema",
            "schema_version",
            "snapshot_root",
        ];
        for key in obj.keys() {
            if !TOP.contains(&key.as_str()) {
                return Err(W1MarkerError::UnknownField(key.clone()));
            }
        }
        let want_str = |k: &str| -> Result<String, W1MarkerError> {
            let v = obj
                .get(k)
                .ok_or_else(|| W1MarkerError::MissingField(k.to_string()))?;
            v.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| W1MarkerError::TypeMismatch(k.to_string()))
        };
        let want_int = |k: &str| -> Result<i64, W1MarkerError> {
            let v = obj
                .get(k)
                .ok_or_else(|| W1MarkerError::MissingField(k.to_string()))?;
            v.as_i64()
                .ok_or_else(|| W1MarkerError::TypeMismatch(k.to_string()))
        };
        let want_obj =
            |k: &str,
             allowed: &[&str]|
             -> Result<serde_json::Map<String, serde_json::Value>, W1MarkerError> {
                let v = obj
                    .get(k)
                    .ok_or_else(|| W1MarkerError::MissingField(k.to_string()))?;
                let m = v
                    .as_object()
                    .ok_or_else(|| W1MarkerError::TypeMismatch(k.to_string()))?;
                for key in m.keys() {
                    if !allowed.contains(&key.as_str()) {
                        return Err(W1MarkerError::UnknownField(format!("{k}.{key}")));
                    }
                }
                Ok(m.clone())
            };

        let db = want_obj(
            "db_identity",
            &[
                "generation",
                "schema_version",
                "sqlite_digest",
                "sqlite_size_bytes",
            ],
        )?;
        let mirror = want_obj("mirror_identity", &["manifest_count", "manifest_root"])?;
        let nested_str = |m: &serde_json::Map<String, serde_json::Value>,
                          parent: &str,
                          k: &str|
         -> Result<String, W1MarkerError> {
            m.get(k)
                .ok_or_else(|| W1MarkerError::MissingField(format!("{parent}.{k}")))?
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| W1MarkerError::TypeMismatch(format!("{parent}.{k}")))
        };
        let nested_int = |m: &serde_json::Map<String, serde_json::Value>,
                          parent: &str,
                          k: &str|
         -> Result<i64, W1MarkerError> {
            m.get(k)
                .ok_or_else(|| W1MarkerError::MissingField(format!("{parent}.{k}")))?
                .as_i64()
                .ok_or_else(|| W1MarkerError::TypeMismatch(format!("{parent}.{k}")))
        };

        let receipt_keys_value = obj
            .get("receipt_keys")
            .ok_or_else(|| W1MarkerError::MissingField("receipt_keys".into()))?;
        let arr = receipt_keys_value
            .as_array()
            .ok_or_else(|| W1MarkerError::TypeMismatch("receipt_keys".into()))?;
        let mut receipt_keys = Vec::with_capacity(arr.len());
        for item in arr {
            receipt_keys.push(
                item.as_str()
                    .ok_or_else(|| W1MarkerError::TypeMismatch("receipt_keys[]".into()))?
                    .to_string(),
            );
        }
        // set 语义：升序且无重复。乱序/重复的 marker 直接判不可解析形态，
        // 否则「摘要是内容的函数」这条就不成立了。
        let mut sorted = receipt_keys.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != receipt_keys {
            return Err(W1MarkerError::Unparsable(
                "receipt_keys must be sorted and unique (set semantics)".into(),
            ));
        }

        Ok(W1CommitMarker {
            schema: want_str("schema")?,
            schema_version: want_int("schema_version")?,
            operation_id: want_str("operation_id")?,
            snapshot_root: want_str("snapshot_root")?,
            content_generation: want_str("content_generation")?,
            journal_state: want_str("journal_state")?,
            journal_digest: want_str("journal_digest")?,
            closure_verdict: want_str("closure_verdict")?,
            planned_count: want_int("planned_count")?,
            // **必填、无缺省**（R-E-79 (a) 条件 2）：`want_int` 对缺字段报
            // `MissingField`，所以 schema 1 的旧 marker 到这里就被拒了。
            // 给它们一个 `unwrap_or(0)` 等于把「没记录」读成「零 HOLD」——
            // 那正是本次要杜绝的那句谎。
            holds_count: want_int("holds_count")?,
            origin_unmapped_count: want_int("origin_unmapped_count")?,
            receipt_keys,
            db_identity: W1DbIdentity {
                sqlite_digest: nested_str(&db, "db_identity", "sqlite_digest")?,
                sqlite_size_bytes: nested_int(&db, "db_identity", "sqlite_size_bytes")? as u64,
                schema_version: nested_int(&db, "db_identity", "schema_version")?,
                generation: nested_str(&db, "db_identity", "generation")?,
            },
            mirror_identity: W1MirrorIdentity {
                manifest_count: nested_int(&mirror, "mirror_identity", "manifest_count")? as u64,
                manifest_root: nested_str(&mirror, "mirror_identity", "manifest_root")?,
            },
        })
    }
}

/// 读 DB 里的内容代际（`meta` 保留 key）。key 常量与写侧共用一个，**不在两处各写一份**。
fn read_content_generation(db_path: &Path) -> anyhow::Result<Option<String>> {
    let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(db_path)
        .map_err(|e| anyhow::anyhow!("open db for generation read: {e}"))?;
    let got: Option<String> = storage
        .raw()
        .query_opt_map(
            "SELECT value FROM meta WHERE key = ?1",
            &[crate::storage::api::Value::from(
                crate::storage::sqlite::SOURCE_CONTENT_GENERATION_META_KEY,
            )],
            |row| row.get_typed(0),
        )?
        .flatten();
    storage.close_best_effort_in_place();
    Ok(got)
}

/// 文件字节的 blake3。**流式**，不把整份读进内存（R2 第 10 条 / R-E-98 H2）。
///
/// 修前是 `std::fs::read` 全量读入：候选库 7.2 GiB 时那是一次 7.2 GiB 连续分配，
/// 而本函数**同时被 marker 构建与 qualify 调用**——一道自称「解析级」的资格门不该
/// 按库的大小吃内存。两处调用共用这一个定义，不另造第二份。
fn file_digest(path: &Path) -> anyhow::Result<String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    // 64 KiB：与 raw_mirror 那条拷贝链同一档，别在同一个仓里散落多个「块大小」。
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// mirror 工作树身份：每份 manifest 的相对路径、**声明的** blob 哈希、以及 **manifest
/// 文件字节的摘要**，三样排序后的聚合摘要（schema 3 口径，裁定 R-E-91）。
///
/// 第三样是 schema 3 加的。schema 2 只摘前两样，而那两样**都是 manifest 自己声称的**——
/// 改它的内容不动路径与声明哈希，根值一位都不变（R1 Finding 7 实证）。
///
/// **摘的是文件字节，不是落盘记录的 `manifest_blake3`。** 后者是 manifest 自己写下的
/// 一行字：篡改者只要不动它，它就还是原值；F12 之前 relink 甚至会替他刷新它。
/// 字节摘要不依赖被测物的自述，这是它与自摘要的根本区别。
fn mirror_identity_of(data_dir: &Path) -> anyhow::Result<W1MirrorIdentity> {
    let root = crate::doctor_raw_mirror_root(data_dir);
    let views = crate::raw_mirror::manifest_views(data_dir)?;
    let mut rows: Vec<String> = Vec::with_capacity(views.len());
    for view in &views {
        let manifest_path = root.join(&view.manifest_relative_path);
        let manifest_bytes_blake3 = file_digest(&manifest_path).map_err(|e| {
            anyhow::anyhow!(
                "digest raw mirror manifest {}: {e}",
                manifest_path.display()
            )
        })?;
        rows.push(format!(
            "{}\u{1f}{}\u{1f}{}",
            view.manifest_relative_path, view.blob_blake3, manifest_bytes_blake3
        ));
    }
    rows.sort();
    let mut hasher = blake3::Hasher::new();
    for row in &rows {
        hasher.update(row.as_bytes());
        hasher.update(b"\x1e");
    }
    Ok(W1MirrorIdentity {
        manifest_count: rows.len() as u64,
        manifest_root: hasher.finalize().to_hex().to_string(),
    })
}

/// mirror 完整性校验的深度（R-E-91 三档口径里的档 2 与档 3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum MirrorVerifyDepth {
    /// **默认档**：只验 blob 的存在性与字节数。纯元数据操作（每份一次 `stat`），
    /// 与 `--qualify`「只解析、只复核」的定位相称。
    ///
    /// 保证面：能挡住 blob 被删、被截、被换成不同长度的东西。
    /// **挡不住等长改写**——那要档 3。
    #[default]
    Default,
    /// **深度档**（`--deep-verify`）：额外把每个 blob 的真实字节全读一遍重算 blake3，
    /// 与 manifest 声称的 `blob_blake3` 比对。
    ///
    /// 保证面：等长改写也挡得住。代价是真语料上一次 9.0 GiB 的顺序读，
    /// **所以它是开关而不是默认**（在一道解析级的门里塞全量重读与它的定位冲突）。
    Deep,
}

/// 档 2 / 档 3 的产出：**查了多少**。
///
/// 之所以把计数带出来而不是返回 `()`：一道「什么都没查」的门与一道「查完全过」的门，
/// 退出码长得一模一样。零 manifest 的候选在这里必须看得出来是零。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MirrorBlobVerification {
    pub manifests_checked: u64,
    /// 深度档下真正重算过字节的 blob 数（默认档恒为 0）。
    ///
    /// **按 blob 路径去重**：内容寻址下多份 manifest 会共用同一个 blob，
    /// 不去重就会把同一份 9 GiB 语料读上好几遍。大小校验不去重（每份 manifest 各自
    /// 声称一个 `blob_size_bytes`，逐份核才挡得住「某份声称错了」）。
    pub blobs_digested: u64,
}

/// 按深度档校验 mirror 里 blob 的**现实**（R-E-91 档 2 / 档 3）。
///
/// **为什么它不折进 `manifest_root`**：身份回答的是「这棵树是不是 marker attest 的那棵」，
/// 一个可比的摘要就够；而 blob 缺失 / 被截 / 被改回答的是「这棵树自己坏没坏」，要的是
/// **指名道姓的错误**。折进摘要只会得到一句 `E-IDENTITY-MISMATCH`，操作者拿着它分不出
/// 「配错了 mirror」与「盘上少了东西」——那正是本仓一路在反对的那种折叠。
fn verify_mirror_blobs(
    data_dir: &Path,
    depth: MirrorVerifyDepth,
) -> Result<MirrorBlobVerification, W1MarkerError> {
    let root = crate::doctor_raw_mirror_root(data_dir);
    let views = crate::raw_mirror::manifest_views(data_dir)
        .map_err(|e| W1MarkerError::MirrorUnreadable(format!("manifest views: {e}")))?;
    let mut digested: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for view in &views {
        let blob = root.join(&view.blob_relative_path);
        // ── R4 第 4 条 / 裁定 R-E-110 K1：与**规范校验器**同口径 ────────────
        //
        // 修前用 `std::fs::metadata`，它**跟随符号链接**且不判类型；而
        // `raw_mirror::verify_existing_file` —— 这套 mirror 的规范校验器 ——
        // 明确用 `symlink_metadata` 并拒 symlink blob。**同一件事两条路径两套口径**，
        // 于是资格门绕过了它：把 blob 换成指向外部同长度文件的链接，默认档照过；
        // 外部文件字节也相同时，**深度档一样照过**，而这份 mirror 一搬走就散了。
        //
        // 与 R4 第 1 条同族：**一条路上有的检查，兄弟路上没有。**
        let meta = match std::fs::symlink_metadata(&blob) {
            Ok(meta) => meta,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(W1MarkerError::MirrorBlobMissing {
                    manifest_relative_path: view.manifest_relative_path.clone(),
                    blob_relative_path: view.blob_relative_path.clone(),
                });
            }
            Err(err) => {
                return Err(W1MarkerError::MirrorUnreadable(format!(
                    "stat {}: {err}",
                    blob.display()
                )));
            }
        };
        if !meta.file_type().is_file() {
            return Err(W1MarkerError::MirrorBlobNotRegularFile {
                blob_relative_path: view.blob_relative_path.clone(),
                detail: format!("{:?}", meta.file_type()),
            });
        }
        if meta.len() != view.blob_size_bytes {
            return Err(W1MarkerError::MirrorBlobSizeMismatch {
                blob_relative_path: view.blob_relative_path.clone(),
                declared: view.blob_size_bytes,
                actual: meta.len(),
            });
        }
        if depth == MirrorVerifyDepth::Deep && !digested.contains(&view.blob_relative_path) {
            let actual = file_digest(&blob).map_err(|e| {
                W1MarkerError::MirrorUnreadable(format!("read {}: {e}", blob.display()))
            })?;
            if actual != view.blob_blake3 {
                return Err(W1MarkerError::MirrorBlobChecksumMismatch {
                    blob_relative_path: view.blob_relative_path.clone(),
                    declared: view.blob_blake3.clone(),
                    actual,
                });
            }
            digested.insert(view.blob_relative_path.clone());
        }
    }
    Ok(MirrorBlobVerification {
        manifests_checked: views.len() as u64,
        blobs_digested: digested.len() as u64,
    })
}

fn db_identity_of(db_path: &Path, generation: &str) -> anyhow::Result<W1DbIdentity> {
    let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(db_path)
        .map_err(|e| anyhow::anyhow!("open db for identity: {e}"))?;
    let schema_version = storage.schema_version()?;
    storage.close_best_effort_in_place();
    Ok(W1DbIdentity {
        sqlite_digest: file_digest(db_path)?,
        sqlite_size_bytes: std::fs::metadata(db_path)?.len(),
        schema_version,
        generation: generation.to_string(),
    })
}

/// 由 journal（**必须是终态**）产出 marker 的内容。
pub(crate) fn build_w1_commit_marker(
    journal: &RestoreJournal,
    journal_path: &Path,
) -> anyhow::Result<W1CommitMarker> {
    if journal.state != RestoreJournalState::ClosureVerified {
        anyhow::bail!(
            "refusing to build a W1 commit marker from a non-terminal journal ({:?})",
            journal.state
        );
    }
    let views = crate::raw_mirror::manifest_views(&journal.data_dir)?;
    let mut receipt_keys = Vec::new();
    for item in &journal.planned {
        let view = views
            .iter()
            .find(|v| v.manifest_id == item.manifest_id)
            .ok_or_else(|| {
                anyhow::anyhow!("planned manifest {} not in mirror", item.manifest_id)
            })?;
        let identity = restore_identity_from_view(view)?;
        receipt_keys.push(restore_idempotency_key_for(
            item.action,
            &journal.snapshot_root,
            &identity,
        ));
    }
    receipt_keys.sort();
    receipt_keys.dedup();

    let generation = read_content_generation(&journal.db_path)?
        .ok_or_else(|| anyhow::anyhow!("candidate db carries no source content generation"))?;

    // ── R-E-79 (b)：库侧代际必须与 journal 声称的一致 ────────────────────
    //
    // 这一格是**读库**得来的，而 journal 记的是本轮**打算**推进到的代际。两者不一致，
    // 意味着「本轮没能把代际推上去」——最典型的来路是 `planned` 为空的那一轮：
    // 代际是逐条在 commit 函数里写的，一条都没提交就没人推进它，于是 marker 会
    // attest 一个**本次运行并未建立**的代际，而 `--qualify` 拿 marker 与库两侧一比
    // 两边都是那个旧值、自洽，照过不误（R1 Finding 2 的子缺陷，实测坐实）。
    //
    // 判**硬失败**而不是「以 journal 为准改写」：这是两个真源互相矛盾，与
    // `restore_account_receipts_present` 面对的是同一类情形，那里的口径就是停手不猜。
    // 同一个文件里对同类矛盾给两套口径，才是真正会咬人的地方。
    if generation != journal.generation {
        anyhow::bail!(
            "E-GENERATION-DISAGREES: candidate db is at content generation {:?} but the journal \
             says this run advanced it to {:?} — refusing to attest a generation this run did \
             not establish (a run with an empty plan advances nothing)",
            generation,
            journal.generation
        );
    }

    Ok(W1CommitMarker {
        schema: W1_COMMIT_MARKER_SCHEMA.to_string(),
        schema_version: W1_COMMIT_MARKER_SCHEMA_VERSION,
        operation_id: journal.operation_id.clone(),
        snapshot_root: journal.snapshot_root.clone(),
        content_generation: generation.clone(),
        journal_state: "closure-verified".to_string(),
        journal_digest: file_digest(journal_path)?,
        closure_verdict: "pass".to_string(),
        planned_count: journal.planned.len() as i64,
        holds_count: journal.holds_count,
        origin_unmapped_count: journal.origin_unmapped_count,
        receipt_keys,
        db_identity: db_identity_of(&journal.db_path, &generation)?,
        mirror_identity: mirror_identity_of(&journal.data_dir)?,
    })
}

/// 写 marker：**先查后做，绝不覆盖**（不变量 I1）。
/// 已存在且逐字段相等 → no-op；不等 → 硬失败。
pub(crate) fn write_w1_commit_marker(
    marker: &W1CommitMarker,
    marker_path: &Path,
) -> anyhow::Result<bool> {
    use std::io::Write as _;
    if let Some(parent) = marker_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // 内容先写进一个**本次调用独占**的 tmp（创建时即 0600），fsync 之后再发布。
    let tmp = unique_sibling_tmp_path(marker_path)?;
    {
        let mut file = create_private_new(&tmp)?;
        file.write_all(&marker.canonical_bytes())?;
        file.sync_all()?;
    }

    // **发布是一次内核级原子的 create-new**（裁定 R-E-87）：`hard_link` 在目标已存在时
    // 以 `EEXIST` 失败，没有「先查后做」的窗口。
    //
    // 修前是 `read()` 判存在 → 写 tmp → `rename()`。那个「判存在」与「rename」之间零互斥：
    // 2000 轮并发实测里 **`refusing to overwrite` 分支一次都没走到**（TOCTOU 2000/2000 全中），
    // 挡住第二个调用方的是它 rename 时撞到的裸 `ENOENT`；而自报发布成功的那一方，
    // 盘上只有 24% 是它自己的字节（13% 是另一方的 marker，63% 是撕裂的不可解析内容）。
    let published = match std::fs::hard_link(&tmp, marker_path) {
        Ok(()) => true,
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(err) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(err.into());
        }
    };
    let _ = std::fs::remove_file(&tmp);

    if !published {
        // 已经有一份了：读回来逐字段比对。相等 = 幂等 no-op；不等 = **以自己的名义拒绝**。
        let existing = std::fs::read(marker_path)?;
        let parsed = W1CommitMarker::parse(&existing)
            .map_err(|e| anyhow::anyhow!("existing marker is unparsable: {e}"))?;
        if &parsed == marker {
            return Ok(false);
        }
        // 错误文本带**两个身份摘要**，否则操作者还得自己去翻两份文件才知道差在哪。
        anyhow::bail!(
            "existing W1 commit marker disagrees with the one we would write — \
             refusing to overwrite (on disk: operation_id={} generation={} digest={}; \
             incoming: operation_id={} generation={} digest={})",
            parsed.operation_id,
            parsed.content_generation,
            short_marker_digest(&existing),
            marker.operation_id,
            marker.content_generation,
            short_marker_digest(&marker.canonical_bytes()),
        );
    }

    if let Some(parent) = marker_path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(true)
}

/// marker canonical 字节的短摘要，只用于把「不等」这件事说清楚。
fn short_marker_digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()[..16].to_string()
}

/// 资格门的输入：**候选侧的四个磁盘对象**，没有第五个入参。
pub(crate) struct W1QualificationInput<'a> {
    pub marker_path: &'a Path,
    pub journal_path: &'a Path,
    pub db_path: &'a Path,
    pub data_dir: &'a Path,
    /// mirror 完整性校验的深度（R-E-91）。**默认档不读 blob 字节**；
    /// `MirrorVerifyDepth::Deep` 由 CLI 的 `--deep-verify` 显式打开。
    pub mirror_verify_depth: MirrorVerifyDepth,
}

/// 过门的产出：**marker 本身 + 这一遍到底查了多少**。
///
/// 不是只把 marker 返回出去，是因为「档 2/3 查了几份」必须能被消费者看见。
/// 一道跑在空 mirror 上的门与一道查完全过的门，退出码一模一样；
/// 把覆盖面带出来，`--qualify` 的输出才有分辨力（同第五棒立的清单型探针规矩）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct W1Qualification {
    pub marker: W1CommitMarker,
    pub mirror_blobs: MirrorBlobVerification,
    pub mirror_verify_depth: MirrorVerifyDepth,
}

/// **解析级机器门**（plan Task E7 Step 3），七步检查序见 wire 说明 §4。
/// 每层以自己的名义拒绝，先到先报。
///
/// # ⚠ `qualified: true` 的边界（FIND-7 / 裁定 R-E-76）
///
/// 这道门核的是**候选侧四个磁盘对象自洽**：marker 可解析、schema 对、journal
/// 到终态、身份绑定成立。它**不核库里有没有因这次恢复而新增行** —— 这是设计分工，
/// 不是缺口：资格门回答「这份候选能不能被下游接手」，回答不了「这次写了多少」。
///
/// 所以 **`qualified: true` 与 closure 绿一样，都不蕴含库里多了行**。操作者要确认
/// 恢复真的到位，用两个独立读法：① 归宿守恒等式
/// `restored + replaced + deduplicated + already_committed == planned`；
/// ② 看 `restored` / `deduplicated` 分格数字判工作量。
///
/// **不要**用「重跑 dry-run 看 `planned` 归零」当幂等完成信号：内容去重挂在另一路径上的
/// 会话**永远规划不完**，理由见 [`restore_verify_closure`] 的说明（FIND-8 / R3 第 16 条）。
pub(crate) fn qualify_w1_candidate(
    input: &W1QualificationInput<'_>,
) -> Result<W1Qualification, W1MarkerError> {
    // 1 · marker 存在且可解析为闭世界 JSON
    let bytes = match std::fs::read(input.marker_path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(W1MarkerError::MarkerMissing);
        }
        Err(err) => return Err(W1MarkerError::Unparsable(err.to_string())),
    };
    let marker = W1CommitMarker::parse(&bytes)?;

    // 2 · schema 与版本
    if marker.schema != W1_COMMIT_MARKER_SCHEMA
        || marker.schema_version != W1_COMMIT_MARKER_SCHEMA_VERSION
    {
        return Err(W1MarkerError::SchemaMismatch {
            got: format!("{}@{}", marker.schema, marker.schema_version),
            expected: format!("{W1_COMMIT_MARKER_SCHEMA}@{W1_COMMIT_MARKER_SCHEMA_VERSION}"),
        });
    }

    // 3 · journal 终态：**既看 marker 自称，也看磁盘上的 journal 本体**
    if marker.journal_state != "closure-verified" {
        return Err(W1MarkerError::JournalNotTerminal {
            detail: format!("marker claims {}", marker.journal_state),
        });
    }
    let journal = match restore_journal_read(input.journal_path) {
        Ok(Some(journal)) => journal,
        Ok(None) => {
            return Err(W1MarkerError::JournalNotTerminal {
                detail: "journal file missing".into(),
            });
        }
        Err(err) => {
            return Err(W1MarkerError::JournalNotTerminal {
                detail: format!("journal unreadable: {err}"),
            });
        }
    };
    if journal.state != RestoreJournalState::ClosureVerified {
        return Err(W1MarkerError::JournalNotTerminal {
            detail: format!("journal on disk is {:?}", journal.state),
        });
    }
    let journal_digest =
        file_digest(input.journal_path).map_err(|e| W1MarkerError::JournalNotTerminal {
            detail: format!("journal digest failed: {e}"),
        })?;
    if journal_digest != marker.journal_digest {
        return Err(W1MarkerError::JournalNotTerminal {
            detail: "journal digest does not match the marker".into(),
        });
    }

    // 4 · closure verdict
    if marker.closure_verdict != "pass" {
        return Err(W1MarkerError::ClosureNotPass {
            got: marker.closure_verdict.clone(),
        });
    }

    // 5 · 双身份逐项相符
    let generation = read_content_generation(input.db_path)
        .map_err(|e| W1MarkerError::IdentityMismatch {
            field: format!("db.generation unreadable: {e}"),
        })?
        .ok_or(W1MarkerError::IdentityMismatch {
            field: "db.generation absent".into(),
        })?;
    let db_identity = db_identity_of(input.db_path, &generation).map_err(|e| {
        W1MarkerError::IdentityMismatch {
            field: format!("db identity unreadable: {e}"),
        }
    })?;
    if db_identity != marker.db_identity {
        return Err(W1MarkerError::IdentityMismatch {
            field: "db_identity".into(),
        });
    }
    let mirror_identity =
        mirror_identity_of(input.data_dir).map_err(|e| W1MarkerError::IdentityMismatch {
            field: format!("mirror identity unreadable: {e}"),
        })?;
    if mirror_identity != marker.mirror_identity {
        return Err(W1MarkerError::IdentityMismatch {
            field: "mirror_identity".into(),
        });
    }

    // 5b · mirror 里 blob 的**现实**（R-E-91 档 2；`--deep-verify` 再加档 3）
    //
    // **排在身份之后是有意的**（同 R-E-89 给 relink 定的那条顺序纪律）：身份不符意味着
    // 手上这棵树压根不是 marker attest 的那棵，此时报「blob 少了一个」会把「配错了 mirror」
    // 说成「盘坏了」，让操作者朝错误的方向排查。先答「是不是那棵树」，再答「那棵树坏没坏」。
    //
    // 反过来说，身份对得上**不蕴含** blob 还在：身份摘的是 manifest 侧的三样东西，
    // blob 文件被删被截，它一位都不变（R1 Finding 7 探针 A 实证）。这一步是独立防线。
    let mirror_blobs = verify_mirror_blobs(input.data_dir, input.mirror_verify_depth)?;

    // 6 · receipt 交叉核：marker 说「我提交了这些」，DB 副本里的 receipt 说「确实提交过」
    let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(input.db_path)
        .map_err(|e| W1MarkerError::ReceiptMissing {
            key: format!("db unreadable: {e}"),
        })?;
    for key in &marker.receipt_keys {
        let found =
            crate::storage::sqlite::franken_operation_commit_receipt_exists(storage.raw(), key)
                .map_err(|e| W1MarkerError::ReceiptMissing {
                    key: format!("{key} (query failed: {e})"),
                })?;
        if !found {
            storage.close_best_effort_in_place();
            return Err(W1MarkerError::ReceiptMissing { key: key.clone() });
        }
    }
    storage.close_best_effort_in_place();
    if marker.receipt_keys.len() as i64 != marker.planned_count {
        return Err(W1MarkerError::ReceiptMissing {
            key: format!(
                "receipt_keys={} != planned_count={}",
                marker.receipt_keys.len(),
                marker.planned_count
            ),
        });
    }

    // 7 · 代际
    if marker.content_generation != generation {
        return Err(W1MarkerError::GenerationMismatch {
            marker: marker.content_generation.clone(),
            db: generation,
        });
    }
    Ok(W1Qualification {
        marker,
        mirror_blobs,
        mirror_verify_depth: input.mirror_verify_depth,
    })
}

// ===========================================================================
// E7 · restore 七态 journal、恢复器与崩溃注入（plan Task E7）
//
// 状态集 = spec §5.2.5 七态。本组测试锁的是那张表里「崩在此处的唯一恢复动作」
// 逐格成立，外加两条从 E6 结转的欠账：
//   欠账① Restore 支「插入已提交 / receipt 未写」窗的**真 SIGKILL 注入 + 全新进程恢复**
//         （E6 只落了状态级证据，证的是重做幂等，没证恢复器判窗正确）；
//   欠账② **receipt 顺序断言** —— 锁「receipt 必须写在插入之后」。把它提前，
//         E6 现有三条用例都不会红，而「记了没插」在重做时查到 receipt 直接短路跳过
//         = 静默丢一条会话，且没有任何约束会报错。
//
// 落点说明见 run root 的 `e7-journal-state-machine.md`（先写说明再动代码，照 E6 先例）。
// ===========================================================================
/// 递归快照一棵树的「相对路径 → 字节数」（目录记成以 `/` 结尾、大小 0）。
///
/// **三条 F15 判据共用这一个定义**（裁定 R-E-92）：复制三份等于给同一句「不写」
/// 造三套口径，日后改一份漏两份。符号链接按自身记（`symlink_metadata`），
/// 不跟随——跟随会让「链接指向的东西变了」冒充成「本树变了」。
#[cfg(test)]
pub(crate) fn test_tree_snapshot(root: &Path) -> Vec<(String, u64)> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, u64)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let rel = path.strip_prefix(base).unwrap().display().to_string();
            if meta.is_dir() {
                out.push((format!("{rel}/"), 0));
                walk(&path, base, out);
            } else {
                out.push((rel, meta.len()));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort();
    out
}

#[cfg(test)]
mod e7_restore_journal_tests {
    use super::*;
    use crate::storage::api::Value as ParamValue;
    use tempfile::TempDir;

    const SNAPSHOT_ROOT: &str = "e7-snapshot-root-0001";
    const GENERATION: &str = "gen-e7-0001";

    /// 用**真的** `capture_source_file` 造 mirror（与 E5 同一条纪律：不手写 manifest JSON，
    /// 手写等于对磁盘格式造第二定义，且格式漂移后 fixture 会一直绿着）。
    fn capture(data_dir: &Path, source: &Path) -> crate::raw_mirror::RawMirrorCaptureRecord {
        capture_as(data_dir, source, "codex")
    }

    /// 带 provider 的版本。openclaw 的实例形态（`openclaw/<inst>`）是 R3 #1 的现场，
    /// 而闭世界枚举会把它折成 family —— 夹具必须能造出这个形态才谈得上判据。
    fn capture_as(
        data_dir: &Path,
        source: &Path,
        provider: &str,
    ) -> crate::raw_mirror::RawMirrorCaptureRecord {
        crate::raw_mirror::capture_source_file(crate::raw_mirror::RawMirrorCaptureInput {
            data_dir,
            provider,
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: source,
            db_links: &[],
        })
        .expect("capture source into raw mirror")
    }

    /// 三条消息的合成 codex 会话。内容逐份不同 —— blob 是内容寻址的，
    /// 字节相同的两份源会共用同一个 blob。
    fn write_session(root: &Path, name: &str, session_id: &str) -> PathBuf {
        let dir = root.join(".codex").join("sessions").join("2026").join("08");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
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

    struct Drill {
        _tmp: TempDir,
        data_dir: PathBuf,
        scratch: PathBuf,
        db_path: PathBuf,
        journal_path: PathBuf,
        /// 库里没有 → 走新建支。
        new_manifest_id: String,
        /// 库里有一条真前缀 → 走 replace 支。
        replace_manifest_id: String,
        replace_conv_id: i64,
        replace_external_id: String,
    }

    fn conv_count(db_path: &Path) -> i64 {
        let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(db_path).unwrap();
        let n = storage
            .raw()
            .query_row_map("SELECT COUNT(*) FROM conversations", &[], |row| {
                row.get_typed(0)
            })
            .unwrap();
        storage.close_best_effort_in_place();
        n
    }

    fn msg_count(db_path: &Path, conversation_external: &str) -> i64 {
        let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(db_path).unwrap();
        let n = storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM messages m JOIN conversations c ON c.id = m.conversation_id
                 WHERE c.external_id = ?1",
                &[ParamValue::from(conversation_external)],
                |row| row.get_typed(0),
            )
            .unwrap();
        storage.close_best_effort_in_place();
        n
    }

    fn receipt_count(db_path: &Path) -> i64 {
        let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(db_path).unwrap();
        let n = storage
            .raw()
            .query_row_map(
                "SELECT COUNT(*) FROM operation_commit_receipt",
                &[],
                |row| row.get_typed(0),
            )
            .unwrap();
        storage.close_best_effort_in_place();
        n
    }

    /// 三组事务外动作的**可观测哨兵**：每一组都先造出一个「任何重做都会抹掉」的现场，
    /// 否则「恢复后收敛」可能只是无事可做的假绿（part5 判据 ⑤）。
    fn plant_post_commit_sentinels(data_dir: &Path, db_path: &Path) {
        // ① readiness：词法重建 checkpoint 存在 = 「索引自称对当前指纹新鲜」。
        let index_dir = crate::search::tantivy::expected_index_dir(data_dir);
        std::fs::create_dir_all(&index_dir).unwrap();
        std::fs::write(index_dir.join(".lexical-rebuild-state.json"), b"{}").unwrap();

        // ② embeddings：语义 sidecar 里放一条分片记录 + 一个 tier 产物。
        let mut shard =
            crate::search::semantic_manifest::SemanticShardManifest::load_or_default(data_dir)
                .unwrap();
        shard.shards.push(sentinel_shard_record());
        shard.save(data_dir).unwrap();

        // ③ analytics：daily_stats 里放一条谁都算不出来的哨兵行；重算必然抹掉它。
        let storage = crate::storage::sqlite::FrankenStorage::open(db_path).unwrap();
        storage
            .raw()
            .execute(
                "INSERT OR REPLACE INTO daily_stats
                 (day_id, agent_slug, source_id, session_count, message_count, total_chars, last_updated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                &[
                    ParamValue::from(999_999i64),
                    ParamValue::from("e7-sentinel"),
                    ParamValue::from("e7-sentinel"),
                    ParamValue::from(7i64),
                    ParamValue::from(7i64),
                    ParamValue::from(7i64),
                    ParamValue::from(0i64),
                ],
            )
            .unwrap();
    }

    fn sentinel_shard_record() -> crate::search::semantic_manifest::SemanticShardRecord {
        crate::search::semantic_manifest::SemanticShardRecord {
            tier: crate::search::semantic_manifest::TierKind::Fast,
            embedder_id: "e7-sentinel-embedder".into(),
            model_revision: "hash".into(),
            schema_version: 1,
            chunking_version: 1,
            dimension: 8,
            shard_index: 0,
            shard_count: 1,
            doc_count: 1,
            total_conversations: 1,
            db_fingerprint: "e7-sentinel-fingerprint".into(),
            index_path: "vector_index/e7-sentinel.bin".into(),
            quantization: "none".into(),
            mmap_ready: false,
            ann_index_path: None,
            ann_size_bytes: 0,
            ann_ready: false,
            size_bytes: 1,
            started_at_ms: 0,
            completed_at_ms: 0,
            ready: true,
        }
    }

    fn lexical_checkpoint_present(data_dir: &Path) -> bool {
        crate::search::tantivy::expected_index_dir(data_dir)
            .join(".lexical-rebuild-state.json")
            .exists()
    }

    fn semantic_shards_present(data_dir: &Path) -> bool {
        crate::search::semantic_manifest::SemanticShardManifest::load(data_dir)
            .unwrap()
            .map(|m| !m.shards.is_empty())
            .unwrap_or(false)
    }

    fn analytics_sentinel_present(db_path: &Path) -> bool {
        let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(db_path).unwrap();
        let found: Option<i64> = storage
            .raw()
            .query_opt_map(
                "SELECT 1 FROM daily_stats WHERE agent_slug = 'e7-sentinel'",
                &[],
                |row| row.get_typed(0),
            )
            .unwrap()
            .flatten();
        storage.close_best_effort_in_place();
        found.is_some()
    }

    /// 取某份 manifest 的 `original_path`（= 该条身份的 canonical 路径）。
    fn view_original_path(d: &Drill, manifest_id: &str) -> String {
        crate::raw_mirror::manifest_views(&d.data_dir)
            .unwrap()
            .into_iter()
            .find(|v| v.manifest_id == manifest_id)
            .expect("manifest 必须在 view 列表里")
            .original_path
    }

    /// 造一条与真身份同 `source_path`、但身份其余维度不同的「诱饵」会话。
    ///
    /// **不手写 INSERT** —— 走 drill 自己那条 `insert_conversations_batched`，
    /// 免得对「一行会话长什么样」造第二定义。`mutate` 里必须让内容与既有行不同，
    /// 否则存储层按内容去重会把它收敛掉（那样前置断言就会红，不会静默假绿）。
    fn plant_decoy_conversation(
        d: &Drill,
        manifest_id: &str,
        mutate: impl FnOnce(&mut crate::model::types::Conversation),
    ) -> i64 {
        let views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let view = views
            .iter()
            .find(|v| v.manifest_id == manifest_id)
            .expect("manifest 必须在 view 列表里");
        let mut conv = project_view_for_test(&d.data_dir, &d.scratch, view);
        mutate(&mut conv);
        let external_id = conv
            .external_id
            .clone()
            .expect("诱饵必须带 external_id —— 没有它就没法把它捞回来");

        let mut storage = crate::storage::sqlite::FrankenStorage::open(&d.db_path).unwrap();
        let agent_id = storage
            .ensure_agent(&crate::model::types::Agent {
                id: None,
                slug: conv.agent_slug.clone(),
                name: conv.agent_slug.clone(),
                version: None,
                kind: crate::model::types::AgentKind::Cli,
            })
            .unwrap();
        let workspace_id = conv
            .workspace
            .as_ref()
            .map(|ws| storage.ensure_workspace(ws, None).unwrap());
        storage
            .insert_conversations_batched(&[(agent_id, workspace_id, &conv)])
            .unwrap();
        let id: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM conversations WHERE external_id = ?1",
                &[ParamValue::from(external_id.as_str())],
                |row| row.get_typed(0),
            )
            .unwrap();
        storage.close_best_effort_in_place();
        id
    }

    /// 读某份 manifest 已发布的 backlink（`db_links` 第一条的 `conversation_id`）。
    fn published_backlink_for(d: &Drill, manifest_id: &str) -> Option<i64> {
        crate::raw_mirror::manifest_views(&d.data_dir)
            .unwrap()
            .into_iter()
            .find(|v| v.manifest_id == manifest_id)
            .expect("manifest 必须在 view 列表里")
            .db_links
            .first()
            .and_then(|link| link.conversation_id)
    }

    /// 测试侧的**独立** oracle：按四维身份把候选行捞出来。
    ///
    /// 刻意不复用被测的 `candidate_versions_from_db` —— 用被测物给被测物当判据，
    /// 两边一起错时会一起绿。
    fn conversation_ids_by_full_identity(d: &Drill, source_path: &str) -> Vec<i64> {
        let mut storage =
            crate::storage::sqlite::FrankenStorage::open_readonly(&d.db_path).unwrap();
        let found: Vec<i64> = storage
            .raw()
            .query_all_map(
                "SELECT c.id FROM conversations c JOIN agents a ON a.id = c.agent_id \
                 WHERE c.source_path = ?1 AND c.source_id = ?2 AND a.slug = ?3 \
                   AND COALESCE(NULLIF(TRIM(COALESCE(c.origin_host, '')), ''), 'local') = ?4",
                &[
                    ParamValue::from(source_path),
                    ParamValue::from("local"),
                    ParamValue::from(Origin::Codex.as_str()),
                    ParamValue::from("local"),
                ],
                |row| row.get_typed(0),
            )
            .unwrap();
        storage.close_best_effort_in_place();
        found
    }

    /// 造一条身份，`source_id` 与 `origin_host` 都可指定。
    fn identity_for(source_path: &str, source_id: &str, origin_host: &str) -> RestoreIdentity {
        RestoreIdentity {
            origin: OriginNamespace {
                agent_slug: Origin::Codex.as_str().to_string(),
                source_id: source_id.to_string(),
                origin_host: origin_host.to_string(),
            },
            canonical_path: source_path.to_string(),
        }
    }

    /// 建演练场：mirror 里两条身份，库里给其中一条种上「真前缀」。
    fn drill() -> Drill {
        drill_with_db_under(None)
    }

    /// `db_subdir = Some(name)`：把候选 DB 放到 `data_dir` **之外**的一棵独立树下。
    ///
    /// 这不是造一个假形态 —— CLI 把 `--data-dir`（mirror 面的根）与 `--candidate-db`
    /// （候选库的稳定副本）定义成**两个独立参数**，拆开正是设计用法。`None` 时逐字节
    /// 等价于原来的 `drill()`（库落在 `data_dir` 下），旧用例的现场一点没变。
    fn drill_with_db_under(db_subdir: Option<&str>) -> Drill {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        let live = tmp.path().join("live");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();

        let a = write_session(&live, "rollout-e7-new.jsonl", "e7-new");
        let b = write_session(&live, "rollout-e7-replace.jsonl", "e7-replace");
        let ca = capture(&data_dir, &a);
        let cb = capture(&data_dir, &b);
        assert_ne!(
            ca.blob_relative_path, cb.blob_relative_path,
            "前置断言：两条身份必须落在不同 blob 上（内容寻址，同字节会共用）"
        );
        // 「live 无」做到字面：投影的定义域里没有活文件系统。
        std::fs::remove_file(&a).unwrap();
        std::fs::remove_file(&b).unwrap();

        let db_path = match db_subdir {
            None => data_dir.join("e7.sqlite"),
            Some(name) => {
                let dir = tmp.path().join(name);
                std::fs::create_dir_all(&dir).unwrap();
                dir.join("e7.sqlite")
            }
        };
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();

        // 给 replace 支种一条真前缀：投影出三条消息的会话，截到两条再落库。
        let views = crate::raw_mirror::manifest_views(&data_dir).unwrap();
        let view = views
            .iter()
            .find(|v| v.manifest_id == cb.manifest_id)
            .expect("replace 支的 manifest 应当在 view 列表里");
        let mut truncated = project_view_for_test(&data_dir, &scratch, view);
        truncated.messages.truncate(2);
        let agent_id = storage
            .ensure_agent(&crate::model::types::Agent {
                id: None,
                slug: truncated.agent_slug.clone(),
                name: truncated.agent_slug.clone(),
                version: None,
                kind: crate::model::types::AgentKind::Cli,
            })
            .unwrap();
        let workspace_id = truncated
            .workspace
            .as_ref()
            .map(|ws| storage.ensure_workspace(ws, None).unwrap());
        storage
            .insert_conversations_batched(&[(agent_id, workspace_id, &truncated)])
            .unwrap();
        let external_id = truncated
            .external_id
            .clone()
            .expect("前置断言：投影产物必须带 external_id —— 没有它就无从判定同一条身份");
        let replace_conv_id: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM conversations WHERE external_id = ?1",
                &[ParamValue::from(external_id.as_str())],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(
            conv_count(&db_path),
            1,
            "前置断言：演练开始时库里恰有一条（replace 支的真前缀），新建支那条必须不在"
        );

        Drill {
            _tmp: tmp,
            data_dir,
            scratch,
            db_path,
            journal_path: tmp_journal_path(),
            new_manifest_id: ca.manifest_id,
            replace_manifest_id: cb.manifest_id,
            replace_conv_id,
            replace_external_id: external_id,
        }
    }

    fn tmp_journal_path() -> PathBuf {
        // journal 落 run root 之外的临时目录：测试不碰任何生产路径。
        let dir = std::env::temp_dir().join(format!("cc-cass-e7-journal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!(
            "restore-journal-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// 测试侧投影：走的仍是生产那条 `read_sealed_blob → project_sealed_source → map_to_internal`，
    /// 不另写一份投影。
    fn project_view_for_test(
        data_dir: &Path,
        scratch: &Path,
        view: &crate::raw_mirror::RawMirrorManifestView,
    ) -> crate::model::types::Conversation {
        let reports = collect_sealed_manifest_reports(data_dir);
        let report = reports
            .iter()
            .find(|r| r.manifest_id == view.manifest_id)
            .expect("每份 manifest 都应有一份 doctor 报告");
        let blob = match read_sealed_blob(data_dir, report) {
            SealedBlobOutcome::Loaded(bytes) => bytes,
            other => panic!("fixture 的 blob 必须读得到：{other:?}"),
        };
        let provenance = provenance_from_manifest_view(view);
        let sealed = SealedSource {
            agent: Origin::Codex,
            canonical_original_path: &view.original_path,
            source_size_bytes: view.source_size_bytes,
            blob: &blob,
        };
        match project_sealed_source(scratch, &sealed, &provenance) {
            Ok(SealedProjection::Projected(conv)) => {
                crate::indexer::persist::map_to_internal(&conv)
            }
            other => panic!("封存投影未产出会话：{other:?}"),
        }
    }

    fn plan_for(d: &Drill) -> RestoreRunPlan {
        RestoreRunPlan {
            operation_id: "e7-op-0001".into(),
            data_dir: d.data_dir.clone(),
            scratch_dir: d.scratch.clone(),
            db_path: d.db_path.clone(),
            marker_path: d.db_path.parent().unwrap().join(W1_COMMIT_MARKER_FILENAME),
            snapshot_root: SNAPSHOT_ROOT.into(),
            generation: GENERATION.into(),
            // 取**互不相同且非零**的值：两格都填 0 的话，一次串位（把 holds 写进
            // unmapped 那一格）在所有断言下都看不出来。
            holds_count: 3,
            origin_unmapped_count: 1,
            planned: vec![
                RestorePlanItem {
                    manifest_id: d.new_manifest_id.clone(),
                    action: PlannedAction::RestoreNew,
                },
                RestorePlanItem {
                    manifest_id: d.replace_manifest_id.clone(),
                    action: PlannedAction::Replace {
                        conversation_id: d.replace_conv_id,
                    },
                },
            ],
        }
    }

    // ── T1：happy path，七态走到终态，三组事务外动作都真的做了 ──────────────
    #[test]
    fn e7_apply_walks_the_seven_states_and_does_all_three_post_commit_actions() {
        let d = drill();
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);
        assert!(
            lexical_checkpoint_present(&d.data_dir)
                && semantic_shards_present(&d.data_dir)
                && analytics_sentinel_present(&d.db_path),
            "前置断言：三个哨兵必须都在，否则「恢复后收敛」是无事可做的假绿"
        );

        let outcome = restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();

        assert_eq!(outcome.restored, 1, "新建支恰一条");
        assert_eq!(outcome.replaced, 1, "replace 支恰一条");
        assert_eq!(conv_count(&d.db_path), 2, "库里应当恰有两条会话");
        assert_eq!(receipt_count(&d.db_path), 2, "两条身份各恰一条 receipt");

        let journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        assert_eq!(
            journal.state,
            RestoreJournalState::ClosureVerified,
            "journal 终态 = closure-verified（§5.2.5 七态，不新增第八态）"
        );
        assert!(
            !lexical_checkpoint_present(&d.data_dir),
            "readiness 必须已失效：词法重建 checkpoint 应当被删掉"
        );
        assert!(
            !semantic_shards_present(&d.data_dir),
            "embedding 必须已作废：语义分片记录应当被清空"
        );
        assert!(
            !analytics_sentinel_present(&d.db_path),
            "analytics 必须已重算：daily_stats 的哨兵行应当被抹掉"
        );
    }

    // ── H1 · #3（R-E-98 H1 / R2 第 3 条）────────────────────────────────
    //
    // 索引作废这两格必须跟着**被改的那个库**走，不能跟着 mirror 的 `--data-dir` 走。
    //
    // CLI 把 `--data-dir`（mirror 面的根）与 `--candidate-db`（候选库的稳定副本）
    // 定义成两个**独立**参数 —— 拆开跑不是异常形态，是设计用法。而 readiness /
    // embedding 这两格作废的对象是「谁在自称对当前指纹新鲜」，那份状态按 cass 自己的
    // 目录约定躺在**库所在的那棵树**里（`default_db_path() = default_data_dir()/agent_search.db`；
    // `plan_for` 里 marker 路径也早就是从 `db_path.parent()` 取的）。
    //
    // 修前两格都读 `journal.data_dir`：拆开跑时**清掉的是 mirror 那棵树**（真实操作里
    // 那往往就是生产 data_dir），而**被改的候选库那棵树照旧自称新鲜**。两个方向都要
    // 断言 —— 只断言「候选那棵被清了」会被一个「反正两棵都清」的实现蒙混过去。
    #[test]
    fn e7_index_invalidation_follows_the_candidate_db_not_the_mirror_data_dir() {
        let d = drill_with_db_under(Some("candidate-tree"));
        let candidate_dir = d.db_path.parent().unwrap().to_path_buf();
        assert_ne!(
            candidate_dir, d.data_dir,
            "前置断言：两棵树必须真的不同，否则本例什么都证不了"
        );

        // 两棵树各种一份哨兵。第三格（analytics）落在库里，与树无关，种一次即可。
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);
        plant_post_commit_sentinels(&candidate_dir, &d.db_path);
        assert!(
            lexical_checkpoint_present(&d.data_dir) && lexical_checkpoint_present(&candidate_dir),
            "前置断言：两棵树都得先有 readiness 哨兵"
        );
        assert!(
            semantic_shards_present(&d.data_dir) && semantic_shards_present(&candidate_dir),
            "前置断言：两棵树都得先有 embedding 哨兵"
        );

        restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();

        assert!(
            !lexical_checkpoint_present(&candidate_dir),
            "被改的是候选库 —— 它那棵树的 readiness 必须失效"
        );
        assert!(
            !semantic_shards_present(&candidate_dir),
            "被改的是候选库 —— 它那棵树的 embedding 必须作废"
        );
        assert!(
            lexical_checkpoint_present(&d.data_dir),
            "mirror 的 data_dir 不是被改的那个库：动它的 readiness 是在动一个本轮没碰过的库"
        );
        assert!(
            semantic_shards_present(&d.data_dir),
            "同上：mirror data_dir 的 embedding 不得被作废"
        );
    }

    // ── H1 · #8（R-E-98 H1 / R2 第 8 条）────────────────────────────────
    //
    // 崩在 `db-committed` **之后**再 `--recover`，归宿仍必须对得上账。
    //
    // `restore_drive` 只在 `state == Planned` 时跑 `restore_run_db_phase` —— 那是全仓
    // **唯一**填 outcome 的地方（定义一处、调用一处）。其余状态只 assert receipt 在不在，
    // 于是恢复一轮四格全 0、`receipt_keys` 空，而那正是操作者对账用的东西。
    // R-E-83 修的是 `Planned` 支**内部**那一分支，**post-`DbCommitted` 这一支从没被覆盖**。
    #[test]
    fn e7_recover_after_db_committed_still_accounts_the_committed_work() {
        let d = drill();
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);
        let first = restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();
        assert_eq!(
            first.restored + first.replaced + first.deduplicated + first.already_committed,
            2,
            "前置断言：首跑必须把两条都归进某一格"
        );

        // 倒回那个真实存在的窗：DB 提交了、journal 也已推进到 db-committed，
        // 后面几格还没做完就崩了。
        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        journal.state = RestoreJournalState::DbCommitted;
        journal.published.clear();
        restore_journal_write(&d.journal_path, &journal).unwrap();

        let outcome = restore_recover(&d.journal_path).unwrap();

        assert_eq!(
            outcome.already_committed, 2,
            "两条都已提交过 → 必须落进 already_committed 这一格，而不是消失"
        );
        assert_eq!(
            outcome.restored + outcome.replaced + outcome.deduplicated,
            0,
            "恢复这一轮没有真写库，那三格必须是 0（别把已提交的工作量重报一遍）"
        );
        assert_eq!(
            outcome.already_committed + outcome.restored + outcome.replaced + outcome.deduplicated,
            journal.planned.len(),
            "归宿守恒：四格之和 == planned，恢复路径恰恰是最需要对账的时候"
        );
        let mut keys = outcome.receipt_keys.clone();
        keys.sort();
        keys.dedup();
        assert_eq!(
            keys.len(),
            2,
            "receipt_keys 是「哪几条真的提交了」的唯一可查凭据，恢复路径不得交空"
        );
    }

    // ── H1 · #4（R-E-98 H1 / R2 第 4 条）────────────────────────────────
    //
    // 发布 backlink 时的候选行查询必须绑**整条身份**，不能只绑路径。
    //
    // 与 #5 互为镜像：同一份身份，查候选时绑了三维（还漏了 host），发布时只绑一维。
    //
    // ⚠ 实测把 R2 对本条后果的描述补全了：只绑路径时，库里存在**另一条同路径异来源**
    // 的会话，命中就是两行，而那句查询是 `query_row_map(..).optional()` ——
    // 多行不是「挑一条」，是 `Err("query returned more than one row")`，`?` 一路抛上去，
    // **apply 在 publish 这一格硬失败**。此时 DB 已提交、journal 已过 `db-committed`，
    // 于是一条同路径的邻居就能把整轮恢复卡在半路。R2 只写了「照发布」那一半
    // （那是恰好一行、而那一行不是本条身份时的形状，由下半那条用例锁）。
    #[test]
    fn e7_publish_backlink_binds_the_whole_identity_not_the_path_alone() {
        let d = drill();
        let new_path = view_original_path(&d, &d.new_manifest_id);

        // 诱饵：**同 source_path**，但 source_id 与 host 都不是新建支那条身份。
        let decoy_id = plant_decoy_conversation(&d, &d.replace_manifest_id, |conv| {
            conv.source_path = std::path::PathBuf::from(&new_path);
            conv.source_id = "some-other-machine".to_string();
            conv.origin_host = Some("some-other-host".to_string());
            conv.external_id = Some("e7-decoy-external-id".to_string());
            conv.messages[0].content.push_str(" -- decoy body");
        });

        // 修前这一行就抛 `query returned more than one row`。
        restore_apply_journaled(plan_for(&d), &d.journal_path)
            .expect("同路径异来源的邻居不该把整轮恢复卡死在 publish 这一格");

        let real = conversation_ids_by_full_identity(&d, &new_path);
        assert_eq!(
            real.len(),
            1,
            "前置断言：四维全等的行必须恰有一条（诱饵不在这个集合里）"
        );
        let linked = published_backlink_for(&d, &d.new_manifest_id);
        assert_ne!(
            linked,
            Some(decoy_id),
            "backlink 不得指向同路径异来源的那一条"
        );
        assert_eq!(
            linked,
            Some(real[0]),
            "backlink 必须指向与本条身份四维全等的那一行"
        );
    }

    // ── H1 · #4 下半：查不到候选行时，publish 不得**静默**发一条空 backlink ──
    //
    // 查不到本身不必然是错（内容去重把行收敛到另一条 source_path 上时就查不到，
    // FIND-7 / R-E-76 已裁定那是合法归宿），所以口径不是硬失败 —— 是**记账**：
    // 空 backlink 必须有它自己的一格，别混进「已发布」里让操作者以为回链建好了。
    #[test]
    fn e7_publish_without_a_backlink_is_counted_not_silent() {
        let d = drill();
        // 只跑 publish 这一格：库里此时**没有**新建支那条会话（drill 的前置断言就是
        // 「库里恰有一条 = replace 支的真前缀」），于是新建支必然查不到候选行。
        //
        // 顺带锁住**静默指错**那一形态：库里放一条同路径、异来源的诱饵。恰好一行命中
        // 时那句只绑路径的查询不会报「多行」，它会**安静地把诱饵的 id 当成回链发出去**。
        let new_path = view_original_path(&d, &d.new_manifest_id);
        let decoy_id = plant_decoy_conversation(&d, &d.replace_manifest_id, |conv| {
            conv.source_path = std::path::PathBuf::from(&new_path);
            conv.source_id = "some-other-machine".to_string();
            conv.origin_host = Some("some-other-host".to_string());
            conv.external_id = Some("e7-decoy-external-id".to_string());
            conv.messages[0].content.push_str(" -- decoy body");
        });
        assert!(
            conversation_ids_by_full_identity(&d, &new_path).is_empty(),
            "前置断言：四维全等的行此刻必须一条都没有 —— 否则本例证不到「查不到」那一支"
        );

        let mut journal = restore_journal_from_plan(plan_for(&d));
        let mut outcome = RestoreRunOutcome::default();
        restore_publish_manifests(&mut journal, &d.journal_path, &mut outcome).unwrap();

        assert_eq!(outcome.published, 2, "两份 manifest 都该发布出去");
        assert_eq!(
            outcome.published_without_backlink, 1,
            "恰有一条（新建支）查不到候选行 —— 必须记账，不许静默"
        );
        let linked = published_backlink_for(&d, &d.new_manifest_id);
        assert_ne!(
            linked,
            Some(decoy_id),
            "静默指错：只绑路径时，恰好一行命中的诱饵会被当成本条身份的回链发出去"
        );
        assert_eq!(linked, None, "查不到就是 None，不许凭路径猜一个填进去");
        assert_eq!(
            published_backlink_for(&d, &d.replace_manifest_id),
            Some(d.replace_conv_id),
            "阳性对照：replace 支的 backlink 由计划显式带着，必须照常建立且不进那一格"
        );
    }

    // ── H1 · #5（R-E-98 H1 / R2 第 5 条）────────────────────────────────
    //
    // 候选查询必须把 `origin_host` 也绑上 —— 且要按**它存进去会长什么样**绑。
    //
    // 修前那条查询绑 path / source_id / agent 三维，漏掉 host；而代码注释声称
    // 「`conversations` 侧没有对应列」——那句是假的（建表处三处 `origin_host TEXT`，
    // relink 自己就在 `SELECT c.origin_host`）。漏掉这一维的后果与 R1 Finding 3 同族：
    // 跨 host 同路径的两条身份被折进同一堆候选，判成 replace 后互相覆盖。
    #[test]
    fn e7_candidate_lookup_binds_origin_host_too() {
        let d = drill();
        let new_path = view_original_path(&d, &d.new_manifest_id);

        // 同 path、同 source_id、同 agent，**只差 host**。用远端 source_id：本机源的
        // host 存储层不保留（下一条用例锁的就是那件事），拿本机源做这条会证不到东西。
        let h1 = plant_decoy_conversation(&d, &d.new_manifest_id, |conv| {
            conv.source_path = std::path::PathBuf::from(&new_path);
            conv.source_id = "work-laptop".to_string();
            conv.origin_host = Some("h1".to_string());
            conv.external_id = Some("e7-host-h1".to_string());
            conv.messages[0].content.push_str(" -- body h1");
        });
        let h2 = plant_decoy_conversation(&d, &d.new_manifest_id, |conv| {
            conv.source_path = std::path::PathBuf::from(&new_path);
            conv.source_id = "work-laptop".to_string();
            conv.origin_host = Some("h2".to_string());
            conv.external_id = Some("e7-host-h2".to_string());
            conv.messages[0].content.push_str(" -- body h2");
        });
        assert_ne!(h1, h2, "前置断言：两条必须真的是两行，没被按内容去重合并");

        let mut storage =
            crate::storage::sqlite::FrankenStorage::open_readonly(&d.db_path).unwrap();
        let hits = |host: &str| {
            conversation_ids_for_identity(&storage, &identity_for(&new_path, "work-laptop", host))
                .unwrap()
        };
        assert_eq!(
            hits("h1"),
            vec![h1],
            "h1 那条身份只该看见 h1 那一行 —— 漏绑 host 会把 h2 也拖进候选堆"
        );
        assert_eq!(
            hits("h2"),
            vec![h2],
            "反向同理：h2 的身份不该看见 h1 那一行"
        );
        storage.close_best_effort_in_place();
    }

    // ── H1 · #5 的另一半：本机源的 host 存储层**不保留**，这一维对它不具区分力 ──
    //
    // 这条用例存在的意义是把一条**真实边界**钉成机器判据，而不是留在注释里。
    // 原注释说的「不可判」结论有一半是对的，但理由（「没有对应列」）是错的：
    // 列在、能绑，只是 `normalized_storage_source_parts` 在写库时就把本机源的
    // `origin_host` 丢成了 `NULL`（实测：`(local, "h1")` 落盘成 `(local, NULL)`）。
    //
    // 于是查询必须按「存进去的样子」比 —— 拿 manifest 上的字面量硬比会**丢候选**：
    // 一份 `source_id=local, origin_host=Some("h1")` 的 manifest 永远匹配不上它自己
    // 那一行，判成 `RestoreNew` 重复插入，比漏绑更糟。
    #[test]
    fn e7_candidate_lookup_cannot_discriminate_host_for_local_sources() {
        let d = drill();
        let new_path = view_original_path(&d, &d.new_manifest_id);

        let with_host = plant_decoy_conversation(&d, &d.new_manifest_id, |conv| {
            conv.source_path = std::path::PathBuf::from(&new_path);
            conv.source_id = "local".to_string();
            conv.origin_host = Some("h1".to_string());
            conv.external_id = Some("e7-local-with-host".to_string());
            conv.messages[0].content.push_str(" -- local with host");
        });
        let without_host = plant_decoy_conversation(&d, &d.new_manifest_id, |conv| {
            conv.source_path = std::path::PathBuf::from(&new_path);
            conv.source_id = "local".to_string();
            conv.origin_host = None;
            conv.external_id = Some("e7-local-no-host".to_string());
            conv.messages[0].content.push_str(" -- local no host");
        });

        // 前置断言：落盘之后这两行的 host 列**都是空的** —— 这就是「存储层不保留」的字面证据。
        let mut storage =
            crate::storage::sqlite::FrankenStorage::open_readonly(&d.db_path).unwrap();
        let stored_hosts: Vec<String> = storage
            .raw()
            .query_all_map(
                "SELECT COALESCE(c.origin_host, '<NULL>') FROM conversations c \
                 WHERE c.external_id IN ('e7-local-with-host', 'e7-local-no-host') ORDER BY c.id",
                &[],
                |row| row.get_typed(0),
            )
            .unwrap();
        assert_eq!(
            stored_hosts,
            vec!["<NULL>".to_string(), "<NULL>".to_string()],
            "前置断言：本机源那两行的 origin_host 落盘后必须都是 NULL"
        );

        // 于是两条身份都只能看见同一对行 —— 这不是漏绑，是信息在写库时就没了。
        let mut expected = vec![with_host, without_host];
        expected.sort();
        for host in ["h1", RESTORE_LOCAL_ORIGIN_HOST] {
            let mut hits =
                conversation_ids_for_identity(&storage, &identity_for(&new_path, "local", host))
                    .unwrap();
            hits.sort();
            assert_eq!(
                hits, expected,
                "本机源：host={host} 这条身份必须仍然看见那两行 —— 按字面量硬比会丢掉自己的行"
            );
        }
        storage.close_best_effort_in_place();
    }

    // ── H2 · #10（R-E-98 H2 / R2 第 10 条）──────────────────────────────
    //
    // `file_digest` 曾是 `std::fs::read` 全量读进内存再哈希。候选库 7.2 GiB 时那是一次
    // 7.2 GiB 连续分配，与「解析级资格门」的定位矛盾（它同时被 marker 构建与 qualify 调用）。
    //
    // 这一条先锁**正确性**：改成流式之后，分块边界上不能算错。取 0 / 1 / 恰好一块 /
    // 一块少一字节 / 一块多一字节 / 多块 六个尺寸，逐个与一次性哈希对比。
    // 边界那几个尺寸不是凑数——分块实现最典型的错法就是丢最后一个不满块，或在整除时多走一轮。
    #[test]
    fn file_digest_matches_one_shot_across_chunk_boundaries() {
        let tmp = TempDir::new().unwrap();
        const CHUNK: usize = 64 * 1024;
        for (i, size) in [0usize, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 7]
            .into_iter()
            .enumerate()
        {
            let path = tmp.path().join(format!("blob-{i}.bin"));
            // 内容不能是全同字节：那样「块序搞错」也算得出同一个值，用例就没有分辨力。
            let bytes: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
            std::fs::write(&path, &bytes).unwrap();
            assert_eq!(
                file_digest(&path).unwrap(),
                blake3::hash(&bytes).to_hex().to_string(),
                "size={size} 的摘要与一次性哈希不符"
            );
        }
    }

    /// #10 的**内存**判据用的子进程入口：只做「摘一个文件」这一件事。
    #[test]
    #[ignore = "由 file_digest_does_not_slurp_the_whole_file_into_memory 以受限地址空间拉起"]
    fn h2_file_digest_child_entrypoint() {
        let path = PathBuf::from(std::env::var("CASS_H2_DIGEST_PATH").unwrap());
        let digest = file_digest(&path).expect("child: file_digest must succeed");
        std::fs::write(std::env::var("CASS_H2_RESULT").unwrap(), digest).unwrap();
    }

    // ── H2 · #10 的真判据：受限地址空间下必须摘得完 ──────────────────────
    //
    // 只测「分块算得对」是不够的——那种用例对「一次性读进内存」同样是绿的，等于没有门。
    // 这里用**稀疏**大文件（`set_len`，占 0 个块，不吃磁盘）配 `ulimit -v` 把子进程的
    // 地址空间卡在远低于文件尺寸、又远高于二进制自身需求的地方：
    // 流式摘要过得去，一次性 `fs::read` 必然分配失败。
    //
    // 带**宽松上限的阳性对照**：先证明这套子进程机制本身跑得通，否则「紧上限下失败」
    // 可能只是机制没搭对，而不是被测行为。
    #[test]
    fn file_digest_does_not_slurp_the_whole_file_into_memory() {
        const FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024; // 4 GiB，稀疏
        const TIGHT_KIB: u64 = 2 * 1024 * 1024; // 2 GiB 地址空间上限
        const LOOSE_KIB: u64 = 16 * 1024 * 1024; // 16 GiB，阳性对照

        let tmp = TempDir::new().unwrap();
        let sparse = tmp.path().join("sparse-4g.bin");
        std::fs::File::create(&sparse)
            .unwrap()
            .set_len(FILE_BYTES)
            .unwrap();
        // 前置断言：它必须真的是稀疏的，否则这条用例在偷偷吃 4 GiB 磁盘。
        {
            use std::os::unix::fs::MetadataExt as _;
            let meta = std::fs::metadata(&sparse).unwrap();
            assert_eq!(meta.size(), FILE_BYTES, "前置断言：逻辑尺寸必须是 4 GiB");
            assert!(
                meta.blocks() * 512 < 1024 * 1024,
                "前置断言：必须是稀疏文件（实占 {} 字节）—— 否则本用例在吃磁盘",
                meta.blocks() * 512
            );
        }

        let run = |limit_kib: u64| -> std::process::ExitStatus {
            let result = tmp.path().join(format!("digest-{limit_kib}.txt"));
            let exe = std::env::current_exe().expect("test binary path");
            std::process::Command::new("bash")
                .arg("-c")
                .arg(format!(
                    "ulimit -v {limit_kib}; exec \"$0\" --ignored --exact \"$1\"",
                ))
                .arg(exe)
                .arg("phase3_restore::e7_restore_journal_tests::h2_file_digest_child_entrypoint")
                .env("CASS_H2_DIGEST_PATH", &sparse)
                .env("CASS_H2_RESULT", &result)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("spawn digest child")
        };

        assert!(
            run(LOOSE_KIB).success(),
            "阳性对照：地址空间宽松时子进程必须跑得通 —— 不通说明是机制没搭对，不是被测行为"
        );
        assert!(
            run(TIGHT_KIB).success(),
            "地址空间卡在 2 GiB、文件 4 GiB：流式摘要必须过得去，整份读进内存必然过不去"
        );
    }

    // ── J1 · R3 #2：Display 串不得再当键用 ─────────────────────────────
    //
    // 原来的构成是 `{agent}@{host}:{source_id} {path}`，分隔符**既不转义也不带长度框**。
    // 于是 `(host="a:b", source_id="c")` 与 `(host="a", source_id="b:c")` 拼出**同一个串**：
    // 分组时两条身份会被并成一条（后者的 manifest 进前者的版本集合），
    // 幂等 key 也会撞车——一条的 receipt 把另一条短路掉。
    //
    // 真语料上目前不可达（实测 `source_id`/`origin_host` 含空格或冒号的行 0），
    // 但那两个字段的取值来自**外部**（远端 source 命名），不该靠「现在没人这么起名」立着。
    #[test]
    fn j1_ambiguous_display_strings_do_not_collide_as_keys() {
        let a = RestoreIdentity {
            origin: OriginNamespace {
                agent_slug: "codex".to_string(),
                source_id: "c".to_string(),
                origin_host: "a:b".to_string(),
            },
            canonical_path: "/x".to_string(),
        };
        let b = RestoreIdentity {
            origin: OriginNamespace {
                agent_slug: "codex".to_string(),
                source_id: "b:c".to_string(),
                origin_host: "a".to_string(),
            },
            canonical_path: "/x".to_string(),
        };

        assert_eq!(
            a.to_string(),
            b.to_string(),
            "前置断言：这两条身份的 Display 串必须真的相同 —— 否则本例证不到「键会撞」"
        );
        assert_ne!(a, b, "它们是两条不同的身份（结构上不等）");

        for op in ["snap-1", "snap-2"] {
            assert_ne!(
                restore_new_idempotency_key(op, &a),
                restore_new_idempotency_key(op, &b),
                "新建支的幂等 key 不得因 Display 撞车而相同"
            );
            assert_ne!(
                replace_idempotency_key(op, &a),
                replace_idempotency_key(op, &b),
                "replace 支同理"
            );
        }

        // 阳性对照：同一条身份的 key 必须稳定可复现，否则「不撞」可以靠随机达成。
        assert_eq!(
            restore_new_idempotency_key("snap-1", &a),
            restore_new_idempotency_key("snap-1", &a)
        );
    }

    // ── J1 · R3 #1：候选查询这一路 ────────────────────────────────────
    //
    // 身份的 agent 维带的是闭世界折叠值 `"openclaw"`，而 DB 侧 `agents.slug` 是
    // `"openclaw/<inst>"` —— 于是 openclaw 实例的会话**永远查不到候选**，
    // 一律被判成 `RestoreNew`，重复插入。
    #[test]
    fn j1_candidate_lookup_finds_an_openclaw_instance_conversation() {
        let d = drill();
        let path = "/home/u/.openclaw/inst-a/sessions/s.jsonl";
        let id = plant_decoy_conversation(&d, &d.new_manifest_id, |conv| {
            conv.source_path = std::path::PathBuf::from(path);
            conv.agent_slug = "openclaw/inst-a".to_string();
            conv.external_id = Some("j1-openclaw-inst".to_string());
            conv.messages[0].content.push_str(" -- openclaw instance");
        });

        let mut storage =
            crate::storage::sqlite::FrankenStorage::open_readonly(&d.db_path).unwrap();
        let identity = RestoreIdentity {
            origin: OriginNamespace {
                // **实例形态**，不是 `Origin::Openclaw.as_str()`（那是 family `"openclaw"`）。
                // 批量改名时我一度把这里也机械换成了 family 值，用例当场红 —— 那正是本条要防的错。
                agent_slug: "openclaw/inst-a".to_string(),
                source_id: "local".to_string(),
                origin_host: RESTORE_LOCAL_ORIGIN_HOST.to_string(),
            },
            canonical_path: path.to_string(),
        };
        let hits = conversation_ids_for_identity(&storage, &identity).unwrap();
        storage.close_best_effort_in_place();

        assert_eq!(
            hits,
            vec![id],
            "openclaw 实例的会话必须查得到 —— 折叠成 family 之后 a.slug 绑的是 \"openclaw\"，\
             而库里存的是 \"openclaw/inst-a\"，于是永远查不到、判成 RestoreNew 重复插入"
        );
    }

    // ── J1 · R3 #1：publish backlink 这一路 ───────────────────────────
    //
    // 与上一条同根。H1 之前 publish 只绑 `source_path`，openclaw 实例靠路径**能**查到；
    // H1 把整条身份绑上去之后，agent 维带着折叠值参与匹配，**backlink 从正确变成 None**。
    // 这一条是我 H1 引入的回归，用例锁它。
    #[test]
    fn j1_publish_backlink_resolves_for_an_openclaw_instance_manifest() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        let live = tmp.path().join("live");
        std::fs::create_dir_all(&data_dir).unwrap();
        let src = write_session(&live, "rollout-j1-openclaw.jsonl", "j1-openclaw");
        let rec = capture_as(&data_dir, &src, "openclaw/inst-a");
        let views = crate::raw_mirror::manifest_views(&data_dir).unwrap();
        let view = views
            .iter()
            .find(|v| v.manifest_id == rec.manifest_id)
            .expect("manifest 必须在 view 列表里");

        // 库里种一条**身份完全对得上**的会话：同路径、同 source_id、agent slug 是实例形态。
        let db_path = data_dir.join("j1.sqlite");
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
        let agent_id = storage
            .ensure_agent(&crate::model::types::Agent {
                id: None,
                slug: "openclaw/inst-a".into(),
                name: "openclaw/inst-a".into(),
                version: None,
                kind: crate::model::types::AgentKind::Cli,
            })
            .unwrap();
        let conv = crate::model::types::Conversation {
            id: None,
            agent_slug: "openclaw/inst-a".into(),
            workspace: None,
            external_id: Some("j1-openclaw-conv".into()),
            title: None,
            source_path: std::path::PathBuf::from(&view.original_path),
            started_at: Some(1),
            ended_at: Some(2),
            approx_tokens: None,
            metadata_json: serde_json::json!({}),
            messages: vec![crate::model::types::Message {
                id: None,
                idx: 0,
                role: crate::model::types::MessageRole::User,
                author: None,
                created_at: Some(1),
                content: "j1 openclaw body".into(),
                extra_json: serde_json::json!({}),
                snippets: Vec::new(),
            }],
            source_id: "local".into(),
            origin_host: None,
        };
        storage
            .insert_conversations_batched(&[(agent_id, None, &conv)])
            .unwrap();
        let expected: i64 = storage
            .raw()
            .query_row_map(
                "SELECT id FROM conversations WHERE external_id = ?1",
                &[ParamValue::from("j1-openclaw-conv")],
                |row| row.get_typed(0),
            )
            .unwrap();
        drop(storage);

        let plan = RestoreRunPlan {
            operation_id: "j1-op".into(),
            data_dir: data_dir.clone(),
            scratch_dir: tmp.path().join("scratch"),
            db_path: db_path.clone(),
            marker_path: db_path.parent().unwrap().join(W1_COMMIT_MARKER_FILENAME),
            snapshot_root: SNAPSHOT_ROOT.into(),
            generation: GENERATION.into(),
            holds_count: 0,
            origin_unmapped_count: 0,
            planned: vec![RestorePlanItem {
                manifest_id: rec.manifest_id.clone(),
                action: PlannedAction::RestoreNew,
            }],
        };
        let mut journal = restore_journal_from_plan(plan);
        let mut outcome = RestoreRunOutcome::default();
        restore_publish_manifests(&mut journal, &tmp_journal_path(), &mut outcome).unwrap();

        let linked = crate::raw_mirror::manifest_views(&data_dir)
            .unwrap()
            .into_iter()
            .find(|v| v.manifest_id == rec.manifest_id)
            .unwrap()
            .db_links
            .first()
            .and_then(|l| l.conversation_id);
        assert_eq!(
            linked,
            Some(expected),
            "openclaw 实例 manifest 的 backlink 必须解析得出 —— 这条在 H1 之前是对的"
        );
        assert_eq!(
            outcome.published_without_backlink, 0,
            "身份对得上就不该计进「发布了但没配上回链」那一格"
        );
    }

    // ── T2：`planned` + **无 receipt** → 必须**重放事务** ─────────────────
    //
    // §5.2.5 原文：「无 receipt 则重放事务」。⚠ 这与 E3 relink 的「不做半步恢复」**相反**，
    // 不得跨任务搬运：relink 崩在计划态什么都不做也不丢东西（重跑 dry-run 即收敛），
    // 而 restore 的计划是**还没做的写库工作**，不重放 = 把这批会话永久丢掉。
    #[test]
    fn e7_planned_without_receipt_replays_the_transaction() {
        let d = drill();
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);
        let mut journal = restore_journal_from_plan(plan_for(&d));
        journal.state = RestoreJournalState::Planned;
        restore_journal_write(&d.journal_path, &journal).unwrap();

        assert_eq!(
            receipt_count(&d.db_path),
            0,
            "前置断言：现场必须没有 receipt"
        );
        assert_eq!(conv_count(&d.db_path), 1, "前置断言：新建支那条还没进库");

        let outcome = restore_recover(&d.journal_path).unwrap();

        assert_eq!(
            outcome.restored, 1,
            "无 receipt = 事务没提交过 → 必须重放，把新建支那条写进去"
        );
        assert_eq!(conv_count(&d.db_path), 2, "重放后库里应当有两条");
        assert_eq!(receipt_count(&d.db_path), 2);
        assert_eq!(
            restore_journal_read(&d.journal_path)
                .unwrap()
                .unwrap()
                .state,
            RestoreJournalState::ClosureVerified
        );
    }

    // ── T3：DB 已提交而 journal 仍停 `planned` → 必须**前进**，不得丢弃 ────
    #[test]
    fn e7_planned_with_receipt_advances_instead_of_discarding() {
        let d = drill();
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);
        // 先完整跑一遍，把 DB 侧做完（receipt 落库）。
        restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();
        let conv_after_first = conv_count(&d.db_path);
        let receipts_after_first = receipt_count(&d.db_path);

        // 再把现场倒回那个**必然存在**的窗：journal 退回 `planned`，
        // 三组事务外动作的哨兵重新种上（模拟「DB 提交了、journal 没推进就崩了」）。
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);
        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        journal.state = RestoreJournalState::Planned;
        journal.committed.clear();
        journal.published.clear();
        restore_journal_write(&d.journal_path, &journal).unwrap();

        let outcome = restore_recover(&d.journal_path).unwrap();

        assert_eq!(
            conv_count(&d.db_path),
            conv_after_first,
            "查到 receipt = 已提交 → **不得**重放 DB 事务，会话数不许变"
        );
        assert_eq!(
            receipt_count(&d.db_path),
            receipts_after_first,
            "receipt 也不许多出来"
        );
        assert_eq!(
            outcome.restored + outcome.replaced,
            0,
            "这一轮不该有任何新的写库动作"
        );
        // 「前进」的观测量：三组事务外动作**必须真的补做**。
        assert!(
            !lexical_checkpoint_present(&d.data_dir),
            "前进 = 续做 readiness 失效；当无副作用丢弃的话这个哨兵会留着"
        );
        assert!(!semantic_shards_present(&d.data_dir));
        assert!(!analytics_sentinel_present(&d.db_path));
        assert_eq!(
            restore_journal_read(&d.journal_path)
                .unwrap()
                .unwrap()
                .state,
            RestoreJournalState::ClosureVerified
        );
    }

    // ── T4：过了 `db-committed` 却查不到 receipt = 两个真源互相矛盾 → 硬失败 ──
    #[test]
    fn e7_state_past_db_committed_without_receipt_is_a_hard_failure() {
        let d = drill();
        restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();
        // 把 receipt 抹掉，制造矛盾现场。
        let storage = crate::storage::sqlite::FrankenStorage::open(&d.db_path).unwrap();
        storage
            .raw()
            .execute("DELETE FROM operation_commit_receipt;", &[])
            .unwrap();
        drop(storage);

        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        journal.state = RestoreJournalState::ReadinessInvalidated;
        restore_journal_write(&d.journal_path, &journal).unwrap();

        let err = restore_recover(&d.journal_path)
            .expect_err("状态已过 db-committed 却无 receipt，必须硬失败而不是猜");
        let text = format!("{err:#}");
        assert!(
            text.contains("receipt"),
            "错误必须点名 receipt 缺失，实得：{text}"
        );
    }

    // ── T5：重跑幂等 —— 收敛后再恢复一次必须是 no-op ────────────────────
    #[test]
    fn e7_second_recovery_is_a_no_op() {
        let d = drill();
        restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();
        let convs = conv_count(&d.db_path);
        let receipts = receipt_count(&d.db_path);

        let again = restore_recover(&d.journal_path).unwrap();

        assert_eq!(again.restored + again.replaced, 0, "第二次恢复不得再写库");
        assert_eq!(conv_count(&d.db_path), convs);
        assert_eq!(receipt_count(&d.db_path), receipts);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FIND-7 · 新建支的报数据实（裁定 R-E-76）
    //
    // 缺陷原样：`commit_restore_new` 丢掉 `insert_conversations_batched` 返回的
    // `Vec<InsertOutcome>`，无条件 `applied: true` —— 存储层按**内容**判定这条会话
    // 已经在库里、一行都没插时，编排层照样报 `restored += 1` 与
    // `messages_inserted += conv.messages.len()`。
    //
    // 为什么既有电池全绿还是漏了它：既有用例覆盖的全是「插入成功」那条路径，
    // **没有一条断言「插入被去重时的报数」**。查测试盲区要问的不只是「后态怎么读」，
    // 还有「**哪条分支的报数**从没被断言过」。
    // ═══════════════════════════════════════════════════════════════════════

    /// 只留新建支那一项的计划 —— 两条判据用例都只关心新建支的报数。
    fn restore_new_only_plan(d: &Drill) -> RestoreRunPlan {
        let mut plan = plan_for(d);
        plan.planned
            .retain(|item| matches!(item.action, PlannedAction::RestoreNew));
        assert_eq!(
            plan.planned.len(),
            1,
            "前置断言：裁剪后计划里必须恰剩新建支那一项"
        );
        plan
    }

    /// 把新建支那条身份的**完整投影**原样种进库，返回它的消息条数。
    ///
    /// 走的是生产那条 `read_sealed_blob → project_sealed_source → map_to_internal`，
    /// 所以种进去的字节与 restore 稍后自己投影出来的**逐字段同一**——
    /// 去重是按内容判的，内容不同一就测不到去重。
    fn seed_restore_new_content(d: &Drill) -> usize {
        let views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let view = views
            .iter()
            .find(|v| v.manifest_id == d.new_manifest_id)
            .expect("新建支的 manifest 应当在 view 列表里");
        let conv = project_view_for_test(&d.data_dir, &d.scratch, view);
        let message_total = conv.messages.len();
        assert!(
            message_total > 0,
            "前置断言：fixture 必须真的带消息，否则「messages_inserted == 0」是无分辨力的假绿"
        );

        let storage = crate::storage::sqlite::FrankenStorage::open(&d.db_path).unwrap();
        let agent_id = storage
            .ensure_agent(&crate::model::types::Agent {
                id: None,
                slug: conv.agent_slug.clone(),
                name: conv.agent_slug.clone(),
                version: None,
                kind: crate::model::types::AgentKind::Cli,
            })
            .unwrap();
        let workspace_id = conv
            .workspace
            .as_ref()
            .map(|ws| storage.ensure_workspace(ws, None).unwrap());
        let seeded = storage
            .insert_conversations_batched(&[(agent_id, workspace_id, &conv)])
            .unwrap();
        assert!(
            seeded[0].conversation_inserted,
            "前置断言：种入这一步自己必须是真插入 —— 否则后面测的根本不是「去重」"
        );
        assert_eq!(
            seeded[0].inserted_indices.len(),
            message_total,
            "前置断言：种入必须把消息全插进去"
        );
        drop(storage);
        message_total
    }

    /// 判据①：**内容已经在库里** → `restored == 0` / `deduplicated == 1` /
    /// `messages_inserted == 0`。
    ///
    /// 造这条案例的判据是「**内容指纹**不在库里」而不是「路径不在库里」：去重按内容判，
    /// 「同一份会话换个路径」在库里就是同一条。这里把这个判据反过来用。
    #[test]
    fn e7_restore_new_reports_deduplicated_not_restored_when_the_content_is_already_there() {
        let d = drill();
        let message_total = seed_restore_new_content(&d);

        let convs_before = conv_count(&d.db_path);
        assert_eq!(
            convs_before, 2,
            "前置断言：replace 支的真前缀 + 刚种进去的新建支内容"
        );

        let outcome = restore_apply_journaled(restore_new_only_plan(&d), &d.journal_path).unwrap();

        assert_eq!(
            outcome.deduplicated, 1,
            "去重命中必须计入具名的 `deduplicated` 格 —— 它是「动作做过了、但库里没多行」\
             这件事的唯一出口，并进 `restored` 就等于把它藏起来"
        );
        assert_eq!(
            (outcome.restored, outcome.messages_inserted),
            (0, 0),
            "一行会话、一条消息都没插进去（fixture 共 {message_total} 条消息），\
             `restored` 就不许是 1、`messages_inserted` 也不许是 `conv.messages.len()` \
             —— 这两个数字一起构成 FIND-7 的形状"
        );
        assert_eq!(
            conv_count(&d.db_path),
            convs_before,
            "末端对账：库里的会话数一条都不许变"
        );
        assert_eq!(
            outcome.receipt_keys.len(),
            1,
            "去重不改变幂等语义：receipt 照写，重跑仍然短路"
        );
    }

    /// 判据②：**全新内容** → `restored == 1`，且**全新进程读回**的计数真的增长了。
    ///
    /// **自读不算数。** 写路径自己报的成功、以及同进程/同连接读回的后态，
    /// 都可能看得见还没落到别人眼里的东西；FIND-7 的全部代价就在这一句里。
    #[test]
    fn e7_restore_new_restored_count_is_confirmed_by_a_fresh_process_readback() {
        let d = drill();
        let views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let view = views
            .iter()
            .find(|v| v.manifest_id == d.new_manifest_id)
            .expect("新建支的 manifest 应当在 view 列表里");
        let message_total = project_view_for_test(&d.data_dir, &d.scratch, view)
            .messages
            .len();
        assert!(message_total > 0, "前置断言：fixture 必须真的带消息");

        let (convs_before, msgs_before) = readback_in_fresh_child(&d);
        assert_eq!(
            (convs_before, msgs_before),
            (1, 2),
            "前置断言：全新进程读回时库里只有 replace 支那条两消息的真前缀"
        );

        let outcome = restore_apply_journaled(restore_new_only_plan(&d), &d.journal_path).unwrap();

        assert_eq!(
            (outcome.restored, outcome.deduplicated),
            (1, 0),
            "内容全新 → 必须真插入，报 restored=1、deduplicated=0"
        );
        assert_eq!(
            outcome.messages_inserted, message_total,
            "全新内容下真实插入条数应当等于投影出来的消息条数"
        );

        let (convs_after, msgs_after) = readback_in_fresh_child(&d);
        assert_eq!(
            convs_after - convs_before,
            1,
            "**新进程读回**的会话数必须恰好增长 1 —— 自读不算数"
        );
        assert_eq!(
            msgs_after - msgs_before,
            message_total as i64,
            "**新进程读回**的消息数必须恰好增长 {message_total} 条"
        );
    }

    /// **全新进程**读回 `(会话数, 消息数)`。
    fn readback_in_fresh_child(d: &Drill) -> (i64, i64) {
        let result = d.db_path.parent().unwrap().join("e7-readback-result.txt");
        let _ = std::fs::remove_file(&result);
        let status = child_command(
            "phase3_restore::e7_restore_journal_tests::e7_readback_child_entrypoint",
            d,
        )
        .env("CASS_E7_RESULT", &result)
        .status()
        .expect("spawn readback child");
        assert!(status.success(), "读回子进程必须成功退出，实得 {status:?}");
        let text = std::fs::read_to_string(&result).expect("读回子进程必须写出结果");
        let mut parts = text.split_whitespace();
        (
            parts.next().unwrap().parse().unwrap(),
            parts.next().unwrap().parse().unwrap(),
        )
    }

    /// 读回子进程入口：**全新进程**，只读打开候选库数两张表。
    #[test]
    #[ignore]
    fn e7_readback_child_entrypoint() {
        let db = PathBuf::from(std::env::var("CASS_E7_DB").unwrap());
        let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(&db).unwrap();
        let (convs, msgs): (i64, i64) = storage
            .raw()
            .query_row_map(
                "SELECT (SELECT COUNT(*) FROM conversations), (SELECT COUNT(*) FROM messages)",
                &[],
                |row| Ok((row.get_typed(0)?, row.get_typed(1)?)),
            )
            .unwrap();
        storage.close_best_effort_in_place();
        std::fs::write(
            std::env::var("CASS_E7_RESULT").unwrap(),
            format!("{convs} {msgs}"),
        )
        .unwrap();
    }

    // ═══════════════════════════════════════════════════════════════════════
    // 崩溃注入（R-E-19 三要求逐条兑现）
    //
    // ① **确定性握手定边界**：子进程到达边界写哨兵文件后原地阻塞，父进程见哨兵才 kill。
    //    禁 sleep 赌时序 —— 赌时序会让注入点漂移，测的就不是那个边界。
    // ② **kill 只打显式持有的子进程句柄**（`Child::kill`，Unix 上即 SIGKILL）。
    //    不杀进程组、不按名字模式匹配。
    // ③ **恢复跑为另一个全新子进程**，输入仅磁盘 journal + receipt。
    //    （E3 的恢复是进程内调用；本任务把它抬到真·跨进程。）
    // ═══════════════════════════════════════════════════════════════════════

    /// 崩溃子进程入口：由父进程用 `--ignored --exact` 拉起。
    #[test]
    #[ignore]
    fn e7_crash_child_entrypoint() {
        let planned: Vec<RestorePlanItem> =
            serde_json::from_str(&std::env::var("CASS_E7_PLAN_JSON").unwrap()).unwrap();
        let plan = RestoreRunPlan {
            operation_id: "e7-op-crash".into(),
            data_dir: PathBuf::from(std::env::var("CASS_E7_DATA_DIR").unwrap()),
            scratch_dir: PathBuf::from(std::env::var("CASS_E7_SCRATCH").unwrap()),
            db_path: PathBuf::from(std::env::var("CASS_E7_DB").unwrap()),
            marker_path: PathBuf::from(std::env::var("CASS_E7_DB").unwrap())
                .parent()
                .unwrap()
                .join(W1_COMMIT_MARKER_FILENAME),
            snapshot_root: SNAPSHOT_ROOT.into(),
            generation: GENERATION.into(),
            holds_count: 3,
            origin_unmapped_count: 1,
            planned,
        };
        let journal = PathBuf::from(std::env::var("CASS_E7_JOURNAL").unwrap());
        let _ = restore_apply_journaled(plan, &journal);
    }

    /// 恢复子进程入口：**全新进程**，入参只有 journal 路径。
    #[test]
    #[ignore]
    fn e7_recover_child_entrypoint() {
        let journal = PathBuf::from(std::env::var("CASS_E7_JOURNAL").unwrap());
        let out = restore_recover(&journal).expect("recovery must converge");
        std::fs::write(
            std::env::var("CASS_E7_RESULT").unwrap(),
            format!("{} {}", out.restored, out.replaced),
        )
        .unwrap();
    }

    fn child_command(test_name: &str, d: &Drill) -> std::process::Command {
        let exe = std::env::current_exe().expect("test binary path");
        let mut cmd = std::process::Command::new(exe);
        cmd.args(["--ignored", "--exact", test_name])
            .env("CASS_E7_DATA_DIR", &d.data_dir)
            .env("CASS_E7_SCRATCH", &d.scratch)
            .env("CASS_E7_DB", &d.db_path)
            .env("CASS_E7_JOURNAL", &d.journal_path)
            // 双 env 隔离兜底：子进程一旦有任何一步回落到「按 env 找产物目录」，
            // 也只会落在本用例的 tempdir 里，碰不到生产。
            .env("CASS_DATA_DIR", &d.data_dir)
            .env("XDG_DATA_HOME", d.data_dir.parent().unwrap())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd
    }

    fn pid_alive(pid: u32) -> bool {
        Path::new(&format!("/proc/{pid}")).exists()
    }

    /// 在 `boundary` 处注入 SIGKILL。返回 (pid, 是否真的握手到那个边界)。
    fn crash_at(boundary: &str, d: &Drill) -> (u32, bool) {
        let sentinel = d
            .db_path
            .parent()
            .unwrap()
            .join(format!("e7-sentinel-{boundary}"));
        let plan_json = serde_json::to_string(&plan_for(d).planned).unwrap();
        let mut child = child_command(
            "phase3_restore::e7_restore_journal_tests::e7_crash_child_entrypoint",
            d,
        )
        .env("CASS_E7_PLAN_JSON", plan_json)
        .env("CASS_RESTORE_PAUSE_AT", boundary)
        .env("CASS_RESTORE_PAUSE_SENTINEL", &sentinel)
        .spawn()
        .expect("spawn crash child");
        let pid = child.id();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let mut handshaken = false;
        while std::time::Instant::now() < deadline {
            if sentinel.exists() {
                handshaken = true;
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                // 子进程自己结束了。**这里必须留下退出状态** —— 否则「哨兵未出现」
                // 会把两种完全不同的原因混成一句话：真·边界不可达，
                // 与「子进程根本没跑起来」（本棒实测：`--exact` 少写模块前缀 →
                // 零匹配、立即退出）。
                eprintln!("crash child exited before boundary {boundary}: {status:?}");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        if handshaken {
            child.kill().expect("SIGKILL the recorded child");
        }
        let _ = child.wait();
        (pid, handshaken)
    }

    /// 恢复：**另一个全新子进程**，输入只有磁盘上的 journal + receipt。
    fn recover_in_fresh_child(d: &Drill) -> (usize, usize) {
        let result = d.db_path.parent().unwrap().join("e7-recover-result.txt");
        let _ = std::fs::remove_file(&result);
        let status = child_command(
            "phase3_restore::e7_restore_journal_tests::e7_recover_child_entrypoint",
            d,
        )
        .env("CASS_E7_RESULT", &result)
        .status()
        .expect("spawn recovery child");
        assert!(status.success(), "恢复子进程必须成功退出，实得 {status:?}");
        let text = std::fs::read_to_string(&result).expect("恢复子进程必须写出结果");
        let mut parts = text.split_whitespace();
        (
            parts.next().unwrap().parse().unwrap(),
            parts.next().unwrap().parse().unwrap(),
        )
    }

    /// 崩溃现场应有的样子：崩在这个边界时，**哪些活还没干**。
    /// 三重断言的第二重靠它 —— 没有未竟工作，「恢复后收敛」就是无事可做的假绿。
    fn assert_work_pending_at(boundary: &str, d: &Drill) {
        match boundary {
            "planned" => {
                assert_eq!(receipt_count(&d.db_path), 0, "崩在 planned：不该有 receipt");
                assert_eq!(conv_count(&d.db_path), 1, "崩在 planned：新建支还没进库");
            }
            // ── 欠账②的机器判据：receipt 必须写在插入**之后** ──────────────
            // 把 receipt 提前，这里就会变成「receipt 在、消息不在」，本断言立刻红。
            // 「记了没插」为什么更糟：重做时查到 receipt → 直接短路跳过 → **静默丢一条
            // 会话**，而且没有任何约束会报错（UNIQUE 只拦重复 receipt，拦不住会话没进来）。
            "restore-new-inserted-not-receipted" => {
                assert_eq!(
                    conv_count(&d.db_path),
                    2,
                    "崩在这个窗：插入已提交，会话必须在库里"
                );
                assert_eq!(
                    receipt_count(&d.db_path),
                    0,
                    "崩在这个窗：receipt 必须**还没**写 —— 若它先于插入落库，这条即红"
                );
            }
            "db-committed" => {
                assert_eq!(receipt_count(&d.db_path), 2, "DB 阶段已完成");
                assert!(
                    lexical_checkpoint_present(&d.data_dir)
                        && semantic_shards_present(&d.data_dir)
                        && analytics_sentinel_present(&d.db_path),
                    "三组事务外动作都还没做"
                );
            }
            "readiness-invalidated" => {
                assert!(!lexical_checkpoint_present(&d.data_dir), "readiness 已失效");
                assert!(semantic_shards_present(&d.data_dir), "embedding 还没作废");
            }
            "embeddings-invalidated" => {
                assert!(!semantic_shards_present(&d.data_dir), "embedding 已作废");
                assert!(analytics_sentinel_present(&d.db_path), "analytics 还没重算");
            }
            "analytics-rebuilt" => {
                assert!(!analytics_sentinel_present(&d.db_path), "analytics 已重算");
                assert!(
                    restore_journal_read(&d.journal_path)
                        .unwrap()
                        .unwrap()
                        .published
                        .is_empty(),
                    "manifest 一份都还没 publish"
                );
            }
            "manifest-partial" => {
                let j = restore_journal_read(&d.journal_path).unwrap().unwrap();
                assert_eq!(
                    j.published.len(),
                    1,
                    "崩在第一份 publish 之后：恰有一份完成，剩下的靠差集续做"
                );
            }
            "closure-verified" => {
                let j = restore_journal_read(&d.journal_path).unwrap().unwrap();
                assert_eq!(j.published.len(), 2, "publish 已全部完成");
            }
            other => panic!("未登记的边界：{other}"),
        }
    }

    fn assert_converged(d: &Drill) {
        assert_eq!(conv_count(&d.db_path), 2, "收敛后库里恰两条会话，不重不漏");
        assert_eq!(receipt_count(&d.db_path), 2, "两条身份各恰一条 receipt");
        assert_eq!(
            msg_count(&d.db_path, &d.replace_external_id),
            3,
            "replace 支收敛后必须是三条消息（真前缀被换成完整版）"
        );
        assert!(!lexical_checkpoint_present(&d.data_dir));
        assert!(!semantic_shards_present(&d.data_dir));
        assert!(!analytics_sentinel_present(&d.db_path));
        let j = restore_journal_read(&d.journal_path).unwrap().unwrap();
        assert_eq!(j.state, RestoreJournalState::ClosureVerified);
        assert_eq!(j.published.len(), 2);
    }

    /// 一个边界的完整三重断言 + 跨进程恢复。
    fn boundary_case(boundary: &str, expected_state: RestoreJournalState) {
        let d = drill();
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);

        let (pid, handshaken) = crash_at(boundary, &d);
        assert!(
            handshaken,
            "边界 {boundary} 未被子进程到达（哨兵未出现）—— 注入点不可达，不能算通过"
        );
        assert!(!pid_alive(pid), "SIGKILL 之后子进程 {pid} 必须已死");

        // 第一重：崩溃现场的 journal **恰为**该边界的状态。
        let mid = restore_journal_read(&d.journal_path)
            .unwrap()
            .expect("journal 必须已落盘");
        assert_eq!(
            mid.state, expected_state,
            "在 {boundary} 注入，崩溃现场的 journal 状态应为 {expected_state:?}"
        );
        // 第二重：崩溃时确有未竟工作。
        assert_work_pending_at(boundary, &d);

        // 第三重：全新子进程恢复后收敛，再恢复一次是 no-op。
        recover_in_fresh_child(&d);
        assert_converged(&d);
        let (again_restored, again_replaced) = recover_in_fresh_child(&d);
        assert_eq!(
            (again_restored, again_replaced),
            (0, 0),
            "第二次恢复必须是 no-op"
        );
        assert_converged(&d);
    }

    #[test]
    fn e7_crash_at_planned_boundary_converges() {
        boundary_case("planned", RestoreJournalState::Planned);
    }

    // ── 欠账①：Restore 支「插入已提交 / receipt 未写」窗的真 SIGKILL 注入 ──
    //
    // E6 只落了**状态级**证据（事后构造那个状态 → 重做 → 不重不漏、receipt 恰一条），
    // 证的是**重做幂等**；**没证**「恢复器判窗正确」—— 那要真 SIGKILL + 全新进程
    // 只读 journal 与 receipt，而恢复器是本任务的交付。这条用例补的就是那一层。
    #[test]
    fn e7_crash_between_restore_new_insert_and_receipt_converges() {
        boundary_case(
            "restore-new-inserted-not-receipted",
            RestoreJournalState::Planned,
        );
    }

    #[test]
    fn e7_crash_at_db_committed_boundary_converges() {
        boundary_case("db-committed", RestoreJournalState::DbCommitted);
    }

    #[test]
    fn e7_crash_at_readiness_invalidated_boundary_converges() {
        boundary_case(
            "readiness-invalidated",
            RestoreJournalState::ReadinessInvalidated,
        );
    }

    #[test]
    fn e7_crash_at_embeddings_invalidated_boundary_converges() {
        boundary_case(
            "embeddings-invalidated",
            RestoreJournalState::EmbeddingsInvalidated,
        );
    }

    #[test]
    fn e7_crash_at_analytics_rebuilt_boundary_converges() {
        boundary_case("analytics-rebuilt", RestoreJournalState::AnalyticsRebuilt);
    }

    #[test]
    fn e7_crash_at_manifest_partial_boundary_converges() {
        boundary_case("manifest-partial", RestoreJournalState::ManifestPartial);
    }

    #[test]
    fn e7_crash_at_closure_verified_boundary_converges() {
        boundary_case("closure-verified", RestoreJournalState::ClosureVerified);
    }

    // ── fsync 顺序（§5.2.5：写 tmp → fsync 文件 → rename → fsync 目录 → 再推进）──
    #[test]
    fn e7_journal_write_follows_the_spec_fsync_order() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("j.json");
        let journal = restore_journal_from_plan(RestoreRunPlan {
            operation_id: "e7-fsync".into(),
            data_dir: dir.path().to_path_buf(),
            scratch_dir: dir.path().to_path_buf(),
            db_path: dir.path().join("x.sqlite"),
            marker_path: dir.path().join(W1_COMMIT_MARKER_FILENAME),
            snapshot_root: SNAPSHOT_ROOT.into(),
            generation: GENERATION.into(),
            holds_count: 0,
            origin_unmapped_count: 0,
            planned: Vec::new(),
        });

        let _ = journal_trace_take();
        restore_journal_write(&path, &journal).unwrap();
        let trace = journal_trace_take();

        assert_eq!(
            trace,
            vec!["write-tmp", "fsync-file", "rename", "fsync-dir"],
            "§5.2.5 的顺序是硬规定：写临时文件 → fsync 文件 → rename → fsync 目录"
        );
        // 顺序之外的两条可观测配套：临时文件不得残留；落盘的是完整 JSON（rename 原子性）。
        assert!(!path.with_extension("tmp").exists(), "临时文件不得残留");
        assert!(restore_journal_read(&path).unwrap().is_some());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Step 3 · W1 commit marker 与**解析级**资格门
    //
    // plan 原文：「资格检查是**解析级机器门，不是文件存在判定**」。四种非法候选全拒
    // （缺 marker / journal 未终态 / closure 红 / 身份不符），外加一条**合法候选判 PASS
    // 的阳性对照** —— 没有它，「全拒」有可能只是接口恒拒的假绿。
    // ═══════════════════════════════════════════════════════════════════════

    fn marker_path_of(d: &Drill) -> PathBuf {
        d.db_path.parent().unwrap().join(W1_COMMIT_MARKER_FILENAME)
    }

    fn qualify_at(d: &Drill, depth: MirrorVerifyDepth) -> Result<W1Qualification, W1MarkerError> {
        let marker_path = marker_path_of(d);
        qualify_w1_candidate(&W1QualificationInput {
            marker_path: &marker_path,
            journal_path: &d.journal_path,
            db_path: &d.db_path,
            data_dir: &d.data_dir,
            mirror_verify_depth: depth,
        })
    }

    /// 默认档（档 1+2）。既有用例全部走它 —— 默认路径的行为不因 R-E-91 而改变，
    /// 变的只是它多看见了哪些东西。
    fn qualify(d: &Drill) -> Result<W1CommitMarker, W1MarkerError> {
        qualify_at(d, MirrorVerifyDepth::Default).map(|q| q.marker)
    }

    /// 深度档（档 3，`--deep-verify`）。
    fn qualify_deep(d: &Drill) -> Result<W1Qualification, W1MarkerError> {
        qualify_at(d, MirrorVerifyDepth::Deep)
    }

    /// 跑完一次完整 restore，得到一个**真候选**（marker 由恢复器自己在终态写出）。
    fn qualified_candidate() -> Drill {
        let d = drill();
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);
        restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();
        assert!(
            marker_path_of(&d).exists(),
            "前置断言：终态必须产出 marker，否则下面的拒绝用例分辨不出「拒对了」还是「本来就没有」"
        );
        d
    }

    fn rewrite_marker(d: &Drill, edit: impl FnOnce(&mut W1CommitMarker)) {
        let bytes = std::fs::read(marker_path_of(d)).unwrap();
        let mut marker = W1CommitMarker::parse(&bytes).unwrap();
        edit(&mut marker);
        std::fs::write(marker_path_of(d), marker.canonical_bytes()).unwrap();
    }

    // ── 阳性对照：合法候选必须判 PASS ────────────────────────────────────
    #[test]
    fn e7_qualification_accepts_a_real_candidate() {
        let d = qualified_candidate();
        let marker = qualify(&d).expect("合法候选必须过门");
        assert_eq!(marker.schema, W1_COMMIT_MARKER_SCHEMA);
        assert_eq!(marker.journal_state, "closure-verified");
        assert_eq!(marker.closure_verdict, "pass");
        assert_eq!(marker.planned_count, 2);
        assert_eq!(marker.receipt_keys.len(), 2);
    }

    // ── 非法候选 ①：缺 marker ───────────────────────────────────────────
    #[test]
    fn e7_qualification_rejects_a_missing_marker() {
        let d = qualified_candidate();
        std::fs::remove_file(marker_path_of(&d)).unwrap();
        let err = qualify(&d).expect_err("缺 marker 必须拒");
        assert_eq!(err.code(), "E-MARKER-MISSING");
    }

    // ── 非法候选 ②：marker 在，但磁盘上的 journal **未终态** ─────────────
    //
    // 这条正是「文件存在判定」与「解析级机器门」的分水岭：marker 文件好端端在那儿，
    // 只有把 journal 解析开、看它停在哪一格，才拒得掉。
    #[test]
    fn e7_qualification_rejects_a_non_terminal_journal() {
        let d = qualified_candidate();
        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        journal.state = RestoreJournalState::AnalyticsRebuilt;
        restore_journal_write(&d.journal_path, &journal).unwrap();
        let err = qualify(&d).expect_err("journal 未终态必须拒");
        assert_eq!(err.code(), "E-JOURNAL-NOT-TERMINAL");
    }

    // ── 非法候选 ③：closure 红 ──────────────────────────────────────────
    #[test]
    fn e7_qualification_rejects_a_red_closure() {
        let d = qualified_candidate();
        rewrite_marker(&d, |m| m.closure_verdict = "fail".into());
        let err = qualify(&d).expect_err("closure 红必须拒");
        assert_eq!(err.code(), "E-CLOSURE-NOT-PASS");
    }

    // ── 非法候选 ④：marker 与候选**身份不符** ───────────────────────────
    //
    // 用**真的身份漂移**构造，不是改 marker 字段：marker 写完之后往 mirror 里再封一条
    // 会话 —— 候选那棵 mirror 工作树变了，而 marker 记的是旧身份。
    // 这比「手改一个摘要字段」更贴近真实误用（换一棵 mirror 配一个 DB 副本）。
    #[test]
    fn e7_qualification_rejects_an_identity_mismatch() {
        let d = qualified_candidate();
        let extra_live = d.data_dir.parent().unwrap().join("extra-live");
        let extra = write_session(&extra_live, "rollout-e7-extra.jsonl", "e7-extra");
        capture(&d.data_dir, &extra);

        let err = qualify(&d).expect_err("mirror 身份漂移必须拒");
        assert_eq!(err.code(), "E-IDENTITY-MISMATCH");
    }

    // ══ R1 Finding 7 / 裁定 R-E-91：身份口径必须覆盖「被声称的东西还是不是那个东西」══
    //
    // 修前 `mirror_identity_of` 只摘 (manifest 相对路径, manifest 里**声明**的 blob_blake3)
    // 这一对。于是 marker 立好之后：blob 被删、被截、被改，或 manifest 的字节被改而路径与
    // 声明哈希不变 —— 重算出的 `manifest_root` **一位都不变**，`--qualify` 照过。
    //
    // 三档口径（R-E-91）：档 1（manifest 字节摘要入 rows）+ 档 2（blob 存在性与大小）进默认；
    // 档 3（blob 真实字节全读重算）做 `--deep-verify` 开关 —— 在这道「只解析、只复核」的门里
    // 放一次全量重读（真语料 9488 manifest / 9.0 GiB）与它的定位冲突，所以不进默认路径。

    /// 档 2 上半：marker 立好之后**删掉 blob 文件**，资格门必须以自己的名义拒。
    #[test]
    fn e7_qualification_notices_a_deleted_blob() {
        let d = qualified_candidate();
        assert!(qualify(&d).is_ok(), "前置断言：动手之前必须是合格的");

        let root = crate::doctor_raw_mirror_root(&d.data_dir);
        let views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let victim = views.first().expect("至少一份 manifest").clone();
        let blob = root.join(&victim.blob_relative_path);
        assert!(
            blob.exists(),
            "前置断言：blob 必须真的在，否则本用例恒红、没有分辨力"
        );
        std::fs::remove_file(&blob).unwrap();

        let err = qualify(&d).expect_err("blob 已经被删掉，资格门必须察觉");
        assert_eq!(err.code(), "E-MIRROR-BLOB-MISSING");
    }

    /// 档 2 下半：blob 还在，但盘上的字节数与 manifest 声称的 `blob_size_bytes` 不符。
    ///
    /// **为什么单独一条**：删文件与改文件是两个不同的失败面，共用一条用例就分不出
    /// 「存在性查了、大小没查」这种半拉子实现。
    #[test]
    fn e7_qualification_notices_a_truncated_blob() {
        let d = qualified_candidate();
        assert!(qualify(&d).is_ok(), "前置断言：动手之前必须是合格的");

        let root = crate::doctor_raw_mirror_root(&d.data_dir);
        let views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let victim = views.first().expect("至少一份 manifest").clone();
        let blob = root.join(&victim.blob_relative_path);
        let on_disk = std::fs::metadata(&blob).unwrap().len();
        assert_eq!(
            on_disk, victim.blob_size_bytes,
            "前置断言：动手之前盘上的大小必须与 manifest 声称的一致"
        );
        assert!(on_disk > 0, "前置断言：blob 非空，否则截不动");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&blob)
            .unwrap()
            .set_len(on_disk - 1)
            .unwrap();

        let err = qualify(&d).expect_err("blob 被截短，资格门必须察觉");
        assert_eq!(err.code(), "E-MIRROR-BLOB-SIZE-MISMATCH");
    }

    /// 档 1：改 manifest 的**字节**（相对路径与声明的 blob 哈希都不动），mirror 身份必须变。
    #[test]
    fn e7_mirror_identity_covers_manifest_bytes() {
        let d = qualified_candidate();
        let before = mirror_identity_of(&d.data_dir).unwrap();

        let root = crate::doctor_raw_mirror_root(&d.data_dir);
        let views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let victim = views.first().expect("至少一份 manifest").clone();
        let mpath = root.join(&victim.manifest_relative_path);
        let raw = std::fs::read_to_string(&mpath).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        json["original_path"] = serde_json::Value::String("/tampered/by/someone-else.jsonl".into());
        std::fs::write(&mpath, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        // 前置断言：这次改动**没有**碰路径与声明哈希 —— 否则测的就不是「字节进不进身份」，
        // 而是旧口径里那两样东西自己变了，用例会因为错误的理由通过。
        let after_views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let after_victim = after_views
            .iter()
            .find(|v| v.manifest_id == victim.manifest_id)
            .expect("篡改之后这份 manifest 仍应在 view 列表里");
        assert_eq!(
            after_victim.manifest_relative_path, victim.manifest_relative_path,
            "前置断言：相对路径不变"
        );
        assert_eq!(
            after_victim.blob_blake3, victim.blob_blake3,
            "前置断言：manifest 里**声明**的 blob 哈希不变"
        );

        let after = mirror_identity_of(&d.data_dir).unwrap();
        assert_ne!(
            before.manifest_root, after.manifest_root,
            "manifest 的字节被改了，而 mirror 身份**一位都没变** —— 身份口径只摘路径与声明哈希"
        );
    }

    /// 端到端：**放行链断裂**（R1 #12 与 #7 串起来的那条链，R-E-91 判据第三条）。
    ///
    /// 链的形状是：篡改 manifest → 一次 relink apply 把它**重新祝福成自洽的**
    /// （`manifest_blake3` 被刷新，篡改证据被抹掉）→ 资格门对这种形状完全失明 →
    /// 候选一路绿到底交给下游。F12（`c75ddc09`）已经堵死了「relink 替攻击者刷新自摘要」
    /// 那一步，所以这里**手工造出同一形状**：本条要证的是**即便证据被抹干净、manifest
    /// 自己看起来完全自洽，资格门也必须拒**——即这条链上两道防线彼此独立。
    #[test]
    fn e7_qualification_breaks_the_blessed_tamper_chain() {
        let d = qualified_candidate();
        assert!(qualify(&d).is_ok(), "前置断言：动手之前必须是合格的");

        let root = crate::doctor_raw_mirror_root(&d.data_dir);
        let views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let victim = views.first().expect("至少一份 manifest").clone();
        let rel = victim.manifest_relative_path.clone();
        let mpath = root.join(&rel);

        // ① 篡改内容 —— 与 R1 #12 探针同一处字段。
        let raw = std::fs::read_to_string(&mpath).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        json["original_path"] = serde_json::Value::String("/tampered/by/someone-else.jsonl".into());
        std::fs::write(&mpath, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        // ② 把自摘要刷新成自洽的 —— 即「被祝福」之后的形状。
        let refreshed = crate::raw_mirror::recompute_manifest_blake3(&d.data_dir, &rel).unwrap();
        let raw = std::fs::read_to_string(&mpath).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        json["manifest_blake3"] = serde_json::Value::String(refreshed);
        std::fs::write(&mpath, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        // ③ 前置断言：它确实是一份**自洽的**被改件 —— F12 那道线在它身上不会响。
        //    少了这一条，用例可能是被 F12 挡住的，而不是被本条要证的身份口径挡住的。
        let recomputed = crate::raw_mirror::recompute_manifest_blake3(&d.data_dir, &rel).unwrap();
        let after_views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let after_victim = after_views
            .iter()
            .find(|v| v.manifest_id == victim.manifest_id)
            .expect("篡改之后这份 manifest 仍应在 view 列表里");
        assert_eq!(
            after_victim.manifest_identity_matches(&recomputed),
            Some(true),
            "前置断言：篡改件必须自洽，否则挡住它的是 F12 那道线、不是本条要证的身份口径"
        );

        // ④ 判据：链在这里断掉。
        let err = qualify(&d).expect_err("自洽的被改件仍然必须被资格门拒");
        assert_eq!(err.code(), "E-IDENTITY-MISMATCH");
    }

    /// 档 3（`--deep-verify`，R-E-91）：blob 被**等字节数**改写。
    ///
    /// **「保持字节数不变」不是随手选的写法**：它把档 2 的大小校验隔离掉，于是这条用例
    /// 只可能由档 3 判红。若随便改几个字节让长度变了，红的会是
    /// `E-MIRROR-BLOB-SIZE-MISMATCH` —— 用例照样绿，但它证明的是档 2 还活着，
    /// 一句都没证到档 3。同族教训见「变异 fixture 必须除待测维度之外哪儿都对」。
    #[test]
    fn e7_deep_verify_catches_an_equal_length_blob_rewrite() {
        let d = qualified_candidate();

        // 阳性对照：动手**之前**深度档必须绿，且必须真的重算过 blob。
        // 少了这一条，一个「永远红」或「什么都没读」的档 3 同样能让下面的断言通过。
        let clean = qualify_deep(&d).expect("前置断言：干净候选在深度档下必须过门");
        assert!(
            clean.mirror_blobs.blobs_digested > 0,
            "前置断言：深度档必须真的重算过 blob 字节，实得 {:?}",
            clean.mirror_blobs
        );

        let root = crate::doctor_raw_mirror_root(&d.data_dir);
        let views = crate::raw_mirror::manifest_views(&d.data_dir).unwrap();
        let victim = views.first().expect("至少一份 manifest").clone();
        let blob = root.join(&victim.blob_relative_path);
        let mut bytes = std::fs::read(&blob).unwrap();
        assert!(!bytes.is_empty(), "前置断言：blob 非空，否则无处可改");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&blob, &bytes).unwrap();
        assert_eq!(
            std::fs::metadata(&blob).unwrap().len(),
            victim.blob_size_bytes,
            "前置断言：字节数必须一位没变，否则挡住它的是档 2 而不是档 3"
        );

        // 默认档对等长改写失明 —— **这是设计，不是缺口**：档 2 只验存在性与大小。
        // 把这一句写成断言，是为了让「默认档的保证面到哪为止」有一条测试守着，
        // 而不是只活在 help 文本里。
        let shallow = qualify_at(&d, MirrorVerifyDepth::Default)
            .expect("默认档只验存在性与大小，等长改写它看不见（设计如此）");
        assert_eq!(
            shallow.mirror_blobs.blobs_digested, 0,
            "默认档一个 blob 字节都不该读，实得 {:?}",
            shallow.mirror_blobs
        );
        assert_eq!(
            shallow.mirror_blobs.manifests_checked,
            views.len() as u64,
            "默认档仍要逐份核 manifest 的 blob 现实，覆盖面不能缩水"
        );

        let err = qualify_deep(&d).expect_err("深度档必须抓到等长改写");
        assert_eq!(err.code(), "E-MIRROR-BLOB-CHECKSUM-MISMATCH");
    }

    /// marker schema 2 → 3（R-E-91）：`manifest_root` 的**派生定义**变了，旧 marker 里的
    /// 那个值按新口径重算必然对不上。靠版本号说话，不靠「重算发现不等」——后者会把
    /// 「版本旧」误报成「候选被动过」，是最坏的一种错误归因。
    ///
    /// 错误文本要同时带**见到的**与**需要的**两个版本：只报 got，操作者不知道该升到哪一版
    /// （与 R-E-88 给 restore journal 立的口径同一条）。
    #[test]
    fn e7_qualification_rejects_a_previous_schema_marker() {
        let d = qualified_candidate();
        assert!(qualify(&d).is_ok(), "前置断言：动手之前必须是合格的");
        rewrite_marker(&d, |m| m.schema_version = 2);
        let err = qualify(&d).expect_err("schema 2 的 marker 必须被拒");
        assert_eq!(err.code(), "E-SCHEMA-MISMATCH");
        let text = err.to_string();
        assert!(
            text.contains("@2") && text.contains('4'),
            "错误文本必须同时带见到的（2）与需要的（4）两个版本；实得 {text}"
        );
    }

    // ══ R1 Finding 15 实质半 / 裁定 R-E-92：三句「不写」的声称转正为机器判据 ══
    //
    // 本条 finding 的成因不是某段代码写错了，是**一句关于代码行为的话变假了而没人发现**
    // （`--apply` 的 help 曾写「不给它就什么都不写」，而规划本身总会往 `--scratch` 下
    // 物化文件）。所以处置也不是改代码，是把这类声称**变成会红的东西**：
    // 声称一旦变假，测试立刻红，而不是等下一次对抗审来读文档。
    //
    // 三条判据分别锚定三句声称，出处逐条写在各自的注释里。

    /// 锚定的声称原文：`--qualify` 的 help（`src/lib.rs` 的 `Commands::MirrorRestore`）——
    /// 「只跑**解析级资格门**（不写任何东西）」。
    ///
    /// 把它变成机器判据：跑一次 qualify，`data_dir` 与候选 DB 所在目录必须逐条不变。
    /// （part6 §3 教训 8 提示过「用 cass 读库会在旁边造出 `doctor/locks/`」——
    /// 在这条路径上没有发生，而「没发生」这件事本身现在有测试守着了。）
    #[test]
    fn e7_qualify_writes_nothing_as_its_help_claims() {
        let d = qualified_candidate();
        let db_dir = d.db_path.parent().unwrap().to_path_buf();
        let before_data = test_tree_snapshot(&d.data_dir);
        let before_db = test_tree_snapshot(&db_dir);
        assert!(
            !before_data.is_empty(),
            "前置断言：现场必须非空，否则「零新增」是在对一棵空树说话"
        );

        qualify(&d).expect("前置断言：这一份必须是合格的，否则门在第一层就退出了、走不到后面");

        let after_data = test_tree_snapshot(&d.data_dir);
        let after_db = test_tree_snapshot(&db_dir);
        let new_data: Vec<_> = after_data
            .iter()
            .filter(|x| !before_data.contains(x))
            .collect();
        let new_db: Vec<_> = after_db.iter().filter(|x| !before_db.contains(x)).collect();
        assert!(
            new_data.is_empty() && new_db.is_empty(),
            "`--qualify` 的 help 说它不写任何东西，实测跑完之后现场多出了东西：\
             data_dir 新增 {new_data:?}；db 目录新增 {new_db:?}"
        );

        // 阳性对照：**空结果 ≠ 不存在**。先证明这个快照抓得到新增文件，
        // 上面那句「零新增」才是结论而不是探针失灵。
        std::fs::write(d.data_dir.join("positive-control.txt"), b"x").unwrap();
        let control = test_tree_snapshot(&d.data_dir);
        assert!(
            control
                .iter()
                .any(|(name, _)| name.contains("positive-control.txt")),
            "阳性对照失败：快照连一个刚写进去的文件都抓不到，上面的「零新增」作废"
        );
    }

    // ── 闭世界：未声明字段 ──────────────────────────────────────────────
    #[test]
    fn e7_qualification_rejects_an_unknown_field() {
        let d = qualified_candidate();
        let bytes = std::fs::read(marker_path_of(&d)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let injected = format!("{{\"extra_field\":1,{}", &text[1..]);
        std::fs::write(marker_path_of(&d), injected).unwrap();
        let err = qualify(&d).expect_err("闭世界：未声明字段必须拒");
        assert_eq!(err.code(), "E-UNKNOWN-FIELD");
    }

    // ── receipt 交叉核：marker 自称的 key 在 DB 副本里查不到 ─────────────
    #[test]
    fn e7_qualification_rejects_a_receipt_that_the_db_does_not_have() {
        let d = qualified_candidate();
        rewrite_marker(&d, |m| {
            m.receipt_keys.push("zzz-nonexistent-receipt-key".into());
            m.receipt_keys.sort();
            m.planned_count += 1;
        });
        let err = qualify(&d).expect_err("marker 说提交了、DB 里没有 receipt，必须拒");
        assert_eq!(err.code(), "E-RECEIPT-MISSING");
    }

    // ── R-E-83：归宿守恒必须在**首跑与恢复两条路径上都成立** ────────────────
    //
    // 这条不变式（runbook 给操作者的对账判据）修前**在恢复路径上是假的**：
    // 先查后做那一支查到 receipt 就 `continue`，`outcome` 一格没动，于是
    // 「全是已提交项」的一轮左边是 0、右边是 planned。
    //
    // 更该记的是它当初怎么漏掉的：**没有任何一条测试以这条不变式为断言**。
    // 与此同时 `e7_planned_with_receipt_advances_instead_of_discarding` 断言
    // `restored + replaced == 0` 而 `planned` 是 2 —— **守恒式在一条从没红过的
    // 绿测试眼皮底下断裂，却没人问**。不变式没有以它为断言的测试，就只是文档修辞。
    #[test]
    fn e7_disposition_conservation_holds_on_both_first_run_and_recovery() {
        let d = drill();
        let planned = plan_for(&d).planned.len();
        assert_eq!(planned, 2, "前置断言：本 fixture 恰有两条计划项");

        // ── 首跑 ────────────────────────────────────────────────────────
        let first = restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();
        assert_eq!(
            first.restored + first.replaced + first.deduplicated + first.already_committed,
            planned,
            "首跑：四项和必须等于 planned，实得 {first:?}"
        );
        assert_eq!(
            first.already_committed, 0,
            "首跑没有任何一条是「已提交」，这一格必须是 0 —— 否则它在冒充工作量"
        );

        // ── 恢复：把 journal 退回 planned，receipt 全在 ──────────────────
        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        journal.state = RestoreJournalState::Planned;
        journal.committed.clear();
        journal.published.clear();
        restore_journal_write(&d.journal_path, &journal).unwrap();

        let again = restore_recover(&d.journal_path).unwrap();
        assert_eq!(
            again.restored + again.replaced + again.deduplicated + again.already_committed,
            planned,
            "恢复：四项和同样必须等于 planned —— 修前这里左边是 0，实得 {again:?}"
        );
        assert_eq!(
            again.already_committed, planned,
            "这一轮每条都是「已提交、跳过」，该格必须等于 planned"
        );
        assert_eq!(
            (again.restored, again.replaced, again.deduplicated),
            (0, 0, 0),
            "恢复轮不该有任何新的写库动作"
        );
        assert_eq!(
            again.receipt_keys.len(),
            planned,
            "跳过的那些 receipt key 也要带出来 —— 不然操作者拿不到对账凭据"
        );
    }

    // ── R-E-79 补充：旧 journal 必须死在**具名版本错误**上，不是 serde 字段错 ──
    //
    // 判据的关键不是「拒不拒」（两种写法都会拒），而是**哪一层在说话**。
    // 死于 `missing field holds_count` 会让操作者去查文件损坏；死于
    // `E-JOURNAL-SCHEMA-MISMATCH` 才会让他去看版本。这条测试锁的就是这个区别。
    #[test]
    fn e7_old_journal_dies_on_the_named_version_error_not_on_a_serde_field_error() {
        let d = drill();
        let journal = restore_journal_from_plan(plan_for(&d));
        restore_journal_write(&d.journal_path, &journal).unwrap();

        // 前置断言：当前版本读得回来，否则这条用例恒红、没有分辨力。
        assert!(
            restore_journal_read(&d.journal_path).unwrap().is_some(),
            "前置断言：当前版本的 journal 必须读得回来"
        );

        // 造一份「旧版」：降版本号，并把两个新格摘掉（旧 journal 本来就没有它们）。
        let mut obj: serde_json::Map<String, serde_json::Value> =
            serde_json::from_slice(&std::fs::read(&d.journal_path).unwrap()).unwrap();
        obj.insert("schema_version".into(), serde_json::json!(1));
        assert!(obj.remove("holds_count").is_some(), "前置断言：新格本来在");
        assert!(
            obj.remove("origin_unmapped_count").is_some(),
            "前置断言：新格本来在"
        );
        std::fs::write(&d.journal_path, serde_json::to_vec(&obj).unwrap()).unwrap();

        let err = restore_journal_read(&d.journal_path).expect_err("旧版 journal 必须被拒");
        let text = format!("{err:#}");
        assert!(
            text.contains("E-JOURNAL-SCHEMA-MISMATCH"),
            "必须以版本这一层的名义拒，实得：{text}"
        );
        assert!(
            text.contains("1") && text.contains(&RESTORE_JOURNAL_SCHEMA_VERSION.to_string()),
            "错误要同时点出「见到哪个版本」与「需要哪个版本」，实得：{text}"
        );
        // 反面：**不得**是 serde 的字段错在说话。
        assert!(
            !text.contains("missing field"),
            "版本这一层必须先开口 —— 让 serde 的字段错先报，就是错误的层在说话：{text}"
        );

        // 版本号完全缺失（更旧的形态）同样走具名错误。
        obj.remove("schema_version");
        std::fs::write(&d.journal_path, serde_json::to_vec(&obj).unwrap()).unwrap();
        let text = format!("{:#}", restore_journal_read(&d.journal_path).unwrap_err());
        assert!(
            text.contains("E-JOURNAL-SCHEMA-MISMATCH") && text.contains("<absent>"),
            "版本号缺失也必须走同一条具名错误并说明是「缺失」，实得：{text}"
        );
    }

    // ── R-E-79 (a) 条件 2：反滥用 —— 新 schema 下两格必填，缺了必须被拒 ──
    //
    // 「可选字段」的问题不在今天，在明天：一份没有 `holds_count` 的 marker 会被读成
    // 「零 HOLD」，而那正是本次要杜绝的谎。所以升 schema 版本 + 闭世界解析报
    // `MissingField`，让旧 marker **必然被拒**而不是被默默读成 0。
    #[test]
    fn e7_marker_without_the_hold_counts_is_refused_not_defaulted_to_zero() {
        let d = qualified_candidate();
        let journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        let marker = build_w1_commit_marker(&journal, &d.journal_path).unwrap();

        // 前置断言：完整的 marker 必须解析得回来，否则下面测的是别的东西。
        let full = marker.canonical_bytes();
        assert_eq!(
            W1CommitMarker::parse(&full).unwrap(),
            marker,
            "前置断言：完整 marker 必须往返一致"
        );

        // 造 schema 1 形态：把两格逐一摘掉，各自都必须以 `MissingField` 被拒。
        for field in ["holds_count", "origin_unmapped_count"] {
            let mut obj: serde_json::Map<String, serde_json::Value> =
                serde_json::from_slice(&full).unwrap();
            assert!(
                obj.remove(field).is_some(),
                "前置断言：{field} 本来就该在 marker 里"
            );
            let bytes = serde_json::to_vec(&obj).unwrap();
            let err = W1CommitMarker::parse(&bytes).expect_err("缺了必填格必须被拒，不许缺省成 0");
            match err {
                W1MarkerError::MissingField(ref got) => assert_eq!(got, field),
                other => panic!("必须以 MissingField 的名义拒，实得 {other:?}"),
            }
        }

        // 另一半：版本号还停在 1 的 marker，即使两格齐全也必须被资格门拒。
        // 光靠「字段缺失」拦不住一个手工补齐了两格却仍自称 schema 1 的东西。
        let mut stale = marker.clone();
        stale.schema_version = 1;
        let err = qualify_w1_candidate(&W1QualificationInput {
            marker_path: &{
                let p = d.db_path.parent().unwrap().join("stale-marker.json");
                std::fs::write(&p, stale.canonical_bytes()).unwrap();
                p
            },
            journal_path: &d.journal_path,
            db_path: &d.db_path,
            data_dir: &d.data_dir,
            mirror_verify_depth: MirrorVerifyDepth::Default,
        })
        .expect_err("schema 版本不对必须被拒");
        assert_eq!(err.code(), "E-SCHEMA-MISMATCH", "实得 {err:?}");
    }

    // ── R-E-79 (b)：marker 的 `content_generation` 不许与 journal 说的不一致 ──
    //
    // 缺陷原样（R1 Finding 2 的子缺陷，实测带出）：`build_w1_commit_marker` 读的是
    // **库里**的 generation，不是 `journal.generation`。零动作那一轮（`planned` 为空）
    // 没有任何一条 commit 去推进库里的代际，于是 marker attest 的是**上一轮**的代际
    // —— 一个本次运行并未建立的值。而 `--qualify` 拿 marker 与库两侧一比，
    // **两边都是那个旧值、自洽**，于是照过。
    //
    // 为什么判硬失败而不是「以 journal 为准改写」：这是**两个真源互相矛盾**，
    // 与 `restore_assert_receipts_present` 遇到的是同一类情形，那里的口径就是停手不猜。
    // 同一个文件里对同类矛盾给两套口径，才是真正会咬人的地方。
    #[test]
    fn e7_marker_refuses_when_db_generation_disagrees_with_the_journal() {
        let d = qualified_candidate();
        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();

        // 前置断言：现在两侧是一致的，否则下面测的是别的东西。
        let db_generation = read_content_generation(&d.db_path)
            .unwrap()
            .expect("前置断言：库里必须已有 generation");
        assert_eq!(
            db_generation, journal.generation,
            "前置断言：动手之前 journal 与库必须一致"
        );
        assert!(
            build_w1_commit_marker(&journal, &d.journal_path).is_ok(),
            "前置断言：一致时必须能正常产出 marker —— 否则这条用例恒红、没有分辨力"
        );

        // 造矛盾：journal 声称本轮推进到了另一个代际，而库里还是旧的。
        // 这正是「零动作 + 库已带 generation」那条真实路径留下的状态。
        journal.generation = format!("{db_generation}-but-the-journal-says-otherwise");

        let err = build_w1_commit_marker(&journal, &d.journal_path)
            .expect_err("库与 journal 的代际不一致，必须硬失败而不是替操作者猜一个");
        let text = format!("{err:#}");
        assert!(
            text.contains("E-GENERATION-DISAGREES"),
            "错误必须带具名错误码 E-GENERATION-DISAGREES，实得：{text}"
        );
        // 两个值都要出现在错误里 —— 只说「不一致」的报错，操作者还得自己去翻两边。
        assert!(
            text.contains(&db_generation) && text.contains(&journal.generation),
            "错误必须同时点出库侧与 journal 侧的值，实得：{text}"
        );
    }

    // ── 写 marker 是先查后做，绝不覆盖（不变量 I1）──────────────────────
    #[test]
    fn e7_marker_write_is_check_then_act_and_never_overwrites() {
        let d = qualified_candidate();
        let journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        let marker = build_w1_commit_marker(&journal, &d.journal_path).unwrap();

        // 同样内容再写一次 = no-op（返回 false），而不是覆盖。
        assert!(
            !write_w1_commit_marker(&marker, &marker_path_of(&d)).unwrap(),
            "内容相同的重写必须是 no-op"
        );

        // 内容不同 → 硬失败，**不覆盖**。覆盖会把「marker 与候选身份不符」这种矛盾抹平，
        // 而那正是资格门要抓的东西。
        let mut tampered = marker.clone();
        tampered.operation_id = "someone-elses-operation".into();
        let err =
            write_w1_commit_marker(&tampered, &marker_path_of(&d)).expect_err("内容不同必须硬失败");
        assert!(format!("{err:#}").contains("refusing to overwrite"));

        // 硬失败之后磁盘上仍是原来那份。
        let on_disk = W1CommitMarker::parse(&std::fs::read(marker_path_of(&d)).unwrap()).unwrap();
        assert_eq!(on_disk.operation_id, marker.operation_id);
    }

    // ── canonical 编码的 vector 式固定测试（R-E-53 条件 2）──────────────
    //
    // **期望字节是手工钉死的字面量，不由编码器算** —— 否则这条测试只证明
    // 「编码器等于它自己」。摘要那条是从这份字面量派生的**变更探测**，
    // 不是独立实现交叉校验（后者是 G1 Step 3 两实现对照那道门的事）。
    //
    // ⚠ 这份 vector 里的 `schema_version: 2` 是**字面量的一部分**，故意不跟着
    // `W1_COMMIT_MARKER_SCHEMA_VERSION` 走（其余字段同理，`manifest_root: "cc"`
    // 也不是真值）。它锁的是**编码形制**，不是当前版本号；挂上常量就等于让编码器
    // 自己算期望值，把这条测试退化成同义反复。当前版本号由
    // `e7_qualification_rejects_a_previous_schema_marker` 那条守。
    #[test]
    fn e7_marker_canonical_encoding_matches_the_pinned_vector() {
        let marker = W1CommitMarker {
            schema: W1_COMMIT_MARKER_SCHEMA.into(),
            schema_version: 2,
            operation_id: "op-1".into(),
            snapshot_root: "root-1".into(),
            content_generation: "gen-1".into(),
            journal_state: "closure-verified".into(),
            journal_digest: "aa".into(),
            closure_verdict: "pass".into(),
            planned_count: 2,
            // 两格取不同值：串位就会被下面的钉死字面量抓到。
            holds_count: 7,
            origin_unmapped_count: 5,
            receipt_keys: vec!["k1".into(), "k2".into()],
            db_identity: W1DbIdentity {
                sqlite_digest: "bb".into(),
                sqlite_size_bytes: 4096,
                schema_version: 21,
                generation: "gen-1".into(),
            },
            mirror_identity: W1MirrorIdentity {
                manifest_count: 2,
                manifest_root: "cc".into(),
            },
        };

        const PINNED: &str = concat!(
            "{\"closure_verdict\":\"pass\"",
            ",\"content_generation\":\"gen-1\"",
            ",\"db_identity\":{\"generation\":\"gen-1\",\"schema_version\":21,",
            "\"sqlite_digest\":\"bb\",\"sqlite_size_bytes\":4096}",
            ",\"holds_count\":7",
            ",\"journal_digest\":\"aa\"",
            ",\"journal_state\":\"closure-verified\"",
            ",\"mirror_identity\":{\"manifest_count\":2,\"manifest_root\":\"cc\"}",
            ",\"operation_id\":\"op-1\"",
            ",\"origin_unmapped_count\":5",
            ",\"planned_count\":2",
            ",\"receipt_keys\":[\"k1\",\"k2\"]",
            ",\"schema\":\"marker.w1-commit\"",
            ",\"schema_version\":2",
            ",\"snapshot_root\":\"root-1\"}"
        );

        assert_eq!(
            String::from_utf8(marker.canonical_bytes()).unwrap(),
            PINNED,
            "canonical 形制漂移：键序 / 空白 / 数字形制 任一变化都会让摘要失去意义"
        );
        assert_eq!(
            blake3::hash(&marker.canonical_bytes()).to_hex().to_string(),
            blake3::hash(PINNED.as_bytes()).to_hex().to_string(),
            "摘要只对 canonical bytes 取 —— Rust 侧不另包一层 `digest()`：
             wire 说明 §5 明写 `marker_digest` 不进 marker 自身、**由消费方算**，
             而消费方是 F4（Python）。多包一层就是没被要求的 API。"
        );

        // 阳性：多一个空格就是另一份字节，摘要必须不等。
        let with_space = PINNED.replacen("{\"closure_verdict\"", "{ \"closure_verdict\"", 1);
        assert_ne!(
            blake3::hash(with_space.as_bytes()).to_hex().to_string(),
            blake3::hash(&marker.canonical_bytes()).to_hex().to_string(),
            "空白敏感性：多一个空格摘要就该不同，否则 canonical 形制没有约束力"
        );
        // 阳性：改一个字段，摘要必须不等。
        let mut other = marker.clone();
        other.planned_count = 3;
        assert_ne!(
            blake3::hash(&other.canonical_bytes()).to_hex().to_string(),
            blake3::hash(&marker.canonical_bytes()).to_hex().to_string()
        );
    }

    // ── 非法候选 ②b：journal 未终态，**且 marker 的摘要与它一致** ────────
    //
    // 为什么要有这一条：②那条用「把 journal 改回非终态」构造，可它同时改了 journal 文件，
    // 于是**下一层的 `journal_digest` 比对**也会拒 —— 两层共用同一个错误码，用例分辨不出
    // 是谁拒的。M4 变异（把「必须终态」那层整个跳过）实测让②**照样绿**，就是这个缘故。
    //
    // 本条把摘要那层的兜底拿掉：改完 journal 之后，把 marker 的 `journal_digest`
    // 改成这份**非终态** journal 的真实摘要。于是只有「状态必须是终态」那一层能拒它，
    // 并且断言 detail 指向 `journal on disk is`，让两层在断言层面可分辨。
    //
    // 判据出处：D5 已入库的那条 —— **每一层必须以自己的名义拒绝；靠别的层兜住，
    // 等于这一层没有守卫、只有运气。**
    #[test]
    fn e7_qualification_rejects_a_non_terminal_journal_even_when_the_digest_agrees() {
        let d = qualified_candidate();
        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        journal.state = RestoreJournalState::AnalyticsRebuilt;
        restore_journal_write(&d.journal_path, &journal).unwrap();

        let agreeing = blake3::hash(&std::fs::read(&d.journal_path).unwrap())
            .to_hex()
            .to_string();
        rewrite_marker(&d, |m| m.journal_digest = agreeing);

        let err = qualify(&d).expect_err("非终态 journal 必须被**这一层**拒掉");
        assert_eq!(err.code(), "E-JOURNAL-NOT-TERMINAL");
        match err {
            W1MarkerError::JournalNotTerminal { detail } => assert!(
                detail.contains("journal on disk is"),
                "必须是「状态非终态」那一层拒的，不是摘要那一层；实得 detail={detail}"
            ),
            other => panic!("错误变体不对：{other:?}"),
        }
    }

    // ============ R1 Finding 10 / 裁定 R-E-87 的判据 ============

    /// 发布 marker 用的临时文件**不得**落在固定可预测的路径上、把同名的既有文件毁掉。
    ///
    /// 修前形态：tmp 恒为 `<marker>.tmp`，且用 `File::create`（截断）打开 ——
    /// 一个与本操作毫无关系、只是恰好同名的文件会被无条件截断并 rename 走，字节不可恢复。
    #[test]
    fn f10_marker_publish_must_not_destroy_a_foreign_file_at_a_predictable_tmp_path() {
        let d = qualified_candidate();
        let mp = marker_path_of(&d);
        let journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        let marker = build_w1_commit_marker(&journal, &d.journal_path).unwrap();
        std::fs::remove_file(&mp).unwrap(); // 让 write 走「不存在」分支
        let tmp = mp.with_extension("tmp");
        let foreign = b"FOREIGN-FILE-THAT-SHOULD-NOT-BE-DESTROYED".to_vec();
        std::fs::write(&tmp, &foreign).unwrap();

        let published = write_w1_commit_marker(&marker, &mp).unwrap();
        assert!(published, "前置断言：marker 不存在时这一次必须真的发布");

        assert!(
            tmp.exists(),
            "写 marker 不该动一个与它无关、只是恰好落在固定 tmp 路径上的既有文件（{}）",
            tmp.display()
        );
        assert_eq!(
            std::fs::read(&tmp).unwrap(),
            foreign,
            "外来文件的字节必须原样还在"
        );
    }

    /// 并发发布必须**原子**且**具名**：两个调用方拿不同的 marker 抢同一个路径时，
    /// 恰好一个 publish 成功、盘上就是它写的字节，另一个以**具名**错误
    /// （`refusing to overwrite`）被拒。
    ///
    /// 修前形态（2000 轮实测）：`err_refuse=0`（I1 的拒绝分支一次都没走到，
    /// TOCTOU 2000/2000 全中，挡住第二个的是裸 `ENOENT`）、
    /// `published_other=264`（13% 盘上是另一个调用方的 marker，而赢家自报成功）、
    /// `published_corrupt=1255`（63% 盘上是两个写者交错出来的不可解析字节）。
    #[test]
    fn f10_concurrent_marker_publish_is_atomic_and_refuses_by_name() {
        use std::sync::{Arc, Barrier};
        let d = qualified_candidate();
        let journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        let m1 = build_w1_commit_marker(&journal, &d.journal_path).unwrap();
        let mut m2 = m1.clone();
        m2.operation_id = "someone-elses-operation".into();

        let rounds = 2000usize;
        let mut both_published = 0usize;
        let mut neither = 0usize;
        let mut one_ok_one_err = 0usize;
        let mut one_ok_one_noop = 0usize;
        let mut err_refuse = 0usize;
        let mut err_other = 0usize;
        let mut published_self = 0usize;
        let mut published_other = 0usize;
        let mut published_corrupt = 0usize;
        let mut published_missing = 0usize;
        for _ in 0..rounds {
            let dir = TempDir::new().unwrap();
            let mp = dir.path().join("w1-commit-marker.json");
            let barrier = Arc::new(Barrier::new(2));
            let handles: Vec<_> = [m1.clone(), m2.clone()]
                .into_iter()
                .enumerate()
                .map(|(i, m)| {
                    let b = Arc::clone(&barrier);
                    let path = mp.clone();
                    let want = m.operation_id.clone();
                    std::thread::spawn(move || {
                        b.wait();
                        (i, want, write_w1_commit_marker(&m, &path))
                    })
                })
                .collect();
            let raw: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            // 赢家（返回 Ok(true) 的那个）发布的字节，真的是它自己的吗？
            if let Some((_, want, _)) = raw.iter().find(|(_, _, r)| matches!(r, Ok(true))) {
                if mp.exists() {
                    let on_disk = W1CommitMarker::parse(&std::fs::read(&mp).unwrap());
                    match on_disk {
                        Ok(parsed) if &parsed.operation_id != want => published_other += 1,
                        Ok(_) => published_self += 1,
                        Err(_) => published_corrupt += 1,
                    }
                } else {
                    published_missing += 1;
                }
            }
            let results: Vec<_> = raw.into_iter().map(|(_, _, r)| r).collect();
            for r in &results {
                if let Err(e) = r {
                    let t = format!("{e:#}");
                    if t.contains("refusing to overwrite") {
                        err_refuse += 1;
                    } else {
                        err_other += 1;
                        if err_other <= 3 {
                            println!("PROBE-B-OTHER-ERR: {t}");
                        }
                    }
                }
            }
            let ok_true = results.iter().filter(|r| matches!(r, Ok(true))).count();
            if ok_true == 2 {
                both_published += 1;
            }
            if ok_true == 0 {
                neither += 1;
            }
            if ok_true == 1 {
                if results.iter().any(|r| matches!(r, Ok(false))) {
                    one_ok_one_noop += 1;
                } else {
                    one_ok_one_err += 1;
                }
            }
        }
        // 先把分布打出来 —— 「没复现」和「探针没跑到点子上」必须分得开。
        println!(
            "PROBE-B-DIST rounds={rounds} both_published={both_published} \
             one_ok_one_err={one_ok_one_err} one_ok_one_noop={one_ok_one_noop} neither={neither} \
             err_refuse={err_refuse} err_other={err_other} \
             published_self={published_self} published_other={published_other} \
             published_corrupt={published_corrupt} published_missing={published_missing}"
        );
        assert_eq!(
            both_published, 0,
            "I1「绝不覆盖」被破：{rounds} 轮里有 {both_published} 轮两个都报 publish 成功"
        );
        assert_eq!(
            neither, 0,
            "每一轮都必须恰好有一个发布成功，实测有 {neither} 轮一个都没成功"
        );
        assert_eq!(
            err_other, 0,
            "被拒的一方必须以**具名**错误被拒（refusing to overwrite），\
             实测有 {err_other} 次拿到的是别的错（修前是裸 ENOENT）"
        );
        assert_eq!(
            err_refuse, rounds,
            "{rounds} 轮里应当恰好有 {rounds} 次具名拒绝，实得 {err_refuse}"
        );
        assert_eq!(
            published_other, 0,
            "有 {published_other} 轮：自报 publish 成功的那一方，盘上却是**另一个调用方**的 marker"
        );
        assert_eq!(
            published_corrupt, 0,
            "有 {published_corrupt} 轮：盘上的 marker **不可解析**（两个写者交错写同一个 tmp）"
        );
        assert_eq!(
            published_self, rounds,
            "每一轮盘上的字节都必须属于自报成功的那一方，实得 {published_self}/{rounds}"
        );
    }
    // =============== R1 Finding 10 判据结束 ===============

    // ============ R1 Finding 14 / 裁定 R-E-90 的判据 ============
    //
    // 「owner-only 的产物」必须**从出生起**就只有属主可读写，不能「先写满再 chmod」。
    // 判据形态：在写入器跑的同时用观察线程扫目标目录，任何**新出现**的文件在任何一刻
    // 都不得带非属主位。修前实测（`write_private_file`，本机 umask 0002）：`0o64`。
    //
    // ⚠ 「窗口很短所以没事」不是辩护：POSIX 的权限检查发生在 `open()` 那一刻，
    // 之后只认描述符 —— 窗口里 open 到的 fd，**不会因为随后的 chmod 或 rename 而失效**
    // （已实证，evidence/r1f14-probes.patch 的探针 B；它测的是内核语义故不转正）。
    // 所以唯一站得住的修法是**创建时即私有**，而不是把窗口做小。

    /// 在 `f` 执行期间盯住 `dir`，返回 (新出现文件里最坏的非属主位, 是否看到过新文件)。
    fn worst_non_owner_bits_during(dir: &Path, f: impl FnOnce()) -> (u32, bool) {
        use std::collections::HashSet;
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

        fn names(dir: &Path) -> HashSet<PathBuf> {
            std::fs::read_dir(dir)
                .map(|rd| rd.flatten().map(|e| e.path()).collect())
                .unwrap_or_default()
        }

        let before = names(dir);
        let worst = Arc::new(AtomicU32::new(0));
        let saw = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let dir = dir.to_path_buf();
            let before = before.clone();
            let (worst, saw, stop) = (Arc::clone(&worst), Arc::clone(&saw), Arc::clone(&stop));
            std::thread::spawn(move || {
                loop {
                    for path in names(&dir) {
                        if before.contains(&path) {
                            continue;
                        }
                        if let Ok(md) = std::fs::symlink_metadata(&path) {
                            if md.is_file() {
                                saw.store(true, Ordering::Relaxed);
                                worst.fetch_max(md.permissions().mode() & 0o077, Ordering::Relaxed);
                            }
                        }
                    }
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    std::hint::spin_loop();
                }
            })
        };
        f();
        stop.store(true, Ordering::Relaxed);
        handle.join().unwrap();
        (worst.load(Ordering::Relaxed), saw.load(Ordering::Relaxed))
    }

    #[test]
    fn f14_restore_journal_write_is_private_from_birth() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = qualified_candidate();
        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        // 把计划撑大，让「写 + fsync」这个窗口足够被观察到（真语料是 5574 条身份）。
        let seed = journal.planned.clone();
        while journal.planned.len() < 20_000 {
            journal.planned.extend(seed.iter().cloned());
        }
        let dir = d.journal_path.parent().unwrap().to_path_buf();
        let path = dir.join("big-restore-journal.json");
        let (worst, saw) = worst_non_owner_bits_during(&dir, || {
            restore_journal_write(&path, &journal).unwrap();
        });
        assert!(
            saw,
            "前置断言：观察线程必须看到过新文件，否则本用例没有分辨力"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "前置断言：收尾必须是 0600"
        );
        assert_eq!(
            worst, 0,
            "restore journal 在写入过程中出现过带非属主位的文件（{worst:#o}）—— \
             owner-only 的产物必须创建时即私有，不能先写满再 chmod"
        );
    }

    // ── R3 第 4 条 / 裁定 R-E-103 J2：journal 写路径必须与受保护输入互异 ──
    //
    // `restore_journal_write` 一律 `rename(tmp, path)` —— **替换任何既有普通文件**，
    // 而 `restore_apply_journaled` 首次调用**既不要求新路径、也不校验路径互异**。
    // `--journal <候选库路径>` 于是在 DB 阶段打开候选库**之前**就把它替换成一份 JSON。
    //
    // **判据形状**：不止断言「返回了 Err」——「拒绝了」和「拒绝之前已经写坏了」
    // 是两回事，所以每一条都把受害文件的**全字节**读回来逐位比。
    #[test]
    fn e7_apply_refuses_a_journal_path_that_aliases_the_candidate_db() {
        let d = drill();
        let before = std::fs::read(&d.db_path).unwrap();
        assert!(
            !before.is_empty(),
            "前置断言：候选库必须非空，否则「字节不变」是在替一个空文件背书"
        );

        let err = restore_apply_journaled(plan_for(&d), &d.db_path)
            .expect_err("--journal 指到候选库必须拒");
        let msg = err.to_string();
        assert!(
            msg.contains("E-RESTORE-WRITE-PATH-ALIAS"),
            "必须以具名错误码拒 —— 操作者要能一眼看出是写路径撞了受保护输入，\
             而不是被打发去查 JSON 损坏。实得：{msg}"
        );
        assert_eq!(
            std::fs::read(&d.db_path).unwrap(),
            before,
            "候选库必须逐位不变 —— 拒之前已经写坏了，和没拒是一回事"
        );
    }

    /// 别名的**拼法**不止一种：字面比较认不出 `..` 绕一圈，也认不出符号链接。
    #[test]
    fn e7_apply_refuses_journal_aliases_spelled_through_dotdot_and_a_symlink() {
        let d = drill();
        let before = std::fs::read(&d.db_path).unwrap();
        let dir = d.db_path.parent().unwrap().to_path_buf();
        let file = d.db_path.file_name().unwrap().to_os_string();

        // ① `..` 拼法：同一个 inode，另一种写法。
        let dotdot = dir
            .join("..")
            .join(dir.file_name().expect("候选库所在目录必须有名字"))
            .join(&file);
        let err =
            restore_apply_journaled(plan_for(&d), &dotdot).expect_err("`..` 拼出来的别名必须拒");
        assert!(
            err.to_string().contains("E-RESTORE-WRITE-PATH-ALIAS"),
            "实得：{err}"
        );
        assert_eq!(
            std::fs::read(&d.db_path).unwrap(),
            before,
            "① 之后候选库必须逐位不变"
        );

        // ② symlink 拼法：落点自己是一条指向候选库的链接。
        //    这一支的**损害形态与 ① 不同**（`rename` 顶掉的是链接本身，不是它指的东西），
        //    但它同样是「写目标解析到受保护输入」，必须被同一道校验以同一个码拒掉。
        let link = dir.join("journal-link.json");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&d.db_path, &link).unwrap();
        let err = restore_apply_journaled(plan_for(&d), &link)
            .expect_err("指向候选库的 symlink 落点必须拒");
        assert!(
            err.to_string().contains("E-RESTORE-WRITE-PATH-ALIAS"),
            "实得：{err}"
        );
        assert_eq!(
            std::fs::read(&d.db_path).unwrap(),
            before,
            "② 之后候选库必须逐位不变"
        );
    }

    /// 受保护的不止候选库主文件：sidecar 是同一个库的一部分，写坏它一样毁库。
    ///
    /// 判据用的是**前缀规则**（同目录下以候选库文件名打头的任何名字），不是一张后缀白名单：
    /// 本仓的 frankensqlite 自己就会产出白名单里没有的 sidecar 族，
    /// 而**漏挡一条 = 毁库，误挡一条 = 换个报告名**，两侧代价不对称。
    #[test]
    fn e7_apply_refuses_a_journal_path_that_lands_on_a_candidate_db_sidecar() {
        let d = drill();
        let wal = PathBuf::from(format!("{}-wal", d.db_path.display()));
        std::fs::write(&wal, b"pretend-wal-bytes").unwrap();
        let before = std::fs::read(&wal).unwrap();

        let err = restore_apply_journaled(plan_for(&d), &wal)
            .expect_err("sidecar 也是候选库的一部分，必须拒");
        assert!(
            err.to_string().contains("E-RESTORE-WRITE-PATH-ALIAS"),
            "实得：{err}"
        );
        assert_eq!(std::fs::read(&wal).unwrap(), before, "sidecar 必须逐位不变");
    }

    /// marker 面与 mirror 面：同一道校验的另外两个受保护输入。
    #[test]
    fn e7_apply_refuses_a_journal_path_on_the_marker_or_inside_the_raw_mirror() {
        let d = drill();

        // marker 面：先种一份既有 marker，判据才分辨得出「拒对了」还是「本来就没有」。
        let marker = marker_path_of(&d);
        std::fs::write(&marker, b"{\"pre-existing\":\"marker\"}").unwrap();
        let before_marker = std::fs::read(&marker).unwrap();
        let err = restore_apply_journaled(plan_for(&d), &marker)
            .expect_err("--journal 指到 marker 落点必须拒");
        assert!(
            err.to_string().contains("E-RESTORE-WRITE-PATH-ALIAS"),
            "实得：{err}"
        );
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            before_marker,
            "marker 必须逐位不变"
        );

        // mirror 面：raw-mirror 树里的任何落点都不许当写目标。
        // 受保护的是**那棵树**，不是整个 `--data-dir` —— 报告落在 data_dir 顶层是正常的。
        let inside = crate::doctor_raw_mirror_root(&d.data_dir)
            .join("manifests")
            .join("restore-journal.json");
        let err = restore_apply_journaled(plan_for(&d), &inside)
            .expect_err("--journal 落在 raw-mirror 树内必须拒");
        assert!(
            err.to_string().contains("E-RESTORE-WRITE-PATH-ALIAS"),
            "实得：{err}"
        );
        assert!(!inside.exists(), "拒了就不该在 raw-mirror 树里留下这个文件");
    }

    /// R3 第 4 条的**第二种形态**（评审原文的场景 B）：同路径重跑 `--apply`。
    ///
    /// 上一轮崩在 DB 提交之后、publish 之前时，盘上那份 journal 是那轮**唯一的记录**。
    /// 首次调用无条件写一份全新的 `planned` journal 上去，就把它抹了 ——
    /// 于是新 planner 可能认为库侧内容已相等而略过该项，
    /// 让新 marker attest 一轮**从没修好那条 backlink** 的运行。
    #[test]
    fn e7_apply_refuses_to_overwrite_an_existing_journal_and_points_at_recover() {
        let d = drill();
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);
        restore_apply_journaled(plan_for(&d), &d.journal_path).unwrap();

        // 倒回那个真实存在的窗：DB 提交了，publish 还没做完。
        let mut journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        journal.state = RestoreJournalState::DbCommitted;
        journal.published.clear();
        restore_journal_write(&d.journal_path, &journal).unwrap();
        let before = std::fs::read(&d.journal_path).unwrap();

        let err = restore_apply_journaled(plan_for(&d), &d.journal_path)
            .expect_err("同路径重跑 --apply 必须拒，不能覆盖掉那份未完成的记录");
        let msg = err.to_string();
        assert!(
            msg.contains("E-JOURNAL-PATH-OCCUPIED"),
            "必须以具名错误码拒，实得：{msg}"
        );
        assert!(
            msg.contains("--recover"),
            "错误信息必须把出路指给操作者（继续那一轮用 --recover），实得：{msg}"
        );
        assert_eq!(
            std::fs::read(&d.journal_path).unwrap(),
            before,
            "那份未完成的 journal 必须逐位不变 —— 它是那一轮唯一的记录"
        );
    }

    /// 硬链接：**路径归约认不出的那一类别名** —— 两条真实存在的不同路径，同一个 inode。
    ///
    /// 这条用例的存在理由就是钉住「同一 inode 判定」那一格：
    /// 前置断言先证明两把钥匙**不同**，否则挡住它的是路径比较，这一格等于没被测到。
    #[test]
    fn e7_apply_refuses_a_journal_path_hard_linked_to_the_candidate_db() {
        let d = drill();
        let before = std::fs::read(&d.db_path).unwrap();
        let hard = d.db_path.parent().unwrap().join("journal-hardlink.json");
        let _ = std::fs::remove_file(&hard);
        std::fs::hard_link(&d.db_path, &hard).unwrap();
        assert_ne!(
            restore_write_path_key(&hard),
            restore_write_path_key(&d.db_path),
            "前置断言：硬链接的路径归约必须与候选库不同 —— 相同的话挡住它的是路径比较，\
             而不是同一 inode 判定，这条用例就没有分辨力"
        );

        let err =
            restore_apply_journaled(plan_for(&d), &hard).expect_err("硬链接到候选库的落点必须拒");
        assert!(
            err.to_string().contains("E-RESTORE-WRITE-PATH-ALIAS"),
            "实得：{err}"
        );
        assert_eq!(
            std::fs::read(&d.db_path).unwrap(),
            before,
            "候选库必须逐位不变"
        );
    }

    /// 路径归约本身的判据：它是上面每一条的**公共前提**，值得被单独钉住。
    #[test]
    fn e7_write_path_key_absolutizes_and_normalizes_before_comparing() {
        let d = drill();
        let dir = d.db_path.parent().unwrap().to_path_buf();
        let file = d.db_path.file_name().unwrap().to_os_string();

        assert_eq!(
            restore_write_path_key(&dir.join(".").join(&file)),
            restore_write_path_key(&d.db_path),
            "`.` 绕一圈必须归约到同一把钥匙"
        );
        assert_eq!(
            restore_write_path_key(&dir.join("no-such-dir").join("..").join(&file)),
            restore_write_path_key(&d.db_path),
            "`..` 跟在一个**不存在**的分量后面时 `canonicalize` 会断在那儿 —— \
             只有词法归并那一趟认得出这仍是候选库"
        );

        let cwd = std::env::current_dir().unwrap();
        assert_eq!(
            restore_write_path_key(Path::new("some-report.json")),
            restore_write_path_key(&cwd.join("some-report.json")),
            "相对路径必须先绝对化，否则「同一个文件」会因为工作目录不同而比不等"
        );
    }

    // ── 反方向臂：互异性校验**不得误伤正常用法** ──────────────────────
    //
    // 常规撤防线臂只证「修有用」，证不了「没修过头」，而这条修复的风险全在过头那一侧：
    // 一道过宽的路径校验会把正常的 dry-run 直接判死。
    #[test]
    fn e7_apply_still_accepts_an_ordinary_new_journal_beside_the_candidate_db() {
        let d = drill();
        plant_post_commit_sentinels(&d.data_dir, &d.db_path);

        // 与候选库**同目录、不同名**是正常用法（marker 默认就与候选库同居）。
        let beside = d
            .db_path
            .parent()
            .unwrap()
            .join("restore-journal-beside.json");
        let _ = std::fs::remove_file(&beside);

        let outcome = restore_apply_journaled(plan_for(&d), &beside)
            .expect("与候选库同目录、不同名的全新 journal 必须照常跑完");
        assert_eq!(
            outcome.restored + outcome.replaced,
            2,
            "反方向臂必须真跑完这一轮，不能只证明「没报错」，实得 {outcome:?}"
        );
        assert!(beside.exists(), "journal 必须真落在那个新路径上");
    }

    #[test]
    fn f14_marker_publish_is_private_from_birth() {
        use std::os::unix::fs::PermissionsExt as _;
        let d = qualified_candidate();
        let journal = restore_journal_read(&d.journal_path).unwrap().unwrap();
        let mut marker = build_w1_commit_marker(&journal, &d.journal_path).unwrap();
        let seed = marker.receipt_keys.clone();
        while marker.receipt_keys.len() < 200_000 {
            marker.receipt_keys.extend(seed.iter().cloned());
        }
        let dir = d.db_path.parent().unwrap().to_path_buf();
        let path = dir.join("big-w1-commit-marker.json");
        let (worst, saw) = worst_non_owner_bits_during(&dir, || {
            write_w1_commit_marker(&marker, &path).unwrap();
        });
        assert!(
            saw,
            "前置断言：观察线程必须看到过新文件，否则本用例没有分辨力"
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "前置断言：收尾必须是 0600"
        );
        assert_eq!(
            worst, 0,
            "W1 marker 在发布过程中出现过带非属主位的文件（{worst:#o}）"
        );
    }
    // =============== R1 Finding 14 判据结束 ===============
}

// ===========================================================================
// E8 · dry-run planner（plan Task E8 Step 1/2）
//
// 形状：**winner 从 mirror 侧选 → candidate 从候选 DB 重建 → `decide_action` → 六类计数**。
// 六类口径**直接复用 E4 的 `RelationCensus`**，不另立一套。
//
// **mirror 面的来源是入参**（`data_dir`）：E8 给封存件只读面，E8b 换 materialize 出来的
// 可写工作树。写死成「就是候选包那棵」会让 E8b 只能回头改这里。
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct MirrorRestorePlanOptions {
    /// mirror 面的根。**入参而非常量**（见上）。
    pub data_dir: PathBuf,
    /// 候选 DB 的稳定副本。dry-run 只读它。
    pub db_path: PathBuf,
    /// 投影物化用的隔离根。**不进任何判定**（R-E-34 条件 2）。
    pub scratch_dir: PathBuf,
    /// 本轮消费的封存件根，进计划项的幂等 key。
    pub snapshot_root: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct MirrorRestorePlanReport {
    /// 六类关系计数（§5.2.1 决策表）。
    pub census: RelationCensus,
    /// 参与判定的 identity 数。
    pub identities_considered: usize,
    /// **不进六类表**的 HOLD 数（版本类 / 身份类 / 输入损坏类）。
    ///
    /// 单独记这一格的理由：`RelationCensus::record` 对这三类返回 `false`，
    /// 若不接住，`census.total()` 与 `identities_considered` 的差额就会**无声吞掉**
    /// 一批身份 —— 而那正是 Step 2 那条验证条件要抓的东西。
    pub non_relation_holds: usize,
    /// 真正构造出来的 candidate 侧版本数。
    ///
    /// 存在的意义是**证伪**：若六类判定只看了 mirror 一侧，这个数会是 0，
    /// 而「四类都有」照样成立 —— 计数不为 0 才说明另一侧真的参与了。
    pub candidate_versions_seen: usize,
    /// 全部 HOLD，交人裁定（Phase 4 开工资格的输入）。
    pub holds: Vec<HoldRecord>,
    /// 可执行计划（`--apply` 消费；dry-run 只产不跑）。
    pub plan: Vec<RestorePlanItem>,
    /// provider 归一不了、**因此连 identity 都构造不出来**的 manifest（R-E-67）。
    ///
    /// 为什么不塞进 `holds`：`HoldRecord` 的 `identity` 是非可选的，四类 HOLD taxonomy
    /// 描述的是「candidate 与 winner 的关系出了什么问题」，**前提就是身份已经成立**。
    /// 这批是**身份成立之前**就挡住的故障，硬塞进去只有两条路——给 `Origin` 编一个假值，
    /// 或者把 `identity` 放松成可选——前者是伪造、后者让所有下游都得处理一个几乎不会出现
    /// 的 `None`。单开一格，两样都不用做。
    pub origin_unmapped: Vec<UnmappedOriginRecord>,
    /// 本轮读到的 manifest 总数。**存在的意义是对账**：
    /// `manifests_seen == 进入分组的 manifest 数 + origin_unmapped.len()`，
    /// 否则「有多少条被无声丢掉了」这个问题没有机器答案。
    pub manifests_seen: usize,
}

/// 一条 provider 归一不了的 manifest（R-E-67）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnmappedOriginRecord {
    pub manifest_id: String,
    /// 原始 slug **原样带出**——不带它，操作者就只知道「有东西没映上」而不知道是什么，
    /// 而「哪些 slug 需要被映射」正是这条记录唯一要回答的问题。
    pub provider: String,
}

// 这里**不放路径**，两个理由各自都够：`RawMirrorManifestView` 根本不暴露脱敏路径，自己
// 用 `format!("[{provider}]/{name}")` 拼一份就是 `raw_mirror::redacted_original_path`
// 的第二定义；而 `original_path` 是家目录全路径，会随报告落盘。`manifest_id` 已经唯一定位
// 到 `manifests/<id>.json`，需要细节的人打开它就是。

/// 候选侧的一条版本：**摘要来自 DB 的 canonical 消息**，字节只作裁定材料。
///
/// 为什么不是「重建字节 → 重解析」（该路线已被证伪，裁定 R-E-58）：
/// verbatim 原始行的唯一写入方是 `doctor_recover.rs` 的损坏恢复路径，正常索引产物存的是
/// **规范化事件**，喂回 pinned parser 必撞守卫（`raw envelope already contains reserved
/// key raw_role`）。而 spec §5.2.1 的比较对象本就是 canonical tuple，不是源字节。
pub(crate) struct CandidateSideVersion {
    pub conversation_id: i64,
    /// 仅作 [`VersionSummary`] 的裁定材料 —— **从不喂给 parser**。
    pub evidence: ContentVersion,
    /// 与投影侧同 scope 的摘要序列。
    pub digests: Vec<CanonicalMessageDigest>,
}

/// 把 DB 的一条 canonical 消息还原成 `NormalizedMessage`，**只用既有符号**：
/// role 走 `crate::model::types::role_as_str`（C 组冻结锚里的那一个），
/// 其余字段原样搬；`invocations` 恒空 —— **DB 没有这一格，这是事实不是简化**。
fn normalized_from_db_message(
    message: &crate::model::types::Message,
) -> franken_agent_detection::types::NormalizedMessage {
    franken_agent_detection::types::NormalizedMessage {
        idx: message.idx,
        role: crate::model::types::role_as_str(&message.role).to_string(),
        author: message.author.clone(),
        created_at: message.created_at,
        content: message.content.clone(),
        extra: message.extra_json.clone(),
        snippets: Vec::new(),
        invocations: Vec::new(),
    }
}

/// 从候选 DB 重建某条 identity 的版本集合。
///
/// cass 把逐条源事件存在 `extra_json` / `extra_bin` 里，所以 canonical 库**自带重建源文件
/// 的能力**（`reconstruct_source_jsonl_for_conversation`）。**重建字节与原文件不必逐字节
/// 相同** —— `compare_versions` 的第二层（投影后的消息序列）正是为这种情形存在的。
///
/// # 身份必须整条参与查询（R-E-80′ / R1 Finding 3）
///
/// 修前这条查询只绑 `canonical_path`，把 `identity.origin` 整个丢掉了 —— 而
/// `OriginNamespace` 的 doc 正上方就写着「必须是**带 host 的命名空间**，否则 §5.2.1
/// 点名的『跨 host 同路径不折叠』做不到」。**类型被特意设计成带 host 的命名空间，
/// 用的时候却只取了路径那一半。**
///
/// 真语料实测：5491 个去重路径里有 **83 个**带多于一个 origin，且 83/83 差在 **agent**
/// 这一维。折叠它们的后果最重的一种是**跨来源静默覆盖**（A 的行被当成 B 的候选，
/// 判成 replace 后用 B 的内容盖掉 A）。
///
/// # `origin_host` 这一维也绑上了（R-E-98 H1 / R2 第 5 条）
///
/// 这里原先写着「`origin_host` 当前不可判：`conversations` 侧没有对应列」，并据此把它
/// 记成一条如实披露的已知缺口。**那句话是假的**：`conversations.origin_host` 建表时就在
/// （`src/storage/sqlite.rs` 三处 `origin_host TEXT`），relink 侧自己就在
/// `SELECT c.origin_host`。R-E-80′ 接受了这个前提而没有回源核，于是一条本来就能关掉的
/// 缺口被当成设计约束记了三轮，注释还替它作了证。
///
/// **推翻一个写了理由的决定，新理由至少要一样清楚**（R-E-82）：新理由是——列存在，
/// 且全仓早已有它的读法与归一化，没有任何东西挡着这一维被绑上。查询本身移到
/// [`conversation_ids_for_identity`]，与 publish 侧共用同一处定义。
///
/// **原结论里有一半是对的，但理由是错的，所以那一半也得重说**：这一维确实对
/// **本机源**不具区分力 —— 不是「没有列」，而是存储层归一化在写库时就把本机源的
/// `origin_host` 丢成了 `NULL`（实测坐实，见 `conversation_ids_for_identity` 的
/// doc 与两条对照用例）。远端源（`source_id` 非 local）的 host 原样保留、可分，
/// 那一档从此真的被绑上了。
fn candidate_versions_from_db(
    storage: &crate::storage::sqlite::FrankenStorage,
    identity: &RestoreIdentity,
) -> anyhow::Result<Vec<CandidateSideVersion>> {
    let ids = conversation_ids_for_identity(storage, identity)?;
    let mut out = Vec::with_capacity(ids.len());
    for conversation_id in ids {
        let messages = storage.fetch_messages(conversation_id)?;
        let digests: Vec<CanonicalMessageDigest> = messages
            .iter()
            .map(|m| {
                compact_invariant_message_digest_scoped(
                    &normalized_from_db_message(m),
                    DigestScope::CandidateComparable,
                )
            })
            .collect();
        // 裁定材料：把 DB 侧那份重建字节的长度等元数据留给歧义表读者。
        // 它**不参与判定**，也从不被解析 —— 判定完全由上面的摘要序列承担。
        let lines = storage.reconstruct_source_jsonl_for_conversation(conversation_id)?;
        let mut raw = Vec::new();
        for line in &lines {
            raw.extend_from_slice(line.as_bytes());
            raw.push(b'\n');
        }
        out.push(CandidateSideVersion {
            conversation_id,
            evidence: ContentVersion::new(
                VersionSource::CandidateDb,
                &raw,
                // 候选库侧**本来就没有**源文件 mtime。从前这里写 `0`，
                // 那是 R3 第 11 条同一个缺陷的另一处：一个编出来的时刻，
                // 看起来和真的一模一样。
                None,
                0,
                format!("db:conversation:{conversation_id}"),
            ),
            digests,
        });
    }
    Ok(out)
}

/// 摘要级的关系判定（裁定 R-E-58 的 (A) 入口）。
///
/// **既有 `decide_action` 签名零改动**；本入口只服务「候选侧没有源字节」这一种形态：
/// 字节层对 DB 侧本就不适用（它没有源字节），于是这里直接从第二层（canonical 消息序列）判。
pub(crate) fn decide_action_with_candidate_digests(
    identity: &RestoreIdentity,
    candidates: &[CandidateSideVersion],
    winner: &ContentVersion,
    winner_digests: &[CanonicalMessageDigest],
) -> RestoreAction {
    let summaries_of = |c: &CandidateSideVersion| {
        vec![VersionSummary::of(&c.evidence), VersionSummary::of(winner)]
    };
    if candidates.len() > 1 {
        return RestoreAction::Hold(HoldRecord {
            identity: identity.clone(),
            reason: HoldReason::MultipleCandidates,
            evidence: HoldEvidence::Versions {
                versions: candidates
                    .iter()
                    .map(|c| VersionSummary::of(&c.evidence))
                    .collect(),
            },
            consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
        });
    }
    let Some(candidate) = candidates.first() else {
        return RestoreAction::Restore;
    };
    match digest_prefix_relation(&candidate.digests, winner_digests) {
        Some(Relation::Equal) => RestoreAction::Skip,
        Some(Relation::StrictlyBefore) => RestoreAction::Replace,
        Some(Relation::StrictlyAfter) => RestoreAction::Hold(HoldRecord {
            identity: identity.clone(),
            reason: HoldReason::CandidateSuperset,
            evidence: HoldEvidence::Versions {
                versions: summaries_of(candidate),
            },
            consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
        }),
        Some(Relation::Diverged) | None => RestoreAction::Hold(HoldRecord {
            identity: identity.clone(),
            reason: HoldReason::CandidateDiverged,
            evidence: HoldEvidence::MessageLayer {
                versions: summaries_of(candidate),
                first_divergent_index: first_divergent_index(&candidate.digests, winner_digests),
            },
            consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION.to_vec(),
        }),
    }
}

/// dry-run planner：**只读**，产六类计数 + 歧义表 + HOLD 清单 + 可执行计划。
pub(crate) fn plan_mirror_restore(
    options: &MirrorRestorePlanOptions,
) -> anyhow::Result<MirrorRestorePlanReport> {
    let views = crate::raw_mirror::manifest_views(&options.data_dir)?;
    let doctor_reports = collect_sealed_manifest_reports(&options.data_dir);
    let mut storage = crate::storage::sqlite::FrankenStorage::open_readonly(&options.db_path)
        .map_err(|e| anyhow::anyhow!("open candidate db {}: {e}", options.db_path.display()))?;

    // 同一 identity 可能有多份 manifest（同一路径被捕获过多次）—— 那是 §5.2.3 的版本集合，
    // 必须先聚起来再选 winner，逐 manifest 独立判会把「同一条会话的两个版本」
    // 当成两条身份分别计数。
    // R3 #2 / R-E-103：键用 `RestoreIdentity` **本体**，不用它的 Display 串。
    // 那个串是 `{agent}@{host}:{source_id} {path}`，分隔符既不转义也不带长度框，
    // 于是含 `:` 或空格的合法取值可以撞成同一个键、把两条身份并成一条。
    // 结构化元组没有这个面（`RestoreIdentity` 已 derive `Ord`/`Eq`）。
    let mut groups: std::collections::BTreeMap<RestoreIdentity, Vec<usize>> =
        std::collections::BTreeMap::new();
    let mut report = MirrorRestorePlanReport {
        manifests_seen: views.len(),
        ..MirrorRestorePlanReport::default()
    };
    for (index, view) in views.iter().enumerate() {
        // R-E-67：provider 归一不了的**不再 bail**。旧行为是撞上第一份未知 slug 就
        // `?` 出去，于是真语料里 36.3% 的 manifest 让整轮一条都判不出来——一条读不懂的
        // 输入不该打死整轮，而「读不懂」与「不存在」必须能分辨。
        if normalize_provider_to_origin(&view.provider).is_none() {
            report.origin_unmapped.push(UnmappedOriginRecord {
                manifest_id: view.manifest_id.clone(),
                provider: view.provider.clone(),
            });
            continue;
        }
        // 归一成功才走这里，所以此处的 `?` 只可能被将来新增的失败原因触发，
        // 而不是被 provider ——「已知会发生的事」在上面被具名接住了。
        let identity = restore_identity_from_view(view)?;
        groups.entry(identity.clone()).or_default().push(index);
    }

    // FIND-5 mitigation (R-E-71'): reopen the read-only candidate handle every
    // REOPEN_EVERY_IDENTITIES identities.
    //
    // **The defect being worked around is not here.** Measured: reading one
    // conversation through this handle costs milliseconds for the first ~1650
    // conversations of a process and then roughly ten seconds each -- about
    // 1500x, on the *same* conversations (200 identities that take 1.1 s alone
    // took ~1600 s once 1647 conversations had already been read through the
    // same handle). The accumulating thing lives below `FrankenStorage`, was not
    // located, and is filed as an open defect: any long-running consumer that
    // reads enough conversations through one handle will hit the same wall.
    // This bounds how many any single handle reads; it does not fix anything.
    //
    // **A property does change and it is stated rather than buried**: the run is
    // no longer one continuous read through a single handle. That is safe here
    // because the candidate database is a *stable copy* produced by D5 with no
    // writer, and because each identity's queries are independent -- no
    // transaction spans identities. On a live database it would not be.
    //
    // 500 rather than 250 or 1000: measured over the 0:2200 prefix, wall clock
    // was 108 s / 107 s / 108 s at 250 / 500 / 1000 -- reopening costs nothing
    // measurable, so the interval is chosen for margin, not for speed. 500 keeps
    // better than 3x headroom under the observed knee; 250 buys no measured
    // benefit for triple the reopens. The same prefix without reopening: 1705 s.
    const REOPEN_EVERY_IDENTITIES: usize = 500;
    let mut since_reopen = 0usize;
    for indices in groups.values() {
        report.identities_considered += 1;
        since_reopen += 1;
        if since_reopen >= REOPEN_EVERY_IDENTITIES {
            storage.close_best_effort_in_place();
            storage = crate::storage::sqlite::FrankenStorage::open_readonly(&options.db_path)
                .map_err(|e| {
                    anyhow::anyhow!("reopen candidate db {}: {e}", options.db_path.display())
                })?;
            since_reopen = 0;
        }
        let head = &views[indices[0]];
        let identity = restore_identity_from_view(head)?;
        // 投影器要的是**分类**（选哪家 pin parser），不是身份 —— 用 family。
        let Some(family) = identity.origin.family() else {
            // provider 归一不出三族：planner 侧本就按 R-E-67 具名 HOLD，这里兜同一档，
            // 不让一条读不懂的 provider 把整轮打死。
            report.holds.push(hold_for_manifest_reference_missing(
                identity.clone(),
                Vec::new(),
            ));
            continue;
        };
        let projector = SealedMessageProjector {
            scratch_root: &options.scratch_dir,
            canonical_original_path: &identity.canonical_path,
            agent: family,
            sealed_source_size_bytes: head.source_size_bytes,
        };
        // winner 选择仍按投影侧全字段口径（mirror 两侧都有源字节，没有理由降口径）。
        // **与候选比时**才切到 candidate-comparable scope —— 两侧同 scope 才可比。
        let comparable = CandidateComparableProjector(SealedMessageProjector {
            scratch_root: &options.scratch_dir,
            canonical_original_path: &identity.canonical_path,
            agent: family,
            sealed_source_size_bytes: head.source_size_bytes,
        });

        // ── mirror 侧的版本集合 ────────────────────────────────────────
        let mut versions = Vec::with_capacity(indices.len());
        let mut input_fault: Option<HoldRecord> = None;
        for &index in indices {
            let view = &views[index];
            let Some(doctor) = doctor_reports
                .iter()
                .find(|r| r.manifest_id == view.manifest_id)
            else {
                input_fault = Some(hold_for_manifest_reference_missing(
                    identity.clone(),
                    Vec::new(),
                ));
                break;
            };
            match read_sealed_blob(&options.data_dir, doctor) {
                SealedBlobOutcome::Loaded(bytes) => versions.push(ContentVersion::new(
                    VersionSource::Mirror,
                    &bytes,
                    // 原样带过去：`unwrap_or_default()` 会把「没记」变成 epoch 0，
                    // 而下游拿它判时间倒挂（R3 第 11 条 / 裁定 R-E-103 J3）。
                    view.source_mtime_ms,
                    view.captured_at_ms,
                    view.blob_blake3.clone(),
                )),
                // blob 读不到 = 输入损坏类 HOLD，**不是**「这条身份不存在」——
                // 而修前这里选的桶名恰恰是「不存在」，注释与代码互相打脸（R3 第 12 条）。
                SealedBlobOutcome::ReferenceMissing => {
                    input_fault = Some(hold_for_manifest_reference_missing(
                        identity.clone(),
                        Vec::new(),
                    ));
                    break;
                }
                SealedBlobOutcome::PayloadHashMismatch { detail } => {
                    input_fault = Some(hold_for_unreadable_sealed_blob(
                        identity.clone(),
                        HoldReason::PayloadHashMismatch,
                        detail,
                    ));
                    break;
                }
                SealedBlobOutcome::Unreadable { detail } => {
                    input_fault = Some(hold_for_unreadable_sealed_blob(
                        identity.clone(),
                        // 读不动但不是哈希不匹配（路径不安全、非常规文件、I/O 错、
                        // 压缩/加密态不支持）：仍是输入损坏，桶名沿用「指向的内容
                        // 取不到」这一档，而**真正的信息在 detail 里**。
                        HoldReason::ManifestReferenceMissing,
                        detail,
                    ));
                    break;
                }
            }
        }
        if let Some(hold) = input_fault {
            report.non_relation_holds += 1;
            report.holds.push(hold);
            continue;
        }

        // ── winner（§5.2.3；选不出来 = 版本类 HOLD，不进六类表）────────
        let winner_index = match select_winner(&identity, &versions, &projector)
            .map_err(|e| anyhow::anyhow!("winner selection failed: {e:?}"))?
        {
            WinnerOutcome::Winner { index, .. } => index,
            WinnerOutcome::Hold(hold) => {
                report.non_relation_holds += 1;
                report.holds.push(hold);
                continue;
            }
        };

        // ── candidate 侧 ──────────────────────────────────────────────
        let candidates = candidate_versions_from_db(&storage, &identity)?;
        report.candidate_versions_seen += candidates.len();
        // R-E-68：**零会话投影**降为具名 HOLD，不再打死整轮。判据读的是 `ProjectionFault`
        // 这个具名类别，**不是** `detail` 的错误文案——文案是给人看的、随时会改，拿它做
        // 控制流等于把行为挂在措辞上。其余投影失败仍然上抛：不假装分得清的，就别分。
        let winner_digests =
            match comparable.project(&identity.origin, versions[winner_index].normalized()) {
                Ok(digests) => digests,
                Err(fault) if fault.is_empty_projection() => {
                    report.non_relation_holds += 1;
                    report.holds.push(HoldRecord {
                        identity: identity.clone(),
                        reason: HoldReason::ProjectionEmpty,
                        evidence: HoldEvidence::WholeFileExcluded {
                            detail: format!(
                                "manifest {} ({} bytes) projected to zero conversations: {}",
                                views[indices[winner_index]].manifest_id,
                                views[indices[winner_index]].blob_size_bytes,
                                fault.detail
                            ),
                        },
                        consumed_manifest_fields: manifest_fields::CONSUMED_BY_WINNER_SELECTION
                            .to_vec(),
                    });
                    continue;
                }
                Err(fault) => return Err(anyhow::anyhow!("winner projection failed: {fault:?}")),
            };

        let action = decide_action_with_candidate_digests(
            &identity,
            &candidates,
            &versions[winner_index],
            &winner_digests,
        );

        if !report.census.record(&action) {
            // 六类之外的 HOLD：`record` 返回 false 就是它在说「我没计」。
            report.non_relation_holds += 1;
        }
        match &action {
            RestoreAction::Skip => {}
            RestoreAction::Restore => report.plan.push(RestorePlanItem {
                manifest_id: views[indices[winner_index]].manifest_id.clone(),
                action: PlannedAction::RestoreNew,
            }),
            RestoreAction::Replace => {
                let conversation_id = candidates
                    .first()
                    .map(|c| c.conversation_id)
                    .ok_or_else(|| anyhow::anyhow!("replace without a candidate conversation"))?;
                report.plan.push(RestorePlanItem {
                    manifest_id: views[indices[winner_index]].manifest_id.clone(),
                    action: PlannedAction::Replace { conversation_id },
                });
            }
            RestoreAction::Hold(hold) => report.holds.push(hold.clone()),
        }
    }

    storage.close_best_effort_in_place();

    // 对账：每一份读到的 manifest 要么进了某个 identity 组，要么被 `origin_unmapped`
    // 具名接住，**没有第三条去处**。R-E-67 加了一条 `continue`，而 `continue` 正是
    // 「无声丢掉一批输入」最常见的入口——把它变成机器判据，就不用指望有人去对两个数。
    let grouped_manifests: usize = groups.values().map(|indices| indices.len()).sum();
    if grouped_manifests + report.origin_unmapped.len() != report.manifests_seen {
        anyhow::bail!(
            "manifest accounting is off: {} read, {} grouped into identities, {} origin-unmapped",
            report.manifests_seen,
            grouped_manifests,
            report.origin_unmapped.len()
        );
    }
    Ok(report)
}

// ===========================================================================
// E8 · dry-run planner（plan Task E8 Step 1/2）
//
// 形状：**winner 从 mirror 侧选 → candidate 从候选 DB 重建 → `decide_action` → 六类计数**。
// 六类口径**直接复用 E4 已落地的 `RelationCensus`**，不另立一套。
//
// candidate 侧的字节由 `reconstruct_source_jsonl_for_conversation` 重建（cass 把逐条源事件
// 存在 `extra_json`/`extra_bin` 里，canonical 库自带重建源文件的能力）。**重建字节与原文件
// 不必逐字节相同** —— `compare_versions` 的第二层（投影后的消息序列）正是为这种情形存在的。
//
// **mirror 面的来源是入参**（`data_dir`）：E8 给的是封存件只读面，E8b 换成 materialize 出来的
// 可写工作树。写死成「就是候选包那棵」会让 E8b 只能回头改这里。
// ===========================================================================
#[cfg(test)]
mod e8_dry_run_planner_tests {
    use super::*;
    use tempfile::TempDir;

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

    /// `n` 条消息的合成 codex 会话。**消息条数可变**是这里的关键 —— 六类关系里的
    /// 「真前缀」「超集」都靠它造。
    fn write_session_n(root: &Path, name: &str, session_id: &str, n: usize) -> PathBuf {
        let dir = root.join(".codex").join("sessions").join("2026").join("08");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut text = format!(
            "{{\"timestamp\":\"2026-08-18T00:00:00.000Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{session_id}\",\"cwd\":\"/fixtures/ws\"}}}}\n"
        );
        for i in 0..n {
            text.push_str(&format!(
                "{{\"timestamp\":\"2026-08-18T00:00:0{}.000Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"user\",\"content\":[{{\"type\":\"input_text\",\"text\":\"{session_id} 第 {i} 条\"}}]}}}}\n",
                (i % 9) + 1
            ));
        }
        std::fs::write(&path, text).unwrap();
        path
    }

    struct Bench {
        _tmp: TempDir,
        data_dir: PathBuf,
        scratch: PathBuf,
        db_path: PathBuf,
        expected_identities: usize,
    }

    fn report_of(b: &Bench) -> MirrorRestorePlanReport {
        plan_mirror_restore(&MirrorRestorePlanOptions {
            data_dir: b.data_dir.clone(),
            db_path: b.db_path.clone(),
            scratch_dir: b.scratch.clone(),
            snapshot_root: "e8-bench-root".into(),
        })
        .expect("dry-run planner must run")
    }

    // ── R3 第 12 条 / 裁定 R-E-103 J3：读不到 ≠ 不存在 ─────────────────
    //
    // `read_sealed_blob` **正确**区分 `ReferenceMissing`（blob 不在）与
    // `Unreadable { detail }`（其余读取 / 校验失败），planner 却把两者并进
    // `hold_for_manifest_reference_missing`，还把 `detail` 丢掉（传 `Vec::new()`）。
    //
    // **代码自己的注释就打脸**：那一行上面写着「blob 读不到 = 输入损坏类 HOLD，
    // **不是**『这条身份不存在』」，而它选的桶名恰恰是「不存在」。
    // 同时 `PayloadHashMismatch` 在分类里定义着，这条路径上**永不发射**。
    //
    // 判据落在 planner 的产物上（HOLD 台账正是操作者读到的那一面），
    // 不落在 `read_sealed_blob` 的返回值上 —— 那一层本来就分得清，缺陷在收口那一步。
    #[test]
    fn a_corrupted_blob_holds_as_payload_hash_mismatch_not_reference_missing() {
        let b = bench();

        // 挑一份 manifest，把它的 blob **留在原地**但换掉字节。
        // 与「blob 不在」是两种不同的输入损坏，操作者的下一步动作也不同：
        // 一个是去找丢失的内容，一个是这份 mirror 本身已经不可信。
        let views = crate::raw_mirror::manifest_views(&b.data_dir).unwrap();
        let victim = views
            .iter()
            .find(|v| v.original_path.ends_with("rollout-missing.jsonl"))
            .expect("前置断言：fixture 里必须有这条身份");
        let blob = crate::doctor_raw_mirror_root(&b.data_dir).join(&victim.blob_relative_path);
        let original = std::fs::read(&blob).unwrap();
        std::fs::write(&blob, b"these bytes do not hash to the recorded blob id\n").unwrap();
        assert!(
            blob.exists(),
            "前置断言：blob **在**，测的不是「不在」那一支"
        );
        assert_ne!(
            std::fs::read(&blob).unwrap(),
            original,
            "前置断言：字节必须真被换掉，否则这条用例没有分辨力"
        );

        let report = report_of(&b);
        let hold = report
            .holds
            .iter()
            .find(|h| h.identity.canonical_path.ends_with("rollout-missing.jsonl"))
            .expect("被破坏的那条身份必须产出一条 HOLD");

        assert_eq!(
            hold.reason,
            HoldReason::PayloadHashMismatch,
            "blob 在、字节对不上 = payload 哈希不匹配。判成\
             `manifest-reference-missing` 会把「这份 mirror 不可信」说成\
             「这条身份不存在」—— 两者的下一步动作完全不同"
        );
        assert_eq!(
            hold.reason.class(),
            HoldClass::InputCorruption,
            "两条 reason 同属输入损坏类，改的是桶名不是类"
        );

        // detail 必须真的被带出来。修前这里传的是 `Vec::new()` ——
        // 一个**空证据**，与「查过了，没发现什么」长得一模一样。
        match &hold.evidence {
            HoldEvidence::InputUnreadable { detail } => assert!(
                detail.contains(&victim.manifest_id),
                "detail 要能把操作者引到**是哪一份** manifest 上，实得：{detail}"
            ),
            other => panic!("读不动的证据必须走 InputUnreadable 这一档，实得 {other:?}"),
        }
    }

    /// 反方向臂：blob **真的不在**时，仍须判 `manifest-reference-missing`。
    /// 把两者并成一个桶是缺陷，把它们对调同样是缺陷。
    #[test]
    fn a_deleted_blob_still_holds_as_manifest_reference_missing() {
        let b = bench();
        let views = crate::raw_mirror::manifest_views(&b.data_dir).unwrap();
        let victim = views
            .iter()
            .find(|v| v.original_path.ends_with("rollout-missing.jsonl"))
            .expect("前置断言：fixture 里必须有这条身份");
        let blob = crate::doctor_raw_mirror_root(&b.data_dir).join(&victim.blob_relative_path);
        std::fs::remove_file(&blob).unwrap();
        assert!(!blob.exists(), "前置断言：blob 必须真的不在了");

        let report = report_of(&b);
        let hold = report
            .holds
            .iter()
            .find(|h| h.identity.canonical_path.ends_with("rollout-missing.jsonl"))
            .expect("blob 不在的那条身份必须产出一条 HOLD");
        assert_eq!(
            hold.reason,
            HoldReason::ManifestReferenceMissing,
            "blob 真的不在时这条桶名是对的，不得被顺手改走"
        );
    }

    /// 锚定的声称原文：`mirror-restore` 子命令的 doc（`src/lib.rs`）——
    /// 「**Dry-run by default: neither the mirror nor the candidate database is
    /// written.** Planning still materializes projections under `--scratch`, and
    /// `--out` writes report files — so this is not a no-write mode.」
    /// （这句是 F11 那批把原来的「什么都不写」改成的如实措辞，R1 Finding 15 / R-E-84。）
    ///
    /// **两半都要判，缺一半这条测试就会替另一句谎话背书**：
    /// 前半句「不写 mirror、不写候选库」判零变化；后半句「不是 no-write 模式」判
    /// scratch 下**确实**多了东西。只判前半句的话，一个真的什么都不做的 planner
    /// 也能让它绿；只判后半句的话，一个顺手改了 mirror 的 planner 同样能绿。
    #[test]
    fn e8_dry_run_writes_only_under_scratch_exactly_as_the_doc_claims() {
        let b = bench();
        let before_data = crate::phase3_restore::test_tree_snapshot(&b.data_dir);
        let before_scratch = crate::phase3_restore::test_tree_snapshot(&b.scratch);
        assert!(
            !before_data.is_empty(),
            "前置断言：mirror 与候选库必须先在盘上，否则「逐条不变」是在对空树说话"
        );

        let report = report_of(&b);
        assert!(
            report.identities_considered > 0,
            "前置断言：planner 必须真的判过身份，否则它什么都没做、下面两半都没意义"
        );

        let after_data = crate::phase3_restore::test_tree_snapshot(&b.data_dir);
        let after_scratch = crate::phase3_restore::test_tree_snapshot(&b.scratch);

        // 前半句：mirror 面与候选库**逐条**不变（新增、消失、大小变化都算变）。
        assert_eq!(
            after_data, before_data,
            "dry-run 说它不写 mirror、也不写候选库，实测 data_dir 变了"
        );

        // 后半句：scratch 下确实多了东西 —— 「这不是 no-write 模式」同样是被声称的事实。
        let new_scratch: Vec<_> = after_scratch
            .iter()
            .filter(|x| !before_scratch.contains(x))
            .collect();
        assert!(
            !new_scratch.is_empty(),
            "doc 明写规划会把投影物化到 --scratch 下，实测 scratch 一个新条目都没有 —— \
             要么 planner 没走到物化，要么那句如实措辞又变假了"
        );
    }

    // ── Step 2 的验证条件写进代码断言：能被机器判的不留给人眼 ────────────
    #[test]
    fn e8_six_class_counts_sum_to_the_identities_considered() {
        let b = bench();
        let report = report_of(&b);
        assert_eq!(
            report.identities_considered, b.expected_identities,
            "参与判定的 identity 数必须等于 mirror 侧的身份数"
        );
        assert_eq!(
            report.census.total() + report.non_relation_holds,
            report.identities_considered,
            "六类计数之和 + 非关系类 HOLD == 参与判定的 identity 数 —— \
             差额意味着有身份被静默丢掉（plan Task E8 Step 2 的验证条件）"
        );
    }

    #[test]
    fn e8_dry_run_reports_each_of_the_four_reachable_relations() {
        let b = bench();
        let report = report_of(&b);
        assert_eq!(report.census.skip, 1, "相等 → Skip");
        assert_eq!(report.census.restore, 1, "candidate 缺失 → Restore");
        assert_eq!(report.census.replace, 1, "candidate 是真前缀 → Replace");
        assert_eq!(report.census.hold_superset, 1, "candidate 是超集 → HOLD");
    }

    // ── HOLD 清单必须完整落盘（Phase 4 开工资格的输入）──────────────────
    #[test]
    fn e8_dry_run_persists_every_hold_with_its_identity_and_reason() {
        let b = bench();
        let report = report_of(&b);
        assert_eq!(
            report.holds.len(),
            report.census.hold_superset
                + report.census.hold_diverged
                + report.census.hold_multiple_candidates
                + report.non_relation_holds,
            "落盘的 HOLD 条数必须与计数吻合 —— 少一条就是静默丢一条待人裁的东西"
        );
        assert!(
            report
                .holds
                .iter()
                .all(|h| !h.identity.canonical_path.is_empty())
        );
    }

    // ── candidate 侧真的参与了判定（否则「四类都有」可能是巧合）──────────
    #[test]
    fn e8_candidate_side_versions_are_tagged_as_candidate_db() {
        let b = bench();
        let report = report_of(&b);
        assert!(
            report.candidate_versions_seen > 0,
            "candidate 侧必须真的被构造过 —— 计数为 0 说明六类判定只看了 mirror 一侧"
        );
        assert_eq!(
            report.candidate_versions_seen, 3,
            "四条身份里有三条在库里有对应会话（equal / prefix / superset）"
        );
    }

    // ── dry-run 必须零写：mirror 写集与 DB 大小前后不变 ──────────────────
    #[test]
    fn e8_dry_run_writes_nothing() {
        let b = bench();
        let before = write_set_snapshot(&b.data_dir);
        let db_before = std::fs::metadata(&b.db_path).unwrap().len();
        let _ = report_of(&b);
        let after = write_set_snapshot(&b.data_dir);
        assert_eq!(before, after, "dry-run 不得写 mirror 面");
        assert_eq!(
            db_before,
            std::fs::metadata(&b.db_path).unwrap().len(),
            "dry-run 不得写候选 DB"
        );
    }

    fn write_set_snapshot(root: &Path) -> Vec<(String, u64)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(meta) = entry.metadata() {
                    out.push((
                        path.strip_prefix(root).unwrap().display().to_string(),
                        meta.len(),
                    ));
                }
            }
        }
        out.sort();
        out
    }

    /// 造决策表里能在隔离小库造出来的四类：Skip / Restore / Replace / HOLD(超集)。
    ///
    /// 「分叉」与「多 candidate」要靠同一 identity 上的多份版本，属 §5.2.3 的版本集合形态，
    /// 归 winner 选择那条线；本演练场只覆盖决策表这一侧，**并把它显式写下来**，
    /// 免得「四类都在」被误读成「六类全覆盖」。
    fn bench() -> Bench {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        let live = tmp.path().join("live");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();

        let equal = write_session_n(&live, "rollout-equal.jsonl", "e8-equal", 3);
        let missing = write_session_n(&live, "rollout-missing.jsonl", "e8-missing", 3);
        let prefix = write_session_n(&live, "rollout-prefix.jsonl", "e8-prefix", 3);
        let superset = write_session_n(&live, "rollout-superset.jsonl", "e8-superset", 2);
        for p in [&equal, &missing, &prefix, &superset] {
            capture(&data_dir, p);
        }

        let db_path = data_dir.join("candidate.sqlite");
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
        seed_from(&storage, &data_dir, &scratch, "rollout-equal.jsonl", None);
        seed_from(
            &storage,
            &data_dir,
            &scratch,
            "rollout-prefix.jsonl",
            Some(2),
        );
        seed_superset(&storage, &data_dir, &scratch, "rollout-superset.jsonl");
        drop(storage);

        Bench {
            _tmp: tmp,
            data_dir,
            scratch,
            db_path,
            expected_identities: 4,
        }
    }

    /// 用**指定 provider** 捕获一条会话。既有的 `capture` 写死 `"codex"`，而这一组用例
    /// 存在的全部理由就是让 fixture 长出真语料的 provider 形状（R-E-67 条件 3）。
    fn capture_as(data_dir: &Path, source: &Path, provider: &str) {
        crate::raw_mirror::capture_source_file(crate::raw_mirror::RawMirrorCaptureInput {
            data_dir,
            provider,
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: source,
            db_links: &[],
        })
        .expect("capture source into raw mirror");
    }

    /// 一条会话、一个 provider 的最小演练场。
    ///
    /// 内容仍是 codex 形态的 JSONL —— 本组用例问的是「provider 归一之后这条 manifest 能不能
    /// 被规划」，不是「三家的解析器各自对不对」；把内容也换掉会同时动两个变量。
    fn bench_with_provider(provider: &str) -> Bench {
        bench_with_providers(&[provider])
    }

    fn bench_with_two_providers(first: &str, second: &str) -> Bench {
        bench_with_providers(&[first, second])
    }

    fn bench_with_providers(providers: &[&str]) -> Bench {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        let live = tmp.path().join("live");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();

        for (index, provider) in providers.iter().enumerate() {
            let path = write_session_n(
                &live,
                &format!("rollout-provider-{index}.jsonl"),
                &format!("e8-provider-{index}"),
                3,
            );
            capture_as(&data_dir, &path, provider);
        }

        // 空候选库：本组问的是归一与记账，不是六类关系。DB 里没有对应会话时每条身份判
        // `Restore`，计数照样进 `identities_considered`。
        let db_path = data_dir.join("candidate.sqlite");
        drop(crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap());

        let expected = providers
            .iter()
            .filter(|p| normalize_provider_to_origin(p).is_some())
            .count();
        Bench {
            _tmp: tmp,
            data_dir,
            scratch,
            db_path,
            expected_identities: expected,
        }
    }

    /// 按**文件名**定位 manifest。会话 id（`e8-equal` 等）只出现在**内容**里，
    /// `original_path` 里没有它 —— 第一版拿会话 id 当锚点，五条用例全部倒在这里。
    /// 把演练场**落到指定目录**，给 CLI 的真观测用（strace 那一跑需要一个盘上的
    /// mirror 树 + 候选 DB）。形态沿用 E7 的子进程入口：`#[ignore]` + env 传参，
    /// 由外部显式拉起，常规跑不执行。
    #[test]
    #[ignore]
    fn e8_materialize_bench_for_observation() {
        let root = PathBuf::from(std::env::var("CASS_E8_BENCH_DIR").unwrap());
        let data_dir = root.join("cass-data");
        let live = root.join("live");
        let scratch = root.join("scratch");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();

        let equal = write_session_n(&live, "rollout-equal.jsonl", "e8-equal", 3);
        let missing = write_session_n(&live, "rollout-missing.jsonl", "e8-missing", 3);
        let prefix = write_session_n(&live, "rollout-prefix.jsonl", "e8-prefix", 3);
        let superset = write_session_n(&live, "rollout-superset.jsonl", "e8-superset", 2);
        for p in [&equal, &missing, &prefix, &superset] {
            capture(&data_dir, p);
        }
        let db_path = data_dir.join("candidate.sqlite");
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
        seed_from(&storage, &data_dir, &scratch, "rollout-equal.jsonl", None);
        seed_from(
            &storage,
            &data_dir,
            &scratch,
            "rollout-prefix.jsonl",
            Some(2),
        );
        seed_superset(&storage, &data_dir, &scratch, "rollout-superset.jsonl");
        drop(storage);
        // live 源文件删掉：投影的定义域里没有活文件系统，留着会让「零 HOME 读取」
        // 这条观测失去意义（读的是 bench 自己的 live 目录也算读，但那不是 HOME）。
        for p in [&equal, &missing, &prefix, &superset] {
            std::fs::remove_file(p).unwrap();
        }
        println!(
            "BENCH-READY data_dir={} db={}",
            data_dir.display(),
            db_path.display()
        );
    }

    fn view_for<'a>(
        views: &'a [crate::raw_mirror::RawMirrorManifestView],
        file_name: &str,
    ) -> &'a crate::raw_mirror::RawMirrorManifestView {
        let hits: Vec<_> = views
            .iter()
            .filter(|v| v.original_path.ends_with(file_name))
            .collect();
        assert_eq!(
            hits.len(),
            1,
            "fixture 锚点必须恰命中 1 份 manifest（实得 {}）—— 命中 0 是锚点错，\
             命中多份是 fixture 造重了，两种都不能继续",
            hits.len()
        );
        hits[0]
    }

    fn seed_from(
        storage: &crate::storage::sqlite::FrankenStorage,
        data_dir: &Path,
        scratch: &Path,
        session: &str,
        truncate_to: Option<usize>,
    ) {
        let views = crate::raw_mirror::manifest_views(data_dir).unwrap();
        let view = view_for(&views, session);
        let mut conv = project_view_for_bench(data_dir, scratch, view);
        if let Some(n) = truncate_to {
            conv.messages.truncate(n);
        }
        insert_conv(storage, &conv);
    }

    fn seed_superset(
        storage: &crate::storage::sqlite::FrankenStorage,
        data_dir: &Path,
        scratch: &Path,
        session: &str,
    ) {
        let views = crate::raw_mirror::manifest_views(data_dir).unwrap();
        let view = view_for(&views, session);
        let mut conv = project_view_for_bench(data_dir, scratch, view);
        let mut extra = conv.messages.last().cloned().expect("至少一条");
        extra.idx = conv.messages.len() as i64;
        extra.content = format!("{} 多出来的一条", extra.content);
        conv.messages.push(extra);
        insert_conv(storage, &conv);
    }

    fn insert_conv(
        storage: &crate::storage::sqlite::FrankenStorage,
        conv: &crate::model::types::Conversation,
    ) {
        let agent_id = storage
            .ensure_agent(&crate::model::types::Agent {
                id: None,
                slug: conv.agent_slug.clone(),
                name: conv.agent_slug.clone(),
                version: None,
                kind: crate::model::types::AgentKind::Cli,
            })
            .unwrap();
        let workspace_id = conv
            .workspace
            .as_ref()
            .map(|ws| storage.ensure_workspace(ws, None).unwrap());
        storage
            .insert_conversations_batched(&[(agent_id, workspace_id, conv)])
            .unwrap();
    }

    fn project_view_for_bench(
        data_dir: &Path,
        scratch: &Path,
        view: &crate::raw_mirror::RawMirrorManifestView,
    ) -> crate::model::types::Conversation {
        let reports = collect_sealed_manifest_reports(data_dir);
        let report = reports
            .iter()
            .find(|r| r.manifest_id == view.manifest_id)
            .expect("doctor report");
        let blob = match read_sealed_blob(data_dir, report) {
            SealedBlobOutcome::Loaded(bytes) => bytes,
            other => panic!("fixture blob 必须读得到：{other:?}"),
        };
        let provenance = provenance_from_manifest_view(view);
        let sealed = SealedSource {
            agent: Origin::Codex,
            canonical_original_path: &view.original_path,
            source_size_bytes: view.source_size_bytes,
            blob: &blob,
        };
        match project_sealed_source(scratch, &sealed, &provenance) {
            Ok(SealedProjection::Projected(conv)) => {
                crate::indexer::persist::map_to_internal(&conv)
            }
            other => panic!("投影未产出会话：{other:?}"),
        }
    }

    // ── R-E-59 条件 ③：DB canonical 空间 == 投影 canonical 空间（限 scope）──
    //
    // 这条是 (A2) 引入的**唯一新前提**的直接机器断言。两条断言缺一不可：
    //   ① `CandidateComparable` scope 下两侧摘要序列**相等** —— 前提成立；
    //   ② `Projection` scope 下两侧**不等** —— 把「DB 丢了 `invocations`」这个空间差异
    //      钉成机器可见的事实。只有 ① 的话，将来谁把 scope 悄悄改回全字段，
    //      测试会红得莫名其妙；有了 ②，红的位置直接指向「这个字段 DB 没有」。
    //
    // **fixture 必须含 tool_call**：纯文本会话的 `invocations` 恒空，两个 scope 算出来一样，
    // ① 会绿而 ② 会红 —— 那种「绿」证明的不是空间一致，是样本恰好不含有分歧的那个字段。
    const CLAUDE_WITH_TOOL_CALL: &str = concat!(
        r#"{"type":"user","timestamp":"2025-12-01T10:00:00Z","message":{"role":"user","content":"kick off"}}"#,
        "\n",
        r#"{"type":"assistant","timestamp":"2025-12-01T10:00:01Z","message":{"role":"assistant","model":"claude-opus-5","content":[{"type":"text","text":"let me look"},{"type":"tool_use","id":"toolu_01","name":"Read","input":{"path":"/x"}}]}}"#,
        "\n",
        r#"{"type":"user","timestamp":"2025-12-01T10:00:02Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01","content":"file body"}]}}"#,
        "\n",
    );

    #[test]
    fn e8_db_canonical_space_matches_projection_space_within_the_candidate_scope() {
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path().join("cass-data");
        let live = tmp.path().join("live");
        let scratch = tmp.path().join("scratch");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();

        let dir = live.join(".claude").join("projects").join("myapp");
        std::fs::create_dir_all(&dir).unwrap();
        let source = dir.join("dddd1111-2222-3333-4444-555555555555.jsonl");
        std::fs::write(&source, CLAUDE_WITH_TOOL_CALL).unwrap();
        crate::raw_mirror::capture_source_file(crate::raw_mirror::RawMirrorCaptureInput {
            data_dir: &data_dir,
            provider: "claude_code",
            source_id: "local",
            origin_kind: "local",
            origin_host: None,
            source_path: &source,
            db_links: &[],
        })
        .unwrap();

        let views = crate::raw_mirror::manifest_views(&data_dir).unwrap();
        assert_eq!(views.len(), 1, "前置断言：fixture 恰一份 manifest");
        let view = &views[0];
        let reports = collect_sealed_manifest_reports(&data_dir);
        let doctor = reports
            .iter()
            .find(|r| r.manifest_id == view.manifest_id)
            .expect("doctor report");
        let blob = match read_sealed_blob(&data_dir, doctor) {
            SealedBlobOutcome::Loaded(bytes) => bytes,
            other => panic!("blob 必须读得到：{other:?}"),
        };
        let provenance = provenance_from_manifest_view(view);
        let sealed = SealedSource {
            agent: Origin::ClaudeCode,
            canonical_original_path: &view.original_path,
            source_size_bytes: view.source_size_bytes,
            blob: &blob,
        };
        let projected = match project_sealed_source(&scratch, &sealed, &provenance) {
            Ok(SealedProjection::Projected(conv)) => *conv,
            other => panic!("投影未产出会话：{other:?}"),
        };

        // **存在型断言先数可满足元素**：没有这一条，下面两条断言可能是在一个
        // 「根本没有 invocation」的样本上空转。
        let with_invocations = projected
            .messages
            .iter()
            .filter(|m| !m.invocations.is_empty())
            .count();
        assert!(
            with_invocations >= 1,
            "fixture 必须至少有一条带 invocation 的消息，否则两个 scope 恒等、本用例空转"
        );

        let projection_side = |scope| -> Vec<CanonicalMessageDigest> {
            projected
                .messages
                .iter()
                .map(|m| compact_invariant_message_digest_scoped(m, scope))
                .collect()
        };

        let internal = crate::indexer::persist::map_to_internal(&projected);
        let db_path = data_dir.join("closure.sqlite");
        let storage = crate::storage::sqlite::FrankenStorage::open(&db_path).unwrap();
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
        let identity = restore_identity_from_view(view).unwrap();
        let candidates = candidate_versions_from_db(&storage, &identity).unwrap();
        assert_eq!(candidates.len(), 1, "库里恰有一条对应会话");

        // ① 限 scope 相等 —— (A2) 的前提成立。
        assert_eq!(
            candidates[0].digests,
            projection_side(DigestScope::CandidateComparable),
            "候选可比 scope 下，DB canonical 空间必须与投影 canonical 空间逐条相等 —— \
             不等说明两个空间有漂移，那是比本次更大的发现"
        );

        // ② 全字段 scope 下**必须不等** —— DB 丢了 `invocations`，把它钉成机器事实。
        let db_full: Vec<CanonicalMessageDigest> = {
            let messages = storage
                .fetch_messages(candidates[0].conversation_id)
                .unwrap();
            messages
                .iter()
                .map(|m| {
                    compact_invariant_message_digest_scoped(
                        &normalized_from_db_message(m),
                        DigestScope::Projection,
                    )
                })
                .collect()
        };
        assert_ne!(
            db_full,
            projection_side(DigestScope::Projection),
            "全字段 scope 下两侧必须不等：DB 的 Message 没有 `invocations` 这一格。\
             这条若变绿，说明要么样本没有工具调用（用例空转），要么 DB 真开始存 invocations 了 —— \
             两种都必须有人看一眼"
        );
    }

    // ======================================================================
    // R-E-67 / R-E-68：真语料形态。
    //
    // 这一组存在的理由，是这个文件里既有的 fixture **全部**用 `codex` / `claude_code`
    // 两个 provider —— 都落在 `Origin::parse` 的接受集里。于是六个 E8 用例全绿，而真语料
    // 里 36.3% 的 manifest 让 planner 一条都判不出来。fixture 造的是代码假设的形状，就只能
    // 印证假设：`mirror_seal.py` 的 F-7 记着同一个失效模式（0/7640 manifest 带
    // `blob_checksum`，而它的 fixture 全都带，于是测试永远说不出「一条都没封上」）。
    // 修法不是多写几个断言，是让 fixture 长出真实语料的形状。
    // ======================================================================

    /// 九个取值全部来自实测（run root 的 `evidence/find-2-provider-space.txt`，
    /// 9488 份真 manifest 的 provider 全集），**不是想出来的**。
    ///
    /// 表里带上三个正名与两个「定案不映射」的值：前者防归一把恒等映射写坏，后者把
    /// 「`pi_agent` / `gemini` 不入三族」（2026-08-19 上位裁定确认）钉成机器事实 —— 哪天有人
    /// 顺手给它们加一条映射，这里会红。
    #[test]
    fn r_e_67_provider_normalization_covers_every_measured_value() {
        let table: [(&str, Option<Origin>); 12] = [
            // 三个正名，恒等。
            ("claude_code", Some(Origin::ClaudeCode)),
            ("codex", Some(Origin::Codex)),
            ("openclaw", Some(Origin::Openclaw)),
            // 同一家的另一个 slug 写法（实测 2387 份）。
            ("claude", Some(Origin::ClaudeCode)),
            // openclaw 的 agent 实例（实测 609/335/61/16/2/2 份）。
            ("openclaw/main", Some(Origin::Openclaw)),
            ("openclaw/wood", Some(Origin::Openclaw)),
            ("openclaw/javich", Some(Origin::Openclaw)),
            ("openclaw/justin", Some(Origin::Openclaw)),
            ("openclaw/alice", Some(Origin::Openclaw)),
            ("openclaw/clawra", Some(Origin::Openclaw)),
            // 不属受保护资产三家 —— 永久具名 HOLD，不入三族。
            ("pi_agent", None),
            ("gemini", None),
        ];
        for (provider, expected) in table {
            assert_eq!(
                normalize_provider_to_origin(provider),
                expected,
                "provider {provider:?} 的归一结果与实测契约不符"
            );
        }

        // 覆盖面自检：清单型断言必须连「查了几条」一起断言，否则一次手滑就把它缩成空门
        // 而全程绿灯（第五棒 §6.2）。
        assert_eq!(table.len(), 12, "表被改动过，请同时更新实测出处");

        // 未知 slug 一律不归一，**不猜不兜底**：前缀像而不是的、空串、大小写变体都不放行。
        for unknown in [
            "",
            "openclaw",
            "openclawx/main",
            "OpenClaw/main",
            "Claude",
            "vscode",
        ] {
            if unknown == "openclaw" {
                continue; // 正名，上表已覆盖
            }
            assert_eq!(
                normalize_provider_to_origin(unknown),
                None,
                "未知 slug {unknown:?} 必须不归一"
            );
        }
    }

    /// `openclaw/<agent>` 与 `claude` 两种真实形状进 planner，**必须被规划、不再 bail**。
    ///
    /// 断言的是「被规划了」而不只是「没报错」：`identities_considered` 计到，且
    /// `origin_unmapped` 为空。只断言 `is_ok()` 的话，一个把所有 manifest 都判成
    /// unmapped 的实现同样能过。
    #[test]
    fn r_e_67_real_world_provider_shapes_are_planned_not_rejected() {
        for provider in ["claude", "openclaw/wood"] {
            let bench = bench_with_provider(provider);
            let report = report_of(&bench);
            assert!(
                report.origin_unmapped.is_empty(),
                "provider {provider:?} 应当被归一，却落进了 origin_unmapped"
            );
            assert!(
                report.identities_considered > 0,
                "provider {provider:?} 一条身份都没进入判定 —— 归一成功但没被规划，\
                 说明挡在了另一层"
            );
            assert_eq!(
                report.manifests_seen,
                report.identities_considered + report.origin_unmapped.len(),
                "manifest 对账：读到的每一份要么成组、要么被具名接住"
            );
        }
    }

    /// 不可归一的 slug **不再打死整轮**：它被具名记下，同一轮里其余身份照常判完。
    ///
    /// 这条是 R-E-67 (c) 的机器判据。旧行为下这个用例会在第一份 `pi_agent` manifest 上
    /// `Err` 出来，一条计数都拿不到。
    #[test]
    fn r_e_67_unmapped_slug_is_named_and_does_not_kill_the_run() {
        let bench = bench_with_two_providers("codex", "pi_agent");
        let report = report_of(&bench);
        assert_eq!(
            report.origin_unmapped.len(),
            1,
            "恰有一份 manifest 的 provider 不可归一"
        );
        assert_eq!(
            report.origin_unmapped[0].provider, "pi_agent",
            "原始 slug 必须原样带出 —— 不带它，看报告的人不知道该去映射什么"
        );
        assert!(
            report.identities_considered > 0,
            "另一份可归一的 manifest 必须照常被判定：一条读不懂的输入不该打死整轮"
        );
        assert_eq!(
            report.manifests_seen,
            report.identities_considered + report.origin_unmapped.len()
        );
    }

    /// R-E-68：投影出零会话的 blob 判 `projection-empty` HOLD，而不是 bail。
    ///
    /// 判据读的是具名的 [`ProjectionFault::UnexpectedConversationCount`]，不是错误文案 ——
    /// 这条断言同时钉死「会话数为 2 不走这条路」：`is_empty_projection` 只认 0。
    #[test]
    fn r_e_68_zero_conversation_projection_is_a_named_hold() {
        assert!(
            ProjectionError::from_fault(ProjectionFault::UnexpectedConversationCount { count: 0 })
                .is_empty_projection(),
            "零会话必须被判为 projection-empty"
        );
        assert!(
            !ProjectionError::from_fault(ProjectionFault::UnexpectedConversationCount { count: 2 })
                .is_empty_projection(),
            "两条会话是另一回事（一个文件里有多条会话），不得走同一条 HOLD"
        );
        assert!(
            !ProjectionError::other("非 UTF-8").is_empty_projection(),
            "没有具名故障的投影失败不得被当成零会话"
        );
        assert_eq!(
            HoldReason::ProjectionEmpty.as_str(),
            "projection-empty",
            "wire 上的字面量是下游解析的契约"
        );
        assert_eq!(
            HoldReason::parse("projection-empty"),
            Some(HoldReason::ProjectionEmpty),
            "新增 reason 必须能从 wire 解析回来 —— 只加不解析等于下游读不懂"
        );
        assert_eq!(
            HoldReason::ALL.len(),
            10,
            "reason 全集变了就要同时更新解析与分类，这条是覆盖面自检"
        );
    }
}
