//! Persisting and reopening the identity of one API-only embedding generation.
//!
//! A generation created from a model-service profile is not identified by its
//! width alone. Three separate facts must be stored together and must be read
//! back together:
//!
//! * the row in `embedding_generations` (embedder id, dimension, the two
//!   pipeline versions, the content fingerprint);
//! * the **representation record** under `api_representation:v1:<id>` — the
//!   exact space the vectors live in (see [`crate::search::model_api::identity`]);
//! * the **provenance record** under `api_generation_provenance:v1:<id>` — who
//!   contributed to that space and how each was called.
//!
//! This module owns the third record and the two helpers that write and read all
//! three inside a caller's transaction. It deliberately owns no transaction of
//! its own: [`create_api_generation`] writes into the caller's [`Tx`], so a
//! failure at any point rolls the whole generation back rather than leaving a
//! half-registered space behind.
//!
//! ## What this module does not do
//!
//! It never activates a generation, never touches `is_active` or `audit_status`,
//! never edits or removes an older generation, and never accepts a caller's word
//! that a record is compatible. The endpoint digest it stores is recomputed from
//! the profile it is handed; the digest is never taken from the caller. There is
//! no public flag a caller can set to declare a record trustworthy.
//!
//! The plain opener remains primary-only. The proof-aware opener verifies each
//! recorded contributor and its original capture against a fully checked bundle.
//! Registering a writer only appends evidence in the caller's transaction.
//! Unknown future headers remain opaque and cannot be rewritten; their JSON
//! may contain numbers such as `1e400` without becoming a corrupt record.
//!
//! ## Why the rejection codes are closed
//!
//! Every rejection here carries a short, closed code and, at most, the
//! compile-time name of a field. No rejection carries a model body, a prefix, a
//! credential, a stored record's bytes or a backend error message, so a
//! `Display` of one is safe to log. The one exception is stated below: a store
//! failure is carried as the typed [`StorageError`] because a transaction-owning
//! caller needs to keep matching `Busy`/`Locked` for its own replay logic, and
//! that value is never rendered by this type's `Display` or `Debug`.

use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use super::api::{StorageError, Tx, params};
use super::schema;
use crate::search::model_api::{
    ApiProtocol, ConfigError, ConfigErrorCode, EndpointConfigIdentity, IdentityError,
    IdentityErrorCode, Normalization, REPRESENTATION_RECORD_VERSION, RepresentationDescriptor,
    RepresentationRecord, ValidatedProfile,
};

/// The meta-key stem of a generation provenance record. The full key is this
/// stem, the record version and the generation number.
const PROVENANCE_KEY_STEM: &str = "api_generation_provenance";

/// The meta-key stem of the representation record this module reads back. It is
/// the same stem [`RepresentationRecord::meta_key`] builds.
const REPRESENTATION_KEY_STEM: &str = "api_representation";

/// The only provenance version this build writes and reads.
pub const API_GENERATION_PROVENANCE_VERSION: i64 = 1;

/// The marker a structurally rejected provenance record carries through the
/// `serde_json` error channel. Kept distinct from [`CONTRIBUTOR_MARKER`] only so
/// a nested contributor failure is still attributed to the contributor.
const PROVENANCE_STRUCTURAL_MARKER: &str = "cass.api-generation.provenance";

/// The marker a structurally rejected contributor carries.
const CONTRIBUTOR_STRUCTURAL_MARKER: &str = "cass.api-generation.contributor";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// The closed set of reasons an API generation record is refused.
///
/// Callers branch on the code, never on a message, and the code never changes
/// meaning. The first six mirror the representation-identity codes so one
/// rejection vocabulary covers the whole family; the last three are new here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiGenerationErrorCode {
    /// A profile or protocol that is not an embedding one was offered.
    WrongKind,
    /// A representation descriptor was malformed, or violated its own rules.
    InvalidDescriptor,
    /// A record was self-contradictory, or disagreed with the row it names.
    InvalidRecord,
    /// A provenance record was malformed, or violated its own rules.
    InvalidProvenance,
    /// A record carries a version this build does not write.
    UnsupportedVersion,
    /// The stored space differs from the one the running profile describes.
    IdentityMismatch,
    /// The record needs successor-side cross-endpoint proof before it may be
    /// used.
    CompatibilityRequired,
    /// The record names more contributors than this build can admit.
    UnsupportedContributors,
    /// The store refused the operation.
    Storage,
}

impl ApiGenerationErrorCode {
    /// The stable wire name of this code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongKind => "WrongKind",
            Self::InvalidDescriptor => "InvalidDescriptor",
            Self::InvalidRecord => "InvalidRecord",
            Self::InvalidProvenance => "InvalidProvenance",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::IdentityMismatch => "IdentityMismatch",
            Self::CompatibilityRequired => "CompatibilityRequired",
            Self::UnsupportedContributors => "UnsupportedContributors",
            Self::Storage => "Storage",
        }
    }
}

impl fmt::Display for ApiGenerationErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused API generation record, or a store failure on the way to one.
///
/// `Rejected` is the closed, content-free half described in the module comment.
/// `Storage` carries the typed store failure so a caller that owns the
/// surrounding transaction can still match `Busy`/`Locked`; neither half is
/// printed with its payload by [`fmt::Debug`] or [`fmt::Display`].
#[derive(Clone)]
pub enum ApiGenerationError {
    /// A record or input was refused for a closed reason.
    Rejected {
        /// The closed reason.
        code: ApiGenerationErrorCode,
        /// The schema field this rejection is attributed to, when known.
        field: Option<&'static str>,
    },
    /// The store refused the operation.
    Storage(StorageError),
}

impl ApiGenerationError {
    /// A rejection attributed to one field.
    ///
    /// `field` must be a compile-time constant from this schema, never text
    /// taken from a stored record.
    const fn at(code: ApiGenerationErrorCode, field: &'static str) -> Self {
        Self::Rejected {
            code,
            field: Some(field),
        }
    }

    /// A rejection that names no particular field.
    const fn plain(code: ApiGenerationErrorCode) -> Self {
        Self::Rejected { code, field: None }
    }

    /// The stable reason code, whether this is a rejection or a store failure.
    pub const fn code(&self) -> ApiGenerationErrorCode {
        match self {
            Self::Rejected { code, .. } => *code,
            Self::Storage(_) => ApiGenerationErrorCode::Storage,
        }
    }

    /// The field this rejection is attributed to, when known.
    pub const fn field(&self) -> Option<&'static str> {
        match self {
            Self::Rejected { field, .. } => *field,
            Self::Storage(_) => None,
        }
    }

    /// The underlying store failure, when this is one.
    ///
    /// This exists so the caller that owns the transaction can keep its own
    /// `Busy`/`Locked` handling. It is not printed by this type.
    pub const fn storage_error(&self) -> Option<&StorageError> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Rejected { .. } => None,
        }
    }

    /// Map a representation-identity rejection onto this vocabulary.
    ///
    /// This is the shape used when a *caller-supplied profile* is turned into an
    /// identity: a disagreement is a live configuration drift, so
    /// `IdentityMismatch` stays one.
    fn from_profile_identity(error: IdentityError) -> Self {
        let code = match error.code() {
            IdentityErrorCode::WrongKind => ApiGenerationErrorCode::WrongKind,
            IdentityErrorCode::InvalidDescriptor => ApiGenerationErrorCode::InvalidDescriptor,
            IdentityErrorCode::InvalidRecord => ApiGenerationErrorCode::InvalidRecord,
            IdentityErrorCode::UnsupportedVersion => ApiGenerationErrorCode::UnsupportedVersion,
            IdentityErrorCode::IdentityMismatch => ApiGenerationErrorCode::IdentityMismatch,
        };
        Self::Rejected {
            code,
            field: error.field(),
        }
    }

    /// Map a rejection of *stored bytes* onto this vocabulary.
    ///
    /// Every check the codec runs is a self-consistency check of the record it
    /// is decoding: a digest that does not match its own descriptor, or a
    /// `request_dimensions` that contradicts the width it was stored beside, is
    /// the store contradicting itself. Those are `InvalidRecord` here, so the
    /// only thing `IdentityMismatch` means at this layer is "the running profile
    /// describes a different space" — it is never raised while reading storage.
    fn from_stored_identity(error: IdentityError) -> Self {
        let code = match error.code() {
            IdentityErrorCode::WrongKind => ApiGenerationErrorCode::WrongKind,
            IdentityErrorCode::InvalidDescriptor => ApiGenerationErrorCode::InvalidDescriptor,
            IdentityErrorCode::InvalidRecord => ApiGenerationErrorCode::InvalidRecord,
            IdentityErrorCode::UnsupportedVersion => ApiGenerationErrorCode::UnsupportedVersion,
            IdentityErrorCode::IdentityMismatch => ApiGenerationErrorCode::InvalidRecord,
        };
        Self::Rejected {
            code,
            field: error.field(),
        }
    }

    /// Map a call-configuration rejection onto this vocabulary.
    ///
    /// Only `KindMismatch` is reachable from
    /// [`EndpointConfigIdentity::from_profile`] for a profile that already built
    /// a descriptor; it means the profile is not an embedding call configuration.
    fn from_config(error: ConfigError) -> Self {
        let code = match error.code() {
            ConfigErrorCode::KindMismatch => ApiGenerationErrorCode::WrongKind,
            _ => ApiGenerationErrorCode::InvalidDescriptor,
        };
        Self::Rejected {
            code,
            field: error.field(),
        }
    }
}

impl fmt::Debug for ApiGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected { code, field } => {
                write!(f, "ApiGenerationError::Rejected({code:?}, {field:?})")
            }
            Self::Storage(_) => f.write_str("ApiGenerationError::Storage(..)"),
        }
    }
}

impl fmt::Display for ApiGenerationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected {
                code,
                field: Some(field),
            } => write!(f, "invalid api generation record: {} ({field})", code.as_str()),
            Self::Rejected { code, field: None } => {
                write!(f, "invalid api generation record: {}", code.as_str())
            }
            Self::Storage(_) => f.write_str("api generation storage failure"),
        }
    }
}

impl std::error::Error for ApiGenerationError {}

impl From<ApiGenerationError> for StorageError {
    /// Collapse a rejection into a store error for a caller whose transaction
    /// closure must return [`StorageError`]. A real store failure is passed
    /// through unchanged so `Busy`/`Locked`/replay semantics survive; a
    /// rejection becomes a fixed-detail `Other`, which carries none of the
    /// rejected bytes.
    fn from(error: ApiGenerationError) -> Self {
        match error {
            ApiGenerationError::Storage(storage) => storage,
            ApiGenerationError::Rejected { code, .. } => StorageError::Other {
                code: None,
                detail: format!("api generation record rejected: {}", code.as_str()),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Provenance record
// ---------------------------------------------------------------------------

/// One producer of vectors in the generation's canonical representation space.
/// The original primary has null compatibility fields. Other entries preserve
/// the complete evidence JSON in a versioned lossless envelope. Unknown future
/// envelopes are retained as raw JSON and refused without rewriting them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiGenerationContributor {
    compatibility_evidence_header: Option<HeaderPresent>,
    compatibility_evidence_sha256: Option<String>,
    document_prefix: String,
    endpoint_config_sha256: String,
    model: String,
    model_revision: String,
    normalization: Normalization,
    protocol: ApiProtocol,
    provider_only: Option<String>,
    query_prefix: String,
}

impl ApiGenerationContributor {
    /// Build the pure-primary contributor from the verified descriptor and the
    /// call configuration of the profile that produced it.
    fn primary(
        descriptor: &RepresentationDescriptor,
        profile: &ValidatedProfile,
        endpoint: &EndpointConfigIdentity,
    ) -> Result<Self, ApiGenerationError> {
        let embedding = profile
            .embedding()
            .ok_or_else(|| ApiGenerationError::at(ApiGenerationErrorCode::WrongKind, "kind"))?;
        Ok(Self {
            compatibility_evidence_header: None,
            compatibility_evidence_sha256: None,
            document_prefix: descriptor.document_prefix().to_string(),
            endpoint_config_sha256: endpoint.sha256(),
            model: descriptor.model().to_string(),
            model_revision: descriptor.model_revision().to_string(),
            normalization: descriptor.normalization(),
            protocol: descriptor.protocol(),
            provider_only: embedding.provider_only.clone(),
            query_prefix: descriptor.query_prefix().to_string(),
        })
    }

    /// Whether this contributor carries a cross-endpoint compatibility-evidence
    /// header. Presence alone never grants admission.
    ///
    /// A read-only predicate; callers must use the proof-aware opener before
    /// using a generation that carries compatibility evidence.
    pub const fn has_compatibility_evidence_header(&self) -> bool {
        self.compatibility_evidence_header.is_some()
    }

    /// The cross-endpoint compatibility-evidence digest, when this contributor
    /// carries one; the original primary has no such digest.
    pub fn compatibility_evidence_sha256(&self) -> Option<&str> {
        self.compatibility_evidence_sha256.as_deref()
    }

    /// The bytes prepended to every document before embedding.
    pub fn document_prefix(&self) -> &str {
        &self.document_prefix
    }

    /// The call-configuration digest of the endpoint that served this
    /// contributor.
    pub fn endpoint_config_sha256(&self) -> &str {
        &self.endpoint_config_sha256
    }

    /// The model identity this contributor was called with.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The deployment contract revision this contributor was called with.
    pub fn model_revision(&self) -> &str {
        &self.model_revision
    }

    /// The normalization convention this contributor follows.
    pub const fn normalization(&self) -> Normalization {
        self.normalization
    }

    /// The wire protocol this contributor speaks.
    pub const fn protocol(&self) -> ApiProtocol {
        self.protocol
    }

    /// The pinned cloud provider, when this contributor sets one.
    pub fn provider_only(&self) -> Option<&str> {
        self.provider_only.as_deref()
    }

    /// The bytes prepended to every query before embedding.
    pub fn query_prefix(&self) -> &str {
        &self.query_prefix
    }

    fn wire(&self) -> ContributorWire<'_> {
        ContributorWire {
            // Known envelopes preserve exact evidence bytes; unknown formats
            // are refused by canonical_bytes before reaching this serializer.
            compatibility_evidence_header: self.compatibility_evidence_header.as_ref().map(|h|h.0.as_ref()),
            compatibility_evidence_sha256: self.compatibility_evidence_sha256.as_deref(),
            document_prefix: &self.document_prefix,
            endpoint_config_sha256: &self.endpoint_config_sha256,
            model: &self.model,
            model_revision: &self.model_revision,
            normalization: self.normalization.as_str(),
            protocol: self.protocol.as_str(),
            provider_only: self.provider_only.as_deref(),
            query_prefix: &self.query_prefix,
        }
    }
}

/// The contributor list of one generation's representation space.
///
/// The four fields are exactly `contributors`, `descriptor_sha256`,
/// `generation_id` and `version`. The descriptor digest always names the
/// generation's own [`RepresentationRecord`], so the two meta records can be
/// cross-checked against each other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiGenerationProvenance {
    contributors: Vec<ApiGenerationContributor>,
    descriptor_sha256: String,
    generation_id: i64,
    version: i64,
}

impl ApiGenerationProvenance {
    /// Build the version-1 provenance of a freshly created generation.
    fn for_primary(
        contributor: ApiGenerationContributor,
        generation_id: i64,
        descriptor_sha256: String,
    ) -> Result<Self, ApiGenerationError> {
        if generation_id < 1 {
            return Err(ApiGenerationError::at(
                ApiGenerationErrorCode::InvalidRecord,
                "generation_id",
            ));
        }
        if !is_lowercase_sha256(&descriptor_sha256) {
            return Err(ApiGenerationError::at(
                ApiGenerationErrorCode::InvalidRecord,
                "descriptor_sha256",
            ));
        }
        Ok(Self {
            contributors: vec![contributor],
            descriptor_sha256,
            generation_id,
            version: API_GENERATION_PROVENANCE_VERSION,
        })
    }

    /// The contributors recorded for this generation.
    pub fn contributors(&self) -> &[ApiGenerationContributor] {
        &self.contributors
    }

    /// The digest of the representation descriptor this provenance names.
    pub fn descriptor_sha256(&self) -> &str {
        &self.descriptor_sha256
    }

    /// The generation this record belongs to.
    pub const fn generation_id(&self) -> i64 {
        self.generation_id
    }

    /// The record schema version.
    pub const fn version(&self) -> i64 {
        self.version
    }

    /// The meta-table key that names this record.
    ///
    /// The generation number is written as a canonical decimal integer, so the
    /// key has no leading zero and no other spelling.
    pub fn meta_key(&self) -> String {
        format!(
            "{PROVENANCE_KEY_STEM}:v{}:{}",
            self.version, self.generation_id
        )
    }

    /// The canonical bytes: one compact JSON object, ASCII-ordered, no newline.
    ///
    /// Unknown evidence formats are refused. A known envelope preserves the
    /// exact original proof JSON and checks its SHA before serialization.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ApiGenerationError> {
        for contributor in &self.contributors {
            if let Some(header)=&contributor.compatibility_evidence_header {
                header.known(contributor.compatibility_evidence_sha256.as_deref())?;
            }
        }
        serde_json::to_vec(&self.wire()).map_err(|_| {
            ApiGenerationError::at(ApiGenerationErrorCode::InvalidRecord, "canonical_bytes")
        })
    }

    /// The lowercase SHA-256 of [`Self::canonical_bytes`].
    pub fn sha256(&self) -> Result<String, ApiGenerationError> {
        Ok(hex::encode(Sha256::digest(self.canonical_bytes()?)))
    }

    /// Parse one provenance record from its canonical bytes.
    ///
    /// Rejects duplicate keys (including keys that only collide after
    /// unescaping), unknown keys, missing keys, a mistyped or out-of-range
    /// number, a future version, a non-positive generation number, a malformed
    /// digest, a contributor with the wrong number of fields, a non-null
    /// compatibility digest that is not a digest, an unknown protocol or
    /// normalization, and trailing data. Trailing whitespace is accepted, as
    /// JSON allows it.
    pub fn decode(bytes: &[u8]) -> Result<Self, ApiGenerationError> {
        // Both structural markers arrive here as a `serde_json` message that
        // *is* the marker, never as text quoted from the rejected document, so
        // collapsing them into one closed code leaks nothing.
        let raw: RawProvenance = serde_json::from_slice(bytes)
            .map_err(|_| ApiGenerationError::plain(ApiGenerationErrorCode::InvalidProvenance))?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawProvenance) -> Result<Self, ApiGenerationError> {
        if raw.version != API_GENERATION_PROVENANCE_VERSION {
            return Err(ApiGenerationError::at(
                ApiGenerationErrorCode::UnsupportedVersion,
                "version",
            ));
        }
        if raw.generation_id < 1 {
            return Err(ApiGenerationError::at(
                ApiGenerationErrorCode::InvalidProvenance,
                "generation_id",
            ));
        }
        if !is_lowercase_sha256(&raw.descriptor_sha256) {
            return Err(ApiGenerationError::at(
                ApiGenerationErrorCode::InvalidProvenance,
                "descriptor_sha256",
            ));
        }
        let contributors = raw
            .contributors
            .into_iter()
            .map(ApiGenerationContributor::from_raw)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            contributors,
            descriptor_sha256: raw.descriptor_sha256,
            generation_id: raw.generation_id,
            version: raw.version,
        })
    }

    /// The single pure-primary contributor, or the closed reason this record is
    /// not one.
    ///
    /// An empty contributor list is a malformed record; more than one
    /// contributor is a shape this build cannot admit; a single contributor
    /// that carries any compatibility evidence needs successor-side admission.
    /// None of these is a claim that the record is corrupt, and none of them
    /// rewrites the stored bytes.
    pub fn single_primary_contributor(
        &self,
    ) -> Result<&ApiGenerationContributor, ApiGenerationError> {
        match self.contributors.len() {
            0 => Err(ApiGenerationError::at(
                ApiGenerationErrorCode::InvalidProvenance,
                "contributors",
            )),
            1 => {
                let contributor = &self.contributors[0];
                if contributor.compatibility_evidence_header.is_some() {
                    return Err(ApiGenerationError::at(
                        ApiGenerationErrorCode::CompatibilityRequired,
                        "compatibility_evidence_header",
                    ));
                }
                if contributor.compatibility_evidence_sha256.is_some() {
                    return Err(ApiGenerationError::at(
                        ApiGenerationErrorCode::CompatibilityRequired,
                        "compatibility_evidence_sha256",
                    ));
                }
                Ok(contributor)
            }
            _ => Err(ApiGenerationError::at(
                ApiGenerationErrorCode::UnsupportedContributors,
                "contributors",
            )),
        }
    }

    fn wire(&self) -> ProvenanceWire<'_> {
        ProvenanceWire {
            contributors: self
                .contributors
                .iter()
                .map(ApiGenerationContributor::wire)
                .collect(),
            descriptor_sha256: &self.descriptor_sha256,
            generation_id: self.generation_id,
            version: self.version,
        }
    }
}

impl ApiGenerationContributor {
    fn from_raw(raw: RawContributor) -> Result<Self, ApiGenerationError> {
        if !is_lowercase_sha256(&raw.endpoint_config_sha256) {
            return Err(ApiGenerationError::at(
                ApiGenerationErrorCode::InvalidProvenance,
                "endpoint_config_sha256",
            ));
        }
        if let Some(digest) = raw.compatibility_evidence_sha256.as_deref()
            && !is_lowercase_sha256(digest)
        {
            return Err(ApiGenerationError::at(
                ApiGenerationErrorCode::InvalidProvenance,
                "compatibility_evidence_sha256",
            ));
        }
        Ok(Self {
            compatibility_evidence_header: raw.compatibility_evidence_header,
            compatibility_evidence_sha256: raw.compatibility_evidence_sha256,
            document_prefix: raw.document_prefix,
            endpoint_config_sha256: raw.endpoint_config_sha256,
            model: raw.model,
            model_revision: raw.model_revision,
            normalization: parse_normalization(&raw.normalization)?,
            protocol: parse_embedding_protocol(&raw.protocol)?,
            provider_only: raw.provider_only,
            query_prefix: raw.query_prefix,
        })
    }
}

/// The contributor exactly as it is written, in canonical key order.
///
/// Null for the original primary; known lossless proof envelopes otherwise.
#[derive(Serialize)]
struct ContributorWire<'a> {
    compatibility_evidence_header: Option<&'a serde_json::value::RawValue>,
    compatibility_evidence_sha256: Option<&'a str>,
    document_prefix: &'a str,
    endpoint_config_sha256: &'a str,
    model: &'a str,
    model_revision: &'a str,
    normalization: &'a str,
    protocol: &'a str,
    provider_only: Option<&'a str>,
    query_prefix: &'a str,
}

/// The provenance record exactly as it is written, in canonical key order.
#[derive(Serialize)]
struct ProvenanceWire<'a> {
    contributors: Vec<ContributorWire<'a>>,
    descriptor_sha256: &'a str,
    generation_id: i64,
    version: i64,
}

/// Raw JSON preserves unknown future headers without interpreting large numbers.
/// Known headers carry the exact evidence-file text so its original SHA remains
/// checkable after storage, including formatting and trailing whitespace.
#[derive(Clone)]
struct HeaderPresent(Box<serde_json::value::RawValue>);
impl fmt::Debug for HeaderPresent {
    fn fmt(&self, f:&mut fmt::Formatter<'_>)->fmt::Result { f.write_str("CompatibilityHeader(<redacted>)") }
}
impl PartialEq for HeaderPresent { fn eq(&self, other:&Self)->bool { self.0.get()==other.0.get() } }
impl Eq for HeaderPresent {}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct CompatibilityHeader {
    schema: String,
    evidence_json: String,
}
impl HeaderPresent {
    fn from_checked(proof:&crate::search::model_api::compatibility_bundle::CheckedBundle)->Result<Self,ApiGenerationError> {
        let bytes=serde_json::to_string(&CompatibilityHeader{schema:"cass.api-compatibility-header.v1".into(),evidence_json:proof.original_json().into()})
            .map_err(|_|ApiGenerationError::plain(ApiGenerationErrorCode::InvalidProvenance))?;
        serde_json::value::RawValue::from_string(bytes).map(Self)
            .map_err(|_|ApiGenerationError::plain(ApiGenerationErrorCode::InvalidProvenance))
    }
    fn known(&self, digest:Option<&str>)->Result<crate::search::model_api::compatibility_bundle::Bundle,ApiGenerationError> {
        let refused=||ApiGenerationError::plain(ApiGenerationErrorCode::CompatibilityRequired);
        let envelope:CompatibilityHeader=serde_json::from_str(self.0.get()).map_err(|_|refused())?;
        if envelope.schema!="cass.api-compatibility-header.v1" || envelope.evidence_json.len()>16*1024*1024
            || digest!=Some(hex::encode(Sha256::digest(envelope.evidence_json.as_bytes())).as_str()) { return Err(refused()); }
        let header:crate::search::model_api::compatibility_bundle::Bundle=serde_json::from_str(&envelope.evidence_json).map_err(|_|refused())?;
        if header.version!=1 || header.verifier!=crate::search::model_api::compatibility_bundle::VERIFIER_VERSION || header.conclusion!="compatible" {return Err(refused());}
        Ok(header)
    }
}
impl<'de> Deserialize<'de> for HeaderPresent {
    fn deserialize<D:Deserializer<'de>>(deserializer:D)->Result<Self,D::Error> {
        Box::<serde_json::value::RawValue>::deserialize(deserializer).map(Self)
    }
}

/// A contributor's keys before any rule beyond structure is applied.
///
/// The two compatibility fields are tracked as `Option<Option<_>>` so "absent"
/// and "present and null" stay different facts. The header's inner type is
/// [`HeaderPresent`] on purpose: a legal JSON header may contain a number no
/// `f64` can hold, and only its *presence* is this version's business.
struct RawContributor {
    compatibility_evidence_header: Option<HeaderPresent>,
    compatibility_evidence_sha256: Option<String>,
    document_prefix: String,
    endpoint_config_sha256: String,
    model: String,
    model_revision: String,
    normalization: String,
    protocol: String,
    provider_only: Option<String>,
    query_prefix: String,
}

/// A provenance record's keys before any rule beyond structure is applied.
struct RawProvenance {
    contributors: Vec<RawContributor>,
    descriptor_sha256: String,
    generation_id: i64,
    version: i64,
}

/// A structural rejection at the provenance layer.
fn provenance_structural<E: de::Error>() -> E {
    E::custom(PROVENANCE_STRUCTURAL_MARKER)
}

/// A structural rejection at the contributor layer.
fn contributor_structural<E: de::Error>() -> E {
    E::custom(CONTRIBUTOR_STRUCTURAL_MARKER)
}

impl<'de> Deserialize<'de> for RawContributor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawContributorVisitor;

        impl<'de> Visitor<'de> for RawContributorVisitor {
            type Value = RawContributor;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an api generation contributor object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut compatibility_evidence_header: Option<Option<HeaderPresent>> = None;
                let mut compatibility_evidence_sha256: Option<Option<String>> = None;
                let mut document_prefix: Option<String> = None;
                let mut endpoint_config_sha256: Option<String> = None;
                let mut model: Option<String> = None;
                let mut model_revision: Option<String> = None;
                let mut normalization: Option<String> = None;
                let mut protocol: Option<String> = None;
                let mut provider_only: Option<Option<String>> = None;
                let mut query_prefix: Option<String> = None;

                while let Some(key) = map
                    .next_key::<String>()
                    .map_err(|_| contributor_structural::<A::Error>())?
                {
                    match key.as_str() {
                        "compatibility_evidence_header" => {
                            if compatibility_evidence_header.is_some() {
                                return Err(contributor_structural());
                            }
                            // Any legal JSON value is a well-formed header. Its
                            // interior is opaque to this version -- including
                            // its numbers, which may not fit an `f64` -- so the
                            // value is skipped at the lexer level and only its
                            // presence is kept.
                            compatibility_evidence_header = Some(
                                map.next_value::<Option<HeaderPresent>>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "compatibility_evidence_sha256" => {
                            if compatibility_evidence_sha256.is_some() {
                                return Err(contributor_structural());
                            }
                            compatibility_evidence_sha256 = Some(
                                map.next_value::<Option<String>>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "document_prefix" => {
                            if document_prefix.is_some() {
                                return Err(contributor_structural());
                            }
                            document_prefix = Some(
                                map.next_value::<String>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "endpoint_config_sha256" => {
                            if endpoint_config_sha256.is_some() {
                                return Err(contributor_structural());
                            }
                            endpoint_config_sha256 = Some(
                                map.next_value::<String>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "model" => {
                            if model.is_some() {
                                return Err(contributor_structural());
                            }
                            model = Some(
                                map.next_value::<String>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "model_revision" => {
                            if model_revision.is_some() {
                                return Err(contributor_structural());
                            }
                            model_revision = Some(
                                map.next_value::<String>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "normalization" => {
                            if normalization.is_some() {
                                return Err(contributor_structural());
                            }
                            normalization = Some(
                                map.next_value::<String>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "protocol" => {
                            if protocol.is_some() {
                                return Err(contributor_structural());
                            }
                            protocol = Some(
                                map.next_value::<String>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "provider_only" => {
                            if provider_only.is_some() {
                                return Err(contributor_structural());
                            }
                            provider_only = Some(
                                map.next_value::<Option<String>>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        "query_prefix" => {
                            if query_prefix.is_some() {
                                return Err(contributor_structural());
                            }
                            query_prefix = Some(
                                map.next_value::<String>()
                                    .map_err(|_| contributor_structural::<A::Error>())?,
                            );
                        }
                        _ => return Err(contributor_structural()),
                    }
                }

                Ok(RawContributor {
                    compatibility_evidence_header: compatibility_evidence_header
                        .ok_or_else(contributor_structural::<A::Error>)?,
                    compatibility_evidence_sha256: compatibility_evidence_sha256
                        .ok_or_else(contributor_structural::<A::Error>)?,
                    document_prefix: document_prefix
                        .ok_or_else(contributor_structural::<A::Error>)?,
                    endpoint_config_sha256: endpoint_config_sha256
                        .ok_or_else(contributor_structural::<A::Error>)?,
                    model: model.ok_or_else(contributor_structural::<A::Error>)?,
                    model_revision: model_revision.ok_or_else(contributor_structural::<A::Error>)?,
                    normalization: normalization.ok_or_else(contributor_structural::<A::Error>)?,
                    protocol: protocol.ok_or_else(contributor_structural::<A::Error>)?,
                    provider_only: provider_only.ok_or_else(contributor_structural::<A::Error>)?,
                    query_prefix: query_prefix.ok_or_else(contributor_structural::<A::Error>)?,
                })
            }
        }

        deserializer.deserialize_map(RawContributorVisitor)
    }
}

impl<'de> Deserialize<'de> for RawProvenance {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawProvenanceVisitor;

        impl<'de> Visitor<'de> for RawProvenanceVisitor {
            type Value = RawProvenance;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an api generation provenance object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut contributors: Option<Vec<RawContributor>> = None;
                let mut descriptor_sha256: Option<String> = None;
                let mut generation_id: Option<i64> = None;
                let mut version: Option<i64> = None;

                while let Some(key) = map
                    .next_key::<String>()
                    .map_err(|_| provenance_structural::<A::Error>())?
                {
                    match key.as_str() {
                        "contributors" => {
                            if contributors.is_some() {
                                return Err(provenance_structural());
                            }
                            // A failure inside a contributor keeps the
                            // contributor's own marker, so the caller can
                            // attribute it correctly.
                            contributors = Some(map.next_value::<Vec<RawContributor>>()?);
                        }
                        "descriptor_sha256" => {
                            if descriptor_sha256.is_some() {
                                return Err(provenance_structural());
                            }
                            descriptor_sha256 = Some(
                                map.next_value::<String>()
                                    .map_err(|_| provenance_structural::<A::Error>())?,
                            );
                        }
                        "generation_id" => {
                            if generation_id.is_some() {
                                return Err(provenance_structural());
                            }
                            generation_id = Some(
                                map.next_value::<i64>()
                                    .map_err(|_| provenance_structural::<A::Error>())?,
                            );
                        }
                        "version" => {
                            if version.is_some() {
                                return Err(provenance_structural());
                            }
                            version = Some(
                                map.next_value::<i64>()
                                    .map_err(|_| provenance_structural::<A::Error>())?,
                            );
                        }
                        _ => return Err(provenance_structural()),
                    }
                }

                Ok(RawProvenance {
                    contributors: contributors.ok_or_else(provenance_structural::<A::Error>)?,
                    descriptor_sha256: descriptor_sha256
                        .ok_or_else(provenance_structural::<A::Error>)?,
                    generation_id: generation_id.ok_or_else(provenance_structural::<A::Error>)?,
                    version: version.ok_or_else(provenance_structural::<A::Error>)?,
                })
            }
        }

        deserializer.deserialize_map(RawProvenanceVisitor)
    }
}

/// Map a stored normalization string back to its variant.
fn parse_normalization(raw: &str) -> Result<Normalization, ApiGenerationError> {
    const NORMALIZATIONS: [Normalization; 2] = [Normalization::L2, Normalization::None];
    NORMALIZATIONS
        .iter()
        .find(|candidate| candidate.as_str() == raw)
        .copied()
        .ok_or_else(|| {
            ApiGenerationError::at(ApiGenerationErrorCode::InvalidProvenance, "normalization")
        })
}

/// Map a stored protocol string back to its embedding variant.
///
/// A contributor to an embedding space speaks an embedding protocol; a rerank
/// protocol here is a wrong kind rather than an unknown name.
fn parse_embedding_protocol(raw: &str) -> Result<ApiProtocol, ApiGenerationError> {
    const EMBEDDING: [ApiProtocol; 2] = [
        ApiProtocol::OpenAiEmbeddingsV1,
        ApiProtocol::OpenRouterEmbeddingsV1,
    ];
    const RERANK: [ApiProtocol; 2] = [ApiProtocol::RerankJsonV1, ApiProtocol::OpenRouterRerankV1];

    if let Some(found) = EMBEDDING.iter().find(|candidate| candidate.as_str() == raw) {
        return Ok(*found);
    }
    if RERANK.iter().any(|candidate| candidate.as_str() == raw) {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::WrongKind,
            "protocol",
        ));
    }
    Err(ApiGenerationError::at(
        ApiGenerationErrorCode::InvalidProvenance,
        "protocol",
    ))
}

/// Whether `value` is exactly 64 lowercase hexadecimal digits.
///
/// Uppercase is rejected rather than folded, so one digest has exactly one
/// spelling and a stored record cannot disagree with its own bytes.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// ---------------------------------------------------------------------------
// The generation row, as this module reads it
// ---------------------------------------------------------------------------

/// The `embedding_generations` columns this module re-checks a record against.
struct GenerationRow {
    embedder_id: String,
    dim: i64,
    canonicalize_version: i64,
    chunking_version: i64,
}

impl GenerationRow {
    fn read(tx: &Tx, generation_id: i64) -> Result<Option<Self>, ApiGenerationError> {
        tx.query_opt_map(
            "SELECT embedder_id, dim, canonicalize_version, chunking_policy_version \
             FROM embedding_generations WHERE id = ?1",
            &params![generation_id],
            |row| {
                Ok(Self {
                    embedder_id: row.get_typed::<String>(0)?,
                    dim: row.get_typed::<i64>(1)?,
                    canonicalize_version: row.get_typed::<i64>(2)?,
                    chunking_version: row.get_typed::<i64>(3)?,
                })
            },
        )
        .map_err(ApiGenerationError::Storage)
    }
}

/// Read one meta value by key, or `None` when the key is absent.
fn read_meta(tx: &Tx, key: &str) -> Result<Option<String>, ApiGenerationError> {
    tx.query_opt_map(
        "SELECT value FROM meta WHERE key = ?1",
        &params![key],
        |row| row.get_typed::<String>(0),
    )
    .map_err(ApiGenerationError::Storage)
}

/// Write one meta value under `key`, inside the caller's transaction.
fn write_meta(tx: &Tx, key: &str, value: &str) -> Result<(), ApiGenerationError> {
    tx.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2)",
        &params![key, value],
    )
    .map_err(ApiGenerationError::Storage)?;
    Ok(())
}

/// The canonical bytes of a record as the UTF-8 text the `meta` column holds.
///
/// `serde_json` always emits valid UTF-8, so the failure branch is unreachable;
/// it exists so the encoding path holds no `unwrap`.
fn canonical_text(bytes: Vec<u8>) -> Result<String, ApiGenerationError> {
    String::from_utf8(bytes).map_err(|_| {
        ApiGenerationError::at(ApiGenerationErrorCode::InvalidRecord, "canonical_bytes")
    })
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

/// Create one API-only embedding generation and its two meta records inside the
/// caller's transaction, returning the new generation id.
///
/// The generation row is created first (through the existing
/// [`schema::create_embedding_generation`], which also refuses an empty
/// fingerprint), then the representation record, then the provenance record.
/// All three share `tx`, so no path here can commit a generation without its
/// records: if any step fails — including a failure the caller hits later in the
/// same transaction — the whole generation rolls back.
///
/// The descriptor and the endpoint digest are computed from `profile` and
/// `observed_dimension`; neither is taken from the caller. `profile` may declare
/// a fallback, but this helper never reads it and never registers the fallback
/// as a contributor.
pub fn create_api_generation(
    tx: &Tx,
    profile: &ValidatedProfile,
    observed_dimension: u64,
    fingerprint: &[u8],
    created_at_ms: i64,
) -> Result<i64, ApiGenerationError> {
    let descriptor = RepresentationDescriptor::from_profile(profile, observed_dimension)
        .map_err(ApiGenerationError::from_profile_identity)?;
    let endpoint = EndpointConfigIdentity::from_profile(profile)
        .map_err(ApiGenerationError::from_config)?;
    let contributor = ApiGenerationContributor::primary(&descriptor, profile, &endpoint)?;

    let dim = i64::try_from(observed_dimension).map_err(|_| {
        ApiGenerationError::at(ApiGenerationErrorCode::InvalidDescriptor, "effective_dimension")
    })?;
    let generation_id = schema::create_embedding_generation(
        tx,
        &descriptor.embedder_id(),
        dim,
        descriptor.canonicalize_version(),
        descriptor.chunking_version(),
        fingerprint,
        created_at_ms,
    )
    .map_err(ApiGenerationError::Storage)?;

    let record = RepresentationRecord::new(descriptor, generation_id)
        .map_err(ApiGenerationError::from_profile_identity)?;
    let representation_text = canonical_text(record.canonical_bytes())?;
    write_meta(tx, &record.meta_key(), &representation_text)?;

    let provenance = ApiGenerationProvenance::for_primary(
        contributor,
        generation_id,
        record.descriptor_sha256().to_string(),
    )?;
    let provenance_text = canonical_text(provenance.canonical_bytes()?)?;
    write_meta(tx, &provenance.meta_key(), &provenance_text)?;

    Ok(generation_id)
}

/// Establish a new canonical space with the backends that actually produced
/// its probe. Both metadata records remain in the caller's creation transaction.
pub(crate) fn create_api_generation_with_producers(
    tx: &Tx, primary: &ValidatedProfile, dimension: u64, fingerprint: &[u8], now: i64,
    producers: &[ValidatedProfile], proof: &crate::search::model_api::compatibility_bundle::CheckedBundle,
) -> Result<i64, ApiGenerationError> {
    if producers.is_empty() { return Err(compatibility_required()); }
    let id = create_api_generation(tx, primary, dimension, fingerprint, now)?;
    let mut verified = open_api_generation(tx, id, primary)?;
    let mut contributors = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for writer in producers {
        let endpoint = EndpointConfigIdentity::from_profile(writer).map_err(ApiGenerationError::from_config)?;
        if !seen.insert(endpoint.sha256()) { continue; }
        if proof.selected_capture(&endpoint.sha256()).is_none() { return Err(compatibility_required()); }
        let descriptor = RepresentationDescriptor::from_profile(writer, dimension).map_err(ApiGenerationError::from_profile_identity)?;
        let mut contributor = ApiGenerationContributor::primary(&descriptor, writer, &endpoint)?;
        contributor.compatibility_evidence_header = Some(HeaderPresent::from_checked(proof)?);
        contributor.compatibility_evidence_sha256 = Some(proof.digest().into());
        contributors.push(contributor);
    }
    verified.provenance.contributors = contributors;
    check_provenance_with_compatibility(&verified.provenance, &verified.record, primary, proof)?;
    let text = canonical_text(verified.provenance.canonical_bytes()?)?;
    let changed = tx.execute("UPDATE meta SET value=?1 WHERE key=?2",
        &params![text, verified.provenance.meta_key()]).map_err(ApiGenerationError::Storage)?;
    if changed != 1 { return Err(ApiGenerationError::plain(ApiGenerationErrorCode::InvalidRecord)); }
    Ok(id)
}

// ---------------------------------------------------------------------------
// Open
// ---------------------------------------------------------------------------

/// A generation reopened and proven to be exactly the space the running profile
/// describes.
///
/// Every field is private and there is no public constructor, so a value of this
/// type is a check that already happened, not a claim a caller made. The type
/// deliberately offers no "compatible" flag: whether a record may be used is the
/// answer this value *is*, not a bit a caller can set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPrimaryGeneration {
    record: RepresentationRecord,
    provenance: ApiGenerationProvenance,
}

impl VerifiedPrimaryGeneration {
    /// The generation this record pins.
    pub const fn generation_id(&self) -> i64 {
        self.record.generation_id()
    }

    /// The space the generation's vectors live in.
    pub fn descriptor(&self) -> &RepresentationDescriptor {
        self.record.descriptor()
    }

    /// The digest of that descriptor.
    pub fn descriptor_sha256(&self) -> &str {
        self.record.descriptor_sha256()
    }

    /// The generation's `embedder_id`, always `api:<descriptor_sha256>`.
    pub fn embedder_id(&self) -> String {
        self.record.embedder_id()
    }

    /// The full provenance record this generation carries.
    pub fn provenance(&self) -> &ApiGenerationProvenance {
        &self.provenance
    }

    /// Return a pure-primary contributor only when this is still a pure-primary
    /// generation. A proof-aware generation must inspect full provenance.
    pub fn primary_contributor(&self) -> Result<&ApiGenerationContributor, ApiGenerationError> {
        self.provenance.single_primary_contributor()
    }
}

/// Reopen one generation through all three of its stored records and prove it is
/// the space `profile` describes.
///
/// The checks run in this order, and the first failure is the answer:
///
/// 1. the row exists and the two meta records exist — a missing record is never
///    inferred to be a pure-primary one;
/// 2. each record is structurally sound and the representation record agrees
///    with its own row (id, embedder id, dimension, both pipeline versions) and
///    with the provenance digest — a disagreement here is a store that
///    contradicts itself;
/// 3. the provenance admits exactly one pure-primary contributor;
/// 4. the stored descriptor still describes the space `profile` describes — a
///    changed model, revision, prefix, normalization, protocol, dimension or
///    pipeline version is an [`ApiGenerationErrorCode::IdentityMismatch`];
/// 5. the stored pinned provider still matches the profile's — a provider
///    change is [`ApiGenerationErrorCode::CompatibilityRequired`], because the
///    record's own bytes stay valid and only successor-side admission may clear
///    it. The stored endpoint digest records how the generation was first
///    called and takes no part in admission: a relocated endpoint, timeout,
///    connect timeout, credential variable name, response ceiling or metadata
///    endpoint still opens the same declared space.
///
/// The read runs inside `tx` so a future batch or activation guard can re-check
/// identity inside the very transaction that writes. Nothing here writes.
pub fn open_api_generation(
    tx: &Tx,
    generation_id: i64,
    profile: &ValidatedProfile,
) -> Result<VerifiedPrimaryGeneration, ApiGenerationError> {
    open_generation_checked(tx, generation_id, profile, None)
}

pub(crate) fn open_api_generation_with_compatibility(
    tx:&Tx, generation_id:i64, profile:&ValidatedProfile,
    proof:&crate::search::model_api::compatibility_bundle::CheckedBundle,
)->Result<VerifiedPrimaryGeneration,ApiGenerationError> {
    open_generation_checked(tx,generation_id,profile,Some(proof))
}

fn open_generation_checked(
    tx:&Tx, generation_id:i64, profile:&ValidatedProfile,
    proof:Option<&crate::search::model_api::compatibility_bundle::CheckedBundle>,
)->Result<VerifiedPrimaryGeneration,ApiGenerationError> {
    if generation_id < 1 {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "generation_id",
        ));
    }

    let row = GenerationRow::read(tx, generation_id)?.ok_or_else(|| {
        ApiGenerationError::at(ApiGenerationErrorCode::InvalidRecord, "generation_id")
    })?;

    let representation_key = format!(
        "{REPRESENTATION_KEY_STEM}:v{REPRESENTATION_RECORD_VERSION}:{generation_id}"
    );
    let representation_text = read_meta(tx, &representation_key)?.ok_or_else(|| {
        ApiGenerationError::at(ApiGenerationErrorCode::InvalidRecord, "api_representation")
    })?;
    let record = RepresentationRecord::decode(representation_text.as_bytes())
        .map_err(ApiGenerationError::from_stored_identity)?;

    check_record_against_row(&record, &row, generation_id)?;

    let provenance_key = format!(
        "{PROVENANCE_KEY_STEM}:v{API_GENERATION_PROVENANCE_VERSION}:{generation_id}"
    );
    let provenance_text = read_meta(tx, &provenance_key)?.ok_or_else(|| {
        ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "api_generation_provenance",
        )
    })?;
    let provenance = ApiGenerationProvenance::decode(provenance_text.as_bytes())?;

    if provenance.generation_id() != generation_id {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "generation_id",
        ));
    }
    if provenance.descriptor_sha256() != record.descriptor_sha256() {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "descriptor_sha256",
        ));
    }

    if let Some(proof)=proof {
        check_provenance_with_compatibility(&provenance,&record,profile,proof)?;
    } else {
        let contributor = provenance.single_primary_contributor()?;
        check_contributor_against_descriptor(contributor, record.descriptor())?;
        check_descriptor_against_profile(record.descriptor(), profile)?;
        check_contributor_against_profile(contributor, profile)?;
    }

    Ok(VerifiedPrimaryGeneration {
        record,
        provenance,
    })
}

fn compatibility_required()->ApiGenerationError {
    ApiGenerationError::plain(ApiGenerationErrorCode::CompatibilityRequired)
}

fn check_provenance_with_compatibility(
    provenance:&ApiGenerationProvenance, record:&RepresentationRecord, primary:&ValidatedProfile,
    proof:&crate::search::model_api::compatibility_bundle::CheckedBundle,
)->Result<(),ApiGenerationError> {
    let first=provenance.contributors.first().ok_or_else(||ApiGenerationError::plain(ApiGenerationErrorCode::InvalidProvenance))?;
    // A generation may start on an admitted backup while its primary is down.
    // Its first actual producer then carries proof, rather than a fabricated
    // pure-primary contribution. The loop below validates that proof normally.
    if first.compatibility_evidence_header.is_none() {
        if first.compatibility_evidence_sha256.is_some() { return Err(compatibility_required()); }
        check_contributor_against_descriptor(first,record.descriptor())?;
    }
    check_descriptor_against_profile(record.descriptor(),primary)?;
    let primary_sha=EndpointConfigIdentity::from_profile(primary).map_err(ApiGenerationError::from_config)?.sha256();
    let header=proof.header();
    if header.primary_descriptor_sha256!=record.descriptor_sha256()
        || !header.members.iter().any(|m|m.capture.sha256==header.primary_capture_sha256 && m.endpoint_config_sha256==primary_sha) {
        return Err(compatibility_required());
    }
    let mut seen=std::collections::HashSet::new();
    for (index,contributor) in provenance.contributors.iter().enumerate() {
        if !seen.insert((contributor.endpoint_config_sha256.as_str(),contributor.compatibility_evidence_sha256.as_deref())) {
            return Err(ApiGenerationError::plain(ApiGenerationErrorCode::InvalidProvenance));
        }
        let profile=if let Some(raw)=&contributor.compatibility_evidence_header {
            let old=raw.known(contributor.compatibility_evidence_sha256.as_deref())?;
            if old.primary_descriptor_sha256!=record.descriptor_sha256() || old.fixture.sha256!=header.fixture.sha256 {return Err(compatibility_required());}
            // Keep the old canonical anchor as well as the actual producer.
            let anchor=old.members.iter().find(|m|m.capture.sha256==old.primary_capture_sha256).ok_or_else(compatibility_required)?;
            if !proof.member_matches(anchor) {return Err(compatibility_required());}
            let mut producer=old.members.iter().filter(|m|m.endpoint_config_sha256==contributor.endpoint_config_sha256
                && (m.capture.sha256==old.primary_capture_sha256 || Some(&m.capture.sha256)==old.fallback_capture_sha256.as_ref()));
            let selected=producer.next().ok_or_else(compatibility_required)?;
            if producer.next().is_some() || !proof.member_matches(selected) {return Err(compatibility_required());}
            proof.capture_profile(&selected.capture.sha256).ok_or_else(compatibility_required)?
        } else {
            if index!=0 || contributor.compatibility_evidence_sha256.is_some() {return Err(compatibility_required());}
            let member=header.members.iter().find(|m|m.endpoint_config_sha256==contributor.endpoint_config_sha256).ok_or_else(compatibility_required)?;
            proof.capture_profile(&member.capture.sha256).ok_or_else(compatibility_required)?
        };
        let descriptor=RepresentationDescriptor::from_profile(profile,record.descriptor().effective_dimension()).map_err(ApiGenerationError::from_profile_identity)?;
        check_contributor_against_descriptor(contributor,&descriptor)?;
        check_contributor_against_profile(contributor,profile)?;
    }
    Ok(())
}

/// Add the backend that actually produced this page, in the caller's write
/// transaction. A page error rolls this metadata back together with its rows.
pub(crate) fn register_api_contribution(
    tx:&Tx,generation_id:i64,primary:&ValidatedProfile,writer:&ValidatedProfile,
    proof:&crate::search::model_api::compatibility_bundle::CheckedBundle,
)->Result<(),ApiGenerationError> {
    let verified=open_api_generation_with_compatibility(tx,generation_id,primary,proof)?;
    let endpoint=EndpointConfigIdentity::from_profile(writer).map_err(ApiGenerationError::from_config)?;
    let selected=proof.selected_capture(&endpoint.sha256()).ok_or_else(compatibility_required)?;
    if proof.capture_profile(selected).is_none() {return Err(compatibility_required());}
    let mut provenance=verified.provenance;
    if provenance.contributors.len()==1 && provenance.contributors[0].endpoint_config_sha256==endpoint.sha256() {return Ok(());}
    if provenance.contributors.iter().any(|c| c.endpoint_config_sha256==endpoint.sha256() && c.compatibility_evidence_sha256.as_deref()==Some(proof.digest())) {return Ok(());}
    let descriptor=RepresentationDescriptor::from_profile(writer,verified.record.descriptor().effective_dimension()).map_err(ApiGenerationError::from_profile_identity)?;
    let mut contributor=ApiGenerationContributor::primary(&descriptor,writer,&endpoint)?;
    contributor.compatibility_evidence_header=Some(HeaderPresent::from_checked(proof)?);
    contributor.compatibility_evidence_sha256=Some(proof.digest().into());
    provenance.contributors.push(contributor);
    let bytes=provenance.canonical_bytes()?;
    let text=String::from_utf8(bytes).map_err(|_|ApiGenerationError::plain(ApiGenerationErrorCode::InvalidProvenance))?;
    let changed=tx.execute("UPDATE meta SET value=?1 WHERE key=?2",&params![text,provenance.meta_key()]).map_err(ApiGenerationError::Storage)?;
    if changed!=1 {return Err(ApiGenerationError::plain(ApiGenerationErrorCode::InvalidRecord));}
    Ok(())
}

/// The representation record must agree with the row it names.
///
/// A disagreement is the store contradicting itself, not a configuration drift,
/// so every case here is `InvalidRecord`.
fn check_record_against_row(
    record: &RepresentationRecord,
    row: &GenerationRow,
    generation_id: i64,
) -> Result<(), ApiGenerationError> {
    if record.generation_id() != generation_id {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "generation_id",
        ));
    }
    if record.embedder_id() != row.embedder_id {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "embedder_id",
        ));
    }
    let dim = u64::try_from(row.dim).map_err(|_| {
        ApiGenerationError::at(ApiGenerationErrorCode::InvalidRecord, "dim")
    })?;
    if record.descriptor().effective_dimension() != dim {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "effective_dimension",
        ));
    }
    if i64::from(record.descriptor().canonicalize_version()) != row.canonicalize_version {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "canonicalize_version",
        ));
    }
    if i64::from(record.descriptor().chunking_version()) != row.chunking_version {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "chunking_version",
        ));
    }
    Ok(())
}

/// The contributor's representation fields must equal the descriptor's.
///
/// They were copied from that descriptor at creation, so a disagreement means
/// the two stored records contradict each other.
fn check_contributor_against_descriptor(
    contributor: &ApiGenerationContributor,
    descriptor: &RepresentationDescriptor,
) -> Result<(), ApiGenerationError> {
    if contributor.model() != descriptor.model() {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "model",
        ));
    }
    if contributor.model_revision() != descriptor.model_revision() {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "model_revision",
        ));
    }
    if contributor.normalization() != descriptor.normalization() {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "normalization",
        ));
    }
    if contributor.protocol() != descriptor.protocol() {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "protocol",
        ));
    }
    if contributor.query_prefix() != descriptor.query_prefix() {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "query_prefix",
        ));
    }
    if contributor.document_prefix() != descriptor.document_prefix() {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::InvalidRecord,
            "document_prefix",
        ));
    }
    Ok(())
}

/// The stored descriptor must still describe the space the profile describes.
fn check_descriptor_against_profile(
    descriptor: &RepresentationDescriptor,
    profile: &ValidatedProfile,
) -> Result<(), ApiGenerationError> {
    let expected = RepresentationDescriptor::from_profile(profile, descriptor.effective_dimension())
        .map_err(ApiGenerationError::from_profile_identity)?;
    if !descriptor.is_equivalent_to(&expected) {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::IdentityMismatch,
            "descriptor",
        ));
    }
    Ok(())
}

/// The stored pinned provider must still match the profile's.
///
/// A provider change moves a *call* without moving the *space*: it leaves the
/// descriptor intact but invalidates the record's admission, which only
/// successor-side cross-endpoint proof may restore. The stored endpoint digest
/// is creation-time evidence only and is deliberately not compared here, so a
/// relocated endpoint or any other call-setting change still opens the declared
/// space.
fn check_contributor_against_profile(
    contributor: &ApiGenerationContributor,
    profile: &ValidatedProfile,
) -> Result<(), ApiGenerationError> {
    let provider = profile.embedding().and_then(|detail| detail.provider_only.as_deref());
    if contributor.provider_only() != provider {
        return Err(ApiGenerationError::at(
            ApiGenerationErrorCode::CompatibilityRequired,
            "provider_only",
        ));
    }
    Ok(())
}

/// The meta-key stem of a generation provenance record, for callers that need to
/// recognise one without decoding it.
pub fn provenance_meta_key(generation_id: i64) -> String {
    format!("{PROVENANCE_KEY_STEM}:v{API_GENERATION_PROVENANCE_VERSION}:{generation_id}")
}

/// The meta-key stem of a generation representation record.
pub fn representation_meta_key(generation_id: i64) -> String {
    format!("{REPRESENTATION_KEY_STEM}:v{REPRESENTATION_RECORD_VERSION}:{generation_id}")
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use crate::search::model_api::compatibility_bundle::tests::migration_fixture;
    use crate::storage::api::{TxMode, StorageError};

    #[test]
    fn backup_only_generation_keeps_canonical_space_without_inventing_primary_production() {
        use crate::search::model_api::compatibility_bundle::tests::fallback_fixture;
        let (config, proof) = fallback_fixture("http://127.0.0.1:1/embedding", "https://example.invalid/embedding");
        let primary = config.profile("primary").unwrap();
        let backup = config.profile("backup").unwrap();
        let root = tempfile::tempdir().unwrap();
        let storage = crate::storage::sqlite::FrankenStorage::open(&root.path().join("db.sqlite")).unwrap();
        let id = storage.raw().with_tx(TxMode::Immediate, |tx| create_api_generation_with_producers(
            tx, primary, 2, &[1;24], 1, &[backup.clone()], &proof).map_err(StorageError::from)).unwrap();
        assert!(storage.raw().with_tx(TxMode::Deferred, |tx| open_api_generation(tx,id,primary).map_err(StorageError::from)).is_err());
        let verified = storage.raw().with_tx(TxMode::Deferred, |tx| open_api_generation_with_compatibility(tx,id,primary,&proof).map_err(StorageError::from)).unwrap();
        assert_eq!(verified.descriptor_sha256(), proof.header().primary_descriptor_sha256);
        assert_eq!(verified.provenance().contributors().len(), 1);
        assert!(verified.primary_contributor().is_err());
        assert_eq!(verified.provenance().contributors()[0].endpoint_config_sha256,
            EndpointConfigIdentity::from_profile(backup).unwrap().sha256());
        storage.raw().with_tx(TxMode::Immediate, |tx| register_api_contribution(tx,id,primary,primary,&proof).map_err(StorageError::from)).unwrap();
        let verified = storage.raw().with_tx(TxMode::Deferred, |tx| open_api_generation_with_compatibility(tx,id,primary,&proof).map_err(StorageError::from)).unwrap();
        assert_eq!(verified.provenance().contributors().len(), 2);
    }

    #[test]
    fn contribution_and_page_failure_share_the_callers_transaction() {
        let root=tempfile::tempdir().unwrap();
        let storage=crate::storage::sqlite::FrankenStorage::open(&root.path().join("db.sqlite")).unwrap();
        let (proof,profiles)=migration_fixture(&[1,2],1,None);
        let id=storage.raw().with_tx(TxMode::Immediate,|tx| create_api_generation(tx,&profiles[0],2,&[1;24],1).map_err(StorageError::from)).unwrap();
        let before=storage.raw().with_tx(TxMode::Deferred,|tx| read_meta(tx,&provenance_meta_key(id)).map_err(StorageError::from)).unwrap();
        let failed:Result<(),StorageError>=storage.raw().with_tx(TxMode::Immediate,|tx| {
            register_api_contribution(tx,id,&profiles[1],&profiles[1],&proof).map_err(StorageError::from)?;
            Err(StorageError::Other{code:None,detail:"synthetic vector page failure".into()})
        });
        assert!(failed.is_err());
        assert_eq!(before,storage.raw().with_tx(TxMode::Deferred,|tx| read_meta(tx,&provenance_meta_key(id)).map_err(StorageError::from)).unwrap());
        storage.raw().with_tx(TxMode::Immediate,|tx| register_api_contribution(tx,id,&profiles[1],&profiles[1],&proof).map_err(StorageError::from)).unwrap();
        let verified=storage.raw().with_tx(TxMode::Deferred,|tx| open_api_generation_with_compatibility(tx,id,&profiles[1],&proof).map_err(StorageError::from)).unwrap();
        assert_eq!(verified.provenance().contributors().len(),2);
        let stored=&verified.provenance().contributors()[1];
        assert_eq!(stored.compatibility_evidence_sha256(),Some(proof.digest()));
        assert_eq!(stored.compatibility_evidence_header.as_ref().unwrap().known(Some(proof.digest())).unwrap().primary_descriptor_sha256,verified.descriptor_sha256());
    }

    #[test]
    fn old_capture_cannot_be_replaced_by_new_sampling_at_the_same_endpoint() {
        let root=tempfile::tempdir().unwrap();
        let storage=crate::storage::sqlite::FrankenStorage::open(&root.path().join("db.sqlite")).unwrap();
        let (first,profiles)=migration_fixture(&[1,2],1,None);
        let id=storage.raw().with_tx(TxMode::Immediate,|tx| create_api_generation(tx,&profiles[0],2,&[1;24],1).map_err(StorageError::from)).unwrap();
        storage.raw().with_tx(TxMode::Immediate,|tx| register_api_contribution(tx,id,&profiles[1],&profiles[1],&first).map_err(StorageError::from)).unwrap();
        let (missing,missing_profiles)=migration_fixture(&[1,3],1,None);
        assert!(storage.raw().with_tx(TxMode::Deferred,|tx| open_api_generation_with_compatibility(tx,id,&missing_profiles[1],&missing).map_err(StorageError::from)).is_err());
        let (fresh,fresh_profiles)=migration_fixture(&[1,2,3],2,Some(2));
        assert!(storage.raw().with_tx(TxMode::Deferred,|tx| open_api_generation_with_compatibility(tx,id,&fresh_profiles[2],&fresh).map_err(StorageError::from)).is_err());
        let (complete,complete_profiles)=migration_fixture(&[1,2,3],2,None);
        storage.raw().with_tx(TxMode::Immediate,|tx| register_api_contribution(tx,id,&complete_profiles[2],&complete_profiles[2],&complete).map_err(StorageError::from)).unwrap();
        let verified=storage.raw().with_tx(TxMode::Deferred,|tx| open_api_generation_with_compatibility(tx,id,&complete_profiles[2],&complete).map_err(StorageError::from)).unwrap();
        assert_eq!(verified.provenance().contributors().len(),3);
        assert_eq!(verified.provenance().contributors()[1].compatibility_evidence_sha256(),Some(first.digest()),"old evidence remains intact");
    }
}
