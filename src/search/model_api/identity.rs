//! The representation identity of one model-service embedding space.
//!
//! Two embedding services can answer with vectors of the same width and still
//! occupy different spaces, so a width is not an identity and neither is a
//! model name on its own. This module owns the smallest complete description of
//! the space a vector was produced in — the **representation descriptor** — and
//! the record that pins that descriptor to one embedding generation.
//!
//! The descriptor binds exactly the fields that change what a vector means: the
//! two pipeline versions, the query and document prefixes, the effective output
//! dimension, the model and its declared revision, the normalization convention,
//! the wire protocol, and the optional explicit `dimensions` request parameter.
//! It deliberately excludes everything that can move without moving the space:
//! the endpoint, the profile id, the timeouts, the credential variable and the
//! fallback wiring. Re-hosting a model or rotating a credential therefore does
//! not force a re-embedding, while a prefix or normalization change does.
//!
//! The canonical form is a compact UTF-8 JSON object whose keys appear in ASCII
//! order with no trailing newline, and the identity is the lowercase SHA-256 of
//! exactly those bytes. Encoding goes through `serde_json`, so string escaping
//! matches the rest of the tree; decoding is strict and walks the original
//! bytes field by field, so a duplicate, unknown, missing or mistyped key is a
//! rejection rather than a last-value-wins repair. A descriptor that decodes is
//! structurally sound; whether the running model may query it is the separate
//! question [`RepresentationDescriptor::is_equivalent_to`] answers.
//!
//! This module is a pure codec. It reads no file, touches no database, opens no
//! socket, reads no environment variable and registers no caller. It neither
//! builds an embedding generation nor decides that one may be activated, and it
//! constructs no provenance record.

use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use super::config::{ApiProtocol, Normalization, ProfileKind, ValidatedProfile};
use crate::search::canonicalize::CANONICALIZE_PIPELINE_VERSION;
use crate::search::chunking::CHUNKING_POLICY_VERSION;

/// The domain tag that keeps this digest apart from every other one in the tree.
pub const REPRESENTATION_DOMAIN: &str = "cass.api-representation/1";

/// The record version this module writes and the only one it reads.
pub const REPRESENTATION_RECORD_VERSION: i64 = 1;

/// The prefix that turns a descriptor digest into an `embedder_id`. A
/// representation identity is never a bare hex string.
const EMBEDDER_ID_PREFIX: &str = "api:";

/// The marker a structurally rejected descriptor carries through the
/// `serde_json` error channel.
///
/// The record nests a descriptor and both layers refuse the same way, so the
/// record layer needs to know which one refused. The marker is a fixed string,
/// never any part of the rejected bytes, and it is consumed here — the public
/// error never carries a parser message.
const DESCRIPTOR_STRUCTURAL_MARKER: &str = "cass.api-representation.descriptor";

/// The marker a structurally rejected record carries. Kept distinct from
/// [`DESCRIPTOR_STRUCTURAL_MARKER`] so a nested descriptor failure is still
/// attributed to the descriptor.
const RECORD_STRUCTURAL_MARKER: &str = "cass.api-representation.record";

/// The closed set of reasons a representation identity is refused.
///
/// Callers branch on the code, never on a message, and the code never changes
/// meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityErrorCode {
    /// A profile or a protocol that is not an embedding protocol was offered.
    WrongKind,
    /// A descriptor was malformed, or violated one of its own field rules.
    InvalidDescriptor,
    /// A representation record was malformed, or violated one of its rules.
    InvalidRecord,
    /// The record carries a version this build does not write.
    UnsupportedVersion,
    /// Two identities that must agree do not.
    IdentityMismatch,
}

impl IdentityErrorCode {
    /// The stable wire name of this code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongKind => "WrongKind",
            Self::InvalidDescriptor => "InvalidDescriptor",
            Self::InvalidRecord => "InvalidRecord",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::IdentityMismatch => "IdentityMismatch",
        }
    }
}

impl fmt::Display for IdentityErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused representation identity.
///
/// The payload is a code plus, at most, the compile-time name of the offending
/// field. It is deliberately too small to carry a model body, a prefix, a
/// credential or any part of the rejected bytes, so `Display` and `Debug` are
/// safe to log. No parser error is attached as a source, because a parser error
/// quotes the input it rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityError {
    code: IdentityErrorCode,
    field: Option<&'static str>,
}

impl IdentityError {
    /// A rejection that names no particular field.
    pub const fn new(code: IdentityErrorCode) -> Self {
        Self { code, field: None }
    }

    /// A rejection attributed to one field.
    ///
    /// `field` must be a compile-time constant from this schema, never text
    /// taken from the rejected document.
    pub const fn at(code: IdentityErrorCode, field: &'static str) -> Self {
        Self {
            code,
            field: Some(field),
        }
    }

    /// The stable reason code.
    pub const fn code(&self) -> IdentityErrorCode {
        self.code
    }

    /// The field this rejection is attributed to, when known.
    pub const fn field(&self) -> Option<&'static str> {
        self.field
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.field {
            Some(field) => write!(
                f,
                "invalid model api representation identity: {} ({field})",
                self.code.as_str()
            ),
            None => write!(
                f,
                "invalid model api representation identity: {}",
                self.code.as_str()
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

/// What one embedding space is, in the terms that change what its vectors mean.
///
/// Build one with [`Self::from_profile`] and read it back with [`Self::decode`].
/// Every field is private; there is no setter and no public constructor from
/// loose values, so a descriptor that exists has passed the rules below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationDescriptor {
    canonicalize_version: u32,
    chunking_version: u32,
    document_prefix: String,
    effective_dimension: u64,
    model: String,
    model_revision: String,
    normalization: Normalization,
    protocol: ApiProtocol,
    query_prefix: String,
    request_dimensions: Option<u64>,
}

impl RepresentationDescriptor {
    /// Build the descriptor of one embedding profile at one observed width.
    ///
    /// `observed_dimension` is what the caller actually measured, not what the
    /// configuration hoped for. It must equal `expected_dimension` and, when
    /// configured, `request_dimensions`; a disagreement is an identity
    /// mismatch, not a descriptor to be repaired.
    ///
    /// The two pipeline versions come from the live constants rather than from
    /// copies, so a version bump is picked up here without a second edit.
    pub fn from_profile(
        profile: &ValidatedProfile,
        observed_dimension: u64,
    ) -> Result<Self, IdentityError> {
        if profile.kind != ProfileKind::Embedding {
            return Err(IdentityError::at(IdentityErrorCode::WrongKind, "kind"));
        }
        let embedding = profile
            .embedding()
            .ok_or_else(|| IdentityError::at(IdentityErrorCode::WrongKind, "kind"))?;
        let protocol = match profile.protocol {
            ApiProtocol::OpenAiEmbeddingsV1 | ApiProtocol::OpenRouterEmbeddingsV1 => {
                profile.protocol
            }
            ApiProtocol::RerankJsonV1 | ApiProtocol::OpenRouterRerankV1 => {
                return Err(IdentityError::at(IdentityErrorCode::WrongKind, "protocol"));
            }
        };

        if observed_dimension == 0 {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "effective_dimension",
            ));
        }
        if let Some(expected) = embedding.expected_dimension
            && expected != observed_dimension
        {
            return Err(IdentityError::at(
                IdentityErrorCode::IdentityMismatch,
                "effective_dimension",
            ));
        }
        if let Some(requested) = embedding.request_dimensions
            && requested != observed_dimension
        {
            return Err(IdentityError::at(
                IdentityErrorCode::IdentityMismatch,
                "request_dimensions",
            ));
        }
        if profile.model.is_empty() {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "model",
            ));
        }
        if profile.model_revision.is_empty() {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "model_revision",
            ));
        }

        Ok(Self {
            canonicalize_version: CANONICALIZE_PIPELINE_VERSION,
            chunking_version: CHUNKING_POLICY_VERSION,
            document_prefix: embedding.document_prefix.clone(),
            effective_dimension: observed_dimension,
            model: profile.model.clone(),
            model_revision: profile.model_revision.clone(),
            normalization: embedding.normalization,
            protocol,
            query_prefix: embedding.query_prefix.clone(),
            request_dimensions: embedding.request_dimensions,
        })
    }

    /// The canonicalization pipeline version this identity was built under.
    pub const fn canonicalize_version(&self) -> u32 {
        self.canonicalize_version
    }

    /// The chunking policy version this identity was built under.
    pub const fn chunking_version(&self) -> u32 {
        self.chunking_version
    }

    /// The bytes prepended to every document before embedding.
    pub fn document_prefix(&self) -> &str {
        &self.document_prefix
    }

    /// The dimension every vector in this space actually has.
    pub const fn effective_dimension(&self) -> u64 {
        self.effective_dimension
    }

    /// The model identity the space was built with.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The deployment contract revision the operator declared.
    pub fn model_revision(&self) -> &str {
        &self.model_revision
    }

    /// The normalization convention this space follows.
    pub const fn normalization(&self) -> Normalization {
        self.normalization
    }

    /// The wire protocol this space's vectors arrive over.
    pub const fn protocol(&self) -> ApiProtocol {
        self.protocol
    }

    /// The bytes prepended to every query before embedding.
    pub fn query_prefix(&self) -> &str {
        &self.query_prefix
    }

    /// The explicit `dimensions` request parameter, when the profile sets one.
    pub const fn request_dimensions(&self) -> Option<u64> {
        self.request_dimensions
    }

    /// The canonical bytes: one compact JSON object, ASCII-ordered, no newline.
    ///
    /// Serializing these field types into a byte buffer cannot fail, so the
    /// empty fallback is unreachable and exists only to keep an `unwrap` out of
    /// the encoding path.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.wire()).unwrap_or_default()
    }

    /// The lowercase SHA-256 of [`Self::canonical_bytes`].
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.canonical_bytes()))
    }

    /// The `embedder_id` that names this space: `api:<sha256>`.
    pub fn embedder_id(&self) -> String {
        format!("{EMBEDDER_ID_PREFIX}{}", self.sha256())
    }

    /// Whether two descriptors describe the same space.
    ///
    /// Every semantic field must be equal. A shared dimension is not enough: a
    /// different model, prefix, normalization or pipeline version is a
    /// different space and must never be queried as this one.
    pub fn is_equivalent_to(&self, other: &Self) -> bool {
        self.canonicalize_version == other.canonicalize_version
            && self.chunking_version == other.chunking_version
            && self.document_prefix == other.document_prefix
            && self.effective_dimension == other.effective_dimension
            && self.model == other.model
            && self.model_revision == other.model_revision
            && self.normalization == other.normalization
            && self.protocol == other.protocol
            && self.query_prefix == other.query_prefix
            && self.request_dimensions == other.request_dimensions
    }

    /// Parse one descriptor from its canonical bytes.
    ///
    /// Rejects duplicate keys (including keys that only collide after
    /// unescaping), unknown keys, missing keys, a mistyped or out-of-range
    /// number, a wrong domain, a wrong protocol family, an empty model, a zero
    /// dimension, trailing data and malformed UTF-8. Trailing whitespace is
    /// accepted, as JSON allows it.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let raw: RawDescriptor = serde_json::from_slice(bytes)
            .map_err(|_| IdentityError::new(IdentityErrorCode::InvalidDescriptor))?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawDescriptor) -> Result<Self, IdentityError> {
        if raw.domain != REPRESENTATION_DOMAIN {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "domain",
            ));
        }
        if raw.canonicalize_version == 0 {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "canonicalize_version",
            ));
        }
        if raw.chunking_version == 0 {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "chunking_version",
            ));
        }
        if raw.effective_dimension == 0 {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "effective_dimension",
            ));
        }
        if raw.request_dimensions == Some(0) {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "request_dimensions",
            ));
        }
        if raw.model.is_empty() {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "model",
            ));
        }
        if raw.model_revision.is_empty() {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidDescriptor,
                "model_revision",
            ));
        }

        Ok(Self {
            canonicalize_version: raw.canonicalize_version,
            chunking_version: raw.chunking_version,
            document_prefix: raw.document_prefix,
            effective_dimension: raw.effective_dimension,
            model: raw.model,
            model_revision: raw.model_revision,
            normalization: parse_normalization(&raw.normalization)?,
            protocol: parse_protocol(&raw.protocol)?,
            query_prefix: raw.query_prefix,
            request_dimensions: raw.request_dimensions,
        })
    }

    fn wire(&self) -> DescriptorWire<'_> {
        DescriptorWire {
            canonicalize_version: self.canonicalize_version,
            chunking_version: self.chunking_version,
            document_prefix: &self.document_prefix,
            domain: REPRESENTATION_DOMAIN,
            effective_dimension: self.effective_dimension,
            model: &self.model,
            model_revision: &self.model_revision,
            normalization: self.normalization.as_str(),
            protocol: self.protocol.as_str(),
            query_prefix: &self.query_prefix,
            request_dimensions: self.request_dimensions,
        }
    }
}

/// One descriptor pinned to one embedding generation.
///
/// The four fields are exactly `descriptor`, `descriptor_sha256`,
/// `generation_id` and `version`; the digest is always recomputed from the
/// descriptor rather than accepted from a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationRecord {
    descriptor: RepresentationDescriptor,
    descriptor_sha256: String,
    generation_id: i64,
    version: i64,
}

impl RepresentationRecord {
    /// Pin a descriptor to a generation.
    ///
    /// `generation_id` is the real positive generation number; a zero or
    /// negative id is not a generation.
    pub fn new(
        descriptor: RepresentationDescriptor,
        generation_id: i64,
    ) -> Result<Self, IdentityError> {
        if generation_id < 1 {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidRecord,
                "generation_id",
            ));
        }
        let descriptor_sha256 = descriptor.sha256();
        Ok(Self {
            descriptor,
            descriptor_sha256,
            generation_id,
            version: REPRESENTATION_RECORD_VERSION,
        })
    }

    /// The space this generation was built in.
    pub fn descriptor(&self) -> &RepresentationDescriptor {
        &self.descriptor
    }

    /// The digest of the descriptor, as stored.
    pub fn descriptor_sha256(&self) -> &str {
        &self.descriptor_sha256
    }

    /// The generation this record pins.
    pub const fn generation_id(&self) -> i64 {
        self.generation_id
    }

    /// The record schema version.
    pub const fn version(&self) -> i64 {
        self.version
    }

    /// The `embedder_id` of the pinned descriptor.
    pub fn embedder_id(&self) -> String {
        self.descriptor.embedder_id()
    }

    /// The meta-table key that names this record.
    ///
    /// The generation number is written as a canonical decimal integer, so the
    /// key has no leading zero and no other spelling.
    pub fn meta_key(&self) -> String {
        format!(
            "api_representation:v{}:{}",
            self.version, self.generation_id
        )
    }

    /// The canonical bytes of the record.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.wire()).unwrap_or_default()
    }

    /// Parse one record from its canonical bytes.
    ///
    /// Beyond the descriptor's own rules this rejects an unknown or duplicate
    /// outer key, a future record version, a non-positive or out-of-range
    /// generation number, a malformed digest and a digest that does not match
    /// the descriptor it was stored with.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let raw: RawRecord = serde_json::from_slice(bytes).map_err(|error| {
            if error.to_string().starts_with(DESCRIPTOR_STRUCTURAL_MARKER) {
                IdentityError::new(IdentityErrorCode::InvalidDescriptor)
            } else {
                IdentityError::new(IdentityErrorCode::InvalidRecord)
            }
        })?;
        Self::from_raw(raw)
    }

    /// Parse a record and require it to be the one the caller expects.
    ///
    /// This is the reopen path: the caller knows the generation it is opening,
    /// the `embedder_id` it recorded and the dimension it needs, and all three
    /// must agree with the stored bytes. A match here is a structural identity
    /// check; whether the running model may query the space is the separate
    /// question [`RepresentationDescriptor::is_equivalent_to`] answers.
    pub fn decode_matching(
        bytes: &[u8],
        expected_generation_id: i64,
        expected_embedder_id: &str,
        expected_dimension: u64,
    ) -> Result<Self, IdentityError> {
        let record = Self::decode(bytes)?;
        if record.generation_id != expected_generation_id {
            return Err(IdentityError::at(
                IdentityErrorCode::IdentityMismatch,
                "generation_id",
            ));
        }
        if record.descriptor.effective_dimension != expected_dimension {
            return Err(IdentityError::at(
                IdentityErrorCode::IdentityMismatch,
                "effective_dimension",
            ));
        }
        if record.descriptor.embedder_id() != expected_embedder_id {
            return Err(IdentityError::at(
                IdentityErrorCode::IdentityMismatch,
                "embedder_id",
            ));
        }
        Ok(record)
    }

    fn from_raw(raw: RawRecord) -> Result<Self, IdentityError> {
        if raw.version != REPRESENTATION_RECORD_VERSION {
            return Err(IdentityError::at(
                IdentityErrorCode::UnsupportedVersion,
                "version",
            ));
        }
        if raw.generation_id < 1 {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidRecord,
                "generation_id",
            ));
        }
        if !is_lowercase_sha256(&raw.descriptor_sha256) {
            return Err(IdentityError::at(
                IdentityErrorCode::InvalidRecord,
                "descriptor_sha256",
            ));
        }
        let descriptor = RepresentationDescriptor::from_raw(raw.descriptor)?;
        if descriptor.sha256() != raw.descriptor_sha256 {
            return Err(IdentityError::at(
                IdentityErrorCode::IdentityMismatch,
                "descriptor_sha256",
            ));
        }
        Ok(Self {
            descriptor,
            descriptor_sha256: raw.descriptor_sha256,
            generation_id: raw.generation_id,
            version: raw.version,
        })
    }

    fn wire(&self) -> RecordWire<'_> {
        RecordWire {
            descriptor: self.descriptor.wire(),
            descriptor_sha256: &self.descriptor_sha256,
            generation_id: self.generation_id,
            version: self.version,
        }
    }
}

/// The descriptor exactly as it is written, in canonical key order.
///
/// Declaring the fields in this order is what fixes the byte layout: `serde`
/// emits struct fields in declaration order, so the output does not depend on a
/// map implementation.
#[derive(Serialize)]
struct DescriptorWire<'a> {
    canonicalize_version: u32,
    chunking_version: u32,
    document_prefix: &'a str,
    domain: &'a str,
    effective_dimension: u64,
    model: &'a str,
    model_revision: &'a str,
    normalization: &'a str,
    protocol: &'a str,
    query_prefix: &'a str,
    request_dimensions: Option<u64>,
}

/// The record exactly as it is written, in canonical key order.
#[derive(Serialize)]
struct RecordWire<'a> {
    descriptor: DescriptorWire<'a>,
    descriptor_sha256: &'a str,
    generation_id: i64,
    version: i64,
}

/// A descriptor's keys, before any rule beyond structure is applied.
///
/// Every field is present exactly once; the strict visitor below refuses a
/// document that would leave one unset, and `request_dimensions` is tracked as
/// an `Option<Option<u64>>` so "absent" and "present and null" stay different
/// facts.
struct RawDescriptor {
    canonicalize_version: u32,
    chunking_version: u32,
    document_prefix: String,
    domain: String,
    effective_dimension: u64,
    model: String,
    model_revision: String,
    normalization: String,
    protocol: String,
    query_prefix: String,
    request_dimensions: Option<u64>,
}

/// A record's keys, before any rule beyond structure is applied.
struct RawRecord {
    descriptor: RawDescriptor,
    descriptor_sha256: String,
    generation_id: i64,
    version: i64,
}

/// A structural rejection at the descriptor layer.
fn descriptor_structural<E: de::Error>() -> E {
    E::custom(DESCRIPTOR_STRUCTURAL_MARKER)
}

/// A structural rejection at the record layer.
fn record_structural<E: de::Error>() -> E {
    E::custom(RECORD_STRUCTURAL_MARKER)
}

impl<'de> Deserialize<'de> for RawDescriptor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawDescriptorVisitor;

        impl<'de> Visitor<'de> for RawDescriptorVisitor {
            type Value = RawDescriptor;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a representation descriptor object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut canonicalize_version: Option<u32> = None;
                let mut chunking_version: Option<u32> = None;
                let mut document_prefix: Option<String> = None;
                let mut domain: Option<String> = None;
                let mut effective_dimension: Option<u64> = None;
                let mut model: Option<String> = None;
                let mut model_revision: Option<String> = None;
                let mut normalization: Option<String> = None;
                let mut protocol: Option<String> = None;
                let mut query_prefix: Option<String> = None;
                let mut request_dimensions: Option<Option<u64>> = None;

                while let Some(key) = map
                    .next_key::<String>()
                    .map_err(|_| descriptor_structural::<A::Error>())?
                {
                    match key.as_str() {
                        "canonicalize_version" => {
                            if canonicalize_version.is_some() {
                                return Err(descriptor_structural());
                            }
                            canonicalize_version = Some(
                                map.next_value::<u32>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "chunking_version" => {
                            if chunking_version.is_some() {
                                return Err(descriptor_structural());
                            }
                            chunking_version = Some(
                                map.next_value::<u32>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "document_prefix" => {
                            if document_prefix.is_some() {
                                return Err(descriptor_structural());
                            }
                            document_prefix = Some(
                                map.next_value::<String>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "domain" => {
                            if domain.is_some() {
                                return Err(descriptor_structural());
                            }
                            domain = Some(
                                map.next_value::<String>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "effective_dimension" => {
                            if effective_dimension.is_some() {
                                return Err(descriptor_structural());
                            }
                            effective_dimension = Some(
                                map.next_value::<u64>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "model" => {
                            if model.is_some() {
                                return Err(descriptor_structural());
                            }
                            model = Some(
                                map.next_value::<String>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "model_revision" => {
                            if model_revision.is_some() {
                                return Err(descriptor_structural());
                            }
                            model_revision = Some(
                                map.next_value::<String>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "normalization" => {
                            if normalization.is_some() {
                                return Err(descriptor_structural());
                            }
                            normalization = Some(
                                map.next_value::<String>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "protocol" => {
                            if protocol.is_some() {
                                return Err(descriptor_structural());
                            }
                            protocol = Some(
                                map.next_value::<String>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "query_prefix" => {
                            if query_prefix.is_some() {
                                return Err(descriptor_structural());
                            }
                            query_prefix = Some(
                                map.next_value::<String>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        "request_dimensions" => {
                            if request_dimensions.is_some() {
                                return Err(descriptor_structural());
                            }
                            request_dimensions = Some(
                                map.next_value::<Option<u64>>()
                                    .map_err(|_| descriptor_structural::<A::Error>())?,
                            );
                        }
                        _ => return Err(descriptor_structural()),
                    }
                }

                Ok(RawDescriptor {
                    canonicalize_version: canonicalize_version
                        .ok_or_else(descriptor_structural::<A::Error>)?,
                    chunking_version: chunking_version
                        .ok_or_else(descriptor_structural::<A::Error>)?,
                    document_prefix: document_prefix
                        .ok_or_else(descriptor_structural::<A::Error>)?,
                    domain: domain.ok_or_else(descriptor_structural::<A::Error>)?,
                    effective_dimension: effective_dimension
                        .ok_or_else(descriptor_structural::<A::Error>)?,
                    model: model.ok_or_else(descriptor_structural::<A::Error>)?,
                    model_revision: model_revision.ok_or_else(descriptor_structural::<A::Error>)?,
                    normalization: normalization.ok_or_else(descriptor_structural::<A::Error>)?,
                    protocol: protocol.ok_or_else(descriptor_structural::<A::Error>)?,
                    query_prefix: query_prefix.ok_or_else(descriptor_structural::<A::Error>)?,
                    request_dimensions: request_dimensions
                        .ok_or_else(descriptor_structural::<A::Error>)?,
                })
            }
        }

        deserializer.deserialize_map(RawDescriptorVisitor)
    }
}

impl<'de> Deserialize<'de> for RawRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RawRecordVisitor;

        impl<'de> Visitor<'de> for RawRecordVisitor {
            type Value = RawRecord;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a representation record object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut descriptor: Option<RawDescriptor> = None;
                let mut descriptor_sha256: Option<String> = None;
                let mut generation_id: Option<i64> = None;
                let mut version: Option<i64> = None;

                while let Some(key) = map
                    .next_key::<String>()
                    .map_err(|_| record_structural::<A::Error>())?
                {
                    match key.as_str() {
                        "descriptor" => {
                            if descriptor.is_some() {
                                return Err(record_structural());
                            }
                            // A failure inside the descriptor keeps the
                            // descriptor's own marker, so the outer layer can
                            // attribute it correctly.
                            descriptor = Some(map.next_value::<RawDescriptor>()?);
                        }
                        "descriptor_sha256" => {
                            if descriptor_sha256.is_some() {
                                return Err(record_structural());
                            }
                            descriptor_sha256 = Some(
                                map.next_value::<String>()
                                    .map_err(|_| record_structural::<A::Error>())?,
                            );
                        }
                        "generation_id" => {
                            if generation_id.is_some() {
                                return Err(record_structural());
                            }
                            generation_id = Some(
                                map.next_value::<i64>()
                                    .map_err(|_| record_structural::<A::Error>())?,
                            );
                        }
                        "version" => {
                            if version.is_some() {
                                return Err(record_structural());
                            }
                            version = Some(
                                map.next_value::<i64>()
                                    .map_err(|_| record_structural::<A::Error>())?,
                            );
                        }
                        _ => return Err(record_structural()),
                    }
                }

                Ok(RawRecord {
                    descriptor: descriptor.ok_or_else(record_structural::<A::Error>)?,
                    descriptor_sha256: descriptor_sha256
                        .ok_or_else(record_structural::<A::Error>)?,
                    generation_id: generation_id.ok_or_else(record_structural::<A::Error>)?,
                    version: version.ok_or_else(record_structural::<A::Error>)?,
                })
            }
        }

        deserializer.deserialize_map(RawRecordVisitor)
    }
}

/// Map a stored protocol string back to its variant.
///
/// The names come from the variants themselves, so this module never restates
/// them. A rerank protocol is a wrong kind rather than a malformed descriptor:
/// it is a real protocol, just not one that describes an embedding space.
fn parse_protocol(raw: &str) -> Result<ApiProtocol, IdentityError> {
    const EMBEDDING: [ApiProtocol; 2] = [
        ApiProtocol::OpenAiEmbeddingsV1,
        ApiProtocol::OpenRouterEmbeddingsV1,
    ];
    const RERANK: [ApiProtocol; 2] = [ApiProtocol::RerankJsonV1, ApiProtocol::OpenRouterRerankV1];

    if let Some(found) = EMBEDDING.iter().find(|candidate| candidate.as_str() == raw) {
        return Ok(*found);
    }
    if RERANK.iter().any(|candidate| candidate.as_str() == raw) {
        return Err(IdentityError::at(IdentityErrorCode::WrongKind, "protocol"));
    }
    Err(IdentityError::at(
        IdentityErrorCode::InvalidDescriptor,
        "protocol",
    ))
}

/// Map a stored normalization string back to its variant.
fn parse_normalization(raw: &str) -> Result<Normalization, IdentityError> {
    const NORMALIZATIONS: [Normalization; 2] = [Normalization::L2, Normalization::None];
    NORMALIZATIONS
        .iter()
        .find(|candidate| candidate.as_str() == raw)
        .copied()
        .ok_or_else(|| IdentityError::at(IdentityErrorCode::InvalidDescriptor, "normalization"))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::model_api::config::ApiConfig;

    /// The canonical bytes of a fixed descriptor, written out by hand.
    ///
    /// The golden digest below was computed from this exact byte string with an
    /// external tool, not by the code under test. The document carries a
    /// non-ASCII model name, a non-ASCII revision, an empty document prefix, an
    /// escaped newline in the query prefix and a null `request_dimensions`.
    const GOLD_DESCRIPTOR_JSON: &str = r#"{"canonicalize_version":3,"chunking_version":1,"document_prefix":"","domain":"cass.api-representation/1","effective_dimension":1024,"model":"vendor-x/模型-甲","model_revision":"rev-字","normalization":"l2","protocol":"openai-embeddings-v1","query_prefix":"查询:\n","request_dimensions":null}"#;

    /// SHA-256 of [`GOLD_DESCRIPTOR_JSON`], computed externally.
    const GOLD_DESCRIPTOR_SHA256: &str =
        "13c13b42236318b0902afa0a96973a2c2043fa6fab992e32ece2727f3c25503e";

    /// SHA-256 of [`GOLD_RECORD_JSON`], computed externally.
    const GOLD_RECORD_SHA256: &str =
        "ef62cd189e73bb7494459fd6d65bd78c3772d52b4364ae72d77490f280be5db0";

    /// The canonical bytes of the record that pins the golden descriptor to
    /// generation 7, written out by hand.
    const GOLD_RECORD_JSON: &str = r#"{"descriptor":{"canonicalize_version":3,"chunking_version":1,"document_prefix":"","domain":"cass.api-representation/1","effective_dimension":1024,"model":"vendor-x/模型-甲","model_revision":"rev-字","normalization":"l2","protocol":"openai-embeddings-v1","query_prefix":"查询:\n","request_dimensions":null},"descriptor_sha256":"13c13b42236318b0902afa0a96973a2c2043fa6fab992e32ece2727f3c25503e","generation_id":7,"version":1}"#;

    /// A complete, valid descriptor document that every negative case edits.
    const VALID_DESCRIPTOR_DOC: &str = r#"{"canonicalize_version":3,"chunking_version":1,"document_prefix":"","domain":"cass.api-representation/1","effective_dimension":1024,"model":"vendor-x/alpha","model_revision":"rev-1","normalization":"l2","protocol":"openai-embeddings-v1","query_prefix":"","request_dimensions":null}"#;

    /// A one-profile embedding document at `endpoint`; `body` supplies the
    /// profile's own keys.
    fn one_profile_at(endpoint: &str, body: &str) -> String {
        format!(
            "version = 1\n\
             [profiles.p1]\n\
             kind = \"embedding\"\n\
             endpoint = \"{endpoint}\"\n\
             scope = \"loopback\"\n\
             {body}"
        )
    }

    /// A one-profile embedding document at the default loopback endpoint.
    fn one_profile(body: &str) -> String {
        one_profile_at("http://127.0.0.1:9100/v1/embeddings", body)
    }

    /// The default semantic keys of a fixture profile, with `extra` appended.
    fn default_body(extra: &str) -> String {
        body_with(
            "openai-embeddings-v1",
            "vendor-x/alpha",
            "rev-1",
            "l2",
            extra,
        )
    }

    /// A fixture profile body with every semantic key chosen by the caller.
    fn body_with(
        protocol: &str,
        model: &str,
        revision: &str,
        normalization: &str,
        extra: &str,
    ) -> String {
        format!(
            "protocol = \"{protocol}\"\n\
             model = \"{model}\"\n\
             model_revision = \"{revision}\"\n\
             normalization = \"{normalization}\"\n\
             {extra}"
        )
    }

    /// The default document, with `extra` appended to the profile.
    fn document(extra: &str) -> String {
        one_profile(&default_body(extra))
    }

    /// The profile named `id` in a document parsed from `text`.
    fn profile(text: &str, id: &str) -> ValidatedProfile {
        ApiConfig::parse_toml(text)
            .expect("fixture config must validate")
            .profile(id)
            .expect("fixture profile must exist")
            .clone()
    }

    /// The descriptor of the one-profile document `text` at `dimension`.
    fn descriptor_of(text: &str, dimension: u64) -> RepresentationDescriptor {
        RepresentationDescriptor::from_profile(&profile(text, "p1"), dimension)
            .expect("fixture descriptor must build")
    }

    /// The descriptor of the default document with `extra`, at `dimension`.
    fn descriptor(extra: &str, dimension: u64) -> RepresentationDescriptor {
        descriptor_of(&document(extra), dimension)
    }

    /// The descriptor of a document whose semantic keys are all chosen here.
    fn custom_descriptor(
        protocol: &str,
        model: &str,
        revision: &str,
        normalization: &str,
        extra: &str,
        dimension: u64,
    ) -> RepresentationDescriptor {
        descriptor_of(
            &one_profile(&body_with(protocol, model, revision, normalization, extra)),
            dimension,
        )
    }

    /// The profile that reproduces the golden bytes at width 1024.
    fn gold_profile() -> ValidatedProfile {
        profile(
            &one_profile(&body_with(
                "openai-embeddings-v1",
                "vendor-x/模型-甲",
                "rev-字",
                "l2",
                "expected_dimension = 1024\nquery_prefix = \"查询:\\n\"\n",
            )),
            "p1",
        )
    }

    /// The golden descriptor, built from the golden profile.
    fn gold_descriptor() -> RepresentationDescriptor {
        RepresentationDescriptor::from_profile(&gold_profile(), 1024)
            .expect("gold descriptor builds")
    }

    /// A descriptor rejection.
    fn refused(bytes: &str) -> IdentityError {
        RepresentationDescriptor::decode(bytes.as_bytes()).expect_err("must be refused")
    }

    /// A record rejection.
    fn refused_record(bytes: &str) -> IdentityError {
        RepresentationRecord::decode(bytes.as_bytes()).expect_err("must be refused")
    }

    /// A valid record document with each field spelled by the caller.
    fn record_json(generation: &str, digest: &str, version: &str) -> String {
        format!(
            "{{\"descriptor\":{GOLD_DESCRIPTOR_JSON},\"descriptor_sha256\":\"{digest}\",\
             \"generation_id\":{generation},\"version\":{version}}}"
        )
    }

    // ---- golden bytes -------------------------------------------------------

    #[test]
    fn gold_constants_agree_with_each_other() {
        // The digest is of the literal bytes above, so the constants cannot
        // drift apart without this failing.
        assert_eq!(
            hex::encode(Sha256::digest(GOLD_DESCRIPTOR_JSON.as_bytes())),
            GOLD_DESCRIPTOR_SHA256
        );
        assert_eq!(
            hex::encode(Sha256::digest(GOLD_RECORD_JSON.as_bytes())),
            GOLD_RECORD_SHA256
        );
        assert!(!GOLD_DESCRIPTOR_JSON.ends_with('\n'));
        assert!(!GOLD_RECORD_JSON.ends_with('\n'));
    }

    #[test]
    fn the_golden_descriptor_encodes_and_decodes_to_its_bytes() {
        let descriptor = gold_descriptor();
        assert_eq!(
            String::from_utf8(descriptor.canonical_bytes()).expect("utf8"),
            GOLD_DESCRIPTOR_JSON
        );
        assert_eq!(descriptor.sha256(), GOLD_DESCRIPTOR_SHA256);
        assert_eq!(
            descriptor.embedder_id(),
            format!("api:{GOLD_DESCRIPTOR_SHA256}")
        );
        assert_eq!(descriptor.effective_dimension(), 1024);
        assert_eq!(descriptor.model(), "vendor-x/模型-甲");
        assert_eq!(descriptor.model_revision(), "rev-字");
        assert_eq!(descriptor.query_prefix(), "查询:\n");
        assert_eq!(descriptor.document_prefix(), "");
        assert_eq!(descriptor.request_dimensions(), None);
        assert_eq!(
            descriptor.canonicalize_version(),
            CANONICALIZE_PIPELINE_VERSION
        );
        assert_eq!(descriptor.chunking_version(), CHUNKING_POLICY_VERSION);

        assert_eq!(
            RepresentationDescriptor::decode(GOLD_DESCRIPTOR_JSON.as_bytes()).expect("decodes"),
            descriptor
        );
    }

    #[test]
    fn the_golden_record_encodes_and_decodes_to_its_bytes() {
        let descriptor = gold_descriptor();
        let record = RepresentationRecord::new(descriptor.clone(), 7).expect("record builds");

        assert_eq!(
            String::from_utf8(record.canonical_bytes()).expect("utf8"),
            GOLD_RECORD_JSON
        );
        assert_eq!(record.descriptor_sha256(), GOLD_DESCRIPTOR_SHA256);
        assert_eq!(record.generation_id(), 7);
        assert_eq!(record.version(), 1);
        assert_eq!(record.meta_key(), "api_representation:v1:7");
        assert_eq!(
            record.embedder_id(),
            format!("api:{GOLD_DESCRIPTOR_SHA256}")
        );

        let reopened = RepresentationRecord::decode(GOLD_RECORD_JSON.as_bytes()).expect("decodes");
        assert_eq!(reopened, record);
        assert_eq!(reopened.descriptor(), &descriptor);
    }

    // ---- identity is the whole tuple, not the width ------------------------

    #[test]
    fn two_legal_spaces_build_and_differ() {
        let first = descriptor("expected_dimension = 1024\n", 1024);
        let second = descriptor_of(
            &one_profile(&body_with(
                "openrouter-embeddings-v1",
                "vendor-y/beta",
                "rev-9",
                "none",
                "provider_only = \"vendor-y\"\nexpected_dimension = 768\n",
            )),
            768,
        );

        assert_eq!(first.effective_dimension(), 1024);
        assert_eq!(second.effective_dimension(), 768);
        assert_eq!(second.protocol(), ApiProtocol::OpenRouterEmbeddingsV1);
        assert_eq!(second.normalization(), Normalization::None);
        assert_ne!(first.sha256(), second.sha256());
        assert!(!first.is_equivalent_to(&second));
    }

    #[test]
    fn every_semantic_field_changes_the_identity() {
        let base = descriptor("expected_dimension = 1024\n", 1024);
        let base_sha = base.sha256();

        let variants = [
            descriptor("expected_dimension = 1024\nquery_prefix = \"q: \"\n", 1024),
            descriptor(
                "expected_dimension = 1024\ndocument_prefix = \"d: \"\n",
                1024,
            ),
            custom_descriptor(
                "openai-embeddings-v1",
                "vendor-x/alpha",
                "rev-1",
                "none",
                "expected_dimension = 1024\n",
                1024,
            ),
            custom_descriptor(
                "openai-embeddings-v1",
                "vendor-x/alpha",
                "rev-2",
                "l2",
                "expected_dimension = 1024\n",
                1024,
            ),
            descriptor(
                "expected_dimension = 1024\nrequest_dimensions = 1024\n",
                1024,
            ),
            custom_descriptor(
                "openrouter-embeddings-v1",
                "vendor-x/alpha",
                "rev-1",
                "l2",
                "provider_only = \"vendor-x\"\nexpected_dimension = 1024\n",
                1024,
            ),
            custom_descriptor(
                "openai-embeddings-v1",
                "vendor-x/other",
                "rev-1",
                "l2",
                "expected_dimension = 1024\n",
                1024,
            ),
            descriptor("expected_dimension = 512\n", 512),
        ];

        for (index, variant) in variants.iter().enumerate() {
            assert_ne!(
                variant.sha256(),
                base_sha,
                "variant {index} must move the identity"
            );
            assert!(!base.is_equivalent_to(variant), "variant {index}");
        }
    }

    #[test]
    fn relocation_and_credential_rotation_keep_the_identity() {
        let first = descriptor("expected_dimension = 1024\n", 1024);
        // Same semantic keys, a different port, a credential variable and
        // different budgets.
        let moved = descriptor_of(
            &one_profile_at(
                "http://127.0.0.1:9201/v1/embeddings",
                &default_body(
                    "api_key_env = \"CASS_TEST_TOKEN\"\n\
                     connect_timeout_ms = 1500\n\
                     timeout_ms = 9000\n\
                     max_response_bytes = 1048576\n\
                     expected_dimension = 1024\n",
                ),
            ),
            1024,
        );

        assert_eq!(first.sha256(), moved.sha256());
        assert!(first.is_equivalent_to(&moved));
        assert_eq!(first.canonical_bytes(), moved.canonical_bytes());
    }

    #[test]
    fn the_profile_display_name_does_not_change_the_identity() {
        let first = descriptor("expected_dimension = 1024\n", 1024);

        let renamed_document = "version = 1\n\
             [profiles.renamed]\n\
             kind = \"embedding\"\n\
             endpoint = \"http://127.0.0.1:9100/v1/embeddings\"\n\
             scope = \"loopback\"\n\
             protocol = \"openai-embeddings-v1\"\n\
             model = \"vendor-x/alpha\"\n\
             model_revision = \"rev-1\"\n\
             normalization = \"l2\"\n\
             expected_dimension = 1024\n";
        let renamed =
            RepresentationDescriptor::from_profile(&profile(renamed_document, "renamed"), 1024)
                .expect("renamed descriptor builds");

        assert_eq!(first.sha256(), renamed.sha256());
        assert!(first.is_equivalent_to(&renamed));
    }

    #[test]
    fn a_shared_width_with_a_different_tuple_is_not_equivalent() {
        let plain = descriptor("expected_dimension = 1024\n", 1024);
        let prefixed = descriptor(
            "expected_dimension = 1024\nquery_prefix = \"query: \"\n",
            1024,
        );
        let requested = descriptor(
            "expected_dimension = 1024\nrequest_dimensions = 1024\n",
            1024,
        );

        assert_eq!(plain.effective_dimension(), requested.effective_dimension());
        assert_ne!(plain.sha256(), prefixed.sha256());
        assert_ne!(plain.sha256(), requested.sha256());
        assert!(!plain.is_equivalent_to(&prefixed));
        assert!(!plain.is_equivalent_to(&requested));
        assert_eq!(plain.request_dimensions(), None);
        assert_eq!(requested.request_dimensions(), Some(1024));
    }

    #[test]
    fn a_configured_width_that_contradicts_the_observation_is_refused() {
        let expected = profile(&document("expected_dimension = 1024\n"), "p1");
        assert_eq!(
            RepresentationDescriptor::from_profile(&expected, 768)
                .expect_err("width conflict")
                .code(),
            IdentityErrorCode::IdentityMismatch
        );

        let requested = profile(&document("request_dimensions = 1024\n"), "p1");
        assert_eq!(
            RepresentationDescriptor::from_profile(&requested, 768)
                .expect_err("requested width conflict")
                .code(),
            IdentityErrorCode::IdentityMismatch
        );

        assert_eq!(
            RepresentationDescriptor::from_profile(&expected, 0)
                .expect_err("zero width")
                .code(),
            IdentityErrorCode::InvalidDescriptor
        );
    }

    #[test]
    fn a_rerank_profile_is_a_wrong_kind() {
        let rerank = profile(
            "version = 1\n\
             [profiles.p1]\n\
             kind = \"rerank\"\n\
             protocol = \"rerank-json-v1\"\n\
             endpoint = \"http://127.0.0.1:9200/score\"\n\
             scope = \"loopback\"\n\
             model = \"vendor-b/ranker\"\n\
             model_revision = \"rev-b\"\n",
            "p1",
        );
        assert_eq!(
            RepresentationDescriptor::from_profile(&rerank, 1024)
                .expect_err("rerank profile")
                .code(),
            IdentityErrorCode::WrongKind
        );
    }

    // ---- strict decoding ----------------------------------------------------

    #[test]
    fn the_valid_document_helper_really_validates() {
        assert!(RepresentationDescriptor::decode(VALID_DESCRIPTOR_DOC.as_bytes()).is_ok());
    }

    #[test]
    fn a_duplicate_descriptor_key_is_refused_even_when_escaped() {
        let duplicated = VALID_DESCRIPTOR_DOC.replace(
            "\"normalization\":\"l2\"",
            "\"normalization\":\"l2\",\"normalization\":\"none\"",
        );
        assert_eq!(
            refused(&duplicated).code(),
            IdentityErrorCode::InvalidDescriptor
        );

        // The second key only collides after unescaping.
        let escaped = VALID_DESCRIPTOR_DOC.replace(
            "\"normalization\":\"l2\"",
            "\"normalization\":\"l2\",\"normalizatio\\u006e\":\"none\"",
        );
        assert_eq!(
            refused(&escaped).code(),
            IdentityErrorCode::InvalidDescriptor
        );
    }

    #[test]
    fn unknown_and_missing_descriptor_keys_are_refused() {
        let unknown = VALID_DESCRIPTOR_DOC.replace(
            "\"request_dimensions\":null}",
            "\"request_dimensions\":null,\"endpoint\":\"http://x/\"}",
        );
        assert_eq!(
            refused(&unknown).code(),
            IdentityErrorCode::InvalidDescriptor
        );

        let missing = VALID_DESCRIPTOR_DOC.replace(",\"query_prefix\":\"\"", "");
        assert_eq!(
            refused(&missing).code(),
            IdentityErrorCode::InvalidDescriptor
        );

        assert_eq!(refused("{}").code(), IdentityErrorCode::InvalidDescriptor);
    }

    #[test]
    fn request_dimensions_must_be_present_and_typed() {
        let null_form = VALID_DESCRIPTOR_DOC;
        let descriptor =
            RepresentationDescriptor::decode(null_form.as_bytes()).expect("null form is legal");
        assert_eq!(descriptor.request_dimensions(), None);

        let some_form = VALID_DESCRIPTOR_DOC
            .replace("\"request_dimensions\":null", "\"request_dimensions\":1024");
        let descriptor =
            RepresentationDescriptor::decode(some_form.as_bytes()).expect("set form is legal");
        assert_eq!(descriptor.request_dimensions(), Some(1024));

        for bad in [
            "0",
            "1024.0",
            "1e3",
            "\"1024\"",
            "true",
            "-1024",
            "18446744073709551616",
        ] {
            let text = VALID_DESCRIPTOR_DOC.replace(
                "\"request_dimensions\":null",
                &format!("\"request_dimensions\":{bad}"),
            );
            assert_eq!(
                refused(&text).code(),
                IdentityErrorCode::InvalidDescriptor,
                "must refuse request_dimensions {bad}"
            );
        }
    }

    #[test]
    fn mistyped_and_out_of_range_descriptor_numbers_are_refused() {
        let cases: &[(&str, &str)] = &[
            ("\"canonicalize_version\":3", "\"canonicalize_version\":3.0"),
            (
                "\"canonicalize_version\":3",
                "\"canonicalize_version\":\"3\"",
            ),
            (
                "\"canonicalize_version\":3",
                "\"canonicalize_version\":true",
            ),
            (
                "\"canonicalize_version\":3",
                "\"canonicalize_version\":4294967296",
            ),
            ("\"canonicalize_version\":3", "\"canonicalize_version\":-1"),
            ("\"canonicalize_version\":3", "\"canonicalize_version\":0"),
            ("\"chunking_version\":1", "\"chunking_version\":1e2"),
            ("\"chunking_version\":1", "\"chunking_version\":0"),
            (
                "\"effective_dimension\":1024",
                "\"effective_dimension\":1024.5",
            ),
            (
                "\"effective_dimension\":1024",
                "\"effective_dimension\":\"1024\"",
            ),
            (
                "\"effective_dimension\":1024",
                "\"effective_dimension\":18446744073709551616",
            ),
            ("\"effective_dimension\":1024", "\"effective_dimension\":0"),
            ("\"effective_dimension\":1024", "\"effective_dimension\":-1"),
        ];

        for (needle, replacement) in cases {
            let text = VALID_DESCRIPTOR_DOC.replace(needle, replacement);
            assert_ne!(
                text, VALID_DESCRIPTOR_DOC,
                "needle {needle} must occur once"
            );
            assert_eq!(
                refused(&text).code(),
                IdentityErrorCode::InvalidDescriptor,
                "must refuse {replacement}"
            );
        }
    }

    #[test]
    fn descriptor_field_values_are_checked() {
        let cases: &[(&str, &str, IdentityErrorCode)] = &[
            (
                "\"domain\":\"cass.api-representation/1\"",
                "\"domain\":\"cass.api-representation/0\"",
                IdentityErrorCode::InvalidDescriptor,
            ),
            (
                "\"model\":\"vendor-x/alpha\"",
                "\"model\":\"\"",
                IdentityErrorCode::InvalidDescriptor,
            ),
            (
                "\"model_revision\":\"rev-1\"",
                "\"model_revision\":\"\"",
                IdentityErrorCode::InvalidDescriptor,
            ),
            (
                "\"normalization\":\"l2\"",
                "\"normalization\":\"cosine\"",
                IdentityErrorCode::InvalidDescriptor,
            ),
            (
                "\"protocol\":\"openai-embeddings-v1\"",
                "\"protocol\":\"rerank-json-v1\"",
                IdentityErrorCode::WrongKind,
            ),
            (
                "\"protocol\":\"openai-embeddings-v1\"",
                "\"protocol\":\"openrouter-rerank-v1\"",
                IdentityErrorCode::WrongKind,
            ),
            (
                "\"protocol\":\"openai-embeddings-v1\"",
                "\"protocol\":\"openai-embeddings-v2\"",
                IdentityErrorCode::InvalidDescriptor,
            ),
        ];

        for (needle, replacement, code) in cases {
            let text = VALID_DESCRIPTOR_DOC.replace(needle, replacement);
            assert_ne!(
                text, VALID_DESCRIPTOR_DOC,
                "needle {needle} must occur once"
            );
            assert_eq!(refused(&text).code(), *code, "must refuse {replacement}");
        }
    }

    #[test]
    fn trailing_data_and_malformed_bytes_are_refused() {
        let valid = GOLD_DESCRIPTOR_JSON;

        // Trailing whitespace is legal JSON padding.
        assert!(RepresentationDescriptor::decode(format!("{valid}   \n ").as_bytes()).is_ok());
        assert!(RepresentationDescriptor::decode(format!(" {valid}").as_bytes()).is_ok());

        // A second value after the object is not.
        for trailer in [" {}", " null", " 3", "[]"] {
            assert_eq!(
                refused(&format!("{valid}{trailer}")).code(),
                IdentityErrorCode::InvalidDescriptor,
                "must refuse a trailing {trailer}"
            );
        }

        // Not an object at all.
        for text in ["[]", "\"descriptor\"", "3", "null", "{"] {
            assert_eq!(refused(text).code(), IdentityErrorCode::InvalidDescriptor);
        }

        // Bytes that are not UTF-8: first as trailing garbage, then inside a
        // string value.
        let mut trailing_bad_byte = valid.as_bytes().to_vec();
        trailing_bad_byte.extend_from_slice(&[b' ', 0xff, b'}']);
        assert!(RepresentationDescriptor::decode(&trailing_bad_byte).is_err());

        let mut value_bad_byte = Vec::new();
        value_bad_byte.extend_from_slice(
            b"{\"canonicalize_version\":3,\"chunking_version\":1,\"document_prefix\":\"",
        );
        value_bad_byte.push(0xff);
        value_bad_byte.extend_from_slice(
            b"\",\"domain\":\"cass.api-representation/1\",\"effective_dimension\":1024,\
              \"model\":\"m\",\"model_revision\":\"r\",\"normalization\":\"l2\",\
              \"protocol\":\"openai-embeddings-v1\",\"query_prefix\":\"\",\
              \"request_dimensions\":null}",
        );
        assert!(RepresentationDescriptor::decode(&value_bad_byte).is_err());
    }

    #[test]
    fn control_characters_survive_the_round_trip() {
        let descriptor = descriptor(
            "query_prefix = \"a\\u0001b\\u001fc\"\nexpected_dimension = 1024\n",
            1024,
        );
        assert_eq!(descriptor.query_prefix(), "a\u{1}b\u{1f}c");

        let bytes = descriptor.canonical_bytes();
        // `serde_json` escapes a control character and leaves it escaped.
        let text = String::from_utf8(bytes.clone()).expect("utf8");
        assert!(text.contains("\\u0001"));
        assert!(text.contains("\\u001f"));
        assert_eq!(
            RepresentationDescriptor::decode(&bytes).expect("decodes"),
            descriptor
        );
    }

    // ---- record rules -------------------------------------------------------

    #[test]
    fn a_future_record_version_is_unsupported() {
        assert_eq!(
            refused_record(&record_json("7", GOLD_DESCRIPTOR_SHA256, "2")).code(),
            IdentityErrorCode::UnsupportedVersion
        );
        assert_eq!(
            refused_record(&record_json("7", GOLD_DESCRIPTOR_SHA256, "0")).code(),
            IdentityErrorCode::UnsupportedVersion
        );
        assert_eq!(
            refused_record(&record_json("7", GOLD_DESCRIPTOR_SHA256, "1.0")).code(),
            IdentityErrorCode::InvalidRecord
        );
    }

    #[test]
    fn generation_bounds_and_digest_shape_are_enforced() {
        assert_eq!(
            refused_record(&record_json("0", GOLD_DESCRIPTOR_SHA256, "1")).code(),
            IdentityErrorCode::InvalidRecord
        );
        assert_eq!(
            refused_record(&record_json("-1", GOLD_DESCRIPTOR_SHA256, "1")).code(),
            IdentityErrorCode::InvalidRecord
        );
        // One past `i64::MAX` does not fit the declared width at all.
        assert_eq!(
            refused_record(&record_json(
                "9223372036854775808",
                GOLD_DESCRIPTOR_SHA256,
                "1"
            ))
            .code(),
            IdentityErrorCode::InvalidRecord
        );
        assert_eq!(
            refused_record(&record_json("7.0", GOLD_DESCRIPTOR_SHA256, "1")).code(),
            IdentityErrorCode::InvalidRecord
        );

        // `i64::MAX` itself is a legal generation.
        let maximal = record_json("9223372036854775807", GOLD_DESCRIPTOR_SHA256, "1");
        let record = RepresentationRecord::decode(maximal.as_bytes()).expect("max generation");
        assert_eq!(record.generation_id(), i64::MAX);
        assert_eq!(
            record.meta_key(),
            "api_representation:v1:9223372036854775807"
        );

        // One digest, one spelling: uppercase and short forms are refused.
        let uppercase = GOLD_DESCRIPTOR_SHA256.to_uppercase();
        assert_eq!(
            refused_record(&record_json("7", &uppercase, "1")).code(),
            IdentityErrorCode::InvalidRecord
        );
        assert_eq!(
            refused_record(&record_json("7", &GOLD_DESCRIPTOR_SHA256[..63], "1")).code(),
            IdentityErrorCode::InvalidRecord
        );
        assert_eq!(
            refused_record(&record_json("7", &"z".repeat(64), "1")).code(),
            IdentityErrorCode::InvalidRecord
        );
    }

    #[test]
    fn a_digest_that_does_not_match_its_descriptor_is_refused() {
        let wrong = "0".repeat(64);
        assert_eq!(
            refused_record(&record_json("7", &wrong, "1")).code(),
            IdentityErrorCode::IdentityMismatch
        );
    }

    #[test]
    fn record_structure_is_strict() {
        let unknown = record_json("7", GOLD_DESCRIPTOR_SHA256, "1")
            .replace("\"version\":1}", "\"version\":1,\"extra\":1}");
        assert_eq!(
            refused_record(&unknown).code(),
            IdentityErrorCode::InvalidRecord
        );

        let duplicated = record_json("7", GOLD_DESCRIPTOR_SHA256, "1").replace(
            "\"generation_id\":7",
            "\"generation_id\":7,\"generation_id\":7",
        );
        assert_eq!(
            refused_record(&duplicated).code(),
            IdentityErrorCode::InvalidRecord
        );

        let missing =
            record_json("7", GOLD_DESCRIPTOR_SHA256, "1").replace(",\"generation_id\":7", "");
        assert_eq!(
            refused_record(&missing).code(),
            IdentityErrorCode::InvalidRecord
        );

        assert_eq!(
            refused_record("[]").code(),
            IdentityErrorCode::InvalidRecord
        );
    }

    #[test]
    fn a_malformed_nested_descriptor_is_attributed_to_the_descriptor() {
        let duplicated_inner = GOLD_RECORD_JSON.replace(
            "\"canonicalize_version\":3",
            "\"canonicalize_version\":3,\"canonicalize_version\":3",
        );
        assert_eq!(
            refused_record(&duplicated_inner).code(),
            IdentityErrorCode::InvalidDescriptor
        );

        let mistyped_inner = GOLD_RECORD_JSON.replace(
            "\"canonicalize_version\":3",
            "\"canonicalize_version\":\"3\"",
        );
        assert_eq!(
            refused_record(&mistyped_inner).code(),
            IdentityErrorCode::InvalidDescriptor
        );

        let unknown_inner = GOLD_RECORD_JSON.replace(
            "\"domain\":\"cass.api-representation/1\"",
            "\"domain\":\"cass.api-representation/1\",\"endpoint\":\"x\"",
        );
        assert_eq!(
            refused_record(&unknown_inner).code(),
            IdentityErrorCode::InvalidDescriptor
        );
    }

    #[test]
    fn decode_matching_requires_all_three_expectations() {
        let descriptor = gold_descriptor();
        let record = RepresentationRecord::new(descriptor.clone(), 7).expect("record builds");
        let bytes = record.canonical_bytes();
        let embedder_id = descriptor.embedder_id();

        let reopened = RepresentationRecord::decode_matching(&bytes, 7, &embedder_id, 1024)
            .expect("matching record");
        assert_eq!(reopened, record);

        assert_eq!(
            RepresentationRecord::decode_matching(&bytes, 8, &embedder_id, 1024)
                .expect_err("wrong generation")
                .code(),
            IdentityErrorCode::IdentityMismatch
        );
        assert_eq!(
            RepresentationRecord::decode_matching(
                &bytes,
                7,
                &format!("api:{}", "0".repeat(64)),
                1024
            )
            .expect_err("wrong embedder id")
            .code(),
            IdentityErrorCode::IdentityMismatch
        );
        assert_eq!(
            RepresentationRecord::decode_matching(&bytes, 7, &embedder_id, 768)
                .expect_err("wrong dimension")
                .code(),
            IdentityErrorCode::IdentityMismatch
        );
    }

    #[test]
    fn a_record_with_a_zero_generation_is_never_built() {
        let descriptor = gold_descriptor();
        assert_eq!(
            RepresentationRecord::new(descriptor.clone(), 0)
                .expect_err("zero generation")
                .code(),
            IdentityErrorCode::InvalidRecord
        );
        assert_eq!(
            RepresentationRecord::new(descriptor, -1)
                .expect_err("negative generation")
                .code(),
            IdentityErrorCode::InvalidRecord
        );
    }

    // ---- reopen -------------------------------------------------------------

    #[test]
    fn a_record_reopens_from_its_saved_bytes() {
        let descriptor = gold_descriptor();
        let record = RepresentationRecord::new(descriptor, 7).expect("record builds");

        // "Close and reopen" is: keep the bytes, build a fresh value from them.
        let saved = record.canonical_bytes();
        let reopened = RepresentationRecord::decode(&saved).expect("reopens");
        assert_eq!(reopened, record);
        assert_eq!(reopened.descriptor_sha256(), record.descriptor_sha256());
        assert_eq!(reopened.embedder_id(), record.embedder_id());
        assert_eq!(
            reopened.descriptor().effective_dimension(),
            record.descriptor().effective_dimension()
        );
        assert!(reopened.descriptor().is_equivalent_to(record.descriptor()));
        assert_eq!(reopened.canonical_bytes(), saved);
        assert_eq!(reopened.meta_key(), record.meta_key());
    }

    // ---- errors stay small --------------------------------------------------

    #[test]
    fn errors_never_echo_the_rejected_bytes() {
        const SECRET: &str = "synthetic-secret-token-abc123";
        let documents = [
            VALID_DESCRIPTOR_DOC.replace(
                "\"request_dimensions\":null}",
                &format!("\"request_dimensions\":null,\"{SECRET}\":1}}"),
            ),
            VALID_DESCRIPTOR_DOC.replace(
                "\"normalization\":\"l2\"",
                &format!("\"normalization\":\"{SECRET}\""),
            ),
            VALID_DESCRIPTOR_DOC.replace(
                "\"model\":\"vendor-x/alpha\"",
                &format!("\"model\":\"{SECRET}\""),
            ),
            record_json("7", GOLD_DESCRIPTOR_SHA256, "1")
                .replace("\"version\":1}", &format!("\"version\":1,\"{SECRET}\":1}}")),
            GOLD_RECORD_JSON.replace(
                "\"canonicalize_version\":3",
                &format!("\"canonicalize_version\":3,\"canonicalize_version\":\"{SECRET}\""),
            ),
        ];

        let mut rejections = 0usize;
        for document in &documents {
            for error in [
                RepresentationDescriptor::decode(document.as_bytes()).err(),
                RepresentationRecord::decode(document.as_bytes()).err(),
            ]
            .into_iter()
            .flatten()
            {
                rejections += 1;
                assert!(
                    !error.to_string().contains(SECRET),
                    "Display echoed the input: {error}"
                );
                assert!(
                    !format!("{error:?}").contains(SECRET),
                    "Debug echoed the input"
                );
            }
        }
        assert!(
            rejections >= 5,
            "the negative fixtures must actually reject"
        );
    }

    #[test]
    fn codes_have_stable_unique_names() {
        let all = [
            IdentityErrorCode::WrongKind,
            IdentityErrorCode::InvalidDescriptor,
            IdentityErrorCode::InvalidRecord,
            IdentityErrorCode::UnsupportedVersion,
            IdentityErrorCode::IdentityMismatch,
        ];
        let mut names: Vec<&str> = all.iter().map(|code| code.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "code names must be unique");
        assert_eq!(IdentityErrorCode::WrongKind.as_str(), "WrongKind");
        assert_eq!(
            IdentityErrorCode::IdentityMismatch.as_str(),
            "IdentityMismatch"
        );

        let bare = IdentityError::new(IdentityErrorCode::InvalidRecord);
        assert_eq!(
            bare.to_string(),
            "invalid model api representation identity: InvalidRecord"
        );
        assert_eq!(bare.field(), None);

        let fielded = IdentityError::at(IdentityErrorCode::InvalidDescriptor, "model");
        assert_eq!(
            fielded.to_string(),
            "invalid model api representation identity: InvalidDescriptor (model)"
        );
        assert_eq!(fielded.field(), Some("model"));

        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&bare);
    }

    #[test]
    fn the_domain_tag_is_pinned() {
        assert_eq!(REPRESENTATION_DOMAIN, "cass.api-representation/1");
        assert_eq!(REPRESENTATION_RECORD_VERSION, 1);
        assert!(GOLD_DESCRIPTOR_JSON.contains("\"domain\":\"cass.api-representation/1\""));
    }
}
