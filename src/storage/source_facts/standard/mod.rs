//! Public standard-fact DTOs (Task10 C1 v2).
//!
//! These types are the frozen wire shape that tickets 11/12 consume. This
//! module defines and serialises the DTOs and exposes the four public scalar
//! primitives (`count_fact`, `time_fact`, `value_fact`, `alias_fact`); it
//! implements no extraction, no source-event mapping, no export and no
//! recovery. Every standard value still comes from the source's safe value
//! tree; `FactValue` keeps the three value domains (plain string, boolean,
//! tagged literal tree) and never normalises numbers through `f64` or a plain
//! JSON `Value`.

use std::collections::BTreeMap;
use std::fmt;

use franken_agent_detection::LosslessSourceValue;

mod claude;
mod codex;
mod value;

pub use claude::map_claude_standard;
pub use codex::map_codex_standard;
pub use value::{alias_fact, count_fact, time_fact, value_fact};

use super::SourceFormat;

/// Internal dispatcher: only the two accepted source connectors get their own
/// mapper. Every other stored connector, including the literal indexer alias
/// `claude`, produces no standard facts.
pub(super) fn map_standard(
    connector: &str,
    format: SourceFormat,
    safe_value: &LosslessSourceValue,
) -> Option<StandardFacts> {
    match connector {
        "claude_code" => Some(map_claude_standard(format, safe_value)),
        "codex" => Some(map_codex_standard(format, safe_value)),
        _ => None,
    }
}

/// One fact's settled status. JSON is the lower-case name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FactStatus {
    Present,
    Missing,
    Invalid,
    Conflict,
}

/// The kind of a structured `value`. JSON is the lower-case name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FactValueKind {
    Object,
    Array,
}

/// The unit a numeric fact is expressed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactUnit {
    Count,
    Epoch,
    NumberText,
}

/// A fact value in one of exactly three value domains.
#[derive(Clone, PartialEq, Eq)]
pub enum FactValue {
    /// A plain JSON string.
    String(String),
    /// A plain JSON boolean.
    Boolean(bool),
    /// The original tagged literal tree, byte-for-byte.
    Tree(LosslessSourceValue),
}

impl fmt::Debug for FactValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String(value) => f.debug_tuple("String").field(&value.len()).finish(),
            Self::Boolean(_) => f.write_str("Boolean(..)"),
            Self::Tree(_) => f.write_str("Tree(..)"),
        }
    }
}

impl serde::Serialize for FactValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::String(value) => serializer.serialize_str(value),
            Self::Boolean(value) => serializer.serialize_bool(*value),
            Self::Tree(value) => {
                // `write_tagged` emits the six-tag wire with exact number
                // tokens and original member order. `RawValue` carries those
                // already-serialised bytes so no ordinary `Value`/`f64`
                // round-trip can touch them.
                let mut bytes = Vec::new();
                value
                    .write_tagged(&mut bytes)
                    .map_err(serde::ser::Error::custom)?;
                let text = String::from_utf8(bytes).map_err(serde::ser::Error::custom)?;
                let raw = serde_json::value::RawValue::from_string(text)
                    .map_err(serde::ser::Error::custom)?;
                raw.serialize(serializer)
            }
        }
    }
}

/// One candidate member of a conflicted fact. Same optional members as
/// [`FieldFact`] but without `field`.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct CandidateFact {
    pub status: FactStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<FactValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_kind: Option<FactValueKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<CandidateFact>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<FactUnit>,
}

impl fmt::Debug for CandidateFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CandidateFact")
            .field("status", &self.status)
            .field("has_value", &self.value.is_some())
            .field("refs", &self.refs.as_ref().map_or(0, Vec::len))
            .finish()
    }
}

/// One negotiated field fact.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct FieldFact {
    pub field: String,
    pub status: FactStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<FactValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_kind: Option<FactValueKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<CandidateFact>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<FactUnit>,
}

impl fmt::Debug for FieldFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldFact")
            .field("status", &self.status)
            .field("has_value", &self.value.is_some())
            .field("refs", &self.refs.as_ref().map_or(0, Vec::len))
            .finish()
    }
}

/// One tool fact. Its `fields` map is flattened into the object: the members
/// are `kind`, `raw_ref` and one entry per field, never a nested `fields` key.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct ToolFact {
    pub kind: String,
    pub raw_ref: String,
    #[serde(flatten)]
    pub fields: BTreeMap<String, FieldFact>,
}

impl fmt::Debug for ToolFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolFact")
            .field("fields", &self.fields.len())
            .finish()
    }
}

/// One usage snapshot. `fields` keeps its own key.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct UsageSnapshot {
    pub scope: String,
    pub role: String,
    pub raw_ref: String,
    pub fields: BTreeMap<String, FieldFact>,
}

impl fmt::Debug for UsageSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsageSnapshot")
            .field("fields", &self.fields.len())
            .finish()
    }
}

/// One message's fact group. The reference member serialises as `ref`.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct MessageFacts {
    #[serde(rename = "ref")]
    pub reference: String,
    pub model: FieldFact,
    pub ids: BTreeMap<String, FieldFact>,
    pub times: BTreeMap<String, FieldFact>,
    pub role: Vec<FieldFact>,
    pub usage: Vec<UsageSnapshot>,
    pub tools: Vec<ToolFact>,
}

impl fmt::Debug for MessageFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageFacts")
            .field("ids", &self.ids.len())
            .field("times", &self.times.len())
            .field("role", &self.role.len())
            .field("usage", &self.usage.len())
            .field("tools", &self.tools.len())
            .finish()
    }
}

/// The seven-root standard fact object. Every root is always serialised, even
/// when empty.
#[derive(Clone, PartialEq, Eq, serde::Serialize)]
pub struct StandardFacts {
    pub model: FieldFact,
    pub provider: FieldFact,
    pub native_ids: BTreeMap<String, FieldFact>,
    pub times: BTreeMap<String, FieldFact>,
    pub tools: Vec<ToolFact>,
    pub usage: Vec<UsageSnapshot>,
    pub messages: Vec<MessageFacts>,
}

impl fmt::Debug for StandardFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StandardFacts")
            .field("native_ids", &self.native_ids.len())
            .field("times", &self.times.len())
            .field("tools", &self.tools.len())
            .field("usage", &self.usage.len())
            .field("messages", &self.messages.len())
            .finish()
    }
}
