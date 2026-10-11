//! Failure codes for the model-service configuration kernel.
//!
//! Every rejection produced by [`crate::search::model_api::config`] is one of
//! the fixed [`ConfigErrorCode`] values below. The set is closed on purpose:
//! callers branch on the code, not on a message, and the code never changes
//! meaning.
//!
//! Nothing here echoes the configuration text. A [`ConfigError`] carries only a
//! code plus, when our own validation knows it, the *name* of the offending
//! field drawn from a compile-time constant list — never a value, never a URL,
//! never a credential and never a fragment of the parsed TOML. `Display` and
//! `Debug` are therefore safe to log.

use std::fmt;

/// The closed set of reasons a model-service configuration is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigErrorCode {
    /// The text is not valid TOML, or the TOML structure cannot be read at all.
    ///
    /// Duplicate keys are rejected here: TOML itself refuses a repeated key, so
    /// a duplicated field or a duplicated profile id never reaches validation.
    InvalidToml,
    /// The top-level `version` is present but not the one version this build
    /// understands.
    UnsupportedVersion,
    /// A required key is absent.
    MissingField,
    /// A key that this schema does not define is present.
    UnknownField,
    /// A value is present and readable but not acceptable (wrong type, empty
    /// where content is required, out of range, or a field that does not belong
    /// to the declared `kind`).
    InvalidValue,
    /// A profile id is not a 1–64 byte ASCII name over `[A-Za-z0-9._-]`.
    InvalidProfileId,
    /// An endpoint URL fails the static scheme/origin/userinfo/fragment/scope
    /// rules. No request is made and no name is resolved to check this.
    InvalidEndpoint,
    /// A reference such as `default_embedding` or `fallback_profile` names a
    /// profile that the document does not define.
    InvalidReference,
    /// A `kind` and a `protocol`, or a default and its profile, disagree about
    /// whether the profile is an embedding or a rerank profile.
    KindMismatch,
    /// The `fallback_profile` graph is malformed: a non-loopback primary, a
    /// non-remote target, a self reference, a target that itself declares a
    /// fallback, a missing cloud provider restriction, or a fallback field on a
    /// profile that declares no fallback.
    InvalidFallback,
    /// A rerank primary and its fallback do not agree on the instruction under
    /// the strict `Option<String>` rule.
    InstructionMismatch,
}

impl ConfigErrorCode {
    /// The stable wire name of this code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidToml => "InvalidToml",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::MissingField => "MissingField",
            Self::UnknownField => "UnknownField",
            Self::InvalidValue => "InvalidValue",
            Self::InvalidProfileId => "InvalidProfileId",
            Self::InvalidEndpoint => "InvalidEndpoint",
            Self::InvalidReference => "InvalidReference",
            Self::KindMismatch => "KindMismatch",
            Self::InvalidFallback => "InvalidFallback",
            Self::InstructionMismatch => "InstructionMismatch",
        }
    }
}

impl fmt::Display for ConfigErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused model-service configuration.
///
/// The payload is a code and, at most, the static name of a schema field. It is
/// deliberately too small to carry any part of the rejected document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    code: ConfigErrorCode,
    field: Option<&'static str>,
}

impl ConfigError {
    /// A rejection that names no particular field.
    pub const fn new(code: ConfigErrorCode) -> Self {
        Self { code, field: None }
    }

    /// A rejection attributed to one schema field.
    ///
    /// `field` must be a compile-time constant from this schema, never text
    /// taken from the parsed document.
    pub const fn at(code: ConfigErrorCode, field: &'static str) -> Self {
        Self {
            code,
            field: Some(field),
        }
    }

    /// The stable reason code.
    pub const fn code(&self) -> ConfigErrorCode {
        self.code
    }

    /// The schema field this rejection is attributed to, when known.
    pub const fn field(&self) -> Option<&'static str> {
        self.field
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.field {
            Some(field) => write!(
                f,
                "invalid model service config: {} ({field})",
                self.code.as_str()
            ),
            None => write!(f, "invalid model service config: {}", self.code.as_str()),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_wire_names_are_stable_and_unique() {
        let all = [
            ConfigErrorCode::InvalidToml,
            ConfigErrorCode::UnsupportedVersion,
            ConfigErrorCode::MissingField,
            ConfigErrorCode::UnknownField,
            ConfigErrorCode::InvalidValue,
            ConfigErrorCode::InvalidProfileId,
            ConfigErrorCode::InvalidEndpoint,
            ConfigErrorCode::InvalidReference,
            ConfigErrorCode::KindMismatch,
            ConfigErrorCode::InvalidFallback,
            ConfigErrorCode::InstructionMismatch,
        ];
        let mut names: Vec<&str> = all.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(names.len(), before, "code names must be unique");
        assert_eq!(ConfigErrorCode::InvalidToml.as_str(), "InvalidToml");
        assert_eq!(ConfigErrorCode::MissingField.as_str(), "MissingField");
    }

    #[test]
    fn display_carries_no_document_text() {
        let err = ConfigError::at(ConfigErrorCode::InvalidEndpoint, "endpoint");
        assert_eq!(
            err.to_string(),
            "invalid model service config: InvalidEndpoint (endpoint)"
        );
        assert_eq!(err.code(), ConfigErrorCode::InvalidEndpoint);
        assert_eq!(err.field(), Some("endpoint"));

        let bare = ConfigError::new(ConfigErrorCode::InvalidToml);
        assert_eq!(
            bare.to_string(),
            "invalid model service config: InvalidToml"
        );
        assert_eq!(bare.field(), None);
    }

    #[test]
    fn error_is_usable_as_a_std_error() {
        fn assert_error<E: std::error::Error>(_: &E) {}
        assert_error(&ConfigError::new(ConfigErrorCode::InvalidValue));
    }
}
