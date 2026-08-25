//! Backend-agnostic storage error types for storage::api.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BusyScope {
    Statement,
    Snapshot,
}

#[derive(Debug)]
pub enum StorageError {
    Busy { scope: BusyScope },
    Locked,
    Corrupt { detail: String },
    Constraint { detail: String },
    Other { code: Option<i32>, detail: String },
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::Busy { scope: BusyScope::Statement } => {
                write!(f, "storage busy (statement)")
            }
            StorageError::Busy { scope: BusyScope::Snapshot } => {
                write!(f, "storage busy (snapshot)")
            }
            StorageError::Locked => write!(f, "storage locked"),
            StorageError::Corrupt { detail } => write!(f, "storage corrupt: {detail}"),
            StorageError::Constraint { detail } => write!(f, "constraint violation: {detail}"),
            StorageError::Other { code: Some(c), detail } => {
                write!(f, "storage error [{c}]: {detail}")
            }
            StorageError::Other { code: None, detail } => write!(f, "storage error: {detail}"),
        }
    }
}

impl std::error::Error for StorageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_error_display_variants() {
        assert_eq!(format!("{}", StorageError::Locked), "storage locked");
        assert_eq!(
            format!("{}", StorageError::Busy { scope: BusyScope::Snapshot }),
            "storage busy (snapshot)"
        );
        assert_eq!(
            format!("{}", StorageError::Busy { scope: BusyScope::Statement }),
            "storage busy (statement)"
        );
        assert!(
            format!("{}", StorageError::Corrupt { detail: "page 3 bad".into() })
                .contains("page 3 bad")
        );
        assert!(
            format!("{}", StorageError::Constraint { detail: "UNIQUE".into() })
                .contains("UNIQUE")
        );
        assert!(
            format!("{}", StorageError::Other { code: Some(11), detail: "x".into() })
                .contains("11")
        );
    }
}
