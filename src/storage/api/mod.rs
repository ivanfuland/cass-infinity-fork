//! storage::api — backend-agnostic facade over the relational storage layer.

mod error;
mod value;

pub use error::{BusyScope, StorageError};
pub use value::{FromValue, IntoValue, Value};
