//! storage::api — backend-agnostic facade over the relational storage layer.

mod error;
mod value;

pub use error::{BusyScope, StorageError};
pub use value::{FromValue, IntoValue, Value};

/// Build a `[Value; N]` from expressions, each converted via [`IntoValue`].
/// Empty parameter lists use a bare `&[]` at the call site instead (no macro needed —
/// `&[Value]` infers from context, matching the 373 existing `&[]` call sites).
macro_rules! params {
    ($($x:expr),+ $(,)?) => {
        [$($crate::storage::api::IntoValue::into_value($x)),+]
    };
}
pub(crate) use params;

#[cfg(test)]
mod params_tests {
    use super::*;

    #[test]
    fn params_macro_converts() {
        let p = params!["s", 42_i64, Option::<i64>::None];
        assert_eq!(p[0], Value::Text("s".into()));
        assert_eq!(p[2], Value::Null);
    }
}
