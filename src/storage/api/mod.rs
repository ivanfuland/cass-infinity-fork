//! storage::api — backend-agnostic facade over the relational storage layer.

mod backend_sqlite;
mod config;
mod conn;
mod error;
mod value;
mod writer;

pub use config::{OpenOptions, Profile};
pub use conn::{Conn, Row, Tx, TxMode};
pub use error::{BusyScope, StorageError};
pub(crate) use error::NO_ROWS_DETAIL;
pub use value::{FromValue, IntoValue, Value};
pub use writer::{
    WriterHandle, reset_writer_connection_peak, writer_connection_count, writer_connection_peak,
};

/// Registers the `vec0` module (sqlite-vec, w3 Task W3-3) with SQLite via
/// `sqlite3_auto_extension`. This is process-global — it affects every
/// connection opened *after* this call, not connections already open (a
/// `sqlite3_auto_extension` registration does not retroactively attach to
/// an already-`sqlite3_open`ed handle) — which is why every real connection
/// entry point in `backend_sqlite.rs` (`open_writable`/`open_read_only`/
/// `open_memory`) calls this before its `rusqlite::Connection::open*` call,
/// not lazily from `storage::vector_domain` at first vec0 use.
///
/// Guarded by [`std::sync::Once`]: `sqlite3_auto_extension` itself
/// tolerates registering the same entry point twice (SQLite's own dedup),
/// but `Once` avoids the FFI call entirely after the first.
///
/// Registration pattern verbatim from `probe/sqlite-vec-eval`'s
/// `examples/w3_sqlite_vec_eval_probe.rs::register_vec0` (@5c5f5128, the
/// KU2 benchmark's own registration code) — cited per 拿来主义 discipline,
/// not independently re-derived.
pub(crate) fn ensure_vec0_extension_registered() {
    static REGISTERED: std::sync::Once = std::sync::Once::new();
    REGISTERED.call_once(|| {
        // Safety: `sqlite_vec::sqlite3_vec_init` is the standard
        // `sqlite3_auto_extension`-compatible entry point sqlite-vec ships
        // for exactly this registration pattern.
        unsafe {
            rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute(
                sqlite_vec::sqlite3_vec_init as *const (),
            )));
        }
    });
}

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
