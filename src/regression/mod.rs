//! Trusted regression inputs. No retrieval or quality evaluation runs here.

pub(crate) mod blind;
pub(crate) mod fixed;
pub(crate) mod fixed_encoding;
pub(crate) mod input;
pub(crate) mod labels;
pub(crate) mod off;
pub(crate) mod on;
pub(crate) mod run;
pub mod types;

pub use types::RegressionCommand;
