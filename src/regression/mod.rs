//! Trusted regression inputs. No retrieval or quality evaluation runs here.

pub(crate) mod input;
pub mod types;
pub(crate) mod run;
pub(crate) mod off;
pub(crate) mod on;

pub use types::RegressionCommand;
