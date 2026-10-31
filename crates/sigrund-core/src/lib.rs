//! Shared, privilege-independent contracts for `sigrun`, `sigrund`, and the
//! remote collector.  Linux operations live outside this crate so these types
//! can be exercised by unprivileged unit tests and the collector.

pub mod approval;
pub mod audit;
pub mod config;
pub mod crypto;
pub mod framing;
pub mod json;
pub mod lifecycle;
pub mod paths;
pub mod protocol;
pub mod snapshot;
mod sqlite_pinned;
pub mod state;
pub mod warrant;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("invalid protocol: {0}")]
    Protocol(String),
    #[error("invalid JSON: {0}")]
    Json(String),
    #[error("invalid value: {0}")]
    Value(String),
    #[error("database error: {0}")]
    Database(String),
}

pub type Result<T> = std::result::Result<T, CoreError>;
