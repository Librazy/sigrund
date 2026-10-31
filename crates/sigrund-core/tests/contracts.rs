//! Cross-module contracts, grouped by the module responsible for validation.
#[path = "contracts/approval.rs"]
mod approval;
#[path = "contracts/config.rs"]
mod config;
#[path = "contracts/json.rs"]
mod json;
#[path = "contracts/protocol.rs"]
mod protocol;
#[path = "contracts/support.rs"]
mod support;
#[path = "contracts/warrant.rs"]
mod warrant;
