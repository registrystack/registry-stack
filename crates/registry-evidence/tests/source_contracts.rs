//! Contract tests for exact, source-neutral source execution through the current pack API.
#![allow(
    clippy::disallowed_methods,
    reason = "tests read governed fixtures and their own synthetic outputs, never operator configuration"
)]

#[path = "support/source_contracts_current.rs"]
mod current_contracts;
