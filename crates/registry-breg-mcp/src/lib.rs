// SPDX-License-Identifier: Apache-2.0

//! A citizen-facing MCP gateway beside the Base Registry Engine.

#[cfg(not(unix))]
compile_error!("registry-breg-mcp requires a Unix target for owner-only secret file guarantees");

pub mod check;
#[doc(hidden)]
pub mod cli;
mod client;
pub mod config;
mod contract;
mod gateway;
mod handler;
mod idempotency;
#[cfg(test)]
#[path = "../tests/support/mock_registry.rs"]
mod mock_registry;
mod problems;
mod provider;
pub mod runtime;
#[cfg(feature = "schema")]
pub mod schema;
mod tools;

pub use cli::command;
pub use provider::{breg_binding, BRegBindingError, BREG_TOOL_NAMES};
