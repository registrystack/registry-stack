// SPDX-License-Identifier: Apache-2.0

//! A citizen-facing MCP gateway beside the Base Registry Engine.

#[cfg(not(unix))]
compile_error!("registry-breg-mcp requires a Unix target for owner-only secret file guarantees");

mod audit;
#[doc(hidden)]
pub mod cli;
pub mod config;
mod contract;
mod gateway;
mod handler;
mod idempotency;
mod inbound;
#[cfg(test)]
#[path = "../tests/support/mock_registry.rs"]
mod mock_registry;
mod outbound;
mod problems;
pub mod runtime;
mod server;
mod tools;

pub use cli::command;
