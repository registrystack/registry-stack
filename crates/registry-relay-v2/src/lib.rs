// SPDX-License-Identifier: Apache-2.0
//! Relay V2's shared governed-contract compiler and runtime kernel.

pub mod api;
pub mod artifacts;
pub mod audit;
pub mod auth;
pub mod authoring;
pub mod compiler;
pub mod contract;
pub mod cursor;
pub mod diff;
pub mod fixture_contract;
#[cfg(feature = "tooling")]
pub mod fixtures;
pub mod format_capabilities;
pub mod identification;
pub mod model;
pub mod package;
pub mod problem;
#[cfg(feature = "schema")]
pub mod schema;
mod sdmx;
mod sdmx_http;
pub mod semantics;
pub mod server;
mod source_observation;
pub mod sqlite_runtime;
pub mod startup;
#[cfg(feature = "tooling")]
pub mod tooling;
pub mod transform;

pub use compiler::{classification_inventory_digest, compile, CompileError};
pub use contract::{RegistryContract, RelayRuntime};
pub use model::{CompileProfile, CompiledRegistry, ObservedSourceSchema};
