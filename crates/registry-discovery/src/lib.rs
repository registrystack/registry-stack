// SPDX-License-Identifier: Apache-2.0
//! Closed immutable index and read-only Registry Discovery service.

/// The canonical index inside every Discovery package.
pub const INDEX_FILE: &str = "discovery-index.json";
/// The command that creates a Discovery package, named in package refusals.
pub const PACKAGE_COMMAND: &str = "discoveryctl package";
/// The index plus the optional shared `REVISION` envelope file.
pub const MAXIMUM_PACKAGE_FILES: usize = 2;
/// The index plus a maximum-length shared `REVISION` line.
pub const MAXIMUM_PACKAGE_BYTES: u64 = MAXIMUM_INDEX_BYTES + 257;
/// Discovery package files live directly under the package root.
pub const MAXIMUM_PACKAGE_DEPTH: usize = 1;

pub mod model;
pub mod openapi;
#[cfg(feature = "server")]
pub mod problem;
pub mod query;
#[cfg(feature = "runtime-config")]
pub mod runtime_config;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod startup;

pub use model::*;
pub use query::{parse_service_filters, Directory, QueryError};
#[cfg(feature = "runtime-config")]
pub use runtime_config::{
    check_runtime, LogLevel, RuntimeCheck, RuntimeConfig, RuntimeLimits, RUNTIME_API_VERSION,
    RUNTIME_KIND,
};
#[cfg(feature = "server")]
pub use server::{router, DiscoveryService, ServiceConfigError};
#[cfg(feature = "server")]
pub use startup::{
    load_index, load_runtime, load_verified_index, package_limits, prepare, serve,
    PreparedDiscovery, StartupError, MAXIMUM_LISTENER_BIND_CHARACTERS,
};
