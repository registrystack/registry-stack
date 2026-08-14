// SPDX-License-Identifier: Apache-2.0
//! Closed immutable index and read-only Registry Discovery service.

pub mod model;
pub mod openapi;
#[cfg(feature = "server")]
pub mod problem;
pub mod query;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod startup;

pub use model::*;
pub use query::{parse_service_filters, Directory, QueryError};
#[cfg(feature = "server")]
pub use server::{router, DiscoveryService, ServiceConfigError};
#[cfg(feature = "server")]
pub use startup::{load_index, load_runtime, prepare, serve, PreparedDiscovery, StartupError};
