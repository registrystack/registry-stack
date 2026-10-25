// SPDX-License-Identifier: Apache-2.0
//! Shared, product-neutral `rstack <product> api` and saved-connection tooling.

mod api;
mod connection;
mod error;
mod file;
mod project;
#[cfg(feature = "schema")]
pub mod schema;

pub use api::{run_api, run_api_with_profile_headers, ApiArgs, LocalConnection};
pub use connection::{
    check_connections_file, inspect_connections_file, run_connection, run_connection_check,
    AddConnectionArgs, CheckConnectionArgs, ConnectionCommand, ListConnectionArgs,
    PlatformCliConnectionCheckReport, ShowConnectionArgs, UseConnectionArgs,
    CONNECTIONS_API_VERSION, CONNECTIONS_KIND, CONNECTION_CHECK_REPORT_API_VERSION,
    CONNECTION_CHECK_REPORT_KIND,
};
pub use error::ApiError;
