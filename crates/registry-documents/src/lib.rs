// SPDX-License-Identifier: Apache-2.0

//! Registry Stack Document Store runtime: the operator configuration, the
//! HTTP surface, and the PostgreSQL store.
//!
//! The runtime serves `/health` and refuses every other request with a
//! problem from the closed vocabulary in `registry-documents-core`.

pub mod config;
pub mod http;
pub mod package;
pub mod runtime;
#[cfg(feature = "schema")]
pub mod schema;
pub mod store;
pub mod verification;
