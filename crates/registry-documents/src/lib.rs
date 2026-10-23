// SPDX-License-Identifier: Apache-2.0

//! Registry Stack Document Store runtime: the operator configuration, the
//! HTTP surface, and the PostgreSQL store.
//!
//! The runtime serves `/health`, `/ready`, and the document routes, behind
//! bearer token verification, and refuses every other request with a problem from
//! the closed vocabulary in `registry-documents-core`.

pub mod activation;
pub mod audit;
pub mod auth;
pub mod config;
pub mod content;
pub mod erasure;
pub mod hooks;
pub mod http;
pub mod package;
pub mod replay;
pub mod runtime;
#[cfg(feature = "schema")]
pub mod schema;
pub mod service;
pub mod store;
pub mod transfer;
pub mod verification;
