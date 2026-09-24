// SPDX-License-Identifier: Apache-2.0

//! Registry Messaging runtime: the operator configuration, bearer
//! authentication against authored access profiles, the HTTP surface, and
//! the PostgreSQL store.

pub mod audit;
pub mod auth;
pub mod config;
pub mod dispatch;
pub mod environment;
pub mod http;
pub mod http_provider;
pub mod messages;
pub mod metrics;
pub mod outbox;
pub mod package;
pub mod providers;
pub mod runtime;
#[cfg(feature = "schema")]
pub mod schema;
pub mod smtp;
pub mod store;
