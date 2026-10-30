// SPDX-License-Identifier: Apache-2.0
//! Configured provider bindings over the shared authenticated MCP edge.
#![deny(unsafe_code)]
pub mod adapter;
pub mod casework;
pub mod config;
pub mod runtime;
#[cfg(feature = "schema")]
pub mod schema;
