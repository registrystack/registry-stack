// SPDX-License-Identifier: Apache-2.0
//! Payment-specific attempt custody at the Adapter host boundary. The generic
//! route engine has no payment state, provider semantics, or receipt authority.
pub mod config;
pub mod http;
pub mod model;
pub mod registry;
pub mod service;
pub mod store;
