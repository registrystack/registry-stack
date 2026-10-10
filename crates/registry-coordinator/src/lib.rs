// SPDX-License-Identifier: Apache-2.0
//! Durable institutional coordination using shared Registry Platform primitives.

pub mod adapters;
pub mod authoring;
pub mod breg_action;
pub mod decision;
pub mod definition;
pub mod error;
pub mod external_http;
mod functions;
pub mod operations;
pub mod project;
mod project_check;
pub mod protocol;
pub mod runtime;
#[cfg(feature = "schema")]
pub(crate) mod schema;
pub mod store;
pub mod worker;

pub use error::{PocError, Result};

pub mod access;
pub mod deployment;
pub mod http;
pub mod protected_state;
pub mod scenarios;

pub mod cli;
pub mod service;
