// SPDX-License-Identifier: Apache-2.0
//! Durable institutional coordination using shared Registry Platform primitives.

pub mod adapters;
pub mod authoring;
pub mod breg_action;
pub mod breg_proposal;
pub mod breg_review_context;
pub mod completion;
pub mod contracts;
pub mod decision;
pub mod definition;
pub mod error;
pub mod event_trigger;
pub mod external_http;
mod functions;
mod mapping_check;
pub mod operations;
pub mod problem;
pub mod project;
mod project_check;
pub mod protocol;
mod review;
pub mod review_provider;
pub mod runtime;
#[cfg(feature = "schema")]
pub(crate) mod schema;
pub mod store;
pub mod worker;

pub use error::{CoordinatorError, Result};

pub mod access;
pub mod deployment;
pub mod http;
pub mod metrics;
pub mod protected_state;
pub mod scenarios;

pub mod cli;
pub mod sdk;
pub mod service;
