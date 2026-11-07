// SPDX-License-Identifier: Apache-2.0
//! Wallet-facing OpenID4VP verifier front end for Registry Evidence.

pub mod config;

#[cfg(feature = "schema")]
pub mod schema;

pub mod session;

pub mod client_identifier;

pub mod policy;
pub mod problem;
pub mod request_object;
pub mod response;

pub mod audit;
pub mod metrics;

pub mod auth;

pub mod service;

pub mod cli;
pub mod contracts;
