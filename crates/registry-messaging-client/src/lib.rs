// SPDX-License-Identifier: Apache-2.0

//! Bounded client for Registry Messaging.
//!
//! A thin relying-party client over the pinned Messaging HTTP contract. The
//! closed problem vocabulary and every route name come from
//! `registry-messaging-core`; the shared transport primitives, the exact
//! problem document shape, and trace correlation come from
//! `registry-platform-httpsec` and `registry-platform-httputil`. This crate
//! never depends on the Messaging runtime or its operator tooling and adds
//! no messaging semantics of its own: a caller matches recoverable outcomes
//! against the core's `ProblemCode`, not a second vocabulary.
//!
//! The client covers the unauthenticated liveness and readiness routes and
//! the bearer-authorized read of one message's status, which answers the
//! core's `MessageView`: the derived status, the dispatch state and delivery
//! report it is derived from, and attempt summaries. It never follows
//! redirects or retries, reads every response under a bounded
//! byte ceiling, and lands every failure in one named shape: a configuration
//! defect, a transport failure, a protocol failure, or a validated product
//! problem surfaced as its typed code.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;

pub use client::{MessagingClient, MessagingComplete};
pub use config::MessagingClientConfig;
pub use error::{MessagingClientError, MessagingProtocolFailure};
pub use registry_messaging_core::{
    type_uri, AttemptOutcome, AttemptSummary, MessageDispatch, MessageReport, MessageStatus,
    MessageView, ProblemCode, HEALTH_PATH, MESSAGE_PATH, MESSAGING_PROBLEM_TYPE_BASE, READY_PATH,
};
pub use registry_platform_httputil::client::{BearerToken, TransportKind};
