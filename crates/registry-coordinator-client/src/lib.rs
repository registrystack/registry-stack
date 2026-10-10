// SPDX-License-Identifier: Apache-2.0
//! Bounded server-side Coordinator admissions, progress and original-receipt recovery.
//!
//! Every method sends exactly one request. The caller owns admission retries and
//! must retain the same verified issuer, subject, client, flow, input and key.
//! A service-owned run never becomes citizen-owned because its input names a
//! citizen's record. Authorize the source record independently before disclosing
//! an application-level correlation. Reconciliation observes the original
//! supported product receipt; it never retries or replaces the product command.
//!
//! Coordinator's product-owned problem is JSON `{code,message,suggestedAction}`,
//! not an RFC 9457 document. The client discards server prose and has no invented
//! trace requirement. Redirects and ambient proxies are disabled by the shared
//! transport, and JSON/header/body bounds are enforced on every response.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;
mod model;

pub use client::{CoordinatorClient, CoordinatorComplete};
pub use config::CoordinatorClientConfig;
pub use error::{CoordinatorClientError, CoordinatorProtocolFailure};
pub use model::*;
pub use registry_platform_httputil::client::{BearerToken, TransportKind};
pub use uuid::Uuid;
