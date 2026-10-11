// SPDX-License-Identifier: Apache-2.0
//! Bounded server-side Coordinator admissions, progress and original-receipt recovery.
//!
//! `list`, `status`, `inspect`, `reconcile`, `retry_same` and `cancel` send
//! exactly one request; `retry_same` and `cancel` take no idempotency key, so
//! the client never resends them. `start` resends an admission whose outcome
//! is unknown under the caller's same key and body, at most
//! `CoordinatorClientConfig::with_max_mutation_retries` times. The caller
//! chooses the key and, after an error whose outcome is unknown, must retain
//! the same verified issuer, subject, client, flow, input and key to recover.
//! A service-owned run never becomes citizen-owned because its input names a
//! citizen's record. Authorize the source record independently before
//! disclosing an application-level correlation.
//! Reconciliation observes the original supported product receipt; it never
//! retries or replaces the product command. The operator routes (doctor,
//! holds, execution recovery and retention) are not part of this client;
//! `coordinatorctl` owns them.
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
pub use model::{
    EffectKind, KeyRequirement, OperationIdentity, RecoverySemantics, RecoveryStatus,
    RetryBlockReason, RetryScheduled, RunInspection, RunList, RunStatus, StartRunRequest,
    StepStatus,
};
pub use registry_platform_httputil::client::{BearerToken, TransportKind};
pub use uuid::Uuid;
