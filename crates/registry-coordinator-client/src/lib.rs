// SPDX-License-Identifier: Apache-2.0
//! Bounded server-side Coordinator admissions, progress and original-receipt recovery.
//!
//! `list`, `status`, `inspect`, `reconcile`, `retry_same` and `cancel` send
//! exactly one request; `retry_same` and `cancel` take no idempotency key, so
//! the client never resends them. `start` resends an admission whose outcome
//! is unknown under the caller's same key and body, at most
//! `CoordinatorClientConfig::with_maximum_mutation_retries` times. The caller
//! chooses the key and, after an error whose outcome is unknown, must retain
//! the same verified issuer, subject, client, workflow, input and key to recover.
//! A service-owned run never becomes citizen-owned because its input names a
//! citizen's record. Authorize the source record independently before
//! disclosing an application-level correlation.
//! Reconciliation observes the original supported product receipt; it never
//! retries or replaces the product command. The operator routes (doctor,
//! holds, execution recovery and retention) are not part of this client;
//! `coordinatorctl` owns them.
//!
//! Every Coordinator refusal is an RFC 9457 `application/problem+json`
//! document with exactly `type`, `title`, `status`, `detail`, `code` and
//! `traceId`. The client accepts one as `CoordinatorClientError::Problem` only
//! when its status equals the answer's, its `traceId` equals the answer's
//! `traceparent` trace, and its `type` is its `family.reason` code under
//! `https://id.registrystack.org/problems/registry-coordinator/`; anything else
//! is a protocol failure. The client discards the title and detail. Redirects
//! and ambient proxies are disabled by the shared transport, and
//! JSON/header/body bounds are enforced on every response.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;
mod model;

pub use client::{CoordinatorClient, CoordinatorComplete};
pub use config::CoordinatorClientConfig;
pub use error::{CoordinatorClientError, CoordinatorProtocolFailure};
pub use model::{
    EffectKind, EffectState, EffectStatus, HoldDetail, KeyRequirement, LastObservation,
    OperationIdentity, ProposalTurn, RecoverySemantics, RecoveryStatus, RetryBlockReason,
    RetryScheduled, RunInspection, RunList, RunListQuery, RunListState, RunStatus, StartRunRequest,
    StepStatus, WaitStatus, WorkflowContract,
};
pub use registry_platform_httputil::client::{BearerToken, TransportKind};
pub use uuid::Uuid;
