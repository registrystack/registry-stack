// SPDX-License-Identifier: Apache-2.0
//! Canonical, bounded client for Registry Scheduling.
//!
//! A thin relying-party client over the pinned Scheduling HTTP contract. The
//! wire documents, the closed problem vocabulary, and every route, query, and
//! header name come from `registry-scheduling-core`; the shared transport
//! primitives, the exact problem document shape, and trace correlation come
//! from `registry-platform-httpsec` and `registry-platform-httputil`. This
//! crate never depends on the Scheduling runtime or its operator tooling,
//! adds no scheduling semantics of its own, and never re-declares a name the
//! core already owns: a caller matches recoverable outcomes against the
//! core's `ProblemCode`, not a second vocabulary.
//!
//! Authentication is a borrowed bearer token per call, the only credential
//! Scheduling accepts. The client never retains the token or follows
//! redirects. Mutating calls carry a caller-supplied idempotency key,
//! validated against the pinned bound before any network input or output;
//! the client never generates one. A keyed command whose outcome is unknown
//! (a timeout or broken exchange after the request was sent, or a 5xx answer)
//! is resent, byte for byte and under the same key, at most
//! `SchedulingClientConfig::with_max_mutation_retries` times (2 by default, 0
//! disables it). Reads and the unkeyed hold release are never resent. A 5xx
//! answer may follow a commit: when `SchedulingClientError::is_outcome_unknown`
//! is still true, the safe recovery is the same request under the same key,
//! never a new key. Responses are read under a bounded byte ceiling, the core
//! answer documents tolerate a member a later deployment added while the
//! request documents the runtime reads refuse one, and every failure lands
//! in one of three named shapes: a caller-side request defect, a transport
//! failure, or a protocol failure, with validated product problems surfaced
//! as their typed code.
//!
//! Re-exports are flat, so a caller names a document, a route constant, or a
//! vocabulary entry through this crate exactly as the core spells it.

//! `appointment_receipt` observes a retained original success by caller, key, and exact request
//! without replaying the mutation. The single read is never retried, and a
//! typed `receipt.unresolved` preserves uncertainty about the original effect.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;
mod model;

pub use client::SchedulingClient;
pub use config::SchedulingClientConfig;
pub use error::{SchedulingClientError, SchedulingProtocolFailure};
pub use model::{SchedulingAuth, SchedulingComplete};
pub use registry_platform_httputil::client::{BearerToken, TransportKind};
pub use registry_scheduling_core::{
    type_uri, AdmissionRequest, AppointmentDocument, AppointmentHistoryEntryDocument,
    AppointmentStateDocument, AvailabilityEntry, CancelAppointmentRequest,
    CreateAppointmentRequest, ExplainDocument, ExternalReference, HoldDocument, LocationDocument,
    OfferingDocument, PageDocument, PartyCounts, ProblemCode, ReminderDocument,
    RescheduleAppointmentRequest, ResourceDocument, SchedulingModeDocument,
    SchedulingServiceDocument, ServiceDocument, WindowDocument, APPOINTMENTS_PATH,
    APPOINTMENT_RECEIPT_PATH, AVAILABILITY_EXPLAIN_PATH, AVAILABILITY_PATH, CURSOR_QUERY_PARAMETER,
    HOLDS_PATH, IDEMPOTENCY_KEY_HEADER, LIMIT_QUERY_PARAMETER, LOCATIONS_PATH,
    MAXIMUM_IDEMPOTENCY_KEY_BYTES, OFFERINGS_PATH, RESOURCES_PATH, SCHEDULING_PATH,
    SCHEDULING_PROBLEM_TYPE_BASE, SERVICES_PATH,
};
