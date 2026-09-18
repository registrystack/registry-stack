// SPDX-License-Identifier: Apache-2.0

//! The delivery core: the at-least-once notification delivery worker and the
//! neutral delivery INSERT.
//!
//! The worker claims due deliveries under `FOR UPDATE SKIP LOCKED` leases,
//! reaps expired leases, expires retained payloads, schedules retries from
//! the per-delivery frozen retry profile, dead-letters exhausted work, and
//! offers bounded operator status and replay. This is the moved delivery
//! core, not a new design: claim, lease/CAS, reaping, retry scheduling,
//! dead-lettering, expiry, replay, attempt-budget accounting, idempotency-key
//! construction, and transport-vs-deadline classification keep their
//! behavior, and the worker sends the captured envelope bytes unchanged. The
//! stored payload is one [`crate::HookEnvelope`] in canonical form; the worker
//! re-reads it before every attempt and refuses a row whose headers would
//! disagree with the body it is about to sign.
//!
//! Everything product-owned enters through [`DeliverySeams`]: the signing
//! scheme and its key material, the idempotency domain, the audit journal and
//! its vocabulary, the operational-event vocabulary, the registry identity
//! preflight, and the activated destinations. The library carries no product
//! name and no product policy; [`DeliveryConfig`] carries the product's
//! schema name, idempotency domain, and delivery source identity.

mod insert;
mod seams;
mod service;

pub use insert::{insert_delivery, DeliveryCapture};
pub use seams::{
    DeliveryAuditDisposition, DeliveryAuditOutcome, DeliveryAuditPhase, DeliveryAuditRecord,
    DeliveryConnection, DeliveryError, DeliveryOperationalEvent, DeliverySeams,
    DeliverySignatureFields, DeliverySignatureRefused, DeliveryTransitionCode, DestinationAnswer,
    HookDestination,
};
pub use service::{
    DeliveryConfig, DeliveryOutcome, DeliveryService, DeliveryStatus, DeliveryStatusKind,
    DeliveryWorker, MAX_DELIVERY_STATUS_RESULTS,
};
