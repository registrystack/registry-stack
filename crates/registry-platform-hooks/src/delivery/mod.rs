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
//! A delivery row names the kind of handler that answers it. For the `url`
//! kind the worker signs and sends, and the bounded response body is the
//! answer. For the local kinds the worker resolves the product's runnable
//! handler for the row's binding and reads the answer back from it; the
//! reviewed program is the product's, and the engine that runs it is this
//! crate's `executor` module when the product enables it. The
//! answer is the same [`crate::HookMessage`] either way: bounded, canonical,
//! digested, and recorded in the delivery state. An answer that proposes
//! hands the proposal to the product's apply seam between the answer and
//! finalization, and the row records what became of it: nothing proposed,
//! applied, refused, or dead-lettered.
//!
//! Everything product-owned enters through [`DeliverySeams`]: the key
//! material, the idempotency domain, the audit journal, the operational-event
//! vocabulary, the registry identity preflight, and the activated
//! destinations. The pieces every product fills the same way live beside the
//! seams so no product re-implements them: the `url` destination
//! ([`UrlDestination`]: Version 1 signing, the closed request template, and
//! the bounded answer read), the pooled connection, the uninhabited
//! [`NoLocalHandler`], the audit words and entry shape
//! ([`hook_audit_entry`]), and the activation-record identity preflight
//! ([`verify_active_package`]). The library carries no product
//! name and no product policy; [`DeliveryConfig`] carries the product's
//! schema name, idempotency domain, and delivery source identity.

mod audit;
mod connection;
mod destination;
mod identity;
mod insert;
mod retention;
mod seams;
mod service;
mod store;

pub use audit::{hook_audit_entry, InvalidDeliveryAudit, MAX_AUDIT_COMPILED_DELIVERY_ID_BYTES};
pub use connection::{NoLocalHandler, PooledConnection};
pub use destination::{
    answer_read_category, url_destination_address, SharedUrlDestination, UrlDestination,
    UrlDestinationAddress, UrlDestinationError, UrlDestinationParts, MIN_HMAC_SHA256_KEY_BYTES,
};
pub use identity::verify_active_package;
pub use insert::{insert_delivery, DeliveryCapture};
pub use registry_platform_dispatch::postgres::RetentionError;
pub use retention::prune_terminal_deliveries;
pub use seams::{
    DeliveryAuditDisposition, DeliveryAuditOutcome, DeliveryAuditPhase, DeliveryAuditRecord,
    DeliveryConnection, DeliveryError, DeliveryOperationalEvent, DeliverySeams,
    DeliverySignatureFields, DeliverySignatureRefused, DeliveryTransitionCode, DestinationAnswer,
    HandlerRunFailure, HookDestination, HookHandler, HookHandlerBinding, ProposalApplication,
    ProposalCode, ProposalOutcome, ProposalReceiptRecovery, ProposalSummary,
};
pub use service::{
    DeliveryConfig, DeliveryFailureReason, DeliveryOutcome, DeliveryService, DeliveryStatus,
    DeliveryStatusKind, DeliveryWorker, RetainedBindingError, MAX_DELIVERY_STATUS_RESULTS,
};
