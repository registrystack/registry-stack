// SPDX-License-Identifier: Apache-2.0
//! The shared hook contract for Registry Stack: declaration types, the
//! envelope, the handler message, the error taxonomy, and the compile-time
//! (load-time) rules.
//!
//! A hook binds a product-owned trigger to a handler. A handler is Rhai, WASM,
//! or a remote URL, and every kind has the same shape: envelope in, message
//! out. The product decides what the message means and applies it through its
//! own authorization and audit path.
//!
//! The crate is mechanism, not policy. It never defines a trigger, never
//! validates a trigger's vocabulary or a `when` condition, and never applies a
//! proposal. Trigger vocabularies, condition languages, projections, and what a
//! handler may propose stay with the owning product.
//!
//! Out of scope in version one, stated so nobody infers otherwise:
//!
//! - In-request decision hooks (a synchronous remote call inside a request,
//!   for example eligibility before a booking). Same handler abstraction, a
//!   second caller to add later.
//! - Phase `before` on plain writes (`created`, `patched`). That would put a
//!   script on a product's write path and is its own security decision.
//! - Orchestration: fan-in, compensation, whole-flow visibility. An
//!   orchestrator correlates on a reference the product stores with its own
//!   record and treats a received event as a wake hint to re-read that
//!   record, never on the envelope's `causation.root`, so orchestrating
//!   changes nothing in the products.
//! - Folding a product's existing notification path into the handler path. A
//!   notification is a handler whose answer is empty; re-expressing it that
//!   way is a refactor for after the library exists.
//!
//! The delivery schema (the three delivery/outbox tables' DDL) and the
//! notification delivery worker live behind the opt-in `postgres` feature;
//! the contract half above is always available and depends on no database.
//! The worker sends the product's captured payload bytes with the product's
//! headers, and everything product-owned enters through the delivery module's
//! seam trait. The same feature carries the shared halves of a product's
//! seam: the URL destination, the pooled connection, the activation-record
//! identity check, and the hook audit entry.
//!
//! The local-handler executor lives in the `executor` module behind the
//! opt-in `rhai` and `wasm` features. A product hands over the reviewed
//! programs its compiled package carries and the executor runs them on the
//! bare platform script engine under one fixed hook profile, so every
//! product runs the same program the same way. A product that enables
//! neither feature compiles neither engine.
//!
//! [`HookCapabilities`] is the product-declared set of handler kinds and
//! declaration features a product supports, checked with one shared
//! diagnostic before any product-specific rule runs.
//!
//! The opt-in `receiver` feature adds `receiver::verify_delivery`, the one
//! receiver-side reading of a signed Version 1 delivery that every product
//! receiving a hook delivery calls.

mod capability;
mod declaration;
#[cfg(feature = "postgres")]
pub mod delivery;
#[cfg(feature = "postgres")]
pub mod delivery_schema;
mod envelope;
mod error;
#[cfg(any(feature = "rhai", feature = "wasm"))]
pub mod executor;
mod message;
#[cfg(feature = "receiver")]
pub mod receiver;
mod retry;
mod validate;

pub use capability::{HookCapabilities, HookCapability, HookCapabilityError};
pub use declaration::{
    HookDeclaration, HookHandlerKind, HookHandlerSource, HookPhase, HOOK_HANDLER_ABI_V1,
};
pub use envelope::{
    Causation, EnvelopeLimits, EventSubject, HookCausationError, HookEnvelope, HookEnvelopeError,
    HOP_CEILING, MAX_ENVELOPE_BYTES,
};
pub use error::ErrorCategory;
pub use message::{
    BoundedText, BoundedTextError, HandlerOutputLimits, HookMessage, HookMessageError,
    HookProposal, MAX_OUTPUT_BYTES, MAX_REFUSAL_CODE_BYTES, MAX_REFUSAL_SUMMARY_BYTES,
};
pub use retry::exponential_retry_delays_ms;
pub use validate::{validate_hooks, HookValidationError};
