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
//! - Orchestration: fan-in, compensation, whole-flow visibility. A later
//!   orchestrator correlates on the envelope's `causation.root`, which already
//!   exists, so orchestrating changes nothing in the products.
//! - Folding BReg's notification path into the handler path. A notification is
//!   a handler whose answer is empty; re-expressing it that way is a refactor
//!   for after the library exists.
//!
//! The delivery schema (the three delivery/outbox tables' DDL) lives here
//! behind the `postgres` feature. No delivery worker and no executor live
//! here.

mod declaration;
#[cfg(feature = "postgres")]
pub mod delivery_schema;
mod envelope;
mod error;
mod message;
mod validate;

pub use declaration::{
    HookDeclaration, HookDeclarationError, HookHandlerSource, HookPhase, HooksDocument,
    HOOK_HANDLER_ABI_V1,
};
pub use envelope::{
    Causation, EnvelopeLimits, EventSubject, HookCausationError, HookEnvelope, HookEnvelopeError,
    HOP_CEILING, MAX_ENVELOPE_BYTES,
};
pub use error::ErrorCategory;
pub use message::{
    BoundedText, BoundedTextError, HandlerOutputLimits, HookMessage, HookMessageError,
    HookProposal, DEFAULT_MAX_OUTPUT_BYTES, MAX_REFUSAL_CODE_BYTES, MAX_REFUSAL_SUMMARY_BYTES,
};
pub use validate::{validate_hooks, HookValidationError};
