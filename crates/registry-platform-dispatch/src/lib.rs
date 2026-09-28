// SPDX-License-Identifier: Apache-2.0

//! Generic at-least-once dispatch core for Registry Stack.
//!
//! A product that hands work to something outside its own transaction (a
//! webhook destination, a remote service) needs the same few guarantees:
//! one worker at a time holds a job, the attempt is recorded before anything
//! leaves the process, a stalled worker can never overwrite the work of the
//! worker that replaced it, retries follow a policy frozen with the job, and
//! an operator can replay terminal work without reusing its identity. This
//! crate is that state machine, over a job table the product owns.
//!
//! The pure half is always compiled: the idempotency-key recipe, the retry
//! and attempt-timeout policy, and the bounded send outcome a transport
//! reports. The `postgres` feature adds the fenced lease machine in
//! [`postgres`]: claim under `FOR UPDATE SKIP LOCKED`, the lease-token and
//! generation compare-and-set every later write carries, lease-expiry
//! recovery, retry scheduling, dead-lettering, expiry, cancellation,
//! generation-bumped replay, and a bounded-concurrency worker.
//!
//! The core owns no product vocabulary. The product names its schema and
//! table, joins its own policy and payload rows into the claim, writes its
//! own audit inside every transition transaction, and adds its own columns
//! to terminal writes.

mod idempotency;
mod identifier;
mod outcome;
mod retry;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use idempotency::idempotency_key;
pub use identifier::is_plain_identifier;
pub use outcome::{
    ConfigError, DispatchError, FailureCode, ReceiverReference, SendOutcome, Sent,
    MAX_FAILURE_CODE_BYTES, MAX_RECEIVER_REFERENCE_BYTES,
};
pub use retry::{
    frozen_retry_delay, remaining_attempt_budget, AttemptTimeoutBound, Backoff, Jitter, JobPolicy,
    RetrySchedule, UncertainOutcome, MAX_ATTEMPT_TIMEOUT,
};
