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
//! The client covers the unauthenticated liveness and readiness routes, the
//! bearer-authorized submission of one message under a caller-chosen
//! idempotency key, which answers the core's `MessageReceipt`, and the
//! bearer-authorized read of one message's status, which answers the
//! core's `MessageView`: the derived status, the dispatch state and delivery
//! report it is derived from, and attempt summaries. It also covers the
//! bearer-authorized cancellation of one undispatched message, which answers
//! the same `MessageView`, and the bearer-authorized preview of one template
//! version, which answers the core's `TemplatePreview` and sends nothing. It
//! never follows
//! redirects or retries, reads every response under a bounded
//! byte ceiling, and lands every failure in one named shape: a configuration
//! defect, a transport failure, a protocol failure, or a validated product
//! problem surfaced as its typed code. A 429 limit refusal also carries the
//! bounded wait its `Retry-After` asked for; waiting and retrying stay the
//! caller's decision.

#![deny(unsafe_code)]

mod client;
mod config;
mod error;

pub use client::{MessagingClient, MessagingComplete, MAXIMUM_RETRY_AFTER_SECONDS};
pub use config::MessagingClientConfig;
pub use error::{MessagingClientError, MessagingProtocolFailure};
pub use registry_messaging_core::{
    type_uri, AttemptOutcome, AttemptSummary, Channel, DirectContent, MessageDispatch,
    MessageLinks, MessageReceipt, MessageReport, MessageStatus, MessageView, ProblemCode,
    Recipient, RenderedParts, SegmentCount, SmsEncoding, SubmitMessageRequest, TemplatePreview,
    TemplatePreviewRequest, TemplateReference, HEALTH_PATH, IDEMPOTENCY_KEY_HEADER,
    MAXIMUM_IDEMPOTENCY_KEY_BYTES, MESSAGES_PATH, MESSAGE_CANCEL_PATH, MESSAGE_PATH,
    MESSAGING_PROBLEM_TYPE_BASE, READY_PATH, TEMPLATE_PREVIEW_PATH,
};
pub use registry_platform_httputil::client::{BearerToken, TransportKind};
