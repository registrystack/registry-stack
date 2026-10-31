// SPDX-License-Identifier: Apache-2.0

//! The journal: Camel's event notifier ported as a synchronous,
//! value-free PostgreSQL journal written before the response is sent
//! (`products/adapter/CONCEPT.md` section 11).
//!
//! Event kinds follow Camel's: `exchangeCreated`, `exchangeSending` and
//! `exchangeSent` (endpoint id, method, path template, status, duration,
//! response size and digest), `exchangeRedelivery`,
//! `exchangeFailureHandled`, `exchangeCompleted`, and `exchangeFailed`
//! (error class, problem code). Each row carries the exchange id, the
//! concrete operation, the caller identity, and the route id. It records
//! no bodies: no request payloads, no response payloads, no field
//! values, no filled query strings. Retention follows the shared
//! `audit.retentionDays` block; the idempotency store is the one
//! retained body and keeps its own retention.
