// SPDX-License-Identifier: Apache-2.0

//! Registry Scheduling runtime: the PostgreSQL store, the HTTP surface, and
//! the supervised workers.
//!
//! The runtime owns commitment: every booking, hold, release, and cancellation
//! lands through one capacity-transaction shape: lock the supply row, read a
//! ledger snapshot whose hold expiries are evaluated in the query, run the
//! pure evaluators from `registry-scheduling-core` in memory, and write the
//! claim, the idempotency attempt, the history event, and the outbox rows in
//! the same transaction. Three supervised workers run beside it: hold expiry,
//! reminder-intent dispatch, and retention sweeps. A dead worker stops the
//! process rather than silently overselling.
//!
//! The dependency runs one way: this crate builds on the source-neutral core
//! and shared `registry-platform-*` primitives, and nothing here may grow a
//! second product's protocol types.

pub mod auth;
pub mod config;
pub mod cursors;
pub mod http;
pub mod runtime;
#[cfg(feature = "schema")]
pub mod schema;
pub mod service;
pub mod store;
