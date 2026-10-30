// SPDX-License-Identifier: Apache-2.0

//! The idempotency store behind the `idempotentConsumer` EIP
//! (`products/adapter/CONCEPT.md` section 9).
//!
//! Every route bound to a write operation runs inside
//! `idempotentConsumer` with Camel's `expression`, `eager` (default
//! true), `removeOnFailure` (default true), and `completionEager`
//! (default false) options. The key is namespaced by caller identity and
//! concrete operation, and bound to the request digest: a duplicate
//! replays the recorded facade response instead of being dropped
//! (`skipDuplicate` is not ported), and a duplicate arriving while the
//! first is in flight answers 409. `removeOnFailure` before any
//! upstream effect removes the key; a failure after a non-safe send
//! keeps the key in a failed state and replays the recorded problem, so
//! a sent effect is never re-executed.
//!
//! The store is PostgreSQL, separate from the audit journal, and the one
//! place the adapter retains a response body: the exact facade response,
//! for the key's retention window, then erased by a supervised sweep, as
//! BReg's store does in `crates/registry-breg/src/idempotency.rs`.
