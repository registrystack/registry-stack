// SPDX-License-Identifier: Apache-2.0
//! The parked BReg connector over the maintained client.
//!
//! A connector turns one prepared delivery attempt into exactly one typed
//! call on `registry-breg-client`, and nothing else: never hand-authored
//! HTTP, never a product database, never a product runtime or tooling
//! crate. The crate is linked by no facade binary and by no job path: it
//! is compiled only behind its off-by-default cargo feature, it is parked
//! while the governed-ingestion delivery design is decided, and the
//! dependency-direction gate in `products/adapter/scripts/` holds the
//! boundary mechanically. No other product client may be linked here
//! while it is parked.
//!
//! The [`operation`] module carries the operation contract a delivery
//! path calls: a descriptor that names what an operation is and needs,
//! an exact persistable prepared form with no bearer token, one send with
//! a shared outcome vocabulary over the product's native detail, and a
//! per-operation recovery rule.
//!
//! The connector implements every BReg operation family, but an
//! ingestion job may send only some of them directly; the `breg`
//! module's `job_direct_admits` names which.

pub mod operation;

#[cfg(feature = "breg")]
pub mod breg;
