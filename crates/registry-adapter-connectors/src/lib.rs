// SPDX-License-Identifier: Apache-2.0
//! Native Registry Stack destination connectors behind explicit,
//! off-by-default features.
//!
//! A connector turns one prepared delivery attempt into exactly one typed
//! call on `registry-breg-client`, and nothing else: never hand-authored
//! HTTP, never a product database, never a product runtime or tooling
//! crate. The crate is linked by no facade binary and only by the job
//! host's explicit destination features. The dependency-direction gate
//! in `products/adapter/scripts/` holds that boundary mechanically.
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

#[cfg(feature = "coordinator-event")]
pub mod coordinator_event;

#[cfg(feature = "native-test-support")]
#[path = "../tests/support/breg_native_service.rs"]
pub mod test_support;
