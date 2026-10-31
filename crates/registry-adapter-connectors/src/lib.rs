// SPDX-License-Identifier: Apache-2.0
//! Native product connectors for the Adapter's ingestion mode.
//!
//! A connector turns one prepared delivery attempt into exactly one typed
//! call on a maintained Registry Stack product client, and nothing else:
//! never hand-authored HTTP, never a product database, never a product
//! runtime or tooling crate (`products/adapter/CONCEPT.md` section 17.3).
//! The crate is linked by no facade binary; each product connector is
//! compiled only behind its off-by-default cargo feature, and the
//! dependency-direction gate in `products/adapter/scripts/` holds the
//! boundary mechanically.
//!
//! The [`operation`] module carries the operation contract the delivery
//! runner calls: a descriptor that names what an operation is and needs,
//! an exact persistable prepared form with no bearer token, one send with
//! a shared outcome vocabulary over the product's native detail, and a
//! per-operation recovery rule. Product modules implement it over their
//! client and add nothing to the route engine's vocabulary.

pub mod operation;

#[cfg(feature = "breg")]
pub mod breg;
#[cfg(feature = "documents")]
pub mod documents;
#[cfg(feature = "scheduling")]
pub mod scheduling;
