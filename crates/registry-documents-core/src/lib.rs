// SPDX-License-Identifier: Apache-2.0

//! Source-neutral core of the Registry Stack Document Store.
//!
//! This crate owns the fixed artifact and route names, the closed problem
//! vocabulary, the HTTP wire documents, and the authored project model a
//! Document Store deployment is configured with. It contains no SQL, no
//! network, no file access, and no clock, so the runtime, adopter tooling,
//! and the client read the same contract.
//!
//! The runtime crate `registry-documents` builds its PostgreSQL store and
//! HTTP surface on top of this model. The dependency runs one way: this
//! crate depends on no other Document Store crate, only on shared
//! `registry-platform-*` primitives, and never on another product's runtime
//! or protocol types.

mod naming;
mod problem;
mod project;
mod wire;

pub use naming::*;
pub use problem::*;
pub use project::*;
pub use wire::*;
