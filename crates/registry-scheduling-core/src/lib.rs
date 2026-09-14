// SPDX-License-Identifier: Apache-2.0

//! Source-neutral core of Registry Scheduling.
//!
//! This crate owns the model an adopter authors and the decisions that model
//! implies, and nothing else: the policy types with their validators, the
//! supply ledger and its pure query methods, the admission evaluators, the
//! offline replay fixtures, the closed problem vocabulary, the HTTP wire
//! documents, and the fixed artifact names. It deliberately contains no
//! source protocol types, no SQL,
//! no I/O, and no clock: every evaluator takes the observed instant as an
//! explicit parameter, so the runtime inside its capacity transaction, the
//! explain path, and an offline fixture replay all run the same pure functions
//! and cannot disagree about what admits.
//!
//! The runtime crate `registry-scheduling` builds its PostgreSQL store, HTTP
//! surface, and workers on top of this model. Adopter tooling
//! (`registry-schedulingctl`) checks and replays authored projects against it.
//! The dependency runs one way: this crate depends only on shared
//! `registry-platform-*` primitives and never on another product's runtime or
//! protocol types.

mod admission;
mod diagnostics;
mod fixture;
mod model;
mod naming;
mod policy;
mod problem;
mod units;
mod wire;

pub use admission::*;
pub use diagnostics::*;
pub use fixture::*;
pub use model::*;
pub use naming::*;
pub use policy::*;
pub use problem::*;
pub use units::*;
pub use wire::*;
