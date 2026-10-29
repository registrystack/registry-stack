// SPDX-License-Identifier: Apache-2.0

//! Source-neutral core of the Registry Stack Adapter.
//!
//! This crate owns the Adapter's source-neutral model: the profile, pack,
//! project, runtime-config, and fixture artifacts, the bounded Camel route
//! model their packs carry, the closed `adapter.*` problem vocabulary, and
//! the pure authoring checks those artifacts must satisfy
//! (`products/adapter/CONCEPT.md` section 8.1). It contains no I/O: no
//! network, no file access, no clock, and no upstream or product types, so
//! the runtime, the operator tooling, and the offline `adapterctl check`
//! read the same contract.
//!
//! The runtime crate `registry-adapter` builds its facade, route
//! interpreter, security surface, and journal on top of this model, and
//! `registry-adapterctl` drives its checks. The dependency runs one way:
//! this crate depends on no other Adapter crate.

mod auth;
mod checks;
mod diagnostics;
mod fixture;
mod model;
mod naming;
mod pack;
mod problem;
mod profile;
mod project;
mod route;
mod runtime;

pub use auth::*;
pub use checks::*;
pub use diagnostics::*;
pub use fixture::*;
pub use model::*;
pub use naming::*;
pub use pack::*;
pub use problem::*;
pub use profile::*;
pub use project::*;
pub use route::*;
pub use runtime::*;
