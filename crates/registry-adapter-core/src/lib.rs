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
//!
//! The header predicates the runtime's request-header filter applies are
//! the crate's own, exported so the runtime consumes the one shared
//! definition rather than forking it:
//!
//! ```
//! // An RFC 9110 token is allowed; a reserved engine name is not.
//! assert!(registry_adapter_core::is_header_token("accept"));
//! assert!(registry_adapter_core::is_reserved_header_name("authorization"));
//! assert!(registry_adapter_core::is_engine_header_name("CamelHttpResponseCode"));
//! assert!(registry_adapter_core::is_engine_exchange_property_name("CamelSplitIndex"));
//! assert!(registry_adapter_core::is_facade_input_header_name("recordId"));
//! assert!(registry_adapter_core::is_route_unwritable_header_name("recordId"));
//! ```

mod auth;
mod checks;
mod diagnostics;
mod envelope;
mod fixture;
mod model;
mod naming;
mod pack;
mod problem;
mod profile;
mod project;
mod result_schema;
mod route;
mod runtime;
mod typed;

pub use auth::*;
pub use checks::*;
pub use diagnostics::*;
pub use envelope::*;
pub use fixture::*;
pub use model::*;
pub use naming::*;
pub use pack::*;
pub use problem::*;
pub use profile::*;
pub use project::*;
pub use result_schema::*;
pub use route::*;
pub use runtime::*;
