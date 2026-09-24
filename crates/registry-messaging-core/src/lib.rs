// SPDX-License-Identifier: Apache-2.0

//! Source-neutral core of Registry Messaging.
//!
//! This crate owns the model a Messaging deployment is configured with and the
//! decisions that model implies, and nothing else: the fixed artifact and
//! route names, the closed problem vocabulary, the HTTP wire documents, the
//! access profiles a caller is resolved to, and the pure authorization and
//! visibility functions over them. It deliberately contains no SQL, no
//! network, no file access, and no clock, so the runtime and adopter tooling
//! run the same decisions and cannot disagree about who may send or see what.
//!
//! The runtime crate `registry-messaging` builds its PostgreSQL store, HTTP
//! surface, and token verification on top of this model. The dependency runs
//! one way: this crate depends on no other Registry Stack crate, and never on
//! another product's runtime or protocol types.

mod access;
mod callback;
mod content;
mod naming;
mod package;
mod problem;
mod receipt;
mod render;
mod sms;
mod template;
mod visibility;
mod wire;

pub use access::*;
pub use callback::*;
pub use content::*;
pub use naming::*;
pub use package::*;
pub use problem::*;
pub use receipt::*;
pub use render::*;
pub use sms::*;
pub use template::*;
pub use visibility::*;
pub use wire::*;
