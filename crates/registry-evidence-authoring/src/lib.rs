//! The Evidence authoring form: the shape an adopter writes under a project
//! directory, and the single implementation of the checks that shape must
//! satisfy.
//!
//! This is a library beside `evidencectl`, not a second runtime. It sits
//! outside the frozen Version 1 runtime contract and adds no Evidence
//! semantics of its own: it describes what an adopter may write and reports
//! where a written document departs from it, so that a compiler and an editor
//! reach the same verdict from the same code.
//!
//! # Crate invariant: no input or output
//!
//! Nothing here reads a file, opens a socket, or starts a process. Every entry
//! point takes text or already-parsed values and returns values, [`Finding`]s,
//! or the shared reader's diagnostics. Reading the bytes is the caller's job,
//! which is what lets an editor run these checks against an unsaved buffer and
//! a compiler run them against a file on disk without either of them owning a
//! second copy of the rules.
//!
//! The invariant is enforced by `tests/no_io.rs`, which sweeps this crate's own
//! sources and its dependency list rather than trusting this paragraph.

pub mod compile;
pub mod derivation;
pub mod finding;
pub mod formats;
pub mod layout;
pub mod openapi;
pub mod project;
#[cfg(feature = "schema")]
pub mod schema;
pub mod target;
pub mod types;
pub mod validate;

pub use derivation::{validate_derive_fact_reads, validate_function};
pub use finding::{FieldPath, FieldStep, Finding};
pub use validate::{
    collection_pointers, valid_field_name, valid_local_identifier, validate_output_schema_document,
};
