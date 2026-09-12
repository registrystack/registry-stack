//! Tooling-only support for pinned ThunderID and its reviewed native extensions.
//!
//! This crate exists so adopter CLIs and integration tests can stand up one
//! development session's ThunderID container, render the pinned release's
//! native declarative resources, perform the upstream bootstrap one-shot, and
//! read back the endpoints and public registration information — without any
//! runtime product gaining a dependency on an issuer implementation.
//!
//! It is deliberately not a general identity platform:
//!
//! - It opens no listener and ships no binary; only adopter CLIs and
//!   integration tests depend on it. The BREG, Evidence, Relay, and OID4VCI
//!   runtime crates must not.
//! - It renders what an owning CLI's validated [`description::IssuerDescription`]
//!   states. It knows no product entity names, institutions, people, or
//!   business purposes, and it must never grow any.
//! - The upstream YAML it writes is the handoff to an externally operated
//!   ThunderID: there is no controller, reconciler, standing admin credential,
//!   or Registry-owned issuer service here.
//! - One instance owns one development session's container. It never stops,
//!   removes, or claims a container or volume it did not create, and its
//!   destructive reset is a separate, explicitly requested operation.
//!
//! The upstream version and image this crate will use live in
//! [`thunderid-version.json`] beside this crate's manifest, and nowhere else;
//! tooling, examples, and CI all read that one pin.

pub mod bootstrap;
pub mod citizen;
pub mod container;
pub mod description;
pub mod grant;
pub mod grant_file;
pub mod issuer;
pub mod local;
mod local_session;
pub mod render;
pub mod version;

/// Test-only fixture support. Never used by, or reachable from, any runtime
/// product; the integration launcher and this crate's own tests are its
/// consumers.
#[doc(hidden)]
pub mod testing;

/// Every way this crate refuses. Fixed text only: no secret, key, assertion,
/// token, or upstream error body ever travels in one of these.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolingError {
    #[error("the ThunderID pin is invalid: {reason}")]
    InvalidPin { reason: &'static str },
    #[error("the issuer description is invalid: {reason}")]
    InvalidDescription { reason: &'static str },
    #[error("the rendered upstream resources are invalid: {reason}")]
    InvalidRender { reason: &'static str },
    #[error("the development session state is unusable: {reason}")]
    InvalidState { reason: &'static str },
    #[error("a command this session owns did not succeed: {step}")]
    CommandFailed { step: &'static str },
    #[error("the issuer did not become reachable: {step}")]
    Unreachable { step: &'static str },
    #[error("the approved task grant could not be acquired: {reason}")]
    GrantAcquisition { reason: &'static str },
    #[error("the functional token check failed: {reason}")]
    TokenCheck { reason: &'static str },
    #[error("an unexpected port occupant refused this session: {detail}")]
    PortOccupied { detail: String },
    #[error("the filesystem refused this session: {reason}")]
    Filesystem { reason: &'static str },
}
