//! Tooling-only support for the pinned upstream ThunderID release.
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
//!   integration tests depend on it. The BREG, Evidence, and OID4VCI
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
pub mod check;
pub mod container;
pub mod description;
#[cfg(feature = "session")]
pub mod grant;
#[cfg(feature = "session")]
pub mod grant_file;
pub mod identity_check;
pub mod identity_deployment;
pub mod identity_facts;
pub mod identity_generate;
pub mod issuer;
pub mod local;
#[cfg(feature = "session")]
mod local_session;
pub mod render;
#[cfg(test)]
mod render_golden_tests;
#[cfg(feature = "schema")]
pub mod schema;
pub mod task_connection;
mod validate;
pub mod version;

/// Test-only fixture support. Never used by, or reachable from, any runtime
/// product; the integration launcher and this crate's own tests are its
/// consumers.
#[doc(hidden)]
pub mod testing;

/// Every way this crate refuses. Fixed text, numeric exit statuses and
/// private file paths only: no secret, key, assertion, token, or upstream
/// error body ever travels in one of these.
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
    /// A one-shot did not succeed. Only its numeric exit status
    /// and the path of the owner-only file holding its redacted output
    /// travel here, never the output.
    #[error(
        "a command this session owns did not succeed: {step}; {}",
        container::one_shot_report(.one_shot, *.exit_code, .log_file.as_deref())
    )]
    OneShotFailed {
        step: &'static str,
        one_shot: &'static str,
        exit_code: Option<i32>,
        log_file: Option<std::path::PathBuf>,
    },
    /// Identity generation refused its inputs. Names a structural location
    /// (a file label and a pointer or index), never a value read from a file
    /// (CFG-SEC-3).
    #[error("identity generation was refused ({code}): {message} (at {location})")]
    IdentityRefused {
        code: &'static str,
        message: &'static str,
        location: String,
    },
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
    /// A generated output path is already taken, or was taken while the
    /// output was being written. Nothing at that path was changed.
    #[error("the output directory already exists; choose a new directory")]
    OutputExists,
    /// A file this crate reads was refused. Its report places every finding
    /// and repeats no value it read (CFG-SEC-3).
    #[error("{what} was refused: {fix}\n{}", .report.render_human().trim_end())]
    FileRefused {
        what: &'static str,
        fix: &'static str,
        report: Box<registry_platform_yaml::Report>,
    },
}

impl ToolingError {
    /// The findings of a refused file, for a caller that prints them as JSON.
    pub fn report(&self) -> Option<&registry_platform_yaml::Report> {
        match self {
            ToolingError::FileRefused { report, .. } => Some(report),
            _ => None,
        }
    }
}
