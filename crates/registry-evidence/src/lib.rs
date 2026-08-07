//! Evidence Version 1 minimum-disclosure assertion runtime.

#[cfg(not(unix))]
compile_error!("registry-evidence Version 1 requires a Unix target for owner and file-identity security guarantees");

pub mod audit;
pub mod auth;
pub mod binding;
pub mod bundle;
pub mod config;
pub mod contracts;
pub mod kernel;
pub mod local_verification;
pub mod model;
pub mod observability;
pub mod problem;
pub mod rate_limit;
pub mod rhai_runtime;
pub mod runtime;
pub mod secrets;
pub mod selector;
pub mod server;
pub mod signing;
pub mod source;
pub mod values;

/// The response formats, their payload contract, and the strict verifier are
/// owned by the portable `registry-evidence-verifier` crate and served here at
/// the runtime's own paths.
pub use registry_evidence_verifier::{
    sdjwt_vc, verifier, EVIDENCE_JWS_CTY, EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_JWS_TYP,
    EVIDENCE_SCHEMA_V1, EVIDENCE_SD_JWT_VC_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_TYP,
    EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1, EVIDENCE_UNSIGNED_MEDIA_TYPE,
};

#[cfg(test)]
mod runtime_tests;

pub const EVIDENCE_DEFINITIONS_SCHEMA_V1: &str = "registry.evidence-definitions/v1";
