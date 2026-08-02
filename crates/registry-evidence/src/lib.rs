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
pub mod model;
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
pub mod verifier;

#[cfg(test)]
mod runtime_tests;

pub const EVIDENCE_SCHEMA_V1: &str = "registry.assertion-evidence/v1";
pub const EVIDENCE_DEFINITIONS_SCHEMA_V1: &str = "registry.evidence-definitions/v1";
pub const EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1: &str = "registry.unsigned-evidence-envelope/v1";
pub const EVIDENCE_JWS_TYP: &str = "evidence+jws";
pub const EVIDENCE_JWS_CTY: &str = "application/evidence+json";
pub const EVIDENCE_JWS_MEDIA_TYPE: &str = "application/jose+json";
pub const EVIDENCE_UNSIGNED_MEDIA_TYPE: &str =
    "application/vnd.registrystack.evidence-unsigned+json";
