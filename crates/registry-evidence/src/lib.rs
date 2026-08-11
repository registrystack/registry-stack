//! Evidence Version 1 minimum-disclosure assertion runtime.

#[cfg(not(unix))]
compile_error!("registry-evidence Version 1 requires a Unix target for owner and file-identity security guarantees");

pub mod audit;
pub mod auth;
pub mod binding;
pub mod bundle;
#[doc(hidden)]
pub mod cli;
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
pub mod source_sqlite;
pub mod trace;
pub mod values;

/// The response formats, their payload contract, and the strict verifier are
/// owned by the portable `registry-evidence-verifier` crate and served here at
/// the runtime's own paths.
pub use registry_evidence_verifier::{
    sdjwt_vc, verifier, EVIDENCE_JWS_CTY, EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_JWS_TYP,
    EVIDENCE_REQUEST_BATCH_MEDIA_TYPE, EVIDENCE_REQUEST_BATCH_SCHEMA_V1, EVIDENCE_SCHEMA_V1,
    EVIDENCE_SD_JWT_VC_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_TYP, EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1,
    EVIDENCE_UNSIGNED_MEDIA_TYPE,
};

pub use cli::command;

#[cfg(test)]
mod runtime_tests;

pub const EVIDENCE_DEFINITIONS_SCHEMA_V1: &str = "registry.evidence-definitions/v1";

/// The batch issuance container is served by this runtime and consumed by no
/// verifier, so it is named here rather than in the portable verifier crate.
pub const EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE: &str =
    "application/vnd.registrystack.evidence.batch+json";
pub const SD_JWT_VC_BATCH_SCHEMA_V1: &str = "registry.sd-jwt-vc-batch-envelope/v1";

/// Ceiling on the serialized batch response, in bytes.
///
/// A batch multiplies one assertion by its member count, so the bound the
/// singular formats never needed becomes load-bearing here: a release that
/// cannot be answered within it is refused rather than served.
pub const MAX_SD_JWT_VC_BATCH_RESPONSE_BYTES: usize = 1_048_576;
