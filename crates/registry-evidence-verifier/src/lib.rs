//! Portable Evidence Version 1 response-verification core.
//!
//! This crate owns the response wire formats, the Evidence payload contract,
//! and the strict relying-party verifier. It carries no server, no source
//! access, no configuration loading, and no service-runtime dependency, so a
//! client can verify a stored response with the same rules the runtime applies.
//!
//! Portable here means free of the service runtime, not target independent.
//! The crypto stack reaches `aws-lc-sys`, so a build needs a C toolchain and is
//! limited to the targets `aws-lc-sys` supports, which excludes `wasm32`. Two
//! edges lead there: `registry-platform-crypto` uses `aws-lc-rs` for RS256 key
//! handling and verification, and `registry-platform-sdjwt` reaches the same
//! library through `jsonwebtoken`.

pub mod contracts;
pub mod model;
pub mod sdjwt_vc;
pub mod verifier;

#[cfg(test)]
mod fixtures;

use serde::{Deserialize, Serialize};

pub const EVIDENCE_SCHEMA_V1: &str = "registry.assertion-evidence/v1";
pub const EVIDENCE_UNSIGNED_ENVELOPE_SCHEMA_V1: &str = "registry.unsigned-evidence-envelope/v1";
pub const EVIDENCE_JWS_TYP: &str = "evidence+jws";
pub const EVIDENCE_JWS_CTY: &str = "application/evidence+json";
pub const EVIDENCE_JWS_MEDIA_TYPE: &str = "application/jose+json";
/// Compact SD-JWT VC serialization of the same assertion. The profile adds a
/// response format only; it introduces no credential lifecycle.
pub const EVIDENCE_SD_JWT_VC_MEDIA_TYPE: &str = "application/dc+sd-jwt";
pub const EVIDENCE_SD_JWT_VC_TYP: &str = "dc+sd-jwt";
pub const EVIDENCE_UNSIGNED_MEDIA_TYPE: &str =
    "application/vnd.registrystack.evidence-unsigned+json";

#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    schemars::JsonSchema,
    utoipa::ToSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum AssuranceProfile {
    Local,
    Production,
    EvidenceGrade,
}

impl AssuranceProfile {
    /// Only the explicit local profile may be authored before fixture
    /// coverage exists. Deployable profiles retain the complete fixture gate.
    pub fn requires_fixtures(self) -> bool {
        matches!(self, Self::Production | Self::EvidenceGrade)
    }
}
