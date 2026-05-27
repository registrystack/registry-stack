// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Witness runtime.

pub mod api;
pub(crate) mod federation;
pub mod openapi;
pub mod runtime;
pub mod self_attestation_rate_limit;
pub mod standalone;

pub(crate) const PROBLEM_TYPE_BASE_URL: &str = "https://docs.registry-witness.dev/problems";

pub use api::{
    router, EvidenceAuditContext, EvidenceErrorCodeContext, EvidenceIssuerResolver,
    RegistryWitnessApiState,
};
pub use openapi::openapi_document;
pub use runtime::{
    claim_summary, credential_profile_for, find_claim, format_time, formats, BatchEvaluateOptions,
    EvidenceStore, MemoState, RegistryWitnessRuntime, SourceReader,
};
pub use self_attestation_rate_limit::{
    SelfAttestationRateLimitBucket, SelfAttestationRateLimitError, SelfAttestationRateLimitKeys,
    SelfAttestationRateLimiter,
};
pub use standalone::{standalone_router, StandaloneServerError};
