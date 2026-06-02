// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary runtime.

// The OpenAPI document is a single large `json!` literal; the pre-authorized-code
// paths push its expansion past the default macro recursion limit.
#![recursion_limit = "256"]

pub mod api;
pub(crate) mod credential_status;
pub(crate) mod federation;
pub(crate) mod metrics;
pub mod openapi;
pub(crate) mod preauth_state;
pub(crate) mod replay;
pub mod runtime;
pub mod self_attestation_rate_limit;
pub mod standalone;

pub(crate) const PROBLEM_TYPE_BASE_URL: &str = "https://docs.registry-notary.dev/problems";

pub use api::{
    router, EvidenceAuditContext, EvidenceErrorCodeContext, EvidenceIssuerResolver,
    RegistryNotaryApiState,
};
pub use openapi::openapi_document;
pub use runtime::{
    claim_summary, credential_profile_for, find_claim, format_time, formats, BatchEvaluateOptions,
    EvidenceStore, MemoState, RegistryNotaryRuntime, SourceReader,
};
pub use self_attestation_rate_limit::{
    SelfAttestationRateLimitBucket, SelfAttestationRateLimitError, SelfAttestationRateLimitKeys,
    SelfAttestationRateLimiter,
};
pub use standalone::{standalone_router, StandaloneServerError};
