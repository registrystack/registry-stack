// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary runtime.

// The OpenAPI document is a single large `json!` literal; the pre-authorized-code
// paths push its expansion past the default macro recursion limit.
#![recursion_limit = "256"]

pub mod api;
pub(crate) mod authz_details;
#[cfg(feature = "registry-notary-cel")]
pub mod cel_worker;
pub mod config_governed;
pub(crate) mod credential_status;
pub mod docs;
pub(crate) mod federation;
pub mod machine_quota;
pub(crate) mod metrics;
pub mod openapi;
pub(crate) mod posture;
pub(crate) mod preauth_state;
pub(crate) mod replay;
pub mod runtime;
pub mod self_attestation_rate_limit;
pub mod standalone;

pub(crate) const PROBLEM_TYPE_BASE_URL: &str =
    "https://id.registrystack.org/problems/registry-notary";

pub use api::{
    router, EvidenceAuditContext, EvidenceErrorCodeContext, EvidenceIssuerResolver,
    RegistryNotaryApiState,
};
pub use machine_quota::{MachineQuotaExceeded, MachineQuotaLimiter};
pub use openapi::openapi_document;
pub use runtime::{
    claim_summary, credential_profile_for, find_claim, format_time, formats, BatchEvaluateOptions,
    EvidenceStore, MemoState, RegistryNotaryRuntime, SourceReader,
};
pub use self_attestation_rate_limit::{
    SelfAttestationRateLimitBucket, SelfAttestationRateLimitError, SelfAttestationRateLimitKeys,
    SelfAttestationRateLimiter,
};
pub use standalone::{
    compile_notary_runtime, notary_admin_router_from_runtime, notary_public_router_from_runtime,
    notary_router_from_runtime, notary_routers_from_runtime, standalone_router,
    EvidenceIssuerRegistry, NotaryRouters, NotaryRuntimeSnapshot, StandaloneServerError,
};
