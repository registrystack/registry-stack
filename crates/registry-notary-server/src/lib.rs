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
pub(crate) mod digest;
pub mod docs;
pub(crate) mod federation;
pub(crate) mod json_path;
pub mod machine_quota;
pub(crate) mod metrics;
pub mod openapi;
pub(crate) mod posture;
pub(crate) mod preauth_state;
pub(crate) mod problem;
pub(crate) mod relay_client;
pub(crate) mod relay_contract;
#[cfg(feature = "relay-contract-test-support")]
#[doc(hidden)]
pub mod relay_contract_test_support;
pub(crate) mod replay;
pub(crate) mod request_context;
pub(crate) mod response_context;
pub mod runtime;
pub mod self_attestation_rate_limit;
pub mod standalone;
pub mod state_plane;

pub(crate) use problem::PROBLEM_TYPE_BASE_URL;

pub use api::{
    router, EvidenceAuditContext, EvidenceErrorCodeContext, EvidenceIssuerResolver,
    RegistryNotaryApiState,
};
pub use machine_quota::{MachineQuotaExceeded, MachineQuotaLimiter};
pub use openapi::openapi_document;
pub use runtime::{
    claim_summary, credential_profile_for, find_claim, format_time, formats, BatchEvaluateOptions,
    EvidenceStore, RegistryNotaryRuntime,
};
pub use self_attestation_rate_limit::{
    SelfAttestationRateLimitBucket, SelfAttestationRateLimitError, SelfAttestationRateLimitKeys,
    SelfAttestationRateLimiter,
};
pub use standalone::{
    compile_notary_runtime, compile_notary_runtime_with_provenance,
    notary_admin_router_from_runtime, notary_public_router_from_runtime,
    notary_router_from_runtime, notary_routers_from_runtime, standalone_router,
    verify_relay_from_config, EvidenceIssuerRegistry, NotaryRouters, NotaryRuntimeSnapshot,
    StandaloneServerError,
};
