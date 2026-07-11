// SPDX-License-Identifier: Apache-2.0
//! Standalone Registry Notary assembly, auth, audit, and HTTP source connectors.

mod runtime;

pub use runtime::{
    compile_notary_runtime, compile_notary_runtime_with_provenance, find_credential,
    notary_admin_router_from_runtime, notary_public_router_from_runtime,
    notary_router_from_runtime, notary_routers_from_runtime, notary_shared_router_from_runtime,
    standalone_router, EvidenceIssuerRegistry, HttpEvidenceSources, NotaryRouters,
    NotaryRuntimeSnapshot, ResolvedCredential, StandaloneServerError,
};

pub(crate) use runtime::{
    audit_error_response, constant_time_eq, current_request_correlation_id,
    generate_numeric_tx_code, generate_opaque_token, get_json_path, new_request_correlation_id,
    pkce_s256_challenge, pre_auth_audit_event, with_request_correlation_id, AuditPipeline,
    AuthAuditState, DeploymentGateState, PreAuthAuditFields, PreAuthRuntime, SignerReadiness,
};
