// SPDX-License-Identifier: Apache-2.0

use axum::http::HeaderMap;
use axum::response::Response;
use registry_notary_core::{
    AccessMode, BoundedCorrelationId, ConfigMetadata, FEDERATION_PROTOCOL_V0_1,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::api::evidence_claim_hash;

use super::errors::FederationProblem;

#[derive(Debug)]
pub(super) struct FederationAuditOutcome {
    pub(super) decision: String,
    pub(super) verification_id: Option<String>,
    pub(super) claim_ids: Vec<String>,
    pub(super) error_code: Option<String>,
    pub(super) peer_node_id: Option<String>,
    pub(super) issuer: Option<String>,
    pub(super) profile: Option<String>,
    pub(super) purpose: Option<String>,
    pub(super) request_jti: Option<String>,
    pub(super) subject_ref_hash: Option<String>,
}

impl FederationAuditOutcome {
    pub(super) fn denied(problem: &FederationProblem) -> Self {
        Self {
            decision: "federated_evaluate_denied".to_string(),
            verification_id: None,
            claim_ids: Vec::new(),
            error_code: Some(problem.code.clone()),
            peer_node_id: None,
            issuer: None,
            profile: None,
            purpose: None,
            request_jti: None,
            subject_ref_hash: None,
        }
    }
}

pub(super) fn federation_audit_event(
    headers: &HeaderMap,
    response: &Response,
    audit: FederationAuditOutcome,
    audit_pipeline: Option<&crate::standalone::AuditPipeline>,
) -> registry_notary_core::EvidenceAuditEvent {
    let occurred_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    let federation_peer_id_hash = audit.peer_node_id.as_deref().and_then(|peer_node_id| {
        audit_pipeline.map(|pipeline| pipeline.hash_principal(peer_node_id))
    });
    registry_notary_core::EvidenceAuditEvent {
        event_id: Ulid::new().to_string(),
        occurred_at,
        principal_id_hash: None,
        decision: audit.decision,
        method: "POST".to_string(),
        path: "/federation/v1/evaluations".to_string(),
        status: response.status().as_u16(),
        verification_id: audit.verification_id,
        claim_hash: (!audit.claim_ids.is_empty()).then(|| evidence_claim_hash(&audit.claim_ids)),
        purposes: None,
        row_count: response.status().is_success().then_some(1),
        error_code: audit.error_code,
        access_mode: Some(AccessMode::MachineClient),
        federation_peer_id_hash,
        federation_issuer: audit.issuer,
        federation_profile: audit.profile,
        federation_purpose: audit.purpose,
        federation_request_jti: audit.request_jti,
        federation_subject_ref_hash: audit.subject_ref_hash,
        denial_code: None,
        token_claim_name: None,
        correlation_id: headers
            .get("x-request-id")
            .or_else(|| headers.get("x-correlation-id"))
            .and_then(|value| value.to_str().ok())
            .and_then(|value| BoundedCorrelationId::new(value.to_string()).ok()),
        credential_profile: None,
        protocol: ConfigMetadata::new(FEDERATION_PROTOCOL_V0_1).ok(),
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_version: None,
        policy_hash: None,
    }
}
