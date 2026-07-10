// SPDX-License-Identifier: Apache-2.0

use axum::response::Response;
use registry_notary_core::{
    AccessMode, ConfigMetadata, FederationPeerConfig, FEDERATION_PROTOCOL_V0_1,
};
use registry_platform_oidc::VerifiedToken;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;

use crate::api::evidence_claim_hash;

use super::errors::FederationProblem;

#[derive(Clone, Debug, Default)]
pub(super) struct FederationAuditContext {
    pub(super) claim_ids: Vec<String>,
    pub(super) peer_node_id: Option<String>,
    pub(super) issuer: Option<String>,
    pub(super) profile: Option<String>,
    pub(super) purpose: Option<String>,
    pub(super) request_jti: Option<String>,
    pub(super) subject_ref_hash: Option<String>,
}

impl FederationAuditContext {
    pub(super) fn from_verified(peer: &FederationPeerConfig, verified: &VerifiedToken) -> Self {
        Self {
            peer_node_id: Some(peer.node_id.clone()),
            issuer: Some(peer.issuer.clone()),
            profile: verified
                .claims
                .extra
                .get("profile")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            purpose: verified
                .claims
                .extra
                .get("purpose")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            request_jti: verified
                .claims
                .extra
                .get("jti")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            ..Self::default()
        }
    }

    pub(super) fn denied(&self, problem: FederationProblem) -> FederationDeniedOutcome {
        FederationDeniedOutcome::with_context(problem, self.clone())
    }
}

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
        Self::denied_with_context(problem, FederationAuditContext::default())
    }

    pub(super) fn denied_with_context(
        problem: &FederationProblem,
        context: FederationAuditContext,
    ) -> Self {
        Self {
            decision: "federated_evaluate_denied".to_string(),
            verification_id: None,
            claim_ids: context.claim_ids,
            error_code: Some(problem.code.clone()),
            peer_node_id: context.peer_node_id,
            issuer: context.issuer,
            profile: context.profile,
            purpose: context.purpose,
            request_jti: context.request_jti,
            subject_ref_hash: context.subject_ref_hash,
        }
    }

    pub(super) fn into_denied(mut self, problem: &FederationProblem) -> Self {
        self.decision = "federated_evaluate_denied".to_string();
        self.error_code = Some(problem.code.clone());
        self
    }
}

#[derive(Debug)]
pub(super) struct FederationDeniedOutcome {
    pub(super) problem: FederationProblem,
    pub(super) audit: FederationAuditOutcome,
}

impl FederationDeniedOutcome {
    pub(super) fn with_context(
        problem: FederationProblem,
        context: FederationAuditContext,
    ) -> Self {
        let audit = FederationAuditOutcome::denied_with_context(&problem, context);
        Self { problem, audit }
    }
}

impl From<FederationProblem> for FederationDeniedOutcome {
    fn from(problem: FederationProblem) -> Self {
        let audit = FederationAuditOutcome::denied(&problem);
        Self { problem, audit }
    }
}

pub(super) fn federation_audit_event(
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
        scopes_used: Vec::new(),
        decision: audit.decision,
        method: "POST".to_string(),
        path: "/federation/v1/evaluations".to_string(),
        status: response.status().as_u16(),
        verification_id: audit.verification_id,
        claim_hash: (!audit.claim_ids.is_empty()).then(|| evidence_claim_hash(&audit.claim_ids)),
        purposes: None,
        row_count: response.status().is_success().then_some(1),
        source_read_count: None,
        forwarded: None,
        error_code: audit.error_code,
        access_mode: Some(AccessMode::MachineClient),
        federation_peer_id_hash,
        federation_issuer: audit.issuer,
        federation_profile: audit.profile,
        federation_purpose: audit.purpose,
        federation_request_jti_hash: audit.request_jti.as_deref().and_then(|request_jti| {
            audit_pipeline.map(|pipeline| pipeline.hash_request_identifier(request_jti))
        }),
        federation_subject_ref_hash: audit.subject_ref_hash,
        denial_code: None,
        token_claim_name: None,
        correlation_id_hash: crate::standalone::current_request_correlation_id()
            .as_ref()
            .and_then(|correlation_id| {
                audit_pipeline
                    .map(|pipeline| pipeline.hash_request_identifier(correlation_id.as_str()))
            }),
        credential_profile: None,
        protocol: ConfigMetadata::new(FEDERATION_PROTOCOL_V0_1).ok(),
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_version: None,
        policy_hash: None,
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        matching_policy_id: None,
        matching_policy_hash: None,
        matching_evaluated_rule_ids: None,
        ecosystem_binding_id: None,
        ecosystem_binding_version: None,
        pack_id: None,
        pack_version: None,
        matching_method: None,
        matching_outcome: None,
        matching_error_code: None,
        redacted_fields: None,
        batch_items: None,
        source_sidecar_config_hashes: None,
        config: None,
    }
}
