// SPDX-License-Identifier: Apache-2.0
//! Response extensions shared by handlers, middleware, audit, and metrics.

use registry_notary_core::{
    AccessMode, ConfigAuditEvent, ConfigMetadata, EvidenceBatchItemAuditEvent,
    EvidenceEntityReference, Hashed, PolicyIdentifier, RateLimitBucket, SelfAttestationDenialCode,
};

#[derive(Clone, Default)]
pub struct EvidenceAuditContext {
    pub verification_id: Option<String>,
    pub verification_decision: Option<String>,
    pub claim_hash: Option<String>,
    pub purposes: Option<Vec<String>>,
    pub row_count: Option<u64>,
    pub source_read_count: Option<u64>,
    /// Restricted cross-service correlation. Response extensions feed the
    /// audit sink only and are never serialized into the HTTP response body.
    pub relay_consultation_ids: Vec<String>,
    pub forwarded: Option<bool>,
    pub access_mode: Option<AccessMode>,
    pub denial_code: Option<SelfAttestationDenialCode>,
    pub token_claim_name: Option<ConfigMetadata>,
    pub credential_profile: Option<ConfigMetadata>,
    pub protocol: Option<ConfigMetadata>,
    pub credential_configuration_id: Option<ConfigMetadata>,
    pub holder_binding_mode: Option<ConfigMetadata>,
    pub rate_limit_bucket: Option<RateLimitBucket>,
    pub policy_hash: Option<Hashed<PolicyIdentifier>>,
    pub target_type: Option<String>,
    pub target_ref_hash: Option<Hashed<EvidenceEntityReference>>,
    pub requester_type: Option<String>,
    pub requester_ref_hash: Option<Hashed<EvidenceEntityReference>>,
    pub matching_policy_id: Option<String>,
    pub matching_policy_hash: Option<Hashed<PolicyIdentifier>>,
    pub matching_evaluated_rule_ids: Option<Vec<String>>,
    pub ecosystem_binding_id: Option<String>,
    pub ecosystem_binding_version: Option<String>,
    pub pack_id: Option<String>,
    pub pack_version: Option<String>,
    pub matching_method: Option<String>,
    pub matching_outcome: Option<String>,
    pub matching_error_code: Option<String>,
    pub redacted_fields: Option<Vec<String>>,
    pub batch_items: Option<Vec<EvidenceBatchItemAuditEvent>>,
    pub source_sidecar_config_hashes: Option<Vec<String>>,
    pub config: Option<ConfigAuditEvent>,
}

impl std::fmt::Debug for EvidenceAuditContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceAuditContext")
            .field("verification_id", &"[REDACTED]")
            .field("verification_decision", &self.verification_decision)
            .field("source_read_count", &self.source_read_count)
            .field("relay_consultation_ids", &"[REDACTED]")
            .field("forwarded", &self.forwarded)
            .field("access_mode", &self.access_mode)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct EvidenceErrorCodeContext(pub String);
