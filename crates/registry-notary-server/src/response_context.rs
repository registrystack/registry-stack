// SPDX-License-Identifier: Apache-2.0
//! Response extensions shared by handlers, middleware, audit, and metrics.

use registry_notary_core::{
    AccessMode, ConfigAuditEvent, ConfigMetadata, EvidenceBatchItemAuditEvent,
    EvidenceEntityReference, Hashed, PolicyIdentifier, RateLimitBucket, SelfAttestationDenialCode,
};

#[derive(Debug, Clone, Default)]
pub struct EvidenceAuditContext {
    pub verification_id: Option<String>,
    pub verification_decision: Option<String>,
    pub claim_hash: Option<String>,
    pub purposes: Option<Vec<String>>,
    pub row_count: Option<u64>,
    pub source_read_count: Option<u64>,
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

#[derive(Debug, Clone)]
pub struct EvidenceErrorCodeContext(pub String);
