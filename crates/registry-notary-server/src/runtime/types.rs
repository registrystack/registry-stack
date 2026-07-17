// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) type ClaimVersionSelections = BTreeMap<String, Option<String>>;
#[derive(Clone)]
pub(super) struct ClaimResultInternal {
    pub(super) evaluation_id: String,
    pub(super) claim_id: String,
    pub(super) claim_version: String,
    pub(super) subject_type: String,
    pub(super) target: EvidenceEntity,
    pub(super) requester: Option<EvidenceEntity>,
    pub(super) value: Value,
    pub(super) redaction_fields: BTreeSet<String>,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) provenance: ClaimProvenance,
    pub(super) relay_consultation_ids: BTreeSet<String>,
    pub(super) own_issuance_provenance: Option<ClaimIssuanceProvenanceInternal>,
}

impl std::fmt::Debug for ClaimResultInternal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaimResultInternal")
            .field("evaluation_id", &"[REDACTED]")
            .field("claim_id", &self.claim_id)
            .field("claim_version", &self.claim_version)
            .field("subject_type", &self.subject_type)
            .field("target", &"[REDACTED]")
            .field("requester", &"[REDACTED]")
            .field("value", &"[REDACTED]")
            .field("redaction_fields", &self.redaction_fields)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("provenance", &self.provenance)
            .field("relay_consultation_ids", &"[REDACTED]")
            .field("own_issuance_provenance", &self.own_issuance_provenance)
            .finish()
    }
}

#[derive(Clone)]
pub(super) struct ClaimIssuanceProvenanceInternal {
    pub(super) claim: StoredIssuanceClaimProvenance,
    pub(super) consultation: StoredIssuanceConsultationProvenance,
}

impl std::fmt::Debug for ClaimIssuanceProvenanceInternal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaimIssuanceProvenanceInternal")
            .field("claim", &self.claim)
            .field("consultation", &self.consultation)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BatchEvaluateOptions<'a> {
    pub header_purpose: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
    pub owner_quota: Option<(&'a crate::MachineQuotaLimiter, u32)>,
}

/// Evaluation policy identity threaded into per-claim provenance
/// (`generated_by.policy_id` / `policy_version` / `policy_hash`). All optional:
/// machine-client flows evaluate under no named policy and leave these unset,
/// while subject-access flows carry the policy that authorized the result.
#[derive(Clone, Default)]
pub(super) struct EvaluationPolicy {
    pub(super) policy_id: Option<String>,
    pub(super) policy_version: Option<String>,
    pub(super) policy_hash: Option<String>,
}

pub(super) struct ClaimEvaluationContext {
    pub(super) evidence: Arc<EvidenceConfig>,
    pub(super) subject_access_rate_keys: Arc<SubjectAccessRateLimitKeys>,
    pub(super) evaluation_capability: EvaluationCapability,
    pub(super) relay_plan: Option<Arc<RequestScopedRelayPlan>>,
    pub(super) context: EvidenceRequestContext,
    pub(super) purpose: String,
    pub(super) correlation_id: Option<BoundedCorrelationId>,
    pub(super) evaluation_id: String,
    pub(super) policy: EvaluationPolicy,
    pub(super) now: OffsetDateTime,
    pub(super) claim_versions: ClaimVersionSelections,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) cel_worker: Option<Arc<CelWorker>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) cel_concurrency: Option<Arc<Semaphore>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) cel_config: Arc<RegistryNotaryCelConfig>,
}

#[cfg_attr(not(feature = "registry-notary-cel"), allow(dead_code))]
pub(super) struct CelEvaluationContext<'a> {
    pub(super) evidence: &'a EvidenceConfig,
    pub(super) claim: &'a ClaimDefinition,
    pub(super) expression: &'a str,
    pub(super) bindings: &'a CelBindingsConfig,
    pub(super) claims: &'a BTreeMap<String, ClaimResultInternal>,
    pub(super) consultation_outputs: &'a BTreeMap<String, Value>,
    pub(super) variables: &'a registry_notary_core::RequestVariables,
    pub(super) subject: Option<&'a SubjectRequest>,
    pub(super) target: &'a EvidenceEntity,
    pub(super) purpose: &'a str,
    pub(super) today: String,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) worker: Option<&'a CelWorker>,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) config: &'a RegistryNotaryCelConfig,
}
