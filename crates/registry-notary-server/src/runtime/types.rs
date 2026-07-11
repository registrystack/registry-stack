// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(super) type FetchMemo = Arc<MemoState>;

/// Result of loading a single source binding: the row value plus, when the
/// value came from the batch memo, the original observation timestamp so the
/// caller can pin `iat` to the upstream read time.
pub(super) type BindingFetchResult =
    Result<(Value, Option<OffsetDateTime>, BindingPolicyEffect), EvidenceError>;

pub(super) type ClaimVersionSelections = BTreeMap<String, Option<String>>;

pub(super) const SOURCE_LOOKUP_CONTEXT_ATTRIBUTE_PREFIX: &str = "__registry_notary_source_lookup_";
pub(super) type PurposeConstraints = Vec<Vec<String>>;
#[derive(Debug, Clone)]
pub(super) struct ClaimResultInternal {
    pub(super) evaluation_id: String,
    pub(super) claim_id: String,
    pub(super) claim_version: String,
    pub(super) subject_type: String,
    pub(super) target: EvidenceEntity,
    pub(super) requester: Option<EvidenceEntity>,
    pub(super) matching: Option<MatchingMetadata>,
    pub(super) value: Value,
    pub(super) redaction_fields: BTreeSet<String>,
    pub(super) issued_at: OffsetDateTime,
    pub(super) expires_at: Option<OffsetDateTime>,
    pub(super) provenance: ClaimProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BindingMatchingPolicyAudit {
    pub(super) policy_id: String,
    pub(super) policy_hash: String,
    pub(super) evaluated_rule_ids: Vec<String>,
}

impl BindingMatchingPolicyAudit {
    pub(super) fn new(audit: PdpDecisionAudit) -> Self {
        Self {
            policy_id: audit.policy_id,
            policy_hash: audit.policy_hash,
            evaluated_rule_ids: dedupe_preserving_order(audit.evaluated_rule_ids),
        }
    }

    pub(super) fn rule_ids(&self) -> Vec<String> {
        self.evaluated_rule_ids.clone()
    }
}

pub(super) fn dedupe_preserving_order(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct MatchingPolicyAudit {
    pub(super) by_binding_id: BTreeMap<String, BindingMatchingPolicyAudit>,
}

impl MatchingPolicyAudit {
    pub(super) fn record(&mut self, binding_id: String, audit: PdpDecisionAudit) {
        match self.by_binding_id.entry(binding_id) {
            Entry::Occupied(mut occupied) => {
                let entry = occupied.get_mut();
                debug_assert_eq!(entry.policy_id, audit.policy_id);
                debug_assert_eq!(entry.policy_hash, audit.policy_hash);
                for rule_id in audit.evaluated_rule_ids {
                    if !entry.evaluated_rule_ids.contains(&rule_id) {
                        entry.evaluated_rule_ids.push(rule_id);
                    }
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(BindingMatchingPolicyAudit::new(audit));
            }
        }
    }

    pub(super) fn for_binding(&self, binding_id: &str) -> Option<&BindingMatchingPolicyAudit> {
        self.by_binding_id.get(binding_id)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.by_binding_id.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct BatchEvaluateOptions<'a> {
    pub header_purpose: Option<&'a str>,
    pub idempotency_key: Option<&'a str>,
    /// Test-only observer: when set, the runtime uses this `MemoState` as the
    /// per-batch memo instead of constructing its own, letting tests read
    /// `hits()` / `misses()` after the call returns. Production callers leave
    /// this `None`.
    pub memo_observer: Option<&'a Arc<MemoState>>,
}

/// Evaluation policy identity threaded into per-claim provenance
/// (`generated_by.policy_id` / `policy_version` / `policy_hash`). All optional:
/// machine-client flows evaluate under no named policy and leave these unset,
/// while self-attestation flows carry the policy that authorized the result.
#[derive(Clone, Default)]
pub(super) struct EvaluationPolicy {
    pub(super) policy_id: Option<String>,
    pub(super) policy_version: Option<String>,
    pub(super) policy_hash: Option<String>,
}

pub(super) struct ClaimEvaluationContext {
    pub(super) evidence: Arc<EvidenceConfig>,
    pub(super) source: Arc<dyn SourceReader>,
    pub(super) self_attestation_rate_keys: Arc<SelfAttestationRateLimitKeys>,
    pub(super) source_capability: SourceCapability,
    pub(super) context: EvidenceRequestContext,
    pub(super) trusted_policy: TrustedPolicyContext,
    pub(super) purpose: String,
    pub(super) disclosure: DisclosureProfile,
    pub(super) format: String,
    pub(super) correlation_id: Option<BoundedCorrelationId>,
    pub(super) evaluation_id: String,
    pub(super) policy: EvaluationPolicy,
    pub(super) now: OffsetDateTime,
    // Per-request cap on parallel source bindings. Acquired only inside
    // `load_sources`, never at the claim level: sibling claims fan out
    // without permits (pure CPU), and only the actual upstream-bound
    // bindings consume permits. Acquiring at both levels with one shared
    // semaphore would deadlock when `bindings <= concurrent claims`.
    pub(super) binding_concurrency: Arc<Semaphore>,
    // Per-batch memoization table. Present only during `batch_evaluate`;
    // `None` for single-subject `evaluate` calls where there are no sibling
    // subjects to share results with.
    pub(super) fetch_memo: Option<FetchMemo>,
    pub(super) claim_versions: ClaimVersionSelections,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) cel_worker: Option<Arc<CelWorker>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) cel_concurrency: Option<Arc<Semaphore>>,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) cel_config: Arc<RegistryNotaryCelConfig>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct TrustedPolicyContext {
    pub(super) authorization_details: Option<EvidenceAuthorizationDetails>,
    pub(super) request_claims: Vec<ClaimRef>,
    pub(super) legal_basis_ref: Option<String>,
    pub(super) consent_ref: Option<String>,
    pub(super) jurisdiction: Option<String>,
    pub(super) assurance_level: Option<String>,
    pub(super) subject_binding_claim: Option<String>,
    pub(super) subject_binding_value: Option<String>,
    pub(super) checked_scopes: BTreeSet<String>,
}

impl TrustedPolicyContext {
    pub(super) fn from_principal(principal: &EvidencePrincipal) -> Self {
        let checked_scopes = principal.scopes.iter().cloned().collect();
        let subject_binding_claim = principal
            .verified_claims
            .as_ref()
            .and_then(|claims| claims.subject_binding_claim.as_ref())
            .map(|claim| claim.as_str().to_string());
        let subject_binding_value = principal
            .verified_claims
            .as_ref()
            .and_then(|claims| claims.subject_binding_value.as_ref())
            .map(|value| value.as_str().to_string());
        let Some(details) = principal.authorization_details.as_ref() else {
            return Self {
                checked_scopes,
                subject_binding_claim,
                subject_binding_value,
                ..Self::default()
            };
        };
        Self {
            authorization_details: Some(details.clone()),
            request_claims: Vec::new(),
            legal_basis_ref: trusted_non_empty(details.legal_basis_ref.as_deref()),
            consent_ref: trusted_non_empty(details.consent_ref.as_deref()),
            jurisdiction: trusted_non_empty(details.jurisdiction.as_deref()),
            assurance_level: trusted_non_empty(details.assurance_level.as_deref()),
            subject_binding_claim,
            subject_binding_value,
            checked_scopes,
        }
    }

    pub(super) fn with_request_claims(mut self, request_claims: Vec<ClaimRef>) -> Self {
        self.request_claims = request_claims;
        self
    }
}

pub(super) fn trusted_non_empty(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg_attr(not(feature = "registry-notary-cel"), allow(dead_code))]
pub(super) struct CelEvaluationContext<'a> {
    pub(super) evidence: &'a EvidenceConfig,
    pub(super) claim: &'a ClaimDefinition,
    pub(super) expression: &'a str,
    pub(super) bindings: &'a CelBindingsConfig,
    pub(super) claims: &'a BTreeMap<String, ClaimResultInternal>,
    pub(super) sources: &'a BTreeMap<String, Value>,
    pub(super) subject: Option<&'a SubjectRequest>,
    pub(super) target: &'a EvidenceEntity,
    pub(super) purpose: &'a str,
    pub(super) today: String,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) worker: Option<&'a CelWorker>,
    #[cfg(feature = "registry-notary-cel")]
    pub(super) config: &'a RegistryNotaryCelConfig,
}
