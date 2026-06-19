//! Native policy decision primitives for Registry services.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const ODRL_ENFORCEMENT_PROFILE: &str = "registry-evidence-gateway-pdp/v1";
pub const SUPPORTED_ODRL_ENFORCEMENT_TERMS: &[&str] = &["odrl:purpose", "odrl:spatial"];

pub const CONTEXT_REQUIRED: &str = "pdp.context_required";
pub const PURPOSE_NOT_PERMITTED: &str = "pdp.purpose_not_permitted";
pub const ASSURANCE_INSUFFICIENT: &str = "pdp.assurance_insufficient";
pub const EVIDENCE_STALE: &str = "pdp.evidence_stale";
pub const LEGAL_BASIS_REQUIRED: &str = "pdp.legal_basis_required";
pub const CONSENT_REQUIRED: &str = "pdp.consent_required";
pub const JURISDICTION_NOT_PERMITTED: &str = "pdp.jurisdiction_not_permitted";
pub const RELATIONSHIP_NOT_PERMITTED: &str = "pdp.relationship_not_permitted";
pub const REQUESTED_FACT_NOT_PERMITTED: &str = "pdp.requested_fact_not_permitted";
pub const DISCLOSURE_NOT_PERMITTED: &str = "pdp.disclosure_not_permitted";
pub const CREDENTIAL_FORMAT_NOT_PERMITTED: &str = "pdp.credential_format_not_permitted";
pub const SOURCE_BINDING_NOT_PERMITTED: &str = "pdp.source_binding_not_permitted";
pub const ROUTE_IDENTITY_NOT_PERMITTED: &str = "pdp.route_identity_not_permitted";
pub const CHECKED_SCOPE_REQUIRED: &str = "pdp.checked_scope_required";
pub const UNSUPPORTED_POLICY_TERM: &str = "pdp.unsupported_policy_term";
pub const POLICY_REQUIRED: &str = "pdp.policy_required";
pub const POLICY_ID_REQUIRED: &str = "pdp.policy_id_required";
pub const POLICY_HASH_INVALID: &str = "pdp.policy_hash_invalid";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRequestContext {
    pub purpose: String,
    #[serde(default)]
    pub legal_basis_ref: Option<String>,
    #[serde(default)]
    pub consent_ref: Option<String>,
    #[serde(default)]
    pub asserted_assurance: Option<String>,
    #[serde(default)]
    pub jurisdiction: Option<String>,
    #[serde(default)]
    pub requester_identity: Option<String>,
    #[serde(default)]
    pub subject_ref: Option<String>,
    #[serde(default)]
    pub relationship: Option<String>,
    #[serde(default)]
    pub on_behalf_of: Option<String>,
    #[serde(default)]
    pub requested_fact: Option<String>,
    #[serde(default)]
    pub requested_disclosure: Option<String>,
    #[serde(default)]
    pub requested_credential_format: Option<String>,
    #[serde(default)]
    pub source_binding: Option<String>,
    #[serde(default)]
    pub route_identity: Option<String>,
    #[serde(default)]
    pub checked_scopes: BTreeSet<String>,
    #[serde(default)]
    pub source_observed_at_unix_seconds: Option<u64>,
    #[serde(default)]
    pub source_observed_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyInput {
    pub policy_id: String,
    pub policy_hash: String,
    #[serde(default)]
    pub ecosystem_binding_id: Option<String>,
    #[serde(default)]
    pub ecosystem_binding_version: Option<String>,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub rule_ids_by_gate: BTreeMap<PolicyGate, Vec<String>>,
    #[serde(default)]
    pub permit_unconstrained: bool,
    #[serde(default)]
    pub required_context: BTreeSet<RequiredContextField>,
    #[serde(default)]
    pub odrl_constraint_terms: Vec<String>,
    #[serde(default)]
    pub purpose_constraints: Vec<Vec<String>>,
    #[serde(default)]
    pub permitted_jurisdictions: Vec<String>,
    #[serde(default)]
    pub allowed_assurance: Vec<String>,
    #[serde(default)]
    pub minimum_assurance: Option<String>,
    #[serde(default)]
    pub max_source_age_seconds: Option<u64>,
    #[serde(default)]
    pub require_legal_basis: bool,
    #[serde(default)]
    pub require_consent: bool,
    #[serde(default)]
    pub allowed_legal_basis_refs: Vec<String>,
    #[serde(default)]
    pub allowed_consent_refs: Vec<String>,
    #[serde(default)]
    pub redaction_fields: BTreeSet<String>,
    #[serde(default)]
    pub allowed_relationships: Vec<String>,
    #[serde(default)]
    pub relationship_purpose_constraints: Vec<RelationshipPurposeConstraint>,
    #[serde(default)]
    pub allowed_requested_facts: Vec<String>,
    #[serde(default)]
    pub allowed_requested_disclosures: Vec<String>,
    #[serde(default)]
    pub allowed_credential_formats: Vec<String>,
    #[serde(default)]
    pub allowed_source_bindings: Vec<String>,
    #[serde(default)]
    pub allowed_route_identities: Vec<String>,
    #[serde(default)]
    pub required_checked_scopes: BTreeSet<String>,
    #[serde(default)]
    pub unsupported_odrl_terms: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredContextField {
    Purpose,
    LegalBasisRef,
    ConsentRef,
    AssertedAssurance,
    Jurisdiction,
    RequesterIdentity,
    SubjectRef,
    Relationship,
    OnBehalfOf,
    RequestedFact,
    RequestedDisclosure,
    RequestedCredentialFormat,
    SourceBinding,
    RouteIdentity,
    CheckedScopes,
    SourceFreshness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationshipPurposeConstraint {
    pub relationship: String,
    #[serde(default)]
    pub allowed_purposes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyGate {
    PolicyIdentity,
    RequiredContext,
    OdrlTerms,
    Purpose,
    Jurisdiction,
    AssuranceAllowedSet,
    MinimumAssurance,
    SourceFreshness,
    LegalBasisRequired,
    ConsentRequired,
    LegalBasisAllowedSet,
    ConsentAllowedSet,
    Relationship,
    RelationshipPurpose,
    RequestedFact,
    RequestedDisclosure,
    CredentialFormat,
    SourceBinding,
    RouteIdentity,
    CheckedScope,
    Redaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Permit(DecisionAudit),
    PermitWithRedaction {
        audit: DecisionAudit,
        field_set: BTreeSet<String>,
        max_age_seconds: Option<u64>,
    },
    Deny {
        audit: DecisionAudit,
        stable_problem_code: String,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionAudit {
    pub policy_id: String,
    pub policy_hash: String,
    pub evaluated_rule_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stable_problem_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem_binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ecosystem_binding_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_binding: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub checked_scopes: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub trust_provenance: BTreeSet<String>,
}

pub fn decide(context: &EvidenceRequestContext, policy: &PolicyInput) -> Decision {
    let mut trace = DecisionTrace::new(policy);
    trace.record(PolicyGate::PolicyIdentity, policy);
    if policy.policy_id.trim().is_empty() {
        return deny(trace.audit(policy, Some(context)), POLICY_ID_REQUIRED);
    }
    if !is_sha256_digest(&policy.policy_hash) {
        return deny(trace.audit(policy, Some(context)), POLICY_HASH_INVALID);
    }
    if !policy.required_context.is_empty() {
        trace.record(PolicyGate::RequiredContext, policy);
        if !missing_required_context(context, &policy.required_context).is_empty() {
            return deny(trace.audit(policy, Some(context)), CONTEXT_REQUIRED);
        }
    }
    if !policy.odrl_constraint_terms.is_empty() || !policy.unsupported_odrl_terms.is_empty() {
        trace.record(PolicyGate::OdrlTerms, policy);
        if policy
            .odrl_constraint_terms
            .iter()
            .any(|term| !SUPPORTED_ODRL_ENFORCEMENT_TERMS.contains(&term.as_str()))
            || !policy.unsupported_odrl_terms.is_empty()
        {
            return deny(trace.audit(policy, Some(context)), UNSUPPORTED_POLICY_TERM);
        }
    }
    if !policy.permit_unconstrained && !policy_has_enforced_gate(policy) {
        return deny(trace.audit(policy, Some(context)), POLICY_REQUIRED);
    }
    if purpose_gate_is_declared(policy) {
        trace.record(PolicyGate::Purpose, policy);
        if policy.purpose_constraints.is_empty()
            || policy.purpose_constraints.iter().any(Vec::is_empty)
            || !policy
                .purpose_constraints
                .iter()
                .all(|constraint| constraint.iter().any(|purpose| purpose == &context.purpose))
        {
            return deny(trace.audit(policy, Some(context)), PURPOSE_NOT_PERMITTED);
        }
    }
    if !policy.permitted_jurisdictions.is_empty() {
        trace.record(PolicyGate::Jurisdiction, policy);
        let Some(jurisdiction) = context.jurisdiction.as_deref() else {
            return deny(
                trace.audit(policy, Some(context)),
                JURISDICTION_NOT_PERMITTED,
            );
        };
        if !policy
            .permitted_jurisdictions
            .iter()
            .any(|permitted| permitted == jurisdiction)
        {
            return deny(
                trace.audit(policy, Some(context)),
                JURISDICTION_NOT_PERMITTED,
            );
        }
    }
    if !policy.allowed_assurance.is_empty() {
        trace.record(PolicyGate::AssuranceAllowedSet, policy);
        let Some(asserted_assurance) = context.asserted_assurance.as_deref() else {
            return deny(trace.audit(policy, Some(context)), ASSURANCE_INSUFFICIENT);
        };
        let normalized_asserted = normalized_assurance(asserted_assurance);
        if !policy
            .allowed_assurance
            .iter()
            .any(|allowed| normalized_assurance(allowed) == normalized_asserted)
        {
            return deny(trace.audit(policy, Some(context)), ASSURANCE_INSUFFICIENT);
        }
    }
    if let Some(minimum_assurance) = policy.minimum_assurance.as_deref() {
        trace.record(PolicyGate::MinimumAssurance, policy);
        let Some(minimum_rank) = assurance_rank(minimum_assurance) else {
            return deny(trace.audit(policy, Some(context)), UNSUPPORTED_POLICY_TERM);
        };
        let Some(asserted_assurance) = context.asserted_assurance.as_deref() else {
            return deny(trace.audit(policy, Some(context)), ASSURANCE_INSUFFICIENT);
        };
        let Some(asserted_rank) = assurance_rank(asserted_assurance) else {
            return deny(trace.audit(policy, Some(context)), ASSURANCE_INSUFFICIENT);
        };
        if asserted_rank < minimum_rank {
            return deny(trace.audit(policy, Some(context)), ASSURANCE_INSUFFICIENT);
        }
    }
    if let Some(max_age) = policy.max_source_age_seconds {
        trace.record(PolicyGate::SourceFreshness, policy);
        let Some(observed_age) = context.source_observed_age_seconds else {
            return deny(trace.audit(policy, Some(context)), EVIDENCE_STALE);
        };
        if observed_age > max_age {
            return deny(trace.audit(policy, Some(context)), EVIDENCE_STALE);
        }
    }
    if policy.require_legal_basis {
        trace.record(PolicyGate::LegalBasisRequired, policy);
        if is_blank(context.legal_basis_ref.as_deref()) {
            return deny(trace.audit(policy, Some(context)), LEGAL_BASIS_REQUIRED);
        }
    }
    if policy.require_consent {
        trace.record(PolicyGate::ConsentRequired, policy);
        if is_blank(context.consent_ref.as_deref()) {
            return deny(trace.audit(policy, Some(context)), CONSENT_REQUIRED);
        }
    }
    if !policy.allowed_legal_basis_refs.is_empty() {
        trace.record(PolicyGate::LegalBasisAllowedSet, policy);
        let Some(legal_basis_ref) = present(context.legal_basis_ref.as_deref()) else {
            return deny(trace.audit(policy, Some(context)), LEGAL_BASIS_REQUIRED);
        };
        if !contains_exact(&policy.allowed_legal_basis_refs, legal_basis_ref) {
            return deny(trace.audit(policy, Some(context)), LEGAL_BASIS_REQUIRED);
        }
    }
    if !policy.allowed_consent_refs.is_empty() {
        trace.record(PolicyGate::ConsentAllowedSet, policy);
        let Some(consent_ref) = present(context.consent_ref.as_deref()) else {
            return deny(trace.audit(policy, Some(context)), CONSENT_REQUIRED);
        };
        if !contains_exact(&policy.allowed_consent_refs, consent_ref) {
            return deny(trace.audit(policy, Some(context)), CONSENT_REQUIRED);
        }
    }
    if !policy.allowed_relationships.is_empty() {
        trace.record(PolicyGate::Relationship, policy);
        let Some(relationship) = present(context.relationship.as_deref()) else {
            return deny(
                trace.audit(policy, Some(context)),
                RELATIONSHIP_NOT_PERMITTED,
            );
        };
        if !contains_exact(&policy.allowed_relationships, relationship) {
            return deny(
                trace.audit(policy, Some(context)),
                RELATIONSHIP_NOT_PERMITTED,
            );
        }
    }
    if !policy.relationship_purpose_constraints.is_empty() {
        trace.record(PolicyGate::RelationshipPurpose, policy);
        let Some(relationship) = present(context.relationship.as_deref()) else {
            return deny(
                trace.audit(policy, Some(context)),
                RELATIONSHIP_NOT_PERMITTED,
            );
        };
        let purpose = context.purpose.trim();
        let Some(constraint) = policy
            .relationship_purpose_constraints
            .iter()
            .find(|constraint| constraint.relationship == relationship)
        else {
            return deny(
                trace.audit(policy, Some(context)),
                RELATIONSHIP_NOT_PERMITTED,
            );
        };
        if !constraint
            .allowed_purposes
            .iter()
            .any(|allowed| allowed == purpose)
        {
            return deny(trace.audit(policy, Some(context)), PURPOSE_NOT_PERMITTED);
        }
    }
    if !policy.allowed_requested_facts.is_empty() {
        trace.record(PolicyGate::RequestedFact, policy);
        let Some(requested_fact) = present(context.requested_fact.as_deref()) else {
            return deny(
                trace.audit(policy, Some(context)),
                REQUESTED_FACT_NOT_PERMITTED,
            );
        };
        if !contains_exact(&policy.allowed_requested_facts, requested_fact) {
            return deny(
                trace.audit(policy, Some(context)),
                REQUESTED_FACT_NOT_PERMITTED,
            );
        }
    }
    if !policy.allowed_requested_disclosures.is_empty() {
        trace.record(PolicyGate::RequestedDisclosure, policy);
        let Some(requested_disclosure) = present(context.requested_disclosure.as_deref()) else {
            return deny(trace.audit(policy, Some(context)), DISCLOSURE_NOT_PERMITTED);
        };
        if !contains_exact(&policy.allowed_requested_disclosures, requested_disclosure) {
            return deny(trace.audit(policy, Some(context)), DISCLOSURE_NOT_PERMITTED);
        }
    }
    if !policy.allowed_credential_formats.is_empty() {
        trace.record(PolicyGate::CredentialFormat, policy);
        let Some(requested_format) = present(context.requested_credential_format.as_deref()) else {
            return deny(
                trace.audit(policy, Some(context)),
                CREDENTIAL_FORMAT_NOT_PERMITTED,
            );
        };
        if !contains_exact(&policy.allowed_credential_formats, requested_format) {
            return deny(
                trace.audit(policy, Some(context)),
                CREDENTIAL_FORMAT_NOT_PERMITTED,
            );
        }
    }
    if !policy.allowed_source_bindings.is_empty() {
        trace.record(PolicyGate::SourceBinding, policy);
        let Some(source_binding) = present(context.source_binding.as_deref()) else {
            return deny(
                trace.audit(policy, Some(context)),
                SOURCE_BINDING_NOT_PERMITTED,
            );
        };
        if !contains_exact(&policy.allowed_source_bindings, source_binding) {
            return deny(
                trace.audit(policy, Some(context)),
                SOURCE_BINDING_NOT_PERMITTED,
            );
        }
    }
    if !policy.allowed_route_identities.is_empty() {
        trace.record(PolicyGate::RouteIdentity, policy);
        let Some(route_identity) = present(context.route_identity.as_deref()) else {
            return deny(
                trace.audit(policy, Some(context)),
                ROUTE_IDENTITY_NOT_PERMITTED,
            );
        };
        if !contains_exact(&policy.allowed_route_identities, route_identity) {
            return deny(
                trace.audit(policy, Some(context)),
                ROUTE_IDENTITY_NOT_PERMITTED,
            );
        }
    }
    if !policy.required_checked_scopes.is_empty() {
        trace.record(PolicyGate::CheckedScope, policy);
        if !policy
            .required_checked_scopes
            .is_subset(&context.checked_scopes)
        {
            return deny(trace.audit(policy, Some(context)), CHECKED_SCOPE_REQUIRED);
        }
    }
    if policy.redaction_fields.is_empty() {
        Decision::Permit(trace.audit(policy, Some(context)))
    } else {
        trace.record(PolicyGate::Redaction, policy);
        Decision::PermitWithRedaction {
            audit: trace.audit(policy, Some(context)),
            field_set: policy.redaction_fields.clone(),
            max_age_seconds: policy.max_source_age_seconds,
        }
    }
}

fn deny(mut audit: DecisionAudit, stable_problem_code: &str) -> Decision {
    audit.stable_problem_code = Some(stable_problem_code.to_string());
    Decision::Deny {
        audit,
        stable_problem_code: stable_problem_code.to_string(),
    }
}

fn redacted_trust_provenance(context: &EvidenceRequestContext) -> BTreeSet<String> {
    [
        ("legal_basis_ref", context.legal_basis_ref.as_ref()),
        ("consent_ref", context.consent_ref.as_ref()),
        ("asserted_assurance", context.asserted_assurance.as_ref()),
        ("jurisdiction", context.jurisdiction.as_ref()),
    ]
    .into_iter()
    .filter_map(|(field, value)| value.map(|_| field.to_string()))
    .chain(
        context
            .source_observed_at_unix_seconds
            .map(|_| "source_observed_at_unix_seconds".to_string()),
    )
    .chain(
        context
            .source_observed_age_seconds
            .map(|_| "source_observed_age_seconds".to_string()),
    )
    .collect()
}

#[derive(Debug, Default)]
struct DecisionTrace {
    evaluated_rule_ids: Vec<String>,
    seen_rule_ids: BTreeSet<String>,
}

impl DecisionTrace {
    fn new(policy: &PolicyInput) -> Self {
        let _ = policy;
        Self::default()
    }

    fn record(&mut self, gate: PolicyGate, policy: &PolicyInput) {
        if let Some(rule_ids) = policy.rule_ids_by_gate.get(&gate) {
            for rule_id in rule_ids {
                self.record_rule_id(rule_id);
            }
            return;
        }
        self.record_rule_id(gate.default_rule_id());
    }

    fn audit(
        &self,
        policy: &PolicyInput,
        context: Option<&EvidenceRequestContext>,
    ) -> DecisionAudit {
        DecisionAudit {
            policy_id: policy.policy_id.clone(),
            policy_hash: policy.policy_hash.clone(),
            evaluated_rule_ids: self.evaluated_rule_ids.clone(),
            stable_problem_code: None,
            ecosystem_binding_id: policy.ecosystem_binding_id.clone(),
            ecosystem_binding_version: policy.ecosystem_binding_version.clone(),
            route_identity: context.and_then(|context| context.route_identity.clone()),
            source_binding: context.and_then(|context| context.source_binding.clone()),
            checked_scopes: context
                .map(|context| context.checked_scopes.clone())
                .unwrap_or_default(),
            trust_provenance: context.map(redacted_trust_provenance).unwrap_or_default(),
        }
    }

    fn record_rule_id(&mut self, rule_id: &str) {
        if self.seen_rule_ids.insert(rule_id.to_string()) {
            self.evaluated_rule_ids.push(rule_id.to_string());
        }
    }
}

impl PolicyGate {
    fn default_rule_id(self) -> &'static str {
        match self {
            PolicyGate::PolicyIdentity => "pdp.policy_identity",
            PolicyGate::RequiredContext => "pdp.required_context",
            PolicyGate::OdrlTerms => "pdp.odrl_terms",
            PolicyGate::Purpose => "pdp.purpose",
            PolicyGate::Jurisdiction => "pdp.jurisdiction",
            PolicyGate::AssuranceAllowedSet => "pdp.assurance_allowed_set",
            PolicyGate::MinimumAssurance => "pdp.minimum_assurance",
            PolicyGate::SourceFreshness => "pdp.source_freshness",
            PolicyGate::LegalBasisRequired => "pdp.legal_basis_required",
            PolicyGate::ConsentRequired => "pdp.consent_required",
            PolicyGate::LegalBasisAllowedSet => "pdp.legal_basis_allowed_set",
            PolicyGate::ConsentAllowedSet => "pdp.consent_allowed_set",
            PolicyGate::Relationship => "pdp.relationship",
            PolicyGate::RelationshipPurpose => "pdp.relationship_purpose",
            PolicyGate::RequestedFact => "pdp.requested_fact",
            PolicyGate::RequestedDisclosure => "pdp.requested_disclosure",
            PolicyGate::CredentialFormat => "pdp.credential_format",
            PolicyGate::SourceBinding => "pdp.source_binding",
            PolicyGate::RouteIdentity => "pdp.route_identity",
            PolicyGate::CheckedScope => "pdp.checked_scope",
            PolicyGate::Redaction => "pdp.redaction",
        }
    }
}

fn is_blank(value: Option<&str>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

fn present(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn contains_exact(values: &[String], requested: &str) -> bool {
    values.iter().any(|value| value == requested)
}

fn purpose_gate_is_declared(policy: &PolicyInput) -> bool {
    !policy.permit_unconstrained
        || !policy.purpose_constraints.is_empty()
        || policy
            .odrl_constraint_terms
            .iter()
            .any(|term| term == "odrl:purpose")
}

fn policy_has_enforced_gate(policy: &PolicyInput) -> bool {
    !policy.required_context.is_empty()
        || policy
            .purpose_constraints
            .iter()
            .any(|constraint| !constraint.is_empty())
        || !policy.permitted_jurisdictions.is_empty()
        || !policy.allowed_assurance.is_empty()
        || policy.minimum_assurance.is_some()
        || policy.max_source_age_seconds.is_some()
        || policy.require_legal_basis
        || policy.require_consent
        || !policy.allowed_legal_basis_refs.is_empty()
        || !policy.allowed_consent_refs.is_empty()
        || !policy.redaction_fields.is_empty()
        || !policy.allowed_relationships.is_empty()
        || !policy.relationship_purpose_constraints.is_empty()
        || !policy.allowed_requested_facts.is_empty()
        || !policy.allowed_requested_disclosures.is_empty()
        || !policy.allowed_credential_formats.is_empty()
        || !policy.allowed_source_bindings.is_empty()
        || !policy.allowed_route_identities.is_empty()
        || !policy.required_checked_scopes.is_empty()
}

fn missing_required_context(
    context: &EvidenceRequestContext,
    required_context: &BTreeSet<RequiredContextField>,
) -> Vec<RequiredContextField> {
    required_context
        .iter()
        .copied()
        .filter(|field| match field {
            RequiredContextField::Purpose => context.purpose.trim().is_empty(),
            RequiredContextField::LegalBasisRef => is_blank(context.legal_basis_ref.as_deref()),
            RequiredContextField::ConsentRef => is_blank(context.consent_ref.as_deref()),
            RequiredContextField::AssertedAssurance => {
                is_blank(context.asserted_assurance.as_deref())
            }
            RequiredContextField::Jurisdiction => is_blank(context.jurisdiction.as_deref()),
            RequiredContextField::RequesterIdentity => {
                is_blank(context.requester_identity.as_deref())
            }
            RequiredContextField::SubjectRef => is_blank(context.subject_ref.as_deref()),
            RequiredContextField::Relationship => is_blank(context.relationship.as_deref()),
            RequiredContextField::OnBehalfOf => is_blank(context.on_behalf_of.as_deref()),
            RequiredContextField::RequestedFact => is_blank(context.requested_fact.as_deref()),
            RequiredContextField::RequestedDisclosure => {
                is_blank(context.requested_disclosure.as_deref())
            }
            RequiredContextField::RequestedCredentialFormat => {
                is_blank(context.requested_credential_format.as_deref())
            }
            RequiredContextField::SourceBinding => is_blank(context.source_binding.as_deref()),
            RequiredContextField::RouteIdentity => is_blank(context.route_identity.as_deref()),
            RequiredContextField::CheckedScopes => context.checked_scopes.is_empty(),
            RequiredContextField::SourceFreshness => {
                context.source_observed_at_unix_seconds.is_none()
                    && context.source_observed_age_seconds.is_none()
            }
        })
        .collect()
}

fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn assurance_rank(level: &str) -> Option<u8> {
    let compact = normalized_assurance(level);
    match compact.as_str() {
        "low" | "ial1" | "loa1" => Some(1),
        "substantial" | "ial2" | "loa2" => Some(2),
        "high" | "ial3" | "loa3" => Some(3),
        _ => None,
    }
}

fn normalized_assurance(level: &str) -> String {
    level
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> EvidenceRequestContext {
        EvidenceRequestContext {
            purpose: "benefits".to_string(),
            legal_basis_ref: Some("law:benefits-act".to_string()),
            consent_ref: Some("consent:123".to_string()),
            asserted_assurance: Some("substantial".to_string()),
            jurisdiction: Some("RW".to_string()),
            requester_identity: Some("did:web:verifier.example".to_string()),
            subject_ref: Some("subject:123".to_string()),
            relationship: Some("self".to_string()),
            on_behalf_of: Some("agency:benefits".to_string()),
            requested_fact: Some("income_eligibility".to_string()),
            requested_disclosure: Some("predicate".to_string()),
            requested_credential_format: Some("sd_jwt_vc".to_string()),
            source_binding: Some("baseline-dpi/v1".to_string()),
            route_identity: Some("route:benefits".to_string()),
            checked_scopes: BTreeSet::from(["evidence.read".to_string()]),
            source_observed_at_unix_seconds: Some(1_782_000_000),
            source_observed_age_seconds: Some(30),
        }
    }

    fn policy() -> PolicyInput {
        PolicyInput {
            policy_id: "policy-1".to_string(),
            policy_hash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            ecosystem_binding_id: None,
            ecosystem_binding_version: None,
            rule_ids: vec!["rule-purpose".to_string()],
            rule_ids_by_gate: Default::default(),
            permit_unconstrained: false,
            required_context: BTreeSet::new(),
            odrl_constraint_terms: Vec::new(),
            purpose_constraints: vec![
                vec!["benefits".to_string(), "research".to_string()],
                vec!["benefits".to_string()],
            ],
            permitted_jurisdictions: vec!["RW".to_string()],
            allowed_assurance: Vec::new(),
            minimum_assurance: Some("substantial".to_string()),
            max_source_age_seconds: Some(60),
            require_legal_basis: true,
            require_consent: true,
            allowed_legal_basis_refs: Vec::new(),
            allowed_consent_refs: Vec::new(),
            redaction_fields: BTreeSet::new(),
            allowed_relationships: Vec::new(),
            relationship_purpose_constraints: Vec::new(),
            allowed_requested_facts: Vec::new(),
            allowed_requested_disclosures: Vec::new(),
            allowed_credential_formats: Vec::new(),
            allowed_source_bindings: Vec::new(),
            allowed_route_identities: Vec::new(),
            required_checked_scopes: BTreeSet::new(),
            unsupported_odrl_terms: Vec::new(),
        }
    }

    fn deny_code(decision: Decision) -> Option<String> {
        match decision {
            Decision::Deny {
                stable_problem_code,
                ..
            } => Some(stable_problem_code),
            _ => None,
        }
    }

    #[test]
    fn permits_when_purpose_is_in_intersection() {
        let decision = decide(&context(), &policy());
        match decision {
            Decision::Permit(audit) => {
                assert_eq!(audit.policy_id, "policy-1");
                assert_eq!(
                    audit.policy_hash,
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                );
                assert_eq!(audit.evaluated_rule_ids, permit_rule_ids());
            }
            other => panic!("expected Permit, got {other:?}"),
        }
    }

    #[test]
    fn evaluated_rule_ids_are_decision_trace_not_config_echo() {
        let mut context = context();
        context.purpose = "research".to_string();
        let mut policy = policy();
        policy.rule_ids = vec![
            "configured-purpose".to_string(),
            "configured-freshness".to_string(),
            "configured-consent".to_string(),
        ];

        match decide(&context, &policy) {
            Decision::Deny {
                audit,
                stable_problem_code,
            } => {
                assert_eq!(stable_problem_code, PURPOSE_NOT_PERMITTED);
                assert_eq!(
                    audit.evaluated_rule_ids,
                    vec!["pdp.policy_identity", "pdp.purpose"]
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn denies_when_purpose_is_not_in_intersection() {
        let mut context = context();
        context.purpose = "research".to_string();

        assert_eq!(
            deny_code(decide(&context, &policy())),
            Some(PURPOSE_NOT_PERMITTED.to_string())
        );
    }

    #[test]
    fn denies_when_assurance_is_insufficient() {
        let mut context = context();
        context.asserted_assurance = Some("low".to_string());

        assert_eq!(
            deny_code(decide(&context, &policy())),
            Some(ASSURANCE_INSUFFICIENT.to_string())
        );
    }

    #[test]
    fn minimum_assurance_accepts_standard_separator_bearing_labels() {
        let mut policy = policy();
        policy.minimum_assurance = Some("IAL-2".to_string());
        let mut context = context();
        context.asserted_assurance = Some("LOA 2".to_string());
        assert!(matches!(decide(&context, &policy), Decision::Permit(_)));

        policy.minimum_assurance = Some("LOA 2".to_string());
        context.asserted_assurance = Some("loa-1".to_string());
        assert_eq!(
            deny_code(decide(&context, &policy)),
            Some(ASSURANCE_INSUFFICIENT.to_string())
        );
    }

    #[test]
    fn nonstandard_substantial_low_minimum_fails_closed() {
        let mut policy = policy();
        policy.minimum_assurance = Some("substantial-low".to_string());

        assert_eq!(
            deny_code(decide(&context(), &policy)),
            Some(UNSUPPORTED_POLICY_TERM.to_string())
        );
    }

    #[test]
    fn denies_when_assurance_is_not_in_allowed_set() {
        let mut policy = policy();
        policy.allowed_assurance = vec!["urn:example:loa:high".to_string()];

        assert_eq!(
            deny_code(decide(&context(), &policy)),
            Some(ASSURANCE_INSUFFICIENT.to_string())
        );

        policy.allowed_assurance = vec!["Substantial".to_string()];
        assert!(matches!(decide(&context(), &policy), Decision::Permit(_)));
    }

    #[test]
    fn allowed_assurance_accepts_standard_separator_bearing_labels() {
        let mut policy = policy();
        policy.minimum_assurance = None;
        policy.allowed_assurance = vec!["IAL2".to_string()];

        let mut context = context();
        context.asserted_assurance = Some("IAL-2".to_string());
        assert!(matches!(decide(&context, &policy), Decision::Permit(_)));

        policy.allowed_assurance = vec!["LOA 2".to_string()];
        context.asserted_assurance = Some("loa_2".to_string());
        assert!(matches!(decide(&context, &policy), Decision::Permit(_)));
    }

    #[test]
    fn unknown_assurance_levels_fail_closed() {
        let mut unknown_asserted = context();
        unknown_asserted.asserted_assurance = Some("pilot".to_string());
        assert_eq!(
            deny_code(decide(&unknown_asserted, &policy())),
            Some(ASSURANCE_INSUFFICIENT.to_string())
        );

        let mut unknown_minimum = policy();
        unknown_minimum.minimum_assurance = Some("pilot".to_string());
        assert_eq!(
            deny_code(decide(&context(), &unknown_minimum)),
            Some(UNSUPPORTED_POLICY_TERM.to_string())
        );
    }

    #[test]
    fn denies_stale_source_observation() {
        let mut context = context();
        context.source_observed_age_seconds = Some(61);

        assert_eq!(
            deny_code(decide(&context, &policy())),
            Some(EVIDENCE_STALE.to_string())
        );
    }

    #[test]
    fn denies_missing_legal_basis_or_consent() {
        let mut no_legal_basis = context();
        no_legal_basis.legal_basis_ref = None;
        assert_eq!(
            deny_code(decide(&no_legal_basis, &policy())),
            Some(LEGAL_BASIS_REQUIRED.to_string())
        );

        let mut no_consent = context();
        no_consent.consent_ref = None;
        assert_eq!(
            deny_code(decide(&no_consent, &policy())),
            Some(CONSENT_REQUIRED.to_string())
        );
    }

    #[test]
    fn denies_disallowed_legal_basis_or_consent() {
        let mut legal_basis_policy = policy();
        legal_basis_policy.allowed_legal_basis_refs = vec!["law:birth-registration".to_string()];
        assert_eq!(
            deny_code(decide(&context(), &legal_basis_policy)),
            Some(LEGAL_BASIS_REQUIRED.to_string())
        );

        let mut consent_policy = policy();
        consent_policy.allowed_consent_refs = vec!["consent:other".to_string()];
        assert_eq!(
            deny_code(decide(&context(), &consent_policy)),
            Some(CONSENT_REQUIRED.to_string())
        );
    }

    #[test]
    fn denies_disallowed_jurisdiction() {
        let mut context = context();
        context.jurisdiction = Some("FR".to_string());

        assert_eq!(
            deny_code(decide(&context, &policy())),
            Some(JURISDICTION_NOT_PERMITTED.to_string())
        );
    }

    #[test]
    fn unsupported_odrl_terms_fail_closed() {
        let mut unsupported_split_policy = policy();
        unsupported_split_policy.unsupported_odrl_terms = vec!["odrl:unknownOperand".to_string()];

        assert_eq!(
            deny_code(decide(&context(), &unsupported_split_policy)),
            Some(UNSUPPORTED_POLICY_TERM.to_string())
        );

        let mut unsupported_term_policy = policy();
        unsupported_term_policy.odrl_constraint_terms = vec!["odrl:count".to_string()];

        assert_eq!(
            deny_code(decide(&context(), &unsupported_term_policy)),
            Some(UNSUPPORTED_POLICY_TERM.to_string())
        );
    }

    #[test]
    fn supported_odrl_terms_are_accepted_by_policy_input() {
        let mut policy = policy();
        policy.odrl_constraint_terms = SUPPORTED_ODRL_ENFORCEMENT_TERMS
            .iter()
            .map(|term| (*term).to_string())
            .collect();

        assert!(matches!(decide(&context(), &policy), Decision::Permit(_)));
    }

    #[test]
    fn missing_required_context_fields_fail_closed() {
        for field in [
            RequiredContextField::Purpose,
            RequiredContextField::LegalBasisRef,
            RequiredContextField::ConsentRef,
            RequiredContextField::AssertedAssurance,
            RequiredContextField::Jurisdiction,
            RequiredContextField::RequesterIdentity,
            RequiredContextField::SubjectRef,
            RequiredContextField::Relationship,
            RequiredContextField::OnBehalfOf,
            RequiredContextField::RequestedFact,
            RequiredContextField::RequestedDisclosure,
            RequiredContextField::RequestedCredentialFormat,
            RequiredContextField::SourceBinding,
            RequiredContextField::RouteIdentity,
            RequiredContextField::CheckedScopes,
            RequiredContextField::SourceFreshness,
        ] {
            let mut context = context();
            let mut policy = policy();
            policy.required_context.insert(field);
            match field {
                RequiredContextField::Purpose => context.purpose.clear(),
                RequiredContextField::LegalBasisRef => context.legal_basis_ref = None,
                RequiredContextField::ConsentRef => context.consent_ref = None,
                RequiredContextField::AssertedAssurance => context.asserted_assurance = None,
                RequiredContextField::Jurisdiction => context.jurisdiction = None,
                RequiredContextField::RequesterIdentity => context.requester_identity = None,
                RequiredContextField::SubjectRef => context.subject_ref = None,
                RequiredContextField::Relationship => context.relationship = None,
                RequiredContextField::OnBehalfOf => context.on_behalf_of = None,
                RequiredContextField::RequestedFact => context.requested_fact = None,
                RequiredContextField::RequestedDisclosure => context.requested_disclosure = None,
                RequiredContextField::RequestedCredentialFormat => {
                    context.requested_credential_format = None;
                }
                RequiredContextField::SourceBinding => context.source_binding = None,
                RequiredContextField::RouteIdentity => context.route_identity = None,
                RequiredContextField::CheckedScopes => context.checked_scopes.clear(),
                RequiredContextField::SourceFreshness => {
                    context.source_observed_at_unix_seconds = None;
                    context.source_observed_age_seconds = None;
                }
            }

            assert_eq!(
                deny_code(decide(&context, &policy)),
                Some(CONTEXT_REQUIRED.to_string()),
                "missing {field:?} should fail closed"
            );
        }
    }

    #[test]
    fn denies_disallowed_relationship_purpose_and_requested_outputs() {
        let mut relationship_policy = policy();
        relationship_policy.allowed_relationships = vec!["guardian".to_string()];
        assert_eq!(
            deny_code(decide(&context(), &relationship_policy)),
            Some(RELATIONSHIP_NOT_PERMITTED.to_string())
        );

        let mut relationship_purpose_policy = policy();
        relationship_purpose_policy
            .relationship_purpose_constraints
            .push(RelationshipPurposeConstraint {
                relationship: "self".to_string(),
                allowed_purposes: vec!["registration".to_string()],
            });
        assert_eq!(
            deny_code(decide(&context(), &relationship_purpose_policy)),
            Some(PURPOSE_NOT_PERMITTED.to_string())
        );

        let mut requested_fact_policy = policy();
        requested_fact_policy.allowed_requested_facts = vec!["birth_registration".to_string()];
        assert_eq!(
            deny_code(decide(&context(), &requested_fact_policy)),
            Some(REQUESTED_FACT_NOT_PERMITTED.to_string())
        );

        let mut disclosure_policy = policy();
        disclosure_policy.allowed_requested_disclosures = vec!["value".to_string()];
        assert_eq!(
            deny_code(decide(&context(), &disclosure_policy)),
            Some(DISCLOSURE_NOT_PERMITTED.to_string())
        );

        let mut format_policy = policy();
        format_policy.allowed_credential_formats = vec!["jwt_vc_json".to_string()];
        assert_eq!(
            deny_code(decide(&context(), &format_policy)),
            Some(CREDENTIAL_FORMAT_NOT_PERMITTED.to_string())
        );
    }

    #[test]
    fn denies_disallowed_route_source_and_scope_context() {
        let mut source_policy = policy();
        source_policy.allowed_source_bindings = vec!["sp-dci/v1".to_string()];
        assert_eq!(
            deny_code(decide(&context(), &source_policy)),
            Some(SOURCE_BINDING_NOT_PERMITTED.to_string())
        );

        let mut route_policy = policy();
        route_policy.allowed_route_identities = vec!["route:registration".to_string()];
        assert_eq!(
            deny_code(decide(&context(), &route_policy)),
            Some(ROUTE_IDENTITY_NOT_PERMITTED.to_string())
        );

        let mut scope_policy = policy();
        scope_policy
            .required_checked_scopes
            .insert("credential.issue".to_string());
        assert_eq!(
            deny_code(decide(&context(), &scope_policy)),
            Some(CHECKED_SCOPE_REQUIRED.to_string())
        );
    }

    #[test]
    fn permits_when_extended_policy_gates_match_context() {
        let mut policy = policy();
        policy.allowed_relationships = vec!["self".to_string()];
        policy
            .relationship_purpose_constraints
            .push(RelationshipPurposeConstraint {
                relationship: "self".to_string(),
                allowed_purposes: vec!["benefits".to_string()],
            });
        policy.allowed_requested_facts = vec!["income_eligibility".to_string()];
        policy.allowed_requested_disclosures = vec!["predicate".to_string()];
        policy.allowed_credential_formats = vec!["sd_jwt_vc".to_string()];
        policy.allowed_source_bindings = vec!["baseline-dpi/v1".to_string()];
        policy.allowed_route_identities = vec!["route:benefits".to_string()];
        policy
            .required_checked_scopes
            .insert("evidence.read".to_string());

        assert!(matches!(decide(&context(), &policy), Decision::Permit(_)));
    }

    #[test]
    fn denies_blank_or_malformed_policy_identity() {
        let mut blank_id = policy();
        blank_id.policy_id = " ".to_string();
        assert_eq!(
            deny_code(decide(&context(), &blank_id)),
            Some(POLICY_ID_REQUIRED.to_string())
        );

        let mut bad_hash = policy();
        bad_hash.policy_hash = "sha256:not-a-digest".to_string();
        assert_eq!(
            deny_code(decide(&context(), &bad_hash)),
            Some(POLICY_HASH_INVALID.to_string())
        );

        let mut uppercase_hash = policy();
        uppercase_hash.policy_hash =
            "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        assert_eq!(
            deny_code(decide(&context(), &uppercase_hash)),
            Some(POLICY_HASH_INVALID.to_string())
        );
    }

    #[test]
    fn denies_empty_policy_by_default() {
        let mut policy = policy();
        policy.rule_ids = vec!["configured-only".to_string()];
        policy.purpose_constraints.clear();
        policy.permitted_jurisdictions.clear();
        policy.minimum_assurance = None;
        policy.max_source_age_seconds = None;
        policy.require_legal_basis = false;
        policy.require_consent = false;

        match decide(&context(), &policy) {
            Decision::Deny {
                audit,
                stable_problem_code,
            } => {
                assert_eq!(stable_problem_code, POLICY_REQUIRED);
                assert_eq!(audit.stable_problem_code.as_deref(), Some(POLICY_REQUIRED));
                assert_eq!(audit.evaluated_rule_ids, vec!["pdp.policy_identity"]);
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn denies_declared_empty_purpose_gate_even_when_other_gate_matches() {
        let mut policy = policy();
        policy.purpose_constraints.clear();
        policy.odrl_constraint_terms = vec!["odrl:purpose".to_string()];
        policy.permitted_jurisdictions = vec!["SN".to_string()];

        assert_eq!(
            deny_code(decide(&context(), &policy)),
            Some(PURPOSE_NOT_PERMITTED.to_string())
        );

        let mut empty_inner = policy;
        empty_inner.purpose_constraints = vec![Vec::new()];
        assert_eq!(
            deny_code(decide(&context(), &empty_inner)),
            Some(PURPOSE_NOT_PERMITTED.to_string())
        );
    }

    #[test]
    fn denies_undeclared_empty_purpose_gate_even_when_other_gate_matches() {
        let mut policy = policy();
        policy.purpose_constraints.clear();
        policy.odrl_constraint_terms.clear();
        policy.permitted_jurisdictions = vec!["SN".to_string()];

        assert_eq!(
            deny_code(decide(&context(), &policy)),
            Some(PURPOSE_NOT_PERMITTED.to_string())
        );
    }

    #[test]
    fn deny_audit_carries_binding_route_scope_and_trust_provenance() {
        let mut policy = policy();
        policy.ecosystem_binding_id = Some("baseline-dpi/v1".to_string());
        policy.ecosystem_binding_version = Some("v1".to_string());

        let mut request_context = context();
        request_context.purpose = "unauthorized-purpose".to_string();

        match decide(&request_context, &policy) {
            Decision::Deny {
                audit,
                stable_problem_code,
            } => {
                assert_eq!(stable_problem_code, PURPOSE_NOT_PERMITTED);
                assert_eq!(
                    audit.stable_problem_code.as_deref(),
                    Some(PURPOSE_NOT_PERMITTED)
                );
                assert_eq!(audit.policy_id, "policy-1");
                assert_eq!(
                    audit.policy_hash,
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                );
                assert_eq!(
                    audit.ecosystem_binding_id.as_deref(),
                    Some("baseline-dpi/v1")
                );
                assert_eq!(audit.ecosystem_binding_version.as_deref(), Some("v1"));
                assert_eq!(audit.route_identity.as_deref(), Some("route:benefits"));
                assert_eq!(audit.source_binding.as_deref(), Some("baseline-dpi/v1"));
                assert_eq!(
                    audit.checked_scopes,
                    BTreeSet::from(["evidence.read".to_string()])
                );
                assert_eq!(
                    audit.trust_provenance,
                    BTreeSet::from([
                        "asserted_assurance".to_string(),
                        "consent_ref".to_string(),
                        "jurisdiction".to_string(),
                        "legal_basis_ref".to_string(),
                        "source_observed_age_seconds".to_string(),
                        "source_observed_at_unix_seconds".to_string(),
                    ])
                );
                assert!(audit
                    .evaluated_rule_ids
                    .iter()
                    .any(|rule| rule == "pdp.policy_identity"));
                assert!(audit
                    .evaluated_rule_ids
                    .iter()
                    .any(|rule| rule == "pdp.purpose"));
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn permits_empty_policy_only_with_explicit_unconstrained_opt_out() {
        let mut policy = policy();
        policy.purpose_constraints.clear();
        policy.permitted_jurisdictions.clear();
        policy.minimum_assurance = None;
        policy.max_source_age_seconds = None;
        policy.require_legal_basis = false;
        policy.require_consent = false;
        policy.permit_unconstrained = true;

        match decide(&context(), &policy) {
            Decision::Permit(audit) => {
                assert_eq!(audit.evaluated_rule_ids, vec!["pdp.policy_identity"]);
            }
            other => panic!("expected Permit, got {other:?}"),
        }
    }

    #[test]
    fn permits_with_redaction_when_policy_has_field_set() {
        let mut policy = policy();
        policy
            .redaction_fields
            .insert("target.birthdate".to_string());

        match decide(&context(), &policy) {
            Decision::PermitWithRedaction {
                audit, field_set, ..
            } => {
                assert_eq!(audit.policy_id, "policy-1");
                assert_eq!(
                    audit.policy_hash,
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                );
                assert_eq!(audit.stable_problem_code, None);
                assert_eq!(audit.route_identity.as_deref(), Some("route:benefits"));
                assert_eq!(audit.source_binding.as_deref(), Some("baseline-dpi/v1"));
                assert_eq!(
                    audit.checked_scopes,
                    BTreeSet::from(["evidence.read".to_string()])
                );
                assert_eq!(
                    audit.trust_provenance,
                    BTreeSet::from([
                        "asserted_assurance".to_string(),
                        "consent_ref".to_string(),
                        "jurisdiction".to_string(),
                        "legal_basis_ref".to_string(),
                        "source_observed_age_seconds".to_string(),
                        "source_observed_at_unix_seconds".to_string(),
                    ])
                );
                let mut expected = permit_rule_ids();
                expected.push("pdp.redaction".to_string());
                assert_eq!(audit.evaluated_rule_ids, expected);
                assert!(field_set.contains("target.birthdate"));
            }
            other => panic!("expected PermitWithRedaction, got {other:?}"),
        }
    }

    fn permit_rule_ids() -> Vec<String> {
        vec![
            "pdp.policy_identity",
            "pdp.purpose",
            "pdp.jurisdiction",
            "pdp.minimum_assurance",
            "pdp.source_freshness",
            "pdp.legal_basis_required",
            "pdp.consent_required",
        ]
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
    }
}
