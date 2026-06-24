//! Native policy decision primitives for Registry services.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextConstraintsConfig {
    #[serde(default)]
    pub legal_basis: LegalBasisPolicy,
    #[serde(default)]
    pub consent: ConsentPolicy,
    #[serde(default)]
    pub jurisdiction: JurisdictionPolicy,
    #[serde(default)]
    pub assurance: AssurancePolicy,
    #[serde(default)]
    pub source_freshness: SourceFreshnessPolicy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegalBasisPolicy {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub allowed_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentPolicy {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub allowed_refs: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JurisdictionPolicy {
    #[serde(default)]
    pub permitted: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssurancePolicy {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub minimum: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFreshnessPolicy {
    #[serde(default)]
    pub max_age_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextConstraintsConfigError {
    BlankEntry { field: &'static str },
    DuplicateEntry { field: &'static str },
    AllowedRefsRequireRequired { field: &'static str },
    ZeroSourceFreshness { field: &'static str },
}

impl fmt::Display for ContextConstraintsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlankEntry { field } => {
                write!(
                    f,
                    "context constraints field {field} contains a blank entry"
                )
            }
            Self::DuplicateEntry { field } => {
                write!(
                    f,
                    "context constraints field {field} contains a duplicate entry"
                )
            }
            Self::AllowedRefsRequireRequired { field } => {
                write!(
                    f,
                    "context constraints field {field} cannot set allowed_refs when required is false"
                )
            }
            Self::ZeroSourceFreshness { field } => {
                write!(
                    f,
                    "context constraints field {field} must be greater than zero"
                )
            }
        }
    }
}

impl Error for ContextConstraintsConfigError {}

impl ContextConstraintsConfig {
    pub fn validate(&self) -> Result<(), ContextConstraintsConfigError> {
        validate_allowed_refs_policy(
            "context_constraints.legal_basis",
            "context_constraints.legal_basis.allowed_refs",
            self.legal_basis.required,
            &self.legal_basis.allowed_refs,
        )?;
        validate_allowed_refs_policy(
            "context_constraints.consent",
            "context_constraints.consent.allowed_refs",
            self.consent.required,
            &self.consent.allowed_refs,
        )?;
        validate_unique_nonblank(
            "context_constraints.jurisdiction.permitted",
            &self.jurisdiction.permitted,
        )?;
        validate_unique_nonblank(
            "context_constraints.assurance.allowed",
            &self.assurance.allowed,
        )?;
        if self
            .assurance
            .minimum
            .as_deref()
            .is_some_and(|minimum| minimum.trim().is_empty())
        {
            return Err(ContextConstraintsConfigError::BlankEntry {
                field: "context_constraints.assurance.minimum",
            });
        }
        if self.source_freshness.max_age_seconds == Some(0) {
            return Err(ContextConstraintsConfigError::ZeroSourceFreshness {
                field: "context_constraints.source_freshness.max_age_seconds",
            });
        }
        Ok(())
    }

    pub fn apply_to_policy_input(
        &self,
        policy: &mut PolicyInput,
    ) -> Result<(), ContextConstraintsConfigError> {
        self.validate()?;
        policy.require_legal_basis = self.legal_basis.required;
        policy.allowed_legal_basis_refs = normalized_string_set(&self.legal_basis.allowed_refs);
        policy.require_consent = self.consent.required;
        policy.allowed_consent_refs = normalized_string_set(&self.consent.allowed_refs);
        policy.permitted_jurisdictions = normalized_string_set(&self.jurisdiction.permitted);
        policy.allowed_assurance = normalized_string_set(&self.assurance.allowed);
        policy.minimum_assurance = self
            .assurance
            .minimum
            .as_deref()
            .map(str::trim)
            .filter(|minimum| !minimum.is_empty())
            .map(ToOwned::to_owned);
        policy.max_source_age_seconds = self.source_freshness.max_age_seconds;
        Ok(())
    }

    pub fn hash_material(&self) -> Result<String, ContextConstraintsConfigError> {
        context_constraints_hash_material(self)
    }
}

pub fn apply_context_constraints_to_policy_input(
    constraints: &ContextConstraintsConfig,
    policy: &mut PolicyInput,
) -> Result<(), ContextConstraintsConfigError> {
    constraints.apply_to_policy_input(policy)
}

pub fn context_constraints_hash_material(
    constraints: &ContextConstraintsConfig,
) -> Result<String, ContextConstraintsConfigError> {
    constraints.validate()?;

    let mut material = String::from("registry-platform-pdp.context_constraints.v1\n");
    push_bool_hash_field(
        &mut material,
        "legal_basis.required",
        constraints.legal_basis.required,
    );
    push_string_list_hash_field(
        &mut material,
        "legal_basis.allowed_refs",
        &normalized_string_set(&constraints.legal_basis.allowed_refs),
    );
    push_bool_hash_field(
        &mut material,
        "consent.required",
        constraints.consent.required,
    );
    push_string_list_hash_field(
        &mut material,
        "consent.allowed_refs",
        &normalized_string_set(&constraints.consent.allowed_refs),
    );
    push_string_list_hash_field(
        &mut material,
        "jurisdiction.permitted",
        &normalized_string_set(&constraints.jurisdiction.permitted),
    );
    push_string_list_hash_field(
        &mut material,
        "assurance.allowed",
        &normalized_string_set(&constraints.assurance.allowed),
    );
    push_optional_string_hash_field(
        &mut material,
        "assurance.minimum",
        constraints.assurance.minimum.as_deref().map(str::trim),
    );
    push_optional_u64_hash_field(
        &mut material,
        "source_freshness.max_age_seconds",
        constraints.source_freshness.max_age_seconds,
    );
    Ok(material)
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

fn validate_allowed_refs_policy(
    policy_field: &'static str,
    allowed_refs_field: &'static str,
    required: bool,
    allowed_refs: &[String],
) -> Result<(), ContextConstraintsConfigError> {
    validate_unique_nonblank(allowed_refs_field, allowed_refs)?;
    if !required && !allowed_refs.is_empty() {
        return Err(ContextConstraintsConfigError::AllowedRefsRequireRequired {
            field: policy_field,
        });
    }
    Ok(())
}

fn validate_unique_nonblank(
    field: &'static str,
    values: &[String],
) -> Result<(), ContextConstraintsConfigError> {
    let mut seen = BTreeSet::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            return Err(ContextConstraintsConfigError::BlankEntry { field });
        }
        if !seen.insert(value) {
            return Err(ContextConstraintsConfigError::DuplicateEntry { field });
        }
    }
    Ok(())
}

fn normalized_string_set(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
}

fn push_bool_hash_field(material: &mut String, field: &str, value: bool) {
    material.push_str(field);
    material.push('=');
    material.push_str(if value { "true" } else { "false" });
    material.push('\n');
}

fn push_optional_u64_hash_field(material: &mut String, field: &str, value: Option<u64>) {
    material.push_str(field);
    material.push('=');
    match value {
        Some(value) => material.push_str(&value.to_string()),
        None => material.push_str("none"),
    }
    material.push('\n');
}

fn push_optional_string_hash_field(material: &mut String, field: &str, value: Option<&str>) {
    material.push_str(field);
    material.push('=');
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        push_len_prefixed_string(material, value);
    } else {
        material.push_str("none");
    }
    material.push('\n');
}

fn push_string_list_hash_field(material: &mut String, field: &str, values: &[String]) {
    material.push_str(field);
    material.push_str(".len=");
    material.push_str(&values.len().to_string());
    material.push('\n');
    for (index, value) in values.iter().enumerate() {
        material.push_str(field);
        material.push('.');
        material.push_str(&index.to_string());
        material.push('=');
        push_len_prefixed_string(material, value);
        material.push('\n');
    }
}

fn push_len_prefixed_string(material: &mut String, value: &str) {
    material.push_str(&value.len().to_string());
    material.push(':');
    material.push_str(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::value::{Error as DeError, MapDeserializer};
    use serde::Deserialize;

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

    fn assert_unknown_field_rejected<T>()
    where
        T: for<'de> Deserialize<'de> + std::fmt::Debug,
    {
        let deserializer = MapDeserializer::<_, DeError>::new(std::iter::once(("typo_field", ())));
        let error = T::deserialize(deserializer).expect_err("unknown field should be rejected");
        assert!(
            error.to_string().contains("unknown field"),
            "unexpected serde error: {error}"
        );
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
    fn context_constraints_validation_rejects_ambiguous_config() {
        let blank = ContextConstraintsConfig {
            jurisdiction: JurisdictionPolicy {
                permitted: vec![" ".to_string()],
            },
            ..Default::default()
        };
        assert_eq!(
            blank.validate(),
            Err(ContextConstraintsConfigError::BlankEntry {
                field: "context_constraints.jurisdiction.permitted"
            })
        );

        let duplicate = ContextConstraintsConfig {
            legal_basis: LegalBasisPolicy {
                required: true,
                allowed_refs: vec!["law:benefits".to_string(), " law:benefits ".to_string()],
            },
            ..Default::default()
        };
        assert_eq!(
            duplicate.validate(),
            Err(ContextConstraintsConfigError::DuplicateEntry {
                field: "context_constraints.legal_basis.allowed_refs"
            })
        );

        let allowed_without_required = ContextConstraintsConfig {
            consent: ConsentPolicy {
                required: false,
                allowed_refs: vec!["consent:benefits".to_string()],
            },
            ..Default::default()
        };
        assert_eq!(
            allowed_without_required.validate(),
            Err(ContextConstraintsConfigError::AllowedRefsRequireRequired {
                field: "context_constraints.consent"
            })
        );

        let zero_freshness = ContextConstraintsConfig {
            source_freshness: SourceFreshnessPolicy {
                max_age_seconds: Some(0),
            },
            ..Default::default()
        };
        assert_eq!(
            zero_freshness.validate(),
            Err(ContextConstraintsConfigError::ZeroSourceFreshness {
                field: "context_constraints.source_freshness.max_age_seconds"
            })
        );
    }

    #[test]
    fn context_constraints_config_rejects_unknown_fields() {
        assert_unknown_field_rejected::<ContextConstraintsConfig>();
        assert_unknown_field_rejected::<LegalBasisPolicy>();
        assert_unknown_field_rejected::<ConsentPolicy>();
        assert_unknown_field_rejected::<JurisdictionPolicy>();
        assert_unknown_field_rejected::<AssurancePolicy>();
        assert_unknown_field_rejected::<SourceFreshnessPolicy>();
    }

    #[test]
    fn context_constraints_apply_to_policy_input_fields() {
        let constraints = ContextConstraintsConfig {
            legal_basis: LegalBasisPolicy {
                required: true,
                allowed_refs: vec![
                    " law:benefits-act ".to_string(),
                    "law:social-protection-act".to_string(),
                ],
            },
            consent: ConsentPolicy {
                required: true,
                allowed_refs: vec!["consent:123".to_string()],
            },
            jurisdiction: JurisdictionPolicy {
                permitted: vec![" RW ".to_string()],
            },
            assurance: AssurancePolicy {
                allowed: vec![" substantial ".to_string()],
                minimum: Some(" substantial ".to_string()),
            },
            source_freshness: SourceFreshnessPolicy {
                max_age_seconds: Some(120),
            },
        };

        let mut policy = policy();
        constraints
            .apply_to_policy_input(&mut policy)
            .expect("constraints are valid");

        assert!(policy.require_legal_basis);
        assert_eq!(
            policy.allowed_legal_basis_refs,
            vec![
                "law:benefits-act".to_string(),
                "law:social-protection-act".to_string()
            ]
        );
        assert!(policy.require_consent);
        assert_eq!(policy.allowed_consent_refs, vec!["consent:123".to_string()]);
        assert_eq!(policy.permitted_jurisdictions, vec!["RW".to_string()]);
        assert_eq!(policy.allowed_assurance, vec!["substantial".to_string()]);
        assert_eq!(policy.minimum_assurance.as_deref(), Some("substantial"));
        assert_eq!(policy.max_source_age_seconds, Some(120));

        assert!(matches!(decide(&context(), &policy), Decision::Permit(_)));

        let mut wrong_legal_basis = context();
        wrong_legal_basis.legal_basis_ref = Some("law:birth-registration".to_string());
        assert_eq!(
            deny_code(decide(&wrong_legal_basis, &policy)),
            Some(LEGAL_BASIS_REQUIRED.to_string())
        );

        let mut wrong_consent = context();
        wrong_consent.consent_ref = Some("consent:other".to_string());
        assert_eq!(
            deny_code(decide(&wrong_consent, &policy)),
            Some(CONSENT_REQUIRED.to_string())
        );
    }

    #[test]
    fn context_constraints_hash_material_is_canonical_and_stable() {
        let constraints = ContextConstraintsConfig {
            legal_basis: LegalBasisPolicy {
                required: true,
                allowed_refs: vec![" law:b ".to_string(), "law:a".to_string()],
            },
            consent: ConsentPolicy {
                required: true,
                allowed_refs: vec!["consent:alpha".to_string()],
            },
            jurisdiction: JurisdictionPolicy {
                permitted: vec!["US".to_string(), " RW ".to_string()],
            },
            assurance: AssurancePolicy {
                allowed: vec!["loa3".to_string(), "ial2".to_string()],
                minimum: Some(" ial2 ".to_string()),
            },
            source_freshness: SourceFreshnessPolicy {
                max_age_seconds: Some(86_400),
            },
        };

        let material =
            context_constraints_hash_material(&constraints).expect("constraints are valid");
        assert_eq!(
            material,
            concat!(
                "registry-platform-pdp.context_constraints.v1\n",
                "legal_basis.required=true\n",
                "legal_basis.allowed_refs.len=2\n",
                "legal_basis.allowed_refs.0=5:law:a\n",
                "legal_basis.allowed_refs.1=5:law:b\n",
                "consent.required=true\n",
                "consent.allowed_refs.len=1\n",
                "consent.allowed_refs.0=13:consent:alpha\n",
                "jurisdiction.permitted.len=2\n",
                "jurisdiction.permitted.0=2:RW\n",
                "jurisdiction.permitted.1=2:US\n",
                "assurance.allowed.len=2\n",
                "assurance.allowed.0=4:ial2\n",
                "assurance.allowed.1=4:loa3\n",
                "assurance.minimum=4:ial2\n",
                "source_freshness.max_age_seconds=86400\n",
            )
        );

        let reordered = ContextConstraintsConfig {
            legal_basis: LegalBasisPolicy {
                required: true,
                allowed_refs: vec!["law:a".to_string(), "law:b".to_string()],
            },
            consent: constraints.consent.clone(),
            jurisdiction: JurisdictionPolicy {
                permitted: vec!["RW".to_string(), "US".to_string()],
            },
            assurance: AssurancePolicy {
                allowed: vec!["ial2".to_string(), "loa3".to_string()],
                minimum: Some("ial2".to_string()),
            },
            source_freshness: constraints.source_freshness.clone(),
        };
        assert_eq!(
            material,
            context_constraints_hash_material(&reordered).expect("constraints are valid")
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
        source_policy.ecosystem_binding_id = Some("baseline-dpi/v1".to_string());
        source_policy.ecosystem_binding_version = Some("v1".to_string());
        source_policy.allowed_source_bindings = vec!["sp-dci/v1".to_string()];
        match decide(&context(), &source_policy) {
            Decision::Deny {
                audit,
                stable_problem_code,
            } => {
                assert_eq!(stable_problem_code, SOURCE_BINDING_NOT_PERMITTED);
                assert_eq!(
                    audit.stable_problem_code.as_deref(),
                    Some(SOURCE_BINDING_NOT_PERMITTED)
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
            }
            other => panic!("expected Deny, got {other:?}"),
        }

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
