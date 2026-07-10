// SPDX-License-Identifier: Apache-2.0
//! Shared governed evidence policy enforcement for entity-backed API reads.

use std::collections::BTreeSet;

use axum::http::HeaderMap;
use registry_manifest_core::{
    CompiledDatasetPolicy, CompiledMetadata, CompiledPolicyOperandValue, EvidencePackMetadata,
};
use registry_platform_pdp::{
    decide as pdp_decide, rule_ids_by_gate, Decision as PdpDecision,
    DecisionAudit as PdpDecisionAudit, EvidenceRequestContext as PdpRequestContext,
    PolicyInput as PdpPolicyInput,
};
use sha2::{Digest, Sha256};

use crate::audit::AuditContextExt;
use crate::auth::{
    scopes::{format_trust_context_scope, TrustContextField},
    Principal,
};
use crate::config::{Config, EntityApiConfig, EntityConfig};
use crate::entity::EntityModel;
use crate::error::{AuthError, Error, InternalError, PdpError};
use crate::runtime_config::RuntimeSnapshot;

pub(crate) const DATA_PURPOSE_HEADER: &str = "data-purpose";
pub(crate) const TRUST_JURISDICTION_HEADER: &str = "x-registry-trust-jurisdiction";
pub(crate) const TRUST_ASSURANCE_HEADER: &str = "x-registry-trust-assurance";
pub(crate) const TRUST_LEGAL_BASIS_HEADER: &str = "x-registry-trust-legal-basis";
pub(crate) const TRUST_CONSENT_HEADER: &str = "x-registry-trust-consent";
const TRUST_SUBJECT_REF_HEADER: &str = "x-registry-subject-ref";
const TRUST_RELATIONSHIP_HEADER: &str = "x-registry-relationship";
const TRUST_ON_BEHALF_OF_HEADER: &str = "x-registry-on-behalf-of";
const TRUST_REQUESTED_CREDENTIAL_FORMAT_HEADER: &str = "x-registry-credential-format";
const TRUST_SOURCE_OBSERVED_AT_UNIX_SECONDS_HEADER: &str =
    "x-registry-source-observed-at-unix-seconds";
pub(crate) const TRUST_SOURCE_OBSERVED_AGE_SECONDS_HEADER: &str =
    "x-registry-source-observed-age-seconds";

const ODRL_PURPOSE: &str = "http://www.w3.org/ns/odrl/2/purpose";
const ODRL_SPATIAL: &str = "http://www.w3.org/ns/odrl/2/spatial";
const ODRL_IS_A: &str = "http://www.w3.org/ns/odrl/2/isA";
const ODRL_PURPOSE_COMPACT: &str = "odrl:purpose";
const ODRL_SPATIAL_COMPACT: &str = "odrl:spatial";

pub(crate) trait GovernedEntity {
    fn name(&self) -> &str;
    fn table_id(&self) -> &str;
    fn read_scope(&self) -> &str;
    fn api(&self) -> &EntityApiConfig;
    fn has_field(&self, field: &str) -> bool;
}

impl GovernedEntity for EntityModel {
    fn name(&self) -> &str {
        &self.name
    }

    fn table_id(&self) -> &str {
        &self.table_id
    }

    fn read_scope(&self) -> &str {
        &self.access.read_scope
    }

    fn api(&self) -> &EntityApiConfig {
        &self.api
    }

    fn has_field(&self, field: &str) -> bool {
        self.fields.iter().any(|candidate| candidate.name == field)
    }
}

impl GovernedEntity for EntityConfig {
    fn name(&self) -> &str {
        &self.name
    }

    fn table_id(&self) -> &str {
        self.table.as_str()
    }

    fn read_scope(&self) -> &str {
        &self.access.read_scope
    }

    fn api(&self) -> &EntityApiConfig {
        &self.api
    }

    fn has_field(&self, field: &str) -> bool {
        self.fields.iter().any(|candidate| candidate.name == field)
    }
}

#[derive(Debug, Default)]
pub(crate) struct GovernedReadDecision {
    pub(crate) audit: Option<PdpDecisionAudit>,
    pub(crate) redaction_fields: BTreeSet<String>,
    pub(crate) purpose: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GovernedRedactionProjection {
    EntityFields,
    DeferredOutput,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct GovernedRequestInfo<'a> {
    pub(crate) route_identity: &'a str,
    pub(crate) requested_disclosure: &'a str,
    pub(crate) checked_scope: &'a str,
    pub(crate) redaction_projection: GovernedRedactionProjection,
}

#[derive(Debug)]
pub(crate) struct GovernedAccessError {
    pub(crate) error: Error,
    pub(crate) pdp_audit: Option<PdpDecisionAudit>,
    pub(crate) pdp_trust_provenance: BTreeSet<String>,
}

impl GovernedAccessError {
    pub(crate) fn from_error(error: impl Into<Error>) -> Self {
        Self {
            error: error.into(),
            pdp_audit: None,
            pdp_trust_provenance: BTreeSet::new(),
        }
    }

    fn with_pdp_audit(error: Error, audit: PdpDecisionAudit) -> Self {
        Self {
            error,
            pdp_audit: Some(audit),
            pdp_trust_provenance: BTreeSet::new(),
        }
    }

    fn with_trust_provenance(mut self, field: &str) -> Self {
        self.pdp_trust_provenance.insert(field.to_string());
        self
    }
}

impl From<Error> for GovernedAccessError {
    fn from(error: Error) -> Self {
        Self::from_error(error)
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn require_governed_read_access<E: GovernedEntity + ?Sized>(
    runtime: &RuntimeSnapshot,
    dataset_id: &str,
    entity: &E,
    headers: &HeaderMap,
    principal: Option<&Principal>,
    request_info: GovernedRequestInfo<'_>,
) -> Result<GovernedReadDecision, GovernedAccessError> {
    let governed_policy = entity.api().governed_policy.as_ref();
    if !entity.api().require_purpose_header && governed_policy.is_none() {
        return Ok(GovernedReadDecision::default());
    }
    let purpose = purpose_header_value(headers)
        .ok_or_else(|| GovernedAccessError::from_error(AuthError::PurposeRequired))?;
    let mut purpose_constraints =
        governed_purpose_constraints(runtime, dataset_id).unwrap_or_default();
    if let Some(configured_purposes) = governed_policy
        .map(|policy| policy.permitted_purposes.clone())
        .filter(|purposes| !purposes.is_empty())
    {
        purpose_constraints.push(configured_purposes);
    }
    if governed_policy.is_none() && purpose_constraints.is_empty() {
        return Ok(GovernedReadDecision::default());
    }
    validate_redaction_fields(entity, governed_policy, request_info.redaction_projection)?;
    let source_binding = source_binding(dataset_id, entity);
    let context = request_pdp_context(
        purpose,
        headers,
        principal,
        entity.name(),
        &source_binding,
        &request_info,
    )?;
    let selected_policy = selected_ecosystem_policy(runtime).map_err(GovernedAccessError::from)?;
    if purpose_constraints.is_empty() {
        return Err(GovernedAccessError::from_error(AuthError::PurposeDenied));
    }
    let policy_rule_id = format!("entity-purpose-required:{}", entity.name());
    let policy = PdpPolicyInput {
        policy_id: selected_policy
            .as_ref()
            .map(|policy| policy.policy_id.clone())
            .unwrap_or_else(|| format!("relay.entity.{}.purpose-required", entity.name())),
        policy_hash: selected_policy
            .as_ref()
            .map(|policy| policy.policy_hash.clone())
            .unwrap_or_else(|| entity_purpose_policy_hash(entity, &purpose_constraints)),
        ecosystem_binding_id: selected_policy
            .as_ref()
            .and_then(|policy| policy.ecosystem_binding_id.clone()),
        ecosystem_binding_version: selected_policy
            .as_ref()
            .and_then(|policy| policy.ecosystem_binding_version.clone()),
        rule_ids: vec![policy_rule_id.clone()],
        rule_ids_by_gate: rule_ids_by_gate(&policy_rule_id),
        permit_unconstrained: false,
        required_context: Default::default(),
        odrl_constraint_terms: selected_policy
            .as_ref()
            .map(|policy| policy.odrl_constraint_terms.clone())
            .unwrap_or_default(),
        purpose_constraints,
        permitted_jurisdictions: governed_policy
            .map(|policy| policy.permitted_jurisdictions.clone())
            .unwrap_or_default(),
        allowed_assurance: governed_policy
            .map(|policy| policy.allowed_assurance.clone())
            .unwrap_or_default(),
        minimum_assurance: governed_policy.and_then(|policy| policy.minimum_assurance.clone()),
        max_source_age_seconds: governed_policy.and_then(|policy| policy.max_source_age_seconds),
        require_legal_basis: governed_policy.is_some_and(|policy| policy.require_legal_basis),
        require_consent: governed_policy.is_some_and(|policy| policy.require_consent),
        allowed_legal_basis_refs: Vec::new(),
        allowed_consent_refs: Vec::new(),
        redaction_fields: governed_policy
            .map(|policy| policy.redaction_fields.iter().cloned().collect())
            .unwrap_or_default(),
        allowed_relationships: Vec::new(),
        relationship_purpose_constraints: Vec::new(),
        allowed_requested_facts: vec![entity.name().to_string()],
        allowed_requested_disclosures: vec![request_info.requested_disclosure.to_string()],
        allowed_credential_formats: Vec::new(),
        allowed_source_bindings: vec![source_binding],
        allowed_route_identities: vec![request_info.route_identity.to_string()],
        required_checked_scopes: BTreeSet::from([request_info.checked_scope.to_string()]),
        unsupported_odrl_terms: selected_policy
            .map(|policy| policy.unsupported_odrl_terms)
            .unwrap_or_default(),
    };
    match relay_pdp_decide(&context, &policy) {
        PdpDecision::Permit(audit) => Ok(GovernedReadDecision {
            audit: Some(audit),
            redaction_fields: BTreeSet::new(),
            purpose: Some(purpose.to_string()),
        }),
        PdpDecision::PermitWithRedaction {
            audit, field_set, ..
        } => Ok(GovernedReadDecision {
            audit: Some(audit),
            redaction_fields: field_set,
            purpose: Some(purpose.to_string()),
        }),
        PdpDecision::Deny {
            audit,
            stable_problem_code,
        } => Err(GovernedAccessError::with_pdp_audit(
            PdpError::from_stable_code(&stable_problem_code).into(),
            audit,
        )),
    }
}

fn relay_pdp_decide(context: &PdpRequestContext, policy: &PdpPolicyInput) -> PdpDecision {
    let mut decision = pdp_decide(context, policy);
    // Keep this enrichment at the Relay boundary. Other platform PDP callers
    // do not share Relay's exact-value scope semantics for these fields.
    let audit = match &mut decision {
        PdpDecision::Permit(audit)
        | PdpDecision::PermitWithRedaction { audit, .. }
        | PdpDecision::Deny { audit, .. } => audit,
    };
    audit.trust_provenance.extend(
        [
            ("subject_ref", context.subject_ref.as_ref()),
            ("relationship", context.relationship.as_ref()),
            ("on_behalf_of", context.on_behalf_of.as_ref()),
            (
                "requested_credential_format",
                context.requested_credential_format.as_ref(),
            ),
        ]
        .into_iter()
        .filter_map(|(field, value)| value.map(|_| field.to_string())),
    );
    decision
}

#[allow(clippy::result_large_err)]
fn request_pdp_context(
    purpose: &str,
    headers: &HeaderMap,
    principal: Option<&Principal>,
    requested_fact: &str,
    source_binding: &str,
    request_info: &GovernedRequestInfo<'_>,
) -> Result<PdpRequestContext, GovernedAccessError> {
    Ok(PdpRequestContext {
        purpose: purpose.to_string(),
        legal_basis_ref: verified_trust_header_value(
            headers,
            principal,
            TRUST_LEGAL_BASIS_HEADER,
            TrustContextField::LegalBasis,
        )
        .map(ToOwned::to_owned),
        consent_ref: verified_trust_header_value(
            headers,
            principal,
            TRUST_CONSENT_HEADER,
            TrustContextField::Consent,
        )
        .map(ToOwned::to_owned),
        asserted_assurance: verified_trust_header_value(
            headers,
            principal,
            TRUST_ASSURANCE_HEADER,
            TrustContextField::Assurance,
        )
        .map(ToOwned::to_owned),
        jurisdiction: verified_trust_header_value(
            headers,
            principal,
            TRUST_JURISDICTION_HEADER,
            TrustContextField::Jurisdiction,
        )
        .map(ToOwned::to_owned),
        requester_identity: principal.map(|principal| principal.principal_id.clone()),
        subject_ref: verified_trust_header_value(
            headers,
            principal,
            TRUST_SUBJECT_REF_HEADER,
            TrustContextField::SubjectRef,
        )
        .map(ToOwned::to_owned),
        relationship: verified_trust_header_value(
            headers,
            principal,
            TRUST_RELATIONSHIP_HEADER,
            TrustContextField::Relationship,
        )
        .map(ToOwned::to_owned),
        on_behalf_of: verified_trust_header_value(
            headers,
            principal,
            TRUST_ON_BEHALF_OF_HEADER,
            TrustContextField::OnBehalfOf,
        )
        .map(ToOwned::to_owned),
        requested_fact: Some(requested_fact.to_string()),
        requested_disclosure: Some(request_info.requested_disclosure.to_string()),
        requested_credential_format: verified_trust_header_value(
            headers,
            principal,
            TRUST_REQUESTED_CREDENTIAL_FORMAT_HEADER,
            TrustContextField::RequestedCredentialFormat,
        )
        .map(ToOwned::to_owned),
        source_binding: Some(source_binding.to_string()),
        route_identity: Some(request_info.route_identity.to_string()),
        checked_scopes: principal
            .filter(|principal| principal.scopes.contains(request_info.checked_scope))
            .map(|_| BTreeSet::from([request_info.checked_scope.to_string()]))
            .unwrap_or_default(),
        source_observed_at_unix_seconds: verified_trust_header_value(
            headers,
            principal,
            TRUST_SOURCE_OBSERVED_AT_UNIX_SECONDS_HEADER,
            TrustContextField::SourceObservedAtUnixSeconds,
        )
        .map(|value| parse_unix_seconds(value, "source_observed_at_unix_seconds"))
        .transpose()?,
        source_observed_age_seconds: source_observed_age_seconds(headers, principal)?,
    })
}

#[allow(clippy::result_large_err)]
fn parse_unix_seconds(value: &str, provenance_field: &str) -> Result<u64, GovernedAccessError> {
    value.parse::<u64>().map_err(|_| {
        GovernedAccessError::from_error(PdpError::from_stable_code(
            registry_platform_pdp::EVIDENCE_STALE,
        ))
        .with_trust_provenance(provenance_field)
    })
}

fn source_binding<E: GovernedEntity + ?Sized>(dataset_id: &str, entity: &E) -> String {
    format!("relay:{dataset_id}:{}", entity.table_id())
}

fn trust_header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn verified_trust_header_value<'a>(
    headers: &'a HeaderMap,
    principal: Option<&Principal>,
    name: &str,
    field: TrustContextField,
) -> Option<&'a str> {
    let value = trust_header_value(headers, name)?;
    let required_scope = format_trust_context_scope(field, value)?;
    principal
        .filter(|principal| principal.scopes.contains(&required_scope))
        .map(|_| value)
}

#[allow(clippy::result_large_err)]
fn source_observed_age_seconds(
    headers: &HeaderMap,
    principal: Option<&Principal>,
) -> Result<Option<u64>, GovernedAccessError> {
    let Some(value) = trust_header_value(headers, TRUST_SOURCE_OBSERVED_AGE_SECONDS_HEADER) else {
        return Ok(None);
    };
    let Some(required_scope) =
        format_trust_context_scope(TrustContextField::SourceObservedAgeSeconds, value)
    else {
        return Ok(None);
    };
    if !principal.is_some_and(|principal| principal.scopes.contains(&required_scope)) {
        return Ok(None);
    }
    value.parse::<u64>().map(Some).map_err(|_| {
        GovernedAccessError::from_error(PdpError::from_stable_code(
            registry_platform_pdp::EVIDENCE_STALE,
        ))
        .with_trust_provenance("source_observed_age_seconds")
    })
}

#[allow(clippy::result_large_err)]
fn validate_redaction_fields<E: GovernedEntity + ?Sized>(
    entity: &E,
    governed_policy: Option<&crate::config::GovernedPolicyConfig>,
    projection: GovernedRedactionProjection,
) -> Result<(), GovernedAccessError> {
    let Some(policy) = governed_policy else {
        return Ok(());
    };
    for field in &policy.redaction_fields {
        let missing_entity_field =
            projection == GovernedRedactionProjection::EntityFields && !entity.has_field(field);
        if !is_top_level_redaction_field(field) || missing_entity_field {
            return Err(GovernedAccessError::from_error(PdpError::from_stable_code(
                registry_platform_pdp::UNSUPPORTED_POLICY_TERM,
            )));
        }
    }
    Ok(())
}

fn is_top_level_redaction_field(field: &str) -> bool {
    !field.trim().is_empty()
        && !field.contains('.')
        && !field.contains('[')
        && !field.contains(']')
        && !field.contains('*')
}

pub(crate) fn attach_pdp_audit(
    context: &mut Option<AuditContextExt>,
    audit: Option<&PdpDecisionAudit>,
) {
    let (Some(context), Some(audit)) = (context.as_mut(), audit) else {
        return;
    };
    context.pdp_policy_id = Some(audit.policy_id.clone());
    context.pdp_policy_hash = Some(audit.policy_hash.clone());
    context.pdp_evaluated_rule_ids =
        (!audit.evaluated_rule_ids.is_empty()).then(|| audit.evaluated_rule_ids.clone());
    context.pdp_stable_problem_code = audit.stable_problem_code.clone();
    context.pdp_ecosystem_binding_id = audit.ecosystem_binding_id.clone();
    context.pdp_ecosystem_binding_version = audit.ecosystem_binding_version.clone();
    context.pdp_route_identity = audit.route_identity.clone();
    context.pdp_source_binding = audit.source_binding.clone();
    context.pdp_checked_scopes =
        (!audit.checked_scopes.is_empty()).then(|| audit.checked_scopes.iter().cloned().collect());
    context.pdp_trust_provenance = (!audit.trust_provenance.is_empty())
        .then(|| audit.trust_provenance.iter().cloned().collect());
}

pub(crate) fn attach_pdp_trust_provenance(
    context: &mut Option<AuditContextExt>,
    provenance: &BTreeSet<String>,
) {
    if provenance.is_empty() {
        return;
    }
    let Some(context) = context.as_mut() else {
        return;
    };
    let mut combined: BTreeSet<String> = context
        .pdp_trust_provenance
        .take()
        .unwrap_or_default()
        .into_iter()
        .collect();
    combined.extend(provenance.iter().cloned());
    context.pdp_trust_provenance = Some(combined.into_iter().collect());
}

pub(crate) fn attach_governed_error_audit(
    context: &mut Option<AuditContextExt>,
    error: &GovernedAccessError,
) {
    attach_pdp_audit(context, error.pdp_audit.as_ref());
    attach_pdp_trust_provenance(context, &error.pdp_trust_provenance);
}

pub(crate) fn governed_cache_variant<'a>(
    base: &str,
    decisions: impl IntoIterator<Item = &'a GovernedReadDecision>,
) -> String {
    let mut material = String::from(base);
    for decision in decisions {
        material.push_str("|purpose=");
        material.push_str(decision.purpose.as_deref().unwrap_or(""));
        if let Some(audit) = decision.audit.as_ref() {
            material.push_str("|pdp_policy_id=");
            material.push_str(&audit.policy_id);
            material.push_str("|pdp_policy_hash=");
            material.push_str(&audit.policy_hash);
            material.push_str("|pdp_rules=");
            material.push_str(&audit.evaluated_rule_ids.join(","));
        }
        material.push_str("|redaction=");
        for field in &decision.redaction_fields {
            material.push_str(field);
            material.push(',');
        }
    }
    material
}

#[doc(hidden)]
pub fn entity_etag(
    kind: &str,
    dataset_id: &str,
    entity_name: &str,
    ingest_version: Option<&str>,
    variant: &str,
) -> Option<String> {
    let ingest_version = ingest_version?;
    Some(strong_etag(&[
        "entity",
        kind,
        dataset_id,
        entity_name,
        ingest_version,
        variant,
    ]))
}

#[doc(hidden)]
pub fn strong_etag(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(part.as_bytes());
        hasher.update(b";");
    }
    format!(r#""sha256:{}""#, hex_lower(&hasher.finalize()))
}

pub(crate) fn purpose_header_value(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(DATA_PURPOSE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn governed_purpose_constraints(
    runtime: &RuntimeSnapshot,
    dataset_id: &str,
) -> Option<Vec<Vec<String>>> {
    let compiled = runtime.compiled_metadata()?;
    let dataset = compiled.dataset(dataset_id)?;
    governed_purpose_constraints_for_policy(&dataset.policy)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SelectedEcosystemPolicy {
    policy_id: String,
    policy_hash: String,
    ecosystem_binding_id: Option<String>,
    ecosystem_binding_version: Option<String>,
    odrl_constraint_terms: Vec<String>,
    unsupported_odrl_terms: Vec<String>,
}

fn selected_ecosystem_policy(
    runtime: &RuntimeSnapshot,
) -> Result<Option<SelectedEcosystemPolicy>, Error> {
    let Some(config) = runtime.config() else {
        return Ok(None);
    };
    let Some(compiled) = runtime.compiled_metadata() else {
        return selected_ecosystem_policy_from_metadata(&config, None);
    };
    selected_ecosystem_policy_from_metadata(&config, Some(compiled.as_ref()))
}

fn selected_ecosystem_policy_from_metadata(
    config: &Config,
    compiled: Option<&CompiledMetadata>,
) -> Result<Option<SelectedEcosystemPolicy>, Error> {
    let Some(selector) = config
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.ecosystem_binding.as_ref())
    else {
        return Ok(None);
    };
    let Some(compiled) = compiled else {
        tracing::error!(
            code = "runtime.binding.ecosystem_binding_missing",
            binding_id = %selector.id,
            binding_version = selector.version.as_deref().unwrap_or("<any>"),
            "configured ecosystem binding selector is unavailable at request time"
        );
        return Err(InternalError::Unhandled.into());
    };
    let binding = compiled.ecosystem_bindings().iter().find(|binding| {
        binding.id == selector.id
            && selector
                .version
                .as_deref()
                .is_none_or(|version| binding.version == version)
    });
    let Some(binding) = binding else {
        tracing::error!(
            code = "runtime.binding.ecosystem_binding_missing",
            binding_id = %selector.id,
            binding_version = selector.version.as_deref().unwrap_or("<any>"),
            "configured ecosystem binding selector is absent at request time"
        );
        return Err(InternalError::Unhandled.into());
    };
    if binding.binding_type != "governed-evidence" {
        tracing::error!(
            code = "runtime.binding.ecosystem_binding_invalid",
            binding_id = %binding.id,
            binding_version = %binding.version,
            binding_type = %binding.binding_type,
            "configured ecosystem binding is not governed evidence at request time"
        );
        return Err(InternalError::Unhandled.into());
    }
    evidence_pack_policy(binding.evidence_pack.as_ref())
        .ok_or_else(|| {
            tracing::error!(
                code = "runtime.binding.ecosystem_binding_invalid",
                binding_id = %binding.id,
                binding_version = %binding.version,
                "configured ecosystem binding evidence pack is incomplete at request time"
            );
            Error::from(InternalError::Unhandled)
        })
        .map(|mut policy| {
            policy.ecosystem_binding_id = Some(binding.id.clone());
            policy.ecosystem_binding_version = Some(binding.version.clone());
            Some(policy)
        })
}

fn evidence_pack_policy(
    evidence_pack: Option<&EvidencePackMetadata>,
) -> Option<SelectedEcosystemPolicy> {
    let evidence_pack = evidence_pack?;
    let enforcement = evidence_pack.odrl_enforcement.as_ref()?;
    let odrl_constraint_terms = enforcement
        .constraint_terms
        .iter()
        .map(|term| normalized_odrl_term(term).to_string())
        .collect::<Vec<_>>();
    let unsupported_odrl_terms = odrl_constraint_terms
        .iter()
        .filter(|term| !supported_odrl_term(term))
        .cloned()
        .collect();
    Some(SelectedEcosystemPolicy {
        policy_id: evidence_pack.policy_id.as_ref()?.trim().to_string(),
        policy_hash: evidence_pack.policy_hash.as_ref()?.trim().to_string(),
        ecosystem_binding_id: None,
        ecosystem_binding_version: None,
        odrl_constraint_terms,
        unsupported_odrl_terms,
    })
}

fn supported_odrl_term(term: &str) -> bool {
    matches!(term, ODRL_PURPOSE_COMPACT)
}

fn normalized_odrl_term(term: &str) -> &str {
    match term {
        ODRL_PURPOSE => ODRL_PURPOSE_COMPACT,
        ODRL_SPATIAL => ODRL_SPATIAL_COMPACT,
        _ => term,
    }
}

fn governed_purpose_constraints_for_policy(
    policy: &CompiledDatasetPolicy,
) -> Option<Vec<Vec<String>>> {
    let mut purposes = policy
        .permissions
        .iter()
        .flat_map(|permission| &permission.constraints)
        .filter(|constraint| {
            constraint.left_operand == ODRL_PURPOSE && constraint.operator == ODRL_IS_A
        })
        .filter_map(|constraint| match &constraint.right_operand {
            CompiledPolicyOperandValue::Iri(value) if !value.trim().is_empty() => {
                Some(value.trim().to_string())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    purposes.sort();
    purposes.dedup();
    if purposes.is_empty() {
        None
    } else {
        Some(vec![purposes])
    }
}

fn entity_purpose_policy_hash<E: GovernedEntity + ?Sized>(
    entity: &E,
    purpose_constraints: &[Vec<String>],
) -> String {
    let policy = entity.api().governed_policy.as_ref();
    let mut material = format!(
        "entity={};table_id={};read_scope={};require_purpose_header={};purpose_constraints={:?}",
        entity.name(),
        entity.table_id(),
        entity.read_scope(),
        entity.api().require_purpose_header,
        purpose_constraints
    );
    if let Some(policy) = policy {
        push_hash_list(
            &mut material,
            "permitted_purposes",
            &policy.permitted_purposes,
        );
        push_hash_list(
            &mut material,
            "permitted_jurisdictions",
            &policy.permitted_jurisdictions,
        );
        push_hash_list(
            &mut material,
            "allowed_assurance",
            &policy.allowed_assurance,
        );
        push_hash_optional(
            &mut material,
            "minimum_assurance",
            policy.minimum_assurance.as_deref(),
        );
        let max_source_age_seconds = policy.max_source_age_seconds.map(|value| value.to_string());
        push_hash_optional(
            &mut material,
            "max_source_age_seconds",
            max_source_age_seconds.as_deref(),
        );
        material.push_str(&format!(
            ";require_legal_basis={};require_consent={}",
            policy.require_legal_basis, policy.require_consent
        ));
        push_hash_list(&mut material, "redaction_fields", &policy.redaction_fields);
        push_hash_optional(
            &mut material,
            "trusted_jurisdiction",
            policy.trusted_context.jurisdiction.as_deref(),
        );
        push_hash_optional(
            &mut material,
            "trusted_asserted_assurance",
            policy.trusted_context.asserted_assurance.as_deref(),
        );
        push_hash_optional(
            &mut material,
            "trusted_legal_basis_ref",
            policy.trusted_context.legal_basis_ref.as_deref(),
        );
        push_hash_optional(
            &mut material,
            "trusted_consent_ref",
            policy.trusted_context.consent_ref.as_deref(),
        );
        let trusted_source_observed_age_seconds = policy
            .trusted_context
            .source_observed_age_seconds
            .map(|value| value.to_string());
        push_hash_optional(
            &mut material,
            "trusted_source_observed_age_seconds",
            trusted_source_observed_age_seconds.as_deref(),
        );
    }
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    format!("sha256:{}", hex_lower(&hasher.finalize()))
}

fn push_hash_list(material: &mut String, name: &str, values: &[String]) {
    let mut values = values.iter().map(String::as_str).collect::<Vec<_>>();
    values.sort_unstable();
    material.push(';');
    material.push_str(name);
    material.push('=');
    material.push_str(&values.join(","));
}

fn push_hash_optional(material: &mut String, name: &str, value: Option<&str>) {
    material.push(';');
    material.push_str(name);
    material.push('=');
    material.push_str(value.unwrap_or(""));
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthMode, ScopeSet};
    use axum::http::HeaderValue;
    use registry_manifest_core::OdrlEnforcementProfile;
    use registry_platform_pdp::RequiredContextField;

    fn config_with_selector() -> Config {
        serde_saphyr::from_str(
            r#"
server:
  bind: 127.0.0.1:0
metadata:
  source:
    path: metadata.yaml
  ecosystem_binding:
    id: baseline-dpi/v1
    version: v1
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
auth:
  mode: api_key
  api_keys: []
datasets: []
audit:
  sink: stdout
  format: jsonl
"#,
        )
        .expect("config parses")
    }

    fn compiled_metadata_with_binding(constraint_terms: &[&str]) -> CompiledMetadata {
        let terms = constraint_terms
            .iter()
            .map(|term| format!("          - {term}"))
            .collect::<Vec<_>>()
            .join("\n");
        let manifest: registry_manifest_core::MetadataManifest = serde_saphyr::from_str(&format!(
            r#"
schema_version: registry-manifest/v1
catalog:
  id: test
  base_url: https://data.example.test
  title: Test
  publisher:
    name: Test
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      pack_id: baseline-dpi/v1
      pack_version: v1
      source_basis:
        family: dpi
        evidence_type: combined_support_evidence
      semantic_profile:
        vocabulary: registry-lab
        fit: strong
      evidence_envelope:
        format: minimized_json
        fields:
          - claim_id
          - result
      required_gates:
        - purpose
        - jurisdiction
        - legal_basis
        - consent
        - authority_basis
        - requester_identity
        - subject_identity
        - subject_relationship
        - assurance
        - source_binding
        - source_freshness
        - requested_disclosure
        - credential_format
        - route_scope
      allowed_outputs:
        - minimized_json
      policy_id: baseline-dpi-policy
      policy_hash: sha256:3333333333333333333333333333333333333333333333333333333333333333
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
{terms}
datasets: []
"#,
        ))
        .expect("metadata manifest parses");
        registry_manifest_core::compile_manifest(&manifest).expect("metadata compiles")
    }

    fn evidence_pack_with_constraint_terms(constraint_terms: Vec<String>) -> EvidencePackMetadata {
        EvidencePackMetadata {
            pack_id: Some("oots-birth-evidence/v1".to_string()),
            pack_version: Some("v1".to_string()),
            source_basis: Some(serde_json::json!({
                "family": "oots-common-data-model",
                "evidence_type": "Birth Evidence"
            })),
            semantic_profile: Some(serde_json::json!({
                "vocabulary": "publicschema",
                "fit": "strong"
            })),
            evidence_envelope: Some(serde_json::json!({
                "identifier": "required",
                "issuing_date": "required",
                "issuing_authority": "required"
            })),
            required_gates: Vec::new(),
            allowed_outputs: vec!["minimized_json".to_string()],
            policy_id: Some("baseline-dpi-policy".to_string()),
            policy_version: None,
            policy_hash: Some(
                "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            ),
            source_mapping: None,
            policy: None,
            fixtures: Vec::new(),
            synthetic_data: Vec::new(),
            odrl_policy_url: None,
            odrl_enforcement: Some(OdrlEnforcementProfile {
                profile: "registry-evidence-gateway-pdp/v1".to_string(),
                constraint_terms,
            }),
        }
    }

    #[test]
    fn selected_ecosystem_policy_uses_evidence_pack_identity() {
        let config = config_with_selector();
        let compiled = compiled_metadata_with_binding(&[ODRL_PURPOSE_COMPACT]);

        let selected = selected_ecosystem_policy_from_metadata(&config, Some(&compiled))
            .expect("selected binding resolves")
            .expect("selector is configured");

        assert_eq!(selected.policy_id, "baseline-dpi-policy");
        assert_eq!(
            selected.policy_hash,
            "sha256:3333333333333333333333333333333333333333333333333333333333333333"
        );
    }

    #[test]
    fn selected_ecosystem_policy_is_absent_without_selector() {
        let mut config = config_with_selector();
        config
            .metadata
            .as_mut()
            .expect("metadata config")
            .ecosystem_binding = None;
        let compiled = compiled_metadata_with_binding(&[ODRL_PURPOSE_COMPACT]);

        let selected = selected_ecosystem_policy_from_metadata(&config, Some(&compiled))
            .expect("metadata without selector is accepted");

        assert_eq!(selected, None);
    }

    #[test]
    fn selected_ecosystem_policy_accepts_purpose_odrl_term() {
        let config = config_with_selector();
        let compiled = compiled_metadata_with_binding(&[ODRL_PURPOSE_COMPACT]);

        let selected = selected_ecosystem_policy_from_metadata(&config, Some(&compiled))
            .expect("selected binding resolves")
            .expect("selector is configured");

        assert!(selected.unsupported_odrl_terms.is_empty());
    }

    #[test]
    fn selected_ecosystem_policy_reports_compact_spatial_odrl_term_unsupported() {
        let config = config_with_selector();
        let compiled =
            compiled_metadata_with_binding(&[ODRL_PURPOSE_COMPACT, ODRL_SPATIAL_COMPACT]);

        let selected = selected_ecosystem_policy_from_metadata(&config, Some(&compiled))
            .expect("selected binding resolves")
            .expect("selector is configured");

        assert_eq!(selected.unsupported_odrl_terms, vec![ODRL_SPATIAL_COMPACT]);
    }

    #[test]
    fn evidence_pack_policy_reports_absolute_spatial_odrl_term_unsupported() {
        let evidence_pack = evidence_pack_with_constraint_terms(vec![
            ODRL_PURPOSE.to_string(),
            ODRL_SPATIAL.to_string(),
        ]);
        let selected = evidence_pack_policy(Some(&evidence_pack)).expect("policy selected");

        assert_eq!(
            selected.odrl_constraint_terms,
            vec![ODRL_PURPOSE_COMPACT, ODRL_SPATIAL_COMPACT]
        );
        assert_eq!(selected.unsupported_odrl_terms, vec![ODRL_SPATIAL_COMPACT]);
    }

    #[test]
    fn selected_ecosystem_policy_reports_unsupported_odrl_terms() {
        let evidence_pack = evidence_pack_with_constraint_terms(vec![
            ODRL_PURPOSE_COMPACT.to_string(),
            "odrl:recipient".to_string(),
        ]);

        let selected = evidence_pack_policy(Some(&evidence_pack)).expect("policy selected");

        assert_eq!(selected.unsupported_odrl_terms, vec!["odrl:recipient"]);
    }

    #[test]
    fn request_pdp_context_records_only_the_route_checked_scope() {
        let principal = Principal {
            principal_id: "client-a".to_string(),
            scopes: [
                "social_registry:rows",
                "registry:trust:jurisdiction:SN",
                "registry_relay:admin",
            ]
            .into_iter()
            .collect::<ScopeSet>(),
            auth_mode: AuthMode::ApiKey,
        };
        let request_info = GovernedRequestInfo {
            route_identity: "relay.entity.collection",
            requested_disclosure: "entity_collection",
            checked_scope: "social_registry:rows",
            redaction_projection: GovernedRedactionProjection::EntityFields,
        };
        let context = request_pdp_context(
            "testing",
            &HeaderMap::new(),
            Some(&principal),
            "individual",
            "relay:social_registry:individuals_table",
            &request_info,
        )
        .expect("PDP context builds");

        assert_eq!(
            context.checked_scopes,
            BTreeSet::from(["social_registry:rows".to_string()])
        );
    }

    #[test]
    fn malformed_exact_scoped_freshness_records_trusted_field_provenance() {
        let request_info = GovernedRequestInfo {
            route_identity: "relay.entity.collection",
            requested_disclosure: "entity_collection",
            checked_scope: "social_registry:rows",
            redaction_projection: GovernedRedactionProjection::EntityFields,
        };
        for (header, field) in [
            (
                TRUST_SOURCE_OBSERVED_AT_UNIX_SECONDS_HEADER,
                TrustContextField::SourceObservedAtUnixSeconds,
            ),
            (
                TRUST_SOURCE_OBSERVED_AGE_SECONDS_HEADER,
                TrustContextField::SourceObservedAgeSeconds,
            ),
        ] {
            let malformed_value = "not-a-unix-second";
            let principal = Principal {
                principal_id: "client-a".to_string(),
                scopes: [
                    "social_registry:rows".to_string(),
                    format_trust_context_scope(field, malformed_value)
                        .expect("non-empty exact trust scope formats"),
                ]
                .into_iter()
                .collect::<ScopeSet>(),
                auth_mode: AuthMode::ApiKey,
            };
            let mut headers = HeaderMap::new();
            headers.insert(header, HeaderValue::from_static(malformed_value));

            let error = request_pdp_context(
                "testing",
                &headers,
                Some(&principal),
                "individual",
                "relay:social_registry:individuals_table",
                &request_info,
            )
            .expect_err("malformed authenticated freshness must deny");

            assert_eq!(
                error.pdp_trust_provenance,
                BTreeSet::from([field.as_str().to_string()])
            );
        }
    }

    fn policy_input_context(scopes: &[&str]) -> PdpRequestContext {
        let principal = Principal {
            principal_id: "client-a".to_string(),
            scopes: scopes.iter().copied().collect::<ScopeSet>(),
            auth_mode: AuthMode::ApiKey,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            TRUST_SUBJECT_REF_HEADER,
            HeaderValue::from_static("subject:123"),
        );
        headers.insert(
            TRUST_RELATIONSHIP_HEADER,
            HeaderValue::from_static("guardian"),
        );
        headers.insert(
            TRUST_ON_BEHALF_OF_HEADER,
            HeaderValue::from_static("agency:benefits"),
        );
        headers.insert(
            TRUST_REQUESTED_CREDENTIAL_FORMAT_HEADER,
            HeaderValue::from_static("sd_jwt_vc"),
        );
        headers.insert(
            TRUST_SOURCE_OBSERVED_AT_UNIX_SECONDS_HEADER,
            HeaderValue::from_static("9999999999"),
        );
        let request_info = GovernedRequestInfo {
            route_identity: "relay.entity.collection",
            requested_disclosure: "entity_collection",
            checked_scope: "social_registry:rows",
            redaction_projection: GovernedRedactionProjection::EntityFields,
        };

        request_pdp_context(
            "testing",
            &headers,
            Some(&principal),
            "individual",
            "relay:social_registry:individuals_table",
            &request_info,
        )
        .expect("PDP context builds")
    }

    fn policy_with_purpose(purpose: &str) -> PdpPolicyInput {
        serde_json::from_value(serde_json::json!({
            "policy_id": "relay.scope-gated-context-test",
            "policy_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "purpose_constraints": [[purpose]]
        }))
        .expect("scope-gated context policy parses")
    }

    #[derive(Clone, Copy, Debug)]
    enum ScopeGatedPolicyField {
        SubjectRef,
        Relationship,
        OnBehalfOf,
        RequestedCredentialFormat,
        SourceObservedAt,
    }

    impl ScopeGatedPolicyField {
        fn exact_scope(self) -> &'static str {
            match self {
                Self::SubjectRef => "registry:trust:subject_ref:subject:123",
                Self::Relationship => "registry:trust:relationship:guardian",
                Self::OnBehalfOf => "registry:trust:on_behalf_of:agency:benefits",
                Self::RequestedCredentialFormat => {
                    "registry:trust:requested_credential_format:sd_jwt_vc"
                }
                Self::SourceObservedAt => {
                    "registry:trust:source_observed_at_unix_seconds:9999999999"
                }
            }
        }

        fn mismatched_scope(self) -> &'static str {
            match self {
                Self::SubjectRef => "registry:trust:subject_ref:subject:other",
                Self::Relationship => "registry:trust:relationship:self",
                Self::OnBehalfOf => "registry:trust:on_behalf_of:agency:other",
                Self::RequestedCredentialFormat => {
                    "registry:trust:requested_credential_format:jwt_vc_json"
                }
                Self::SourceObservedAt => "registry:trust:source_observed_at_unix_seconds:1",
            }
        }

        fn policy(self) -> PdpPolicyInput {
            let mut policy = policy_with_purpose("testing");
            match self {
                Self::SubjectRef => {
                    policy
                        .required_context
                        .insert(RequiredContextField::SubjectRef);
                }
                Self::Relationship => {
                    policy.allowed_relationships = vec!["guardian".to_string()];
                }
                Self::OnBehalfOf => {
                    policy
                        .required_context
                        .insert(RequiredContextField::OnBehalfOf);
                }
                Self::RequestedCredentialFormat => {
                    policy.allowed_credential_formats = vec!["sd_jwt_vc".to_string()];
                }
                Self::SourceObservedAt => {
                    policy
                        .required_context
                        .insert(RequiredContextField::SourceFreshness);
                }
            }
            policy
        }

        fn denied_code(self) -> &'static str {
            match self {
                Self::SubjectRef | Self::OnBehalfOf | Self::SourceObservedAt => {
                    registry_platform_pdp::CONTEXT_REQUIRED
                }
                Self::Relationship => registry_platform_pdp::RELATIONSHIP_NOT_PERMITTED,
                Self::RequestedCredentialFormat => {
                    registry_platform_pdp::CREDENTIAL_FORMAT_NOT_PERMITTED
                }
            }
        }
    }

    fn assert_policy_denied(
        field: ScopeGatedPolicyField,
        context: &PdpRequestContext,
        policy: &PdpPolicyInput,
    ) {
        match relay_pdp_decide(context, policy) {
            PdpDecision::Deny {
                stable_problem_code,
                ..
            } => assert_eq!(stable_problem_code, field.denied_code(), "{field:?}"),
            decision => panic!("{field:?} should deny, got {decision:?}"),
        }
    }

    #[test]
    fn scope_gated_policy_inputs_require_the_exact_value_scope_to_permit() {
        for field in [
            ScopeGatedPolicyField::SubjectRef,
            ScopeGatedPolicyField::Relationship,
            ScopeGatedPolicyField::OnBehalfOf,
            ScopeGatedPolicyField::RequestedCredentialFormat,
            ScopeGatedPolicyField::SourceObservedAt,
        ] {
            let policy = field.policy();

            let absent_scope_context = policy_input_context(&["social_registry:rows"]);
            assert_policy_denied(field, &absent_scope_context, &policy);

            let mismatched_scope_context =
                policy_input_context(&["social_registry:rows", field.mismatched_scope()]);
            assert_policy_denied(field, &mismatched_scope_context, &policy);

            let exact_scope_context =
                policy_input_context(&["social_registry:rows", field.exact_scope()]);
            assert!(
                matches!(
                    relay_pdp_decide(&exact_scope_context, &policy),
                    PdpDecision::Permit(_)
                ),
                "{field:?} should permit with its exact value scope"
            );
        }
    }

    fn assert_relay_only_provenance(expected_permit: bool) {
        let cases: &[(&str, &[&str], bool)] = &[
            ("unscoped", &["social_registry:rows"], false),
            (
                "mismatched",
                &[
                    "social_registry:rows",
                    "registry:trust:subject_ref:subject:other",
                    "registry:trust:relationship:self",
                    "registry:trust:on_behalf_of:agency:other",
                    "registry:trust:requested_credential_format:jwt_vc_json",
                ],
                false,
            ),
            (
                "exact-scoped",
                &[
                    "social_registry:rows",
                    "registry:trust:subject_ref:subject:123",
                    "registry:trust:relationship:guardian",
                    "registry:trust:on_behalf_of:agency:benefits",
                    "registry:trust:requested_credential_format:sd_jwt_vc",
                ],
                true,
            ),
        ];
        let policy = policy_with_purpose(if expected_permit {
            "testing"
        } else {
            "other-purpose"
        });

        for (label, scopes, expected_provenance) in cases {
            let context = policy_input_context(scopes);
            let decision = relay_pdp_decide(&context, &policy);
            let audit = match (expected_permit, decision) {
                (true, PdpDecision::Permit(audit)) => audit,
                (false, PdpDecision::Deny { audit, .. }) => audit,
                (_, decision) => panic!("{label} produced an unexpected decision: {decision:?}"),
            };
            let expected = if *expected_provenance {
                BTreeSet::from([
                    "on_behalf_of".to_string(),
                    "relationship".to_string(),
                    "requested_credential_format".to_string(),
                    "subject_ref".to_string(),
                ])
            } else {
                BTreeSet::new()
            };
            assert_eq!(audit.trust_provenance, expected, "{label}");

            let serialized = serde_json::to_string(&audit).expect("decision audit serializes");
            for raw_value in ["subject:123", "guardian", "agency:benefits", "sd_jwt_vc"] {
                assert!(
                    !serialized.contains(raw_value),
                    "{label} audit must not include raw context value {raw_value}"
                );
            }
        }
    }

    #[test]
    fn relay_permit_audit_records_only_exact_scoped_context_field_names() {
        assert_relay_only_provenance(true);
    }

    #[test]
    fn relay_deny_audit_records_only_exact_scoped_context_field_names() {
        assert_relay_only_provenance(false);
    }
}
