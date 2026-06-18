// SPDX-License-Identifier: Apache-2.0
//! Shared governed evidence policy enforcement for entity-backed API reads.

use std::collections::BTreeSet;

use axum::http::HeaderMap;
use registry_manifest_core::{
    CompiledDatasetPolicy, CompiledMetadata, CompiledPolicyOperandValue, EvidencePackMetadata,
};
use registry_platform_pdp::{
    decide as pdp_decide, Decision as PdpDecision, DecisionAudit as PdpDecisionAudit,
    EvidenceRequestContext as PdpRequestContext, PolicyInput as PdpPolicyInput,
};
use sha2::{Digest, Sha256};

use crate::audit::AuditContextExt;
use crate::config::{Config, EntityApiConfig, EntityConfig};
use crate::entity::EntityModel;
use crate::error::{AuthError, Error, InternalError, PdpError};
use crate::runtime_config::RuntimeSnapshot;

pub(crate) const DATA_PURPOSE_HEADER: &str = "data-purpose";

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
}

#[derive(Debug, Default)]
pub(crate) struct GovernedReadDecision {
    pub(crate) audit: Option<PdpDecisionAudit>,
    pub(crate) redaction_fields: BTreeSet<String>,
    pub(crate) purpose: Option<String>,
}

#[derive(Debug)]
pub(crate) struct GovernedAccessError {
    pub(crate) error: Error,
    pub(crate) pdp_audit: Option<PdpDecisionAudit>,
}

impl GovernedAccessError {
    pub(crate) fn from_error(error: impl Into<Error>) -> Self {
        Self {
            error: error.into(),
            pdp_audit: None,
        }
    }

    fn with_pdp_audit(error: Error, audit: PdpDecisionAudit) -> Self {
        Self {
            error,
            pdp_audit: Some(audit),
        }
    }
}

impl From<Error> for GovernedAccessError {
    fn from(error: Error) -> Self {
        Self::from_error(error)
    }
}

pub(crate) fn require_governed_read_access<E: GovernedEntity + ?Sized>(
    runtime: &RuntimeSnapshot,
    dataset_id: &str,
    entity: &E,
    headers: &HeaderMap,
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
    let context = PdpRequestContext {
        purpose: purpose.to_string(),
        legal_basis_ref: governed_policy
            .and_then(|policy| policy.trusted_context.legal_basis_ref.clone()),
        consent_ref: governed_policy.and_then(|policy| policy.trusted_context.consent_ref.clone()),
        asserted_assurance: governed_policy
            .and_then(|policy| policy.trusted_context.asserted_assurance.clone()),
        jurisdiction: governed_policy
            .and_then(|policy| policy.trusted_context.jurisdiction.clone()),
        source_observed_age_seconds: governed_policy
            .and_then(|policy| policy.trusted_context.source_observed_age_seconds),
    };
    let selected_policy = selected_ecosystem_policy(runtime).map_err(GovernedAccessError::from)?;
    if purpose_constraints.is_empty() {
        return Err(GovernedAccessError::from_error(AuthError::PurposeDenied));
    }
    let policy = PdpPolicyInput {
        policy_id: selected_policy
            .as_ref()
            .map(|policy| policy.policy_id.clone())
            .unwrap_or_else(|| format!("relay.entity.{}.purpose-required", entity.name())),
        policy_hash: selected_policy
            .as_ref()
            .map(|policy| policy.policy_hash.clone())
            .unwrap_or_else(|| entity_purpose_policy_hash(entity, &purpose_constraints)),
        rule_ids: vec![format!("entity-purpose-required:{}", entity.name())],
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
        redaction_fields: governed_policy
            .map(|policy| policy.redaction_fields.iter().cloned().collect())
            .unwrap_or_default(),
        unsupported_odrl_terms: selected_policy
            .map(|policy| policy.unsupported_odrl_terms)
            .unwrap_or_default(),
    };
    match pdp_decide(&context, &policy) {
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
        .map(Some)
}

fn evidence_pack_policy(
    evidence_pack: Option<&EvidencePackMetadata>,
) -> Option<SelectedEcosystemPolicy> {
    let evidence_pack = evidence_pack?;
    let enforcement = evidence_pack.odrl_enforcement.as_ref()?;
    let unsupported_odrl_terms = enforcement
        .constraint_terms
        .iter()
        .filter(|term| !supported_odrl_term(term))
        .cloned()
        .collect();
    Some(SelectedEcosystemPolicy {
        policy_id: evidence_pack.policy_id.as_ref()?.trim().to_string(),
        policy_hash: evidence_pack.policy_hash.as_ref()?.trim().to_string(),
        unsupported_odrl_terms,
    })
}

fn supported_odrl_term(term: &str) -> bool {
    matches!(
        term,
        ODRL_PURPOSE | ODRL_PURPOSE_COMPACT | ODRL_SPATIAL | ODRL_SPATIAL_COMPACT
    )
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
    use registry_manifest_core::OdrlEnforcementProfile;

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
    fn selected_ecosystem_policy_accepts_pdp_supported_odrl_terms() {
        let config = config_with_selector();
        let compiled =
            compiled_metadata_with_binding(&[ODRL_PURPOSE_COMPACT, ODRL_SPATIAL_COMPACT]);

        let selected = selected_ecosystem_policy_from_metadata(&config, Some(&compiled))
            .expect("selected binding resolves")
            .expect("selector is configured");

        assert!(selected.unsupported_odrl_terms.is_empty());
    }

    #[test]
    fn selected_ecosystem_policy_reports_unsupported_odrl_terms() {
        let evidence_pack = EvidencePackMetadata {
            policy_id: Some("baseline-dpi-policy".to_string()),
            policy_version: None,
            policy_hash: Some(
                "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            ),
            odrl_policy_url: None,
            odrl_enforcement: Some(OdrlEnforcementProfile {
                profile: "registry-evidence-gateway-pdp/v1".to_string(),
                constraint_terms: vec![
                    ODRL_PURPOSE_COMPACT.to_string(),
                    "odrl:recipient".to_string(),
                ],
            }),
        };

        let selected = evidence_pack_policy(Some(&evidence_pack)).expect("policy selected");

        assert_eq!(selected.unsupported_odrl_terms, vec!["odrl:recipient"]);
    }
}
