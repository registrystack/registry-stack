// SPDX-License-Identifier: Apache-2.0
//! Claim definitions, rules, and operation configuration.

use super::*;

fn default_claim_formats() -> Vec<String> {
    vec![FORMAT_CLAIM_RESULT_JSON.to_string()]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDefinition {
    pub id: String,
    pub title: String,
    pub version: String,
    pub subject_type: String,
    #[serde(default)]
    pub value: ClaimValueConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantics: Option<ClaimSemanticConfig>,
    #[serde(default)]
    pub inputs: Vec<ClaimInputConfig>,
    #[serde(default)]
    pub depends_on: Vec<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    #[serde(default)]
    pub source_bindings: BTreeMap<String, SourceBindingConfig>,
    pub rule: RuleConfig,
    #[serde(default)]
    pub operations: ClaimOperationsConfig,
    #[serde(default)]
    pub disclosure: DisclosureConfig,
    #[serde(default = "default_claim_formats")]
    pub formats: Vec<String>,
    #[serde(default)]
    pub credential_profiles: Vec<String>,
    #[serde(default)]
    pub cccev: Option<CccevConfig>,
    #[serde(default)]
    pub oots: Option<OotsConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSemanticConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concept: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicate: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_mapping: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimValueConfig {
    #[serde(rename = "type", default)]
    pub value_type: String,
    #[serde(default)]
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimInputConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub input_type: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuleConfig {
    Extract {
        source: String,
        field: String,
    },
    Exists {
        source: String,
    },
    Cel {
        expression: String,
        #[serde(default)]
        bindings: CelBindingsConfig,
    },
    Plugin {
        plugin: String,
    },
}

pub(in crate::config) fn validate_claim_semantics(
    claim: &ClaimDefinition,
) -> Result<(), EvidenceConfigError> {
    let Some(semantics) = &claim.semantics else {
        return Ok(());
    };
    let mut has_term = false;
    for (field, value) in [
        ("concept", semantics.concept.as_deref()),
        ("property", semantics.property.as_deref()),
        ("vocabulary", semantics.vocabulary.as_deref()),
        ("predicate", semantics.predicate.as_deref()),
    ] {
        let Some(value) = value else {
            continue;
        };
        has_term = true;
        validate_semantic_reference(&claim.id, field, value)?;
    }
    for value in &semantics.derived_from {
        has_term = true;
        validate_semantic_reference(&claim.id, "derived_from", value)?;
    }
    if let Some(value_mapping) = semantics.value_mapping.as_deref() {
        if value_mapping.trim().is_empty() {
            return invalid_claim_semantics(&claim.id, "value_mapping must not be empty");
        }
    }
    if !has_term {
        return invalid_claim_semantics(
            &claim.id,
            "at least one of concept, property, vocabulary, predicate, or derived_from must be set",
        );
    }
    if semantics.property.is_some() && semantics.predicate.is_some() {
        return invalid_claim_semantics(
            &claim.id,
            "property and predicate are mutually exclusive; use derived_from for predicate inputs",
        );
    }
    if let RuleConfig::Extract { source, field } = &claim.rule {
        validate_extract_semantics(claim, semantics, source, field)?;
    }
    Ok(())
}

pub(in crate::config) fn validate_extract_semantics(
    claim: &ClaimDefinition,
    semantics: &ClaimSemanticConfig,
    source: &str,
    field: &str,
) -> Result<(), EvidenceConfigError> {
    let Some(property) = semantics.property.as_deref() else {
        return Ok(());
    };
    let Some(binding) = claim.source_bindings.get(source) else {
        return Ok(());
    };
    let Some(source_field) = binding.fields.get(field) else {
        return Ok(());
    };
    let Some(field_term) = source_field.semantic_term.as_deref().map(str::trim) else {
        return Ok(());
    };
    let property = property.trim();
    if field_term != property {
        return invalid_claim_semantics(
            &claim.id,
            format!(
                "property '{property}' conflicts with source field '{source}.{field}' semantic_term '{field_term}'"
            ),
        );
    }
    Ok(())
}

pub(in crate::config) fn validate_semantic_reference(
    claim_id: &str,
    field: &str,
    value: &str,
) -> Result<(), EvidenceConfigError> {
    let value = value.trim();
    if value.is_empty() {
        return invalid_claim_semantics(claim_id, format!("{field} must not be empty"));
    }
    if value.starts_with("https://") || value.starts_with("http://") || value.starts_with("urn:") {
        return Ok(());
    }
    invalid_claim_semantics(
        claim_id,
        format!("{field} must be an absolute http(s) URI or urn"),
    )
}

pub(in crate::config) fn invalid_claim_semantics<T>(
    claim: &str,
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidClaimSemantics {
        claim: claim.to_string(),
        reason: reason.into(),
    })
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CelBindingsConfig {
    #[serde(default)]
    pub claims: BTreeMap<String, ClaimBindingConfig>,
    #[serde(default)]
    pub vars: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimBindingConfig {
    pub claim: String,
    #[serde(default)]
    pub binding_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimOperationsConfig {
    #[serde(default = "default_enabled_operation")]
    pub evaluate: OperationConfig,
    #[serde(default)]
    pub batch_evaluate: BatchOperationConfig,
}

impl Default for ClaimOperationsConfig {
    fn default() -> Self {
        Self {
            evaluate: OperationConfig { enabled: true },
            batch_evaluate: BatchOperationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationConfig {
    #[serde(default)]
    pub enabled: bool,
}

pub(in crate::config) fn default_enabled_operation() -> OperationConfig {
    OperationConfig { enabled: true }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchOperationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_inline_batch_limit")]
    pub max_subjects: usize,
}

impl Default for BatchOperationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_subjects: default_inline_batch_limit(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CccevConfig {
    #[serde(default)]
    pub requirement_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_type_iri: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OotsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub requirement: Option<String>,
    #[serde(default)]
    pub reference_framework: Option<String>,
    #[serde(default)]
    pub evidence_type_classification: Option<String>,
    #[serde(default)]
    pub evidence_type_list: Option<String>,
    #[serde(default)]
    pub languages: Vec<String>,
    #[serde(default)]
    pub authentication_level_of_assurance: Option<String>,
}
