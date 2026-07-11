// SPDX-License-Identifier: Apache-2.0
//! Claim definitions, rules, and operation configuration.

use super::*;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimDefinition {
    pub id: String,
    pub title: String,
    pub version: String,
    pub subject_type: String,
    /// Sealed provenance choice. This field is intentionally required so an
    /// omitted connection can never turn a registry-backed claim into a
    /// source-free claim.
    pub evidence_mode: ClaimEvidenceMode,
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
    /// Caller scopes checked before any registry consultation is dispatched.
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub source_bindings: BTreeMap<String, SourceBindingConfig>,
    pub rule: RuleConfig,
    #[serde(default)]
    pub operations: ClaimOperationsConfig,
    #[serde(default)]
    pub disclosure: DisclosureConfig,
    #[serde(default)]
    pub formats: Vec<String>,
    #[serde(default)]
    pub credential_profiles: Vec<String>,
    #[serde(default)]
    pub cccev: Option<CccevConfig>,
    #[serde(default)]
    pub oots: Option<OotsConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClaimEvidenceMode {
    RegistryBacked {
        consultations: BTreeMap<String, RelayConsultationConfig>,
    },
    SelfAttested,
    /// Temporary migration mode for the pre-convergence direct-source model.
    /// It has no default or aliases, keeping its eventual removal mechanical.
    TransitionalDirect,
}

impl<'de> Deserialize<'de> for ClaimEvidenceMode {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
        enum SealedClaimEvidenceMode {
            RegistryBacked {
                consultations: BTreeMap<String, RelayConsultationConfig>,
            },
            SelfAttested {},
            TransitionalDirect {},
        }

        match SealedClaimEvidenceMode::deserialize(deserializer)? {
            SealedClaimEvidenceMode::RegistryBacked { consultations } => {
                Ok(Self::RegistryBacked { consultations })
            }
            SealedClaimEvidenceMode::SelfAttested {} => Ok(Self::SelfAttested),
            SealedClaimEvidenceMode::TransitionalDirect {} => Ok(Self::TransitionalDirect),
        }
    }
}

impl ClaimEvidenceMode {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::RegistryBacked { .. } => "registry_backed",
            Self::SelfAttested => "self_attested",
            Self::TransitionalDirect => "transitional_direct",
        }
    }

    #[must_use]
    pub const fn is_registry_backed(&self) -> bool {
        matches!(self, Self::RegistryBacked { .. })
    }

    #[must_use]
    pub const fn is_self_attested(&self) -> bool {
        matches!(self, Self::SelfAttested)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConsultationConfig {
    pub profile: RelayConsultationProfileRef,
    pub inputs: BTreeMap<String, RelayConsultationInput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConsultationProfileRef {
    pub id: String,
    pub version: String,
    pub contract_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RelayConsultationInput {
    #[serde(rename = "target.id")]
    TargetId,
}

impl<'de> Deserialize<'de> for RelayConsultationInput {
    fn deserialize<Deserializer>(deserializer: Deserializer) -> Result<Self, Deserializer::Error>
    where
        Deserializer: serde::Deserializer<'de>,
    {
        let mapping = String::deserialize(deserializer)?;
        if mapping == "target.id" {
            Ok(Self::TargetId)
        } else {
            Err(serde::de::Error::custom(
                "unsupported consultation input mapping; v1 permits only target.id",
            ))
        }
    }
}

pub(in crate::config) fn validate_claim_evidence_mode(
    claim: &ClaimDefinition,
    relay_configured: bool,
) -> Result<(), EvidenceConfigError> {
    validate_claim_required_scopes(claim)?;
    match &claim.evidence_mode {
        ClaimEvidenceMode::RegistryBacked { consultations } => {
            if !relay_configured {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed requires evidence.relay",
                );
            }
            if !claim.source_bindings.is_empty() {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed cannot declare source_bindings",
                );
            }
            if claim.purpose.as_deref().is_none_or(|purpose| {
                purpose.is_empty()
                    || purpose.len() > 256
                    || purpose.contains(',')
                    || purpose
                        .chars()
                        .any(|character| character.is_control() || character.is_whitespace())
            }) {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed requires one explicit bounded purpose token",
                );
            }
            if claim.required_scopes.is_empty() {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed requires required_scopes to contain at least one entry",
                );
            }
            if claim.operations.batch_evaluate.enabled {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed cannot enable batch_evaluate in v1",
                );
            }
            if consultations.len() != 1 {
                return invalid_claim_evidence_mode(
                    claim,
                    "registry_backed requires exactly one named consultation in v1",
                );
            }
            let (consultation_name, consultation) = consultations
                .first_key_value()
                .expect("exactly one consultation was checked above");
            validate_consultation(claim, consultation_name, consultation)?;
            match &claim.rule {
                RuleConfig::Extract { source, field } => {
                    if source != consultation_name {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed rule.source must match its consultation name",
                        );
                    }
                    if !is_input_name(field) {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed extract rule.field must be one top-level Relay output name",
                        );
                    }
                    if !matches!(
                        claim.value.value_type.as_str(),
                        "string" | "boolean" | "integer" | "number"
                    ) {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed extract claim value.type must be string, boolean, integer, or number",
                        );
                    }
                }
                RuleConfig::Exists { source } => {
                    if source != consultation_name {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed rule.source must match its consultation name",
                        );
                    }
                    if claim.value.value_type != "boolean" {
                        return invalid_claim_evidence_mode(
                            claim,
                            "registry_backed exists claim value.type must be boolean",
                        );
                    }
                }
                RuleConfig::Cel { .. } | RuleConfig::Plugin { .. } => {
                    return invalid_claim_evidence_mode(
                        claim,
                        "registry_backed supports only exists and extract rules in v1",
                    );
                }
            }
        }
        ClaimEvidenceMode::SelfAttested => {
            if !claim.source_bindings.is_empty() {
                return invalid_claim_evidence_mode(
                    claim,
                    "self_attested cannot declare source_bindings",
                );
            }
            if matches!(
                claim.rule,
                RuleConfig::Extract { .. } | RuleConfig::Exists { .. }
            ) {
                return invalid_claim_evidence_mode(
                    claim,
                    "self_attested rules cannot name an evidence source",
                );
            }
        }
        ClaimEvidenceMode::TransitionalDirect => {}
    }
    Ok(())
}

pub(in crate::config) fn validate_self_attested_dependency_modes(
    claims: &[ClaimDefinition],
) -> Result<(), EvidenceConfigError> {
    for claim in claims
        .iter()
        .filter(|claim| claim.evidence_mode.is_self_attested())
    {
        let mut pending: Vec<&str> = claim.depends_on.iter().map(String::as_str).collect();
        let mut visited = HashSet::new();
        while let Some(dependency_id) = pending.pop() {
            if !visited.insert(dependency_id) {
                continue;
            }
            let Some(dependency) = claims
                .iter()
                .find(|candidate| candidate.id == dependency_id)
            else {
                continue;
            };
            if !dependency.evidence_mode.is_self_attested() {
                return invalid_claim_evidence_mode(
                    claim,
                    "self_attested dependency closure may contain only self_attested claims",
                );
            }
            pending.extend(dependency.depends_on.iter().map(String::as_str));
        }
    }
    Ok(())
}

fn validate_claim_required_scopes(claim: &ClaimDefinition) -> Result<(), EvidenceConfigError> {
    if claim.required_scopes.len() > 16 {
        return invalid_claim_evidence_mode(
            claim,
            "required_scopes cannot contain more than 16 entries",
        );
    }
    let mut seen = HashSet::new();
    for scope in &claim.required_scopes {
        if scope.is_empty()
            || scope.len() > 128
            || !scope
                .bytes()
                .all(|byte| matches!(byte, b'!' | b'#'..=b'[' | b']'..=b'~'))
        {
            return invalid_claim_evidence_mode(
                claim,
                "required_scopes entries must be bounded OAuth scope tokens",
            );
        }
        if !seen.insert(scope.as_str()) {
            return invalid_claim_evidence_mode(
                claim,
                "required_scopes must not contain duplicate entries",
            );
        }
    }
    Ok(())
}

fn validate_consultation(
    claim: &ClaimDefinition,
    name: &str,
    consultation: &RelayConsultationConfig,
) -> Result<(), EvidenceConfigError> {
    if !is_stable_id(name) {
        return invalid_claim_evidence_mode(
            claim,
            "consultation names must use the bounded Relay stable-id grammar",
        );
    }
    if !is_stable_id(&consultation.profile.id) {
        return invalid_claim_evidence_mode(
            claim,
            "consultation profile.id must match [a-z][a-z0-9._-]{0,95}",
        );
    }
    if !is_profile_version(&consultation.profile.version) {
        return invalid_claim_evidence_mode(
            claim,
            "consultation profile.version must match [1-9][0-9]{0,9}",
        );
    }
    validate_sha256_uri(&consultation.profile.contract_hash).map_err(|reason| {
        EvidenceConfigError::InvalidClaimEvidenceMode {
            claim: claim.id.clone(),
            reason: format!("consultation profile.contract_hash {reason}"),
        }
    })?;
    if consultation.inputs.len() != 1 {
        return invalid_claim_evidence_mode(
            claim,
            "consultation inputs must contain exactly one target.id mapping in v1",
        );
    }
    let (input_name, input) = consultation
        .inputs
        .first_key_value()
        .expect("exactly one consultation input was checked above");
    if !is_input_name(input_name) {
        return invalid_claim_evidence_mode(
            claim,
            "consultation input names must match [a-z][a-z0-9_]{0,95}",
        );
    }
    if *input != RelayConsultationInput::TargetId {
        return invalid_claim_evidence_mode(
            claim,
            "consultation inputs support only target.id in v1",
        );
    }
    Ok(())
}

fn is_stable_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 96
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-' | b'_'))
}

fn is_input_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 96
        && bytes.all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
}

fn is_profile_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 10
        && matches!(value.as_bytes().first(), Some(b'1'..=b'9'))
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn invalid_claim_evidence_mode<T>(
    claim: &ClaimDefinition,
    reason: impl Into<String>,
) -> Result<T, EvidenceConfigError> {
    Err(EvidenceConfigError::InvalidClaimEvidenceMode {
        claim: claim.id.clone(),
        reason: reason.into(),
    })
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
