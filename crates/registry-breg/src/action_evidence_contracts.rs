// SPDX-License-Identifier: Apache-2.0
//! Offline, governed Evidence capabilities for immediate actions.
use crate::{
    contract::{ChangeRequestEvidenceSource, FieldTypeSource, ModuleAssetSource, RegistryProject},
    diagnostics::Diagnostic,
    model::CompiledActionInventory,
};
use registry_evidence_client::{
    DefinitionResponseFormat, EvidenceDefinition, ExpectedFormDocument, ExpectedScalarFormDocument,
    ReviewedContracts, SelectorValueOrigin,
};
use registry_evidence_verifier::model::SubjectBindingMode;
use registry_evidence_verifier::AssuranceProfile;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_EVIDENCE_CAPABILITIES: usize = 2;
pub const MAX_EVIDENCE_CONTRACT_BYTES: usize = 1_048_576;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceSubjectResolution {
    TrustedProviderExactSelector,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceProviderSource {
    pub id: String,
    pub contracts: String,
    pub subject_resolution: EvidenceSubjectResolution,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ActionEvidenceSource {
    pub id: String,
    pub provider: String,
    pub requirement: String,
    pub subjects: BTreeMap<String, EvidenceSubjectSource>,
    pub outputs: Vec<String>,
    pub maximum_observation_age_seconds: u64,
}
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EvidenceSubjectSource {
    pub profile: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CompiledEvidenceCapability {
    pub id: String,
    pub provider: String,
    pub contract_fingerprint: String,
    pub assurance_profile: AssuranceProfile,
    pub audience: String,
    pub issued_by: String,
    pub provided_by: String,
    pub definition: EvidenceDefinition,
    pub outputs: Vec<String>,
    pub maximum_observation_age_seconds: u64,
    pub subject_resolution: EvidenceSubjectResolution,
}

// Match the governed action identifier grammar so aliases are safe bounded locations.
fn valid_evidence_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

pub(crate) fn compile_request_evidence(
    project: &RegistryProject,
    assets: &[ModuleAssetSource],
    source: &ChangeRequestEvidenceSource,
) -> Result<CompiledEvidenceCapability, ()> {
    let provider = project
        .evidence_providers
        .iter()
        .find(|provider| provider.id == source.provider)
        .ok_or(())?;
    let matches = assets
        .iter()
        .filter(|asset| asset.module.is_none() && asset.path == provider.contracts)
        .collect::<Vec<_>>();
    if !valid_contract_path(&provider.contracts)
        || matches.len() != 1
        || matches[0].bytes.len() > MAX_EVIDENCE_CONTRACT_BYTES
    {
        return Err(());
    }
    let contracts = registry_platform_canonical_json::parse_json_strict(&matches[0].bytes)
        .ok()
        .and_then(|value| serde_json::from_value::<ReviewedContracts>(value).ok())
        .filter(|contract| contract.validate().is_ok())
        .ok_or(())?;
    let definitions = contracts
        .definitions
        .iter()
        .filter(|definition| {
            definition.requirement == source.requirement
                && definition.subjects.len() == source.subjects.len()
                && definition.subjects.iter().all(|subject| {
                    source
                        .subjects
                        .get(&subject.role)
                        .is_some_and(|selected| selected.profile == subject.selector.profile)
                })
        })
        .collect::<Vec<_>>();
    let definition = definitions.first().copied().ok_or(())?;
    let outputs = source
        .requires
        .iter()
        .map(|requirement| requirement.output.clone())
        .collect::<Vec<_>>();
    let output_ids = outputs.iter().collect::<BTreeSet<_>>();
    let valid = valid_evidence_id(&source.id)
        && valid_evidence_id(&provider.id)
        && definitions.len() == 1
        && (1..=300).contains(&source.maximum_observation_age_seconds)
        && !outputs.is_empty()
        && output_ids.len() == outputs.len()
        && definition
            .subject_binding_mode
            .unwrap_or(SubjectBindingMode::AudienceScoped)
            == SubjectBindingMode::AudienceScoped
        && definition
            .response_formats
            .contains(&DefinitionResponseFormat::SignedJws)
        && definition
            .subjects
            .iter()
            .all(|subject| subject.selector.value_origin == SelectorValueOrigin::Request)
        && source.requires.iter().all(|requirement| {
            let choices = usize::from(requirement.equals.is_some())
                + usize::from(requirement.equals_from_request_field.is_some())
                + usize::from(requirement.at_least.is_some())
                + usize::from(requirement.at_most.is_some());
            choices == 1
                && definition.concepts.iter().any(|concept| {
                    concept.handle == requirement.output
                        && concept.scalar_expected_output().is_some_and(|expected| {
                            requirement.equals.as_ref().is_none_or(|value| {
                                evidence_requirement_value_valid(value, &expected.form)
                            }) && if requirement.at_least.is_some() || requirement.at_most.is_some()
                            {
                                matches!(
                                    expected.form,
                                    ExpectedFormDocument::Scalar(
                                        ExpectedScalarFormDocument::Integer
                                    )
                                )
                            } else {
                                true
                            }
                        })
                })
        });
    if !valid {
        return Err(());
    }
    let fingerprint = digest_fingerprint(Sha256::digest(
        registry_platform_canonical_json::canonicalize_json(&serde_json::json!({
            "capability": source,
            "provider": provider,
            "contract": contracts,
        }))
        .map_err(|_| ())?,
    ));
    Ok(CompiledEvidenceCapability {
        id: source.id.clone(),
        provider: provider.id.clone(),
        contract_fingerprint: fingerprint,
        assurance_profile: contracts.assurance_profile,
        audience: contracts.audience.clone(),
        issued_by: contracts.issued_by.clone(),
        provided_by: contracts.provided_by.clone(),
        definition: definition.clone(),
        outputs,
        maximum_observation_age_seconds: source.maximum_observation_age_seconds,
        subject_resolution: provider.subject_resolution,
    })
}

fn evidence_requirement_value_valid(
    value: &serde_json::Value,
    form: &ExpectedFormDocument,
) -> bool {
    // Reuse the verifier's closed wire representation before comparing forms.
    // This rejects missing members and extra properties in structured scalars.
    if serde_json::from_value::<registry_evidence_verifier::model::PublicValue>(value.clone())
        .is_err()
    {
        return false;
    }
    match form {
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean) => value.is_boolean(),
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Integer) => value
            .as_number()
            .and_then(registry_evidence_verifier::model::safe_json_integer)
            .is_some(),
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::String) => value.is_string(),
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::DateBucket) => {
            value.get("form").and_then(serde_json::Value::as_str) == Some("date-bucket")
        }
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::TimeBucket) => {
            value.get("form").and_then(serde_json::Value::as_str) == Some("time-bucket")
        }
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::EntityReference) => {
            value.get("form").and_then(serde_json::Value::as_str)
                == Some("audience-scoped-entity-reference")
        }
        // Reviewed structured outputs are deliberately outside the finite
        // equality grammar used by Registry application preconditions.
        ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Structured)
        | ExpectedFormDocument::List(_) => false,
    }
}

pub(crate) fn evidence_output_matches_field_type(
    capability: &CompiledEvidenceCapability,
    output: &str,
    field_type: &FieldTypeSource,
) -> bool {
    capability
        .definition
        .concepts
        .iter()
        .find(|concept| concept.handle == output)
        .and_then(|concept| concept.scalar_expected_output())
        .is_some_and(|expected| {
            matches!(
                (&expected.form, field_type),
                (
                    ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
                    FieldTypeSource::Boolean,
                ) | (
                    ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Integer),
                    FieldTypeSource::Int64,
                ) | (
                    ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::String),
                    FieldTypeSource::String { .. }
                        | FieldTypeSource::Text { .. }
                        | FieldTypeSource::Uuid
                        | FieldTypeSource::Reference { .. }
                        | FieldTypeSource::Timestamp,
                )
            )
        })
}

pub(crate) fn selector_field_matches_field_type(
    selector: &registry_evidence_client::SelectorField,
    field_type: &FieldTypeSource,
) -> bool {
    if let registry_evidence_client::SelectorField::String {
        minimum_bytes,
        maximum_bytes,
        ..
    } = selector
    {
        match field_type {
            FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => {
                return (*minimum_bytes..=*maximum_bytes).contains(&36);
            }
            FieldTypeSource::String {
                min_length,
                max_length,
            } => {
                return u64::from(*min_length) <= *maximum_bytes
                    && *minimum_bytes <= u64::from(*max_length) * 4;
            }
            FieldTypeSource::Text { max_length } => {
                return *minimum_bytes <= u64::from(*max_length) * 4;
            }
            _ => {}
        }
    }
    matches!(
        (selector, field_type),
        (
            registry_evidence_client::SelectorField::Boolean { .. },
            FieldTypeSource::Boolean
        ) | (
            registry_evidence_client::SelectorField::Integer { .. },
            FieldTypeSource::Int64
        ) | (
            registry_evidence_client::SelectorField::Date { .. },
            FieldTypeSource::Date
        ) | (
            registry_evidence_client::SelectorField::ControlledCode { .. },
            FieldTypeSource::VocabularyCode { .. }
        ) | (
            registry_evidence_client::SelectorField::String { .. },
            FieldTypeSource::String { .. }
                | FieldTypeSource::Text { .. }
                | FieldTypeSource::Uuid
                | FieldTypeSource::Reference { .. }
                | FieldTypeSource::Timestamp
        )
    )
}

pub fn valid_contract_path(path: &str) -> bool {
    path.len() <= 256
        && path.ends_with(".json")
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

pub(crate) fn compile_evidence(
    project: &RegistryProject,
    assets: &[ModuleAssetSource],
    inventory: &mut CompiledActionInventory,
) -> Result<(), Vec<Diagnostic>> {
    let mut errors = Vec::new();
    let mut providers = BTreeMap::new();
    for provider in &project.evidence_providers {
        let path = format!("evidenceProviders[{}].contracts", provider.id);
        let matches = assets
            .iter()
            .filter(|asset| asset.module.is_none() && asset.path == provider.contracts)
            .collect::<Vec<_>>();
        let contract = if valid_contract_path(&provider.contracts)
            && matches.len() == 1
            && matches[0].bytes.len() <= MAX_EVIDENCE_CONTRACT_BYTES
        {
            registry_platform_canonical_json::parse_json_strict(&matches[0].bytes)
                .ok()
                .and_then(|value| serde_json::from_value::<ReviewedContracts>(value).ok())
                .filter(|contract| contract.validate().is_ok())
        } else {
            None
        };
        match contract {
            Some(contract)
                if valid_evidence_id(&provider.id) && !providers.contains_key(&provider.id) =>
            {
                providers.insert(provider.id.clone(), (provider, contract));
            }
            _ => errors.push(Diagnostic::error("action.evidence.contract.invalid", &path, "declare a unique provider and a bounded valid reviewed Evidence contract in the offline project assets")),
        }
    }
    for action in &mut inventory.actions {
        let Some(source) = project.actions.iter().find(|source| source.id == action.id) else {
            continue;
        };
        let path = format!("actions[{}].evidence", action.id);
        if source.evidence.len() > MAX_EVIDENCE_CAPABILITIES
            || (!source.evidence.is_empty()
                && source
                    .handler
                    .as_ref()
                    .is_none_or(|handler| handler.abi != crate::contract::ACTION_HANDLER_ABI_V2))
        {
            errors.push(Diagnostic::error(
                "action.evidence.ceiling.invalid",
                &path,
                "Evidence requires handler ABI v2 and permits at most two optional capabilities",
            ));
            continue;
        }
        let mut ids = BTreeSet::new();
        for capability in &source.evidence {
            let location = format!("{path}[{}]", capability.id);
            let Some((provider, contracts)) = providers.get(&capability.provider) else {
                errors.push(Diagnostic::error(
                    "action.evidence.provider.unknown",
                    &location,
                    "the capability must reference a declared Evidence provider",
                ));
                continue;
            };
            let definitions = contracts
                .definitions
                .iter()
                .filter(|definition| {
                    definition.requirement == capability.requirement
                        && definition.subjects.len() == capability.subjects.len()
                        && definition.subjects.iter().all(|subject| {
                            capability
                                .subjects
                                .get(&subject.role)
                                .is_some_and(|selected| {
                                    selected.profile == subject.selector.profile
                                })
                        })
                })
                .collect::<Vec<_>>();
            let definition = definitions.first().copied();
            let valid = valid_evidence_id(&capability.id)
                && ids.insert(&capability.id)
                && (1..=300).contains(&capability.maximum_observation_age_seconds)
                && definitions.len() == 1
                && definition.is_some_and(|definition| {
                    definition
                        .subject_binding_mode
                        .unwrap_or(SubjectBindingMode::AudienceScoped)
                        == SubjectBindingMode::AudienceScoped
                        && definition
                            .response_formats
                            .contains(&DefinitionResponseFormat::SignedJws)
                        && definition.subjects.iter().all(|subject| {
                            subject.selector.value_origin == SelectorValueOrigin::Request
                        })
                        && !capability.outputs.is_empty()
                        && capability.outputs.iter().collect::<BTreeSet<_>>().len()
                            == capability.outputs.len()
                        && capability.outputs.iter().all(|output| {
                            definition.concepts.iter().any(|concept| {
                                &concept.handle == output
                                    && concept.scalar_expected_output().is_some()
                            })
                        })
                });
            if !valid {
                errors.push(Diagnostic::error("action.evidence.capability.invalid", &location, "require one exact signed-JWS audience-scoped contract, request-origin profiles, unique scalar outputs and observation age 1..300 seconds"));
                continue;
            }
            let definition = definition.unwrap().clone();
            let fingerprint = digest_fingerprint(Sha256::digest(registry_platform_canonical_json::canonicalize_json(&serde_json::json!({"capability":capability,"provider":provider,"contract":contracts})).expect("serializable contract")));
            action.evidence.push(CompiledEvidenceCapability {
                id: capability.id.clone(),
                provider: provider.id.clone(),
                contract_fingerprint: fingerprint,
                assurance_profile: contracts.assurance_profile,
                audience: contracts.audience.clone(),
                issued_by: contracts.issued_by.clone(),
                provided_by: contracts.provided_by.clone(),
                definition,
                outputs: capability.outputs.clone(),
                maximum_observation_age_seconds: capability.maximum_observation_age_seconds,
                subject_resolution: provider.subject_resolution,
            });
        }
        if !action.evidence.is_empty() {
            action.contract_fingerprint = digest_fingerprint(Sha256::digest(registry_platform_canonical_json::canonicalize_json(&serde_json::json!({"action":action.contract_fingerprint,"evidence":action.evidence})).expect("serializable capabilities")));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn digest_fingerprint(bytes: impl AsRef<[u8]>) -> String {
    format!(
        "sha256:{}",
        bytes
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
mod requirement_literal_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn structured_scalar_literals_follow_the_complete_verifier_wire_shape() {
        for (form, valid) in [
            (
                ExpectedScalarFormDocument::DateBucket,
                json!({"form":"date-bucket", "scheme":"urn:example:year", "bucket":"2026"}),
            ),
            (
                ExpectedScalarFormDocument::TimeBucket,
                json!({"form":"time-bucket", "scheme":"urn:example:hour", "bucket":"09"}),
            ),
            (
                ExpectedScalarFormDocument::EntityReference,
                json!({"form":"audience-scoped-entity-reference", "reference":"urn:example:record:1"}),
            ),
        ] {
            let expected = ExpectedFormDocument::Scalar(form);
            assert!(evidence_requirement_value_valid(&valid, &expected));
            for field in valid.as_object().unwrap().keys() {
                let mut missing = valid.clone();
                missing.as_object_mut().unwrap().remove(field);
                assert!(!evidence_requirement_value_valid(&missing, &expected));
            }
            let mut extra = valid.clone();
            extra["unexpected"] = json!(true);
            assert!(!evidence_requirement_value_valid(&extra, &expected));
            let mut wrong_type = valid.clone();
            let field = if valid.get("reference").is_some() {
                "reference"
            } else {
                "bucket"
            };
            wrong_type[field] = json!(42);
            assert!(!evidence_requirement_value_valid(&wrong_type, &expected));
        }
    }
}
