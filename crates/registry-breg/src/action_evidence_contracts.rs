// SPDX-License-Identifier: Apache-2.0
//! Offline, governed Evidence capabilities for immediate actions.
use crate::{
    contract::{ModuleAssetSource, RegistryProject},
    diagnostics::Diagnostic,
    model::CompiledActionInventory,
};
use registry_evidence_client::{
    DefinitionResponseFormat, EvidenceDefinition, ReviewedContracts, SelectorValueOrigin,
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
