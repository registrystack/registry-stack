// SPDX-License-Identifier: Apache-2.0
//! Exact reviewed Evidence contracts bound to guard-only Action inputs.
use std::collections::{BTreeMap, BTreeSet};

use crate::contract::{
    ActionSource, CommitEvidenceSelectorSource, FieldTypeSource, ModuleAssetSource, Operation,
    RegistryProject,
};
use crate::diagnostics::Diagnostic;
use crate::model::{
    CompiledActionInput, CompiledActionTargetUse, CompiledActionTargetUseSource,
    CompiledCommitEvidence, CompiledCommitEvidenceExpected, CompiledCommitEvidenceRequirement,
    CompiledCommitEvidenceSelector, CompiledCommitEvidenceSubject, CompiledEntity,
};

pub(super) fn compile(
    project: &RegistryProject,
    action: &ActionSource,
    inputs: &BTreeMap<&str, &CompiledActionInput>,
    entities: &BTreeMap<String, CompiledEntity>,
    assets: &[ModuleAssetSource],
    target_uses: &mut Vec<CompiledActionTargetUse>,
    errors: &mut Vec<Diagnostic>,
) -> Vec<CompiledCommitEvidence> {
    let base = format!("actions[id={}].commitGuards.evidence", action.id);
    let sources = &action.commit_guards.evidence;
    if sources.len() > crate::action_evidence_contracts::MAX_EVIDENCE_CAPABILITIES
        || sources
            .iter()
            .map(|item| item.requires.len())
            .sum::<usize>()
            > usize::from(crate::plan::MAX_PLAN_FIELD_MUTATIONS)
        || serde_json::to_vec(sources).map_or(true, |bytes| {
            bytes.len() > crate::plan::MAX_PLAN_SNAPSHOT_BYTES as usize
        })
    {
        errors.push(Diagnostic::error(
            "breg.action.commit-evidence-bounds",
            &base,
            "commit Evidence exceeds its finite capability, predicate, or byte ceiling",
        ));
        return Vec::new();
    }
    let mut ids = BTreeSet::new();
    let mut compiled = Vec::new();
    for source in sources {
        let path = format!("{base}[id={}]", source.id);
        if !ids.insert(&source.id) {
            errors.push(Diagnostic::error(
                "breg.action.commit-evidence-duplicate",
                &path,
                "commit Evidence identifiers must be unique",
            ));
            continue;
        }
        let capability = match crate::action_evidence_contracts::compile_commit_evidence(
            project, assets, source,
        ) {
            Ok(capability) => capability,
            Err(()) => {
                errors.push(Diagnostic::error("breg.action.commit-evidence-invalid", &path, "require one exact reviewed signed-JWS audience-scoped contract, request-origin selectors, unique scalar predicates, and observation age 1 through 300 seconds"));
                continue;
            }
        };
        let mut subjects = BTreeMap::new();
        for (role, subject) in &source.subjects {
            let definition = capability
                .definition
                .subjects
                .iter()
                .find(|entry| &entry.role == role);
            let fields = definition
                .into_iter()
                .flat_map(|entry| &entry.selector.fields)
                .map(registry_evidence_client::SelectorField::name)
                .collect::<BTreeSet<_>>();
            if fields != subject.selectors.keys().map(String::as_str).collect() {
                errors.push(Diagnostic::error(
                    "breg.action.commit-evidence-selector-fields",
                    format!("{path}.subjects[{role}].selectors"),
                    "bind exactly every field in the reviewed selector profile",
                ));
            }
            let mut selectors = BTreeMap::new();
            for (name, selector) in &subject.selectors {
                let location = format!("{path}.subjects[{role}].selectors[{name}]");
                let expected = definition.and_then(|entry| {
                    entry
                        .selector
                        .fields
                        .iter()
                        .find(|field| field.name() == name)
                });
                let resolved = match selector {
                    CommitEvidenceSelectorSource::Input { input } => {
                        inputs.get(input.as_str()).map(|field| {
                            (
                                CompiledCommitEvidenceSelector::Input {
                                    input: input.clone(),
                                },
                                &field.field_type,
                                field.required,
                                false,
                            )
                        })
                    }
                    CommitEvidenceSelectorSource::TargetField { input, field } => {
                        inputs.get(input.as_str()).and_then(|binding| {
                            if !binding.required {
                                return None;
                            }
                            let FieldTypeSource::Reference { target, .. } = &binding.field_type
                            else {
                                return None;
                            };
                            let selected = entities.get(target)?.fields.get(field)?;
                            if !selected.required || selected.encryption.is_some() {
                                return None;
                            }
                            remember_read(target_uses, target, input, field);
                            Some((
                                CompiledCommitEvidenceSelector::TargetField {
                                    input: input.clone(),
                                    field: field.clone(),
                                },
                                &selected.field_type,
                                selected.required,
                                selected.encryption.is_some(),
                            ))
                        })
                    }
                };
                let Some((selector, field_type, required, encrypted)) = resolved else {
                    errors.push(Diagnostic::error("breg.action.commit-evidence-selector-binding", &location, "bind a required Action input or unencrypted required field of a required reference input"));
                    continue;
                };
                if !required
                    || encrypted
                    || expected.is_none_or(|expected| {
                        !crate::action_evidence_contracts::selector_field_matches_field_type(
                            expected, field_type,
                        )
                    })
                {
                    errors.push(Diagnostic::error("breg.action.commit-evidence-selector-type", &location, "the binding must match the reviewed selector's exact scalar type and bounds"));
                    continue;
                }
                selectors.insert(name.clone(), selector);
            }
            subjects.insert(
                role.clone(),
                CompiledCommitEvidenceSubject {
                    profile: subject.profile.clone(),
                    selectors,
                },
            );
        }
        let mut requirements = Vec::new();
        for requirement in &source.requires {
            let expected = match (
                &requirement.equals,
                &requirement.equals_from_input,
                requirement.at_least,
                requirement.at_most,
            ) {
                (Some(value), None, None, None) => Some(CompiledCommitEvidenceExpected::Literal {
                    value: value.clone(),
                }),
                (None, Some(input), None, None)
                    if inputs.get(input.as_str()).is_some_and(|field| {
                        field.required
                            && crate::action_evidence_contracts::evidence_output_matches_field_type(
                                &capability,
                                &requirement.output,
                                &field.field_type,
                            )
                    }) =>
                {
                    Some(CompiledCommitEvidenceExpected::FromInput {
                        input: input.clone(),
                    })
                }
                (None, None, Some(value), None) => {
                    Some(CompiledCommitEvidenceExpected::AtLeast { value })
                }
                (None, None, None, Some(value)) => {
                    Some(CompiledCommitEvidenceExpected::AtMost { value })
                }
                _ => None,
            };
            let Some(expected) = expected else {
                errors.push(Diagnostic::error(
                    "breg.action.commit-evidence-predicate",
                    format!("{path}.requires[output={}]", requirement.output),
                    "require one typed scalar literal, required Action input, or integer threshold",
                ));
                continue;
            };
            requirements.push(CompiledCommitEvidenceRequirement {
                output: requirement.output.clone(),
                expected,
            });
        }
        compiled.push(CompiledCommitEvidence {
            capability,
            subjects,
            requires: requirements,
        });
    }
    compiled
}

fn remember_read(
    uses: &mut Vec<CompiledActionTargetUse>,
    entity_id: &str,
    input: &str,
    field: &str,
) {
    if let Some(existing) = uses.iter_mut().find(|entry| entry.operation == Operation::Get && entry.entity_id == entity_id && matches!(&entry.source, CompiledActionTargetUseSource::Input { input: binding } if binding == input)) {
        existing.fields.insert(field.to_owned());
    } else {
        uses.push(CompiledActionTargetUse { entity_id: entity_id.to_owned(), operation: Operation::Get, fields: BTreeSet::from([field.to_owned()]), source: CompiledActionTargetUseSource::Input { input: input.to_owned() }, condition_required: false });
    }
}
