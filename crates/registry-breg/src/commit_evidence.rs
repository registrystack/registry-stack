// SPDX-License-Identifier: Apache-2.0
//! Guard-only Evidence binding shared by both commit controllers.

use crate::action_evidence_client::{EvidenceSubjects, VerifiedAcquisition};
use crate::action_evidence_contracts::CompiledEvidenceCapability;
use crate::model::{
    CompiledCommitEvidence, CompiledCommitEvidenceExpected, CompiledCommitEvidenceSelector,
};
use crate::mutation::MutationError;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// The caller supplies only rows admitted and locked by its target authority,
/// keyed by logical reference input. No record values enter the plan evaluator.
pub(crate) fn requests(
    guards: &[CompiledCommitEvidence],
    inputs: &Map<String, Value>,
    records: &BTreeMap<String, Map<String, Value>>,
) -> Result<Vec<(CompiledEvidenceCapability, EvidenceSubjects)>, MutationError> {
    guards
        .iter()
        .map(|guard| {
            let subjects = guard
                .subjects
                .iter()
                .map(|(role, subject)| {
                    let values = subject
                        .selectors
                        .iter()
                        .map(|(name, selector)| {
                            let value = match selector {
                                CompiledCommitEvidenceSelector::Input { input } => {
                                    inputs.get(input)
                                }
                                CompiledCommitEvidenceSelector::TargetField { input, field } => {
                                    records.get(input).and_then(|row| row.get(field))
                                }
                            }
                            .ok_or(MutationError::PreconditionFailed)?;
                            Ok((name.clone(), value.clone()))
                        })
                        .collect::<Result<BTreeMap<_, _>, MutationError>>()?;
                    Ok((role.clone(), values))
                })
                .collect::<Result<EvidenceSubjects, MutationError>>()?;
            crate::action_evidence_validation::validate_call_arguments(
                &guard.capability,
                &subjects,
            )
            .map_err(MutationError::from)?;
            Ok((guard.capability.clone(), subjects))
        })
        .collect()
}

pub(crate) fn target_fields(
    guards: &[CompiledCommitEvidence],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut fields = BTreeMap::<String, BTreeSet<String>>::new();
    for selector in guards
        .iter()
        .flat_map(|guard| guard.subjects.values())
        .flat_map(|subject| subject.selectors.values())
    {
        if let CompiledCommitEvidenceSelector::TargetField { input, field } = selector {
            fields
                .entry(input.clone())
                .or_default()
                .insert(field.clone());
        }
    }
    fields
}

/// Verify identity, current signed validity, observation age, and every frozen
/// predicate. Outputs only admit or refuse the already frozen effects.
pub(crate) fn verify(
    guards: &[CompiledCommitEvidence],
    inputs: &Map<String, Value>,
    is_timestamp: impl Fn(&str) -> bool,
    acquisitions: &[VerifiedAcquisition],
) -> Result<(), MutationError> {
    if acquisitions.len() != guards.len() {
        return Err(MutationError::PreconditionFailed);
    }
    let now = chrono::Utc::now();
    for (guard, acquisition) in guards.iter().zip(acquisitions) {
        if acquisition.capability_id() != guard.capability.id
            || acquisition.contract_fingerprint() != guard.capability.contract_fingerprint
        {
            return Err(MutationError::PreconditionFailed);
        }
        acquisition
            .validate_acceptance(now)
            .map_err(MutationError::from)?;
        crate::action_evidence_validation::validate_selected_outputs(
            &guard.capability,
            acquisition.outputs(),
        )
        .map_err(MutationError::from)?;
        for requirement in &guard.requires {
            let actual = acquisition.outputs().get(&requirement.output);
            let accepted = match &requirement.expected {
                CompiledCommitEvidenceExpected::Literal { value } => actual == Some(value),
                CompiledCommitEvidenceExpected::FromInput { input } => actual
                    .zip(inputs.get(input))
                    .is_some_and(|(actual, expected)| {
                        crate::commit_guard::predicate_values_equal(
                            actual,
                            expected,
                            is_timestamp(input),
                        )
                    }),
                CompiledCommitEvidenceExpected::AtLeast { value } => actual
                    .and_then(Value::as_i64)
                    .is_some_and(|actual| actual >= *value),
                CompiledCommitEvidenceExpected::AtMost { value } => actual
                    .and_then(Value::as_i64)
                    .is_some_and(|actual| actual <= *value),
            };
            if !accepted {
                return Err(MutationError::PreconditionFailed);
            }
        }
    }
    Ok(())
}
