//! Side-effect-free validation shared by Evidence action runtime and fixtures.
use crate::action_evidence_contracts::CompiledEvidenceCapability;
use chrono::NaiveDate;
use registry_evidence_client::{
    definitions::{SelectorField, SelectorValueOrigin},
    SelectorValue, SubjectRequest,
};
use serde_json::Value;
use std::collections::BTreeMap;
pub type EvidenceSubjects = BTreeMap<String, BTreeMap<String, Value>>;
/// Static categories only: provider problems and computed selector values never
/// become action diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceAcquisitionFailure {
    #[error("Evidence arguments do not satisfy the declared capability")]
    InvalidArguments,
    #[error("Evidence is unavailable")]
    Unavailable,
    #[error("Evidence verification failed")]
    Verification,
    #[error("Evidence is outside the accepted observation age")]
    Expired,
    #[error("Evidence evaluation was cancelled or its deadline expired")]
    Cancelled,
    #[error("Evidence evaluation exceeded its retained byte budget")]
    BudgetExceeded,
    #[error("Evidence provider binding is unusable")]
    Configuration,
}

pub(crate) fn validate_subjects(
    capability: &CompiledEvidenceCapability,
    values: &EvidenceSubjects,
) -> Result<Vec<SubjectRequest>, EvidenceAcquisitionFailure> {
    let definitions = &capability.definition.subjects;
    if values.len() != definitions.len() {
        return Err(EvidenceAcquisitionFailure::InvalidArguments);
    }
    definitions
        .iter()
        .map(|definition| {
            let selector = &definition.selector;
            let fields = values
                .get(&definition.role)
                .ok_or(EvidenceAcquisitionFailure::InvalidArguments)?;
            if selector.value_origin != SelectorValueOrigin::Request
                || fields.len() != selector.fields.len()
            {
                return Err(EvidenceAcquisitionFailure::InvalidArguments);
            }
            let selector_values = selector
                .fields
                .iter()
                .map(|field| {
                    let value = fields
                        .get(field.name())
                        .ok_or(EvidenceAcquisitionFailure::InvalidArguments)?;
                    let value = validate_selector_field(field, value)?;
                    Ok((field.name().to_owned(), value))
                })
                .collect::<Result<Vec<_>, EvidenceAcquisitionFailure>>()?;
            Ok(SubjectRequest {
                role: definition.role.clone(),
                selector_profile: selector.profile.clone(),
                selector_values: Some(selector_values),
            })
        })
        .collect()
}

/// Apply the same request-origin checks to the offline authored fixture seam.
pub fn validate_call_arguments(
    capability: &CompiledEvidenceCapability,
    subjects: &EvidenceSubjects,
) -> Result<(), EvidenceAcquisitionFailure> {
    validate_subjects(capability, subjects).map(|_| ())
}

/// Validate only the selected typed output map used by authored fixtures.
/// This does not turn fixture values into verified Evidence acquisitions.
pub fn validate_selected_outputs(
    capability: &CompiledEvidenceCapability,
    outputs: &BTreeMap<String, Value>,
) -> Result<(), EvidenceAcquisitionFailure> {
    use registry_evidence_client::{
        definitions::{ConceptForm, DefinitionConceptForm},
        BucketForm, PublicValue,
    };
    if outputs
        .keys()
        .any(|handle| !capability.outputs.contains(handle))
    {
        return Err(EvidenceAcquisitionFailure::Verification);
    }
    for handle in &capability.outputs {
        let concept = capability
            .definition
            .concepts
            .iter()
            .find(|concept| &concept.handle == handle)
            .ok_or(EvidenceAcquisitionFailure::Configuration)?;
        let Some(value) = outputs.get(handle) else {
            if concept.required {
                return Err(EvidenceAcquisitionFailure::Verification);
            }
            continue;
        };
        let value: PublicValue = serde_json::from_value(value.clone())
            .map_err(|_| EvidenceAcquisitionFailure::Verification)?;
        let valid = match (&concept.form, value) {
            (DefinitionConceptForm::Scalar(ConceptForm::Boolean), PublicValue::Boolean(_))
            | (DefinitionConceptForm::Scalar(ConceptForm::Integer), PublicValue::Integer(_))
            | (DefinitionConceptForm::Scalar(ConceptForm::String), PublicValue::String(_))
            | (
                DefinitionConceptForm::Scalar(ConceptForm::EntityReference),
                PublicValue::EntityReference(_),
            )
            | (
                DefinitionConceptForm::Scalar(ConceptForm::Structured),
                PublicValue::Structured(_),
            ) => true,
            (
                DefinitionConceptForm::Scalar(ConceptForm::DateBucket),
                PublicValue::Bucket(value),
            ) => value.form == BucketForm::DateBucket,
            (
                DefinitionConceptForm::Scalar(ConceptForm::TimeBucket),
                PublicValue::Bucket(value),
            ) => value.form == BucketForm::TimeBucket,
            _ => false,
        };
        if !valid {
            return Err(EvidenceAcquisitionFailure::Verification);
        }
    }
    Ok(())
}

pub(crate) fn validate_selector_field(
    field: &SelectorField,
    value: &Value,
) -> Result<SelectorValue, EvidenceAcquisitionFailure> {
    let accepted = match (field, value) {
        (
            SelectorField::String {
                minimum_bytes,
                maximum_bytes,
                ..
            },
            Value::String(value),
        ) if (*minimum_bytes..=*maximum_bytes).contains(&(value.len() as u64)) => {
            Some(SelectorValue::String(value.clone()))
        }
        (SelectorField::ControlledCode { maximum_bytes, .. }, Value::String(value))
            if !value.is_empty() && value.len() as u64 <= *maximum_bytes =>
        {
            Some(SelectorValue::String(value.clone()))
        }
        (SelectorField::Date { .. }, Value::String(value))
            if value.len() == 10 && NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok() =>
        {
            Some(SelectorValue::String(value.clone()))
        }
        (
            SelectorField::Integer {
                minimum, maximum, ..
            },
            Value::Number(value),
        ) => value
            .as_i64()
            .filter(|value| (*minimum..=*maximum).contains(value))
            .map(SelectorValue::Integer),
        (SelectorField::Boolean { .. }, Value::Bool(value)) => Some(SelectorValue::Boolean(*value)),
        _ => None,
    };
    accepted.ok_or(EvidenceAcquisitionFailure::InvalidArguments)
}
