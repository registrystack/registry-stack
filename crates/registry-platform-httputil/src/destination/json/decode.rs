// SPDX-License-Identifier: Apache-2.0
//! Sensitive runtime decoding and bounded scalar projection.
use std::fmt;
use std::mem;

use registry_platform_canonical_json::parse_json_strict;
use serde_json::Value;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::destination::{BoundedDestinationBody, DataDestination, DataDestinationBody};

use super::contract::{
    ClosedJsonDecoder, ClosedJsonSchema, ClosedJsonSchemaNode, CompiledPresenceProjection,
    CompiledRecordRoot, CompiledScalarProjection, ProjectionStep, ScalarContract,
};
use super::preflight::{preflight_json, JsonPreflightError};

pub(super) fn decode_body(
    decoder: &ClosedJsonDecoder,
    body: DataDestinationBody,
) -> Result<ClosedJsonOutcome, ClosedJsonDecodeError> {
    let BoundedDestinationBody { bytes, slot: _ } = body;
    preflight_json(
        bytes.as_slice(),
        decoder.preflight_token_limit,
        decoder.preflight_depth_limit,
    )
    .map_err(|error| match error {
        JsonPreflightError::InvalidJson => ClosedJsonDecodeError::InvalidJson,
        JsonPreflightError::ContractLimitExceeded => {
            ClosedJsonDecodeError::ResponseContractViolation
        }
    })?;
    let parsed =
        parse_json_strict(bytes.as_slice()).map_err(|_| ClosedJsonDecodeError::InvalidJson)?;
    drop(bytes);
    let sensitive = SensitiveJsonValue(parsed);
    let normalized = normalized_records(sensitive.value(), &decoder.root)?;
    validate_response_value(sensitive.value(), &decoder.schema)?;

    match normalized {
        NormalizedRecords::None => Ok(ClosedJsonOutcome::NoMatch),
        NormalizedRecords::Ambiguous => Ok(ClosedJsonOutcome::Ambiguous),
        NormalizedRecords::One(record) => {
            let mut fields =
                Vec::with_capacity(decoder.projections.len() + decoder.presence_projections.len());
            for projection in &decoder.projections {
                fields.push(project_field(record, projection)?);
            }
            for projection in &decoder.presence_projections {
                fields.push(project_presence(record, projection));
            }
            Ok(ClosedJsonOutcome::One(ProjectedJsonRecord {
                fields: fields.into_boxed_slice(),
            }))
        }
    }
}

/// Value-free failures while decoding one sensitive response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ClosedJsonDecodeError {
    #[error("destination response is not unambiguous strict JSON")]
    InvalidJson,
    #[error("destination response violates its closed JSON contract")]
    ResponseContractViolation,
    #[error("destination response exceeds the probe-two cardinality bound")]
    CardinalityViolation,
    #[error("destination response violates its scalar projection contract")]
    ProjectionContractViolation,
}
/// Cardinality plus the only projected record that may be published.
///
/// ```compile_fail
/// use registry_platform_httputil::destination::json::ClosedJsonOutcome;
///
/// fn raw_json_cannot_escape(outcome: ClosedJsonOutcome) {
///     let _ = outcome.into_json_value();
/// }
/// ```
#[must_use = "decoded cardinality and projections must be handled"]
pub enum ClosedJsonOutcome {
    NoMatch,
    One(ProjectedJsonRecord),
    Ambiguous,
}

impl fmt::Debug for ClosedJsonOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatch => formatter.write_str("ClosedJsonOutcome::NoMatch"),
            Self::One(record) => formatter
                .debug_tuple("ClosedJsonOutcome::One")
                .field(record)
                .finish(),
            Self::Ambiguous => formatter.write_str("ClosedJsonOutcome::Ambiguous"),
        }
    }
}

/// One record containing only reviewed scalar projections.
pub struct ProjectedJsonRecord {
    fields: Box<[ProjectedJsonField]>,
}

impl ProjectedJsonRecord {
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ProjectedJsonScalar> {
        self.fields
            .iter()
            .find(|field| field.name.as_ref() == name)
            .map(|field| &field.value)
    }

    pub fn fields(&self) -> impl ExactSizeIterator<Item = &ProjectedJsonField> {
        self.fields.iter()
    }

    #[must_use]
    pub fn into_fields(self) -> Box<[ProjectedJsonField]> {
        self.fields
    }
}

impl fmt::Debug for ProjectedJsonRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectedJsonRecord")
            .field("field_count", &self.fields.len())
            .field("fields", &"[REDACTED]")
            .finish()
    }
}

/// One declared projection name and bounded scalar value.
pub struct ProjectedJsonField {
    name: Box<str>,
    value: ProjectedJsonScalar,
}

impl ProjectedJsonField {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub const fn value(&self) -> &ProjectedJsonScalar {
        &self.value
    }

    #[must_use]
    pub fn into_parts(self) -> (Box<str>, ProjectedJsonScalar) {
        (self.name, self.value)
    }
}

impl fmt::Debug for ProjectedJsonField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectedJsonField")
            .field("name", &"[REDACTED]")
            .field("value", &self.value)
            .finish()
    }
}

/// One schema-validated scalar. Projected strings retain a zeroizing owner.
pub enum ProjectedJsonScalar {
    Null,
    String(Zeroizing<String>),
    Boolean(bool),
    Integer(i64),
    Number(f64),
}

impl fmt::Debug for ProjectedJsonScalar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Null => "null",
            Self::String(_) => "string",
            Self::Boolean(_) => "boolean",
            Self::Integer(_) => "integer",
            Self::Number(_) => "number",
        };
        formatter
            .debug_struct("ProjectedJsonScalar")
            .field("kind", &kind)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

fn validate_response_value(
    value: &Value,
    schema: &ClosedJsonSchema,
) -> Result<(), ClosedJsonDecodeError> {
    if value.is_null() {
        return schema
            .nullable()
            .then_some(())
            .ok_or(ClosedJsonDecodeError::ResponseContractViolation);
    }
    match (&schema.node, value) {
        (ClosedJsonSchemaNode::Object { fields, .. }, Value::Object(object)) => {
            if object
                .keys()
                .any(|name| !fields.iter().any(|field| field.name.as_ref() == name))
                || fields
                    .iter()
                    .any(|field| field.required && !object.contains_key(field.name.as_ref()))
            {
                return Err(ClosedJsonDecodeError::ResponseContractViolation);
            }
            for (name, member) in object {
                let field = fields
                    .iter()
                    .find(|field| field.name.as_ref() == name)
                    .ok_or(ClosedJsonDecodeError::ResponseContractViolation)?;
                validate_response_value(member, &field.schema)?;
            }
            Ok(())
        }
        (
            ClosedJsonSchemaNode::Array {
                max_items, items, ..
            },
            Value::Array(values),
        ) if values.len() <= usize::from(*max_items) => {
            for item in values {
                validate_response_value(item, items)?;
            }
            Ok(())
        }
        (ClosedJsonSchemaNode::String { max_bytes, .. }, Value::String(value))
            if value.len() <= *max_bytes as usize =>
        {
            Ok(())
        }
        (ClosedJsonSchemaNode::Boolean { .. }, Value::Bool(_)) => Ok(()),
        (
            ClosedJsonSchemaNode::Integer {
                minimum, maximum, ..
            },
            Value::Number(value),
        ) => exact_i64(value)
            .filter(|integer| integer >= minimum && integer <= maximum)
            .map(|_| ())
            .ok_or(ClosedJsonDecodeError::ResponseContractViolation),
        (
            ClosedJsonSchemaNode::Number {
                minimum, maximum, ..
            },
            Value::Number(value),
        ) => value
            .as_f64()
            .filter(|number| number.is_finite())
            .filter(|number| *number >= *minimum as f64 && *number <= *maximum as f64)
            .map(|_| ())
            .ok_or(ClosedJsonDecodeError::ResponseContractViolation),
        _ => Err(ClosedJsonDecodeError::ResponseContractViolation),
    }
}

fn exact_i64(value: &serde_json::Number) -> Option<i64> {
    value.as_i64().or_else(|| {
        value
            .as_u64()
            .and_then(|integer| i64::try_from(integer).ok())
    })
}

enum NormalizedRecords<'value> {
    None,
    One(&'value Value),
    Ambiguous,
}

fn normalized_records<'value>(
    value: &'value Value,
    root: &CompiledRecordRoot,
) -> Result<NormalizedRecords<'value>, ClosedJsonDecodeError> {
    let records = match root {
        CompiledRecordRoot::Object => return Ok(NormalizedRecords::One(value)),
        CompiledRecordRoot::ArrayProbeTwo => value.as_array(),
        CompiledRecordRoot::ObjectArrayProbeTwo { field } => value
            .as_object()
            .and_then(|object| object.get(field.as_ref()))
            .and_then(Value::as_array),
    }
    .ok_or(ClosedJsonDecodeError::ResponseContractViolation)?;
    match records.as_slice() {
        [] => Ok(NormalizedRecords::None),
        [record] => Ok(NormalizedRecords::One(record)),
        [_, _] => Ok(NormalizedRecords::Ambiguous),
        _ => Err(ClosedJsonDecodeError::CardinalityViolation),
    }
}

fn project_field(
    record: &Value,
    projection: &CompiledScalarProjection,
) -> Result<ProjectedJsonField, ClosedJsonDecodeError> {
    let mut current = record;
    for step in &projection.steps {
        let next = match step {
            ProjectionStep::Object(name) => current
                .as_object()
                .and_then(|object| object.get(name.as_ref())),
            ProjectionStep::Array(index) => current.as_array().and_then(|array| array.get(*index)),
        };
        let Some(next) = next else {
            return projection
                .scalar
                .nullable()
                .then(|| ProjectedJsonField {
                    name: projection.name.clone(),
                    value: ProjectedJsonScalar::Null,
                })
                .ok_or(ClosedJsonDecodeError::ProjectionContractViolation);
        };
        current = next;
    }
    let value = project_scalar(current, projection.scalar)?;
    Ok(ProjectedJsonField {
        name: projection.name.clone(),
        value,
    })
}

fn project_presence(record: &Value, projection: &CompiledPresenceProjection) -> ProjectedJsonField {
    let mut current = Some(record);
    for step in &projection.steps {
        current = current.and_then(|value| match step {
            ProjectionStep::Object(name) => value
                .as_object()
                .and_then(|object| object.get(name.as_ref())),
            ProjectionStep::Array(index) => value.as_array().and_then(|array| array.get(*index)),
        });
    }
    ProjectedJsonField {
        name: projection.name.clone(),
        value: ProjectedJsonScalar::Boolean(current.is_some_and(|value| !value.is_null())),
    }
}

fn project_scalar(
    value: &Value,
    contract: ScalarContract,
) -> Result<ProjectedJsonScalar, ClosedJsonDecodeError> {
    if value.is_null() {
        let nullable = match contract {
            ScalarContract::String { nullable, .. }
            | ScalarContract::Boolean { nullable }
            | ScalarContract::Integer { nullable, .. }
            | ScalarContract::Number { nullable, .. } => nullable,
        };
        return nullable
            .then_some(ProjectedJsonScalar::Null)
            .ok_or(ClosedJsonDecodeError::ProjectionContractViolation);
    }
    match (contract, value) {
        (ScalarContract::String { max_bytes, .. }, Value::String(value))
            if value.len() <= max_bytes as usize =>
        {
            Ok(ProjectedJsonScalar::String(Zeroizing::new(
                value.to_owned(),
            )))
        }
        (ScalarContract::Boolean { .. }, Value::Bool(value)) => {
            Ok(ProjectedJsonScalar::Boolean(*value))
        }
        (
            ScalarContract::Integer {
                minimum, maximum, ..
            },
            Value::Number(value),
        ) => exact_i64(value)
            .filter(|integer| *integer >= minimum && *integer <= maximum)
            .map(ProjectedJsonScalar::Integer)
            .ok_or(ClosedJsonDecodeError::ProjectionContractViolation),
        (
            ScalarContract::Number {
                minimum, maximum, ..
            },
            Value::Number(value),
        ) => value
            .as_f64()
            .filter(|number| number.is_finite())
            .filter(|number| *number >= minimum as f64 && *number <= maximum as f64)
            .map(ProjectedJsonScalar::Number)
            .ok_or(ClosedJsonDecodeError::ProjectionContractViolation),
        _ => Err(ClosedJsonDecodeError::ProjectionContractViolation),
    }
}

/// Guard that scrubs successful parse-tree string values and member names
/// before their allocations are released.
struct SensitiveJsonValue(Value);

impl SensitiveJsonValue {
    fn value(&self) -> &Value {
        &self.0
    }
}

impl Drop for SensitiveJsonValue {
    fn drop(&mut self) {
        zeroize_json_value(&mut self.0);
    }
}

pub(super) fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(string) => string.zeroize(),
        Value::Array(array) => array.iter_mut().for_each(zeroize_json_value),
        Value::Object(object) => {
            let retained = mem::take(object);
            for (mut name, mut member) in retained {
                name.zeroize();
                zeroize_json_value(&mut member);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

// Keep the slot marker part of this module's concrete type boundary. This
// assertion also prevents an accidental generic body decoder refactor.
const _: fn(BoundedDestinationBody<DataDestination>) = |_: DataDestinationBody| {};
