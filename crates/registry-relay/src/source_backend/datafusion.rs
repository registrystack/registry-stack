// SPDX-License-Identifier: Apache-2.0
//! Dedicated bounded DataFusion executor for SnapshotExact.

use std::collections::BTreeSet;
use std::sync::Arc;

use ::datafusion::execution::context::SessionContext;
use serde_json::{Map, Value};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::time::Instant;

use crate::consultation::ConsultationOutcome;
use crate::query::{read_snapshot_exact_and, SnapshotExactPredicate, SnapshotExactProjection};
use crate::source_plan::{
    CompiledResponseSchema, CompiledScalarShape, CompiledSourcePlan, SourceCardinality,
    SourcePlanKind,
};

use super::PublishedSnapshotHandle;

/// One closed, schema-validated snapshot row. The selector and physical field
/// names have already been discarded.
pub(crate) struct SnapshotExactRecord {
    fields: Map<String, Value>,
}

impl SnapshotExactRecord {
    pub(crate) const fn fields(&self) -> &Map<String, Value> {
        &self.fields
    }
}

/// Decoder-issued pairing of the public outcome, optional closed row, and the
/// exact immutable snapshot handle used by the query.
pub(crate) struct SnapshotExactBackendResult {
    outcome: ConsultationOutcome,
    record: Option<SnapshotExactRecord>,
    snapshot: Arc<PublishedSnapshotHandle>,
    source_observed_at_unix_ms: Option<i64>,
    source_revision: Option<Box<str>>,
}

impl SnapshotExactBackendResult {
    pub(crate) const fn outcome(&self) -> ConsultationOutcome {
        self.outcome
    }

    pub(crate) const fn record(&self) -> Option<&SnapshotExactRecord> {
        self.record.as_ref()
    }

    pub(crate) fn snapshot(&self) -> &PublishedSnapshotHandle {
        &self.snapshot
    }

    pub(crate) const fn source_observed_at_unix_ms(&self) -> Option<i64> {
        self.source_observed_at_unix_ms
    }

    pub(crate) fn source_revision(&self) -> Option<&str> {
        self.source_revision.as_deref()
    }
}

/// Execute the exact local lookup using only the compiler-owned mapping.
pub(crate) async fn execute_snapshot_exact(
    ctx: &SessionContext,
    plan: &CompiledSourcePlan,
    snapshot: Arc<PublishedSnapshotHandle>,
    canonical_inputs: &[&str],
    deadline: Instant,
) -> Result<SnapshotExactBackendResult, SnapshotExactBackendError> {
    if plan.kind() != SourcePlanKind::SnapshotExact {
        return Err(SnapshotExactBackendError::InvalidPlan);
    }
    let binding = plan
        .snapshot_binding()
        .ok_or(SnapshotExactBackendError::InvalidPlan)?;
    let projection = binding
        .projection()
        .map(|(logical, physical)| SnapshotExactProjection::new(physical, logical))
        .collect::<Vec<_>>();
    if canonical_inputs.len() != binding.keys().len() {
        return Err(SnapshotExactBackendError::InvalidPlan);
    }
    let predicates = binding
        .keys()
        .zip(canonical_inputs.iter().copied())
        .map(
            |((_input, physical_field), canonical_value)| SnapshotExactPredicate {
                physical_field,
                canonical_value,
            },
        )
        .collect::<Vec<_>>();
    let probe_limit = match plan.cardinality() {
        SourceCardinality::Singleton => 1,
        SourceCardinality::AmbiguityProbe => 2,
    };
    let rows = read_snapshot_exact_and(
        ctx,
        snapshot.provider(),
        &predicates,
        &projection,
        probe_limit,
        deadline,
    )
    .await
    .map_err(|_| SnapshotExactBackendError::Unavailable)?
    .into_rows();

    let (outcome, record, source_observed_at_unix_ms, source_revision) =
        decode_snapshot_rows(plan, rows)?;
    Ok(SnapshotExactBackendResult {
        outcome,
        record,
        snapshot,
        source_observed_at_unix_ms,
        source_revision,
    })
}

pub(crate) type DecodedSnapshotRows = (
    ConsultationOutcome,
    Option<SnapshotExactRecord>,
    Option<i64>,
    Option<Box<str>>,
);

pub(crate) fn decode_snapshot_rows(
    plan: &CompiledSourcePlan,
    rows: Vec<Value>,
) -> Result<DecodedSnapshotRows, SnapshotExactBackendError> {
    let binding = plan
        .snapshot_binding()
        .ok_or(SnapshotExactBackendError::InvalidPlan)?;
    let outcome = match rows.len() {
        0 => ConsultationOutcome::NoMatch,
        1 => ConsultationOutcome::Match,
        _ if plan.cardinality() == SourceCardinality::AmbiguityProbe => {
            ConsultationOutcome::Ambiguous
        }
        _ => return Err(SnapshotExactBackendError::CardinalityViolation),
    };
    plan.footprint()
        .validate_outcome(outcome)
        .map_err(|_| SnapshotExactBackendError::CardinalityViolation)?;
    let (record, source_observed_at_unix_ms, source_revision) =
        match (outcome, rows.into_iter().next()) {
            (ConsultationOutcome::Match, Some(Value::Object(row))) => {
                validate_closed_row(plan, &row)?;
                let source_observed_at_unix_ms = extract_source_observed_at(binding, &row)?;
                let source_revision = extract_source_revision(binding, &row)?;
                (
                    Some(SnapshotExactRecord { fields: row }),
                    source_observed_at_unix_ms,
                    source_revision,
                )
            }
            (ConsultationOutcome::NoMatch | ConsultationOutcome::Ambiguous, _) => {
                (None, None, None)
            }
            _ => return Err(SnapshotExactBackendError::ResponseContractViolation),
        };
    Ok((outcome, record, source_observed_at_unix_ms, source_revision))
}

fn extract_source_observed_at(
    binding: &crate::source_plan::CompiledSnapshotBinding,
    row: &Map<String, Value>,
) -> Result<Option<i64>, SnapshotExactBackendError> {
    let Some((logical, _physical)) = binding.source_observed_at_extraction() else {
        return Ok(None);
    };
    let value = row
        .get(logical)
        .and_then(Value::as_str)
        .ok_or(SnapshotExactBackendError::ResponseContractViolation)?;
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| SnapshotExactBackendError::ResponseContractViolation)?;
    let unix_ms = parsed
        .unix_timestamp_nanos()
        .checked_div(1_000_000)
        .and_then(|value| i64::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(SnapshotExactBackendError::ResponseContractViolation)?;
    Ok(Some(unix_ms))
}

fn extract_source_revision(
    binding: &crate::source_plan::CompiledSnapshotBinding,
    row: &Map<String, Value>,
) -> Result<Option<Box<str>>, SnapshotExactBackendError> {
    let Some((logical, _physical, max_bytes)) = binding.source_revision_extraction() else {
        return Ok(None);
    };
    let value = row
        .get(logical)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= usize::from(max_bytes))
        .ok_or(SnapshotExactBackendError::ResponseContractViolation)?;
    Ok(Some(value.into()))
}

fn validate_closed_row(
    plan: &CompiledSourcePlan,
    row: &Map<String, Value>,
) -> Result<(), SnapshotExactBackendError> {
    let profile = plan.runtime_profile();
    let expected = profile
        .acquisition()
        .fields()
        .map(|field| field.name())
        .collect::<BTreeSet<_>>();
    let actual = row.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(SnapshotExactBackendError::ResponseContractViolation);
    }
    for field in profile.acquisition().fields() {
        let value = row
            .get(field.name())
            .ok_or(SnapshotExactBackendError::ResponseContractViolation)?;
        if !validates_snapshot_value(field.schema(), value) {
            return Err(SnapshotExactBackendError::ResponseContractViolation);
        }
    }
    Ok(())
}

fn validates_snapshot_value(schema: &CompiledResponseSchema, value: &Value) -> bool {
    if value.is_null() {
        return schema.nullable();
    }
    match (schema, value) {
        (
            CompiledResponseSchema::Scalar(CompiledScalarShape::String { max_bytes, .. }),
            Value::String(value),
        ) => usize::try_from(*max_bytes).is_ok_and(|limit| value.len() <= limit),
        (CompiledResponseSchema::Scalar(CompiledScalarShape::Boolean { .. }), Value::Bool(_)) => {
            true
        }
        (
            CompiledResponseSchema::Scalar(CompiledScalarShape::Integer {
                minimum, maximum, ..
            }),
            Value::Number(value),
        ) => value
            .as_i64()
            .is_some_and(|value| (*minimum..=*maximum).contains(&value)),
        (
            CompiledResponseSchema::Scalar(CompiledScalarShape::Number {
                minimum, maximum, ..
            }),
            Value::Number(value),
        ) => value.as_f64().is_some_and(|value| {
            value.is_finite() && value >= *minimum as f64 && value <= *maximum as f64
        }),
        (
            CompiledResponseSchema::Array {
                max_items, items, ..
            },
            Value::Array(values),
        ) => {
            values.len() <= usize::from(*max_items)
                && values
                    .iter()
                    .all(|value| validates_snapshot_value(items, value))
        }
        (CompiledResponseSchema::Object { fields, .. }, Value::Object(values)) => {
            values.len() <= fields.len()
                && values
                    .keys()
                    .all(|name| fields.iter().any(|field| field.name() == name.as_str()))
                && fields.iter().all(|field| match values.get(field.name()) {
                    Some(value) => validates_snapshot_value(field.schema(), value),
                    None => !field.required(),
                })
        }
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum SnapshotExactBackendError {
    #[error("snapshot exact plan is invalid")]
    InvalidPlan,
    #[error("snapshot exact provider is unavailable")]
    Unavailable,
    #[error("snapshot exact cardinality contract was violated")]
    CardinalityViolation,
    #[error("snapshot exact row violated the closed response contract")]
    ResponseContractViolation,
}
