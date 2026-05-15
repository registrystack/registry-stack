// SPDX-License-Identifier: Apache-2.0
//! Schema validation: declared vs observed.
//!
//! Implements every row of the rule table in `decisions/wave-1.md` §4.
//! Public surface:
//! - [`validate`]: returns a [`ProjectionPlan`] on accept,
//!   [`IngestError`] on hard fail. Logs a structured `tracing::error!`
//!   on every hard fail and on every `strict_extra_column` rejection,
//!   carrying the declared/observed/diff fields and the dataset/resource
//!   ids so operators can correlate the failure.
//! - [`ProjectionPlan::apply`]: project + cast an Arrow `RecordBatch`
//!   to the declared schema's column order and Arrow types. Idempotent.
//!
//! `IngestError` is the existing Wave 0 enum (`src/error.rs`). No new
//! variants are needed: the diff payload is emitted via `tracing` here
//! so the operational log is complete, and the error stays opaque for
//! `/ready` rendering (Spec §13 scrubbing).

use std::sync::Arc;

use datafusion::arrow::array::{Array, RecordBatch};
use datafusion::arrow::compute::cast;
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime};
use tracing::{error, warn};

use crate::config::{DatasetId, FieldType, ResourceId};
use crate::error::IngestError;
use crate::ingest::declared_schema::{declared_type_to_arrow, DeclaredSchema};

/// Per-column instruction for [`ProjectionPlan::apply`]. One entry per
/// declared field, in declared order; carries the index into the
/// observed schema so projection is a direct lookup.
#[derive(Clone, Debug)]
struct ColumnPlan {
    /// Position of this column in the observed `RecordBatch`.
    observed_index: usize,
    /// Target Arrow type the apply step casts to (matches the declared
    /// type via [`declared_type_to_arrow`]).
    target_type: DataType,
    /// Name of the output field (always the declared name, even if the
    /// observed column carried it positionally).
    name: String,
}

/// Plan produced by [`validate`] and consumed by Track 6's pipeline.
///
/// Opaque to callers; the only behaviour they need is
/// [`ProjectionPlan::apply`] to project + cast a decoded `RecordBatch`
/// into the declared shape before writing it to the Parquet cache.
///
/// `apply` is idempotent: running it twice on the same batch yields a
/// batch equal to running it once (declared shape is a fixed point of
/// the cast operations).
#[derive(Clone, Debug)]
pub struct ProjectionPlan {
    plan: Vec<ColumnPlan>,
    output_schema: SchemaRef,
}

impl ProjectionPlan {
    /// Project and cast `batch` into the declared schema's column order
    /// and types.
    ///
    /// Returns `IngestError::SchemaMismatch` if any cast fails at this
    /// stage. In practice, validate-time checks should catch uncastable
    /// combinations before `apply` runs, so a failure here means the
    /// batch contents (not its schema) refused the cast.
    pub fn apply(&self, batch: &RecordBatch) -> Result<RecordBatch, IngestError> {
        let mut columns: Vec<Arc<dyn Array>> = Vec::with_capacity(self.plan.len());
        for col in &self.plan {
            let src = batch.column(col.observed_index);
            let casted = if src.data_type() == &col.target_type {
                src.clone()
            } else {
                cast(src.as_ref(), &col.target_type).map_err(|e| {
                    error!(
                        event = "ingest.schema_mismatch",
                        reason = "cast_failed_at_apply",
                        column = %col.name,
                        from_type = ?src.data_type(),
                        to_type = ?col.target_type,
                        error = %e,
                    );
                    IngestError::SchemaMismatch
                })?
            };
            columns.push(casted);
        }
        RecordBatch::try_new(self.output_schema.clone(), columns).map_err(|e| {
            error!(
                event = "ingest.schema_mismatch",
                reason = "record_batch_construction_failed",
                error = %e,
            );
            IngestError::SchemaMismatch
        })
    }

    /// Arrow schema of the output batches. Useful to Track 6 when it
    /// builds the Parquet writer's expected schema.
    pub fn output_schema(&self) -> SchemaRef {
        self.output_schema.clone()
    }
}

/// Validate `observed` against `declared` and produce a
/// [`ProjectionPlan`] that turns one into the other.
///
/// `sample_rows` enables the sample-mode checks (null-in-non-nullable,
/// primary-key uniqueness, RFC 3339 parseability for string-encoded
/// date/timestamp columns). When `None`, those checks are skipped
/// (cheap-mode; used by Track 6 to validate the schema shape before
/// running the full decode pipeline).
///
/// On accept, logs nothing at error level; `strict: false` extra
/// columns are logged at `warn` level only. On hard fail, logs a
/// `tracing::error!` with the diff payload and returns the appropriate
/// [`IngestError`] variant. The error carries no diff; Track 6 already
/// has the dataset/resource ids in scope when it consumes the result.
#[allow(clippy::too_many_lines)]
pub fn validate(
    dataset_id: &DatasetId,
    resource_id: &ResourceId,
    declared: &DeclaredSchema,
    observed: &Schema,
    primary_key: Option<&str>,
    sample_rows: Option<&RecordBatch>,
) -> Result<ProjectionPlan, IngestError> {
    let declared_names: Vec<&str> = declared.fields.iter().map(|f| f.name.as_str()).collect();
    let observed_names: Vec<&str> = observed
        .fields()
        .iter()
        .map(|f| f.name().as_str())
        .collect();

    // ── Rule: declared column missing from observed ──────────────────
    let missing: Vec<String> = declared_names
        .iter()
        .filter(|n| !observed_names.iter().any(|o| o == *n))
        .map(|s| s.to_string())
        .collect();
    if !missing.is_empty() {
        log_schema_mismatch(
            dataset_id,
            resource_id,
            declared,
            observed,
            missing.iter().map(|m| format!("missing: {m}")).collect(),
        );
        return Err(IngestError::SchemaMismatch);
    }

    // ── Rule: observed column not in declared (strict / lax) ─────────
    let extras: Vec<String> = observed_names
        .iter()
        .filter(|o| !declared_names.iter().any(|d| d == *o))
        .map(|s| s.to_string())
        .collect();
    if !extras.is_empty() {
        if declared.strict {
            error!(
                event = "ingest.strict_extra_column",
                dataset_id = %dataset_id,
                resource_id = %resource_id,
                declared = ?summarise_fields_declared(declared),
                observed = ?summarise_fields_arrow(observed),
                diff = ?extras
                    .iter()
                    .map(|e| format!("extra: {e}"))
                    .collect::<Vec<_>>(),
            );
            return Err(IngestError::StrictExtraColumn);
        } else {
            // Lax: log a warn, drop the column from the projection.
            warn!(
                event = "ingest.extra_column_dropped",
                dataset_id = %dataset_id,
                resource_id = %resource_id,
                extras = ?extras,
            );
        }
    }

    // ── Rule: primary_key field present in declared+observed ─────────
    if let Some(pk) = primary_key {
        if !declared_names.iter().any(|n| n == &pk) {
            log_schema_mismatch(
                dataset_id,
                resource_id,
                declared,
                observed,
                vec![format!("primary_key_missing_from_declared: {pk}")],
            );
            return Err(IngestError::SchemaMismatch);
        }
        if !observed_names.iter().any(|n| n == &pk) {
            log_schema_mismatch(
                dataset_id,
                resource_id,
                declared,
                observed,
                vec![format!("primary_key_missing_from_observed: {pk}")],
            );
            return Err(IngestError::SchemaMismatch);
        }
    }

    // ── Rule: per-column type compatibility + cast plan ──────────────
    let mut plan: Vec<ColumnPlan> = Vec::with_capacity(declared.fields.len());
    let mut output_fields: Vec<Field> = Vec::with_capacity(declared.fields.len());
    for dfield in &declared.fields {
        // Safe to unwrap: we already proved every declared name exists
        // in observed above.
        let (obs_idx, obs_field) = observed
            .fields()
            .iter()
            .enumerate()
            .find(|(_, f)| f.name() == &dfield.name)
            .map(|(i, f)| (i, f.as_ref()))
            .expect("declared name was proven to exist in observed");

        let target = declared_type_to_arrow(dfield.ty);
        match type_compatibility(dfield.ty, obs_field.data_type()) {
            TypeCheck::Ok => {}
            TypeCheck::NeedsSampleParse => {
                // RFC 3339 / ISO-8601 parse: cheap-mode skips, sample-mode
                // parses each non-null row.
                if let Some(batch) = sample_rows {
                    let col = batch.column(obs_idx);
                    if let Err(diff) =
                        parse_string_like_array(col.as_ref(), dfield.ty, &dfield.name)
                    {
                        log_schema_mismatch(
                            dataset_id,
                            resource_id,
                            declared,
                            observed,
                            vec![diff],
                        );
                        return Err(IngestError::SchemaMismatch);
                    }
                }
                // Cheap-mode: accept the Utf8 column; the decoder is
                // expected to coerce to the target type at decode time.
            }
            TypeCheck::Fail => {
                log_schema_mismatch(
                    dataset_id,
                    resource_id,
                    declared,
                    observed,
                    vec![format!(
                        "type_mismatch: {} (declared {:?}, observed {:?})",
                        dfield.name,
                        dfield.ty,
                        obs_field.data_type()
                    )],
                );
                return Err(IngestError::SchemaMismatch);
            }
        }

        plan.push(ColumnPlan {
            observed_index: obs_idx,
            target_type: target.clone(),
            name: dfield.name.clone(),
        });
        output_fields.push(Field::new(&dfield.name, target, dfield.nullable));
    }

    // ── Rule: declared non-null columns have no null rows in sample ──
    if let Some(batch) = sample_rows {
        if batch.num_rows() == 0 {
            warn!(
                event = "ingest.zero_rows",
                dataset_id = %dataset_id,
                resource_id = %resource_id,
            );
        }

        for (idx, dfield) in declared.fields.iter().enumerate() {
            if dfield.nullable {
                continue;
            }
            let obs_idx = plan[idx].observed_index;
            let col = batch.column(obs_idx);
            if col.null_count() > 0 {
                log_schema_mismatch(
                    dataset_id,
                    resource_id,
                    declared,
                    observed,
                    vec![format!("non_null_violation: {}", dfield.name)],
                );
                return Err(IngestError::SchemaMismatch);
            }
        }
    }

    // ── Rule: primary key uniqueness in sample ──────────────────────
    if let Some(pk) = primary_key {
        if let Some(batch) = sample_rows {
            let obs_idx = observed
                .fields()
                .iter()
                .position(|f| f.name() == pk)
                .expect("primary key presence checked above");
            if !primary_key_unique(batch, obs_idx) {
                log_schema_mismatch(
                    dataset_id,
                    resource_id,
                    declared,
                    observed,
                    vec![format!("primary_key_not_unique: {pk}")],
                );
                return Err(IngestError::SchemaMismatch);
            }
        }
    }

    Ok(ProjectionPlan {
        plan,
        output_schema: Arc::new(Schema::new(output_fields)),
    })
}

/// Parse every non-null string in a Utf8 or LargeUtf8 array per
/// `declared` (date or timestamp). Returns the first diff string on
/// failure.
fn parse_string_like_array(
    arr: &dyn Array,
    declared: FieldType,
    col_name: &str,
) -> Result<(), String> {
    if let Some(strings) = arr
        .as_any()
        .downcast_ref::<datafusion::arrow::array::StringArray>()
    {
        return parse_all_string_values(
            strings.len(),
            |idx| {
                if strings.is_null(idx) {
                    None
                } else {
                    Some(strings.value(idx))
                }
            },
            declared,
            col_name,
        );
    }

    if let Some(strings) = arr
        .as_any()
        .downcast_ref::<datafusion::arrow::array::LargeStringArray>()
    {
        return parse_all_string_values(
            strings.len(),
            |idx| {
                if strings.is_null(idx) {
                    None
                } else {
                    Some(strings.value(idx))
                }
            },
            declared,
            col_name,
        );
    }

    Err(format!(
        "type_mismatch: {col_name} (declared {declared:?}, expected Utf8 or LargeUtf8 for sample parse)"
    ))
}

fn parse_all_string_values<'a>(
    len: usize,
    value_at: impl Fn(usize) -> Option<&'a str>,
    declared: FieldType,
    col_name: &str,
) -> Result<(), String> {
    for i in 0..len {
        let Some(raw) = value_at(i).map(str::trim) else {
            continue;
        };
        let ok = match declared {
            FieldType::Date => {
                // RFC 3339 dates: YYYY-MM-DD. `time::Date::parse` with a
                // format description is faster than `OffsetDateTime`.
                Date::parse(
                    raw,
                    &time::macros::format_description!("[year]-[month]-[day]"),
                )
                .is_ok()
            }
            FieldType::Timestamp => OffsetDateTime::parse(raw, &Rfc3339).is_ok(),
            _ => unreachable!("parse_all_strings only called for Date/Timestamp"),
        };
        if !ok {
            return Err(format!(
                "rfc3339_parse_failed: {col_name} (row {i}, declared {declared:?})"
            ));
        }
    }
    Ok(())
}

/// Outcome of comparing one declared type to one observed Arrow type.
enum TypeCheck {
    /// Castable / equal.
    Ok,
    /// Acceptable only if the sample-mode parse succeeds. Today this is
    /// declared `Date` vs observed `Utf8` and declared `Timestamp` vs
    /// observed `Utf8`.
    NeedsSampleParse,
    /// Hard fail.
    Fail,
}

fn type_compatibility(declared: FieldType, observed: &DataType) -> TypeCheck {
    use FieldType as F;
    match (declared, observed) {
        (F::String, DataType::Utf8) | (F::String, DataType::LargeUtf8) => TypeCheck::Ok,
        (
            F::Number,
            DataType::Float64
            | DataType::Float32
            | DataType::Int64
            | DataType::Int32
            | DataType::Int16
            | DataType::Int8
            | DataType::UInt64
            | DataType::UInt32
            | DataType::UInt16
            | DataType::UInt8
            | DataType::Decimal128(_, _)
            | DataType::Decimal256(_, _),
        ) => TypeCheck::Ok,
        (
            F::Integer,
            DataType::Int64
            | DataType::Int32
            | DataType::Int16
            | DataType::Int8
            | DataType::UInt32
            | DataType::UInt16
            | DataType::UInt8,
        ) => TypeCheck::Ok,
        (F::Boolean, DataType::Boolean) => TypeCheck::Ok,
        (F::Date, DataType::Date32) | (F::Date, DataType::Date64) => TypeCheck::Ok,
        (F::Date, DataType::Utf8) | (F::Date, DataType::LargeUtf8) => TypeCheck::NeedsSampleParse,
        (F::Timestamp, DataType::Timestamp(_, _)) => TypeCheck::Ok,
        (F::Timestamp, DataType::Utf8) | (F::Timestamp, DataType::LargeUtf8) => {
            TypeCheck::NeedsSampleParse
        }
        _ => TypeCheck::Fail,
    }
}

/// Check primary-key uniqueness in a sample batch. The column may be of
/// any Arrow type; we hash row strings (debug repr) for V1 sample
/// volumes. This is sample-mode only, not production-scale.
fn primary_key_unique(batch: &RecordBatch, col_idx: usize) -> bool {
    use std::collections::HashSet;
    let col = batch.column(col_idx);
    // Format each value cheaply; we only run this on sample batches.
    let mut seen: HashSet<String> = HashSet::with_capacity(batch.num_rows());
    for row in 0..batch.num_rows() {
        if col.is_null(row) {
            // Null primary keys are not unique by definition. Treat as
            // a uniqueness violation so the §4 rule fires.
            if !seen.insert(String::from("\0__null__\0")) {
                return false;
            }
            continue;
        }
        let key = format_array_value(col.as_ref(), row);
        if !seen.insert(key) {
            return false;
        }
    }
    true
}

/// Cheap string repr of a single cell. Used for primary-key uniqueness
/// in sample mode; not a general-purpose serialiser.
fn format_array_value(arr: &dyn Array, row: usize) -> String {
    use datafusion::arrow::array::{
        BooleanArray, Date32Array, Float64Array, Int32Array, Int64Array, StringArray,
        TimestampMillisecondArray,
    };
    if let Some(a) = arr.as_any().downcast_ref::<StringArray>() {
        return a.value(row).to_string();
    }
    if let Some(a) = arr.as_any().downcast_ref::<Int64Array>() {
        return a.value(row).to_string();
    }
    if let Some(a) = arr.as_any().downcast_ref::<Int32Array>() {
        return a.value(row).to_string();
    }
    if let Some(a) = arr.as_any().downcast_ref::<Float64Array>() {
        return a.value(row).to_string();
    }
    if let Some(a) = arr.as_any().downcast_ref::<BooleanArray>() {
        return a.value(row).to_string();
    }
    if let Some(a) = arr.as_any().downcast_ref::<Date32Array>() {
        return a.value(row).to_string();
    }
    if let Some(a) = arr.as_any().downcast_ref::<TimestampMillisecondArray>() {
        return a.value(row).to_string();
    }
    // Fallback: use the Arrow debug repr scoped to a single row via
    // slicing, so an unexpected type still produces a stable string.
    let slice = arr.slice(row, 1);
    format!("{slice:?}")
}

fn log_schema_mismatch(
    dataset_id: &DatasetId,
    resource_id: &ResourceId,
    declared: &DeclaredSchema,
    observed: &Schema,
    diff: Vec<String>,
) {
    error!(
        event = "ingest.schema_mismatch",
        dataset_id = %dataset_id,
        resource_id = %resource_id,
        declared = ?summarise_fields_declared(declared),
        observed = ?summarise_fields_arrow(observed),
        diff = ?diff,
    );
}

fn summarise_fields_declared(s: &DeclaredSchema) -> Vec<String> {
    s.fields
        .iter()
        .map(|f| {
            format!(
                "{{name={}, type={:?}, nullable={}}}",
                f.name, f.ty, f.nullable
            )
        })
        .collect()
}

fn summarise_fields_arrow(s: &Schema) -> Vec<String> {
    s.fields()
        .iter()
        .map(|f| {
            format!(
                "{{name={}, type={:?}, nullable={}}}",
                f.name(),
                f.data_type(),
                f.is_nullable()
            )
        })
        .collect()
}
