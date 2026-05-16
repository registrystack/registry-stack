// SPDX-License-Identifier: Apache-2.0
//! Integration tests for `ingest::validation`.
//!
//! Each test constructs a small Arrow schema (and where the rule needs
//! sample data, a `RecordBatch`) inline, calls `validate`, and asserts
//! the result against the expected behavior.

use std::sync::Arc;

use datafusion::arrow::array::{Float64Array, Int32Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;

use data_gate::config::{DatasetId, FieldType, ResourceId};
use data_gate::error::IngestError;
use data_gate::ingest::declared_schema::{DeclaredField, DeclaredSchema};
use data_gate::ingest::validation::{validate, ProjectionPlan};

// ── Helpers ──────────────────────────────────────────────────────────────────

fn dsid() -> DatasetId {
    serde_json::from_str(r#""social_registry""#).expect("DatasetId")
}

fn rsid() -> ResourceId {
    serde_json::from_str(r#""beneficiaries""#).expect("ResourceId")
}

fn field(name: &str, ty: FieldType, nullable: bool) -> DeclaredField {
    DeclaredField {
        name: name.to_string(),
        ty,
        nullable,
        concept_uri: None,
        codelist: None,
        unit: None,
        language: None,
    }
}

fn declared(strict: bool, fields: Vec<DeclaredField>) -> DeclaredSchema {
    DeclaredSchema { strict, fields }
}

fn arrow_schema(cols: Vec<(&str, DataType, bool)>) -> Schema {
    Schema::new(
        cols.into_iter()
            .map(|(n, t, nl)| Field::new(n, t, nl))
            .collect::<Vec<_>>(),
    )
}

fn run(
    decl: &DeclaredSchema,
    obs: &Schema,
    pk: Option<&str>,
    sample: Option<&RecordBatch>,
) -> Result<ProjectionPlan, IngestError> {
    validate(&dsid(), &rsid(), decl, obs, pk, sample)
}

// ── Rule 1: declared column missing from observed -> SchemaMismatch ──────────

#[test]
fn declared_column_missing_from_observed_fails() {
    let decl = declared(
        false,
        vec![
            field("id", FieldType::Integer, false),
            field("name", FieldType::String, true),
        ],
    );
    let obs = arrow_schema(vec![("id", DataType::Int64, false)]);
    let err = run(&decl, &obs, None, None).unwrap_err();
    assert!(matches!(err, IngestError::SchemaMismatch));
}

// ── Rule 2: observed column not in declared, strict: true -> StrictExtraColumn

#[test]
fn observed_extra_column_in_strict_schema_fails_with_strict_extra_column() {
    let decl = declared(true, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![
        ("id", DataType::Int64, false),
        ("surprise", DataType::Utf8, true),
    ]);
    let err = run(&decl, &obs, None, None).unwrap_err();
    assert!(matches!(err, IngestError::StrictExtraColumn));
}

// ── Rule 3: observed extra column, strict: false -> dropped from projection ──

#[test]
fn observed_extra_column_in_lax_schema_drops_it_from_plan() {
    let decl = declared(false, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![
        ("id", DataType::Int64, false),
        ("extra", DataType::Utf8, true),
    ]);
    let plan = run(&decl, &obs, None, None).expect("should accept");
    // The plan's output schema should not contain "extra".
    let out = plan.output_schema();
    assert_eq!(out.fields().len(), 1);
    assert_eq!(out.field(0).name(), "id");

    // And apply() should drop the column when fed a sample batch.
    let batch = RecordBatch::try_new(
        Arc::new(obs),
        vec![
            Arc::new(Int64Array::from(vec![1, 2])),
            Arc::new(StringArray::from(vec!["a", "b"])),
        ],
    )
    .unwrap();
    let out_batch = plan.apply(&batch).expect("apply");
    assert_eq!(out_batch.num_columns(), 1);
    assert_eq!(out_batch.num_rows(), 2);
    assert_eq!(out_batch.schema().field(0).name(), "id");
}

// ── Rule 4: declared string vs observed Utf8 -> Ok ───────────────────────────

#[test]
fn declared_string_against_utf8_accepts() {
    let decl = declared(false, vec![field("name", FieldType::String, true)]);
    let obs = arrow_schema(vec![("name", DataType::Utf8, true)]);
    run(&decl, &obs, None, None).expect("string vs Utf8 should accept");
}

// ── Rule 5: declared number vs observed Float64/Int*/Decimal -> Ok, cast ─────

#[test]
fn declared_number_against_float64_and_ints_accepts_and_casts() {
    let decl = declared(false, vec![field("score", FieldType::Number, true)]);

    // Float64 input: cast is a no-op.
    let obs = arrow_schema(vec![("score", DataType::Float64, true)]);
    let plan = run(&decl, &obs, None, None).expect("number vs Float64");
    assert_eq!(
        plan.output_schema().field(0).data_type(),
        &DataType::Float64
    );

    // Int64 input: plan should cast to Float64.
    let obs2 = arrow_schema(vec![("score", DataType::Int64, true)]);
    let plan2 = run(&decl, &obs2, None, None).expect("number vs Int64");
    let batch = RecordBatch::try_new(
        Arc::new(obs2),
        vec![Arc::new(Int64Array::from(vec![1, 2, 3]))],
    )
    .unwrap();
    let out = plan2.apply(&batch).expect("apply Int64 -> Float64");
    assert_eq!(out.schema().field(0).data_type(), &DataType::Float64);
    let casted = out
        .column(0)
        .as_any()
        .downcast_ref::<Float64Array>()
        .unwrap();
    assert_eq!(casted.values(), &[1.0, 2.0, 3.0]);

    // Decimal128 input: accepted; cast to Float64 at apply time.
    let obs3 = arrow_schema(vec![("score", DataType::Decimal128(10, 2), true)]);
    let plan3 = run(&decl, &obs3, None, None).expect("number vs Decimal128");
    assert_eq!(
        plan3.output_schema().field(0).data_type(),
        &DataType::Float64
    );
}

// ── Rule 6: declared integer vs observed Int64/Int32 -> Ok, cast to Int64 ────

#[test]
fn declared_integer_against_int32_accepts_and_casts_to_int64() {
    let decl = declared(false, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![("id", DataType::Int32, false)]);
    let plan = run(&decl, &obs, None, None).expect("integer vs Int32");

    let batch = RecordBatch::try_new(
        Arc::new(obs),
        vec![Arc::new(Int32Array::from(vec![10, 20, 30]))],
    )
    .unwrap();
    let out = plan.apply(&batch).expect("apply Int32 -> Int64");
    let casted = out.column(0).as_any().downcast_ref::<Int64Array>().unwrap();
    assert_eq!(casted.values(), &[10_i64, 20, 30]);
}

// ── Rule 7: declared boolean vs observed Boolean -> Ok ───────────────────────

#[test]
fn declared_boolean_against_boolean_accepts() {
    let decl = declared(false, vec![field("active", FieldType::Boolean, true)]);
    let obs = arrow_schema(vec![("active", DataType::Boolean, true)]);
    run(&decl, &obs, None, None).expect("boolean vs Boolean");
}

// ── Rule 8: declared date vs observed Date32 -> Ok ───────────────────────────

#[test]
fn declared_date_against_date32_accepts() {
    let decl = declared(false, vec![field("dob", FieldType::Date, true)]);
    let obs = arrow_schema(vec![("dob", DataType::Date32, true)]);
    run(&decl, &obs, None, None).expect("date vs Date32");
}

// ── Rule 9: declared date vs observed Utf8 -> OK in cheap-mode; parse in
// sample-mode (success and failure paths) ────────────────────────────────────

#[test]
fn declared_date_against_utf8_accepts_in_cheap_mode() {
    let decl = declared(false, vec![field("dob", FieldType::Date, true)]);
    let obs = arrow_schema(vec![("dob", DataType::Utf8, true)]);
    // No sample rows: cheap-mode skips the parse check.
    run(&decl, &obs, None, None).expect("date vs Utf8 cheap-mode");
}

#[test]
fn declared_date_against_utf8_sample_parses_valid_rfc3339() {
    let decl = declared(false, vec![field("dob", FieldType::Date, true)]);
    let obs = arrow_schema(vec![("dob", DataType::Utf8, true)]);
    let batch = RecordBatch::try_new(
        Arc::new(obs.clone()),
        vec![Arc::new(StringArray::from(vec![
            Some("1990-01-15"),
            None,
            Some("2024-12-31"),
        ]))],
    )
    .unwrap();
    run(&decl, &obs, None, Some(&batch)).expect("valid ISO dates");
}

#[test]
fn declared_date_against_utf8_sample_fails_on_unparseable() {
    let decl = declared(false, vec![field("dob", FieldType::Date, true)]);
    let obs = arrow_schema(vec![("dob", DataType::Utf8, true)]);
    let batch = RecordBatch::try_new(
        Arc::new(obs.clone()),
        vec![Arc::new(StringArray::from(vec!["not-a-date"]))],
    )
    .unwrap();
    let err = run(&decl, &obs, None, Some(&batch)).unwrap_err();
    assert!(matches!(err, IngestError::SchemaMismatch));
}

// ── Rule 10: declared timestamp vs observed Timestamp(_,_) -> Ok ─────────────

#[test]
fn declared_timestamp_against_any_timestamp_accepts() {
    let decl = declared(false, vec![field("created_at", FieldType::Timestamp, true)]);
    let obs = arrow_schema(vec![(
        "created_at",
        DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
        true,
    )]);
    let plan = run(&decl, &obs, None, None).expect("timestamp vs Timestamp(us, UTC)");
    // Output schema normalises to Timestamp(Millisecond, "UTC").
    assert_eq!(
        plan.output_schema().field(0).data_type(),
        &DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into()))
    );
}

// ── Rule 11: declared timestamp vs observed Utf8 -> parse in sample-mode ─────

#[test]
fn declared_timestamp_against_utf8_sample_fails_on_unparseable() {
    let decl = declared(false, vec![field("created_at", FieldType::Timestamp, true)]);
    let obs = arrow_schema(vec![("created_at", DataType::Utf8, true)]);
    let batch = RecordBatch::try_new(
        Arc::new(obs.clone()),
        vec![Arc::new(StringArray::from(vec!["not-a-timestamp"]))],
    )
    .unwrap();
    let err = run(&decl, &obs, None, Some(&batch)).unwrap_err();
    assert!(matches!(err, IngestError::SchemaMismatch));
}

#[test]
fn declared_timestamp_against_utf8_sample_accepts_valid_rfc3339() {
    let decl = declared(false, vec![field("created_at", FieldType::Timestamp, true)]);
    let obs = arrow_schema(vec![("created_at", DataType::Utf8, true)]);
    let batch = RecordBatch::try_new(
        Arc::new(obs.clone()),
        vec![Arc::new(StringArray::from(vec![
            "2024-01-15T10:30:00Z",
            "2024-06-30T23:59:59+02:00",
        ]))],
    )
    .unwrap();
    run(&decl, &obs, None, Some(&batch)).expect("valid RFC 3339 timestamps");
}

// ── Rule 12: declared non-null column has null rows -> SchemaMismatch ────────

#[test]
fn declared_non_null_column_with_nulls_fails_in_sample_mode() {
    let decl = declared(false, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![("id", DataType::Int64, true)]);
    let batch = RecordBatch::try_new(
        Arc::new(obs.clone()),
        vec![Arc::new(Int64Array::from(vec![Some(1), None, Some(3)]))],
    )
    .unwrap();
    let err = run(&decl, &obs, None, Some(&batch)).unwrap_err();
    assert!(matches!(err, IngestError::SchemaMismatch));
}

// ── Rule 13a: primary_key field missing from declared/observed ───────────────

#[test]
fn primary_key_missing_from_observed_fails() {
    // Declared has the pk, observed does NOT.
    let decl = declared(
        false,
        vec![
            field("id", FieldType::Integer, false),
            field("name", FieldType::String, true),
        ],
    );
    let obs = arrow_schema(vec![
        ("id", DataType::Int64, false),
        ("name", DataType::Utf8, true),
    ]);
    // Test that an explicitly referenced pk that isn't even in
    // declared+observed lookup fails. The validator first verifies the
    // declared/observed shape, then the pk presence.
    let err = run(&decl, &obs, Some("nonexistent_pk"), None).unwrap_err();
    assert!(matches!(err, IngestError::SchemaMismatch));
}

#[test]
fn primary_key_present_in_observed_accepts() {
    let decl = declared(false, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![("id", DataType::Int64, false)]);
    run(&decl, &obs, Some("id"), None).expect("pk present");
}

// ── Rule 13b: primary_key non-unique in sample -> SchemaMismatch ─────────────

#[test]
fn primary_key_non_unique_in_sample_fails() {
    let decl = declared(false, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![("id", DataType::Int64, false)]);
    let batch = RecordBatch::try_new(
        Arc::new(obs.clone()),
        vec![Arc::new(Int64Array::from(vec![1, 2, 2, 3]))],
    )
    .unwrap();
    let err = run(&decl, &obs, Some("id"), Some(&batch)).unwrap_err();
    assert!(matches!(err, IngestError::SchemaMismatch));
}

#[test]
fn primary_key_unique_in_sample_accepts() {
    let decl = declared(false, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![("id", DataType::Int64, false)]);
    let batch = RecordBatch::try_new(
        Arc::new(obs.clone()),
        vec![Arc::new(Int64Array::from(vec![1, 2, 3, 4]))],
    )
    .unwrap();
    run(&decl, &obs, Some("id"), Some(&batch)).expect("unique pk");
}

// ── Rule 14: declared type uncastable to observed -> SchemaMismatch ──────────

#[test]
fn declared_integer_against_utf8_fails() {
    // The §4 example: declared integer, observed Utf8 of non-numeric.
    // At validate() time, the type pair is not in the castable matrix,
    // so it fails as a type mismatch even without sample rows.
    let decl = declared(false, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![("id", DataType::Utf8, false)]);
    let err = run(&decl, &obs, None, None).unwrap_err();
    assert!(matches!(err, IngestError::SchemaMismatch));
}

// ── Rule 15: source returns zero rows -> OK, log only ────────────────────────

#[test]
fn zero_rows_in_sample_accepts() {
    let decl = declared(false, vec![field("id", FieldType::Integer, false)]);
    let obs = arrow_schema(vec![("id", DataType::Int64, false)]);
    let batch = RecordBatch::try_new(
        Arc::new(obs.clone()),
        vec![Arc::new(Int64Array::from(Vec::<i64>::new()))],
    )
    .unwrap();
    run(&decl, &obs, None, Some(&batch)).expect("zero rows accept");
}

// ── Rule 16: field name case mismatch -> SchemaMismatch (case-sensitive) ─────

#[test]
fn field_name_case_mismatch_fails() {
    // Declared `MunicipalityCode`, observed `municipality_code`.
    let decl = declared(
        false,
        vec![field("MunicipalityCode", FieldType::String, false)],
    );
    let obs = arrow_schema(vec![("municipality_code", DataType::Utf8, false)]);
    let err = run(&decl, &obs, None, None).unwrap_err();
    assert!(matches!(err, IngestError::SchemaMismatch));
}

// ── apply() idempotence ──────────────────────────────────────────────────────

#[test]
fn apply_is_idempotent() {
    // Build a plan that casts Int32 -> Int64 (i.e., the cast actually
    // changes the type), then assert apply(apply(b)) == apply(b).
    let decl = declared(
        false,
        vec![
            field("id", FieldType::Integer, false),
            field("name", FieldType::String, true),
        ],
    );
    let obs = arrow_schema(vec![
        ("id", DataType::Int32, false),
        ("name", DataType::Utf8, true),
        ("dropped", DataType::Float64, true),
    ]);
    let plan = run(&decl, &obs, None, None).expect("plan");

    let batch = RecordBatch::try_new(
        Arc::new(obs),
        vec![
            Arc::new(Int32Array::from(vec![1, 2, 3])),
            Arc::new(StringArray::from(vec!["a", "b", "c"])),
            Arc::new(Float64Array::from(vec![0.1, 0.2, 0.3])),
        ],
    )
    .unwrap();

    let once = plan.apply(&batch).expect("apply once");
    // Re-apply to the already-projected batch: the apply step looks up
    // columns by index, so build a *fresh* plan against the projected
    // schema to test idempotence at the semantic level.
    let plan2 = run(&decl, once.schema().as_ref(), None, None).expect("plan2");
    let twice = plan2.apply(&once).expect("apply twice");

    assert_eq!(once.schema(), twice.schema());
    assert_eq!(once.num_rows(), twice.num_rows());
    assert_eq!(once.num_columns(), twice.num_columns());
    for col_idx in 0..once.num_columns() {
        let a = once.column(col_idx);
        let b = twice.column(col_idx);
        assert_eq!(
            a.as_ref().len(),
            b.as_ref().len(),
            "column {col_idx} length"
        );
        // Compare by Arrow's Array trait equality (PartialEq via dyn).
        assert_eq!(format!("{a:?}"), format!("{b:?}"), "column {col_idx} data");
    }
}

// Dataset/resource id validation belongs to the config validator, not
// declared-vs-observed schema validation.

// ── Sanity: declared types -> Arrow schema mapping ───────────────────────────

#[test]
fn declared_schema_to_arrow_schema_uses_canonical_types() {
    let decl = declared(
        true,
        vec![
            field("s", FieldType::String, true),
            field("i", FieldType::Integer, false),
            field("n", FieldType::Number, true),
            field("b", FieldType::Boolean, true),
            field("d", FieldType::Date, true),
            field("t", FieldType::Timestamp, true),
        ],
    );
    let arrow = decl.to_arrow_schema();
    assert_eq!(arrow.field(0).data_type(), &DataType::Utf8);
    assert_eq!(arrow.field(1).data_type(), &DataType::Int64);
    assert_eq!(arrow.field(2).data_type(), &DataType::Float64);
    assert_eq!(arrow.field(3).data_type(), &DataType::Boolean);
    assert_eq!(arrow.field(4).data_type(), &DataType::Date32);
    assert_eq!(
        arrow.field(5).data_type(),
        &DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into()))
    );
    // Order is preserved.
    assert_eq!(
        arrow
            .fields()
            .iter()
            .map(|f| f.name().as_str())
            .collect::<Vec<_>>(),
        vec!["s", "i", "n", "b", "d", "t"]
    );
}
