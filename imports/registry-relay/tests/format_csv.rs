// SPDX-License-Identifier: Apache-2.0
//! Integration tests for `CsvFormat`.
//!
//! Each test builds a `Pin<Box<dyn AsyncRead>>` from a byte slice, calls
//! `CsvFormat::decode`, and asserts the resulting `DecodedStream`.

use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;

use datafusion::arrow::array::{
    Array, BooleanArray, Float64Array, Int64Array, StringArray, TimestampMillisecondArray,
};
use datafusion::arrow::datatypes::{DataType, TimeUnit};
use futures::StreamExt;
use tokio::io::AsyncRead;

use data_gate::config::FieldType;
use data_gate::format::csv::CsvFormat;
use data_gate::format::{Format, FormatHints};
use data_gate::ingest::declared_schema::{DeclaredField, DeclaredSchema};

// ── helpers ──────────────────────────────────────────────────────────────────

fn reader(bytes: &'static [u8]) -> Pin<Box<dyn AsyncRead + Send + Unpin>> {
    Box::pin(Cursor::new(bytes))
}

fn hints_default() -> FormatHints {
    FormatHints {
        sheet: None,
        header_row: Some(1),
        data_range: None,
        delimiter: None,
        quote: None,
        declared: DeclaredSchema::empty(),
    }
}

fn schema_with(fields: Vec<DeclaredField>) -> Arc<DeclaredSchema> {
    Arc::new(DeclaredSchema {
        strict: false,
        fields,
    })
}

fn field(name: &str, ty: FieldType) -> DeclaredField {
    DeclaredField {
        name: name.to_string(),
        ty,
        nullable: true,
        concept_uri: None,
        codelist: None,
        unit: None,
        language: None,
    }
}

// ── Test 1 ────────────────────────────────────────────────────────────────────

/// Well-formed CSV with a header row and 3 data rows.
/// Four columns of mixed declared types; asserts row count and column values.
#[tokio::test]
async fn decodes_well_formed_csv_with_header_row() {
    let csv = b"id,name,score,active\n1,Alice,9.5,true\n2,Bob,8.0,false\n3,Carol,7.3,true\n";

    let hints = FormatHints {
        declared: schema_with(vec![
            field("id", FieldType::Integer),
            field("name", FieldType::String),
            field("score", FieldType::Number),
            field("active", FieldType::Boolean),
        ]),
        ..hints_default()
    };

    let decoded = CsvFormat::new()
        .decode(reader(csv), hints)
        .await
        .expect("decode should succeed");

    let batches: Vec<_> = decoded.batches.collect::<Vec<_>>().await;
    assert_eq!(batches.len(), 1, "V1 yields one batch");
    let batch = batches[0].as_ref().expect("batch should be Ok");

    assert_eq!(batch.num_rows(), 3);
    assert_eq!(batch.num_columns(), 4);

    let ids = batch
        .column_by_name("id")
        .expect("id column")
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("id: Int64Array");
    assert_eq!(ids.values(), &[1, 2, 3]);

    let names = batch
        .column_by_name("name")
        .expect("name column")
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("name: StringArray");
    assert_eq!(names.value(0), "Alice");
    assert_eq!(names.value(1), "Bob");
    assert_eq!(names.value(2), "Carol");

    let scores = batch
        .column_by_name("score")
        .expect("score column")
        .as_any()
        .downcast_ref::<Float64Array>()
        .expect("score: Float64Array");
    assert!((scores.value(0) - 9.5).abs() < 1e-9);
    assert!((scores.value(1) - 8.0).abs() < 1e-9);

    let active = batch
        .column_by_name("active")
        .expect("active column")
        .as_any()
        .downcast_ref::<BooleanArray>()
        .expect("active: BooleanArray");
    assert!(active.value(0));
    assert!(!active.value(1));
    assert!(active.value(2));
}

// ── Test 2 ────────────────────────────────────────────────────────────────────

/// No declared schema: all columns come out as Utf8.
#[tokio::test]
async fn decodes_csv_with_no_declared_schema_as_utf8() {
    let csv = b"city,population\nParis,2161000\nLyon,518000\n";

    let decoded = CsvFormat::new()
        .decode(reader(csv), hints_default())
        .await
        .expect("decode should succeed");

    // All fields are Utf8 when no declared schema is provided
    for field in decoded.observed_schema.fields() {
        assert_eq!(
            *field.data_type(),
            DataType::Utf8,
            "field {} should be Utf8",
            field.name()
        );
    }

    let batches: Vec<_> = decoded.batches.collect::<Vec<_>>().await;
    let batch = batches[0].as_ref().expect("batch Ok");
    assert_eq!(batch.num_rows(), 2);

    let city = batch
        .column_by_name("city")
        .expect("city")
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("StringArray");
    assert_eq!(city.value(0), "Paris");
}

// ── Test 3 ────────────────────────────────────────────────────────────────────

/// TSV input with `delimiter: Some(b'\t')`.
#[tokio::test]
async fn honors_custom_delimiter_tab() {
    let tsv = b"country\tcapital\nFrance\tParis\nGermany\tBerlin\n";

    let hints = FormatHints {
        delimiter: Some(b'\t'),
        ..hints_default()
    };

    let decoded = CsvFormat::new()
        .decode(reader(tsv), hints)
        .await
        .expect("decode should succeed");

    let batches: Vec<_> = decoded.batches.collect::<Vec<_>>().await;
    let batch = batches[0].as_ref().expect("batch Ok");
    assert_eq!(batch.num_rows(), 2);
    assert_eq!(batch.num_columns(), 2);

    let capital = batch
        .column_by_name("capital")
        .expect("capital")
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("StringArray");
    assert_eq!(capital.value(0), "Paris");
    assert_eq!(capital.value(1), "Berlin");
}

// ── Test 4 ────────────────────────────────────────────────────────────────────

/// No header row in the file; `FormatHints.header_row = None`.
/// Columns should be named c0, c1, c2, ...
#[tokio::test]
async fn honors_header_row_none_synthesizes_column_names() {
    let csv = b"Alice,30,Engineer\nBob,25,Designer\n";

    let hints = FormatHints {
        header_row: None,
        ..hints_default()
    };

    let decoded = CsvFormat::new()
        .decode(reader(csv), hints)
        .await
        .expect("decode should succeed");

    let schema = &decoded.observed_schema;
    assert_eq!(schema.field(0).name(), "c0");
    assert_eq!(schema.field(1).name(), "c1");
    assert_eq!(schema.field(2).name(), "c2");

    let batches: Vec<_> = decoded.batches.collect::<Vec<_>>().await;
    let batch = batches[0].as_ref().expect("batch Ok");
    assert_eq!(batch.num_rows(), 2);
}

// ── Test 5 ────────────────────────────────────────────────────────────────────

/// Declared Integer/Number/Boolean/Date/Timestamp coerce to matching Arrow types.
#[tokio::test]
async fn coerces_strings_to_declared_types() {
    let csv =
        b"count,ratio,flag,birthday,created_at\n42,3.14,true,2024-06-15,2024-06-15T12:30:00Z\n";

    let hints = FormatHints {
        declared: schema_with(vec![
            field("count", FieldType::Integer),
            field("ratio", FieldType::Number),
            field("flag", FieldType::Boolean),
            field("birthday", FieldType::Date),
            field("created_at", FieldType::Timestamp),
        ]),
        ..hints_default()
    };

    let decoded = CsvFormat::new()
        .decode(reader(csv), hints)
        .await
        .expect("decode should succeed");

    let schema = &decoded.observed_schema;
    assert_eq!(
        *schema.field_with_name("count").unwrap().data_type(),
        DataType::Int64
    );
    assert_eq!(
        *schema.field_with_name("ratio").unwrap().data_type(),
        DataType::Float64
    );
    assert_eq!(
        *schema.field_with_name("flag").unwrap().data_type(),
        DataType::Boolean
    );
    assert_eq!(
        *schema.field_with_name("birthday").unwrap().data_type(),
        DataType::Date32
    );
    assert_eq!(
        *schema.field_with_name("created_at").unwrap().data_type(),
        DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into()))
    );

    let batches: Vec<_> = decoded.batches.collect::<Vec<_>>().await;
    let batch = batches[0].as_ref().expect("batch Ok");
    assert_eq!(batch.num_rows(), 1);

    // Spot-check a value
    let count = batch
        .column_by_name("count")
        .expect("count")
        .as_any()
        .downcast_ref::<Int64Array>()
        .expect("Int64Array");
    assert_eq!(count.value(0), 42);

    let ts = batch
        .column_by_name("created_at")
        .expect("created_at")
        .as_any()
        .downcast_ref::<TimestampMillisecondArray>()
        .expect("TimestampMillisecondArray");
    // 2024-06-15T12:30:00Z in milliseconds since epoch
    assert!(ts.value(0) > 0);
}

// ── Test 6 ────────────────────────────────────────────────────────────────────

/// Declared Integer column with a non-numeric value yields FormatError::Parse
/// with row and column context.
#[tokio::test]
async fn rejects_malformed_csv_with_parse_error() {
    let csv = b"id,amount\n1,100\n2,not_a_number\n3,300\n";

    let hints = FormatHints {
        declared: schema_with(vec![
            field("id", FieldType::Integer),
            field("amount", FieldType::Integer),
        ]),
        ..hints_default()
    };

    let result = CsvFormat::new().decode(reader(csv), hints).await;

    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("not_a_number"),
                "error should mention the bad value: {msg}"
            );
            assert!(
                msg.contains("amount"),
                "error should mention the column: {msg}"
            );
        }
        Ok(decoded) => {
            // Error may also surface when consuming the batch stream
            let batches: Vec<_> = decoded.batches.collect::<Vec<_>>().await;
            let has_error = batches.iter().any(|b| b.is_err());
            assert!(has_error, "expected a parse error in the batch stream");
        }
    }
}

// ── Test 7 ────────────────────────────────────────────────────────────────────

/// Zero data rows after header is valid: yields an empty batch, not an error.
#[tokio::test]
async fn empty_csv_yields_empty_batch_not_error() {
    let csv = b"id,name\n";

    let decoded = CsvFormat::new()
        .decode(reader(csv), hints_default())
        .await
        .expect("decode should succeed");

    let batches: Vec<_> = decoded.batches.collect::<Vec<_>>().await;
    assert_eq!(batches.len(), 1);
    let batch = batches[0].as_ref().expect("batch Ok");
    assert_eq!(batch.num_rows(), 0);
    assert_eq!(batch.num_columns(), 2);
}

// ── Test 8 ────────────────────────────────────────────────────────────────────

/// Various boolean spellings (yes/No/TRUE/0) all parse correctly.
#[tokio::test]
async fn coerces_boolean_variants_case_insensitive() {
    let csv = b"flag\nyes\nNo\nTRUE\n0\n";

    let hints = FormatHints {
        declared: schema_with(vec![field("flag", FieldType::Boolean)]),
        ..hints_default()
    };

    let decoded = CsvFormat::new()
        .decode(reader(csv), hints)
        .await
        .expect("decode should succeed");

    let batches: Vec<_> = decoded.batches.collect::<Vec<_>>().await;
    let batch = batches[0].as_ref().expect("batch Ok");
    assert_eq!(batch.num_rows(), 4);

    let flags = batch
        .column_by_name("flag")
        .expect("flag")
        .as_any()
        .downcast_ref::<BooleanArray>()
        .expect("BooleanArray");

    assert!(flags.value(0), "yes -> true");
    assert!(!flags.value(1), "No -> false");
    assert!(flags.value(2), "TRUE -> true");
    assert!(!flags.value(3), "0 -> false");
}
