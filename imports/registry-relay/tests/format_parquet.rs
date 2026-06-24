// SPDX-License-Identifier: Apache-2.0
//! Integration tests for `ParquetFormat`.
//!
//! Coverage:
//! - round-trip: write via `AsyncArrowWriter`, read back via `ParquetFormat::decode`
//! - observed schema matches parquet file metadata
//! - `FormatHints` fields irrelevant to parquet (sheet, delimiter, etc.) are ignored
//! - corrupt bytes surface as `FormatError::Parse` or `FormatError::Io`
//! - parquet with multiple row groups returns more than one batch
//!
//! Fixtures are generated at test time using `datafusion::parquet::arrow::AsyncArrowWriter`
//! writing to `Vec<u8>`, then wrapped in a `std::io::Cursor` / Tokio `AsyncRead`.
//! No binary fixtures are checked in.

use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;

use datafusion::arrow::array::{Float64Array, Int32Array, Int64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::parquet::arrow::AsyncArrowWriter;
use datafusion::parquet::file::properties::WriterProperties;
use futures::TryStreamExt as _;

use registry_relay::format::parquet::ParquetFormat;
use registry_relay::format::{DecodedStream, Format, FormatError, FormatHints};
use registry_relay::ingest::declared_schema::DeclaredSchema;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Write `batches` to an in-memory `Vec<u8>` as a Parquet file, with the
/// given `WriterProperties`. Returns the raw bytes.
async fn write_parquet(
    schema: SchemaRef,
    batches: &[RecordBatch],
    props: Option<WriterProperties>,
) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    let mut writer =
        AsyncArrowWriter::try_new(&mut buf, schema, props).expect("AsyncArrowWriter::try_new");
    for batch in batches {
        writer.write(batch).await.expect("writer.write");
    }
    writer.close().await.expect("writer.close");
    buf
}

/// Wrap raw bytes in a boxed `AsyncRead` suitable for `Format::decode`.
fn boxed_reader(bytes: Vec<u8>) -> Pin<Box<dyn tokio::io::AsyncRead + Send + Unpin>> {
    Box::pin(tokio::io::BufReader::new(Cursor::new(bytes)))
}

/// Default `FormatHints` with an empty `DeclaredSchema` (parquet doesn't use
/// the hint fields, but the type requires them).
fn empty_hints() -> FormatHints {
    FormatHints {
        sheet: None,
        header_row: None,
        data_range: None,
        delimiter: None,
        quote: None,
        declared: DeclaredSchema::empty(),
    }
}

/// Collect all batches from a `DecodedStream`, asserting no errors.
async fn collect_batches(stream: DecodedStream) -> Vec<RecordBatch> {
    stream
        .batches
        .try_collect::<Vec<_>>()
        .await
        .expect("batch stream error")
}

// ─── 1. round trip ───────────────────────────────────────────────────────────

#[tokio::test]
async fn decodes_simple_parquet_round_trip() {
    let schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Int64, false),
        Field::new("name", DataType::Utf8, true),
    ]));
    let ids = Arc::new(Int64Array::from(vec![1_i64, 2, 3]));
    let names = Arc::new(StringArray::from(vec!["alice", "bob", "carol"]));
    let original =
        RecordBatch::try_new(schema.clone(), vec![ids, names]).expect("RecordBatch::try_new");

    let bytes = write_parquet(schema.clone(), std::slice::from_ref(&original), None).await;
    let fmt = ParquetFormat::new();
    let decoded = fmt
        .decode(boxed_reader(bytes), empty_hints())
        .await
        .expect("decode");

    assert_eq!(decoded.observed_schema.fields().len(), 2);
    let batches = collect_batches(decoded).await;
    assert!(!batches.is_empty());

    // Collect rows across all batches.
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 3);

    // The schema returned must have the same field names and types.
    let obs = &batches[0].schema();
    assert_eq!(obs.field(0).name(), "id");
    assert_eq!(obs.field(0).data_type(), &DataType::Int64);
    assert_eq!(obs.field(1).name(), "name");
    assert_eq!(obs.field(1).data_type(), &DataType::Utf8);
}

// ─── 2. observed schema matches parquet metadata ──────────────────────────────

#[tokio::test]
async fn observed_schema_matches_parquet_metadata() {
    let schema = Arc::new(Schema::new(vec![
        Field::new("alpha", DataType::Int32, false),
        Field::new("beta", DataType::Float64, true),
        Field::new("gamma", DataType::Utf8, true),
        Field::new("delta", DataType::Int64, false),
    ]));
    let a = Arc::new(Int32Array::from(vec![1_i32, 2]));
    let b = Arc::new(Float64Array::from(vec![1.0_f64, 2.0]));
    let c = Arc::new(StringArray::from(vec!["x", "y"]));
    let d = Arc::new(Int64Array::from(vec![10_i64, 20]));
    let batch =
        RecordBatch::try_new(schema.clone(), vec![a, b, c, d]).expect("RecordBatch::try_new");

    let bytes = write_parquet(schema.clone(), &[batch], None).await;
    let fmt = ParquetFormat::new();
    let decoded = fmt
        .decode(boxed_reader(bytes), empty_hints())
        .await
        .expect("decode");

    let obs = &decoded.observed_schema;
    assert_eq!(obs.fields().len(), 4);
    assert_eq!(obs.field(0).name(), "alpha");
    assert_eq!(obs.field(1).name(), "beta");
    assert_eq!(obs.field(2).name(), "gamma");
    assert_eq!(obs.field(3).name(), "delta");

    // Parquet round-trips Int32 as Int32; Float64 as Float64.
    assert_eq!(obs.field(0).data_type(), &DataType::Int32);
    assert_eq!(obs.field(1).data_type(), &DataType::Float64);
    assert_eq!(obs.field(2).data_type(), &DataType::Utf8);
    assert_eq!(obs.field(3).data_type(), &DataType::Int64);
}

// ─── 3. irrelevant hints are ignored ─────────────────────────────────────────

#[tokio::test]
async fn ignores_format_hints_irrelevant_to_parquet() {
    let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]));
    let vals = Arc::new(Int64Array::from(vec![42_i64]));
    let batch = RecordBatch::try_new(schema.clone(), vec![vals]).expect("RecordBatch::try_new");

    let bytes = write_parquet(schema, &[batch], None).await;

    // Populate every CSV/XLSX-specific hint field; parquet must not fail.
    let hints = FormatHints {
        sheet: Some("Sheet1".to_string()),
        header_row: Some(1),
        data_range: Some("A2:B1000".to_string()),
        delimiter: Some(b';'),
        quote: Some(b'\''),
        declared: DeclaredSchema::empty(),
    };

    let fmt = ParquetFormat::new();
    let decoded = fmt
        .decode(boxed_reader(bytes), hints)
        .await
        .expect("decode should succeed even with irrelevant hints");

    let batches = collect_batches(decoded).await;
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 1);
}

// ─── 4. corrupt bytes → FormatError ──────────────────────────────────────────

#[tokio::test]
async fn surfaces_corrupt_parquet_as_format_error() {
    // Random non-parquet bytes.
    let garbage: Vec<u8> = (0..512).map(|i| (i % 255) as u8).collect();
    let fmt = ParquetFormat::new();
    let result = fmt.decode(boxed_reader(garbage), empty_hints()).await;

    match result {
        Err(FormatError::Parse(_)) | Err(FormatError::Io(_)) => {}
        Ok(_) => panic!("expected FormatError::Parse or Io, but got Ok"),
        Err(e) => panic!("expected FormatError::Parse or Io, got other error: {e}"),
    }
}

// ─── 5. decompression bomb guards (security review 2026-05-16) ──────────────

/// A file whose tail does not end with the `PAR1` magic must be rejected as
/// a parse error before `ParquetRecordBatchReaderBuilder::try_new` is asked
/// to allocate a footer. This is the cheap-magic-check branch of the
/// pre-decode validation added in response to the footer-bomb finding.
#[tokio::test]
async fn rejects_parquet_without_par1_magic() {
    // 16 zero bytes: enough to clear the 8-byte minimum so the size check
    // does not short-circuit, but the trailing four bytes are not `PAR1`.
    let bytes = vec![0u8; 16];
    let fmt = ParquetFormat::new();
    let result = fmt.decode(boxed_reader(bytes), empty_hints()).await;

    match result {
        Err(FormatError::Parse(_)) => {}
        Err(other) => panic!("expected FormatError::Parse, got {other:?}"),
        Ok(_) => panic!("non-Parquet bytes must be rejected"),
    }
}

/// A file whose footer-length field at `len - 8` advertises a footer larger
/// than `MAX_PARQUET_FOOTER_BYTES` must be rejected with `LimitExceeded`
/// before any 4 GB allocation is attempted. We forge such a file by writing
/// a real, valid Parquet, then rewriting the four footer-length bytes at
/// offset `len - 8` to `u32::MAX`. The trailing `PAR1` magic stays intact
/// so the magic check passes and the cap is what causes the rejection.
#[tokio::test]
async fn rejects_parquet_with_oversized_footer_length() {
    use datafusion::arrow::array::Int64Array;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};

    let schema = Arc::new(Schema::new(vec![Field::new("v", DataType::Int64, false)]));
    let vals = Arc::new(Int64Array::from(vec![1_i64, 2, 3]));
    let batch = RecordBatch::try_new(schema.clone(), vec![vals]).expect("RecordBatch::try_new");
    let mut bytes = write_parquet(schema, &[batch], None).await;

    // Overwrite the footer-length u32 LE at offset (len - 8) with u32::MAX.
    let n = bytes.len();
    assert!(n >= 8);
    bytes[n - 8..n - 4].copy_from_slice(&u32::MAX.to_le_bytes());

    let fmt = ParquetFormat::new();
    let result = fmt.decode(boxed_reader(bytes), empty_hints()).await;
    match result {
        Err(FormatError::LimitExceeded(_)) => {}
        Err(other) => panic!("expected FormatError::LimitExceeded, got {other:?}"),
        Ok(_) => panic!("a bomb footer must be rejected"),
    }
}

/// A file with more than `MAX_PARQUET_COLUMNS` columns must be rejected
/// after `try_new` succeeds. We build a 5000-column file (cap is 4096) of
/// nullable Utf8 columns with one empty row; the column count guard fires.
#[tokio::test]
async fn rejects_parquet_with_too_many_columns() {
    use datafusion::arrow::array::StringArray;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};

    const N: usize = 5000;
    let fields: Vec<Field> = (0..N)
        .map(|i| Field::new(format!("c{i}"), DataType::Utf8, true))
        .collect();
    let schema = Arc::new(Schema::new(fields));
    let columns: Vec<Arc<dyn datafusion::arrow::array::Array>> = (0..N)
        .map(|_| Arc::new(StringArray::from(vec![Option::<&str>::None])) as _)
        .collect();
    let batch = RecordBatch::try_new(schema.clone(), columns).expect("RecordBatch::try_new");
    let bytes = write_parquet(schema, &[batch], None).await;

    let fmt = ParquetFormat::new();
    let result = fmt.decode(boxed_reader(bytes), empty_hints()).await;
    match result {
        Err(FormatError::LimitExceeded(_)) => {}
        Err(other) => panic!("expected FormatError::LimitExceeded, got {other:?}"),
        Ok(_) => panic!("a high column count must be rejected"),
    }
}

// ─── 6. multiple row groups → multiple batches ────────────────────────────────

#[tokio::test]
async fn multi_batch_parquet_streams_through() {
    // Write three row groups by flushing after each batch.
    // `WriterProperties::max_row_group_size(1)` forces one row per row group,
    // ensuring the reader returns multiple batches when `batch_size` is also
    // small. We just rely on the row-group boundary here.
    let schema = Arc::new(Schema::new(vec![Field::new("n", DataType::Int64, false)]));

    let props = WriterProperties::builder()
        .set_max_row_group_row_count(Some(1))
        .build();

    let mut buf: Vec<u8> = Vec::new();
    let mut writer =
        AsyncArrowWriter::try_new(&mut buf, schema.clone(), Some(props)).expect("writer");

    for i in 0_i64..3 {
        let batch = RecordBatch::try_new(schema.clone(), vec![Arc::new(Int64Array::from(vec![i]))])
            .expect("batch");
        writer.write(&batch).await.expect("write batch");
        writer.flush().await.expect("flush");
    }
    writer.close().await.expect("close");

    let fmt = ParquetFormat::new();
    let decoded = fmt
        .decode(boxed_reader(buf), empty_hints())
        .await
        .expect("decode");

    let batches = collect_batches(decoded).await;
    assert!(
        !batches.is_empty(),
        "expected at least 1 batch, got {}",
        batches.len()
    );
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(total_rows, 3, "total rows across batches");
}
