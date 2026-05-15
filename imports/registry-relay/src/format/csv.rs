// SPDX-License-Identifier: Apache-2.0
//! `CsvFormat`: decode CSV byte streams to Arrow `RecordBatch`es.
//!
//! Uses the sync `csv` crate inside `tokio::task::spawn_blocking` per
//! `decisions/wave-1.md` W1-10. Reads the entire byte stream into memory
//! once (V1 accepted cost), hands the buffer to `csv::Reader`, then builds
//! Arrow arrays from the resulting string records. Type coercion is driven
//! by `FormatHints.declared`.

use std::pin::Pin;
use std::sync::Arc;

use datafusion::arrow::array::{
    ArrayRef, BooleanBuilder, Date32Builder, Float64Builder, Int64Builder, StringBuilder,
    TimestampMillisecondBuilder,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use futures::stream;
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::config::FieldType;
use crate::format::{DecodedStream, Format, FormatError, FormatFuture, FormatHints};
use crate::ingest::declared_schema::DeclaredField;

/// Decoder for CSV input.
///
/// Stateless; one instance serves every CSV resource. Per-resource
/// configuration (delimiter, quote, header row, declared schema) arrives
/// via `FormatHints`.
#[derive(Debug, Default, Clone)]
pub struct CsvFormat;

impl CsvFormat {
    pub fn new() -> Self {
        Self
    }
}

impl Format for CsvFormat {
    fn name(&self) -> &'static str {
        "csv"
    }

    fn decode<'a>(
        &'a self,
        reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
        hints: FormatHints,
    ) -> FormatFuture<'a, DecodedStream> {
        Box::pin(async move { decode_csv(reader, hints).await })
    }
}

// ── Core decode logic ─────────────────────────────────────────────────────────

async fn decode_csv(
    mut reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    hints: FormatHints,
) -> Result<DecodedStream, FormatError> {
    // Step 1: read the full byte stream into memory (V1 accepted cost).
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .await
        .map_err(FormatError::Io)?;

    let declared = hints.declared.clone();

    // Step 2: parse on a blocking thread so the sync `csv` crate does not
    // starve the async executor.
    let result = tokio::task::spawn_blocking(move || {
        parse_csv_blocking(
            bytes,
            hints.header_row,
            hints.delimiter,
            hints.quote,
            &declared,
        )
    })
    .await
    .map_err(|join_err| FormatError::Parse(format!("spawn_blocking panicked: {join_err}")))??;

    let (schema, batch) = result;
    let schema_ref: SchemaRef = Arc::new(schema);

    // Step 3: wrap the single batch in a stream (V1: one batch per decode).
    let batches_stream = stream::once(async move { Ok(batch) });

    Ok(DecodedStream {
        observed_schema: schema_ref,
        batches: Box::pin(batches_stream),
    })
}

// ── Blocking parse (runs in spawn_blocking) ───────────────────────────────────

fn parse_csv_blocking(
    bytes: Vec<u8>,
    header_row: Option<u32>,
    delimiter: Option<u8>,
    quote: Option<u8>,
    declared: &crate::ingest::declared_schema::DeclaredSchema,
) -> Result<(Schema, RecordBatch), FormatError> {
    let delim = delimiter.unwrap_or(b',');
    let q = quote.unwrap_or(b'"');

    // Whether the first row is a header.
    let has_header = header_row.is_some();

    // Build the csv::Reader over the byte slice.
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(delim)
        .quote(q)
        .has_headers(has_header)
        .from_reader(bytes.as_slice());

    // Collect column names: either from the header record or synthesised.
    let column_names: Vec<String> = if has_header {
        rdr.headers()
            .map_err(|e| FormatError::Parse(format!("CSV header error: {e}")))?
            .iter()
            .map(|s| s.to_string())
            .collect()
    } else {
        // Peek at the first record to know the column count, then reset.
        // The `csv` crate positions after headers when has_header=true.
        // With has_header=false, we read the first record to measure width.
        let first_record = {
            let mut records = rdr.records();
            records
                .next()
                .transpose()
                .map_err(|e| FormatError::Parse(format!("CSV first record error: {e}")))?
        };
        match first_record {
            Some(rec) => (0..rec.len()).map(|i| format!("c{i}")).collect(),
            None => {
                // Completely empty file: no columns, no rows.
                return Ok((
                    Schema::empty(),
                    RecordBatch::new_empty(Arc::new(Schema::empty())),
                ));
            }
        }
    };

    let n_cols = column_names.len();

    // Build Arrow field descriptors driven by declared schema (or Utf8 fallback).
    let arrow_fields: Vec<Field> = column_names
        .iter()
        .map(|name| {
            let data_type = declared
                .field(name)
                .map(|f| declared_type_to_arrow(f.ty))
                .unwrap_or(DataType::Utf8);
            Field::new(name.as_str(), data_type, true)
        })
        .collect();

    let schema = Schema::new(arrow_fields.clone());

    // Build one builder per column.
    let mut builders: Vec<ColumnBuilder> = arrow_fields
        .iter()
        .map(|f| ColumnBuilder::for_type(f.data_type()))
        .collect();

    // Replay: for has_header=false we already consumed the first record; we
    // need to rebuild the reader to replay from the top.
    let mut rdr2 = csv::ReaderBuilder::new()
        .delimiter(delim)
        .quote(q)
        .has_headers(has_header)
        .from_reader(bytes.as_slice());

    // Row index for error messages (1-indexed data rows, past any header).
    for (data_row_idx, record_result) in (1_u64..).zip(rdr2.records()) {
        let record = record_result.map_err(|e| {
            FormatError::Parse(format!("CSV record error at row {data_row_idx}: {e}"))
        })?;

        if record.len() != n_cols {
            return Err(FormatError::Parse(format!(
                "row {data_row_idx}: expected {n_cols} columns, got {}",
                record.len()
            )));
        }

        for (col_idx, value) in record.iter().enumerate() {
            let col_name = &column_names[col_idx];
            let declared_field: Option<&DeclaredField> = declared.field(col_name);
            builders[col_idx].push(value, data_row_idx, col_name, declared_field)?;
        }
    }

    // Finalise arrays.
    let arrays: Vec<ArrayRef> = builders.into_iter().map(|b| b.finish()).collect();

    let batch = RecordBatch::try_new(Arc::new(schema.clone()), arrays)
        .map_err(|e| FormatError::Parse(format!("RecordBatch construction failed: {e}")))?;

    Ok((schema, batch))
}

// ── Type mapping ──────────────────────────────────────────────────────────────

fn declared_type_to_arrow(ty: FieldType) -> DataType {
    match ty {
        FieldType::String => DataType::Utf8,
        FieldType::Integer => DataType::Int64,
        FieldType::Number => DataType::Float64,
        FieldType::Boolean => DataType::Boolean,
        FieldType::Date => DataType::Date32,
        FieldType::Timestamp => DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
    }
}

// ── Per-column builder ────────────────────────────────────────────────────────

/// Wraps one of the typed Arrow builders so the column loop can be generic.
enum ColumnBuilder {
    Utf8(StringBuilder),
    Int64(Int64Builder),
    Float64(Float64Builder),
    Boolean(BooleanBuilder),
    Date32(Date32Builder),
    TimestampMs(TimestampMillisecondBuilder),
}

impl ColumnBuilder {
    fn for_type(dt: &DataType) -> Self {
        match dt {
            DataType::Int64 => Self::Int64(Int64Builder::new()),
            DataType::Float64 => Self::Float64(Float64Builder::new()),
            DataType::Boolean => Self::Boolean(BooleanBuilder::new()),
            DataType::Date32 => Self::Date32(Date32Builder::new()),
            DataType::Timestamp(TimeUnit::Millisecond, _) => {
                Self::TimestampMs(TimestampMillisecondBuilder::new().with_timezone("UTC"))
            }
            _ => Self::Utf8(StringBuilder::new()),
        }
    }

    fn push(
        &mut self,
        value: &str,
        row_idx: u64,
        col_name: &str,
        declared_field: Option<&DeclaredField>,
    ) -> Result<(), FormatError> {
        if value.trim().is_empty() && declared_field.is_some_and(|field| field.nullable) {
            match self {
                Self::Utf8(b) => b.append_null(),
                Self::Int64(b) => b.append_null(),
                Self::Float64(b) => b.append_null(),
                Self::Boolean(b) => b.append_null(),
                Self::Date32(b) => b.append_null(),
                Self::TimestampMs(b) => b.append_null(),
            }
            return Ok(());
        }

        match self {
            Self::Utf8(b) => {
                b.append_value(value);
            }
            Self::Int64(b) => {
                let parsed = value.trim().parse::<i64>().map_err(|_| {
                    FormatError::Parse(format!(
                        "row {row_idx}, column {col_name}: cannot parse '{value}' as {}",
                        declared_field
                            .map(|f| format!("{:?}", f.ty))
                            .unwrap_or_else(|| "Integer".to_string())
                    ))
                })?;
                b.append_value(parsed);
            }
            Self::Float64(b) => {
                let parsed = value.trim().parse::<f64>().map_err(|_| {
                    FormatError::Parse(format!(
                        "row {row_idx}, column {col_name}: cannot parse '{value}' as {}",
                        declared_field
                            .map(|f| format!("{:?}", f.ty))
                            .unwrap_or_else(|| "Number".to_string())
                    ))
                })?;
                b.append_value(parsed);
            }
            Self::Boolean(b) => {
                let v = parse_bool(value).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "row {row_idx}, column {col_name}: cannot parse '{value}' as Boolean"
                    ))
                })?;
                b.append_value(v);
            }
            Self::Date32(b) => {
                let date = parse_date(value).map_err(|_| {
                    FormatError::Parse(format!(
                        "row {row_idx}, column {col_name}: cannot parse '{value}' as Date"
                    ))
                })?;
                // Days since Unix epoch (1970-01-01).
                let epoch = Date::from_calendar_date(1970, time::Month::January, 1).unwrap();
                let days = (date - epoch).whole_days() as i32;
                b.append_value(days);
            }
            Self::TimestampMs(b) => {
                let dt = OffsetDateTime::parse(value.trim(), &Rfc3339).map_err(|_| {
                    FormatError::Parse(format!(
                        "row {row_idx}, column {col_name}: cannot parse '{value}' as Timestamp (expected RFC 3339)"
                    ))
                })?;
                let ms = dt.unix_timestamp() * 1_000 + (dt.nanosecond() as i64 / 1_000_000);
                b.append_value(ms);
            }
        }
        Ok(())
    }

    fn finish(self) -> ArrayRef {
        match self {
            Self::Utf8(mut b) => Arc::new(b.finish()),
            Self::Int64(mut b) => Arc::new(b.finish()),
            Self::Float64(mut b) => Arc::new(b.finish()),
            Self::Boolean(mut b) => Arc::new(b.finish()),
            Self::Date32(mut b) => Arc::new(b.finish()),
            Self::TimestampMs(mut b) => Arc::new(b.finish()),
        }
    }
}

// ── Value parsers ─────────────────────────────────────────────────────────────

/// Parse boolean from common string variants, case-insensitive.
/// Accepts: `true|false|1|0|yes|no`.
fn parse_bool(s: &str) -> Option<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

/// Parse ISO 8601 date (`YYYY-MM-DD`).
fn parse_date(s: &str) -> Result<Date, ()> {
    let fmt = format_description!("[year]-[month]-[day]");
    Date::parse(s.trim(), &fmt).map_err(|_| ())
}
