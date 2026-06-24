// SPDX-License-Identifier: Apache-2.0
//! `XlsxFormat`: decode XLSX byte streams to Arrow `RecordBatch`es.
//!
//! Uses `calamine` to parse the workbook. `calamine` is not streaming:
//! the entire workbook is read into memory before the first batch is
//! yielded. `IngestPlan` enforces the max-file-bytes guard before
//! calling `decode`; this module does not enforce it.

use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;

use calamine::{Data, DataType as CalaDataType, ExcelDateTime, ExcelDateTimeType, Reader};
use datafusion::arrow::array::{
    ArrayRef, BooleanBuilder, Date32Builder, Float64Builder, Int64Builder, StringBuilder,
    TimestampMillisecondBuilder,
};
use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use datafusion::arrow::record_batch::RecordBatch;
use futures::stream;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::config::FieldType;
use crate::format::{DecodedStream, Format, FormatError, FormatFuture, FormatHints};

/// Upper bound on the number of cells (rows x columns) calamine is allowed
/// to materialise for one XLSX worksheet.
///
/// Mitigates a decompression-bomb vector. The on-disk size cap
/// (`xlsx_max_*` in [`crate::ingest`]) only bounds the compressed ZIP;
/// an attacker can declare a 26 col x 10M row `<dimension>` element in
/// a kilobyte of XML and watch calamine allocate a 16 GB sparse
/// `Range`. We refuse the workbook *before* calling `worksheet_range`
/// (which itself calls `Range::from_sparse`, the allocating step).
///
/// 10M cells is generous for legitimate use (a 1M-row sheet with 10
/// columns); calibrate down later if real workloads stay well below this.
pub(crate) const MAX_XLSX_CELLS: usize = 10_000_000;

/// Decoder for XLSX input.
#[derive(Debug, Default, Clone)]
pub struct XlsxFormat;

impl XlsxFormat {
    pub fn new() -> Self {
        Self
    }
}

impl Format for XlsxFormat {
    fn name(&self) -> &'static str {
        "xlsx"
    }

    fn decode<'a>(
        &'a self,
        mut reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
        hints: FormatHints,
    ) -> FormatFuture<'a, DecodedStream> {
        Box::pin(async move {
            // Read the full workbook into memory (calamine is non-streaming).
            let mut bytes = Vec::new();
            reader
                .read_to_end(&mut bytes)
                .await
                .map_err(FormatError::Io)?;

            // Parse on a blocking thread: calamine is sync and CPU-bound.
            tokio::task::spawn_blocking(move || decode_xlsx(bytes, hints))
                .await
                .map_err(|join_err| {
                    FormatError::Parse(format!("XLSX decode task panicked: {join_err}"))
                })?
        })
    }
}

// ── Sync decode (runs inside spawn_blocking) ──────────────────────────────────

fn decode_xlsx(bytes: Vec<u8>, hints: FormatHints) -> Result<DecodedStream, FormatError> {
    let cursor = Cursor::new(bytes);
    let mut wb: calamine::Xlsx<_> = calamine::Reader::new(cursor)
        .map_err(|e| FormatError::Parse(format!("failed to open XLSX workbook: {e}")))?;

    // Select the sheet.
    let sheet_name = match &hints.sheet {
        Some(name) => name.clone(),
        None => wb
            .sheet_names()
            .into_iter()
            .next()
            .ok_or_else(|| FormatError::Parse("workbook has no sheets".to_string()))?,
    };

    // Determine row/column window from data_range + header_row.
    // data_range is an A1-notation range like "A5:E10" (1-indexed, inclusive).
    // header_row is 1-indexed. When data_range is given, header_row acts as
    // the absolute row number of the header within the range.
    let (range_start_row, range_start_col, range_end_row, range_end_col) =
        parse_data_range(hints.data_range.as_deref())?;

    // header_row is 1-indexed config value; default is 1.
    let header_row_1indexed: u32 = hints.header_row.unwrap_or(1);

    // ── Decompression-bomb guard (W1-9 follow-up, security review 2026-05-16).
    //
    // The on-disk cap enforced in `crate::ingest` only sees compressed bytes.
    // Before calamine's `worksheet_range` calls `from_sparse` (which allocates
    // `vec![Data::default(); height * width]`), look at the worksheet's
    // declared `<dimension>` element via the cell reader and refuse anything
    // over `MAX_XLSX_CELLS`. A second post-check below catches lying
    // dimensions where the actual cell positions exceed the declared bounds.
    //
    // The error string is deliberately generic: it does not echo the declared
    // cell count, so an attacker probing the cap cannot pull it out of the
    // response.
    {
        let reader = wb
            .worksheet_cells_reader(&sheet_name)
            .map_err(|e| FormatError::Parse(format!("sheet {sheet_name:?} not found: {e}")))?;
        let dims = reader.dimensions();
        let declared_h = (dims.end.0.saturating_sub(dims.start.0) as usize).saturating_add(1);
        let declared_w = (dims.end.1.saturating_sub(dims.start.1) as usize).saturating_add(1);
        let declared_cells = declared_h.saturating_mul(declared_w);
        if declared_cells > MAX_XLSX_CELLS {
            return Err(FormatError::LimitExceeded(
                "xlsx worksheet declared cell count exceeds configured maximum".to_string(),
            ));
        }
    }

    let full_range = wb
        .worksheet_range(&sheet_name)
        .map_err(|e| FormatError::Parse(format!("sheet {sheet_name:?} not found: {e}")))?;

    // Post-check: a workbook can under-declare its `<dimension>` and place
    // real cells outside the advertised range. `Range::get_size` reflects the
    // materialised cells; reject if they exceed the cap even though the
    // declared dimension was small.
    {
        let (h, w) = full_range.get_size();
        if h.saturating_mul(w) > MAX_XLSX_CELLS {
            return Err(FormatError::LimitExceeded(
                "xlsx worksheet materialised cell count exceeds configured maximum".to_string(),
            ));
        }
    }

    // Apply the data_range window if specified.
    // range_start_row/col are 1-indexed; calamine Range uses 0-indexed absolute.
    let (window_row_start, window_col_start, window_row_end, window_col_end) =
        if let Some(((r0, c0), (r1, c1))) = range_start_row
            .zip(range_start_col)
            .zip(range_end_row.zip(range_end_col))
        {
            // Convert 1-indexed range to 0-indexed.
            (r0 - 1, c0 - 1, r1 - 1, c1 - 1)
        } else {
            // No data_range: use full sheet extent.
            let (h, w) = full_range.get_size();
            if h == 0 || w == 0 {
                return empty_decoded_stream();
            }
            let (start_row, start_col) = full_range.start().unwrap_or((0, 0));
            let (end_row, end_col) = full_range.end().unwrap_or((0, 0));
            (start_row, start_col, end_row, end_col)
        };

    reject_formula_cells_in_window(
        &mut wb,
        &sheet_name,
        window_row_start,
        window_col_start,
        window_row_end,
        window_col_end,
    )?;

    // The header row within the window (0-indexed within the full range).
    // header_row_1indexed is relative to the workbook sheet row numbers (1-indexed).
    // When data_range is given, header is expected to be inside the range.
    let header_abs_row: u32 = if hints.data_range.is_some() {
        // header_row_1indexed is the sheet row number; convert to 0-indexed.
        header_row_1indexed.saturating_sub(1)
    } else {
        // Without data_range, header is relative to the sheet start.
        window_row_start + header_row_1indexed.saturating_sub(1)
    };

    // Build column name list from the header row.
    let col_names: Vec<String> = {
        let mut names = Vec::new();
        for col in window_col_start..=window_col_end {
            let cell = full_range
                .get((header_abs_row as usize, col as usize))
                .unwrap_or(&Data::Empty);
            let name = match cell {
                Data::String(s) => s.clone(),
                Data::Int(i) => i.to_string(),
                Data::Float(f) => f.to_string(),
                other if !CalaDataType::is_empty(other) => format!("{other}"),
                _ => format!("c{}", col - window_col_start),
            };
            names.push(name);
        }
        names
    };

    // Build the Arrow schema from declared types or inference.
    let declared = &hints.declared;
    let arrow_fields: Vec<Field> = col_names
        .iter()
        .map(|name| {
            let dt = declared
                .field(name)
                .map(|f| declared_to_arrow(f.ty))
                .unwrap_or(DataType::Utf8);
            Field::new(name.as_str(), dt, true)
        })
        .collect();
    let schema = Arc::new(Schema::new(arrow_fields));

    // Collect data rows: rows after the header row, within the window.
    let data_row_start = header_abs_row + 1;
    let data_rows: Vec<Vec<Data>> = (data_row_start..=window_row_end)
        .map(|row_idx| {
            (window_col_start..=window_col_end)
                .map(|col_idx| {
                    full_range
                        .get((row_idx as usize, col_idx as usize))
                        .cloned()
                        .unwrap_or(Data::Empty)
                })
                .collect()
        })
        .collect();

    // Build Arrow arrays column by column.
    let arrays = build_arrow_arrays(&schema, &col_names, &data_rows)?;

    let batch = RecordBatch::try_new(schema.clone(), arrays)
        .map_err(|e| FormatError::Parse(format!("failed to build RecordBatch: {e}")))?;

    Ok(DecodedStream {
        observed_schema: schema as SchemaRef,
        batches: Box::pin(stream::iter(vec![Ok(batch)])),
    })
}

// ── Arrow array builder ───────────────────────────────────────────────────────

fn build_arrow_arrays(
    schema: &Schema,
    col_names: &[String],
    data_rows: &[Vec<Data>],
) -> Result<Vec<ArrayRef>, FormatError> {
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(col_names.len());

    for (col_idx, col_name) in col_names.iter().enumerate() {
        let arrow_type = schema.field(col_idx).data_type();

        let col_data: Vec<&Data> = data_rows.iter().map(|row| &row[col_idx]).collect();

        let array: ArrayRef = match arrow_type {
            DataType::Int64 => build_int64_col(col_name, &col_data)?,
            DataType::Float64 => build_float64_col(col_name, &col_data)?,
            DataType::Boolean => build_bool_col(col_name, &col_data)?,
            DataType::Date32 => build_date32_col(col_name, &col_data)?,
            DataType::Timestamp(TimeUnit::Millisecond, _) => {
                build_timestamp_millis_col(col_name, &col_data)?
            }
            DataType::Utf8 => build_utf8_col(&col_data),
            other => {
                return Err(FormatError::Parse(format!(
                    "unsupported Arrow type {other:?} for column {col_name:?}"
                )));
            }
        };

        arrays.push(array);
    }

    Ok(arrays)
}

fn build_int64_col(col_name: &str, col_data: &[&Data]) -> Result<ArrayRef, FormatError> {
    let mut builder = Int64Builder::new();
    for (row_idx, cell) in col_data.iter().enumerate() {
        match *cell {
            Data::Empty => builder.append_null(),
            other => {
                let v = CalaDataType::as_i64(other).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: cannot coerce {other:?} to Integer",
                        row_idx + 2 // +2: 1-indexed + skip header
                    ))
                })?;
                builder.append_value(v);
            }
        }
    }
    Ok(Arc::new(builder.finish()))
}

fn build_float64_col(col_name: &str, col_data: &[&Data]) -> Result<ArrayRef, FormatError> {
    let mut builder = Float64Builder::new();
    for (row_idx, cell) in col_data.iter().enumerate() {
        match *cell {
            Data::Empty => builder.append_null(),
            other => {
                let v = CalaDataType::as_f64(other).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: cannot coerce {other:?} to Number",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(v);
            }
        }
    }
    Ok(Arc::new(builder.finish()))
}

fn build_bool_col(col_name: &str, col_data: &[&Data]) -> Result<ArrayRef, FormatError> {
    let mut builder = BooleanBuilder::new();
    for (row_idx, cell) in col_data.iter().enumerate() {
        match cell {
            Data::Empty => builder.append_null(),
            Data::Bool(b) => builder.append_value(*b),
            Data::Int(i) => builder.append_value(*i != 0),
            Data::Float(f) => builder.append_value(*f != 0.0),
            Data::String(s) => {
                let v = parse_bool_str(s).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: cannot coerce {s:?} to Boolean",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(v);
            }
            other => {
                return Err(FormatError::Parse(format!(
                    "column {col_name:?}, row {}: cannot coerce {other:?} to Boolean",
                    row_idx + 2
                )));
            }
        }
    }
    Ok(Arc::new(builder.finish()))
}

fn parse_bool_str(s: &str) -> Option<bool> {
    match s.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Some(true),
        "false" | "no" | "0" | "off" => Some(false),
        _ => None,
    }
}

fn build_date32_col(col_name: &str, col_data: &[&Data]) -> Result<ArrayRef, FormatError> {
    let mut builder = Date32Builder::new();
    for (row_idx, cell) in col_data.iter().enumerate() {
        match cell {
            Data::Empty => builder.append_null(),
            Data::DateTime(edt) => {
                let days = excel_datetime_to_date32(*edt).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: Excel date serial out of range",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(days);
            }
            Data::DateTimeIso(s) => {
                let days = parse_date_string_to_days(s).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: cannot parse {s:?} as Date",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(days);
            }
            Data::String(s) => {
                let days = parse_date_string_to_days(s).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: cannot parse {s:?} as Date",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(days);
            }
            Data::Float(f) => {
                // Excel stores dates as float serials too.
                let edt = ExcelDateTime::new(*f, ExcelDateTimeType::DateTime, false);
                let days = excel_datetime_to_date32(edt).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: Excel date serial {f} out of range",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(days);
            }
            Data::Int(i) => {
                let edt = ExcelDateTime::new(*i as f64, ExcelDateTimeType::DateTime, false);
                let days = excel_datetime_to_date32(edt).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: Excel date serial {i} out of range",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(days);
            }
            other => {
                return Err(FormatError::Parse(format!(
                    "column {col_name:?}, row {}: cannot coerce {other:?} to Date",
                    row_idx + 2
                )));
            }
        }
    }
    Ok(Arc::new(builder.finish()))
}

/// Convert an `ExcelDateTime` to days since UNIX epoch (Arrow Date32).
fn excel_datetime_to_date32(edt: ExcelDateTime) -> Option<i32> {
    let (year, month, day, _, _, _, _) = edt.to_ymd_hms_milli();
    ymd_to_unix_days(year as i32, month as u32, day as u32)
}

/// Convert a date string (RFC 3339 / ISO 8601 date) to days since UNIX epoch.
fn parse_date_string_to_days(s: &str) -> Option<i32> {
    // Accept "YYYY-MM-DD" and "YYYY-MM-DDTHH:MM:SSZ" (truncate to date).
    let date_part = if let Some(t_pos) = s.find('T') {
        &s[..t_pos]
    } else {
        s.trim()
    };
    let parts: Vec<&str> = date_part.splitn(3, '-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: i32 = parts[0].parse().ok()?;
    let month: u32 = parts[1].parse().ok()?;
    let day: u32 = parts[2].parse().ok()?;
    ymd_to_unix_days(year, month, day)
}

/// Convert year/month/day to days since UNIX epoch (1970-01-01), i32 (Arrow Date32).
fn ymd_to_unix_days(year: i32, month: u32, day: u32) -> Option<i32> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // Days from a proleptic Gregorian year start.
    let days_before_year = |y: i64| -> i64 {
        let y = y - 1;
        365 * y + y / 4 - y / 100 + y / 400
    };
    let is_leap = |y: i32| -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 };
    let days_in_months: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut doy = 0u32;
    for m in 0..(month - 1) {
        doy += days_in_months[m as usize];
    }
    if month > 2 && is_leap(year) {
        doy += 1;
    }
    doy += day;

    let unix_days = days_before_year(year as i64) + doy as i64 - days_before_year(1970) - 1;
    i32::try_from(unix_days).ok()
}

fn build_timestamp_millis_col(col_name: &str, col_data: &[&Data]) -> Result<ArrayRef, FormatError> {
    let mut builder = TimestampMillisecondBuilder::new().with_timezone("UTC".to_string());
    for (row_idx, cell) in col_data.iter().enumerate() {
        match cell {
            Data::Empty => builder.append_null(),
            Data::DateTime(edt) => {
                let ms = excel_datetime_to_millis(*edt).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: Excel datetime out of range",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(ms);
            }
            Data::DateTimeIso(s) | Data::String(s) => {
                let ms = parse_rfc3339_to_millis(s).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: cannot parse {s:?} as Timestamp",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(ms);
            }
            Data::Float(f) => {
                let edt = ExcelDateTime::new(*f, ExcelDateTimeType::DateTime, false);
                let ms = excel_datetime_to_millis(edt).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: Excel datetime serial {f} out of range",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(ms);
            }
            Data::Int(i) => {
                let edt = ExcelDateTime::new(*i as f64, ExcelDateTimeType::DateTime, false);
                let ms = excel_datetime_to_millis(edt).ok_or_else(|| {
                    FormatError::Parse(format!(
                        "column {col_name:?}, row {}: Excel datetime serial {i} out of range",
                        row_idx + 2
                    ))
                })?;
                builder.append_value(ms);
            }
            other => {
                return Err(FormatError::Parse(format!(
                    "column {col_name:?}, row {}: cannot coerce {other:?} to Timestamp",
                    row_idx + 2
                )));
            }
        }
    }
    Ok(Arc::new(builder.finish()))
}

/// Convert an `ExcelDateTime` to milliseconds since UNIX epoch.
///
/// Excel's epoch is 1900-01-00 (with the infamous 1900 leap-year bug).
/// We use `to_ymd_hms_milli()` to get clean Gregorian components, then
/// convert to a UNIX timestamp.
fn excel_datetime_to_millis(edt: ExcelDateTime) -> Option<i64> {
    let (year, month, day, hour, min, sec, milli) = edt.to_ymd_hms_milli();
    let date_days = ymd_to_unix_days(year as i32, month as u32, day as u32)?;
    let time_ms =
        (hour as i64) * 3_600_000 + (min as i64) * 60_000 + (sec as i64) * 1_000 + (milli as i64);
    Some((date_days as i64) * 86_400_000 + time_ms)
}

/// Parse an RFC 3339 / ISO 8601 string to milliseconds since UNIX epoch.
fn parse_rfc3339_to_millis(s: &str) -> Option<i64> {
    let dt = OffsetDateTime::parse(s.trim(), &Rfc3339).ok()?;
    let nanos = dt.unix_timestamp_nanos();
    i64::try_from(nanos.div_euclid(1_000_000)).ok()
}

fn build_utf8_col(col_data: &[&Data]) -> ArrayRef {
    let mut builder = StringBuilder::new();
    for cell in col_data.iter() {
        match cell {
            Data::Empty => builder.append_null(),
            Data::String(s) => builder.append_value(s.as_str()),
            Data::Int(i) => builder.append_value(i.to_string()),
            Data::Float(f) => builder.append_value(f.to_string()),
            Data::Bool(b) => builder.append_value(b.to_string()),
            Data::DateTime(edt) => {
                let (y, mo, d, h, mi, s, ms) = edt.to_ymd_hms_milli();
                builder.append_value(format!(
                    "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{ms:03}Z"
                ));
            }
            Data::DateTimeIso(s) => builder.append_value(s.as_str()),
            Data::DurationIso(s) => builder.append_value(s.as_str()),
            Data::Error(e) => builder.append_value(format!("{e}")),
        }
    }
    Arc::new(builder.finish())
}

fn reject_formula_cells_in_window(
    wb: &mut calamine::Xlsx<Cursor<Vec<u8>>>,
    sheet_name: &str,
    window_row_start: u32,
    window_col_start: u32,
    window_row_end: u32,
    window_col_end: u32,
) -> Result<(), FormatError> {
    let mut reader = wb
        .worksheet_cells_reader(sheet_name)
        .map_err(|e| FormatError::Parse(format!("failed to inspect XLSX formulas: {e}")))?;

    while let Some(cell) = reader
        .next_formula()
        .map_err(|e| FormatError::Parse(format!("failed to inspect XLSX formulas: {e}")))?
    {
        if cell.get_value().is_empty() {
            continue;
        }
        let (row, col) = cell.get_position();
        if row >= window_row_start
            && row <= window_row_end
            && col >= window_col_start
            && col <= window_col_end
        {
            return Err(FormatError::Parse(
                "xlsx worksheet contains formula cell within configured range".to_string(),
            ));
        }
    }

    Ok(())
}

// ── Range parsing ─────────────────────────────────────────────────────────────

/// `(start_row, start_col, end_row, end_col)`, all 1-indexed in sheet
/// coordinates. `None` means the component was not specified (no range hint).
type RangeWindow = (Option<u32>, Option<u32>, Option<u32>, Option<u32>);

/// Parse an A1-notation range like "A5:E10" into 1-indexed (row, col) pairs.
/// Returns `(start_row, start_col, end_row, end_col)`, all 1-indexed and
/// wrapped in `Option` so the caller can detect absent components.
fn parse_data_range(s: Option<&str>) -> Result<RangeWindow, FormatError> {
    let Some(s) = s else {
        return Ok((None, None, None, None));
    };
    let s = s.trim().to_ascii_uppercase();
    let parts: Vec<&str> = s.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(FormatError::Parse(format!(
            "invalid data_range {s:?}: expected A1:B2 notation"
        )));
    }
    let (r0, c0) = parse_cell_ref(parts[0])
        .ok_or_else(|| FormatError::Parse(format!("invalid cell reference {:?}", parts[0])))?;
    let (r1, c1) = parse_cell_ref(parts[1])
        .ok_or_else(|| FormatError::Parse(format!("invalid cell reference {:?}", parts[1])))?;
    Ok((Some(r0), Some(c0), Some(r1), Some(c1)))
}

/// Parse an A1-notation cell reference (e.g. "A5", "AB100") into
/// 1-indexed (row, col).
fn parse_cell_ref(s: &str) -> Option<(u32, u32)> {
    let col_str: String = s.chars().take_while(|c| c.is_ascii_alphabetic()).collect();
    let row_str: String = s.chars().skip_while(|c| c.is_ascii_alphabetic()).collect();
    if col_str.is_empty() || row_str.is_empty() {
        return None;
    }
    let col = col_letters_to_number(&col_str)?;
    let row: u32 = row_str.parse().ok()?;
    Some((row, col))
}

/// Convert column letters (A=1, B=2, ..., Z=26, AA=27, ...) to a 1-indexed
/// column number.
fn col_letters_to_number(s: &str) -> Option<u32> {
    let mut n: u32 = 0;
    for c in s.chars() {
        if !c.is_ascii_alphabetic() {
            return None;
        }
        let v = (c.to_ascii_uppercase() as u32) - ('A' as u32) + 1;
        n = n.checked_mul(26)?.checked_add(v)?;
    }
    Some(n)
}

/// Returns an empty `DecodedStream` with an empty schema.
fn empty_decoded_stream() -> Result<DecodedStream, FormatError> {
    use datafusion::arrow::datatypes::Schema;
    let schema = Arc::new(Schema::empty());
    let batch = RecordBatch::new_empty(schema.clone());
    Ok(DecodedStream {
        observed_schema: schema as SchemaRef,
        batches: Box::pin(stream::iter(vec![Ok(batch)])),
    })
}

/// Map a `FieldType` to its corresponding Arrow `DataType`.
fn declared_to_arrow(ty: FieldType) -> DataType {
    match ty {
        FieldType::String => DataType::Utf8,
        FieldType::Integer => DataType::Int64,
        FieldType::Number => DataType::Float64,
        FieldType::Boolean => DataType::Boolean,
        FieldType::Date => DataType::Date32,
        FieldType::Timestamp => DataType::Timestamp(TimeUnit::Millisecond, Some("UTC".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339_to_millis;

    #[test]
    fn parses_rfc3339_negative_utc_offset_as_utc_millis() {
        assert_eq!(
            parse_rfc3339_to_millis("2024-01-01T00:30:00-02:00"),
            parse_rfc3339_to_millis("2024-01-01T02:30:00Z")
        );
    }
}
