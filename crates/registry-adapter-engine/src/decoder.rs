// SPDX-License-Identifier: Apache-2.0

//! The bounded decoders of the governed-ingestion read step
//! (`products/adapter/CONCEPT.md` sections 8.10 and 17.2): the port of
//! Camel's `CsvDataFormat` restricted to a bounded row decoder, the
//! `jsonl` addition under section 5.4, and the `raw` fallback.
//!
//! Deterministic rules every decoder shares: values are strings, never
//! inferred, so leading zeros and quoted multiline fields survive; a
//! read stops at the profile's rows bound and reports where it stopped,
//! so the next read resumes at the byte offset after the last emitted
//! row; a malformed CSV record fails the read under
//! `adapter.job.decoder-row` naming the record's index only, and the
//! next read re-encounters it and fails again the same way; CSV and JSONL
//! rows take identity from one declared RFC 6901 pointer selecting an opaque
//! string, never from the file digest or row position; a malformed JSONL line
//! is counted and the remaining lines continue, the count leaving the page
//! through the job entry's side channel. A record over
//! the row bound or a field over the field bound fails the read under
//! `adapter.job.read-bound`, never a partial row; the CSV header record
//! holds the same bounds, and a JSONL field is any string or member name
//! of the line's value, at any depth.
//!
//! Port record: the decoder options and defaults are
//! camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java
//! as landed in `registry_adapter_core::CsvDecoder`; the row identity,
//! per-record refusal, and paged decoding are original work Camel does
//! not supply (`products/adapter/CONCEPT.md` section 17.2).

use std::collections::HashSet;

use registry_adapter_core::{
    CsvDecoder, ReadBounds, SourceItem, FILE_ROW_IDENTITY_VERSION, MAXIMUM_ITEM_KEY_BYTES,
};

/// The decoder a read applies to one file's bytes.
#[derive(Clone, Debug)]
pub(crate) enum Decoder {
    /// One item per file: the file's name and size, the digest riding the
    /// key and the cursor.
    Raw,
    /// Comma-separated rows under the landed options.
    Csv {
        options: CsvDecoder,
        key_pointer: String,
    },
    /// One bounded JSON value per line.
    Jsonl { key_pointer: String },
}

/// One decoded page: the rows emitted, the byte offset the next read
/// resumes at, whether the file's rows are exhausted, and how many
/// malformed JSONL lines the page skipped.
pub(crate) struct DecodedPage {
    pub(crate) items: Vec<SourceItem>,
    /// The byte offset after the last emitted row; zero when no row was
    /// emitted. A completed file's cursor carries the file's length
    /// beside this, so the next read starts past it.
    pub(crate) position: u64,
    /// Whether the file carries no rows beyond `position`.
    pub(crate) complete: bool,
    pub(crate) malformed_lines: u32,
}

pub(crate) struct DecodeInput<'input> {
    pub(crate) namespace: &'input str,
    pub(crate) digest: &'input str,
    pub(crate) name: &'input str,
    pub(crate) bytes: &'input [u8],
}

/// Why a decode refused the read. The route failure carries the class;
/// the processor carries the code beside it.
#[derive(Debug)]
pub(crate) enum DecoderFault {
    /// A malformed record: the read fails and the next read re-fails
    /// deterministically at the same bytes. The payload is the record's
    /// 0-based index over every record of the file, header included,
    /// the one value the refusal may name.
    Row(u64),
    /// The declared business-key pointer did not select a member of this
    /// decoded record.
    KeyMissing(u64),
    /// The selected business key was not a non-empty string whose encoded
    /// source-item key fits the existing bound.
    KeyInvalid(u64),
    /// A second record in the same file selected the same business key.
    KeyDuplicate(u64),
    /// A record or field over the profile's read bounds.
    Bound,
    /// A CSV syntax character (delimiter, quote, or comment marker)
    /// outside ASCII, which no single CSV byte can carry.
    Syntax,
    /// The asynchronous caller abandoned the blocking decode. This never
    /// becomes a route diagnostic: the abandoned result has no receiver.
    Cancelled,
}

/// Decode one file's rows from `resume`, the byte offset after the last
/// row the previous page emitted (zero on the first read). The whole
/// file is in memory under the read bounds, so the header record and
/// every resume offset are exact; the page is bounded by
/// `bounds.maximum_rows_per_page`.
#[cfg(test)]
pub(crate) fn decode(
    decoder: &Decoder,
    namespace: &str,
    digest: &str,
    name: &str,
    bytes: &[u8],
    resume: u64,
    bounds: &ReadBounds,
) -> Result<DecodedPage, DecoderFault> {
    decode_with_cancellation(
        decoder,
        DecodeInput {
            namespace,
            digest,
            name,
            bytes,
        },
        resume,
        bounds,
        &|| false,
    )
}

pub(crate) fn decode_with_cancellation(
    decoder: &Decoder,
    input: DecodeInput<'_>,
    resume: u64,
    bounds: &ReadBounds,
    cancelled: &dyn Fn() -> bool,
) -> Result<DecodedPage, DecoderFault> {
    match decoder {
        Decoder::Raw => Ok(DecodedPage {
            items: vec![SourceItem {
                key: format!("{}:{}", input.namespace, input.digest),
                revision: None,
                value: serde_json::json!({ "name": input.name, "bytes": input.bytes.len() }),
            }],
            position: input.bytes.len() as u64,
            complete: true,
            malformed_lines: 0,
        }),
        Decoder::Csv {
            options,
            key_pointer,
        } => decode_csv(
            options,
            key_pointer,
            input.namespace,
            input.bytes,
            resume,
            bounds,
            cancelled,
        ),
        Decoder::Jsonl { key_pointer } => decode_jsonl(
            key_pointer,
            input.namespace,
            input.bytes,
            resume,
            bounds,
            cancelled,
        ),
    }
}

/// Decode CSV rows. The reader walks every record from the file's start,
/// which keeps the header record and each record's byte offsets exact,
/// and emits from the resume offset on. Record refusals use a 0-based
/// ordinal over every record the walk reads, header included. Row identity
/// instead comes from the declared business-key pointer. The walk makes
/// one page cost O(file bytes), bounded by `maximumFileBytes`; the file
/// source records that cost beside its paging rules.
fn decode_csv(
    options: &CsvDecoder,
    key_pointer: &str,
    namespace: &str,
    bytes: &[u8],
    resume: u64,
    bounds: &ReadBounds,
    cancelled: &dyn Fn() -> bool,
) -> Result<DecodedPage, DecoderFault> {
    let mut reader = BoundedCsvReader::new(options)?;
    let maximum_rows = bounds.maximum_rows_per_page.get() as usize;
    let mut items = Vec::new();
    let mut header: Option<Vec<String>> = None;
    let mut key_index: Option<usize> = None;
    let mut keys = HashSet::new();
    let mut key_string_capacity = 0_usize;
    let mut ordinal = 0_u64;
    let mut emitted_end = resume;
    let mut page_overflow = false;
    while let Some((record, record_end)) = reader.next_record(bytes, bounds, cancelled)? {
        if ordinal == 0 && options.header {
            header = Some(header_names(&record, ordinal)?);
            key_index = Some(csv_key_index(header.as_deref(), key_pointer, ordinal)?);
            ordinal += 1;
            continue;
        }
        if key_index.is_none() {
            key_index = Some(csv_key_index(None, key_pointer, ordinal)?);
        }
        validate_csv_record(&record, header.as_deref(), ordinal)?;
        let index = key_index.expect("the key index was resolved above");
        let business_key = match header.as_deref() {
            Some(_) => record.get(index).map_or(&[][..], Box::as_ref),
            None => record
                .get(index)
                .map(Box::as_ref)
                .ok_or(DecoderFault::KeyMissing(ordinal))?,
        };
        let business_key =
            std::str::from_utf8(business_key).map_err(|_| DecoderFault::KeyInvalid(ordinal))?;
        let key = encode_row_key(namespace, business_key, ordinal)?;
        insert_business_key(
            &mut keys,
            &mut key_string_capacity,
            business_key,
            bounds.maximum_file_bytes.get() as usize,
            ordinal,
        )?;

        if record_end > resume {
            if items.len() < maximum_rows {
                items.push(SourceItem {
                    key,
                    revision: None,
                    value: csv_record_value(&record, header.as_deref(), ordinal)?,
                });
                emitted_end = record_end;
            } else {
                page_overflow = true;
            }
        }
        ordinal += 1;
    }
    Ok(DecodedPage {
        items,
        position: emitted_end,
        complete: !page_overflow,
        malformed_lines: 0,
    })
}

const CSV_INPUT_CHUNK_BYTES: usize = 64 * 1024;
const CSV_OUTPUT_CHUNK_BYTES: usize = 8 * 1024;

type CsvRecord = Vec<Box<[u8]>>;

struct BoundedCsvReader {
    reader: csv_core::Reader,
    offset: usize,
    trim: bool,
}

impl BoundedCsvReader {
    fn new(options: &CsvDecoder) -> Result<Self, DecoderFault> {
        let mut builder = csv_core::ReaderBuilder::new();
        builder
            .delimiter(ascii_byte(options.delimiter)?)
            .quote(ascii_byte(options.quote)?)
            .quoting(!options.quote_disabled)
            .comment(options.comment_marker.map(ascii_byte).transpose()?);
        Ok(Self {
            reader: builder.build(),
            offset: 0,
            trim: options.trim,
        })
    }

    fn next_record(
        &mut self,
        bytes: &[u8],
        bounds: &ReadBounds,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<(CsvRecord, u64)>, DecoderFault> {
        let maximum_field_bytes = bounds.maximum_field_bytes.get() as usize;
        let maximum_row_bytes = bounds.maximum_row_bytes.get() as usize;
        let mut record = Vec::new();
        let mut record_value_bytes = 0_usize;
        let mut field = BoundedCsvField::default();
        let mut output = [0_u8; CSV_OUTPUT_CHUNK_BYTES];
        loop {
            if cancelled() {
                return Err(DecoderFault::Cancelled);
            }
            let input_end = self
                .offset
                .saturating_add(CSV_INPUT_CHUNK_BYTES)
                .min(bytes.len());
            let input = &bytes[self.offset..input_end];
            let (result, consumed, written) = self.reader.read_field(input, &mut output);
            self.offset = self.offset.saturating_add(consumed);
            field.push(&output[..written], self.trim, maximum_field_bytes)?;
            match result {
                csv_core::ReadFieldResult::InputEmpty | csv_core::ReadFieldResult::OutputFull => {
                    continue
                }
                csv_core::ReadFieldResult::Field { record_end } => {
                    let value = field.finish();
                    let next_value_bytes = record_value_bytes.saturating_add(value.len());
                    let structural_bytes = record
                        .len()
                        .saturating_add(1)
                        .saturating_mul(std::mem::size_of::<Box<[u8]>>());
                    if next_value_bytes.saturating_add(structural_bytes) > maximum_row_bytes {
                        return Err(DecoderFault::Bound);
                    }
                    record_value_bytes = next_value_bytes;
                    record.push(value);
                    field = BoundedCsvField::default();
                    if record_end {
                        return Ok(Some((record, self.offset as u64)));
                    }
                }
                csv_core::ReadFieldResult::End => return Ok(None),
            }
        }
    }
}

#[derive(Default)]
struct BoundedCsvField {
    value: Vec<u8>,
    pending_whitespace: Vec<u8>,
    pending_overflow: bool,
    started: bool,
}

impl BoundedCsvField {
    fn push(&mut self, bytes: &[u8], trim: bool, maximum: usize) -> Result<(), DecoderFault> {
        if !trim {
            if self.value.len().saturating_add(bytes.len()) > maximum {
                return Err(DecoderFault::Bound);
            }
            self.value.extend_from_slice(bytes);
            return Ok(());
        }
        for byte in bytes {
            if byte.is_ascii_whitespace() {
                if !self.started {
                    continue;
                }
                if self
                    .value
                    .len()
                    .saturating_add(self.pending_whitespace.len())
                    < maximum
                {
                    self.pending_whitespace.push(*byte);
                } else {
                    self.pending_overflow = true;
                }
                continue;
            }
            if self.pending_overflow
                || self
                    .value
                    .len()
                    .saturating_add(self.pending_whitespace.len())
                    .saturating_add(1)
                    > maximum
            {
                return Err(DecoderFault::Bound);
            }
            self.value.append(&mut self.pending_whitespace);
            self.value.push(*byte);
            self.started = true;
        }
        Ok(())
    }

    fn finish(self) -> Box<[u8]> {
        self.value.into_boxed_slice()
    }
}

/// One CSV syntax character as the single byte the reader takes. Only
/// ASCII fits one byte; anything wider refuses rather than truncating to
/// another byte. The check refuses the same declaration at compile, so
/// this holds the line for a hand-built decoder.
fn ascii_byte(character: char) -> Result<u8, DecoderFault> {
    if character.is_ascii() {
        u8::try_from(character).map_err(|_| DecoderFault::Syntax)
    } else {
        Err(DecoderFault::Syntax)
    }
}

/// The header record's names, refusing a duplicate name that would fold
/// two columns into one map member.
fn header_names(record: &CsvRecord, ordinal: u64) -> Result<Vec<String>, DecoderFault> {
    let mut names = Vec::with_capacity(record.len());
    for field in record {
        let name = field_text(field, ordinal)?;
        if names.contains(&name) {
            return Err(DecoderFault::Row(ordinal));
        }
        names.push(name);
    }
    Ok(names)
}

/// Validate every decoded field as UTF-8 and the CSV row shape before key
/// selection. A short header row still pads with empty strings; a longer row
/// refuses before any page escapes.
fn validate_csv_record(
    record: &CsvRecord,
    header: Option<&[String]>,
    ordinal: u64,
) -> Result<(), DecoderFault> {
    if header.is_some_and(|names| record.len() > names.len()) {
        return Err(DecoderFault::Row(ordinal));
    }
    for field in record {
        std::str::from_utf8(field).map_err(|_| DecoderFault::Row(ordinal))?;
    }
    Ok(())
}

/// One bounded record as its page value: a map keyed by the header record,
/// or a bare array when the file declares no header.
fn csv_record_value(
    record: &CsvRecord,
    header: Option<&[String]>,
    ordinal: u64,
) -> Result<serde_json::Value, DecoderFault> {
    match header {
        Some(names) => {
            let mut members = serde_json::Map::new();
            for (index, name) in names.iter().enumerate() {
                let text = record
                    .get(index)
                    .map(|field| field_text(field.as_ref(), ordinal))
                    .transpose()?
                    .unwrap_or_default();
                members.insert(name.clone(), serde_json::Value::String(text));
            }
            Ok(serde_json::Value::Object(members))
        }
        None => {
            let mut fields = Vec::with_capacity(record.len());
            for field in record {
                fields.push(serde_json::Value::String(field_text(field, ordinal)?));
            }
            Ok(serde_json::Value::Array(fields))
        }
    }
}

/// A field's text: the file's bytes are UTF-8 only, so anything else is
/// a malformed record.
fn field_text(field: &[u8], ordinal: u64) -> Result<String, DecoderFault> {
    std::str::from_utf8(field)
        .map(str::to_owned)
        .map_err(|_| DecoderFault::Row(ordinal))
}

/// Insert one exact business key under an explicit whole-index budget. The
/// charge includes actual string capacity and a deliberately conservative
/// hash bucket count, including the stored `String`, hash/control overhead,
/// and spare capacity. This makes both bytes and entry count finite under the
/// existing maximum-file-bytes ceiling.
fn insert_business_key(
    keys: &mut HashSet<String>,
    string_capacity: &mut usize,
    business_key: &str,
    budget: usize,
    ordinal: u64,
) -> Result<(), DecoderFault> {
    if keys.contains(business_key) {
        return Err(DecoderFault::KeyDuplicate(ordinal));
    }
    let next_len = keys.len().saturating_add(1);
    let conservative_buckets = next_len.next_power_of_two().saturating_mul(2).max(4);
    let bucket_charge = std::mem::size_of::<String>()
        .saturating_add(std::mem::size_of::<usize>())
        .saturating_add(1);
    let preallocation_charge = string_capacity
        .saturating_add(business_key.len())
        .saturating_add(conservative_buckets.saturating_mul(bucket_charge));
    if preallocation_charge > budget {
        return Err(DecoderFault::Bound);
    }

    keys.reserve(1);
    let owned = business_key.to_owned();
    let actual_string_capacity = owned.capacity();
    let actual_buckets = keys.capacity().max(conservative_buckets);
    let actual_charge = string_capacity
        .saturating_add(actual_string_capacity)
        .saturating_add(actual_buckets.saturating_mul(bucket_charge));
    if actual_charge > budget {
        return Err(DecoderFault::Bound);
    }
    *string_capacity = string_capacity.saturating_add(actual_string_capacity);
    let inserted = keys.insert(owned);
    debug_assert!(
        inserted,
        "the borrowed duplicate check ran before insertion"
    );
    Ok(())
}

/// Resolve the single member an RFC 6901 pointer can select from a decoded
/// CSV row. CSV rows are flat objects with headers or flat arrays without
/// them, so a deeper pointer is necessarily missing rather than a second
/// expression language.
fn csv_key_index(
    header: Option<&[String]>,
    key_pointer: &str,
    ordinal: u64,
) -> Result<usize, DecoderFault> {
    let token = single_pointer_token(key_pointer).ok_or(DecoderFault::KeyMissing(ordinal))?;
    match header {
        Some(names) => names
            .iter()
            .position(|name| name == &token)
            .ok_or(DecoderFault::KeyMissing(ordinal)),
        None => {
            if token.is_empty()
                || (token.len() > 1 && token.starts_with('0'))
                || !token.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(DecoderFault::KeyMissing(ordinal));
            }
            token
                .parse::<usize>()
                .map_err(|_| DecoderFault::KeyMissing(ordinal))
        }
    }
}

/// Decode one RFC 6901 pointer token, rejecting a root pointer, a nested
/// pointer, and malformed `~` escapes. The authoring checks hold the general
/// pointer syntax; this decoder narrows it to CSV's flat row shape.
fn single_pointer_token(pointer: &str) -> Option<String> {
    let token = pointer.strip_prefix('/')?;
    if token.contains('/') {
        return None;
    }
    let mut decoded = String::with_capacity(token.len());
    let mut characters = token.chars();
    while let Some(character) = characters.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match characters.next()? {
            '0' => decoded.push('~'),
            '1' => decoded.push('/'),
            _ => return None,
        }
    }
    Some(decoded)
}

/// Select and encode one row's exact business key. Strings are never parsed
/// or coerced, so lexical identifiers such as `00123` remain distinct from
/// `123`.
fn row_key(
    value: &serde_json::Value,
    key_pointer: &str,
    namespace: &str,
    ordinal: u64,
) -> Result<String, DecoderFault> {
    encode_row_key(
        namespace,
        selected_business_key(value, key_pointer, ordinal)?,
        ordinal,
    )
}

fn selected_business_key<'value>(
    value: &'value serde_json::Value,
    key_pointer: &str,
    ordinal: u64,
) -> Result<&'value str, DecoderFault> {
    value
        .pointer(key_pointer)
        .ok_or(DecoderFault::KeyMissing(ordinal))?
        .as_str()
        .ok_or(DecoderFault::KeyInvalid(ordinal))
}

/// Namespace a business key without an ambiguous separator boundary. The
/// byte-length prefix is deterministic across transports and the version tag
/// makes legacy positional keys visibly distinct without parsing either
/// source value.
fn encode_row_key(
    namespace: &str,
    business_key: &str,
    ordinal: u64,
) -> Result<String, DecoderFault> {
    if business_key.is_empty() {
        return Err(DecoderFault::KeyInvalid(ordinal));
    }
    let key = format!(
        "{FILE_ROW_IDENTITY_VERSION}:{}:{namespace}:{business_key}",
        namespace.len()
    );
    if key.len() > MAXIMUM_ITEM_KEY_BYTES {
        return Err(DecoderFault::KeyInvalid(ordinal));
    }
    Ok(key)
}

/// Validate every valid JSONL row's business key before any bounded page
/// escapes. Malformed JSONL remains the decoder's declared per-line skip and
/// is counted only when the corresponding page is read.
fn validate_jsonl_keys(
    key_pointer: &str,
    namespace: &str,
    bytes: &[u8],
    bounds: &ReadBounds,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), DecoderFault> {
    let mut keys = HashSet::new();
    let mut key_string_capacity = 0_usize;
    let mut line_ordinal = 0_u64;
    let mut offset = utf8_bom_length(bytes);
    while offset < bytes.len() {
        let end = line_end(bytes, offset, cancelled)?;
        if let Some(line) = bounded_jsonl_line(&bytes[offset..end], bounds, cancelled)? {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(line) {
                if !crate::json_bounds::json_within_field_bound(
                    &value,
                    bounds.maximum_field_bytes.get() as usize,
                ) {
                    return Err(DecoderFault::Bound);
                }
                let business_key = selected_business_key(&value, key_pointer, line_ordinal)?;
                encode_row_key(namespace, business_key, line_ordinal)?;
                insert_business_key(
                    &mut keys,
                    &mut key_string_capacity,
                    business_key,
                    bounds.maximum_file_bytes.get() as usize,
                    line_ordinal,
                )?;
            }
        }
        offset = end.saturating_add(1);
        line_ordinal += 1;
    }
    Ok(())
}

/// The length of one UTF-8 byte-order mark at byte 0, which spreadsheet
/// and Windows exports write and which is not part of the first line. The
/// CSV reader (`csv-core`) strips the same mark itself; offsets stay those
/// of the whole file either way.
fn utf8_bom_length(bytes: &[u8]) -> usize {
    if bytes.starts_with(b"\xEF\xBB\xBF") {
        3
    } else {
        0
    }
}

/// Decode JSONL lines: one bounded JSON value per line, a malformed line
/// counted and skipped, the remaining lines continuing. Refusal ordinals are
/// 0-based over every line of the file, blank and malformed included; item
/// identity comes from the declared business-key pointer.
fn decode_jsonl(
    key_pointer: &str,
    namespace: &str,
    bytes: &[u8],
    resume: u64,
    bounds: &ReadBounds,
    cancelled: &dyn Fn() -> bool,
) -> Result<DecodedPage, DecoderFault> {
    validate_jsonl_keys(key_pointer, namespace, bytes, bounds, cancelled)?;
    let maximum_rows = bounds.maximum_rows_per_page.get() as usize;
    let mut items = Vec::new();
    let mut malformed_lines = 0_u32;
    let mut emitted_end = 0_u64;
    let mut line_ordinal = 0_u64;
    let mut offset = utf8_bom_length(bytes) as u64;
    while offset < bytes.len() as u64 {
        let start = offset as usize;
        let end = line_end(bytes, start, cancelled)?;
        let next_offset = (end + 1) as u64;
        let line = bounded_jsonl_line(&bytes[start..end], bounds, cancelled)?;
        if let Some(line) = line {
            if offset + u64::try_from(line.len()).unwrap_or(u64::MAX) > resume {
                if items.len() >= maximum_rows {
                    return Ok(DecodedPage {
                        items,
                        position: emitted_end,
                        complete: false,
                        malformed_lines,
                    });
                }
                match serde_json::from_slice::<serde_json::Value>(line) {
                    Ok(value) => {
                        if !crate::json_bounds::json_within_field_bound(
                            &value,
                            bounds.maximum_field_bytes.get() as usize,
                        ) {
                            return Err(DecoderFault::Bound);
                        }
                        items.push(SourceItem {
                            key: row_key(&value, key_pointer, namespace, line_ordinal)?,
                            revision: None,
                            value,
                        });
                        emitted_end = next_offset.min(bytes.len() as u64);
                    }
                    Err(_) => {
                        malformed_lines = malformed_lines.saturating_add(1);
                    }
                }
            }
        }
        offset = next_offset;
        line_ordinal += 1;
    }
    Ok(DecodedPage {
        items,
        position: emitted_end,
        complete: true,
        malformed_lines,
    })
}

/// Apply the row bound to every physical JSONL line before classifying a
/// blank line. Blank classification checks cancellation between fixed input
/// chunks because a skipped line can still approach the admitted row ceiling.
fn bounded_jsonl_line<'line>(
    line: &'line [u8],
    bounds: &ReadBounds,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<&'line [u8]>, DecoderFault> {
    if line.len() > bounds.maximum_row_bytes.get() as usize {
        return Err(DecoderFault::Bound);
    }
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    for chunk in line.chunks(CSV_INPUT_CHUNK_BYTES) {
        if cancelled() {
            return Err(DecoderFault::Cancelled);
        }
        if !chunk.iter().all(|byte| byte.is_ascii_whitespace()) {
            return Ok(Some(line));
        }
    }
    Ok(None)
}

/// Find one JSONL line ending while retaining the blocking decoder's bounded
/// cancellation latency even for an admitted file containing one huge line.
fn line_end(
    bytes: &[u8],
    offset: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<usize, DecoderFault> {
    let mut scanned = offset;
    loop {
        if cancelled() {
            return Err(DecoderFault::Cancelled);
        }
        let chunk_end = scanned
            .saturating_add(CSV_INPUT_CHUNK_BYTES)
            .min(bytes.len());
        if let Some(position) = bytes[scanned..chunk_end]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            return Ok(scanned + position);
        }
        if chunk_end == bytes.len() {
            return Ok(bytes.len());
        }
        scanned = chunk_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn csv(key_pointer: &str) -> Decoder {
        Decoder::Csv {
            options: CsvDecoder::default(),
            key_pointer: key_pointer.to_owned(),
        }
    }

    fn csv_with(options: CsvDecoder, key_pointer: &str) -> Decoder {
        Decoder::Csv {
            options,
            key_pointer: key_pointer.to_owned(),
        }
    }

    fn jsonl(key_pointer: &str) -> Decoder {
        Decoder::Jsonl {
            key_pointer: key_pointer.to_owned(),
        }
    }

    fn bounds(rows: usize) -> ReadBounds {
        ReadBounds {
            maximum_file_bytes: 1_073_741_824.try_into().expect("inside its range"),
            maximum_row_bytes: 1_048_576.try_into().expect("inside its range"),
            maximum_field_bytes: 65_536.try_into().expect("inside its range"),
            maximum_rows_per_page: (rows as u32).try_into().expect("inside its range"),
        }
    }

    /// A UTF-8 byte-order mark at byte 0, which spreadsheet exports
    /// write, is not part of the first header or the first JSONL line.
    /// Positions stay offsets into the whole file, so a page resumes
    /// after the mark exactly as it would without it.
    #[test]
    fn a_leading_utf8_bom_is_not_part_of_the_first_csv_header_or_jsonl_line() {
        let bytes = b"\xEF\xBB\xBFid,name\n001,alice\n002,bob\n";
        let first = decode(
            &csv("/id"),
            "exports",
            "sha256:aa",
            "people.csv",
            bytes,
            0,
            &bounds(1),
        )
        .expect("a CSV file with a BOM decodes");
        assert_eq!(
            first.items[0].value,
            serde_json::json!({"id": "001", "name": "alice"})
        );
        assert_eq!(
            first.position,
            b"\xEF\xBB\xBFid,name\n001,alice\n".len() as u64
        );
        let second = decode(
            &csv("/id"),
            "exports",
            "sha256:aa",
            "people.csv",
            bytes,
            first.position,
            &bounds(1),
        )
        .expect("the second page decodes");
        assert_eq!(
            second.items[0].value,
            serde_json::json!({"id": "002", "name": "bob"})
        );

        let headerless = CsvDecoder {
            header: false,
            ..CsvDecoder::default()
        };
        let page = decode(
            &csv_with(headerless, "/0"),
            "exports",
            "sha256:aa",
            "people.csv",
            b"\xEF\xBB\xBFalice,7\n",
            0,
            &bounds(10),
        )
        .expect("a headerless CSV file with a BOM decodes");
        assert_eq!(page.items[0].value, serde_json::json!(["alice", "7"]));

        let bytes = b"\xEF\xBB\xBF{\"id\":\"001\"}\n{\"id\":\"002\"}\n";
        let page = decode(
            &jsonl("/id"),
            "exports",
            "sha256:aa",
            "people.jsonl",
            bytes,
            0,
            &bounds(10),
        )
        .expect("a JSONL file with a BOM decodes");
        assert_eq!(page.malformed_lines, 0, "the first line is not lost");
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].value, serde_json::json!({"id": "001"}));
        assert_eq!(page.position, bytes.len() as u64);
    }

    /// The CSV defaults from the CsvDataFormat Java: comma delimiter,
    /// double quote, header record on, no trimming. Values stay strings,
    /// leading zeros survive, a short record pads with the empty string,
    /// and a record longer than the header refuses.
    #[test]
    fn csv_defaults_decode_deterministic_rows() {
        let bytes = b"name,age\nalice,007\nbob\n";
        let page = decode(
            &csv("/name"),
            "exports",
            "sha256:aa",
            "people.csv",
            bytes,
            0,
            &bounds(10),
        )
        .expect("the file decodes");
        assert!(page.complete);
        assert_eq!(page.position, bytes.len() as u64);
        assert_eq!(page.items[0].key, "file-row-v1:7:exports:alice");
        assert_eq!(
            page.items[0].value,
            serde_json::json!({"name": "alice", "age": "007"}),
            "leading zeros survive as strings"
        );
        assert_eq!(
            page.items[1].value,
            serde_json::json!({"name": "bob", "age": ""}),
            "a missing trailing field is the empty string, never null"
        );
    }

    /// A record longer than the header refuses; with the header off, a
    /// row decodes as a bare array.
    #[test]
    fn csv_refuses_extra_fields_and_decodes_headerless_rows_as_arrays() {
        let bytes = b"name,age\nalice,7,extra\n";
        assert!(matches!(
            decode(
                &csv("/name"),
                "exports",
                "sha256:aa",
                "people.csv",
                bytes,
                0,
                &bounds(10),
            ),
            Err(DecoderFault::Row(_))
        ));
        let headerless = CsvDecoder {
            header: false,
            ..CsvDecoder::default()
        };
        let page = decode(
            &csv_with(headerless, "/0"),
            "exports",
            "sha256:aa",
            "people.csv",
            b"alice,7\n",
            0,
            &bounds(10),
        )
        .expect("the headerless file decodes");
        assert_eq!(page.items[0].key, "file-row-v1:7:exports:alice");
        assert_eq!(page.items[0].value, serde_json::json!(["alice", "7"]));
    }

    /// A malformed record fails the whole read naming its index. Validation
    /// happens before paging, so no earlier row escapes and the caller keeps
    /// its previous cursor.
    #[test]
    fn a_malformed_csv_record_blocks_its_file() {
        // The third record carries one field more than the header names,
        // which no column of the row map can hold.
        let bytes = b"name,age\nalice,7\nalice,7,extra\nbob,3\n";
        let result = decode(
            &csv("/name"),
            "exports",
            "sha256:aa",
            "people.csv",
            bytes,
            0,
            &bounds(1),
        );
        assert!(
            matches!(result, Err(DecoderFault::Row(2))),
            "the bad record refuses before any partial page escapes"
        );
    }

    /// A quoted multiline field decodes whole; its byte offsets page
    /// exactly, so the second read resumes inside the quoted field's
    /// tail and emits the rest.
    #[test]
    fn a_quoted_multiline_field_pages_exactly() {
        let bytes = b"name,note\nalice,\"two\nlines\"\nbob,3\n";
        let first = decode(
            &csv("/name"),
            "exports",
            "sha256:aa",
            "people.csv",
            bytes,
            0,
            &bounds(1),
        )
        .expect("the first row decodes");
        assert_eq!(
            first.items[0].value,
            serde_json::json!({"name": "alice", "note": "two\nlines"})
        );
        assert!(!first.complete);
        let second = decode(
            &csv("/name"),
            "exports",
            "sha256:aa",
            "people.csv",
            bytes,
            first.position,
            &bounds(10),
        )
        .expect("the second page decodes");
        assert_eq!(second.items.len(), 1);
        assert_eq!(
            second.items[0].value,
            serde_json::json!({"name": "bob", "note": "3"})
        );
        assert!(second.complete);
        assert_eq!(second.position, bytes.len() as u64);
    }

    /// A record over the row bound or a field over the field bound
    /// refuses the read; a smaller bound admits both.
    #[test]
    fn csv_bounds_refuse_oversized_records_and_fields() {
        let wide = format!("name,age\n{},7\n", "w".repeat(2_000_000));
        assert!(matches!(
            decode(
                &csv("/name"),
                "exports",
                "sha256:aa",
                "people.csv",
                wide.as_bytes(),
                0,
                &bounds(10),
            ),
            Err(DecoderFault::Bound)
        ));

        let mut tight = bounds(10);
        tight.maximum_field_bytes = 8.try_into().expect("inside its range");
        let late_quoted = format!(
            "id,note\n001,ok\n002,\"{}\"\n",
            "x".repeat(CSV_OUTPUT_CHUNK_BYTES * 3)
        );
        assert!(matches!(
            decode(
                &csv("/id"),
                "exports",
                "sha256:aa",
                "people.csv",
                late_quoted.as_bytes(),
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
        assert!(matches!(
            decode(
                &csv("/name"),
                "exports",
                "sha256:aa",
                "people.csv",
                b"name,age\nabcdefghi,7\n",
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
    }

    /// The header record is a record like any other: a header field over
    /// the field bound, or a header record over the row bound, refuses
    /// the read instead of slipping past the bounds the data rows hold.
    #[test]
    fn csv_bounds_hold_on_the_header_record() {
        let mut tight = bounds(10);
        tight.maximum_field_bytes = 8.try_into().expect("inside its range");
        assert!(matches!(
            decode(
                &csv("/name"),
                "exports",
                "sha256:aa",
                "people.csv",
                b"abcdefghi,age\nalice,7\n",
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
        let mut narrow = bounds(10);
        narrow.maximum_row_bytes = 8.try_into().expect("inside its range");
        assert!(matches!(
            decode(
                &csv("/name"),
                "exports",
                "sha256:aa",
                "people.csv",
                b"name,age,city\n",
                0,
                &narrow,
            ),
            Err(DecoderFault::Bound)
        ));
    }

    /// A syntax character outside ASCII cannot be one CSV byte: the
    /// decoder refuses it instead of truncating it to another byte.
    #[test]
    fn csv_refuses_a_syntax_character_outside_ascii() {
        for options in [
            CsvDecoder {
                delimiter: '\u{ff1b}',
                ..CsvDecoder::default()
            },
            CsvDecoder {
                quote: '\u{201c}',
                ..CsvDecoder::default()
            },
            CsvDecoder {
                comment_marker: Some('\u{00a7}'),
                ..CsvDecoder::default()
            },
        ] {
            assert!(matches!(
                decode(
                    &csv_with(options, "/name"),
                    "exports",
                    "sha256:aa",
                    "people.csv",
                    b"name,age\nalice,7\n",
                    0,
                    &bounds(10),
                ),
                Err(DecoderFault::Syntax)
            ));
        }
    }

    /// The field bound holds on JSONL values: a string or member name
    /// over it refuses the read wherever it nests, and a value inside it
    /// decodes.
    #[test]
    fn jsonl_refuses_a_field_over_the_field_bound() {
        let mut tight = bounds(10);
        tight.maximum_field_bytes = 4.try_into().expect("inside its range");
        for line in [
            &b"{\"id\":\"1\",\"name\":\"12345\"}\n"[..],
            &b"{\"id\":\"1\",\"a\":{\"b\":[\"12345\"]}}\n"[..],
            &b"{\"id\":\"1\",\"longer\":\"1\"}\n"[..],
        ] {
            assert!(matches!(
                decode(
                    &jsonl("/id"),
                    "exports",
                    "sha256:aa",
                    "events.jsonl",
                    line,
                    0,
                    &tight,
                ),
                Err(DecoderFault::Bound)
            ));
        }
        let page = decode(
            &jsonl("/name"),
            "exports",
            "sha256:aa",
            "events.jsonl",
            b"{\"name\":\"1234\",\"n\":[1,2]}\n",
            0,
            &tight,
        )
        .expect("a value inside the field bound decodes");
        assert_eq!(page.items.len(), 1);
    }

    /// JSONL: one value per line, a malformed line counted and skipped
    /// with the rest continuing, blanks ignored, and the key ordinal
    /// counting every line so a skipped line cannot shift the keys.
    #[test]
    fn jsonl_continues_past_a_malformed_line() {
        let bytes = b"{\"a\":\"001\"}\nnot json\n\n{\"a\":\"002\"}\n";
        let page = decode(
            &jsonl("/a"),
            "exports",
            "sha256:aa",
            "events.jsonl",
            bytes,
            0,
            &bounds(10),
        )
        .expect("the file decodes");
        assert_eq!(page.malformed_lines, 1);
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.items[0].key, "file-row-v1:7:exports:001");
        assert_eq!(page.items[1].key, "file-row-v1:7:exports:002");
        assert!(page.complete);
    }

    /// JSONL pages at the rows bound and resumes at the byte offset
    /// after the last emitted line.
    #[test]
    fn jsonl_pages_at_the_rows_bound() {
        let bytes = b"{\"a\":\"1\"}\n{\"a\":\"2\"}\n{\"a\":\"3\"}\n";
        let first = decode(
            &jsonl("/a"),
            "exports",
            "sha256:aa",
            "events.jsonl",
            bytes,
            0,
            &bounds(2),
        )
        .expect("the first page decodes");
        assert_eq!(first.items.len(), 2);
        assert!(!first.complete);
        let second = decode(
            &jsonl("/a"),
            "exports",
            "sha256:aa",
            "events.jsonl",
            bytes,
            first.position,
            &bounds(2),
        )
        .expect("the second page decodes");
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].key, "file-row-v1:7:exports:3");
        assert!(second.complete);
    }

    /// A JSONL line over the row bound refuses the read.
    #[test]
    fn jsonl_refuses_an_oversized_line() {
        let wide = format!("{{\"id\":\"1\",\"a\": \"{}\"}}\n", "w".repeat(2_000_000));
        assert!(matches!(
            decode(
                &jsonl("/id"),
                "exports",
                "sha256:aa",
                "events.jsonl",
                wide.as_bytes(),
                0,
                &bounds(10),
            ),
            Err(DecoderFault::Bound)
        ));
    }

    /// Blank physical lines are still rows for resource accounting. They
    /// cannot bypass the row bound merely because the JSONL decoder skips
    /// them semantically.
    #[test]
    fn jsonl_applies_the_row_bound_to_blank_physical_lines() {
        let mut tight = bounds(10);
        tight.maximum_row_bytes = 8.try_into().expect("inside its range");
        assert!(matches!(
            decode(
                &jsonl("/id"),
                "exports",
                "sha256:aa",
                "events.jsonl",
                b"         \n",
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
    }

    /// Newline discovery is not the only potentially long scan: blank-line
    /// classification also observes cancellation between 64 KiB chunks.
    #[test]
    fn jsonl_whitespace_scanning_stops_cooperatively_at_a_chunk_boundary() {
        let calls = std::cell::Cell::new(0_u32);
        let cancelled = || {
            let next = calls.get().saturating_add(1);
            calls.set(next);
            next >= 12
        };
        let long = format!("{}\n", " ".repeat(CSV_INPUT_CHUNK_BYTES * 3));
        assert!(matches!(
            decode_with_cancellation(
                &jsonl("/id"),
                DecodeInput {
                    namespace: "exports",
                    digest: "sha256:aa",
                    name: "events.jsonl",
                    bytes: long.as_bytes(),
                },
                0,
                &bounds(10),
                &cancelled,
            ),
            Err(DecoderFault::Cancelled)
        ));
        assert_eq!(calls.get(), 12, "cancellation is checked between scans");
    }

    /// Whole-file validation applies row bounds before parsing every later
    /// record. An oversized row beyond the first page therefore refuses with
    /// no partial page, and JSONL never allocates its value before the bound.
    #[test]
    fn a_late_oversized_row_refuses_before_the_first_page() {
        let mut tight = bounds(1);
        tight.maximum_row_bytes = 24.try_into().expect("inside its range");
        assert!(matches!(
            decode(
                &csv("/id"),
                "exports",
                "sha256:aa",
                "people.csv",
                b"id,name\n001,Ada\n002,this-row-is-far-too-wide\n",
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
        assert!(matches!(
            decode(
                &jsonl("/id"),
                "exports",
                "sha256:aa",
                "events.jsonl",
                b"{\"id\":\"001\"}\n{\"id\":\"002\",\"value\":\"this-line-is-far-too-wide\"}\n",
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
    }

    /// CSV parser working memory includes field slots, not only decoded field
    /// bytes. A delimiter-only record therefore cannot amplify one small row
    /// bound into an arbitrarily large field vector.
    #[test]
    fn comma_only_fields_are_charged_to_the_row_budget() {
        let mut tight = bounds(10);
        tight.maximum_row_bytes = 64.try_into().expect("inside its range");
        assert!(matches!(
            decode(
                &csv_with(
                    CsvDecoder {
                        header: false,
                        ..CsvDecoder::default()
                    },
                    "/0",
                ),
                "exports",
                "sha256:aa",
                "people.csv",
                b"001,,,,,,,,,,,,,,,,\n",
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
    }

    /// The exact whole-file duplicate index charges strings and conservative
    /// hash-table capacity against the existing file-byte ceiling.
    #[test]
    fn business_key_index_is_bounded_before_growth() {
        let mut tight = bounds(1);
        tight.maximum_file_bytes = 256.try_into().expect("inside its range");
        assert!(matches!(
            decode(
                &csv("/id"),
                "exports",
                "sha256:aa",
                "people.csv",
                b"id\n001\n002\n003\n",
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
        assert!(matches!(
            decode(
                &jsonl("/id"),
                "exports",
                "sha256:aa",
                "events.jsonl",
                b"{\"id\":\"001\"}\n{\"id\":\"002\"}\n{\"id\":\"003\"}\n",
                0,
                &tight,
            ),
            Err(DecoderFault::Bound)
        ));
    }

    /// A detached blocking parser observes cancellation at its next bounded
    /// input boundary instead of continuing through the admitted whole file.
    #[test]
    fn csv_parsing_stops_cooperatively_at_a_chunk_boundary() {
        let calls = std::cell::Cell::new(0_u32);
        let cancelled = || {
            let next = calls.get().saturating_add(1);
            calls.set(next);
            next >= 5
        };
        let long = format!("id,note\n001,\"{}\"\n", "x".repeat(200_000));
        assert!(matches!(
            decode_with_cancellation(
                &csv("/id"),
                DecodeInput {
                    namespace: "exports",
                    digest: "sha256:aa",
                    name: "people.csv",
                    bytes: long.as_bytes(),
                },
                0,
                &bounds(10),
                &cancelled,
            ),
            Err(DecoderFault::Cancelled)
        ));
        assert_eq!(calls.get(), 5, "cancellation is checked between chunks");
    }

    /// Row identity comes only from the declared business key. A new file
    /// digest and a new row order therefore preserve item identity, while a
    /// changed row under that key remains the same item for the pass to
    /// classify as revised from its projection digest.
    #[test]
    fn csv_business_keys_survive_file_replacement_reorder_and_row_edits() {
        let first = decode(
            &csv("/householdId"),
            "exports",
            "sha256:first",
            "households.csv",
            b"householdId,name\n00123,Ada\n00456,Bob\n",
            0,
            &bounds(10),
        )
        .expect("the first file decodes");
        let replacement = decode(
            &csv("/householdId"),
            "exports",
            "sha256:replacement",
            "households.csv",
            b"householdId,name\n00456,Bob\n00123,Ada Lovelace\n",
            0,
            &bounds(10),
        )
        .expect("the replacement decodes");

        assert_eq!(first.items[0].key, "file-row-v1:7:exports:00123");
        assert_eq!(first.items[1].key, replacement.items[0].key);
        assert_eq!(first.items[0].key, replacement.items[1].key);
        assert_ne!(first.items[0].value, replacement.items[1].value);
    }

    /// The length prefix makes namespace boundaries unambiguous even when
    /// source values contain the separator used by the text encoding.
    #[test]
    fn row_key_encoding_is_collision_free_across_namespaces() {
        let left = decode(
            &csv("/id"),
            "a:b",
            "sha256:left",
            "left.csv",
            b"id\nc\n",
            0,
            &bounds(10),
        )
        .expect("the left row decodes");
        let right = decode(
            &csv("/id"),
            "a",
            "sha256:right",
            "right.csv",
            b"id\nb:c\n",
            0,
            &bounds(10),
        )
        .expect("the right row decodes");

        assert_ne!(left.items[0].key, right.items[0].key);
    }

    /// A missing selector, an empty or non-string selected value, and a key
    /// whose encoded item identity exceeds the existing bound all fail closed
    /// at the exact value-free record ordinal.
    #[test]
    fn row_key_failures_are_typed_and_located() {
        assert!(matches!(
            decode(
                &csv("/missing"),
                "exports",
                "sha256:aa",
                "people.csv",
                b"id,name\n1,Ada\n",
                0,
                &bounds(10),
            ),
            Err(DecoderFault::KeyMissing(0))
        ));
        for line in [b"{\"id\":null}\n".as_slice(), b"{\"id\":\"\"}\n".as_slice()] {
            assert!(matches!(
                decode(
                    &jsonl("/id"),
                    "exports",
                    "sha256:aa",
                    "events.jsonl",
                    line,
                    0,
                    &bounds(10),
                ),
                Err(DecoderFault::KeyInvalid(0))
            ));
        }
        let overbound = format!("{{\"id\":\"{}\"}}\n", "k".repeat(512));
        assert!(matches!(
            decode(
                &jsonl("/id"),
                "exports",
                "sha256:aa",
                "events.jsonl",
                overbound.as_bytes(),
                0,
                &bounds(10),
            ),
            Err(DecoderFault::KeyInvalid(0))
        ));
    }

    /// Duplicate business keys are rejected across the whole file before a
    /// bounded first page can escape. The second occurrence supplies the
    /// record locator, including the CSV header in the ordinal.
    #[test]
    fn duplicate_keys_across_a_page_boundary_fail_the_whole_read() {
        assert!(matches!(
            decode(
                &csv("/id"),
                "exports",
                "sha256:aa",
                "people.csv",
                b"id,name\n001,Ada\n002,Bob\n001,Eve\n",
                0,
                &bounds(1),
            ),
            Err(DecoderFault::KeyDuplicate(3))
        ));
        assert!(matches!(
            decode(
                &jsonl("/id"),
                "exports",
                "sha256:aa",
                "events.jsonl",
                b"{\"id\":\"001\"}\n{\"id\":\"002\"}\n{\"id\":\"001\"}\n",
                0,
                &bounds(1),
            ),
            Err(DecoderFault::KeyDuplicate(2))
        ));
    }

    /// Raw: one item per file, the name and size as the value, the
    /// digest in the key, and the file's length as the position.
    #[test]
    fn raw_emits_one_item_per_file() {
        let page = decode(
            &Decoder::Raw,
            "exports",
            "sha256:aa",
            "blob.bin",
            b"content",
            0,
            &bounds(10),
        )
        .expect("the file decodes");
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].key, "exports:sha256:aa");
        assert_eq!(
            page.items[0].value,
            serde_json::json!({"name": "blob.bin", "bytes": 7})
        );
        assert!(page.complete);
        assert_eq!(page.position, 7);
    }

    /// The record ordinal a CSV refusal names is 0-based over every
    /// record including the header, so the header is record 0 and the
    /// first data row is 1.
    #[test]
    fn the_csv_ordinal_counts_the_header() {
        // Record 0 is the header; a duplicate column name is a refusal
        // at record 0's read.
        let duplicate = b"name,name\nalice,7\n";
        assert!(matches!(
            decode(
                &csv("/name"),
                "exports",
                "sha256:aa",
                "people.csv",
                duplicate,
                0,
                &bounds(10),
            ),
            Err(DecoderFault::Row(_))
        ));
        // Invalid UTF-8 in the second data row (record 2) refuses the whole
        // read before the bounded first page can escape.
        let invalid = b"name,age\nalice,7\n\xff,2\n";
        assert!(matches!(
            decode(
                &csv("/age"),
                "exports",
                "sha256:aa",
                "people.csv",
                invalid,
                0,
                &bounds(1),
            ),
            Err(DecoderFault::Row(2))
        ));
    }
}
