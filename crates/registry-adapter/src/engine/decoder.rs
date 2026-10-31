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
//! next read re-encounters it and fails again the same way; a malformed
//! JSONL line is counted and the remaining lines continue, the count
//! leaving the page through the job entry's side channel. A record over
//! the row bound or a field over the field bound fails the read under
//! `adapter.job.read-bound`, never a partial row.
//!
//! Port record: the decoder options and defaults are
//! camel-4.23.0:core/camel-core-model/src/main/java/org/apache/camel/model/dataformat/CsvDataFormat.java
//! as landed in `registry_adapter_core::CsvDecoder`; the row identity,
//! per-record refusal, and paged decoding are original work Camel does
//! not supply (the governed-ingestion detailed design, section 6).

use registry_adapter_core::{CsvDecoder, ReadBounds, SourceItem};

/// The decoder a read applies to one file's bytes.
#[derive(Clone, Debug)]
pub(crate) enum Decoder {
    /// One item per file: the file's name and size, the digest riding
    /// the key and the cursor.
    Raw,
    /// Comma-separated rows under the landed options.
    Csv(CsvDecoder),
    /// One bounded JSON value per line.
    Jsonl,
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

/// Why a decode refused the read. The route failure carries the class;
/// the processor carries the code beside it.
#[derive(Debug)]
pub(crate) enum DecoderFault {
    /// A malformed record: the read fails and the next read re-fails
    /// deterministically at the same bytes. The payload is the record's
    /// 0-based index over every record of the file, header included,
    /// the one value the refusal may name.
    Row(u64),
    /// A record or field over the profile's read bounds.
    Bound,
}

/// Decode one file's rows from `resume`, the byte offset after the last
/// row the previous page emitted (zero on the first read). The whole
/// file is in memory under the read bounds, so the header record and
/// every resume offset are exact; the page is bounded by
/// `bounds.maximum_rows_per_page`.
pub(crate) fn decode(
    decoder: &Decoder,
    namespace: &str,
    digest: &str,
    name: &str,
    bytes: &[u8],
    resume: u64,
    bounds: &ReadBounds,
) -> Result<DecodedPage, DecoderFault> {
    match decoder {
        Decoder::Raw => Ok(DecodedPage {
            items: vec![SourceItem {
                key: format!("{namespace}:{digest}"),
                revision: None,
                value: serde_json::json!({ "name": name, "bytes": bytes.len() }),
            }],
            position: bytes.len() as u64,
            complete: true,
            malformed_lines: 0,
        }),
        Decoder::Csv(options) => decode_csv(options, namespace, digest, bytes, resume, bounds),
        Decoder::Jsonl => decode_jsonl(namespace, digest, bytes, resume, bounds),
    }
}

/// Decode CSV rows. The reader walks every record from the file's start,
/// which keeps the header record and each record's byte offsets exact,
/// and emits from the resume offset on. The record ordinal in a key and
/// in a refusal is 0-based over every record the walk reads, header
/// included, so both name the same row on every read.
fn decode_csv(
    options: &CsvDecoder,
    namespace: &str,
    digest: &str,
    bytes: &[u8],
    resume: u64,
    bounds: &ReadBounds,
) -> Result<DecodedPage, DecoderFault> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(options.delimiter as u8)
        .quote(options.quote as u8)
        .quoting(!options.quote_disabled)
        .comment(options.comment_marker.map(|marker| marker as u8))
        .trim(if options.trim {
            csv::Trim::All
        } else {
            csv::Trim::None
        })
        .has_headers(false)
        .flexible(true)
        .from_reader(bytes);
    let maximum_rows = bounds.maximum_rows_per_page as usize;
    let mut items = Vec::new();
    let mut header: Option<Vec<String>> = None;
    let mut record = csv::ByteRecord::new();
    let mut ordinal = 0_u64;
    let mut emitted_end = 0_u64;
    loop {
        let read = reader
            .read_byte_record(&mut record)
            .map_err(|_| DecoderFault::Row(ordinal))?;
        if !read {
            // The walk reached the file's end: every row past the resume
            // offset is emitted, so the file is complete.
            return Ok(DecodedPage {
                items,
                position: emitted_end,
                complete: true,
                malformed_lines: 0,
            });
        }
        if ordinal == 0 && options.header {
            header = Some(header_names(&record, ordinal)?);
            ordinal += 1;
            continue;
        }
        let record_end = reader.position().byte();
        if record_end <= resume {
            ordinal += 1;
            continue;
        }
        if items.len() >= maximum_rows {
            // The bound is hit before this record: it stands beyond the
            // last emitted one, so the file is not complete, and the
            // next read resumes at the byte offset after that row.
            return Ok(DecodedPage {
                items,
                position: emitted_end,
                complete: false,
                malformed_lines: 0,
            });
        }
        let item = csv_record_item(
            &record,
            header.as_deref(),
            namespace,
            digest,
            ordinal,
            bounds,
        )?;
        emitted_end = record_end;
        items.push(item);
        ordinal += 1;
    }
}

/// The header record's names, refusing a duplicate name that would fold
/// two columns into one map member.
fn header_names(record: &csv::ByteRecord, ordinal: u64) -> Result<Vec<String>, DecoderFault> {
    let mut names = Vec::with_capacity(record.len());
    for field in record.iter() {
        let name = field_text(field, ordinal)?;
        if names.contains(&name) {
            return Err(DecoderFault::Row(ordinal));
        }
        names.push(name);
    }
    Ok(names)
}

/// One record as a source item: a map keyed by the header record, or a
/// bare array when the file declares no header. A record shorter than
/// the header pads with the empty string, never null; a record longer
/// than the header refuses; a record or field over its bound refuses.
fn csv_record_item(
    record: &csv::ByteRecord,
    header: Option<&[String]>,
    namespace: &str,
    digest: &str,
    ordinal: u64,
    bounds: &ReadBounds,
) -> Result<SourceItem, DecoderFault> {
    if record.as_slice().len() > bounds.maximum_row_bytes as usize {
        return Err(DecoderFault::Bound);
    }
    for field in record.iter() {
        if field.len() > bounds.maximum_field_bytes as usize {
            return Err(DecoderFault::Bound);
        }
    }
    let key = format!("{namespace}:{digest}:{ordinal}");
    let value = match header {
        Some(names) => {
            if record.len() > names.len() {
                return Err(DecoderFault::Row(ordinal));
            }
            let mut members = serde_json::Map::new();
            for (index, name) in names.iter().enumerate() {
                let text = record
                    .get(index)
                    .map(|field| field_text(field, ordinal))
                    .transpose()?
                    .unwrap_or_default();
                members.insert(name.clone(), serde_json::Value::String(text));
            }
            serde_json::Value::Object(members)
        }
        None => {
            let mut fields = Vec::with_capacity(record.len());
            for field in record.iter() {
                fields.push(serde_json::Value::String(field_text(field, ordinal)?));
            }
            serde_json::Value::Array(fields)
        }
    };
    Ok(SourceItem {
        key,
        revision: None,
        value,
    })
}

/// A field's text: the file's bytes are UTF-8 only, so anything else is
/// a malformed record.
fn field_text(field: &[u8], ordinal: u64) -> Result<String, DecoderFault> {
    std::str::from_utf8(field)
        .map(str::to_owned)
        .map_err(|_| DecoderFault::Row(ordinal))
}

/// Decode JSONL lines: one bounded JSON value per line, a malformed
/// line counted and skipped, the remaining lines continuing. The line
/// ordinal in a key is 0-based over every line of the file, blank and
/// malformed included, so a key names the same line whatever the page
/// skipped before it.
fn decode_jsonl(
    namespace: &str,
    digest: &str,
    bytes: &[u8],
    resume: u64,
    bounds: &ReadBounds,
) -> Result<DecodedPage, DecoderFault> {
    let maximum_rows = bounds.maximum_rows_per_page as usize;
    let mut items = Vec::new();
    let mut malformed_lines = 0_u32;
    let mut emitted_end = 0_u64;
    let mut line_ordinal = 0_u64;
    let mut offset = 0_u64;
    while offset < bytes.len() as u64 {
        let start = offset as usize;
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(bytes.len(), |position| start + position);
        let next_offset = (end + 1) as u64;
        let mut line = &bytes[start..end];
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        let blank = line.iter().all(|byte| byte.is_ascii_whitespace());
        if !blank && offset + u64::try_from(line.len()).unwrap_or(u64::MAX) > resume {
            if line.len() > bounds.maximum_row_bytes as usize {
                return Err(DecoderFault::Bound);
            }
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
                    items.push(SourceItem {
                        key: format!("{namespace}:{digest}:{line_ordinal}"),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds(rows: usize) -> ReadBounds {
        ReadBounds {
            maximum_file_bytes: 1_073_741_824,
            maximum_row_bytes: 1_048_576,
            maximum_field_bytes: 65_536,
            maximum_rows_per_page: rows as u32,
        }
    }

    /// The CSV defaults from the CsvDataFormat Java: comma delimiter,
    /// double quote, header record on, no trimming. Values stay strings,
    /// leading zeros survive, a short record pads with the empty string,
    /// and a record longer than the header refuses.
    #[test]
    fn csv_defaults_decode_deterministic_rows() {
        let bytes = b"name,age\nalice,007\nbob\n";
        let page = decode(
            &Decoder::Csv(CsvDecoder::default()),
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
        assert_eq!(page.items[0].key, "exports:sha256:aa:1");
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
                &Decoder::Csv(CsvDecoder::default()),
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
            &Decoder::Csv(headerless),
            "exports",
            "sha256:aa",
            "people.csv",
            b"alice,7\n",
            0,
            &bounds(10),
        )
        .expect("the headerless file decodes");
        assert_eq!(page.items[0].key, "exports:sha256:aa:0");
        assert_eq!(page.items[0].value, serde_json::json!(["alice", "7"]));
    }

    /// A malformed record fails the read naming its index; the page
    /// stops before it, and a resumed read re-encounters the same bytes
    /// and fails again the same way.
    #[test]
    fn a_malformed_csv_record_blocks_its_file() {
        // The third record carries one field more than the header names,
        // which no column of the row map can hold.
        let bytes = b"name,age\nalice,7\nalice,7,extra\nbob,3\n";
        let first = decode(
            &Decoder::Csv(CsvDecoder::default()),
            "exports",
            "sha256:aa",
            "people.csv",
            bytes,
            0,
            &bounds(1),
        )
        .expect("the first row decodes");
        assert_eq!(first.items.len(), 1);
        assert!(!first.complete);
        let second = decode(
            &Decoder::Csv(CsvDecoder::default()),
            "exports",
            "sha256:aa",
            "people.csv",
            bytes,
            first.position,
            &bounds(10),
        );
        assert!(
            matches!(second, Err(DecoderFault::Row(2))),
            "the bad record refuses again at its own index"
        );
    }

    /// A quoted multiline field decodes whole; its byte offsets page
    /// exactly, so the second read resumes inside the quoted field's
    /// tail and emits the rest.
    #[test]
    fn a_quoted_multiline_field_pages_exactly() {
        let bytes = b"name,note\nalice,\"two\nlines\"\nbob,3\n";
        let first = decode(
            &Decoder::Csv(CsvDecoder::default()),
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
            &Decoder::Csv(CsvDecoder::default()),
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
                &Decoder::Csv(CsvDecoder::default()),
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
        tight.maximum_field_bytes = 8;
        assert!(matches!(
            decode(
                &Decoder::Csv(CsvDecoder::default()),
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

    /// JSONL: one value per line, a malformed line counted and skipped
    /// with the rest continuing, blanks ignored, and the key ordinal
    /// counting every line so a skipped line cannot shift the keys.
    #[test]
    fn jsonl_continues_past_a_malformed_line() {
        let bytes = b"{\"a\":1}\nnot json\n\n{\"a\":2}\n";
        let page = decode(
            &Decoder::Jsonl,
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
        assert_eq!(page.items[0].key, "exports:sha256:aa:0");
        assert_eq!(page.items[1].key, "exports:sha256:aa:3");
        assert!(page.complete);
    }

    /// JSONL pages at the rows bound and resumes at the byte offset
    /// after the last emitted line.
    #[test]
    fn jsonl_pages_at_the_rows_bound() {
        let bytes = b"{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n";
        let first = decode(
            &Decoder::Jsonl,
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
            &Decoder::Jsonl,
            "exports",
            "sha256:aa",
            "events.jsonl",
            bytes,
            first.position,
            &bounds(2),
        )
        .expect("the second page decodes");
        assert_eq!(second.items.len(), 1);
        assert_eq!(second.items[0].key, "exports:sha256:aa:2");
        assert!(second.complete);
    }

    /// A JSONL line over the row bound refuses the read.
    #[test]
    fn jsonl_refuses_an_oversized_line() {
        let wide = format!("{{\"a\": \"{}\"}}\n", "w".repeat(2_000_000));
        assert!(matches!(
            decode(
                &Decoder::Jsonl,
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
                &Decoder::Csv(CsvDecoder::default()),
                "exports",
                "sha256:aa",
                "people.csv",
                duplicate,
                0,
                &bounds(10),
            ),
            Err(DecoderFault::Row(_))
        ));
        // Invalid UTF-8 in the first data row (record 1) is the same
        // refusal at its own read.
        let invalid = b"name,age\nalice,7\n\xff,2\n";
        let first = decode(
            &Decoder::Csv(CsvDecoder::default()),
            "exports",
            "sha256:aa",
            "people.csv",
            invalid,
            0,
            &bounds(1),
        )
        .expect("the first row decodes");
        assert!(matches!(
            decode(
                &Decoder::Csv(CsvDecoder::default()),
                "exports",
                "sha256:aa",
                "people.csv",
                invalid,
                first.position,
                &bounds(10),
            ),
            Err(DecoderFault::Row(_))
        ));
    }
}
