// SPDX-License-Identifier: Apache-2.0
//! `ParquetFormat`: decode Parquet byte streams to Arrow `RecordBatch`es.
//!
//! Parquet is Arrow-native, so this decoder is mostly a passthrough:
//! buffer the bytes, hand them to
//! `parquet::arrow::async_reader::ParquetRecordBatchStreamBuilder`, and
//! yield the resulting `RecordBatch` stream. The observed schema is read
//! directly from the Parquet file metadata.
//!
//! ## Implementation note
//!
//! The reader buffers the entire input into memory before handing it to
//! `ParquetRecordBatchStreamBuilder`. The async reader can accept an
//! `AsyncFileReader` that does range reads, which would avoid the full
//! buffer, but that requires `AsyncRead + AsyncSeek` from the caller
//! (the `Format::decode` surface only promises `AsyncRead`). Wrapping
//! the buffered bytes in a `Cursor<Bytes>` provides the required `Seek`
//! support at the cost of memory. A range-reading source can remove
//! that full-buffer cost later.
//!
//! ## FormatHints
//!
//! Parquet is self-describing. The fields `sheet`, `header_row`,
//! `data_range`, `delimiter`, and `quote` are not applicable and are
//! silently ignored. `hints.declared` is not used for coercion here;
//! schema validation against the declared types belongs to
//! `src/ingest/validation.rs`. This decoder returns the observed Arrow
//! schema as-is.

use std::pin::Pin;
use std::sync::Arc;

use datafusion::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use futures::stream;
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::format::{DecodedStream, Format, FormatError, FormatFuture, FormatHints};

/// Maximum byte length of a Parquet footer we are willing to allocate.
///
/// `ParquetRecordBatchReaderBuilder::try_new` reads the four bytes at
/// `len - 8` as a little-endian `u32` and allocates a buffer of that size
/// to hold the footer metadata. A forged 5 MB file declaring a 4 GB
/// footer length would otherwise trigger an OOM before any row group is
/// touched. 32 MiB is comfortably above the largest legitimate
/// wide-schema Parquet footers seen in practice; tighten if real data
/// stays well below.
pub(crate) const MAX_PARQUET_FOOTER_BYTES: usize = 32 * 1024 * 1024;

/// Maximum number of leaf columns we accept in a Parquet schema.
///
/// Per-column statistics (min/max byte blobs) live inside the footer.
/// Even within `MAX_PARQUET_FOOTER_BYTES`, a 4096-column footer is a
/// reasonable budget; legitimate wide-schema datasets stay well below it.
/// `try_new` is allowed to parse the footer (its allocation is bounded by
/// the byte cap above); the column-count check fires before any row-group
/// reader is built.
pub(crate) const MAX_PARQUET_COLUMNS: usize = 4096;

/// Last four bytes of every valid Parquet file. Used as a cheap shape
/// check before we trust the footer-length field.
const PARQUET_MAGIC: [u8; 4] = *b"PAR1";

/// Decoder for Parquet input.
///
/// Stateless; one instance serves every Parquet resource. Per-resource
/// configuration arrives via [`FormatHints`], but only `declared` is
/// relevant to this layer and is forwarded to validation rather than
/// consumed here.
#[derive(Debug, Default, Clone)]
pub struct ParquetFormat;

impl ParquetFormat {
    pub fn new() -> Self {
        Self
    }
}

impl Format for ParquetFormat {
    fn name(&self) -> &'static str {
        "parquet"
    }

    fn decode<'a>(
        &'a self,
        reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
        _hints: FormatHints,
    ) -> FormatFuture<'a, DecodedStream> {
        Box::pin(decode_parquet(reader))
    }
}

// ── Core decode logic ─────────────────────────────────────────────────────────

async fn decode_parquet(
    mut reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
) -> Result<DecodedStream, FormatError> {
    // Step 1: buffer the entire byte stream into memory.
    // V1 accepted cost; see module-level docstring for the V1.x optimisation
    // path (range-read via AsyncRead + AsyncSeek).
    let mut raw: Vec<u8> = Vec::new();
    reader
        .read_to_end(&mut raw)
        .await
        .map_err(FormatError::Io)?;

    // Pre-decode validation (security review 2026-05-16, footer-bomb).
    // Reject malformed shape and oversized footer-length declarations
    // *before* `ParquetRecordBatchReaderBuilder::try_new` is asked to
    // allocate a buffer sized after the attacker-controlled length field.
    validate_parquet_envelope(&raw)?;

    let (observed_schema, batches) = tokio::task::spawn_blocking(move || {
        let builder = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(raw))
            .map_err(|e| FormatError::Parse(format!("parquet metadata error: {e}")))?;

        // Cap leaf column count. Statistics blobs live inside the
        // footer, so an attacker can fit 3000+ wide columns inside a
        // valid footer envelope. Refuse before any row-group reader is
        // built.
        let num_columns = builder
            .metadata()
            .file_metadata()
            .schema_descr()
            .num_columns();
        if num_columns > MAX_PARQUET_COLUMNS {
            return Err(FormatError::LimitExceeded(
                "parquet schema column count exceeds configured maximum".to_string(),
            ));
        }

        let observed_schema = Arc::clone(builder.schema());
        let reader = builder
            .build()
            .map_err(|e| FormatError::Parse(format!("parquet stream build error: {e}")))?;
        let batches = reader
            .map(|result| {
                result.map_err(|e| FormatError::Parse(format!("parquet batch decode error: {e}")))
            })
            .collect::<Vec<_>>();
        Ok::<_, FormatError>((observed_schema, batches))
    })
    .await
    .map_err(|join_err| {
        FormatError::Parse(format!("parquet decode task panicked: {join_err}"))
    })??;

    Ok(DecodedStream {
        observed_schema,
        batches: Box::pin(stream::iter(batches)),
    })
}

/// Cheap pre-decode validation of the Parquet file envelope.
///
/// A valid Parquet file is at least eight bytes long: the trailing four
/// bytes are the `PAR1` magic, the four bytes before that are a
/// little-endian `u32` footer length. We refuse files that fail any of:
///
/// - shorter than eight bytes (no envelope),
/// - trailing magic is not `PAR1` (not a Parquet file),
/// - declared footer length is larger than the data that precedes it
///   (impossible footer),
/// - declared footer length is larger than [`MAX_PARQUET_FOOTER_BYTES`]
///   (footer-metadata bomb).
///
/// All checks operate on the bytes already in memory at the call site;
/// no extra I/O.
fn validate_parquet_envelope(raw: &[u8]) -> Result<(), FormatError> {
    if raw.len() < 8 {
        return Err(FormatError::Parse(
            "parquet file too small: missing 8-byte footer envelope".to_string(),
        ));
    }
    let n = raw.len();
    if raw[n - 4..n] != PARQUET_MAGIC {
        return Err(FormatError::Parse(
            "parquet file does not end with PAR1 magic".to_string(),
        ));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&raw[n - 8..n - 4]);
    let footer_len = u32::from_le_bytes(len_bytes) as usize;
    // The footer must physically fit before the magic+length envelope.
    if footer_len > n - 8 {
        return Err(FormatError::LimitExceeded(
            "parquet footer length exceeds remaining file bytes".to_string(),
        ));
    }
    if footer_len > MAX_PARQUET_FOOTER_BYTES {
        return Err(FormatError::LimitExceeded(
            "parquet footer length exceeds configured maximum".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{validate_parquet_envelope, MAX_PARQUET_FOOTER_BYTES, PARQUET_MAGIC};
    use crate::format::FormatError;

    /// A buffer shorter than the 8-byte envelope is unconditionally rejected.
    #[test]
    fn rejects_truncated_envelope() {
        let raw = [0u8; 4];
        match validate_parquet_envelope(&raw) {
            Err(FormatError::Parse(_)) => {}
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    /// 8-byte buffer with the wrong magic is a parse error.
    #[test]
    fn rejects_bad_magic() {
        let raw = [0u8; 8];
        match validate_parquet_envelope(&raw) {
            Err(FormatError::Parse(_)) => {}
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    /// A footer length that exceeds the remaining bytes (impossible
    /// footer) is rejected as `LimitExceeded`.
    #[test]
    fn rejects_footer_longer_than_file() {
        // n = 12, n - 8 = 4 available footer bytes, claim 5.
        let mut raw = vec![0u8; 12];
        raw[4..8].copy_from_slice(&5u32.to_le_bytes());
        raw[8..12].copy_from_slice(&PARQUET_MAGIC);
        match validate_parquet_envelope(&raw) {
            Err(FormatError::LimitExceeded(_)) => {}
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    /// Footer length over the configured cap is rejected as `LimitExceeded`.
    #[test]
    fn rejects_oversized_footer_length() {
        // Build a buffer big enough that `footer_len <= n - 8` is true,
        // so the cap is what triggers the rejection, not the "fits in
        // file" check. We claim `MAX_PARQUET_FOOTER_BYTES + 1`.
        let claim = MAX_PARQUET_FOOTER_BYTES + 1;
        let n = claim + 8 + 1;
        let mut raw = vec![0u8; n];
        let len_offset = n - 8;
        raw[len_offset..len_offset + 4].copy_from_slice(&(claim as u32).to_le_bytes());
        raw[n - 4..n].copy_from_slice(&PARQUET_MAGIC);
        match validate_parquet_envelope(&raw) {
            Err(FormatError::LimitExceeded(_)) => {}
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    /// A footer length within the cap and the file bounds passes the
    /// envelope check (deeper validation is up to `try_new`).
    #[test]
    fn accepts_well_formed_envelope() {
        // Layout: [footer payload..][footer_len u32 LE][PAR1].
        // Here: 8 bytes of dummy payload + 4 byte length (claim = 4 fits
        // within the 8 bytes that precede it) + 4 byte magic = 16 bytes.
        let claim: u32 = 4;
        let mut raw = vec![0u8; 16];
        raw[8..12].copy_from_slice(&claim.to_le_bytes());
        raw[12..16].copy_from_slice(&PARQUET_MAGIC);
        validate_parquet_envelope(&raw).expect("well-formed envelope must pass");
    }
}
