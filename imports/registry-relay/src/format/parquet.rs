// SPDX-License-Identifier: Apache-2.0
//! `ParquetFormat`: decode Parquet byte streams to Arrow `RecordBatch`es.
//!
//! Parquet is Arrow-native, so this decoder is mostly a passthrough:
//! buffer the bytes, hand them to
//! `parquet::arrow::async_reader::ParquetRecordBatchStreamBuilder`, and
//! yield the resulting `RecordBatch` stream. The observed schema is read
//! directly from the Parquet file metadata.
//!
//! ## V1 simplicity note
//!
//! The reader buffers the entire input into memory before handing it to
//! `ParquetRecordBatchStreamBuilder`. The async reader can accept an
//! `AsyncFileReader` that does range reads, which would avoid the full
//! buffer, but that requires `AsyncRead + AsyncSeek` from the caller
//! (the `Format::decode` surface only promises `AsyncRead`). Wrapping
//! the buffered bytes in a `Cursor<Bytes>` provides the required `Seek`
//! support at the cost of memory. This is a V1.x optimisation target.
//!
//! ## FormatHints
//!
//! Parquet is self-describing. The fields `sheet`, `header_row`,
//! `data_range`, `delimiter`, and `quote` are not applicable and are
//! silently ignored. `hints.declared` is not used for coercion here;
//! schema validation against the declared types is Track 5's job
//! (`src/ingest/validation.rs`). This decoder returns the observed
//! Arrow schema as-is.

use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;

use datafusion::parquet::arrow::async_reader::ParquetRecordBatchStreamBuilder;
use futures::StreamExt as _;
use tokio::io::{AsyncRead, AsyncReadExt as _};

use crate::format::{DecodedStream, Format, FormatError, FormatFuture, FormatHints};

/// Decoder for Parquet input.
///
/// Stateless; one instance serves every Parquet resource. Per-resource
/// configuration arrives via [`FormatHints`], but only `declared` is
/// relevant to this layer (and is forwarded to Track 5 validation rather
/// than consumed here).
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

    // Step 2: wrap in a seekable cursor and hand to the async Parquet reader.
    // `Cursor<Vec<u8>>` implements both `AsyncRead` and `AsyncSeek`, which
    // satisfies the `AsyncFileReader` blanket impl in the `parquet` crate.
    let cursor = Cursor::new(raw);

    let builder = ParquetRecordBatchStreamBuilder::new(cursor)
        .await
        .map_err(|e| FormatError::Parse(format!("parquet metadata error: {e}")))?;

    // Step 3: capture the observed schema before consuming the builder.
    let observed_schema = Arc::clone(builder.schema());

    // Step 4: build the record batch stream.
    let stream = builder
        .build()
        .map_err(|e| FormatError::Parse(format!("parquet stream build error: {e}")))?;

    // Step 5: map `ParquetError` to `FormatError` on the stream items.
    let mapped = stream.map(|result| {
        result.map_err(|e| FormatError::Parse(format!("parquet batch decode error: {e}")))
    });

    Ok(DecodedStream {
        observed_schema,
        batches: Box::pin(mapped),
    })
}
