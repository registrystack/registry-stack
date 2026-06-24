// SPDX-License-Identifier: Apache-2.0
//! Decoders from a byte stream into Arrow `RecordBatch`es.
//!
//! Formats are stateless decoders. Per-resource details such as sheet
//! names, header rows, delimiters, and declared schemas arrive through
//! [`FormatHints`], which keeps the decoders reusable across datasets.
//!
//! ## Source / Format separation
//!
//! See `crate::source` for the byte producer side. The two layers stay
//! decoupled so V1.x can ship new sources without touching decoders and
//! vice versa.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use futures::stream::BoxStream;
use tokio::io::AsyncRead;

use crate::ingest::declared_schema::DeclaredSchema;

pub mod csv;
pub mod parquet;
pub mod xlsx;

/// A decoder from a byte stream into Arrow `RecordBatch`es.
///
/// Implementations are stateless. Per-resource hints (header row, data
/// range, sheet name, declared schema) arrive as [`FormatHints`] so the
/// same decoder serves every resource of its format.
///
/// V1 impls: [`csv::CsvFormat`], [`xlsx::XlsxFormat`],
/// [`parquet::ParquetFormat`]. Future targets include `JsonlFormat`,
/// `AvroFormat`, `ArrowIpcFormat`. Each is a new struct plus one line
/// in [`FormatRegistry::with_v1_defaults`].
///
/// XLSX note: `calamine` is non-streaming. `XlsxFormat::decode` reads
/// the entire workbook into memory before yielding the first batch.
/// `IngestPlan` enforces a max-file-bytes guard before calling this
/// trait; `XlsxFormat` does not enforce it itself.
pub trait Format: Send + Sync + 'static {
    /// Canonical name (`"csv"`, `"xlsx"`, `"parquet"`); used in audit
    /// and operational logs.
    fn name(&self) -> &'static str;

    /// Decode a byte stream into a `RecordBatch` stream.
    ///
    /// Implementations consume `reader` exactly once. `hints` carries
    /// per-resource configuration (sheet, header row, delimiter,
    /// declared schema for type coercion). Schema *validation* is not
    /// the format's job; it returns the observed Arrow schema and lets
    /// `ingest::validation` decide whether to accept.
    fn decode<'a>(
        &'a self,
        reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
        hints: FormatHints,
    ) -> FormatFuture<'a, DecodedStream>;
}

/// `RecordBatch` stream plus the schema as observed at decode time.
/// `IngestPlan` uses the observed schema for validation against the
/// declared schema in config.
pub struct DecodedStream {
    pub observed_schema: SchemaRef,
    pub batches: BoxStream<'static, Result<RecordBatch, FormatError>>,
}

/// Per-resource decoding configuration. Built by `IngestPlan` from the
/// `ResourceConfig`; never reaches back into `Config` from inside a
/// `Format` impl.
#[derive(Clone, Debug)]
pub struct FormatHints {
    /// XLSX: workbook sheet name.
    pub sheet: Option<String>,
    /// CSV / XLSX: header row (1-indexed in config; `None` = no header
    /// row, columns named `c0..cN`).
    pub header_row: Option<u32>,
    /// XLSX: spreadsheet range, e.g. `"A2:E100000"`.
    pub data_range: Option<String>,
    /// CSV: byte delimiter, default `b','`.
    pub delimiter: Option<u8>,
    /// CSV: byte quote character, default `b'"'`.
    pub quote: Option<u8>,
    /// Declared field types from the config. Decoders MAY use this for
    /// type coercion (e.g. CSV string-to-date parsing). `None` per
    /// field means "let the decoder infer".
    pub declared: Arc<DeclaredSchema>,
}

/// Errors raised by a [`Format`] impl. Mapped to `ingest.*` taxonomy
/// codes in `IngestPlan`.
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("format parse error: {0}")]
    Parse(String),
    #[error("format I/O error")]
    Io(#[source] std::io::Error),
    #[error("format limit exceeded: {0}")]
    LimitExceeded(String),
}

/// Manually-typed future to match the project's existing
/// non-`async_trait` convention.
pub type FormatFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, FormatError>> + Send + 'a>>;

/// Registry of available formats, looked up by name. V1 registers
/// CSV/XLSX/Parquet at startup. The registry is held in `AppState`; the
/// ingest task holds a clone.
#[derive(Clone, Default)]
pub struct FormatRegistry {
    by_name: HashMap<&'static str, Arc<dyn Format>>,
}

impl FormatRegistry {
    /// Empty registry. Prefer [`with_v1_defaults`](Self::with_v1_defaults)
    /// in production wiring.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry pre-populated with CSV, XLSX, Parquet.
    pub fn with_v1_defaults() -> Self {
        let mut r = Self::new();
        r.register("csv", Arc::new(csv::CsvFormat::new()));
        r.register("xlsx", Arc::new(xlsx::XlsxFormat::new()));
        r.register("parquet", Arc::new(parquet::ParquetFormat::new()));
        r
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn Format>> {
        self.by_name.get(name).cloned()
    }

    pub fn register(&mut self, name: &'static str, format: Arc<dyn Format>) {
        self.by_name.insert(name, format);
    }
}

impl std::fmt::Debug for FormatRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FormatRegistry")
            .field("names", &self.by_name.keys().collect::<Vec<_>>())
            .finish()
    }
}
