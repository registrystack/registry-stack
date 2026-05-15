// SPDX-License-Identifier: Apache-2.0
//! Byte-producing sources for ingestion.
//!
//! Trait shape, field semantics, and forward-compat story are pinned in
//! `decisions/wave-1.md` Section 2.1. This file is the Wave 1 Architect
//! precondition: trait surface + supporting types with stub bodies, so
//! all seven Wave 1 tracks can compile against the contract in parallel.
//! Track 1 (Source + LocalFileSource) replaces the stubs with the real
//! `LocalFileSource` impl and completes the error mapping.
//!
//! ## Source / Format separation (W1-1)
//!
//! A `Source` produces raw bytes plus a change token; a `Format` decodes
//! those bytes into Arrow `RecordBatch`es. They are paired by
//! `IngestPlan`. Mixing in a new byte producer (HTTP, S3, SharePoint)
//! costs nothing in the format layer, and vice versa. This mirrors
//! DataFusion's `ObjectStore` + `FileFormat` split.

use std::future::Future;
use std::pin::Pin;

use time::OffsetDateTime;
use tokio::io::AsyncRead;

pub mod local_file;

/// A byte producer for ingestion.
///
/// Implementations open a logical resource (local file path, future HTTP
/// URL, future S3 key) and yield a byte stream plus a change token.
/// They are agnostic to the decoded format; pairing with a [`Format`]
/// happens in `IngestPlan`.
///
/// V1 impl: [`local_file::LocalFileSource`].
/// V1.x targets: HTTP, S3, SharePoint, Nextcloud. Each is a new struct
/// implementing this trait; no other code in the gateway changes.
///
/// Forward compatibility:
/// - Streaming sources (Kafka, CDC): add `async fn subscribe()
///   -> Result<BoxStream<'static, ChangeEvent>>` in V2. Not in V1.
/// - Pre-fetch sizing / range reads: a `range()` method may join the
///   trait in V1.x; the current shape does not preclude it.
///
/// [`Format`]: crate::format::Format
pub trait Source: Send + Sync + 'static {
    /// Stable identifier for this source instance, for logging and
    /// audit. Never includes secrets; for `LocalFileSource` this is the
    /// canonical path string.
    fn descriptor(&self) -> SourceDescriptor;

    /// Open the source for reading. Returns a boxed `AsyncRead` plus a
    /// [`SourceMetadata`] snapshot captured at open time (mtime, size,
    /// content-type hint). The reader yields raw bytes; decoding is the
    /// caller's job. `Format::decode` consumes the reader exactly once.
    fn open<'a>(&'a self) -> SourceFuture<'a, OpenedSource>;

    /// Sample the source's change token without reading the body. Used
    /// by the refresh loop's `mtime` policy. Returns `None` for fields
    /// the source can't expose (refresh degrades to `interval` or
    /// `manual`).
    fn metadata<'a>(&'a self) -> SourceFuture<'a, SourceMetadata>;
}

/// Boxed [`AsyncRead`] plus the metadata captured at open time. The
/// metadata is the value the change-token comparison MUST use for this
/// read; sampling `metadata()` again later would race against an
/// in-flight refresh.
pub struct OpenedSource {
    pub reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    pub metadata: SourceMetadata,
}

/// Snapshot of source-level change-detection inputs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceMetadata {
    /// File mtime (local-file source). `None` for sources that don't
    /// expose mtime (future HTTP without `Last-Modified`).
    pub mtime: Option<OffsetDateTime>,
    /// Byte size when known (skipped for streaming sources).
    pub size_bytes: Option<u64>,
    /// `ETag` or equivalent strong validator. Local-file source returns
    /// a `dev:inode:mtime_ns:size` fingerprint so refresh can detect
    /// rename-in-place or atomic-replace mutations the mtime alone
    /// might miss.
    pub etag: Option<String>,
    /// Content-type hint from the producer. Local-file source returns
    /// `None` (extension-based dispatch happens in the format layer).
    pub content_type: Option<String>,
}

/// Stable identifier for an open source instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceDescriptor {
    /// Scheme: `file`, `http`, `s3`, ... Matches the `SourceConfig` tag.
    pub scheme: &'static str,
    /// Human-readable target (path, URL minus credentials, S3 key).
    pub target: String,
}

/// Manually-typed future to match the project's existing
/// non-`async_trait` convention ([`crate::auth::AuthProvider`],
/// [`crate::audit::AuditSink`]).
pub type SourceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, SourceError>> + Send + 'a>>;

/// Errors raised by a [`Source`] impl. Mapped to `ingest.*` taxonomy
/// codes in `IngestPlan`.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source not found")]
    NotFound,
    #[error("source unreadable: {0}")]
    Unreadable(String),
    #[error("source I/O error")]
    Io(#[source] std::io::Error),
}
