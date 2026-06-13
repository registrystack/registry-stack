// SPDX-License-Identifier: Apache-2.0
//! `LocalFileSource`: byte producer for filesystem-resident resources.
//!
//! Implements the [`Source`] trait by opening a path on the local filesystem
//! via `tokio::fs`. The ETag fingerprint is `dev:inode:mtime_ns:size` so the
//! refresh loop detects both in-place mutations and atomic renames. On
//! non-Unix targets, where device and inode numbers are unavailable, the
//! fingerprint degrades to `mtime_ns:size`.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use time::OffsetDateTime;

use crate::source::{
    OpenedSource, Source, SourceDescriptor, SourceError, SourceFuture, SourceMetadata,
};

/// A [`Source`] that reads bytes from a path on the local filesystem.
///
/// Construction is cheap and does no I/O; [`open`] and [`metadata`]
/// perform the syscalls. The path is canonicalised at construction so
/// downstream descriptors and audit records carry the absolute form.
///
/// [`open`]: LocalFileSource::open
/// [`metadata`]: LocalFileSource::metadata
#[derive(Debug, Clone)]
pub struct LocalFileSource {
    canonical_path: PathBuf,
}

impl LocalFileSource {
    /// Build a source from a configured path. Canonicalises the path
    /// against the current working directory so audit and operational
    /// logs report a stable identifier even if the working directory
    /// changes later.
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let canonical_path = std::fs::canonicalize(path)?;
        Ok(Self { canonical_path })
    }

    /// The canonicalised path. Useful for tests; matches
    /// `descriptor().target`.
    pub fn path(&self) -> &Path {
        &self.canonical_path
    }
}

/// Convert a `std::fs::Metadata` into a `SourceMetadata` snapshot.
///
/// On Unix the ETag is `dev:inode:mtime_ns:size` using the Unix metadata
/// extension fields. Nanosecond mtime resolution ensures atomic-replace
/// and rapid in-place mutations are detected even when the wall-clock
/// second does not change. On non-Unix targets the ETag is
/// `mtime_ns:size` from the portable `modified()` timestamp, which still
/// catches in-place mutations but cannot distinguish an atomic rename
/// that preserves both mtime and size.
fn metadata_from_std(std_meta: std::fs::Metadata) -> SourceMetadata {
    let size = std_meta.len();

    #[cfg(unix)]
    let etag = {
        let dev = std_meta.dev();
        let ino = std_meta.ino();
        // `mtime_nsec()` is the sub-second nanosecond fraction; combine with
        // the full second to get a single nanosecond count since the epoch.
        let mtime_ns = (std_meta.mtime() as u64)
            .saturating_mul(1_000_000_000)
            .saturating_add(std_meta.mtime_nsec() as u64);
        format!("{dev}:{ino}:{mtime_ns}:{size}")
    };
    #[cfg(not(unix))]
    let etag = {
        let mtime_ns = std_meta
            .modified()
            .ok()
            .and_then(|st| st.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        format!("{mtime_ns}:{size}")
    };

    let mtime = std_meta.modified().ok().and_then(|st| {
        OffsetDateTime::from_unix_timestamp_nanos(
            st.duration_since(std::time::UNIX_EPOCH).ok()?.as_nanos() as i128,
        )
        .ok()
    });

    SourceMetadata {
        mtime,
        size_bytes: Some(size),
        etag: Some(etag),
        content_type: None,
    }
}

/// Map a `std::io::Error` to a `SourceError`.
fn map_io_err(err: std::io::Error) -> SourceError {
    if err.kind() == std::io::ErrorKind::NotFound {
        SourceError::NotFound
    } else {
        SourceError::Io(err)
    }
}

impl Source for LocalFileSource {
    fn descriptor(&self) -> SourceDescriptor {
        SourceDescriptor {
            scheme: "file",
            target: self.canonical_path.display().to_string(),
        }
    }

    fn open<'a>(&'a self) -> SourceFuture<'a, OpenedSource> {
        Box::pin(async move {
            let file = tokio::fs::File::open(&self.canonical_path)
                .await
                .map_err(map_io_err)?;
            // Stat the opened handle, not the path. This keeps the
            // size/ETag snapshot tied to the bytes that will be read even
            // if the configured path is replaced between syscalls.
            let std_meta = file.metadata().await.map_err(map_io_err)?;
            let metadata = metadata_from_std(std_meta);

            Ok(OpenedSource {
                reader: Box::pin(file),
                metadata,
            })
        })
    }

    fn metadata<'a>(&'a self) -> SourceFuture<'a, SourceMetadata> {
        Box::pin(async move {
            // Open the file handle first, then stat it so the metadata
            // corresponds to the same inode that was opened, eliminating
            // the TOCTOU window that exists when using the path-based
            // `tokio::fs::metadata` call.
            let file = tokio::fs::File::open(&self.canonical_path)
                .await
                .map_err(map_io_err)?;
            let std_meta = file.metadata().await.map_err(map_io_err)?;
            Ok(metadata_from_std(std_meta))
        })
    }
}
