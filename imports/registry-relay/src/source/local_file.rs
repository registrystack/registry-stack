// SPDX-License-Identifier: Apache-2.0
//! `LocalFileSource`: byte producer for filesystem-resident resources.
//!
//! Implements the [`Source`] trait by opening a path on the local filesystem
//! via `tokio::fs`. The ETag fingerprint is `dev:inode:mtime_ns:size` so the
//! refresh loop detects both in-place mutations and atomic renames. On
//! non-Unix targets, where device and inode numbers are unavailable, the ETag
//! includes a bounded SHA-256 content digest plus the portable `mtime_ns:size`
//! fingerprint.

#[cfg(any(not(unix), test))]
use std::io::SeekFrom;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

#[cfg(any(not(unix), test))]
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
#[cfg(any(not(unix), test))]
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncSeek, AsyncSeekExt as _};

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
    #[cfg_attr(unix, allow(dead_code))]
    max_content_digest_bytes: u64,
}

impl LocalFileSource {
    pub const DEFAULT_MAX_CONTENT_DIGEST_BYTES: u64 = 256 * 1024 * 1024;

    /// Build a source from a configured path. Canonicalises the path
    /// against the current working directory so audit and operational
    /// logs report a stable identifier even if the working directory
    /// changes later.
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::new_with_content_digest_limit(path, Self::DEFAULT_MAX_CONTENT_DIGEST_BYTES)
    }

    /// Build a source and bound any non-Unix content digest work to the same
    /// byte ceiling used before snapshot decoding.
    pub fn new_with_content_digest_limit(
        path: impl AsRef<Path>,
        max_content_digest_bytes: u64,
    ) -> std::io::Result<Self> {
        let canonical_path = std::fs::canonicalize(path)?;
        Ok(Self {
            canonical_path,
            max_content_digest_bytes,
        })
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
/// and rapid in-place mutations are detected even when the wall-clock second
/// does not change. On non-Unix targets this returns the portable
/// `mtime_ns:size` fingerprint; callers strengthen it with a bounded content
/// digest after opening the file handle.
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

#[cfg(any(not(unix), test))]
fn content_digest_etag(portable_fingerprint: &str, digest: &[u8]) -> String {
    format!("sha256:{}:{portable_fingerprint}", hex_lower(digest))
}

#[cfg(any(not(unix), test))]
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

#[cfg(not(unix))]
async fn strengthen_non_unix_metadata(
    file: &mut tokio::fs::File,
    metadata: &mut SourceMetadata,
    max_content_digest_bytes: u64,
) -> Result<(), SourceError> {
    ensure_content_digest_size_allowed(metadata.size_bytes, max_content_digest_bytes)?;
    let portable_fingerprint = metadata.etag.clone().unwrap_or_else(|| "0:0".to_string());
    let digest = file_content_digest(file).await?;
    metadata.etag = Some(content_digest_etag(&portable_fingerprint, &digest));
    Ok(())
}

#[cfg(any(not(unix), test))]
fn ensure_content_digest_size_allowed(
    size_bytes: Option<u64>,
    max_content_digest_bytes: u64,
) -> Result<(), SourceError> {
    if let Some(size_bytes) = size_bytes {
        if size_bytes > max_content_digest_bytes {
            return Err(SourceError::Unreadable(format!(
                "source exceeds configured maximum before content digest: {size_bytes} > {max_content_digest_bytes}"
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn file_content_digest(file: &mut tokio::fs::File) -> Result<Vec<u8>, SourceError> {
    content_digest_for_reader(file).await
}

#[cfg(any(not(unix), test))]
async fn content_digest_for_reader<R>(reader: &mut R) -> Result<Vec<u8>, SourceError>
where
    R: AsyncRead + AsyncSeek + Unpin,
{
    reader.seek(SeekFrom::Start(0)).await.map_err(map_io_err)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await.map_err(map_io_err)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    reader.seek(SeekFrom::Start(0)).await.map_err(map_io_err)?;
    Ok(hasher.finalize().to_vec())
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
            #[cfg(not(unix))]
            let mut file = file;
            // Stat the opened handle, not the path. This keeps the
            // size/ETag snapshot tied to the bytes that will be read even
            // if the configured path is replaced between syscalls.
            let std_meta = file.metadata().await.map_err(map_io_err)?;
            let metadata = metadata_from_std(std_meta);
            #[cfg(not(unix))]
            let metadata = {
                let mut metadata = metadata;
                strengthen_non_unix_metadata(
                    &mut file,
                    &mut metadata,
                    self.max_content_digest_bytes,
                )
                .await?;
                metadata
            };

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
            #[cfg(not(unix))]
            let mut file = file;
            let std_meta = file.metadata().await.map_err(map_io_err)?;
            let metadata = metadata_from_std(std_meta);
            #[cfg(not(unix))]
            let metadata = {
                let mut metadata = metadata;
                strengthen_non_unix_metadata(
                    &mut file,
                    &mut metadata,
                    self.max_content_digest_bytes,
                )
                .await?;
                metadata
            };
            Ok(metadata)
        })
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt as _;

    use super::{
        content_digest_etag, content_digest_for_reader, ensure_content_digest_size_allowed,
    };

    #[test]
    fn content_digest_etag_changes_when_digest_changes() {
        let portable_fingerprint = "123456789:42";
        let first = content_digest_etag(portable_fingerprint, &[0xab; 32]);
        let second = content_digest_etag(portable_fingerprint, &[0xcd; 32]);

        assert_ne!(first, second);
        assert!(first.starts_with("sha256:"));
        assert!(first.ends_with(":123456789:42"));
    }

    #[tokio::test]
    async fn content_digest_for_reader_rewinds_before_returning() {
        let mut reader = std::io::Cursor::new(b"payload".to_vec());

        let digest = content_digest_for_reader(&mut reader)
            .await
            .expect("digest computes");
        assert_eq!(digest.len(), 32);

        let mut bytes = Vec::new();
        reader
            .read_to_end(&mut bytes)
            .await
            .expect("reader remains readable");
        assert_eq!(bytes, b"payload");
    }

    #[test]
    fn content_digest_size_guard_rejects_oversized_sources() {
        let error = ensure_content_digest_size_allowed(Some(11), 10)
            .expect_err("oversized digest input rejected");

        assert!(
            matches!(error, crate::source::SourceError::Unreadable(ref message) if message.contains("11 > 10")),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn content_digest_size_guard_allows_unknown_or_bounded_sizes() {
        ensure_content_digest_size_allowed(None, 10).expect("unknown size allowed");
        ensure_content_digest_size_allowed(Some(10), 10).expect("bounded size allowed");
    }
}
