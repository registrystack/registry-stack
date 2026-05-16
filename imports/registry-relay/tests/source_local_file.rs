// SPDX-License-Identifier: Apache-2.0
//! Integration tests for `LocalFileSource`.
//!
//! Coverage:
//! - descriptor scheme and canonical-path target
//! - open yields all file bytes via `AsyncRead`
//! - metadata captures mtime, size, and ETag without opening the file
//! - ETag rotates on atomic replace (write tmp + rename)
//! - ETag rotates on in-place mtime change (same path, same inode on APFS
//!   if possible, but ETag must still change because mtime_ns changes)
//! - open on a missing path returns `SourceError::NotFound`
//! - metadata on a missing path returns `SourceError::NotFound`
//!
//! These tests use `tempfile::tempdir()` for filesystem fixtures so they
//! are isolated and self-cleaning.

use std::io::Write as _;
use std::path::PathBuf;

use data_gate::source::local_file::LocalFileSource;
use data_gate::source::{Source, SourceError};
use tempfile::tempdir;
use tokio::io::AsyncReadExt as _;

// ─── helpers ─────────────────────────────────────────────────────────────────

/// Write `contents` to `path`, creating or truncating the file.
fn write_file(path: &PathBuf, contents: &[u8]) {
    let mut f = std::fs::File::create(path).expect("create file");
    f.write_all(contents).expect("write contents");
    f.flush().expect("flush");
    // fsync so mtime is durable on APFS (which coalesces writes within
    // the same HFS+ timestamp bucket without a sync).
    f.sync_all().expect("sync_all");
}

/// Write `contents` to a temp path, then atomically rename to `dest`.
fn atomic_write(dest: &PathBuf, contents: &[u8]) {
    let dir = dest.parent().expect("dest has parent");
    let mut tmp = dir.to_path_buf();
    tmp.push(".tmp-test-atomic");
    write_file(&tmp, contents);
    std::fs::rename(&tmp, dest).expect("atomic rename");
}

// ─── 1. descriptor ───────────────────────────────────────────────────────────

#[tokio::test]
async fn descriptor_returns_canonical_path_and_file_scheme() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("data.csv");
    write_file(&path, b"hello");

    let source = LocalFileSource::new(&path).expect("new");
    let desc = source.descriptor();

    assert_eq!(desc.scheme, "file");
    // The target must be an absolute path that resolves to the same file.
    let target = PathBuf::from(&desc.target);
    assert!(target.is_absolute(), "target is absolute");
    assert_eq!(
        std::fs::canonicalize(&path).expect("canonicalize"),
        std::fs::canonicalize(&target).expect("canonicalize target"),
    );
}

// ─── 2. open yields file bytes ────────────────────────────────────────────────

#[tokio::test]
async fn open_returns_reader_yielding_file_bytes() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("payload.bin");
    let expected = b"the quick brown fox jumps over the lazy dog";
    write_file(&path, expected);

    let source = LocalFileSource::new(&path).expect("new");
    let opened = source.open().await.expect("open succeeds");

    let mut buf = Vec::new();
    let mut reader = opened.reader;
    reader.read_to_end(&mut buf).await.expect("read_to_end");

    assert_eq!(&buf, expected);
}

// ─── 3. metadata fields ───────────────────────────────────────────────────────

#[tokio::test]
async fn metadata_captures_mtime_size_and_etag_without_opening() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("meta.bin");
    let content = b"metadata test content";
    write_file(&path, content);

    let source = LocalFileSource::new(&path).expect("new");
    let meta = source.metadata().await.expect("metadata succeeds");

    assert!(meta.mtime.is_some(), "mtime must be Some");
    assert_eq!(
        meta.size_bytes,
        Some(content.len() as u64),
        "size_bytes matches content length"
    );

    let etag = meta.etag.expect("etag must be Some");
    // ETag shape: "dev:inode:mtime_ns:size"
    let parts: Vec<&str> = etag.split(':').collect();
    assert_eq!(
        parts.len(),
        4,
        "ETag has 4 colon-separated parts, got: {etag}"
    );
    // Each part must parse as a u64 (all four fields are numeric).
    for part in &parts {
        part.parse::<u64>()
            .unwrap_or_else(|_| panic!("ETag part '{part}' is not a u64; full etag: {etag}"));
    }
    // The size part (4th) must match the file size.
    assert_eq!(
        parts[3].parse::<u64>().unwrap(),
        content.len() as u64,
        "ETag size component matches content length"
    );
}

// ─── 4. ETag rotates on atomic replace ────────────────────────────────────────

#[tokio::test]
async fn etag_rotates_on_atomic_replace() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("rotating.csv");
    write_file(&path, b"version-one");

    let source = LocalFileSource::new(&path).expect("new");
    let etag1 = source
        .metadata()
        .await
        .expect("metadata 1")
        .etag
        .expect("etag 1");

    // Atomic replace: new inode on APFS, new mtime everywhere.
    atomic_write(&path, b"version-two");

    let etag2 = source
        .metadata()
        .await
        .expect("metadata 2")
        .etag
        .expect("etag 2");

    assert_ne!(etag1, etag2, "ETag must rotate after atomic replace");
}

// ─── 5. ETag rotates on in-place mtime change ────────────────────────────────

#[tokio::test]
async fn etag_rotates_on_in_place_mtime_change() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("inplace.csv");
    write_file(&path, b"original content here");

    let source = LocalFileSource::new(&path).expect("new");
    let etag1 = source
        .metadata()
        .await
        .expect("metadata 1")
        .etag
        .expect("etag 1");

    // Sleep long enough for the filesystem mtime to tick. APFS has
    // nanosecond resolution so 10 ms is sufficient on macOS.
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    // Overwrite the file in-place (same path; inode may or may not
    // change depending on the OS; mtime_ns must change).
    write_file(&path, b"replaced content here");

    let etag2 = source
        .metadata()
        .await
        .expect("metadata 2")
        .etag
        .expect("etag 2");

    assert_ne!(
        etag1, etag2,
        "ETag must rotate after in-place content change"
    );
}

// ─── 6. open on missing path returns NotFound ─────────────────────────────────

#[tokio::test]
async fn open_on_missing_path_returns_not_found() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("present.csv");
    write_file(&path, b"exists for construction");

    // Construction must succeed (file exists at new() time).
    let source = LocalFileSource::new(&path).expect("new");

    // Delete the file before calling open().
    std::fs::remove_file(&path).expect("remove");

    match source.open().await {
        Err(SourceError::NotFound) => {} // expected
        Err(other) => panic!("expected SourceError::NotFound, got: {other:?}"),
        Ok(_) => panic!("open on missing path must not succeed"),
    }
}

// ─── 7. metadata on missing path returns NotFound ─────────────────────────────

#[tokio::test]
async fn metadata_on_missing_path_returns_not_found() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("present2.csv");
    write_file(&path, b"exists for construction");

    let source = LocalFileSource::new(&path).expect("new");

    std::fs::remove_file(&path).expect("remove");

    let err = source
        .metadata()
        .await
        .expect_err("metadata on missing path must fail");
    assert!(
        matches!(err, SourceError::NotFound),
        "expected SourceError::NotFound, got: {err:?}"
    );
}
