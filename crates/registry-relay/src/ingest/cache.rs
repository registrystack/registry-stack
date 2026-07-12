// SPDX-License-Identifier: Apache-2.0
//! Parquet cache: atomic write + rename + GC.
//!
//! Write path: stream batches into `.tmp-<ULID>.parquet`, fsync, then
//! POSIX-rename to `<ULID>.parquet`. Rename is atomic within the same
//! filesystem per POSIX. Crash-recovery: stale `.tmp-*` files are
//! deleted by [`gc_resource`] on the next successful refresh.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use datafusion::arrow::datatypes::SchemaRef;
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::parquet::arrow::async_writer::AsyncArrowWriter;
use datafusion::parquet::basic::Compression;
use datafusion::parquet::file::properties::WriterProperties;
use futures::{Stream, StreamExt as _};
use tokio::fs;
use ulid::Ulid;

use crate::config::{DatasetId, ResourceId};
use crate::error::IngestError;

/// Resolves filesystem paths for one cache root.
///
/// All paths are under `<root>/<dataset_id>/<resource_id>/`.
pub struct CacheLayout {
    pub root: Arc<Path>,
}

impl CacheLayout {
    pub fn new(root: Arc<Path>) -> Self {
        Self { root }
    }

    /// `<root>/<dataset>/<resource>/<ulid>.parquet`
    pub fn final_path(&self, dataset: &DatasetId, resource: &ResourceId, ulid: Ulid) -> PathBuf {
        self.dir(dataset, resource).join(format!("{ulid}.parquet"))
    }

    /// `<root>/<dataset>/<resource>/.tmp-<ulid>.parquet`
    pub fn tmp_path(&self, dataset: &DatasetId, resource: &ResourceId, ulid: Ulid) -> PathBuf {
        self.dir(dataset, resource)
            .join(format!(".tmp-{ulid}.parquet"))
    }

    fn dir(&self, dataset: &DatasetId, resource: &ResourceId) -> PathBuf {
        self.root.join(dataset.as_str()).join(resource.as_str())
    }
}

/// Write a stream of `RecordBatch`es to a Parquet file atomically.
///
/// 1. Creates parent directories if absent.
/// 2. Streams batches into `tmp_path` via `AsyncArrowWriter` (SNAPPY).
/// 3. fsyncs the tmp file before closing.
/// 4. POSIX-renames `tmp_path` → `final_path` (atomic on same fs).
/// 5. Returns `final_path`.
///
/// If anything fails, the tmp file is best-effort removed; `final_path`
/// is untouched.
pub async fn write_atomic(
    layout: &CacheLayout,
    dataset: &DatasetId,
    resource: &ResourceId,
    ulid: Ulid,
    schema: SchemaRef,
    batches: impl Stream<Item = Result<RecordBatch, IngestError>> + Unpin,
) -> Result<PathBuf, IngestError> {
    let final_path = layout.final_path(dataset, resource, ulid);
    let tmp_path = layout.tmp_path(dataset, resource, ulid);

    // Ensure parent directory exists.
    let dir = final_path
        .parent()
        .expect("final_path always has a parent under cache root");
    fs::create_dir_all(dir)
        .await
        .map_err(|e| cache_err("create_dir_all", e))?;

    let result = write_tmp(&tmp_path, schema, batches).await;
    match result {
        Err(e) => {
            best_effort_remove(&tmp_path).await;
            Err(e)
        }
        Ok(()) => {
            // Atomic rename.
            fs::rename(&tmp_path, &final_path)
                .await
                .map_err(|e| cache_err("rename", e))?;
            Ok(final_path)
        }
    }
}

/// Stream batches into a Parquet file at `tmp_path`, then fsync.
async fn write_tmp(
    tmp_path: &Path,
    schema: SchemaRef,
    mut batches: impl Stream<Item = Result<RecordBatch, IngestError>> + Unpin,
) -> Result<(), IngestError> {
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .build();

    // Open the tmp file for writing.
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp_path)
        .await
        .map_err(|e| cache_err("open_tmp", e))?;

    let mut writer = AsyncArrowWriter::try_new(file, schema, Some(props)).map_err(|e| {
        tracing::error!(
            event = "ingest.cache_write_failed",
            path = %tmp_path.display(),
            error = %e,
        );
        IngestError::CacheWriteFailed
    })?;

    while let Some(batch_result) = batches.next().await {
        let batch = batch_result?;
        writer.write(&batch).await.map_err(|e| {
            tracing::error!(
                event = "ingest.cache_write_failed",
                path = %tmp_path.display(),
                error = %e,
            );
            IngestError::CacheWriteFailed
        })?;
    }

    // Finish flushes row groups; get back the underlying file for fsync.
    writer.finish().await.map_err(|e| {
        tracing::error!(
            event = "ingest.cache_write_failed",
            path = %tmp_path.display(),
            error = %e,
        );
        IngestError::CacheWriteFailed
    })?;
    let raw_file = writer.into_inner();

    // fsync before rename so the data survives a crash between rename and
    // the OS flushing its page cache.
    raw_file.sync_all().await.map_err(|e| {
        tracing::error!(
            event = "ingest.cache_write_failed",
            path = %tmp_path.display(),
            error = %e,
        );
        IngestError::CacheWriteFailed
    })?;

    Ok(())
}

/// Garbage-collect stale Parquet files for one resource.
///
/// Keeps the file matching `keep_ulid` plus the immediately previous
/// `<ulid>.parquet`; deletes older cache files and any `.tmp-*.parquet`
/// left from crashes. Best-effort: logs warnings
/// but never errors the pipeline.
pub async fn gc_resource(
    layout: &CacheLayout,
    dataset: &DatasetId,
    resource: &ResourceId,
    keep_ulid: Ulid,
) {
    gc_resource_with_retention(layout, dataset, resource, keep_ulid, 2).await;
}

/// Garbage-collect stale cache files while retaining the active generation and
/// a bounded number of immediately preceding generations.
pub async fn gc_resource_with_retention(
    layout: &CacheLayout,
    dataset: &DatasetId,
    resource: &ResourceId,
    keep_ulid: Ulid,
    retention_generations: u16,
) {
    let dir = layout
        .final_path(dataset, resource, keep_ulid)
        .parent()
        .expect("always has parent")
        .to_path_buf();

    let keep_name = format!("{keep_ulid}.parquet");
    let retention_generations = usize::from(retention_generations.max(1));
    let mut parquet_entries = Vec::new();

    let mut entries = match fs::read_dir(&dir).await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                event = "ingest.gc_read_dir_failed",
                dir = %dir.display(),
                error = %e,
            );
            return;
        }
    };

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(
                    event = "ingest.gc_entry_error",
                    dir = %dir.display(),
                    error = %e,
                );
                break;
            }
        };

        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();

        if name.starts_with(".tmp-") {
            if let Err(e) = fs::remove_file(entry.path()).await {
                tracing::warn!(
                    event = "ingest.gc_remove_failed",
                    path = %entry.path().display(),
                    error = %e,
                );
            } else {
                tracing::debug!(
                    event = "ingest.gc_removed",
                    path = %entry.path().display(),
                );
            }
            continue;
        }

        if name.ends_with(".parquet") {
            if let Some(stem) = name.strip_suffix(".parquet") {
                if let Ok(ulid) = stem.parse::<Ulid>() {
                    let _ = ulid;
                }
            }
            parquet_entries.push(entry.path());
        }
    }

    let mut generations = parquet_entries
        .iter()
        .filter_map(|path| {
            path.file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<Ulid>().ok())
        })
        .collect::<Vec<_>>();
    generations.sort_unstable_by(|left, right| right.cmp(left));
    let retained = generations
        .into_iter()
        .filter(|generation| *generation <= keep_ulid)
        .take(retention_generations)
        .map(|generation| format!("{generation}.parquet"))
        .collect::<std::collections::BTreeSet<_>>();

    for path in parquet_entries {
        let Some(name) = path.file_name().map(|name| name.to_string_lossy()) else {
            continue;
        };
        let should_delete = name != keep_name && !retained.contains(name.as_ref());

        if should_delete {
            if let Err(e) = fs::remove_file(&path).await {
                tracing::warn!(
                    event = "ingest.gc_remove_failed",
                    path = %path.display(),
                    error = %e,
                );
            } else {
                tracing::debug!(
                    event = "ingest.gc_removed",
                    path = %path.display(),
                );
            }
        }
    }
}

async fn best_effort_remove(path: &Path) {
    if let Err(e) = fs::remove_file(path).await {
        if e.kind() != io::ErrorKind::NotFound {
            tracing::warn!(
                event = "ingest.tmp_cleanup_failed",
                path = %path.display(),
                error = %e,
            );
        }
    }
}

fn cache_err(op: &str, e: io::Error) -> IngestError {
    tracing::error!(
        event = "ingest.cache_write_failed",
        operation = op,
        error = %e,
    );
    IngestError::CacheWriteFailed
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use datafusion::arrow::array::{Int64Array, StringArray};
    use datafusion::arrow::datatypes::{DataType, Field, Schema, SchemaRef};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use futures::stream;
    use tempfile::TempDir;

    use super::{gc_resource, write_atomic, CacheLayout};
    use crate::config::{DatasetId, ResourceId};
    use crate::error::IngestError;

    fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
        serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
    }

    fn simple_batch() -> (SchemaRef, RecordBatch) {
        let schema = Arc::new(Schema::new(vec![
            Field::new("id", DataType::Int64, false),
            Field::new("name", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(Int64Array::from(vec![1_i64, 2])),
                Arc::new(StringArray::from(vec!["alice", "bob"])),
            ],
        )
        .expect("record batch");

        (schema, batch)
    }

    #[tokio::test]
    async fn write_atomic_writes_readable_parquet_and_removes_tmp() {
        let tmp = TempDir::new().expect("tempdir");
        let layout = CacheLayout::new(Arc::from(tmp.path()));
        let dataset: DatasetId = id("dataset");
        let resource: ResourceId = id("resource");
        let ulid = ulid::Ulid::from_string("01CRZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let (schema, batch) = simple_batch();

        let final_path = write_atomic(
            &layout,
            &dataset,
            &resource,
            ulid,
            schema,
            stream::iter(vec![Ok(batch)]),
        )
        .await
        .expect("write succeeds");

        assert_eq!(final_path, layout.final_path(&dataset, &resource, ulid));
        assert!(final_path.exists());
        assert!(!layout.tmp_path(&dataset, &resource, ulid).exists());

        let raw = tokio::fs::read(&final_path).await.expect("read parquet");
        let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(raw))
            .expect("parquet metadata")
            .build()
            .expect("parquet reader");
        let batches = reader
            .collect::<Result<Vec<_>, _>>()
            .expect("parquet batches");
        let total_rows: usize = batches.iter().map(|batch| batch.num_rows()).sum();

        assert_eq!(total_rows, 2);
        assert_eq!(batches[0].schema().field(0).name(), "id");
        assert_eq!(batches[0].schema().field(1).name(), "name");
    }

    #[tokio::test]
    async fn write_atomic_removes_tmp_when_batch_stream_fails() {
        let tmp = TempDir::new().expect("tempdir");
        let layout = CacheLayout::new(Arc::from(tmp.path()));
        let dataset: DatasetId = id("dataset");
        let resource: ResourceId = id("resource");
        let ulid = ulid::Ulid::from_string("01CRZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let (schema, batch) = simple_batch();

        let err = write_atomic(
            &layout,
            &dataset,
            &resource,
            ulid,
            schema,
            stream::iter(vec![Ok(batch), Err(IngestError::SourceUnreadable)]),
        )
        .await
        .expect_err("stream failure propagates");

        assert!(matches!(err, IngestError::SourceUnreadable));
        assert!(!layout.final_path(&dataset, &resource, ulid).exists());
        assert!(!layout.tmp_path(&dataset, &resource, ulid).exists());
    }

    #[tokio::test]
    async fn gc_keeps_current_and_one_previous_ulid() {
        let tmp = TempDir::new().expect("tempdir");
        let layout = CacheLayout::new(Arc::from(tmp.path()));
        let dataset: DatasetId = id("dataset");
        let resource: ResourceId = id("resource");
        let older = ulid::Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let previous = ulid::Ulid::from_string("01BRZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let current = ulid::Ulid::from_string("01CRZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let future = ulid::Ulid::from_string("01DRZ3NDEKTSV4RRFFQ69G5FAV").unwrap();

        for ulid in [older, previous, current, future] {
            let path = layout.final_path(&dataset, &resource, ulid);
            tokio::fs::create_dir_all(path.parent().unwrap())
                .await
                .unwrap();
            tokio::fs::write(path, b"cache").await.unwrap();
        }
        tokio::fs::write(layout.tmp_path(&dataset, &resource, current), b"tmp")
            .await
            .unwrap();

        gc_resource(&layout, &dataset, &resource, current).await;

        assert!(!layout.final_path(&dataset, &resource, older).exists());
        assert!(layout.final_path(&dataset, &resource, previous).exists());
        assert!(layout.final_path(&dataset, &resource, current).exists());
        assert!(!layout.final_path(&dataset, &resource, future).exists());
        assert!(!layout.tmp_path(&dataset, &resource, current).exists());
    }
}
