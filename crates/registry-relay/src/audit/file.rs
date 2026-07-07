// SPDX-License-Identifier: Apache-2.0
//! File audit sink adapter backed by `registry-platform-audit`.

use std::path::{Path, PathBuf};

use registry_platform_audit::{AuditChainHasher, AuditSink as PlatformAuditSink, JsonlFileSink};

use super::AuditError;

/// Writes relay audit records as platform audit JSONL envelopes.
#[derive(Debug, Clone)]
pub struct FileSink {
    inner: JsonlFileSink,
}

impl FileSink {
    /// Construct a file sink and create the parent directory when one
    /// is configured in the path.
    ///
    /// Takes the process-lifetime single-writer advisory lock on the sink
    /// (#211): a second relay process (or an overlapping container during a
    /// restart/recreate) sharing the same audit volume fails loudly here with
    /// [`AuditError::SinkLocked`] instead of silently forking the audit chain.
    pub fn new(
        path: impl Into<PathBuf>,
        max_size_mb: u64,
        max_files: u32,
    ) -> Result<Self, AuditError> {
        let path = path.into();
        ensure_parent_dir(&path)?;
        Ok(Self {
            inner: JsonlFileSink::with_rotation_single_writer(
                path,
                max_size_mb.saturating_mul(1024 * 1024),
                max_files,
            )?,
        })
    }
}

#[async_trait::async_trait]
impl PlatformAuditSink for FileSink {
    async fn write(
        &self,
        envelope: &registry_platform_audit::AuditEnvelope,
    ) -> Result<(), AuditError> {
        self.inner.write(envelope).await
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        self.inner
            .tail_hash_with_hasher(&AuditChainHasher::unkeyed_dev_only())
            .await
    }

    async fn tail_hash_with_hasher(
        &self,
        hasher: &registry_platform_audit::AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        self.inner.tail_hash_with_hasher(hasher).await
    }
}

fn ensure_parent_dir(path: &Path) -> Result<(), AuditError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(AuditError::Io)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_sink_new_is_single_writer() {
        // #211: the production relay file sink takes the single-writer advisory
        // lock, so a second sink on the same audit path fails loudly instead of
        // forking the chain.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let _first = FileSink::new(&path, 10, 50).expect("first file sink locks");
        let second = FileSink::new(&path, 10, 50);
        assert!(
            matches!(second, Err(AuditError::SinkLocked { .. })),
            "second file sink must be rejected, got {second:?}"
        );
    }
}
