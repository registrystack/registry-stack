// SPDX-License-Identifier: Apache-2.0
//! File audit sink adapter backed by `registry-platform-audit`.

use std::path::{Path, PathBuf};

use registry_platform_audit::{AuditSink as PlatformAuditSink, JsonlFileSink};

use super::AuditError;

/// Writes relay audit records as platform audit JSONL envelopes.
#[derive(Debug, Clone)]
pub struct FileSink {
    inner: JsonlFileSink,
}

impl FileSink {
    /// Construct a file sink and create the parent directory when one
    /// is configured in the path.
    pub fn new(
        path: impl Into<PathBuf>,
        max_size_mb: u64,
        max_files: u32,
    ) -> Result<Self, AuditError> {
        let path = path.into();
        ensure_parent_dir(&path)?;
        Ok(Self {
            inner: JsonlFileSink::with_rotation(
                path,
                max_size_mb.saturating_mul(1024 * 1024),
                max_files,
            ),
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
        self.inner.tail_hash().await
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
