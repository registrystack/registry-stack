// SPDX-License-Identifier: Apache-2.0
//! Syslog audit sink adapter backed by `registry-platform-audit`.

use std::path::PathBuf;

use registry_platform_audit::{AuditChainHasher, AuditSink as PlatformAuditSink};

use super::AuditError;

/// Sends relay audit records as platform audit JSONL envelopes to syslog.
#[derive(Debug, Clone)]
pub struct SyslogSink {
    inner: registry_platform_audit::SyslogSink,
}

impl SyslogSink {
    #[must_use]
    pub fn new() -> Self {
        Self::with_inner(registry_platform_audit::SyslogSink::new())
    }

    #[must_use]
    pub fn with_socket_path(path: impl Into<PathBuf>) -> Self {
        Self::with_inner(registry_platform_audit::SyslogSink::with_socket_path(path))
    }

    fn with_inner(inner: registry_platform_audit::SyslogSink) -> Self {
        Self { inner }
    }
}

impl Default for SyslogSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PlatformAuditSink for SyslogSink {
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
        hasher: &AuditChainHasher,
    ) -> Result<Option<[u8; 32]>, AuditError> {
        self.inner.tail_hash_with_hasher(hasher).await
    }
}
