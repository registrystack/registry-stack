// SPDX-License-Identifier: Apache-2.0
//! Stdout audit sink adapter backed by `registry-platform-audit`.

use registry_platform_audit::{AuditSink as PlatformAuditSink, JsonlStdoutSink};

use super::AuditError;

/// Writes relay audit records as platform audit JSONL envelopes to stdout.
#[derive(Debug, Clone)]
pub struct StdoutSink {
    inner: JsonlStdoutSink,
}

impl StdoutSink {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: JsonlStdoutSink::new(),
        }
    }
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl PlatformAuditSink for StdoutSink {
    async fn write(
        &self,
        envelope: &registry_platform_audit::AuditEnvelope,
    ) -> Result<(), AuditError> {
        self.inner.write(envelope).await
    }

    async fn tail_hash(&self) -> Result<Option<[u8; 32]>, AuditError> {
        self.inner.tail_hash().await
    }
}
