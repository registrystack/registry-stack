// SPDX-License-Identifier: Apache-2.0
//! Stdout audit sink: writes one JSONL record per call to process stdout.
//!
//! Each write is dispatched via `tokio::task::spawn_blocking` because
//! `std::io::stdout().lock()` acquires a global OS-level lock shared with
//! `tracing`'s fmt subscriber and any log collector attached to the
//! process. Holding that lock on an async runtime thread can stall all
//! tasks on that thread while a slow collector drains the pipe.
//!
//! We deliberately do not buffer across writes: each record must be
//! durable on stdout before the request completes, otherwise a panic
//! between buffer fill and flush would silently drop audit. The container
//! runtime owns durability once the line reaches stdout.

use std::io::{self, Write};

use super::{AuditEnvelope, AuditError, AuditFuture, AuditSink};

/// Writes audit records as JSONL to process stdout. Each `write` flushes
/// the underlying handle so logs are durable line-by-line, which is the
/// behaviour container log collectors expect.
#[derive(Debug, Default)]
pub struct StdoutSink {
    _private: (),
}

impl StdoutSink {
    /// Construct a new stdout sink. There is no configuration: format
    /// is fixed to JSONL per the only V1 `AuditFormat` variant.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }
}

impl AuditSink for StdoutSink {
    fn write<'a>(&'a self, envelope: AuditEnvelope) -> AuditFuture<'a> {
        Box::pin(async move {
            let line = envelope.to_jsonl()?;
            // Dispatch to a blocking thread so the stdout lock (a global
            // OS-level lock shared with tracing's fmt subscriber) is never
            // held on an async runtime thread.
            tokio::task::spawn_blocking(move || {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                handle.write_all(line.as_bytes()).map_err(AuditError::Io)?;
                handle.flush().map_err(AuditError::Io)
            })
            .await
            .map_err(|join_err| AuditError::Io(std::io::Error::other(join_err)))?
        })
    }

    fn flush<'a>(&'a self) -> AuditFuture<'a> {
        Box::pin(async move {
            tokio::task::spawn_blocking(|| {
                let stdout = io::stdout();
                let mut handle = stdout.lock();
                handle.flush().map_err(AuditError::Io)
            })
            .await
            .map_err(|join_err| AuditError::Io(std::io::Error::other(join_err)))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditRecord, EndpointKind};

    fn fixture() -> AuditRecord {
        AuditRecord {
            ts: "2026-05-15T10:00:00.123Z".to_string(),
            request_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string(),
            api_key_id: None,
            auth_mode: None,
            remote_addr: "127.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/health".to_string(),
            endpoint_kind: EndpointKind::Health,
            dataset_id: None,
            entity_name: None,
            table_id: None,
            relationship: None,
            aggregate_id: None,
            scopes_used: Vec::new(),
            query_params: serde_json::json!({}),
            purpose: None,
            status_code: 200,
            row_count: None,
            suppressed_groups: None,
            duration_ms: 1,
            error_code: None,
        }
    }

    #[tokio::test]
    async fn write_returns_ok_for_typical_record() {
        let sink = StdoutSink::new();
        sink.write(AuditEnvelope::from(fixture())).await.unwrap();
        sink.flush().await.unwrap();
    }
}
