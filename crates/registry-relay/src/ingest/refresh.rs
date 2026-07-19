// SPDX-License-Identifier: Apache-2.0
//! Per-resource refresh loop: mtime / interval / manual polling, backoff.
//!
//! Backoff schedule: 30s, 60s, 120s, 240s, then cap at 600s.
//! Resets to the policy's normal interval on any success.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::audit::{AuditPipeline, OperationalAuditEvent};

use super::{restricted_change_token_revision, IngestPlan};

/// Refresh schedule policy parsed from `ResourceConfig.refresh`.
pub enum RefreshPolicy {
    /// Poll connector metadata every `interval`; refresh if the change token changes.
    Mtime { interval: Duration },
    /// Unconditionally refresh every `interval`.
    Interval { interval: Duration },
    /// Never auto-refresh.
    Manual,
}

/// Spawn the refresh loop for one `IngestPlan`.
///
/// Loops until `shutdown` is cancelled. Implements the exponential
/// backoff schedule used after refresh failures.
pub async fn run_refresh_loop(
    plan: Arc<IngestPlan>,
    policy: RefreshPolicy,
    shutdown: CancellationToken,
    publish_readiness: Arc<dyn Fn() + Send + Sync>,
    audit_sink: Option<Arc<AuditPipeline>>,
) {
    match policy {
        RefreshPolicy::Manual => {
            // Nothing to do; wait for shutdown.
            shutdown.cancelled().await;
        }
        RefreshPolicy::Interval { interval } => {
            run_interval_loop(plan, interval, shutdown, publish_readiness, audit_sink).await;
        }
        RefreshPolicy::Mtime { interval } => {
            run_mtime_loop(plan, interval, shutdown, publish_readiness, audit_sink).await;
        }
    }
}

async fn run_interval_loop(
    plan: Arc<IngestPlan>,
    interval: Duration,
    shutdown: CancellationToken,
    publish_readiness: Arc<dyn Fn() + Send + Sync>,
    audit_sink: Option<Arc<AuditPipeline>>,
) {
    let mut backoff = BackoffState::new();
    loop {
        let wait = backoff.next_wait(interval);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = sleep(wait) => {}
        }
        tracing::debug!(
            dataset_id = %plan.dataset_id(),
            resource_id = %plan.resource_id(),
            "refresh: interval tick",
        );
        match plan.refresh().await {
            Ok(()) => {
                backoff.reset();
                publish_readiness();
            }
            Err(e) => {
                tracing::error!(
                    event = "ingest.refresh_failed",
                    dataset_id = %plan.dataset_id(),
                    resource_id = %plan.resource_id(),
                    error = %e,
                );
                write_refresh_audit_event(
                    audit_sink.as_ref(),
                    "ingest.refresh_failed",
                    Arc::clone(&plan),
                )
                .await;
                backoff.record_failure();
                publish_readiness();
            }
        }
    }
}

async fn run_mtime_loop(
    plan: Arc<IngestPlan>,
    interval: Duration,
    shutdown: CancellationToken,
    publish_readiness: Arc<dyn Fn() + Send + Sync>,
    audit_sink: Option<Arc<AuditPipeline>>,
) {
    let mut backoff = BackoffState::new();

    loop {
        let wait = backoff.next_wait(interval);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = sleep(wait) => {}
        }

        // Sample connector metadata without reading the full table.
        let meta = match plan.connector_metadata().await {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(
                    event = "ingest.refresh_metadata_failed",
                    dataset_id = %plan.dataset_id(),
                    resource_id = %plan.resource_id(),
                    error = %e,
                );
                write_refresh_audit_event(
                    audit_sink.as_ref(),
                    "ingest.refresh_metadata_failed",
                    Arc::clone(&plan),
                )
                .await;
                backoff.record_failure();
                publish_readiness();
                continue;
            }
        };

        let current_source_revision =
            restricted_change_token_revision(meta.change_token.as_deref());
        let loaded_source_revision = plan.loaded_source_revision();
        let changed = match (&loaded_source_revision, &current_source_revision) {
            (Some(prev), Some(cur)) => prev != cur,
            _ => true, // Missing token: conservatively re-ingest.
        };

        if !changed {
            tracing::debug!(
                dataset_id = %plan.dataset_id(),
                resource_id = %plan.resource_id(),
                "refresh: mtime unchanged, skipping",
            );
            // Successful poll (no change): reset backoff.
            backoff.reset();
            plan.record_unchanged_metadata_success();
            publish_readiness();
            continue;
        }

        tracing::debug!(
            dataset_id = %plan.dataset_id(),
            resource_id = %plan.resource_id(),
            "refresh: mtime changed, re-ingesting",
        );

        match plan.refresh().await {
            Ok(()) => {
                backoff.reset();
                publish_readiness();
            }
            Err(e) => {
                tracing::error!(
                    event = "ingest.refresh_failed",
                    dataset_id = %plan.dataset_id(),
                    resource_id = %plan.resource_id(),
                    error = %e,
                );
                write_refresh_audit_event(
                    audit_sink.as_ref(),
                    "ingest.refresh_failed",
                    Arc::clone(&plan),
                )
                .await;
                backoff.record_failure();
                publish_readiness();
            }
        }
    }
}

async fn write_refresh_audit_event(
    audit_sink: Option<&Arc<AuditPipeline>>,
    event: &'static str,
    plan: Arc<IngestPlan>,
) {
    let Some(audit_sink) = audit_sink else {
        return;
    };
    let audit_event = OperationalAuditEvent::new(event, event)
        .for_dataset(plan.dataset_id().as_str().to_string());
    if let Err(err) = audit_sink.write_operational_event(audit_event).await {
        tracing::error!(error = %err, event, "audit.refresh_event_write_failed");
    }
}

/// Per-resource backoff state. Stores consecutive failure count.
///
/// Schedule: first failure → 30s, doubling each time, capped at 600s.
pub struct BackoffState {
    /// Number of consecutive failures since the last success.
    consecutive_failures: u32,
}

impl BackoffState {
    pub fn new() -> Self {
        Self {
            consecutive_failures: 0,
        }
    }

    /// Record one failure. Increments the consecutive failure counter.
    pub fn record_failure(&mut self) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
    }

    /// Reset to "no failures". Called on success.
    pub fn reset(&mut self) {
        self.consecutive_failures = 0;
    }

    /// Sleep duration for the next attempt.
    ///
    /// Returns the normal `interval` when there are no consecutive failures.
    /// Otherwise: 30s * 2^(n-1), capped at 600s.
    pub fn next_wait(&self, normal_interval: Duration) -> Duration {
        if self.consecutive_failures == 0 {
            return normal_interval;
        }
        let base_secs: u64 = 30;
        let shift = (self.consecutive_failures - 1).min(4); // 2^4 = 16; 30*16 = 480 < 600
        let secs = base_secs.saturating_mul(1u64 << shift).min(600);
        Duration::from_secs(secs)
    }
}

impl Default for BackoffState {
    fn default() -> Self {
        Self::new()
    }
}
