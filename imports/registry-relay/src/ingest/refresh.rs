// SPDX-License-Identifier: Apache-2.0
//! Per-resource refresh loop: mtime / interval / manual polling, backoff.
//!
//! Backoff schedule (W1-14): 30s → 60s → 120s → 240s → cap 600s.
//! Resets to the policy's normal interval on any success.
//!
//! State machine transitions are described in `decisions/wave-1.md` §3.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::sleep;
use tokio_util::sync::CancellationToken;

use crate::source::SourceMetadata;

use super::IngestPlan;

/// Refresh schedule policy parsed from `ResourceConfig.refresh`.
pub enum RefreshPolicy {
    /// Poll `Source::metadata` every `interval`; refresh if ETag changes.
    Mtime { interval: Duration },
    /// Unconditionally refresh every `interval`.
    Interval { interval: Duration },
    /// Never auto-refresh.
    Manual,
}

/// Spawn the refresh loop for one `IngestPlan`.
///
/// Loops until `shutdown` is cancelled. Implements the exponential
/// backoff schedule from `decisions/wave-1.md` §1 W1-14.
pub async fn run_refresh_loop(
    plan: Arc<IngestPlan>,
    policy: RefreshPolicy,
    shutdown: CancellationToken,
) {
    match policy {
        RefreshPolicy::Manual => {
            // Nothing to do; wait for shutdown.
            shutdown.cancelled().await;
        }
        RefreshPolicy::Interval { interval } => {
            run_interval_loop(plan, interval, shutdown).await;
        }
        RefreshPolicy::Mtime { interval } => {
            run_mtime_loop(plan, interval, shutdown).await;
        }
    }
}

async fn run_interval_loop(plan: Arc<IngestPlan>, interval: Duration, shutdown: CancellationToken) {
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
            Ok(()) => backoff.reset(),
            Err(e) => {
                tracing::error!(
                    event = "ingest.refresh_failed",
                    dataset_id = %plan.dataset_id(),
                    resource_id = %plan.resource_id(),
                    error = %e,
                );
                backoff.record_failure();
            }
        }
    }
}

async fn run_mtime_loop(plan: Arc<IngestPlan>, interval: Duration, shutdown: CancellationToken) {
    let mut backoff = BackoffState::new();
    let mut last_etag: Option<String> = None;

    loop {
        let wait = backoff.next_wait(interval);
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = sleep(wait) => {}
        }

        // Sample the source metadata without reading the body.
        let meta: SourceMetadata = match plan.source_metadata().await {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(
                    event = "ingest.refresh_metadata_failed",
                    dataset_id = %plan.dataset_id(),
                    resource_id = %plan.resource_id(),
                    error = %e,
                );
                backoff.record_failure();
                continue;
            }
        };

        let current_etag = meta.etag.clone();
        let changed = match (&last_etag, &current_etag) {
            (None, _) => true, // First poll: treat as changed.
            (Some(prev), Some(cur)) => prev != cur,
            (Some(_), None) => true, // Source lost its ETag: re-ingest.
        };

        if !changed {
            tracing::debug!(
                dataset_id = %plan.dataset_id(),
                resource_id = %plan.resource_id(),
                "refresh: mtime unchanged, skipping",
            );
            // Successful poll (no change): reset backoff.
            backoff.reset();
            continue;
        }

        tracing::debug!(
            dataset_id = %plan.dataset_id(),
            resource_id = %plan.resource_id(),
            "refresh: mtime changed, re-ingesting",
        );

        match plan.refresh().await {
            Ok(()) => {
                last_etag = current_etag;
                backoff.reset();
            }
            Err(e) => {
                tracing::error!(
                    event = "ingest.refresh_failed",
                    dataset_id = %plan.dataset_id(),
                    resource_id = %plan.resource_id(),
                    error = %e,
                );
                backoff.record_failure();
            }
        }
    }
}

/// Per-resource backoff state. Tracks consecutive failure count.
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
