// SPDX-License-Identifier: Apache-2.0
//! Outcome counters distinguishing how an execution finished.
//!
//! These let an embedder observe the distribution of terminal states without
//! inspecting individual errors: a completed run, a deadline overrun, an
//! explicit cancellation, a budget exhaustion, a transport failure, or an
//! admission rejection under saturation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Shareable, thread-safe execution outcome counters.
#[derive(Clone, Default)]
pub struct ExecCounters {
    /// Runs that returned a valid result.
    pub completed: Arc<AtomicU64>,
    /// Runs aborted because the wall-clock deadline elapsed.
    pub timed_out: Arc<AtomicU64>,
    /// Runs aborted because the cancel flag was set.
    pub cancelled: Arc<AtomicU64>,
    /// Runs aborted because a resource budget was exhausted.
    pub budget_terminated: Arc<AtomicU64>,
    /// Runs in which an upstream transport call failed.
    pub transport_failed: Arc<AtomicU64>,
    /// Runs rejected at admission because no permit was available.
    pub saturated: Arc<AtomicU64>,
}

impl ExecCounters {
    /// Create a fresh set of zeroed counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment a single counter.
    pub fn inc(counter: &Arc<AtomicU64>) {
        counter.fetch_add(1, Ordering::SeqCst);
    }

    fn get(counter: &Arc<AtomicU64>) -> u64 {
        counter.load(Ordering::SeqCst)
    }

    /// Snapshot all counters as
    /// `(completed, timed_out, cancelled, budget_terminated, transport_failed, saturated)`.
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64, u64) {
        (
            Self::get(&self.completed),
            Self::get(&self.timed_out),
            Self::get(&self.cancelled),
            Self::get(&self.budget_terminated),
            Self::get(&self.transport_failed),
            Self::get(&self.saturated),
        )
    }
}
