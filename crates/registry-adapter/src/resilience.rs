// SPDX-License-Identifier: Apache-2.0

//! The process-local state behind the resilience steps: one circuit
//! breaker per `circuitBreaker` node and one pacer per `throttle` node
//! (`products/adapter/CONCEPT.md` sections 8.6 and 8.7), both built at
//! load and keyed by the address of the step node in the served
//! operation's step tree, which is owned for the process lifetime and
//! never moved after `ResilienceRuntime::compile` walks it. The generic
//! mechanisms live in the platform crates (`registry-platform-resilience`
//! for the breaker state machine, `registry-platform-ratelimit` for the
//! rolling window); what stays here is the per-node shape the processors
//! address and the concurrent-request governor, which has no window of
//! its own to pace over.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use registry_adapter_core::{CircuitBreakerStep, Step, ThrottleMode, ThrottleStep};
use registry_platform_ratelimit::rolling_window::{RollingWindowConfig, RollingWindowLimiter};
use registry_platform_resilience::circuit_breaker::{BreakerConfig, CircuitBreaker};
use tokio::time::Instant;

/// The key of one resilience node: the address of its step in the
/// served operation's step tree.
type NodeKey = usize;

/// How one `throttle` node paces its exchanges.
pub enum ThrottlePacer {
    /// Camel's `TotalRequests`: at most `limit` admissions inside the
    /// rolling period, the limit read per exchange.
    Total(RollingWindowLimiter),
    /// Camel's `ConcurrentRequests`: at most `limit` bodies inside the
    /// throttle at once, the permit held for the body's own run.
    Concurrent(ConcurrentGovernor),
}

/// The concurrent-request governor of one `throttle` node: a count of
/// bodies inside the throttle and a notifier for the exchanges waiting
/// on a slot.
pub struct ConcurrentGovernor {
    outstanding: Mutex<usize>,
    notify: tokio::sync::Notify,
}

impl ConcurrentGovernor {
    fn new() -> Self {
        Self {
            outstanding: Mutex::new(0),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Take one slot under `limit`. `Ok(())` means the caller holds a
    /// slot and must release it when its body completes; `Err(())`
    /// means the exchange is over the limit and, unless it rejects
    /// immediately, waited at most until `deadline` for a slot.
    pub async fn acquire(&self, limit: u32, deadline: Instant, reject: bool) -> Result<(), ()> {
        loop {
            // Registered before the state check, so a release that
            // happens while this exchange is checking cannot be missed.
            let notified = self.notify.notified();
            {
                let mut outstanding = self
                    .outstanding
                    .lock()
                    .expect("the governor lock is not poisoned");
                if *outstanding < limit as usize {
                    *outstanding += 1;
                    return Ok(());
                }
            }
            if reject {
                return Err(());
            }
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep_until(deadline) => return Err(()),
            }
        }
    }

    /// Give one slot back and wake one waiting exchange.
    pub fn release(&self) {
        let mut outstanding = self
            .outstanding
            .lock()
            .expect("the governor lock is not poisoned");
        *outstanding = outstanding.saturating_sub(1);
        self.notify.notify_one();
    }
}

enum NodeState {
    Breaker(Arc<CircuitBreaker>),
    Throttle(Arc<ThrottlePacer>),
}

/// The resilience state of one served operation: one node per
/// `circuitBreaker` and `throttle` step its tree holds, built once at
/// load. An empty runtime serves a route with no resilience steps.
pub struct ResilienceRuntime {
    nodes: HashMap<NodeKey, NodeState>,
}

impl ResilienceRuntime {
    /// Build the state for a step tree, before the tree is served.
    #[must_use]
    pub fn compile(steps: &[Step]) -> Self {
        let mut nodes = HashMap::new();
        walk(steps, &mut nodes);
        Self { nodes }
    }

    /// The runtime of a tree with no resilience steps.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    /// The breaker of one `circuitBreaker` node, when the tree holds it.
    pub(crate) fn breaker(&self, key: NodeKey) -> Option<Arc<CircuitBreaker>> {
        match self.nodes.get(&key) {
            Some(NodeState::Breaker(breaker)) => Some(Arc::clone(breaker)),
            _ => None,
        }
    }

    /// The pacer of one `throttle` node, when the tree holds it.
    pub(crate) fn pacer(&self, key: NodeKey) -> Option<Arc<ThrottlePacer>> {
        match self.nodes.get(&key) {
            Some(NodeState::Throttle(pacer)) => Some(Arc::clone(pacer)),
            _ => None,
        }
    }
}

fn walk(steps: &[Step], nodes: &mut HashMap<NodeKey, NodeState>) {
    for step in steps {
        match step {
            Step::CircuitBreaker(breaker) => {
                nodes.insert(
                    std::ptr::from_ref(step) as NodeKey,
                    NodeState::Breaker(Arc::new(breaker_state(breaker))),
                );
                walk(&breaker.steps, nodes);
                if let Some(fallback) = &breaker.on_fallback {
                    walk(&fallback.steps, nodes);
                }
            }
            Step::Throttle(throttle) => {
                nodes.insert(
                    std::ptr::from_ref(step) as NodeKey,
                    NodeState::Throttle(Arc::new(pacer(throttle))),
                );
                walk(&throttle.steps, nodes);
            }
            Step::Choice(choice) => {
                for clause in &choice.when {
                    walk(&clause.steps, nodes);
                }
                if let Some(otherwise) = &choice.otherwise {
                    walk(&otherwise.steps, nodes);
                }
            }
            Step::Filter(filter) => walk(&filter.steps, nodes),
            Step::Split(split) => walk(&split.steps, nodes),
            Step::Loop(looped) => walk(&looped.steps, nodes),
            Step::DoTry(block) => {
                walk(&block.steps, nodes);
                for catch in &block.do_catch {
                    walk(&catch.steps, nodes);
                }
                if let Some(finally) = &block.do_finally {
                    walk(&finally.steps, nodes);
                }
            }
            Step::OnException(clause) => walk(&clause.steps, nodes),
            _ => {}
        }
    }
}

/// The breaker of one node over the model's configuration (section
/// 8.7): resilience4j semantics and defaults, per node.
fn breaker_state(breaker: &CircuitBreakerStep) -> CircuitBreaker {
    CircuitBreaker::new(BreakerConfig {
        failure_rate_threshold: f64::from(breaker.failure_rate_threshold.get()),
        slow_call_rate_threshold: f64::from(breaker.slow_call_rate_threshold.get()),
        slow_call_duration_threshold: std::time::Duration::from_secs(u64::from(
            breaker.slow_call_duration_threshold_seconds.get(),
        )),
        sliding_window_calls: breaker.sliding_window_calls.get() as usize,
        minimum_number_of_calls: breaker.minimum_number_of_calls.get() as usize,
        open_state_wait: std::time::Duration::from_secs(u64::from(
            breaker.open_state_wait_seconds.get(),
        )),
        maximum_half_open_calls: breaker.maximum_half_open_calls.get() as usize,
    })
    // `check_servable` refuses every configuration the platform refuses
    // before a route is registered: the thresholds are bounded away from
    // zero by their type, and the minimum cannot exceed the window.
    .expect("the step passed its serving checks")
}

/// The pacer of one node over the model's configuration (section 8.6).
fn pacer(throttle: &ThrottleStep) -> ThrottlePacer {
    match throttle.mode {
        Some(ThrottleMode::ConcurrentRequests) => {
            ThrottlePacer::Concurrent(ConcurrentGovernor::new())
        }
        _ => ThrottlePacer::Total(
            RollingWindowLimiter::new(RollingWindowConfig {
                window: std::time::Duration::from_millis(u64::from(
                    throttle.time_period_milliseconds.get(),
                )),
            })
            .expect("the period is bounded away from zero by its type"),
        ),
    }
}
