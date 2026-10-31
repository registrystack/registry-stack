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

/// One held concurrent-request slot. The slot is given back when the
/// permit drops, however the body ends, including a future dropped
/// mid-run by a route timeout.
pub struct GovernorPermit<'a> {
    governor: &'a ConcurrentGovernor,
}

impl Drop for GovernorPermit<'_> {
    fn drop(&mut self) {
        self.governor.release();
    }
}

impl ConcurrentGovernor {
    fn new() -> Self {
        Self {
            outstanding: Mutex::new(0),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Take one slot under `limit`. `Ok` hands the caller a permit that
    /// holds the slot until it drops; `Err(())` means the exchange is
    /// over the limit and, unless it rejects immediately, waited at
    /// most until `deadline` for a slot.
    pub async fn acquire(
        &self,
        limit: u32,
        deadline: Instant,
        reject: bool,
    ) -> Result<GovernorPermit<'_>, ()> {
        loop {
            // Listening starts at enable(), before the state check, so
            // a release while this exchange is checking is delivered to
            // this listener rather than collapsing into the single
            // stored wakeup the notifier can hold.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let taken = {
                let mut outstanding = self
                    .outstanding
                    .lock()
                    .expect("the governor lock is not poisoned");
                if *outstanding < limit as usize {
                    *outstanding += 1;
                    true
                } else {
                    false
                }
            };
            if taken {
                // The slot is taken without waiting: a wakeup this
                // listener may already have absorbed is passed on so no
                // release is lost. A wakeup with no waiter behind it
                // only wakes one exchange to re-check.
                self.notify.notify_one();
                return Ok(GovernorPermit { governor: self });
            }
            if reject {
                // Nothing was taken, but the enabled listener may have
                // absorbed a wakeup on its way out.
                self.notify.notify_one();
                return Err(());
            }
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(deadline) => {
                    // The wait lost the race with the deadline; a
                    // wakeup already delivered to this listener leaves
                    // with it.
                    self.notify.notify_one();
                    return Err(());
                }
            }
        }
    }

    /// Give one slot back and wake one waiting exchange.
    fn release(&self) {
        let mut outstanding = self
            .outstanding
            .lock()
            .expect("the governor lock is not poisoned");
        *outstanding = outstanding.saturating_sub(1);
        self.notify.notify_one();
    }
}

#[derive(Clone)]
enum NodeState {
    Breaker(Arc<CircuitBreaker>),
    Throttle(Arc<ThrottlePacer>),
}

/// The resilience state of a deployment's route table: one node per
/// `circuitBreaker` and `throttle` step the table holds, built once at
/// load. Every served operation runs over a clone of the same runtime,
/// so the nodes a route shares with a `direct:` target's own steps are
/// the same process-local state. An empty runtime serves a tree with no
/// resilience steps.
#[derive(Clone)]
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

    /// Add the nodes of one more route's tree, the way a load assembles
    /// the whole table's state before serving any of it.
    pub fn absorb(&mut self, steps: &[Step]) {
        walk(steps, &mut self.nodes);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A body whose future is dropped mid-run must not leak its
    /// concurrent slot: the next exchange is admitted without waiting
    /// for a release that never comes.
    #[tokio::test]
    async fn an_aborted_body_gives_its_slot_back() {
        let governor = Arc::new(ConcurrentGovernor::new());
        let far = tokio::time::Instant::now() + Duration::from_secs(30);
        let body = {
            let governor = Arc::clone(&governor);
            tokio::spawn(async move {
                let _permit = governor.acquire(1, far, false).await;
                std::future::pending::<()>().await;
            })
        };
        // Wait until the body holds the slot: a rejecting probe is
        // refused only once the limit is reached.
        while let Ok(probe) = governor.acquire(1, far, true).await {
            drop(probe);
            tokio::task::yield_now().await;
        }
        body.abort();
        let soon = tokio::time::Instant::now() + Duration::from_millis(500);
        let admitted = governor.acquire(1, soon, false).await.is_ok();
        assert!(admitted, "an aborted body must give its slot back");
    }

    /// Two releases while two exchanges wait must wake both: the
    /// second release may not collapse into the first.
    #[tokio::test]
    async fn two_releases_wake_two_waiting_exchanges() {
        let governor = Arc::new(ConcurrentGovernor::new());
        let far = tokio::time::Instant::now() + Duration::from_secs(30);
        let (first, second) = match (
            governor.acquire(2, far, false).await,
            governor.acquire(2, far, false).await,
        ) {
            (Ok(first), Ok(second)) => (first, second),
            _ => panic!("a governor at its limit admits two bodies"),
        };
        let waiter = |governor: Arc<ConcurrentGovernor>| async move {
            governor.acquire(2, far, false).await.is_ok()
        };
        let one = tokio::spawn(waiter(Arc::clone(&governor)));
        let two = tokio::spawn(waiter(Arc::clone(&governor)));
        // Let both waiters park before releasing.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        drop(first);
        drop(second);
        let (one, two) = tokio::time::timeout(Duration::from_secs(2), async {
            (
                one.await.expect("waiter one finishes"),
                two.await.expect("waiter two finishes"),
            )
        })
        .await
        .expect("both releases wake their own waiter");
        assert!(one, "the first released slot admits its waiter");
        assert!(two, "the second released slot admits its waiter");
    }
}
