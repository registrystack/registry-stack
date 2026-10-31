// SPDX-License-Identifier: Apache-2.0

//! The `circuitBreaker` processor: resilience4j semantics and defaults,
//! per EIP node with process-local state, as in Camel
//! (`products/adapter/CONCEPT.md` sections 8.6 and 8.7).
//!
//! Defaults: `failureRateThreshold` 50, a count-based sliding window of
//! `slidingWindowCalls` 100, `minimumNumberOfCalls` 100,
//! `openStateWaitSeconds` 60, `maximumHalfOpenCalls` 10,
//! `automaticTransitionFromOpenToHalfOpenEnabled` false,
//! `slowCallRateThreshold` 100, `slowCallDurationThresholdSeconds` 60.
//! A rejected call always raises `breaker.open`, diverging from Camel's
//! `throwExceptionWhenHalfOpenOrOpenState: false` default, and
//! `onFallback` runs on failure and on rejection with its output
//! validated like any route output.
//!
//! The guarded steps and the fallback run bare, the way every nested
//! body does: the route error handler does not wrap a breaker or its
//! steps (section 8.7, `inheritErrorHandler` false).

use registry_adapter_core::{CircuitBreakerStep, ErrorClass};
use registry_platform_resilience::circuit_breaker::{Acquired, BreakerState};
use serde_json::json;

use crate::route::{Flow, RouteFailure, Run};

/// Run one guarded exchange under the node's breaker, keyed by the
/// address of its step in the served operation's step tree.
pub(crate) async fn run(
    run: &mut Run<'_, '_>,
    step: &CircuitBreakerStep,
    key: usize,
) -> Result<Flow, RouteFailure> {
    let Some(breaker) = run.context.resilience.breaker(key) else {
        return Err(RouteFailure::of(ErrorClass::Script));
    };
    let permit = match breaker.acquire() {
        Acquired::Permitted(permit) => permit,
        Acquired::Rejected => {
            // The refusal never reached the source, so it carries the
            // adapter's own class and the state that refused it.
            let state = match breaker.state() {
                BreakerState::HalfOpen => "halfOpen",
                _ => "open",
            };
            run.record("breakerRefused", json!({ "state": state }));
            return fallback(run, step, None).await;
        }
    };
    let started = std::time::Instant::now();
    let outcome = run.run_steps(&step.steps).await;
    let duration = started.elapsed();
    match outcome {
        Ok(flow) => {
            permit.record(true, duration);
            Ok(flow)
        }
        Err(failure) => {
            permit.record(false, duration);
            fallback(run, step, Some(failure)).await
        }
    }
}

/// The fallback of a refused or failed guarded call, on failure and on
/// rejection (section 8.7). Without one, a failure keeps its own class
/// and a refusal is `breaker.open`.
async fn fallback(
    run: &mut Run<'_, '_>,
    step: &CircuitBreakerStep,
    failure: Option<RouteFailure>,
) -> Result<Flow, RouteFailure> {
    match &step.on_fallback {
        Some(on_fallback) => run.run_steps(&on_fallback.steps).await,
        None => Err(failure.unwrap_or_else(|| RouteFailure::of(ErrorClass::BreakerOpen))),
    }
}
