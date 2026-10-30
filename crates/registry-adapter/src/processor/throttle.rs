// SPDX-License-Identifier: Apache-2.0

//! The `throttle` processor, Camel 4's Throttler
//! (`products/adapter/CONCEPT.md` section 8.6): `mode` (`TotalRequests`
//! default, or `ConcurrentRequests`), a limit expression,
//! `timePeriodMilliseconds` (default 1000), and `rejectExecution`
//! (default false).
//!
//! Divergence: a waiting exchange waits at most until its deadline,
//! then raises `throttle.rejected`, instead of waiting without bound.

use registry_adapter_core::{ErrorClass, Expression, ThrottleStep};
use registry_platform_ratelimit::rolling_window::RollingWindowError;
use serde_json::{json, Value};

use crate::resilience::ThrottlePacer;
use crate::route::{Flow, RouteFailure, Run};

/// Run one exchange under the node's pacer, keyed by the address of its
/// step in the served operation's step tree.
pub(crate) async fn run(
    run: &mut Run<'_, '_>,
    step: &ThrottleStep,
    key: usize,
) -> Result<Flow, RouteFailure> {
    let limit = read_limit(run, &step.limit)?;
    let Some(pacer) = run.context.resilience.pacer(key) else {
        return Err(RouteFailure::of(ErrorClass::Script));
    };
    match &*pacer {
        ThrottlePacer::Total(window) => {
            loop {
                match window.acquire(limit).await {
                    Ok(()) => break,
                    Err(RollingWindowError::Configuration) => return Err(invalid_limit()),
                    Err(RollingWindowError::Exceeded { retry_after }) => {
                        if step.reject_execution {
                            return Err(refused(run, "window"));
                        }
                        // A wait that cannot finish before the exchange's
                        // deadline refuses now with the throttler's own
                        // class, instead of letting the run's budget
                        // expire it as `budget.exhausted` (section 8.6).
                        if tokio::time::Instant::now() + retry_after > run.deadline {
                            return Err(refused(run, "deadline"));
                        }
                        tokio::time::sleep(retry_after).await;
                    }
                }
            }
        }
        ThrottlePacer::Concurrent(governor) => {
            // The slot is held for the body's own run and given back
            // when it completes, on every exit.
            if governor
                .acquire(limit, run.deadline, step.reject_execution)
                .await
                .is_err()
            {
                return Err(refused(run, "concurrent"));
            }
            let outcome = run.run_steps(&step.steps).await;
            governor.release();
            return outcome;
        }
    }
    run.run_steps(&step.steps).await
}

/// The limit as Camel 4 reads it: a whole positive number, evaluated
/// per exchange (section 8.6).
fn read_limit(run: &Run<'_, '_>, expression: &Expression) -> Result<u32, RouteFailure> {
    match run.eval(expression)? {
        Value::Number(number) => number
            .as_u64()
            .and_then(|limit| u32::try_from(limit).ok())
            .filter(|limit| *limit > 0)
            .ok_or_else(invalid_limit),
        _ => Err(invalid_limit()),
    }
}

fn invalid_limit() -> RouteFailure {
    RouteFailure {
        class: ErrorClass::Validation,
        message: Some("a throttle limit must be a positive integer".to_owned()),
        auth: None,
    }
}

/// One refusal the throttler raised itself, as a value-free journal
/// fact naming the bound that refused the exchange.
fn refused(run: &mut Run<'_, '_>, reason: &'static str) -> RouteFailure {
    run.record("throttleRefused", json!({ "reason": reason }));
    RouteFailure::of(ErrorClass::ThrottleRejected)
}
