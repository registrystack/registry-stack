// SPDX-License-Identifier: Apache-2.0

//! The `loop` processor, Camel's Loop EIP
//! (`products/adapter/CONCEPT.md` section 8.6).
//!
//! The `expression` form repeats for a count and the `doWhile` form
//! repeats while its predicate holds; `copy` (default false) chooses
//! whether each iteration runs on a copy; `CamelLoopIndex` carries the
//! iteration position. `maximumIterations` is mandatory, and a `doWhile`
//! loop still true at the maximum raises
//! `loop.maximum-iterations-reached`. The several-upstream-pages-per-
//! facade-page pagination shape runs `doWhile` over a property holding
//! the upstream cursor, with an `enrich` per page (section 8.11.7).
//!
//! As `LoopProcessor` does: a count is read once before iterating and
//! `CamelLoopSize` set then; a count of zero or less runs no iteration;
//! the `doWhile` predicate is tested on the current exchange before
//! every iteration, the first included; `copy` starts each iteration
//! from the exchange as the loop received it and leaves the last
//! iteration's exchange as the result, an error restoring the exchange
//! as it stood before the failed iteration.

use registry_adapter_core::{ErrorClass, LoopStep};
use serde_json::{json, Value};

use crate::engine::exchange::{LOOP_INDEX_PROPERTY, LOOP_SIZE_PROPERTY};
use crate::engine::route::{Flow, RouteFailure, Run};

pub(crate) async fn run(run: &mut Run<'_, '_>, step: &LoopStep) -> Result<Flow, RouteFailure> {
    let Some(bound) = step.maximum_iterations else {
        return Err(RouteFailure::of(ErrorClass::Validation));
    };
    let Some(expression) = step.expression() else {
        return Err(RouteFailure::of(ErrorClass::Validation));
    };
    if step.do_while {
        // With `copy`, every iteration starts from the exchange as the loop
        // received it, whatever the earlier iterations did to their own. A
        // chaining loop needs no retained clone of the whole exchange.
        let original = step.copy.then(|| run.exchange.clone());
        // The predicate is tested before every iteration, the first
        // included; a loop still holding at the bound raises instead of
        // stopping silently (section 8.6).
        for index in 0..bound.get() {
            yield_within_deadline(run).await?;
            if !run.predicate(&expression)? {
                return Ok(Flow::Continue);
            }
            if let flow @ (Ok(Flow::Stop) | Err(_)) =
                iterate(run, step, original.as_ref(), index).await
            {
                return flow;
            }
        }
        if run.predicate(&expression)? {
            return Err(RouteFailure::of(ErrorClass::LoopMaximumIterationsReached));
        }
        return Ok(Flow::Continue);
    }
    // The count form reads the count once before iterating; a
    // non-integer count fails the exchange and a count of zero or less
    // runs no iteration.
    let count = match run.eval(&expression)? {
        Value::Number(number) => {
            if let Some(count) = number.as_u64() {
                count
            } else if let Some(count) = number.as_i64() {
                count.max(0) as u64
            } else {
                return Err(not_an_integer());
            }
        }
        _ => return Err(not_an_integer()),
    };
    run.exchange.set_property(LOOP_SIZE_PROPERTY, json!(count));
    // Camel places the size before taking a per-iteration copy, so copied
    // count-loop exchanges carry the same engine-owned size property.
    let original = step.copy.then(|| run.exchange.clone());
    // A count above the bound runs exactly the bound's iterations, then
    // raises: never a silent stop, never more than the bound.
    for index in 0..count.min(bound.get()) {
        yield_within_deadline(run).await?;
        if let flow @ (Ok(Flow::Stop) | Err(_)) = iterate(run, step, original.as_ref(), index).await
        {
            return flow;
        }
    }
    if count > bound.get() {
        return Err(RouteFailure::of(ErrorClass::LoopMaximumIterationsReached));
    }
    Ok(Flow::Continue)
}

fn not_an_integer() -> RouteFailure {
    RouteFailure {
        class: ErrorClass::Validation,
        message: Some("a loop count must be an integer".to_owned()),
        data: None,
        auth: None,
        code: None,
    }
}

/// Run one iteration, answering how the loop continues. Without `copy`
/// the steps work on the exchange the loop holds. With `copy` they work
/// on a copy of `original` carrying the index property; the last
/// iteration's exchange becomes the exchange the loop holds, and an
/// error restores the exchange as it stood before the iteration.
async fn iterate(
    run: &mut Run<'_, '_>,
    step: &LoopStep,
    original: Option<&crate::engine::exchange::Exchange>,
    index: u64,
) -> Result<Flow, RouteFailure> {
    if !step.copy {
        run.exchange.set_property(LOOP_INDEX_PROPERTY, json!(index));
        return run.run_steps(&step.steps).await;
    }
    let Some(original) = original else {
        return Err(RouteFailure::of(ErrorClass::Validation));
    };
    let mut iteration = original.clone();
    iteration.set_property(LOOP_INDEX_PROPERTY, json!(index));
    let standing = std::mem::replace(&mut run.exchange, iteration);
    match run.run_steps(&step.steps).await {
        // The iteration's exchange stands: the next predicate test, and
        // on completion the route, see the last iteration's result.
        flow @ (Ok(Flow::Continue) | Ok(Flow::Stop)) => flow,
        // `run_steps` never yields `Handled`; a body it ended stands as
        // a stop.
        Ok(Flow::Handled) => Ok(Flow::Stop),
        Err(failure) => {
            run.exchange = standing;
            Err(failure)
        }
    }
}

/// A no-send loop must still give the deadline timer a scheduling point.
async fn yield_within_deadline(run: &Run<'_, '_>) -> Result<(), RouteFailure> {
    if tokio::time::Instant::now() >= run.deadline {
        return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
    }
    tokio::task::yield_now().await;
    if tokio::time::Instant::now() >= run.deadline {
        return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
    }
    Ok(())
}
