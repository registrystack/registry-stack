// SPDX-License-Identifier: Apache-2.0

//! The `split` processor, Camel's Splitter
//! (`products/adapter/CONCEPT.md` section 8.6).
//!
//! Ported: `expression`, `aggregationStrategy` (default returns the
//! original message), `stopOnException` (default false), the failure
//! accounting of `errorThreshold` and `maxFailedRecords`, and the
//! exchange properties `CamelSplitIndex`, `CamelSplitSize`,
//! `CamelSplitComplete`, and `CamelSplitResult`. Not ported:
//! `parallelProcessing`, `streaming`, and `timeout`. `maximumItems` is
//! mandatory.
//!
//! The port runs one piece at a time on a copy of the exchange. An item
//! failure under the accounting thresholds is counted and its piece is
//! left out of the merged result; the accounting exists to let a split
//! finish with some pieces failed, and a piece that failed has no body
//! worth merging. This is a recorded divergence: Camel clears the
//! failed piece's exception so aggregation proceeds and the piece's
//! body still joins the aggregate
//! (camel-4.23.0:core/camel-core-processor/src/main/java/org/apache/camel/processor/Splitter.java,
//! `shouldContinueOnFailure`); the merged body here omits it. Without
//! the accounting every piece runs and the last item failure is raised
//! after the split completes, Camel's newest-first `checkException`
//! (`Splitter.java`). The `CamelSplitResult` property carries
//! totalItems, processedItems, and failureCount; Camel's per-item
//! failures map is dropped for the value-free contract and its
//! aborted flag is the raised failure itself.

use registry_adapter_core::{AggregationStrategy, ErrorClass, Expression, SplitStep};
use serde_json::json;

use crate::engine::exchange::{
    ensure_value_bounded, ensure_values_bounded, SPLIT_COMPLETE_PROPERTY, SPLIT_INDEX_PROPERTY,
    SPLIT_RESULT_PROPERTY, SPLIT_SIZE_PROPERTY,
};
use crate::engine::language::{compile_selector, JsonPathResult};
use crate::engine::processor::aggregation;
use crate::engine::route::{Flow, RouteFailure, Run};

pub(crate) async fn run(run: &mut Run<'_, '_>, step: &SplitStep) -> Result<Flow, RouteFailure> {
    let Some(bound) = step.maximum_items else {
        return Err(RouteFailure::of(ErrorClass::Validation));
    };
    let maximum_bytes = run.maximum_exchange_bytes;
    let pieces = bounded_pieces(run, &step.expression, bound.get() as usize, maximum_bytes)?;
    let strategy = step
        .aggregation_strategy
        .clone()
        .unwrap_or(AggregationStrategy::UseOriginal {
            propagate_exception: true,
        });
    let accounting = step.error_threshold.is_some() || step.maximum_failed_records.is_some();
    let total = pieces.len() as u64;
    let mut accumulated = aggregation::initial_body(&strategy, &run.exchange.message.body);
    run.exchange
        .ensure_body_bounded_within(&accumulated, maximum_bytes)
        .map_err(RouteFailure::of)?;
    let mut processed = 0_u64;
    let mut failures = 0_u64;
    let mut last_failure = None;
    for (index, piece) in pieces.into_iter().enumerate() {
        yield_within_deadline(run).await?;
        // Each piece runs on its own copy of the exchange, carrying the
        // engine properties the piece's steps read.
        let mut item = run.exchange.clone();
        item.message.body = piece;
        item.set_property(SPLIT_INDEX_PROPERTY, json!(index));
        item.set_property(SPLIT_SIZE_PROPERTY, json!(total));
        item.set_property(SPLIT_COMPLETE_PROPERTY, json!(index as u64 + 1 == total));
        item.ensure_bounded_within(maximum_bytes)
            .map_err(RouteFailure::of)?;
        std::mem::swap(&mut run.exchange, &mut item);
        let flow = run.run_steps(&step.steps).await;
        // The route exchange keeps the original until every piece has
        // run; a failure leaves it untouched.
        std::mem::swap(&mut run.exchange, &mut item);
        match flow {
            Ok(Flow::Continue) => {}
            // `run_steps` never yields `Handled`; a body it ended folds
            // into the stop arm.
            Ok(Flow::Stop | Flow::Handled) => {
                processed += 1;
                let properties = match aggregation::fold_split(
                    run.context.scripts,
                    &run.context.code_maps,
                    &strategy,
                    &mut accumulated,
                    &item,
                    run.deadline,
                    maximum_bytes,
                ) {
                    Ok(properties) => properties,
                    Err(failure) => {
                        record_pending_consumed(run, &mut last_failure);
                        return Err(failure);
                    }
                };
                apply_properties(run, properties);
                if let Err(class) = run
                    .exchange
                    .ensure_body_bounded_within(&accumulated, maximum_bytes)
                {
                    record_pending_consumed(run, &mut last_failure);
                    return Err(RouteFailure::of(class));
                }
                record_pending_consumed(run, &mut last_failure);
                finish(run, accumulated, accounting, total, processed, failures);
                return Ok(Flow::Stop);
            }
            Err(failure) => {
                processed += 1;
                // The uncatchable classes guard the engine's own bounds;
                // no accounting may swallow them.
                if failure.class.is_uncatchable() || step.stop_on_exception {
                    record_pending_consumed(run, &mut last_failure);
                    return Err(failure);
                }
                failures += 1;
                if let Some(maximum) = step.maximum_failed_records {
                    if failures >= maximum.get() {
                        set_accounting(run, total, processed, failures);
                        record_pending_consumed(run, &mut last_failure);
                        return Err(failure);
                    }
                }
                if let Some(threshold) = step.error_threshold {
                    let share = failures as f64 / processed as f64;
                    if share >= threshold {
                        set_accounting(run, total, processed, failures);
                        record_pending_consumed(run, &mut last_failure);
                        return Err(failure);
                    }
                }
                // A counted failure is swallowed: the accounting exists
                // so a split can finish with pieces failed. Only without
                // it does the last item failure surface at the end.
                if accounting {
                    run.record_consumed_failure("split", &failure);
                } else {
                    if let Some(previous) = last_failure.replace(failure) {
                        run.record_consumed_failure("split", &previous);
                    }
                }
                continue;
            }
        }
        processed += 1;
        let properties = match aggregation::fold_split(
            run.context.scripts,
            &run.context.code_maps,
            &strategy,
            &mut accumulated,
            &item,
            run.deadline,
            maximum_bytes,
        ) {
            Ok(properties) => properties,
            Err(failure) => {
                record_pending_consumed(run, &mut last_failure);
                return Err(failure);
            }
        };
        apply_properties(run, properties);
        if let Err(class) = run
            .exchange
            .ensure_body_bounded_within(&accumulated, maximum_bytes)
        {
            record_pending_consumed(run, &mut last_failure);
            return Err(RouteFailure::of(class));
        }
    }
    finish(run, accumulated, accounting, total, processed, failures);
    match last_failure {
        Some(failure) if aggregation::propagates(&strategy) => Err(failure),
        Some(failure) => {
            run.record_consumed_failure("split", &failure);
            Ok(Flow::Continue)
        }
        None => Ok(Flow::Continue),
    }
}

/// Read an array expression only after checking `maximumItems` against
/// the borrowed result. Rhai necessarily returns an owned value, but the
/// constant, header, property, and JSONPath forms avoid cloning an
/// over-limit collection first.
fn bounded_pieces(
    run: &Run<'_, '_>,
    expression: &Expression,
    maximum: usize,
    maximum_bytes: usize,
) -> Result<Vec<serde_json::Value>, RouteFailure> {
    match expression {
        Expression::Constant(value) => clone_array_within(value, maximum, maximum_bytes),
        Expression::Header(name) => run.exchange.message.header(name).map_or_else(
            || Err(not_an_array()),
            |value| clone_array_within(value, maximum, maximum_bytes),
        ),
        Expression::ExchangeProperty(name) => run.exchange.property(name).map_or_else(
            || Err(not_an_array()),
            |value| clone_array_within(value, maximum, maximum_bytes),
        ),
        Expression::JsonPath(selector) => {
            let compiled =
                compile_selector(selector).map_err(|_| RouteFailure::of(ErrorClass::Validation))?;
            match compiled.evaluate(&run.exchange.message.body) {
                Ok(JsonPathResult::Singular(Some(value))) => {
                    clone_array_within(value, maximum, maximum_bytes)
                }
                Ok(JsonPathResult::List(nodes)) => {
                    if nodes.len() > maximum {
                        return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
                    }
                    ensure_values_bounded(&nodes, maximum_bytes).map_err(RouteFailure::of)?;
                    Ok(nodes.into_iter().cloned().collect())
                }
                _ => Err(not_an_array()),
            }
        }
        Expression::Rhai(_) => {
            clone_owned_array_within(run.eval(expression)?, maximum, maximum_bytes)
        }
    }
}

fn clone_array_within(
    value: &serde_json::Value,
    maximum: usize,
    maximum_bytes: usize,
) -> Result<Vec<serde_json::Value>, RouteFailure> {
    let serde_json::Value::Array(items) = value else {
        return Err(not_an_array());
    };
    if items.len() > maximum {
        return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
    }
    ensure_value_bounded(value, maximum_bytes).map_err(RouteFailure::of)?;
    Ok(items.clone())
}

fn clone_owned_array_within(
    value: serde_json::Value,
    maximum: usize,
    maximum_bytes: usize,
) -> Result<Vec<serde_json::Value>, RouteFailure> {
    let serde_json::Value::Array(items) = &value else {
        return Err(not_an_array());
    };
    if items.len() > maximum {
        return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
    }
    ensure_value_bounded(&value, maximum_bytes).map_err(RouteFailure::of)?;
    match value {
        serde_json::Value::Array(items) => Ok(items),
        _ => Err(not_an_array()),
    }
}

fn not_an_array() -> RouteFailure {
    RouteFailure {
        class: ErrorClass::Validation,
        message: Some("a split expression must yield a JSON array".to_owned()),
        data: None,
        auth: None,
        code: None,
    }
}

/// A no-send split must still give the deadline timer a scheduling point.
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

fn record_pending_consumed(run: &mut Run<'_, '_>, pending: &mut Option<RouteFailure>) {
    if let Some(failure) = pending.take() {
        run.record_consumed_failure("split", &failure);
    }
}

/// Place the merged body and, with the accounting declared, its summary
/// property on the route exchange.
fn finish(
    run: &mut Run<'_, '_>,
    body: serde_json::Value,
    accounting: bool,
    total: u64,
    processed: u64,
    failures: u64,
) {
    run.exchange.message.body = body;
    if accounting {
        set_accounting(run, total, processed, failures);
    }
}

fn set_accounting(run: &mut Run<'_, '_>, total: u64, processed: u64, failures: u64) {
    run.exchange.set_property(
        SPLIT_RESULT_PROPERTY,
        json!({
            "totalItems": total,
            "processedItems": processed,
            "failureCount": failures,
        }),
    );
}

/// Apply a strategy's property writes: a value sets, an absent selection
/// removes.
fn apply_properties(run: &mut Run<'_, '_>, properties: Vec<(String, Option<serde_json::Value>)>) {
    for (name, value) in properties {
        match value {
            Some(value) => run.exchange.set_property(&name, value),
            None => run.exchange.remove_property(&name),
        }
    }
}
