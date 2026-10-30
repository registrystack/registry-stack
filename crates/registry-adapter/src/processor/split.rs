// SPDX-License-Identifier: Apache-2.0

//! The `split` processor, Camel's Splitter
//! (`products/adapter/CONCEPT.md` section 8.6).
//!
//! Ported: `expression`, `aggregationStrategy` (default returns the
//! original message), `stopOnException` (default false), the failure
//! accounting of `errorThreshold` and `maxFailedRecords`, and the
//! exchange headers `CamelSplitIndex`, `CamelSplitSize`,
//! `CamelSplitComplete`, and `CamelSplitResult`. Not ported:
//! `parallelProcessing`, `streaming`, and `timeout`. `maximumItems` is
//! mandatory.
//!
//! The port runs one piece at a time on a copy of the exchange. An item
//! failure under the accounting thresholds is counted and its piece is
//! left out of the merged result; the accounting exists to let a split
//! finish with some pieces failed, and a piece that failed has no body
//! worth merging. Without the accounting every piece runs and the last
//! item failure is raised after the split completes, Camel's
//! newest-first `checkException` (`Splitter.java`).

use registry_adapter_core::{AggregationStrategy, ErrorClass, SplitStep};
use serde_json::json;

use crate::processor::aggregation;
use crate::route::{Flow, RouteFailure, Run};

/// The headers the split places on each piece's exchange.
const SPLIT_INDEX_HEADER: &str = "CamelSplitIndex";
const SPLIT_SIZE_HEADER: &str = "CamelSplitSize";
const SPLIT_COMPLETE_HEADER: &str = "CamelSplitComplete";
/// The accounting summary, set only when the split declares it.
const SPLIT_RESULT_HEADER: &str = "CamelSplitResult";

pub(crate) async fn run(run: &mut Run<'_, '_>, step: &SplitStep) -> Result<Flow, RouteFailure> {
    let Some(bound) = step.maximum_items else {
        return Err(RouteFailure::of(ErrorClass::Validation));
    };
    let pieces = match run.eval(&step.expression)? {
        serde_json::Value::Array(pieces) => pieces,
        _ => {
            return Err(RouteFailure {
                class: ErrorClass::Validation,
                message: Some("a split expression must yield a JSON array".to_owned()),
                auth: None,
            })
        }
    };
    if pieces.len() > bound.get() as usize {
        return Err(RouteFailure::of(ErrorClass::BudgetExhausted));
    }
    let strategy = step
        .aggregation_strategy
        .clone()
        .unwrap_or(AggregationStrategy::UseOriginal {
            propagate_exception: true,
        });
    let accounting = step.error_threshold.is_some() || step.maximum_failed_records.is_some();
    let total = pieces.len() as u64;
    let mut accumulated = aggregation::initial_body(&strategy, &run.exchange.message.body);
    let mut processed = 0_u64;
    let mut failures = 0_u64;
    let mut last_failure = None;
    for (index, piece) in pieces.into_iter().enumerate() {
        // Each piece runs on its own copy of the exchange, carrying the
        // engine headers the piece's steps read.
        let mut item = run.exchange.clone();
        item.message.body = piece;
        item.message.set_header(SPLIT_INDEX_HEADER, json!(index));
        item.message.set_header(SPLIT_SIZE_HEADER, json!(total));
        item.message
            .set_header(SPLIT_COMPLETE_HEADER, json!(index as u64 + 1 == total));
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
                let merged =
                    aggregation::fold(run.context.scripts, &strategy, &accumulated, &item)?;
                accumulated = merged.body;
                apply_properties(run, merged.properties);
                finish(run, accumulated, accounting, total, processed, failures);
                return Ok(Flow::Stop);
            }
            Err(failure) => {
                processed += 1;
                // The uncatchable classes guard the engine's own bounds;
                // no accounting may swallow them.
                if failure.class.is_uncatchable() || step.stop_on_exception {
                    return Err(failure);
                }
                failures += 1;
                if let Some(maximum) = step.maximum_failed_records {
                    if failures >= maximum.get() {
                        return Err(failure);
                    }
                }
                if let Some(threshold) = step.error_threshold {
                    let share = failures as f64 / processed as f64;
                    if share >= threshold {
                        return Err(failure);
                    }
                }
                // A counted failure is swallowed: the accounting exists
                // so a split can finish with pieces failed. Only without
                // it does the last item failure surface at the end.
                if !accounting {
                    last_failure = Some(failure);
                }
                continue;
            }
        }
        processed += 1;
        let merged = aggregation::fold(run.context.scripts, &strategy, &accumulated, &item)?;
        accumulated = merged.body;
        apply_properties(run, merged.properties);
    }
    finish(run, accumulated, accounting, total, processed, failures);
    match last_failure {
        Some(failure) if aggregation::propagates(&strategy) => Err(failure),
        _ => Ok(Flow::Continue),
    }
}

/// Place the merged body and, with the accounting declared, its summary
/// header on the route exchange.
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
        run.exchange.message.set_header(
            SPLIT_RESULT_HEADER,
            json!({
                "totalItems": total,
                "processedItems": processed,
                "failureCount": failures,
                "aborted": false,
            }),
        );
    }
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
