// SPDX-License-Identifier: Apache-2.0

//! The `doTry`, `doCatch`, and `doFinally` processors, ported as in
//! Camel (`products/adapter/CONCEPT.md` section 8.7, `doTry-eip.adoc`,
//! `TryProcessor`). A `doCatch` narrows with `onWhen`, and no clause may
//! name an uncatchable class: when an uncatchable class is in the
//! error's cause chain, no clause fires at all, whatever the other
//! causes are.

use registry_adapter_core::DoTryStep;
use serde_json::json;

use crate::engine::exchange::EXCEPTION_CAUGHT_HEADER;
use crate::engine::route::{Flow, RouteFailure, Run};

pub(crate) async fn run(run: &mut Run<'_, '_>, step: &DoTryStep) -> Result<Flow, RouteFailure> {
    // The try body runs through run_steps, so the route's clauses and
    // redelivery never reach it: inside a doTry block the route error
    // handler is not in use (section 8.7). A `to: direct:` inside keeps
    // its own handling, as in Camel.
    let (mut outcome, mut suppressed) = match run.run_steps(&step.steps).await {
        Ok(flow) => (Ok(flow), Vec::new()),
        Err(failure) => match catch(run, step, &failure).await {
            Ok(Some(flow)) => (Ok(flow), Vec::new()),
            // No catch matched, or one raised inside itself: an error
            // raised in a doCatch (or by its onWhen) leaves the doTry
            // and fails the exchange, the original kept as suppressed.
            Ok(None) => (Err(failure), Vec::new()),
            Err(raised) => (Err(raised), vec![failure]),
        },
    };
    // doFinally runs on every exit path. An error it raises wins only
    // when no failure is pending; beside a pending failure it is kept as
    // suppressed and the original wins (FinallyProcessor,
    // DoTryEdgeCasesTest.testDoFinallyThrowsKeepsOriginal). A stop in it
    // ends the route on a clean or caught exit and never rescues a
    // failing one.
    if let Some(finally) = &step.do_finally {
        match run.run_steps(&finally.steps).await {
            Ok(Flow::Continue) => {}
            // `run_steps` never yields `Handled`; a body it ended folds
            // into the stop arm.
            Ok(Flow::Stop | Flow::Handled) => {
                if outcome.is_ok() {
                    outcome = Ok(Flow::Stop);
                }
            }
            Err(raised) => match outcome {
                Err(_) => suppressed.push(raised),
                Ok(_) => outcome = Err(raised),
            },
        }
    }
    // The failure record keeps a suppressed class beside the winning
    // one; the exchange carries no cause chain (section 8.7).
    for failure in suppressed {
        run.record(
            "exchangeFailureSuppressed",
            json!({ "class": failure.class.class() }),
        );
    }
    outcome
}

/// The first `doCatch` whose class matches and whose `onWhen` holds,
/// with `CamelExceptionCaught` on the exchange for the catch's steps.
/// `Ok(None)` is no match; `Err` is an error the catch raised itself. A
/// catch whose `onWhen` does not hold is left, as in Camel.
async fn catch(
    run: &mut Run<'_, '_>,
    step: &DoTryStep,
    failure: &RouteFailure,
) -> Result<Option<Flow>, RouteFailure> {
    // The boundary is never caught, whatever class a catch could name.
    if failure.class.is_uncatchable() {
        return Ok(None);
    }
    for catch in &step.do_catch {
        let matches = catch
            .exception
            .iter()
            .any(|declared| failure.class.is_within(*declared));
        if !matches {
            continue;
        }
        // An onWhen that raises fails the exchange with that error, the
        // original kept as suppressed (section 8.7).
        if let Some(condition) = &catch.on_when {
            if !run.predicate(condition)? {
                continue;
            }
        }
        run.exchange
            .message
            .set_header(EXCEPTION_CAUGHT_HEADER, json!(failure.class.class()));
        run.record_consumed_failure("doCatch", failure);
        let handled = run.run_steps(&catch.steps).await;
        run.exchange.message.remove_header(EXCEPTION_CAUGHT_HEADER);
        return Ok(Some(handled?));
    }
    Ok(None)
}
