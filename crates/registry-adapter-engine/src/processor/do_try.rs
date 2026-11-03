// SPDX-License-Identifier: Apache-2.0

//! The `doTry`, `doCatch`, and `doFinally` processors, a bounded port of
//! Camel (`products/adapter/CONCEPT.md` section 8.7, `doTry-eip.adoc`,
//! `TryProcessor`). A `doCatch` narrows with `onWhen`, and no clause may
//! name an uncatchable class: when an uncatchable class is in the
//! error's cause chain, no clause fires at all, whatever the other
//! causes are.

use registry_adapter_core::DoTryStep;
use serde_json::json;

use crate::exchange::EXCEPTION_CAUGHT_HEADER;
use crate::route::{Flow, RouteFailure, Run};

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
    // Pack cleanup may itself perform source effects. Once an uncatchable
    // boundary is pending, no later pack step may run, including doFinally.
    // Clean, caught, and catchable-failure exits retain ordinary Camel
    // finally semantics: an ordinary error it raises wins only when no failure is
    // pending, and a stop never rescues a failing exit.
    let terminal_failure_pending = matches!(
        &outcome,
        Err(failure) if failure.class.is_uncatchable()
    );
    if run.async_accepted() {
        return Ok(Flow::Stop);
    }
    if !terminal_failure_pending {
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
                Err(raised) => {
                    let terminal_raised = raised.class.is_uncatchable();
                    match outcome {
                        // A terminal boundary raised by finally cannot be
                        // softened behind an earlier ordinary failure. Keep
                        // that earlier class as suppressed and retain the
                        // terminal failure, including its governed diagnostic,
                        // as the active result.
                        Err(pending) if terminal_raised => {
                            suppressed.push(pending);
                            outcome = Err(raised);
                        }
                        Err(_) => suppressed.push(raised),
                        Ok(_) => outcome = Err(raised),
                    }
                }
            }
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
