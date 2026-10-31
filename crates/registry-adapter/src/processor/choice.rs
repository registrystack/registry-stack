// SPDX-License-Identifier: Apache-2.0

//! The `choice` processor, Camel's Content-Based Router
//! (`products/adapter/CONCEPT.md` section 8.6): the first matching
//! `when` predicate wins, and `otherwise` runs when none matches.
//!
//! A predicate is an expression whose result is a boolean; a non-boolean
//! result is an error, never a truthiness guess (section 8.5).

use registry_adapter_core::{ChoiceStep, ErrorClass};

use crate::route::{Flow, RouteFailure, Run};

pub(crate) async fn run(run: &mut Run<'_, '_>, step: &ChoiceStep) -> Result<Flow, RouteFailure> {
    for clause in &step.when {
        // `check_servable` refuses a clause without exactly one language
        // member, so a `None` predicate never reaches the interpreter.
        let Some(predicate) = clause.predicate() else {
            return Err(RouteFailure::of(ErrorClass::Script));
        };
        if run.predicate(&predicate)? {
            return run.run_steps(&clause.steps).await;
        }
    }
    if let Some(otherwise) = &step.otherwise {
        return run.run_steps(&otherwise.steps).await;
    }
    Ok(Flow::Continue)
}
