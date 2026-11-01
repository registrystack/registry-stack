// SPDX-License-Identifier: Apache-2.0

//! The `validate` processor (`products/adapter/CONCEPT.md` section 8.6):
//! a failing predicate raises the `validation` class, which the profile
//! maps to its problem for the caller like any other error
//! (section 8.11.6).

use registry_adapter_core::{ErrorClass, ValidateStep};

use crate::engine::route::{Flow, RouteFailure, Run};

pub(crate) fn run(run: &mut Run<'_, '_>, step: &ValidateStep) -> Result<Flow, RouteFailure> {
    if run.predicate(&step.expression)? {
        Ok(Flow::Continue)
    } else {
        Err(RouteFailure::of(ErrorClass::Validation))
    }
}
