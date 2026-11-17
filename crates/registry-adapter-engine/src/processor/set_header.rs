// SPDX-License-Identifier: Apache-2.0

//! The `setHeader` processor: set a message header from an expression.
//!
//! The read-only facade inputs are refused as targets.
//! A `header` expression may read only a facade input header, a declared
//! response header, a Camel engine header the engine sets, or a header
//! an earlier step of the same route set.

use registry_adapter_core::SetHeaderStep;

use crate::route::{Flow, RouteFailure, Run};

pub(crate) fn run(run: &mut Run<'_, '_>, step: &SetHeaderStep) -> Result<Flow, RouteFailure> {
    let value = run.eval(&step.value)?;
    run.exchange.message.set_header(&step.name, value);
    Ok(Flow::Continue)
}
