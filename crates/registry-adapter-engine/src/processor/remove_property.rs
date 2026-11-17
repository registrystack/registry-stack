// SPDX-License-Identifier: Apache-2.0

//! The `removeProperty` processor: remove an exchange property. The read-only facade
//! inputs are refused as targets, except
//! `AdapterNextContinuation`, which exists to be set by a search route.

use crate::route::{Flow, RouteFailure, Run};

pub(crate) fn run(run: &mut Run<'_, '_>, name: &str) -> Result<Flow, RouteFailure> {
    run.exchange.remove_property(name);
    Ok(Flow::Continue)
}
