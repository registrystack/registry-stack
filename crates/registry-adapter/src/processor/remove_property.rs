// SPDX-License-Identifier: Apache-2.0

//! The `removeProperty` processor: remove an exchange property
//! (`products/adapter/CONCEPT.md` section 8.6). The read-only facade
//! inputs of section 8.11.1 are refused as targets, except
//! `AdapterNextContinuation`, which exists to be set by a search route
//! (section 8.11.2).

use crate::route::{Flow, RouteFailure, Run};

pub(crate) fn run(run: &mut Run<'_, '_>, name: &str) -> Result<Flow, RouteFailure> {
    run.exchange.remove_property(name);
    Ok(Flow::Continue)
}
