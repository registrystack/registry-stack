// SPDX-License-Identifier: Apache-2.0

//! The `script` processor: run an expression for effect on exchange
//! properties without changing the body, as Camel's `script` EIP
//! (`products/adapter/CONCEPT.md` section 8.6).
//!
//! The `rhai` entrypoint receives the exchange view of section 8.11.3
//! and returns a map of property names to values. Each script file is
//! its own compilation unit and the budgets are
//! `registry-platform-script`'s; exceeding one raises the uncatchable
//! `script.budget-exceeded`.

use registry_adapter_core::{ErrorClass, Expression};

use crate::engine::exchange::{NEXT_CONTINUATION_PROPERTY, RESERVED_PROPERTY_PREFIX};
use crate::engine::route::{Flow, RouteFailure, Run};

pub(crate) fn run(run: &mut Run<'_, '_>, expression: &Expression) -> Result<Flow, RouteFailure> {
    let returned = run.eval(expression)?;
    let Some(properties) = returned.as_object() else {
        // Section 8.11.3: the slot returns a map of property names.
        return Err(RouteFailure::of(ErrorClass::Script));
    };
    // The set rule of section 8.11.2, one step down: a route's own names
    // pass, the engine's `Adapter` prefix does not, except the one
    // continuation property a search route hands back.
    for name in properties.keys() {
        if name.starts_with(RESERVED_PROPERTY_PREFIX) && name != NEXT_CONTINUATION_PROPERTY {
            return Err(RouteFailure::of(ErrorClass::Script));
        }
    }
    for (name, value) in properties {
        run.exchange.set_property(name, value.clone());
    }
    Ok(Flow::Continue)
}
