// SPDX-License-Identifier: Apache-2.0

//! The `filter` processor, Camel's Message Filter
//! (`products/adapter/CONCEPT.md` section 8.6): the nested steps run
//! only on a matching predicate, and the route continues after the
//! filter either way. `statusPropertyName`, when declared, records the
//! boolean outcome on an exchange property; Camel 4 sets no fixed filter
//! property, and neither does the port.

use registry_adapter_core::{ErrorClass, FilterStep};
use serde_json::json;

use crate::engine::route::{Flow, RouteFailure, Run};

pub(crate) async fn run(run: &mut Run<'_, '_>, step: &FilterStep) -> Result<Flow, RouteFailure> {
    // As for `choice`: a malformed clause never loads.
    let Some(predicate) = step.predicate() else {
        return Err(RouteFailure::of(ErrorClass::Script));
    };
    let matched = run.predicate(&predicate)?;
    if let Some(name) = &step.status_property_name {
        run.exchange.set_property(name, json!(matched));
    }
    if matched {
        run.run_steps(&step.steps).await
    } else {
        Ok(Flow::Continue)
    }
}
