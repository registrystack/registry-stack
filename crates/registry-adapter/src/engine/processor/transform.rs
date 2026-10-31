// SPDX-License-Identifier: Apache-2.0

//! The `transform` processor, Camel's message transformation sugar over
//! `setBody` (`products/adapter/CONCEPT.md` section 8.6). It replaces
//! the body with its expression's value under the same rules as
//! `crate::engine::processor::set_body`.

use registry_adapter_core::Expression;

use crate::engine::processor::set_body;
use crate::engine::route::{Flow, RouteFailure, Run};

pub(crate) fn run(run: &mut Run<'_, '_>, expression: &Expression) -> Result<Flow, RouteFailure> {
    set_body::assign(run, expression)
}
