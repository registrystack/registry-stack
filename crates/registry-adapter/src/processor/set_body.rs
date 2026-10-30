// SPDX-License-Identifier: Apache-2.0

//! The `setBody` processor: replace the message body with the value of
//! its expression (`products/adapter/CONCEPT.md` section 8.6).
//!
//! The expression is one of the languages of section 8.5. An absent
//! JSONPath result raises the `validation` class where a value is
//! required (section 8.11.8).

use registry_adapter_core::Expression;

use crate::route::{Flow, RouteFailure, Run};

/// Assign the body from the expression. `transform` runs under the same
/// rule; this is the interpreter's one body assign.
pub(crate) fn assign(run: &mut Run<'_, '_>, expression: &Expression) -> Result<Flow, RouteFailure> {
    run.exchange.message.body = run.eval_required(expression)?;
    Ok(Flow::Continue)
}
