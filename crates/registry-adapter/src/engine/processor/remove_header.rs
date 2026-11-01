// SPDX-License-Identifier: Apache-2.0

//! The `removeHeader` processor: remove a message header
//! (`products/adapter/CONCEPT.md` section 8.6). The read-only facade
//! inputs of section 8.11.1 are refused as targets.

use crate::engine::route::{Flow, RouteFailure, Run};

pub(crate) fn run(run: &mut Run<'_, '_>, name: &str) -> Result<Flow, RouteFailure> {
    run.exchange.message.remove_header(name);
    Ok(Flow::Continue)
}
