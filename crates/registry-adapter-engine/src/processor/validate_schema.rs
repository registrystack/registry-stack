// SPDX-License-Identifier: Apache-2.0

//! Digest-pinned provider response validation. A mismatch is a source
//! protocol boundary failure, not a pack-authored validation outcome, so it
//! cannot be normalized by `onException` or `doCatch`.

use registry_adapter_core::{ErrorClass, ScriptReference};

use crate::route::{Flow, RouteFailure, Run};

pub(crate) fn run(
    run: &mut Run<'_, '_>,
    reference: &ScriptReference,
) -> Result<Flow, RouteFailure> {
    if run
        .context
        .scripts
        .provider_schema_validates(reference, &run.exchange.message.body)
    {
        return Ok(Flow::Continue);
    }
    Err(RouteFailure {
        class: ErrorClass::DisclosureViolation,
        message: None,
        data: None,
        auth: None,
        code: Some("adapter.source.response-schema"),
        record: None,
        evidence_diagnostic: None,
    })
}
