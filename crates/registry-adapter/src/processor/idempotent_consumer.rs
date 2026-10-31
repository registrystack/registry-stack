// SPDX-License-Identifier: Apache-2.0

//! The `idempotentConsumer` processor for served writes
//! (`products/adapter/CONCEPT.md` section 9). The store eagerly claims the
//! caller, operation, key, and request digest before guarded work. A source
//! effect is marked separately by [`crate::exchange::Exchange::before_upstream_effect`]
//! immediately before the non-safe send.

use registry_adapter_core::{ErrorClass, IdempotentConsumerStep};
use serde_json::Value;

use crate::exchange::WriteClaim;
use crate::idempotent::MAX_IDEMPOTENCY_KEY_BYTES;
use crate::route::{Flow, RouteFailure, Run};

pub(crate) async fn run(
    run: &mut Run<'_, '_>,
    step: &IdempotentConsumerStep,
) -> Result<Flow, RouteFailure> {
    // The synchronous served-write slice needs the claim before guarded work
    // and the terminal facade response after the whole route. Non-default
    // timing is refused at load; keep the interpreter fail-closed if a caller
    // assembles a RouteContext directly.
    if !step.eager || step.completion_eager {
        return Err(RouteFailure::of(ErrorClass::Facade));
    }
    let key = match run.eval(&step.expression)? {
        Value::String(key)
            if !key.is_empty() && key.len() <= MAX_IDEMPOTENCY_KEY_BYTES && !key.contains('\0') =>
        {
            key
        }
        _ => return Err(RouteFailure::of(ErrorClass::FacadeInvalidField)),
    };
    match run.exchange.claim_write_key(&key).await? {
        WriteClaim::Stop => Ok(Flow::Stop),
        WriteClaim::Execute => match run.run_steps(&step.steps).await {
            Ok(flow) => Ok(flow),
            Err(failure) => {
                if step.remove_on_failure {
                    run.exchange.release_write_before_effect().await?;
                }
                Err(failure)
            }
        },
    }
}
