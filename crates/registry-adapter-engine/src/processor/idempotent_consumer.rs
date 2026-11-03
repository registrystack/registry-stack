// SPDX-License-Identifier: Apache-2.0

//! The `idempotentConsumer` processor for served writes
//! (`products/adapter/CONCEPT.md` section 9). The host reserves the caller,
//! operation, key, and request digest before guarded work so write-effect
//! custody stays fail-closed. The EIP's `eager` option independently selects
//! repository-membership timing, and `completionEager` selects block or whole
//! exchange completion. A source effect is marked separately by
//! [`crate::exchange::Exchange::before_upstream_effect`] immediately before
//! the non-safe send.

use registry_adapter_core::{ErrorClass, IdempotentConsumerStep};
use serde_json::Value;

use crate::exchange::WriteClaim;
use crate::exchange::MAX_IDEMPOTENCY_KEY_BYTES;
use crate::route::{Flow, RouteFailure, Run};

pub(crate) async fn run(
    run: &mut Run<'_, '_>,
    step: &IdempotentConsumerStep,
) -> Result<Flow, RouteFailure> {
    let key = match run.eval(&step.expression)? {
        Value::String(key)
            if !key.is_empty() && key.len() <= MAX_IDEMPOTENCY_KEY_BYTES && !key.contains('\0') =>
        {
            key
        }
        _ => return Err(RouteFailure::of(ErrorClass::FacadeInvalidField)),
    };
    let claim = run.exchange.claim_write_key(&key, step.eager).await?;
    match claim {
        WriteClaim::Stop => Ok(Flow::Stop),
        claim @ (WriteClaim::Execute | WriteClaim::Resume(_)) => {
            let resume = match claim {
                WriteClaim::Execute => None,
                WriteClaim::Resume(execution) => Some(execution),
                WriteClaim::Stop => return Err(RouteFailure::of(ErrorClass::Facade)),
            };
            run.begin_resume(resume)?;
            if !step.completion_eager {
                run.defer_write_completion(step.remove_on_failure)?;
            }
            let outcome = run.run_steps(&step.steps).await;
            if step.completion_eager && !run.async_accepted() {
                let succeeded = run.completion_succeeded(outcome.is_ok());
                run.exchange
                    .complete_write_key(succeeded, step.remove_on_failure)
                    .await?;
            }
            outcome
        }
    }
}
