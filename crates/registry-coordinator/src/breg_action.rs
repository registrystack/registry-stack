// SPDX-License-Identifier: Apache-2.0
//! Durable handoff for one configured BReg immediate action.
//!
//! The BReg client owns metadata promotion, target conditions, exact recovery
//! and receipt validation. Preparation reads current authority but sends no
//! mutation. Saved bytes are inert and must be protected with the command.

use registry_breg_client::{
    BRegActionInvocationRequest, BRegActionTargetConditionsRequest, BRegIdempotencyKey,
    BRegImmediateActionBinding, BRegPreparedAction, BRegProblemCode, BaseRegistryClient,
    BaseRegistryClientError,
};
use serde::Deserialize;
use serde_json::{Map, Value};

use crate::{
    adapters::{refused, retryable, token_failure},
    protocol::{CallOutcome, CallRequest, Operation},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionInput {
    action: String,
    input: Map<String, Value>,
}

fn input(request: &CallRequest) -> Result<(ActionInput, BRegIdempotencyKey), CallOutcome> {
    if request.operation != Operation::InvokeBregAction {
        return Err(refused("invalid-command"));
    }
    let input =
        serde_json::from_value(request.input.clone()).map_err(|_| refused("invalid-command"))?;
    let key = request
        .idempotency_key
        .as_deref()
        .ok_or_else(|| refused("invalid-command"))?;
    let key = BRegIdempotencyKey::parse(key).map_err(|_| refused("invalid-command"))?;
    Ok((input, key))
}

fn failure(error: BaseRegistryClientError, mutation: bool) -> CallOutcome {
    if mutation && error.problem_code() == Some(BRegProblemCode::IdempotencyExpired) {
        return CallOutcome::ReceiptExpired;
    }
    if mutation && error.is_outcome_unknown() {
        return CallOutcome::Uncertain {
            code: "transport-uncertain".into(),
        };
    }
    match error {
        BaseRegistryClientError::Token(error) => token_failure(&error),
        BaseRegistryClientError::Transport { .. } => retryable("transport-unavailable"),
        error if error.status() == Some(429) => retryable("rate-limited"),
        BaseRegistryClientError::Problem {
            status: 401 | 403, ..
        } => refused("product-forbidden"),
        BaseRegistryClientError::Problem { status: 404, .. } => refused("product-not-found"),
        error
            if !mutation
                && error
                    .status()
                    .is_some_and(|status| status == 408 || status >= 500) =>
        {
            retryable("transport-unavailable")
        }
        BaseRegistryClientError::InvalidRequest { .. } => refused("invalid-command"),
        BaseRegistryClientError::Protocol { .. } => refused("invalid-response"),
        _ => refused("product-refused"),
    }
}

async fn binding(
    client: &BaseRegistryClient,
    profile: &str,
    action: &str,
) -> Result<BRegImmediateActionBinding, CallOutcome> {
    let metadata = client
        .registry_contract(Some(profile))
        .await
        .map_err(|error| failure(error, false))?;
    metadata
        .value
        .select_immediate_action(action, profile)
        .map_err(|_| refused("action-unavailable"))
}

/// Prepare exact client-owned evidence before durable dispatch. The configured
/// service profile owns authority; caller input cannot select another profile.
pub async fn prepare(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
) -> Result<Vec<u8>, CallOutcome> {
    let (input, key) = input(request)?;
    let action = binding(client, profile, &input.action).await?;
    BRegActionInvocationRequest::validate_inputs(&action, &input.input)
        .map_err(|_| refused("invalid-command"))?;
    let conditions = if action.required_condition_keys().is_empty() {
        None
    } else {
        let targets = action
            .required_condition_keys()
            .iter()
            .map(|name| {
                input
                    .input
                    .get(name)
                    .cloned()
                    .map(|value| (name.clone(), value))
            })
            .collect::<Option<Map<_, _>>>()
            .ok_or_else(|| refused("invalid-command"))?;
        let conditions_request = BRegActionTargetConditionsRequest::new(&action, targets)
            .map_err(|_| refused("invalid-command"))?;
        Some(
            client
                .action_target_conditions(&action, &conditions_request)
                .await
                .map_err(|error| failure(error, false))?
                .value,
        )
    };
    let invocation = BRegActionInvocationRequest::new(&action, input.input, conditions.as_ref())
        .map_err(|_| refused("invalid-command"))?;
    client
        .prepare_action(&action, &invocation, &key)
        .map(|prepared| prepared.as_bytes().to_vec())
        .map_err(|error| failure(error, false))
}

/// Rebind saved evidence to fresh caller-filtered metadata and perform exactly
/// the original invocation. This never fetches replacement target conditions.
/// The configured client must disable internal mutation retries.
pub async fn execute(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
    prepared: &[u8],
) -> CallOutcome {
    let (input, key) = match input(request) {
        Ok(input) => input,
        Err(outcome) => return outcome,
    };
    let prepared = match BRegPreparedAction::from_slice(prepared) {
        Ok(prepared) => prepared,
        Err(_) => return refused("invalid-command"),
    };
    let action = match binding(client, profile, &input.action).await {
        Ok(action) => action,
        Err(outcome) => return outcome,
    };
    let invocation = match client.recover_action(&action, &prepared, &input.input, &key) {
        Ok(invocation) => invocation,
        Err(_) => return refused("prepared-command-mismatch"),
    };
    match client.invoke_action(&action, &invocation, &key).await {
        Ok(answer) => match serde_json::to_value(answer.value) {
            Ok(value) => CallOutcome::Success(value),
            Err(_) => CallOutcome::Uncertain {
                code: "invalid-response".into(),
            },
        },
        Err(error) => failure(error, true),
    }
}
