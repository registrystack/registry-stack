// SPDX-License-Identifier: Apache-2.0
//! Durable handoff for one exact configured BReg Action.
//!
//! The BReg client owns metadata promotion, target conditions, exact recovery
//! and receipt validation. Preparation reads current authority but sends no
//! mutation. Saved bytes are inert and must be protected with the command.

use registry_breg_client::{
    BRegActionBinding, BRegActionInvocationRequest, BRegActionMode,
    BRegActionTargetConditionsRequest, BRegIdempotencyKey, BRegPreparedAction, BRegProblemCode,
    BaseRegistryClient, BaseRegistryClientError,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    adapters::{refused, retryable, token_failure},
    protocol::{CallOutcome, CallRequest, DeclaredRefusal, Operation},
};

/// Package-pinned specialization exported by the owning BReg compiler.
/// Current caller metadata must promote the same Action before every attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ActionContract {
    pub action_id: String,
    pub action_revision: String,
    #[cfg_attr(feature = "schema", schemars(with = "String", extend("enum" = ["immediate", "proposal"])))]
    pub mode: BRegActionMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct ActionInput {
    input: Map<String, Value>,
    #[serde(default)]
    preconditions: Option<Value>,
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

fn declared_refusal(
    mutation: bool,
    status: Option<u16>,
    problem: Option<BRegProblemCode>,
    refusal_code: Option<&str>,
) -> Option<DeclaredRefusal> {
    (mutation && status == Some(422) && problem == Some(BRegProblemCode::ActionRefused))
        .then_some(refusal_code)
        .flatten()
        .and_then(DeclaredRefusal::new)
}

pub(crate) fn failure(error: BaseRegistryClientError, mutation: bool) -> CallOutcome {
    if mutation && error.problem_code() == Some(BRegProblemCode::IdempotencyExpired) {
        return CallOutcome::ReceiptExpired;
    }
    if mutation && error.is_outcome_unknown() {
        return CallOutcome::Uncertain {
            code: "transport-uncertain".into(),
        };
    }
    if let Some(refusal) = declared_refusal(
        mutation,
        error.status(),
        error.problem_code(),
        error.refusal_code().map(|code| code.as_str()),
    ) {
        return CallOutcome::DeclaredRefusal(refusal);
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
    expected: &ActionContract,
) -> Result<BRegActionBinding, CallOutcome> {
    let metadata = client
        .registry_contract(Some(profile))
        .await
        .map_err(|error| failure(error, false))?;
    let action = metadata
        .value
        .select_action(&expected.action_id, profile)
        .map_err(|_| refused("action-unavailable"))?;
    if action.definition_revision() != expected.action_revision || action.mode() != expected.mode {
        return Err(refused("action-contract-changed"));
    }
    Ok(action)
}

/// Prepare exact client-owned evidence before durable dispatch. The configured
/// service profile owns authority; caller input cannot select another profile.
pub async fn prepare(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
) -> Result<Vec<u8>, CallOutcome> {
    let (input, key) = input(request)?;
    let expected = request
        .operation_contract
        .as_ref()
        .ok_or_else(|| refused("action-contract-missing"))?;
    let action = binding(client, profile, expected).await?;
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
    if input.preconditions.as_ref().is_some_and(|expected| {
        conditions
            .as_ref()
            .and_then(|conditions| serde_json::to_value(conditions).ok())
            .and_then(|value| value.get("preconditions").cloned())
            .as_ref()
            != Some(expected)
    }) {
        return Err(refused("target-conditions-mismatch"));
    }
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
    let Some(expected) = request.operation_contract.as_ref() else {
        return refused("action-contract-missing");
    };
    let action = match binding(client, profile, expected).await {
        Ok(action) => action,
        Err(outcome) => return outcome,
    };
    let invocation = match client.recover_action(&action, &prepared, &input.input, &key) {
        Ok(invocation) => invocation,
        Err(_) => return refused("prepared-command-mismatch"),
    };
    if action.mode() == BRegActionMode::Proposal {
        return match client.start_proposal(&action, &invocation, &key).await {
            Ok(answer)
                if answer.value.state() != registry_breg_client::BRegProposalState::Draft
                    || answer.value.application().is_some() =>
            {
                CallOutcome::Uncertain {
                    code: "invalid-response".into(),
                }
            }
            Ok(answer) => match serde_json::to_value(answer.value) {
                Ok(proposal) => CallOutcome::Success(serde_json::json!({"proposal":proposal})),
                Err(_) => CallOutcome::Uncertain {
                    code: "invalid-response".into(),
                },
            },
            Err(error) => failure(error, true),
        };
    }
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

#[cfg(test)]
mod tests {
    use super::{declared_refusal, failure};
    use crate::protocol::CallOutcome;
    use registry_breg_client::{BRegProblemCode, BRegProtocolFailure, BaseRegistryClientError};

    #[test]
    fn local_invalid_commands_and_post_send_protocol_failures_keep_distinct_outcomes() {
        assert!(matches!(
            failure(
                BaseRegistryClientError::InvalidRequest {
                    reason: "synthetic local preparation refusal"
                },
                true
            ),
            CallOutcome::Refused { code } if code == "invalid-command"
        ));
        for status in [200, 201] {
            assert!(matches!(
                failure(
                    BaseRegistryClientError::Protocol {
                        status,
                        failure: BRegProtocolFailure::Body,
                        trace_id: None,
                        metadata: None,
                    },
                    true
                ),
                CallOutcome::Uncertain { code } if code == "transport-uncertain"
            ));
        }
    }

    #[test]
    fn declared_refusal_classification_requires_every_typed_execution_guard() {
        let classify = |mutation, status, problem, code| {
            declared_refusal(mutation, status, problem, code)
                .map(|refusal| refusal.refusal_code().to_owned())
        };
        let refused = Some(BRegProblemCode::ActionRefused);
        assert_eq!(
            classify(true, Some(422), refused, Some("not-eligible")),
            Some("not-eligible".to_owned())
        );
        for refusal in [
            classify(false, Some(422), refused, Some("not-eligible")),
            classify(true, Some(409), refused, Some("not-eligible")),
            classify(
                true,
                Some(422),
                Some(BRegProblemCode::PreconditionFailed),
                Some("not-eligible"),
            ),
            classify(true, Some(422), refused, None),
            classify(true, Some(422), refused, Some("line\nbreak")),
            classify(true, Some(422), refused, Some(&"x".repeat(129))),
        ] {
            assert_eq!(refusal, None);
        }
    }
}
