// SPDX-License-Identifier: Apache-2.0
//! Proposals of one pinned BReg Proposal Action: the calls that read, start,
//! submit and cancel one, and the follow that turns a current Proposal Get
//! into a wait observation.
//!
//! A run never approves, rejects or applies a Proposal; BReg and its review
//! authority decide. The follow settles only from the current Proposal Get
//! under the connection profile's own get grant, never from an event.

use registry_breg_client::{
    BRegActionBinding, BRegActionInvocationRequest, BRegIdempotencyKey, BRegPreparedProposal,
    BRegProposal, BRegProposalState, BRegProposalTurn, BaseRegistryClient, BaseRegistryClientError,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    adapters::refused,
    breg_action::{failure, ActionContract},
    protocol::{CallOutcome, CallRequest, CompletionObservation, Operation, ProposalObservation},
};

/// The input of `breg.read-proposal/v1` and `breg.cancel-proposal/v1`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct ProposalReference {
    proposal_id: Uuid,
}

/// The output of every Proposal call: which Proposal the run holds, of which
/// Action revision, at which submission version and state.
#[derive(Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub(crate) struct ProposalReceipt {
    proposal_id: Uuid,
    action_id: String,
    #[cfg_attr(
        feature = "schema",
        schemars(regex(pattern = r"^sha256:[0-9a-f]{64}$"))
    )]
    action_revision: String,
    #[cfg_attr(feature = "schema", schemars(range(min = 1)))]
    submission_version: u32,
    state: BRegProposalState,
}

/// The part of an accepted call output the follow binds to.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Accepted {
    proposal_id: Uuid,
    submission_version: u32,
}

fn receipt(proposal: &BRegProposal) -> CallOutcome {
    let Ok(proposal_id) = Uuid::parse_str(proposal.id()) else {
        return CallOutcome::Uncertain {
            code: "invalid-response".into(),
        };
    };
    match serde_json::to_value(ProposalReceipt {
        proposal_id,
        action_id: proposal.action_id().to_owned(),
        action_revision: proposal.action_revision().to_owned(),
        submission_version: proposal.submission_version(),
        state: proposal.state(),
    }) {
        Ok(value) => CallOutcome::Success(value),
        Err(_) => CallOutcome::Uncertain {
            code: "invalid-response".into(),
        },
    }
}

/// The outcomes a follow of `operation` can return. A run that submitted
/// the Proposal sees a return to its holder as `returned`; a run that
/// started or read one keeps waiting while the holder revises.
pub(crate) fn outcomes(operation: Operation) -> &'static [&'static str] {
    if operation == Operation::SubmitProposal {
        &["applied", "rejected", "cancelled", "returned"]
    } else {
        &["applied", "rejected", "cancelled"]
    }
}

/// The settled `input`: the Action's input members, none required, because
/// BReg discloses only the members the connection profile may read.
pub(crate) fn settled_input(action_input: &Value) -> Value {
    let mut input = action_input
        .pointer("/properties/input")
        .filter(|schema| schema.is_object())
        .cloned()
        .unwrap_or_else(|| json!({"type": "object"}));
    if let Some(schema) = input.as_object_mut() {
        schema.remove("required");
    }
    input
}

/// The output a `wait-for` on the host-owned `proposal` completion holds.
pub(crate) fn completion_schema(operation: Operation, input: Value) -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": format!("{} proposal completion", operation.as_str()),
        "type": "object",
        "additionalProperties": false,
        "required": ["outcome", "proposalId", "submissionVersion", "actionRevision", "input"],
        "properties": {
            "outcome": {"type": "string", "enum": outcomes(operation)},
            "proposalId": {"type": "string", "format": "uuid"},
            "submissionVersion": {"type": "integer", "minimum": 1},
            "actionRevision": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "decision": {
                "type": "object",
                "additionalProperties": false,
                "required": ["status", "decidedAt"],
                "properties": {
                    "status": {"type": "string",
                        "enum": ["approved", "rejected", "changes-requested", "answered"]},
                    "decidedAt": {"type": "string", "format": "date-time"},
                    "publicReason": {"type": "string"}
                }
            },
            "input": input
        }
    })
}

/// Whether a stored completion is the host-owned one for this operation.
pub(crate) fn completion_matches(operation: Operation, output: &Value) -> bool {
    operation.follows_proposal()
        && output
            .pointer("/properties/input")
            .filter(|input| input.get("type").and_then(Value::as_str) == Some("object"))
            .is_some_and(|input| *output == completion_schema(operation, input.clone()))
}

fn pinned(request: &CallRequest) -> Result<&ActionContract, CallOutcome> {
    request
        .operation_contract
        .as_ref()
        .ok_or_else(|| refused("action-contract-missing"))
}

/// Reads one Proposal through the profile's own get grant. A Proposal of
/// another Action is not the one this operation names.
async fn current(
    client: &BaseRegistryClient,
    profile: &str,
    expected: &ActionContract,
    proposal_id: Uuid,
) -> Result<BRegProposal, Reading> {
    let metadata = crate::adapters::breg_metadata_client(client)
        .map_err(Reading::Failed)?
        .registry_contract(Some(profile))
        .await
        .map_err(Reading::Failed)?;
    let binding = metadata
        .value
        .select_proposal_get(profile)
        .map_err(|_| Reading::Ungranted)?;
    let proposal = client
        .get_proposal(&binding, &proposal_id.to_string())
        .await
        .map_err(Reading::Failed)?
        .value;
    if proposal.action_id() != expected.action_id {
        return Err(Reading::OtherAction);
    }
    Ok(proposal)
}

enum Reading {
    Failed(BaseRegistryClientError),
    Ungranted,
    OtherAction,
}

impl Reading {
    fn call_outcome(self) -> CallOutcome {
        match self {
            Self::Failed(error) => failure(error, false),
            Self::Ungranted => refused("product-forbidden"),
            Self::OtherAction => refused("invalid-command"),
        }
    }
}

fn reference(request: &CallRequest) -> Result<Uuid, CallOutcome> {
    serde_json::from_value::<ProposalReference>(request.input.clone())
        .map(|reference| reference.proposal_id)
        .map_err(|_| refused("invalid-command"))
}

fn key(request: &CallRequest) -> Result<BRegIdempotencyKey, CallOutcome> {
    request
        .idempotency_key
        .as_deref()
        .and_then(|key| BRegIdempotencyKey::parse(key).ok())
        .ok_or_else(|| refused("invalid-command"))
}

/// `breg.read-proposal/v1`: the Proposal a person started, by id.
pub(crate) async fn read(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
) -> CallOutcome {
    let (id, expected) = match reference(request).and_then(|id| Ok((id, pinned(request)?))) {
        Ok(found) => found,
        Err(outcome) => return outcome,
    };
    match current(client, profile, expected, id).await {
        Ok(proposal) => receipt(&proposal),
        Err(reading) => reading.call_outcome(),
    }
}

/// A Proposal operation's own refusal is not a declared business refusal.
fn mutation_failure(error: BaseRegistryClientError) -> CallOutcome {
    match failure(error, true) {
        CallOutcome::DeclaredRefusal(_) => refused("product-refused"),
        outcome => outcome,
    }
}

/// `breg.start-proposal/v1` and `breg.submit-proposal/v1`, after the shared
/// Action preparation recovered the frozen start command. Submit sends a
/// second frozen command, the empty submit transition, under its own key
/// derived from the start key; both replay on every attempt.
pub(crate) async fn start(
    client: &BaseRegistryClient,
    action: &BRegActionBinding,
    invocation: &BRegActionInvocationRequest,
    key: &BRegIdempotencyKey,
    operation: Operation,
) -> CallOutcome {
    let draft = match client.start_proposal(action, invocation, key).await {
        Ok(answer) => answer.value,
        Err(error) => return mutation_failure(error),
    };
    if operation != Operation::SubmitProposal {
        return receipt(&draft);
    }
    let Ok(submit_key) = BRegIdempotencyKey::parse(format!("{}:submit", key.as_str())) else {
        return refused("invalid-command");
    };
    let prepared = match client.prepare_proposal(&draft, "submit", json!({}), &submit_key) {
        Ok(prepared) => prepared,
        Err(error) => return mutation_failure(error),
    };
    match client.execute_proposal(&prepared).await {
        Ok(answer) => receipt(&answer.value),
        Err(error) => mutation_failure(error),
    }
}

/// `breg.cancel-proposal/v1` preparation: freeze the cancel transition of
/// the current Proposal. No mutation is sent.
pub(crate) async fn prepare_cancel(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
) -> Result<Vec<u8>, CallOutcome> {
    let id = reference(request)?;
    let key = key(request)?;
    let proposal = current(client, profile, pinned(request)?, id)
        .await
        .map_err(Reading::call_outcome)?;
    client
        .prepare_proposal(&proposal, "cancel", json!({}), &key)
        .map(|prepared| prepared.as_bytes().to_vec())
        .map_err(|error| failure(error, false))
}

/// `breg.cancel-proposal/v1` execution: rebind the frozen transition to a
/// current read and send it. A Proposal already cancelled, by this command
/// or by anyone, needs no further request.
pub(crate) async fn cancel(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
    prepared: &[u8],
) -> CallOutcome {
    let (id, expected) = match reference(request).and_then(|id| Ok((id, pinned(request)?))) {
        Ok(found) => found,
        Err(outcome) => return outcome,
    };
    let Ok(prepared) = BRegPreparedProposal::from_slice(prepared) else {
        return refused("invalid-command");
    };
    let proposal = match current(client, profile, expected, id).await {
        Ok(proposal) => proposal,
        Err(reading) => return reading.call_outcome(),
    };
    if proposal.state() == BRegProposalState::Cancelled {
        return receipt(&proposal);
    }
    let attempt = match client.recover_proposal(&proposal, &prepared) {
        Ok(attempt) => attempt,
        Err(_) => return refused("prepared-command-mismatch"),
    };
    match client.execute_proposal(&attempt).await {
        Ok(answer) => receipt(&answer.value),
        Err(error) => mutation_failure(error),
    }
}

/// One scheduled or early read of a followed Proposal.
pub(crate) async fn observe(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
    accepted: &Value,
) -> CompletionObservation {
    let (Ok(accepted), Some(expected)) = (
        serde_json::from_value::<Accepted>(accepted.clone()),
        request.operation_contract.as_ref(),
    ) else {
        return CompletionObservation::Hold {
            code: "completion-invalid-response".into(),
        };
    };
    match current(client, profile, expected, accepted.proposal_id).await {
        Ok(proposal) => match observation(&proposal) {
            Some(seen) => CompletionObservation::Followed {
                proposal: seen,
                read: Box::new(classify(request.operation, &accepted, &proposal)),
            },
            None => CompletionObservation::Hold {
                code: "completion-invalid-response".into(),
            },
        },
        Err(Reading::Ungranted) => unreadable(),
        Err(Reading::OtherAction) => CompletionObservation::Hold {
            code: "completion-invalid-response".into(),
        },
        Err(Reading::Failed(error)) => match error.status() {
            Some(401 | 403 | 404) => unreadable(),
            _ => CompletionObservation::from_failure(failure(error, false)),
        },
    }
}

/// What the wait keeps from one answered read: the Proposal's state, turn,
/// submission version and any hand-off refusal code, and nothing else.
fn observation(proposal: &BRegProposal) -> Option<ProposalObservation> {
    let name = |value: Value| value.as_str().map(str::to_owned);
    Some(ProposalObservation {
        state: name(serde_json::to_value(proposal.state()).ok()?)?,
        turn: match proposal.turn() {
            Some(turn) => Some(name(serde_json::to_value(turn).ok()?)?),
            None => None,
        },
        submission_version: u64::from(proposal.submission_version()),
        handoff_refusal: proposal
            .handoff_refusal()
            .map(|code| code.as_str().to_owned()),
    })
}

fn unreadable() -> CompletionObservation {
    CompletionObservation::Hold {
        code: "proposal-unreadable".into(),
    }
}

/// The observation table of the product contract. Only a terminal state
/// settles; a follow of a submitted Proposal also ends when the run's own
/// submission comes back to its holder.
fn classify(
    operation: Operation,
    accepted: &Accepted,
    proposal: &BRegProposal,
) -> CompletionObservation {
    let submitted_by_run = operation == Operation::SubmitProposal;
    let outcome = match proposal.state() {
        BRegProposalState::Applied => "applied",
        BRegProposalState::Rejected => "rejected",
        BRegProposalState::Cancelled => "cancelled",
        _ if !submitted_by_run => return pending(),
        _ if proposal.submission_version() > accepted.submission_version => "returned",
        BRegProposalState::Draft => "returned",
        BRegProposalState::Submitted if proposal.handoff_refusal().is_some() => {
            return CompletionObservation::Hold {
                code: "proposal-handoff-refused".into(),
            };
        }
        BRegProposalState::Submitted if proposal.turn() == Some(BRegProposalTurn::Party) => {
            "returned"
        }
        BRegProposalState::Submitted => return pending(),
    };
    let mut settled = Map::new();
    settled.insert("outcome".into(), outcome.into());
    settled.insert("proposalId".into(), proposal.id().into());
    settled.insert(
        "submissionVersion".into(),
        proposal.submission_version().into(),
    );
    settled.insert("actionRevision".into(), proposal.action_revision().into());
    if let Some(decision) = proposal.decision() {
        match serde_json::to_value(decision) {
            Ok(decision) => {
                settled.insert("decision".into(), decision);
            }
            Err(_) => {
                return CompletionObservation::Hold {
                    code: "completion-invalid-response".into(),
                }
            }
        }
    }
    settled.insert(
        "input".into(),
        Value::Object(proposal.input().cloned().unwrap_or_default()),
    );
    CompletionObservation::Settled(Value::Object(settled))
}

fn pending() -> CompletionObservation {
    CompletionObservation::Pending { retry_after: None }
}
