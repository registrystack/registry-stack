// SPDX-License-Identifier: Apache-2.0
//! Exact Proposal transitions and observation through the ordinary BReg client.
//!
//! Observation starts only from a retained accepted submission. It cannot
//! recover an unknown Action start or submit command or grant apply authority.

use registry_breg_client::{
    BRegIdempotencyKey, BRegPreparedProposal, BRegProposal, BRegProposalApplicationReason,
    BRegProposalApplicationState, BRegProposalState, BRegRetryAfter, BaseRegistryClient,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::{
    adapters::refused,
    breg_action::failure,
    protocol::{CallOutcome, CallRequest, Operation},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transition {
    Submit,
    Apply,
    Cancel,
    Retry,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PreparedTransition {
    version: u8,
    request_digest: String,
    transition: Transition,
    owner_preparation: String,
}

fn request_digest(request: &CallRequest) -> Result<String, CallOutcome> {
    let value = serde_json::to_value(request).map_err(|_| refused("invalid-command"))?;
    let bytes = registry_platform_canonical_json::canonicalize_json(&value)
        .map_err(|_| refused("invalid-command"))?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(bytes))))
}

impl Transition {
    fn coordinator_operation(self) -> Operation {
        match self {
            Self::Submit => Operation::SubmitBregProposal,
            Self::Apply => Operation::ApplyBregProposal,
            Self::Cancel => Operation::CancelBregProposal,
            Self::Retry => Operation::RetryBregProposal,
        }
    }

    fn operation(self) -> &'static str {
        match self {
            Self::Submit => "submit",
            Self::Apply => "apply",
            Self::Cancel => "cancel",
            Self::Retry => "retry",
        }
    }

    fn body(self, proposal: &BRegProposal) -> Result<Value, CallOutcome> {
        if self == Self::Apply {
            let digest = proposal
                .effect_digest()
                .ok_or_else(|| refused("submission-missing"))?;
            if proposal.submission_version() == 0
                || proposal.state() != BRegProposalState::Submitted
            {
                return Err(refused("submission-missing"));
            }
            Ok(json!({"submissionVersion":proposal.submission_version(),"effectDigest":digest}))
        } else {
            Ok(json!({}))
        }
    }
}

/// Only the receiver's authenticated representation can complete this wait.
pub enum ApplicationObservation {
    Pending {
        retry_after: Option<Duration>,
    },
    Complete(Value),
    Retryable {
        code: String,
        retry_after: Option<Duration>,
    },
    Hold {
        code: String,
    },
}

fn proposal(value: &Value) -> Result<BRegProposal, CallOutcome> {
    let bytes = serde_json::to_vec(value).map_err(|_| refused("invalid-command"))?;
    BRegProposal::from_slice(&bytes).map_err(|_| refused("invalid-command"))
}

async fn current(
    client: &BaseRegistryClient,
    profile: &str,
    expected: &BRegProposal,
) -> Result<BRegProposal, CallOutcome> {
    let metadata = client
        .registry_contract(Some(profile))
        .await
        .map_err(|error| failure(error, false))?;
    let binding = metadata
        .value
        .select_proposal_get(profile)
        .map_err(|_| refused("proposal-unavailable"))?;
    let current = client
        .get_proposal(&binding, expected.id())
        .await
        .map_err(|error| failure(error, false))?
        .value;
    if current.action_id() != expected.action_id() {
        return Err(refused("proposal-binding-mismatch"));
    }
    Ok(current)
}

fn same_submission(expected: &BRegProposal, current: &BRegProposal) -> bool {
    expected.id() == current.id()
        && expected.action_id() == current.action_id()
        && expected.action_revision() == current.action_revision()
        && expected.submission_version() == current.submission_version()
        && expected.effect_digest() == current.effect_digest()
}

/// Read current authority and promote the exact supplied Proposal revision.
/// Preparation never dispatches a lifecycle mutation.
pub async fn prepare(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
    transition: Transition,
) -> Result<Vec<u8>, CallOutcome> {
    if request.operation != transition.coordinator_operation() {
        return Err(refused("invalid-command"));
    }
    let expected = proposal(&request.input)?;
    let key = request
        .idempotency_key
        .as_deref()
        .ok_or_else(|| refused("invalid-command"))?;
    let key = BRegIdempotencyKey::parse(key).map_err(|_| refused("invalid-command"))?;
    let current = current(client, profile, &expected).await?;
    if !same_submission(&expected, &current)
        || expected.revision() != current.revision()
        || expected.state() != current.state()
    {
        return Err(refused("proposal-revision-changed"));
    }
    if transition == Transition::Submit && current.state() != BRegProposalState::Draft {
        return Err(refused("proposal-not-draft"));
    }
    let body = transition.body(&current)?;
    let prepared = client
        .prepare_proposal(&current, transition.operation(), body, &key)
        .map_err(|error| failure(error, false))?;
    let wrapper = PreparedTransition {
        version: 1,
        request_digest: request_digest(request)?,
        transition,
        owner_preparation: std::str::from_utf8(prepared.as_bytes())
            .map_err(|_| refused("invalid-command"))?
            .to_owned(),
    };
    serde_json::to_vec(&wrapper).map_err(|_| refused("invalid-command"))
}

/// Recover only the protected original command under fresh ordinary authority.
/// A status read never substitutes for executing the receiver's exact replay.
pub async fn execute(
    client: &BaseRegistryClient,
    profile: &str,
    request: &CallRequest,
    prepared: &[u8],
    transition: Transition,
) -> CallOutcome {
    let digest = match request_digest(request) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let wrapper: PreparedTransition =
        match registry_platform_canonical_json::parse_json_strict(prepared)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
        {
            Some(value) => value,
            None => return refused("invalid-command"),
        };
    if wrapper.version != 1
        || wrapper.transition != transition
        || wrapper.request_digest != digest
        || request.operation != transition.coordinator_operation()
    {
        return refused("prepared-command-mismatch");
    }
    let expected = match proposal(&request.input) {
        Ok(value) => value,
        Err(error) => return error,
    };
    let prepared = match BRegPreparedProposal::from_slice(wrapper.owner_preparation.as_bytes()) {
        Ok(value) => value,
        Err(_) => return refused("invalid-command"),
    };
    let current = match current(client, profile, &expected).await {
        Ok(value) => value,
        Err(error) => return error,
    };
    // Reconstruct the client preparation from the original resource only when
    // still current. After a possible dispatch, the client's exact recovery
    // accepts a retained receipt transition without replacing its condition.
    if expected.id() != current.id()
        || expected.action_id() != current.action_id()
        || expected.action_revision() != current.action_revision()
        || expected.submission_version() != current.submission_version()
        || transition != Transition::Submit && expected.effect_digest() != current.effect_digest()
    {
        return refused("submission-stale");
    }
    let restored = match client.recover_proposal(&current, &prepared) {
        Ok(value) => value,
        Err(_) => return refused("prepared-command-mismatch"),
    };
    match client.execute_proposal(&restored).await {
        Ok(answer) => {
            let answer = answer.value;
            if answer.id() != expected.id()
                || answer.action_id() != expected.action_id()
                || answer.action_revision() != expected.action_revision()
                || answer.submission_version() != expected.submission_version()
                // Submit creates the frozen digest. Every later transition
                // must retain it; cancelling an unfrozen draft retains None.
                || transition != Transition::Submit
                    && answer.effect_digest() != expected.effect_digest()
                || transition == Transition::Submit
                    && (answer.state() == BRegProposalState::Draft
                        || answer.effect_digest().is_none())
            {
                return CallOutcome::Uncertain {
                    code: "proposal-binding-mismatch".into(),
                };
            }
            match serde_json::to_value(answer) {
                Ok(value) => CallOutcome::Success(value),
                Err(_) => CallOutcome::Uncertain {
                    code: "invalid-response".into(),
                },
            }
        }
        // The current client reports a malformed successful Proposal body as
        // InvalidRequest. After the validated prepared dispatch it is evidence
        // of an unreadable outcome, never proof the mutation was refused.
        Err(registry_breg_client::BaseRegistryClientError::InvalidRequest { .. }) => {
            CallOutcome::Uncertain {
                code: "invalid-response".into(),
            }
        }
        Err(error) => match failure(error, true) {
            // Submit evaluates the Action's plan. The generic lifecycle
            // Operation has no Action-specific refusal schema, but the owner's
            // validated no-effect response is still a known refusal.
            CallOutcome::DeclaredRefusal(_) => refused("action-refused"),
            outcome => outcome,
        },
    }
}

pub async fn observe_application(
    client: &BaseRegistryClient,
    profile: &str,
    accepted: &Value,
) -> ApplicationObservation {
    let expected = match proposal(accepted) {
        Ok(value)
            if value.submission_version() > 0
                && value.effect_digest().is_some()
                && matches!(
                    value.state(),
                    BRegProposalState::Submitted | BRegProposalState::Applied
                ) =>
        {
            value
        }
        _ => {
            return ApplicationObservation::Hold {
                code: "submission-missing".into(),
            };
        }
    };
    let metadata_observation = client.registry_contract_observation(Some(profile)).await;
    let metadata_retry_after = match metadata_observation.retry_after {
        BRegRetryAfter::Absent => None,
        BRegRetryAfter::Seconds(seconds) => Some(Duration::from_secs(seconds)),
        BRegRetryAfter::Unusable => {
            return ApplicationObservation::Hold {
                code: "observation-backoff-unusable".into(),
            };
        }
    };
    let metadata = match metadata_observation.outcome {
        Ok(value) => value,
        Err(error) => {
            return match failure(error, false) {
                CallOutcome::Retryable { code, .. } => ApplicationObservation::Retryable {
                    code,
                    retry_after: metadata_retry_after,
                },
                _ => ApplicationObservation::Hold {
                    code: "proposal-not-visible".into(),
                },
            };
        }
    };
    let binding = match metadata.value.select_proposal_get(profile) {
        Ok(value) => value,
        Err(_) => {
            return ApplicationObservation::Hold {
                code: "proposal-not-visible".into(),
            };
        }
    };
    let observation = client
        .get_proposal_observation(&binding, expected.id())
        .await;
    let retry_after = match observation.retry_after {
        BRegRetryAfter::Absent => metadata_retry_after,
        BRegRetryAfter::Seconds(seconds) => {
            Some(Duration::from_secs(seconds)).max(metadata_retry_after)
        }
        BRegRetryAfter::Unusable => {
            return ApplicationObservation::Hold {
                code: "observation-backoff-unusable".into(),
            };
        }
    };
    let current = match observation.outcome.map_err(|error| failure(error, false)) {
        Ok(value) => value.value,
        Err(CallOutcome::Retryable { code, .. }) => {
            return ApplicationObservation::Retryable { code, retry_after };
        }
        Err(_) => {
            return ApplicationObservation::Hold {
                code: "proposal-not-visible".into(),
            };
        }
    };
    let current = match serde_json::to_value(current) {
        Ok(value) => value,
        Err(_) => {
            return ApplicationObservation::Hold {
                code: "invalid-response".into(),
            };
        }
    };
    match classify_application(accepted, &current) {
        ApplicationObservation::Pending { .. } => ApplicationObservation::Pending { retry_after },
        outcome => outcome,
    }
}

/// Shared typed classifier for native observations and deterministic scenarios.
/// It trusts no signal payload and never performs a status read for a command
/// whose accepted frozen submission has not been retained.
pub(crate) fn classify_application(accepted: &Value, current: &Value) -> ApplicationObservation {
    let expected = match proposal(accepted) {
        Ok(value)
            if value.submission_version() > 0
                && value.effect_digest().is_some()
                && matches!(
                    value.state(),
                    BRegProposalState::Submitted | BRegProposalState::Applied
                ) =>
        {
            value
        }
        _ => {
            return ApplicationObservation::Hold {
                code: "submission-missing".into(),
            };
        }
    };
    let current = match proposal(current) {
        Ok(value) => value,
        Err(_) => {
            return ApplicationObservation::Hold {
                code: "invalid-response".into(),
            };
        }
    };
    if !same_submission(&expected, &current) {
        return ApplicationObservation::Hold {
            code: "submission-stale".into(),
        };
    }
    match current.state() {
        BRegProposalState::Applied => {
            let Some(evidence) = current.application() else {
                return ApplicationObservation::Hold {
                    code: "application-evidence-missing".into(),
                };
            };
            if evidence.submission_version != expected.submission_version()
                || Some(evidence.effect_digest.as_str()) != expected.effect_digest()
            {
                return ApplicationObservation::Hold {
                    code: "application-binding-mismatch".into(),
                };
            }
            match serde_json::to_value(current) {
                Ok(value) => {
                    ApplicationObservation::Complete(json!({"outcome":"applied","proposal":value}))
                }
                Err(_) => ApplicationObservation::Hold {
                    code: "invalid-response".into(),
                },
            }
        }
        BRegProposalState::Cancelled => match serde_json::to_value(current) {
            Ok(value) => {
                ApplicationObservation::Complete(json!({"outcome":"closed","proposal":value}))
            }
            Err(_) => ApplicationObservation::Hold {
                code: "invalid-response".into(),
            },
        },
        BRegProposalState::Submitted
            if current
                .application_status()
                .is_some_and(|status| status.state == BRegProposalApplicationState::Blocked) =>
        {
            use BRegProposalApplicationReason::*;
            let code = match current
                .application_status()
                .and_then(|status| status.reason)
            {
                Some(ContractChanged) => "proposal-contract-changed",
                Some(DependencyOutage) => "proposal-dependency-outage",
                Some(LeaseExpired) => "proposal-lease-expired",
                Some(ApplicationRefused) => "proposal-application-refused",
                Some(AttemptsExhausted) => "proposal-attempts-exhausted",
                None => "proposal-blocked",
            };
            ApplicationObservation::Hold { code: code.into() }
        }
        BRegProposalState::Submitted if current.blocked_reason().is_some() => {
            ApplicationObservation::Hold {
                code: "proposal-blocked".into(),
            }
        }
        BRegProposalState::Submitted => ApplicationObservation::Pending { retry_after: None },
        BRegProposalState::Draft => ApplicationObservation::Hold {
            code: "submission-stale".into(),
        },
    }
}
