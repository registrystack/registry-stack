use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AttemptState, IssuerPrincipal, OccurrenceState, OperationName};

/// Largest settlement reason, in UTF-8 bytes.
pub const MAXIMUM_SETTLEMENT_REASON_BYTES: usize = 2_000;
/// Largest settlement decider, in UTF-8 bytes.
pub const MAXIMUM_SETTLEMENT_DECIDED_BY_BYTES: usize = 256;

/// What an operator established about a source attempt whose outcome
/// Casework could not observe.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptSettlementOutcome {
    /// The source applied the attempt.
    Applied,
    /// The source did not apply the attempt.
    NotApplied,
}

/// An operator decision that settles one uncertain attempt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptSettlement {
    pub attempt_id: Uuid,
    pub outcome: AttemptSettlementOutcome,
    pub reason: String,
    pub decided_by: String,
}

/// Preview or report of one settlement. The states are the ones the attempt
/// and its item hold once the settlement is applied.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptSettlementReport {
    pub attempt_id: Uuid,
    pub item_id: Uuid,
    pub operation: OperationName,
    pub binding_reference: String,
    pub outcome: AttemptSettlementOutcome,
    pub reason: String,
    pub decided_by: String,
    pub attempt_state: AttemptState,
    pub item_state: OccurrenceState,
    pub applied: bool,
}

/// An operator decision that marks one pending attempt uncertain once its
/// execution lease has expired, so an attempt whose original actor can no
/// longer recover it can be settled.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptUncertainMarking {
    pub attempt_id: Uuid,
    pub reason: String,
    pub decided_by: String,
}

/// Preview or report of one uncertainty marking. The original actor and
/// profile are the ones that reserved the attempt; the states are the ones the
/// attempt and its item hold once the marking is applied.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptUncertainMarkingReport {
    pub attempt_id: Uuid,
    pub item_id: Uuid,
    pub operation: OperationName,
    pub binding_reference: String,
    pub original_actor: IssuerPrincipal,
    pub original_profile_id: String,
    pub reason: String,
    pub decided_by: String,
    pub attempt_state: AttemptState,
    pub item_state: OccurrenceState,
    pub applied: bool,
}
