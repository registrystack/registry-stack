use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use registry_review_protocol::{ContentDigest, ReviewResultStatus, SubjectBinding};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    ClockPolicy, HostedDecisionRequest, HostedKindPolicy, HostedKindPolicySnapshot,
    HostedOutcomePolicy, HostedPolicyError, HostedRetentionPolicy, HostedValidationError,
    IssuerPrincipal,
};

pub const MAXIMUM_REVIEW_STAGES: usize = 32;
pub const MAXIMUM_REVIEW_PROFILES_PER_STAGE: usize = 32;
pub const MAXIMUM_REVIEW_APPROVALS_PER_STAGE: u16 = 32;

pub type ReviewRetentionPolicy = HostedRetentionPolicy;
pub type ReviewPolicyDigest = ContentDigest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewClockCorrelation {
    Subject {
        source: String,
        subject_type: String,
        id: String,
    },
    Activity {
        task_id: Uuid,
        stage_id: String,
    },
}

impl ReviewClockCorrelation {
    #[must_use]
    pub fn for_policy(
        policy: &ClockPolicy,
        subject: &SubjectBinding,
        task_id: Uuid,
        stage_id: &str,
    ) -> Self {
        match policy {
            ClockPolicy::Subject { .. } => Self::Subject {
                source: subject.source.clone(),
                subject_type: subject.subject_type.clone(),
                id: subject.id.clone(),
            },
            ClockPolicy::Activity { .. } => Self::Activity {
                task_id,
                stage_id: stage_id.to_owned(),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKindPurpose {
    Approval,
    Answer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewContextStrategy {
    Submitted,
    Source,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewOutcomeSettlement {
    Rejected,
    ChangesRequested,
    Answered,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewOutcomePolicy {
    pub id: String,
    pub label: String,
    pub settlement: ReviewOutcomeSettlement,
    pub reason_required: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub result_required: bool,
}

impl ReviewOutcomePolicy {
    fn hosted(&self) -> HostedOutcomePolicy {
        HostedOutcomePolicy {
            id: self.id.clone(),
            label: self.label.clone(),
            reason_required: self.reason_required,
            result_required: self.result_required,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewStagePolicy {
    pub id: String,
    pub queue: String,
    pub deciding_profiles: Vec<String>,
    pub required_approvals: u16,
    #[serde(default)]
    pub exclude_initiator: bool,
    #[serde(default)]
    pub exclude_previous_stage_reviewers: bool,
}

impl ReviewStagePolicy {
    fn check(&self) -> Result<(), ReviewPolicyError> {
        if !valid_identifier(&self.id)
            || !valid_identifier(&self.queue)
            || self.deciding_profiles.is_empty()
            || self.deciding_profiles.len() > MAXIMUM_REVIEW_PROFILES_PER_STAGE
            || !all_unique(self.deciding_profiles.iter().map(String::as_str))
            || self
                .deciding_profiles
                .iter()
                .any(|profile| !valid_identifier(profile))
        {
            return Err(ReviewPolicyError::StageIdentity);
        }
        if self.required_approvals == 0
            || self.required_approvals > MAXIMUM_REVIEW_APPROVALS_PER_STAGE
        {
            return Err(ReviewPolicyError::StageThreshold);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewKindPolicy {
    pub id: String,
    pub version: String,
    pub purpose: ReviewKindPurpose,
    pub context_strategy: ReviewContextStrategy,
    pub stages: Vec<ReviewStagePolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clocks: Vec<String>,
    pub retention: ReviewRetentionPolicy,
    pub display_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<ReviewOutcomePolicy>,
}

impl ReviewKindPolicy {
    pub fn check(&self) -> Result<(), ReviewPolicyError> {
        if self.stages.is_empty() || self.stages.len() > MAXIMUM_REVIEW_STAGES {
            return Err(ReviewPolicyError::Stages);
        }
        if !all_unique(self.stages.iter().map(|stage| stage.id.as_str())) {
            return Err(ReviewPolicyError::StageIdentity);
        }
        if self.clocks.len() > 32
            || !all_unique(self.clocks.iter().map(String::as_str))
            || self.clocks.iter().any(|clock| !valid_identifier(clock))
        {
            return Err(ReviewPolicyError::ClockIdentity);
        }
        for stage in &self.stages {
            stage.check()?;
        }

        match self.purpose {
            ReviewKindPurpose::Approval => {
                if self
                    .outcomes
                    .iter()
                    .any(|outcome| outcome.settlement == ReviewOutcomeSettlement::Answered)
                {
                    return Err(ReviewPolicyError::ApprovalPayload);
                }
            }
            ReviewKindPurpose::Answer => {
                if self.stages.len() != 1 || self.stages[0].required_approvals != 1 {
                    return Err(ReviewPolicyError::AnswerStages);
                }
                if self.outcomes.is_empty()
                    || self
                        .outcomes
                        .iter()
                        .any(|outcome| outcome.settlement != ReviewOutcomeSettlement::Answered)
                {
                    return Err(ReviewPolicyError::AnswerOutcomes);
                }
            }
        }

        self.hosted_validation_policy().check()?;
        Ok(())
    }

    pub fn policy_digest(&self) -> Result<ReviewPolicyDigest, ReviewPolicyError> {
        self.check()?;
        let value = json!({
            "schema": "registry-casework-review-kind-policy/v1",
            "policy": self,
        });
        let canonical = registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| ReviewPolicyError::Canonical)?;
        Ok(ContentDigest::for_bytes(&canonical))
    }

    pub fn snapshot(&self) -> Result<ReviewKindPolicySnapshot, ReviewPolicyError> {
        Ok(ReviewKindPolicySnapshot {
            identity: ReviewPolicyIdentity {
                id: self.id.clone(),
                version: self.version.clone(),
                digest: self.policy_digest()?,
            },
            purpose: self.purpose,
            context_strategy: self.context_strategy,
            stages: self.stages.clone(),
            clocks: self.clocks.clone(),
            retention: self.retention.clone(),
            display_schema: self.display_schema.clone(),
            result_schema: self.result_schema.clone(),
            outcomes: self.outcomes.clone(),
        })
    }

    fn hosted_validation_policy(&self) -> HostedKindPolicy {
        let stage = &self.stages[0];
        HostedKindPolicy {
            id: self.id.clone(),
            version: self.version.clone(),
            queue: stage.queue.clone(),
            deciding_profiles: stage.deciding_profiles.clone(),
            retention: self.retention.clone(),
            display_schema: self.display_schema.clone(),
            result_schema: self.result_schema.clone(),
            outcomes: if self.outcomes.is_empty() {
                vec![HostedOutcomePolicy {
                    id: "approval".to_owned(),
                    label: "Approval".to_owned(),
                    reason_required: false,
                    result_required: false,
                }]
            } else {
                self.outcomes
                    .iter()
                    .map(ReviewOutcomePolicy::hosted)
                    .collect()
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewPolicyIdentity {
    pub id: String,
    pub version: String,
    pub digest: ReviewPolicyDigest,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewKindPolicySnapshot {
    pub identity: ReviewPolicyIdentity,
    pub purpose: ReviewKindPurpose,
    pub context_strategy: ReviewContextStrategy,
    pub stages: Vec<ReviewStagePolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clocks: Vec<String>,
    pub retention: ReviewRetentionPolicy,
    pub display_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_schema: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outcomes: Vec<ReviewOutcomePolicy>,
}

impl ReviewKindPolicySnapshot {
    pub fn verify(&self) -> Result<(), ReviewPolicyError> {
        let policy = self.as_policy();
        if policy.policy_digest()? != self.identity.digest {
            return Err(ReviewPolicyError::DigestMismatch);
        }
        Ok(())
    }

    pub fn validate_display(&self, display: &Value) -> Result<(), ReviewValidationError> {
        self.verify()?;
        self.hosted_snapshot()?.validate_display(display)?;
        Ok(())
    }

    pub fn validate_result_constraints(
        &self,
        constraints: &Value,
    ) -> Result<(), ReviewValidationError> {
        self.verify()?;
        self.hosted_snapshot()?
            .validate_result_constraints(constraints)?;
        Ok(())
    }

    fn validate_outcome(
        &self,
        outcome: &str,
        reason: Option<&str>,
        result: Option<&Value>,
        constraints: Option<&Value>,
    ) -> Result<(), ReviewValidationError> {
        self.verify()?;
        HostedDecisionRequest {
            outcome: outcome.to_owned(),
            reason: reason.map(str::to_owned),
            result: result.cloned(),
        }
        .check(&self.hosted_snapshot()?, constraints)?;
        Ok(())
    }

    fn as_policy(&self) -> ReviewKindPolicy {
        ReviewKindPolicy {
            id: self.identity.id.clone(),
            version: self.identity.version.clone(),
            purpose: self.purpose,
            context_strategy: self.context_strategy,
            stages: self.stages.clone(),
            clocks: self.clocks.clone(),
            retention: self.retention.clone(),
            display_schema: self.display_schema.clone(),
            result_schema: self.result_schema.clone(),
            outcomes: self.outcomes.clone(),
        }
    }

    fn hosted_snapshot(&self) -> Result<HostedKindPolicySnapshot, ReviewPolicyError> {
        self.as_policy()
            .hosted_validation_policy()
            .snapshot()
            .map_err(ReviewPolicyError::from)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerTaskState {
    Open,
    Held { holder: IssuerPrincipal },
    Decided,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewerTask {
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub stage_index: u16,
    pub stage_id: String,
    pub queue: String,
    pub revision: i64,
    pub eligible_profiles: Vec<String>,
    pub state: ReviewerTaskState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskPage {
    pub items: Vec<ReviewerTask>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewHistoryPage {
    pub items: Vec<ReviewHistoryEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskDraftInput {
    pub body: Value,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskDraft {
    pub task_id: Uuid,
    pub author: IssuerPrincipal,
    pub body: Value,
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewHistoryAudience {
    Reviewers,
    Requester,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewNoteRequest {
    pub audience: ReviewHistoryAudience,
    pub note: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewHistoryEntry {
    pub event_id: Uuid,
    pub request_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<Uuid>,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_ref: Option<String>,
    #[serde(default)]
    pub detail: Value,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewAccountabilityRecord {
    pub event_id: Uuid,
    pub request_id: Uuid,
    pub task_id: Uuid,
    pub actor_ref: String,
    pub actor: IssuerPrincipal,
    pub profile_id: String,
    pub decision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_digest: Option<String>,
    pub occurred_at: DateTime<Utc>,
    pub retained_until: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewerDecisionKind {
    Approve,
    Reject {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
    ChangesRequested {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
    Answer {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewerDecision {
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub stage_id: String,
    pub reviewer: IssuerPrincipal,
    pub profile_id: String,
    pub decision: ReviewerDecisionKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewSettlement {
    Approved,
    Rejected {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
    ChangesRequested {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
    Answered {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<Value>,
    },
}

impl ReviewSettlement {
    #[must_use]
    pub fn result_status(&self) -> ReviewResultStatus {
        match self {
            Self::Approved => ReviewResultStatus::Approved,
            Self::Rejected { .. } => ReviewResultStatus::Rejected,
            Self::ChangesRequested { .. } => ReviewResultStatus::ChangesRequested,
            Self::Answered { .. } => ReviewResultStatus::Answered,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewProgress {
    pub request_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiator: Option<IssuerPrincipal>,
    pub active_stage: u16,
    #[serde(default)]
    pub decisions: Vec<ReviewerDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_constraints: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement: Option<ReviewSettlement>,
}

impl ReviewProgress {
    pub fn new(
        request_id: Uuid,
        initiator: Option<IssuerPrincipal>,
        result_constraints: Option<Value>,
        policy: &ReviewKindPolicySnapshot,
    ) -> Result<Self, ReviewValidationError> {
        policy.verify()?;
        if let Some(constraints) = &result_constraints {
            policy.validate_result_constraints(constraints)?;
        }
        Ok(Self {
            request_id,
            initiator,
            active_stage: 0,
            decisions: Vec::new(),
            result_constraints,
            settlement: None,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReviewTransition {
    Recorded {
        remaining_approvals: u16,
    },
    StageAdvanced {
        completed_stage: String,
        next_stage: String,
    },
    Settled {
        settlement: ReviewSettlement,
    },
}

pub fn record_review_decision(
    policy: &ReviewKindPolicySnapshot,
    progress: &mut ReviewProgress,
    task: &ReviewerTask,
    decision: ReviewerDecision,
) -> Result<ReviewTransition, ReviewDecisionError> {
    policy.verify()?;
    if progress.settlement.is_some() {
        return Err(ReviewDecisionError::AlreadySettled);
    }
    let stage = policy
        .stages
        .get(usize::from(progress.active_stage))
        .ok_or(ReviewDecisionError::StageMismatch)?;
    if progress.request_id != task.request_id || progress.request_id != decision.request_id {
        return Err(ReviewDecisionError::RequestMismatch);
    }
    if task.stage_index != progress.active_stage
        || task.stage_id != stage.id
        || decision.stage_id != stage.id
        || decision.task_id != task.task_id
    {
        return Err(ReviewDecisionError::StageMismatch);
    }
    match &task.state {
        ReviewerTaskState::Open => return Err(ReviewDecisionError::TaskNotHeld),
        ReviewerTaskState::Held { holder } if *holder == decision.reviewer => {}
        ReviewerTaskState::Held { .. } => return Err(ReviewDecisionError::HolderMismatch),
        ReviewerTaskState::Decided => return Err(ReviewDecisionError::TaskAlreadyDecided),
    }
    if !stage
        .deciding_profiles
        .iter()
        .any(|profile| profile == &decision.profile_id)
        || !task
            .eligible_profiles
            .iter()
            .any(|profile| profile == &decision.profile_id)
    {
        return Err(ReviewDecisionError::ProfileNotEligible);
    }
    if progress
        .decisions
        .iter()
        .any(|recorded| recorded.task_id == decision.task_id)
    {
        return Err(ReviewDecisionError::TaskAlreadyDecided);
    }
    if progress
        .decisions
        .iter()
        .any(|recorded| recorded.stage_id == stage.id && recorded.reviewer == decision.reviewer)
    {
        return Err(ReviewDecisionError::DuplicateReviewer);
    }
    if stage.exclude_initiator
        && progress
            .initiator
            .as_ref()
            .is_some_and(|initiator| *initiator == decision.reviewer)
    {
        return Err(ReviewDecisionError::InitiatorExcluded);
    }
    if stage.exclude_previous_stage_reviewers
        && progress
            .decisions
            .iter()
            .any(|recorded| recorded.stage_id != stage.id && recorded.reviewer == decision.reviewer)
    {
        return Err(ReviewDecisionError::PreviousStageReviewerExcluded);
    }

    match (&policy.purpose, &decision.decision) {
        (ReviewKindPurpose::Approval, ReviewerDecisionKind::Approve) => {}
        (
            ReviewKindPurpose::Approval,
            ReviewerDecisionKind::Reject {
                outcome,
                reason,
                result,
            },
        ) => {
            validate_settlement_outcome(
                policy,
                ReviewOutcomeSettlement::Rejected,
                outcome,
                reason.as_deref(),
                result.as_ref(),
                progress.result_constraints.as_ref(),
            )?;
        }
        (
            ReviewKindPurpose::Approval,
            ReviewerDecisionKind::ChangesRequested {
                outcome,
                reason,
                result,
            },
        ) => {
            validate_settlement_outcome(
                policy,
                ReviewOutcomeSettlement::ChangesRequested,
                outcome,
                reason.as_deref(),
                result.as_ref(),
                progress.result_constraints.as_ref(),
            )?;
        }
        (
            ReviewKindPurpose::Answer,
            ReviewerDecisionKind::Answer {
                outcome,
                reason,
                result,
            },
        ) => validate_settlement_outcome(
            policy,
            ReviewOutcomeSettlement::Answered,
            outcome,
            reason.as_deref(),
            result.as_ref(),
            progress.result_constraints.as_ref(),
        )?,
        _ => return Err(ReviewDecisionError::DecisionNotAllowed),
    }

    let settlement = match &decision.decision {
        ReviewerDecisionKind::Reject {
            outcome, result, ..
        } => Some(ReviewSettlement::Rejected {
            outcome: outcome.clone(),
            result: result.clone(),
        }),
        ReviewerDecisionKind::ChangesRequested {
            outcome, result, ..
        } => Some(ReviewSettlement::ChangesRequested {
            outcome: outcome.clone(),
            result: result.clone(),
        }),
        ReviewerDecisionKind::Answer {
            outcome, result, ..
        } => Some(ReviewSettlement::Answered {
            outcome: outcome.clone(),
            result: result.clone(),
        }),
        ReviewerDecisionKind::Approve => None,
    };

    progress.decisions.push(decision);
    if let Some(settlement) = settlement {
        progress.settlement = Some(settlement.clone());
        return Ok(ReviewTransition::Settled { settlement });
    }

    let approvals = progress
        .decisions
        .iter()
        .filter(|decision| {
            decision.stage_id == stage.id
                && matches!(&decision.decision, ReviewerDecisionKind::Approve)
        })
        .count();
    let approvals = u16::try_from(approvals).expect("review approval count is policy bounded");
    if approvals < stage.required_approvals {
        return Ok(ReviewTransition::Recorded {
            remaining_approvals: stage.required_approvals - approvals,
        });
    }

    if usize::from(progress.active_stage) + 1 == policy.stages.len() {
        let settlement = ReviewSettlement::Approved;
        progress.settlement = Some(settlement.clone());
        Ok(ReviewTransition::Settled { settlement })
    } else {
        let completed_stage = stage.id.clone();
        progress.active_stage += 1;
        Ok(ReviewTransition::StageAdvanced {
            completed_stage,
            next_stage: policy.stages[usize::from(progress.active_stage)].id.clone(),
        })
    }
}

fn validate_settlement_outcome(
    policy: &ReviewKindPolicySnapshot,
    expected: ReviewOutcomeSettlement,
    outcome: &str,
    reason: Option<&str>,
    result: Option<&Value>,
    constraints: Option<&Value>,
) -> Result<(), ReviewDecisionError> {
    if policy
        .outcomes
        .iter()
        .find(|candidate| candidate.id == outcome)
        .is_none_or(|candidate| candidate.settlement != expected)
    {
        return Err(ReviewDecisionError::DecisionNotAllowed);
    }
    policy.validate_outcome(outcome, reason, result, constraints)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReviewPolicyError {
    #[error("a review policy must declare one to thirty-two ordered stages")]
    Stages,
    #[error("review stage identifiers, queues, or deciding profiles are invalid")]
    StageIdentity,
    #[error("review clock identifiers must be unique and bounded")]
    ClockIdentity,
    #[error("review stage approval counts must be positive and bounded")]
    StageThreshold,
    #[error("approval policies can declare only rejected or changes-requested outcomes")]
    ApprovalPayload,
    #[error("answer policies require exactly one single-decision stage")]
    AnswerStages,
    #[error("answer policies can declare only answered outcomes")]
    AnswerOutcomes,
    #[error("the review policy could not be canonically encoded")]
    Canonical,
    #[error("the review policy snapshot digest does not match its contents")]
    DigestMismatch,
    #[error("the shared structured policy is invalid: {0}")]
    Hosted(#[from] HostedPolicyError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReviewValidationError {
    #[error(transparent)]
    Policy(#[from] ReviewPolicyError),
    #[error(transparent)]
    Structured(#[from] HostedValidationError),
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReviewDecisionError {
    #[error(transparent)]
    Policy(#[from] ReviewPolicyError),
    #[error(transparent)]
    Validation(#[from] ReviewValidationError),
    #[error("the review request is already settled")]
    AlreadySettled,
    #[error("the task and decision do not belong to this request")]
    RequestMismatch,
    #[error("the task and decision do not belong to the active stage")]
    StageMismatch,
    #[error("the task was already decided")]
    TaskAlreadyDecided,
    #[error("the task must be held before it can be decided")]
    TaskNotHeld,
    #[error("only the task holder may decide a held task")]
    HolderMismatch,
    #[error("the selected profile is not eligible for this task and stage")]
    ProfileNotEligible,
    #[error("one person cannot decide twice in the same stage")]
    DuplicateReviewer,
    #[error("the request initiator is excluded from this stage")]
    InitiatorExcluded,
    #[error("a reviewer from an earlier stage is excluded from this stage")]
    PreviousStageReviewerExcluded,
    #[error("the decision is not valid for this review kind")]
    DecisionNotAllowed,
    #[error("rejection and changes-requested reasons must be bounded non-empty text")]
    ReasonInvalid,
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_lowercase()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn all_unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().all(|value| seen.insert(value))
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(subject: &str) -> IssuerPrincipal {
        IssuerPrincipal {
            issuer: "https://issuer.example".to_owned(),
            subject: subject.to_owned(),
        }
    }

    fn stage(id: &str, required_approvals: u16) -> ReviewStagePolicy {
        ReviewStagePolicy {
            id: id.to_owned(),
            queue: "review".to_owned(),
            deciding_profiles: vec!["reviewer".to_owned()],
            required_approvals,
            exclude_initiator: true,
            exclude_previous_stage_reviewers: true,
        }
    }

    fn approval_policy(stages: Vec<ReviewStagePolicy>) -> ReviewKindPolicy {
        ReviewKindPolicy {
            id: "registry-correction".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewKindPurpose::Approval,
            context_strategy: ReviewContextStrategy::Source,
            stages,
            clocks: Vec::new(),
            retention: HostedRetentionPolicy {
                terminal_days: 90,
                accountability_days: 365,
            },
            display_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["summary"],
                "properties": {"summary": {"type": "string", "maxLength": 160}}
            }),
            result_schema: None,
            outcomes: vec![
                ReviewOutcomePolicy {
                    id: "rejected".to_owned(),
                    label: "Reject".to_owned(),
                    settlement: ReviewOutcomeSettlement::Rejected,
                    reason_required: true,
                    result_required: false,
                },
                ReviewOutcomePolicy {
                    id: "changes-requested".to_owned(),
                    label: "Request changes".to_owned(),
                    settlement: ReviewOutcomeSettlement::ChangesRequested,
                    reason_required: true,
                    result_required: false,
                },
            ],
        }
    }

    fn answer_policy() -> ReviewKindPolicy {
        ReviewKindPolicy {
            id: "standalone-question".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewKindPurpose::Answer,
            context_strategy: ReviewContextStrategy::Submitted,
            stages: vec![stage("answer", 1)],
            clocks: Vec::new(),
            retention: HostedRetentionPolicy {
                terminal_days: 90,
                accountability_days: 365,
            },
            display_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["question"],
                "properties": {"question": {"type": "string", "maxLength": 160}}
            }),
            result_schema: Some(json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["code"],
                "properties": {"code": {"type": "integer", "minimum": 1, "maximum": 9}}
            })),
            outcomes: vec![ReviewOutcomePolicy {
                id: "approved".to_owned(),
                label: "Record answer".to_owned(),
                settlement: ReviewOutcomeSettlement::Answered,
                reason_required: false,
                result_required: true,
            }],
        }
    }

    fn task(
        request_id: Uuid,
        stage_index: u16,
        stage_id: &str,
        nonce: u128,
        holder: &str,
    ) -> ReviewerTask {
        ReviewerTask {
            task_id: Uuid::from_u128(nonce),
            request_id,
            stage_index,
            stage_id: stage_id.to_owned(),
            queue: "review".to_owned(),
            revision: 1,
            eligible_profiles: vec!["reviewer".to_owned()],
            state: ReviewerTaskState::Held {
                holder: person(holder),
            },
        }
    }

    fn approve(task: &ReviewerTask, reviewer: IssuerPrincipal) -> ReviewerDecision {
        ReviewerDecision {
            task_id: task.task_id,
            request_id: task.request_id,
            stage_id: task.stage_id.clone(),
            reviewer,
            profile_id: "reviewer".to_owned(),
            decision: ReviewerDecisionKind::Approve,
        }
    }

    #[test]
    fn stage_thresholds_are_independent_and_ordered() {
        let snapshot = approval_policy(vec![stage("technical", 2), stage("authority", 1)])
            .snapshot()
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let first = task(request_id, 0, "technical", 1, "a");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &first,
                approve(&first, person("a"))
            )
            .unwrap(),
            ReviewTransition::Recorded {
                remaining_approvals: 1
            }
        );
        let second = task(request_id, 0, "technical", 2, "b");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &second,
                approve(&second, person("b"))
            )
            .unwrap(),
            ReviewTransition::StageAdvanced {
                completed_stage: "technical".to_owned(),
                next_stage: "authority".to_owned(),
            }
        );
        assert!(progress.settlement.is_none());
        let third = task(request_id, 1, "authority", 3, "c");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &third,
                approve(&third, person("c"))
            )
            .unwrap(),
            ReviewTransition::Settled {
                settlement: ReviewSettlement::Approved
            }
        );
    }

    #[test]
    fn duplicate_initiator_and_previous_stage_reviewers_are_refused() {
        let snapshot = approval_policy(vec![stage("first", 2), stage("second", 1)])
            .snapshot()
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let initiator = person("initiator");
        let mut progress =
            ReviewProgress::new(request_id, Some(initiator.clone()), None, &snapshot).unwrap();
        let initiator_task = task(request_id, 0, "first", 1, "initiator");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &initiator_task,
                approve(&initiator_task, initiator)
            ),
            Err(ReviewDecisionError::InitiatorExcluded)
        );
        let first = task(request_id, 0, "first", 2, "a");
        record_review_decision(
            &snapshot,
            &mut progress,
            &first,
            approve(&first, person("a")),
        )
        .unwrap();
        let duplicate = task(request_id, 0, "first", 3, "a");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &duplicate,
                approve(&duplicate, person("a"))
            ),
            Err(ReviewDecisionError::DuplicateReviewer)
        );
        let completing = task(request_id, 0, "first", 4, "b");
        record_review_decision(
            &snapshot,
            &mut progress,
            &completing,
            approve(&completing, person("b")),
        )
        .unwrap();
        let prior = task(request_id, 1, "second", 5, "a");
        assert_eq!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &prior,
                approve(&prior, person("a"))
            ),
            Err(ReviewDecisionError::PreviousStageReviewerExcluded)
        );
    }

    #[test]
    fn empty_or_zero_count_stages_are_refused_and_insufficient_staffing_stays_open() {
        assert_eq!(
            approval_policy(vec![]).check(),
            Err(ReviewPolicyError::Stages)
        );
        assert_eq!(
            approval_policy(vec![stage("invalid", 0)]).check(),
            Err(ReviewPolicyError::StageThreshold)
        );

        let snapshot = approval_policy(vec![stage("only", 2)]).snapshot().unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let only_staffed_task = task(request_id, 0, "only", 1, "sole-reviewer");
        assert!(matches!(
            record_review_decision(
                &snapshot,
                &mut progress,
                &only_staffed_task,
                approve(&only_staffed_task, person("sole-reviewer"))
            ),
            Ok(ReviewTransition::Recorded {
                remaining_approvals: 1
            })
        ));
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn policy_snapshot_digest_pins_every_stage_rule() {
        let mut snapshot = approval_policy(vec![stage("first", 1)]).snapshot().unwrap();
        assert_eq!(
            serde_json::to_value(&snapshot.identity).unwrap(),
            json!({
                "id": "registry-correction",
                "version": "1",
                "digest": snapshot.identity.digest.clone(),
            })
        );
        snapshot.stages[0].exclude_initiator = false;
        assert_eq!(snapshot.verify(), Err(ReviewPolicyError::DigestMismatch));

        let mut context_snapshot = approval_policy(vec![stage("first", 1)]).snapshot().unwrap();
        context_snapshot.context_strategy = ReviewContextStrategy::Submitted;
        assert_eq!(
            context_snapshot.verify(),
            Err(ReviewPolicyError::DigestMismatch)
        );

        let mut clock_snapshot = approval_policy(vec![stage("first", 1)]).snapshot().unwrap();
        clock_snapshot.clocks.push("response-deadline".to_owned());
        assert_eq!(
            clock_snapshot.verify(),
            Err(ReviewPolicyError::DigestMismatch)
        );
    }

    #[test]
    fn subject_clock_correlation_survives_new_review_rounds_but_activity_does_not() {
        let clock = ClockPolicy::Subject {
            id: "response-budget".to_owned(),
            anchor: crate::SubjectClockAnchor::FirstSubmittedAt,
            complete_on: crate::SubjectClockCompletion::ReviewCompleted,
            after: crate::ElapsedDuration {
                elapsed: "PT1H".to_owned(),
            },
            pause_while: vec![crate::SubjectClockPause::AwaitingApplicant],
        };
        let first = SubjectBinding {
            source: "registry".to_owned(),
            subject_type: "record".to_owned(),
            id: "record-1".to_owned(),
            version: "1".to_owned(),
            digest: ContentDigest::for_bytes(b"one"),
        };
        let mut next = first.clone();
        next.version = "2".to_owned();
        next.digest = ContentDigest::for_bytes(b"two");
        let first_request = Uuid::from_u128(1);
        let next_request = Uuid::from_u128(2);

        assert_eq!(
            ReviewClockCorrelation::for_policy(&clock, &first, first_request, "review"),
            ReviewClockCorrelation::for_policy(&clock, &next, next_request, "review")
        );
        assert_ne!(
            ReviewClockCorrelation::Activity {
                task_id: first_request,
                stage_id: "review".to_owned(),
            },
            ReviewClockCorrelation::Activity {
                task_id: next_request,
                stage_id: "review".to_owned(),
            }
        );
    }

    #[test]
    fn an_open_task_cannot_be_decided_without_current_ownership() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .snapshot()
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let mut open_task = task(request_id, 0, "review", 1, "reviewer");
        open_task.state = ReviewerTaskState::Open;
        let decision = approve(&open_task, person("reviewer"));

        assert_eq!(
            record_review_decision(&snapshot, &mut progress, &open_task, decision),
            Err(ReviewDecisionError::TaskNotHeld)
        );
        assert!(progress.decisions.is_empty());
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn custom_outcome_named_approved_settles_as_answered() {
        let snapshot = answer_policy().snapshot().unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let task = task(request_id, 0, "answer", 1, "answerer");
        let decision = ReviewerDecision {
            task_id: task.task_id,
            request_id,
            stage_id: "answer".to_owned(),
            reviewer: person("answerer"),
            profile_id: "reviewer".to_owned(),
            decision: ReviewerDecisionKind::Answer {
                outcome: "approved".to_owned(),
                reason: None,
                result: Some(json!({"code": 4})),
            },
        };
        let transition = record_review_decision(&snapshot, &mut progress, &task, decision).unwrap();
        assert_eq!(
            transition,
            ReviewTransition::Settled {
                settlement: ReviewSettlement::Answered {
                    outcome: "approved".to_owned(),
                    result: Some(json!({"code": 4})),
                }
            }
        );
        assert_eq!(
            progress.settlement.unwrap().result_status(),
            ReviewResultStatus::Answered
        );
    }

    #[test]
    fn structured_answers_reuse_required_result_and_schema_rules() {
        let snapshot = answer_policy().snapshot().unwrap();
        let request_id = Uuid::from_u128(100);

        let invalid_result = |result: Option<Value>| ReviewerDecision {
            task_id: Uuid::from_u128(1),
            request_id,
            stage_id: "answer".to_owned(),
            reviewer: person("answerer"),
            profile_id: "reviewer".to_owned(),
            decision: ReviewerDecisionKind::Answer {
                outcome: "approved".to_owned(),
                reason: None,
                result,
            },
        };
        let task = task(request_id, 0, "answer", 1, "answerer");

        for result in [None, Some(json!({"code": "four"}))] {
            let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
            assert!(matches!(
                record_review_decision(&snapshot, &mut progress, &task, invalid_result(result)),
                Err(ReviewDecisionError::Validation(
                    ReviewValidationError::Structured(_)
                ))
            ));
            assert!(progress.decisions.is_empty());
            assert!(progress.settlement.is_none());
        }

        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        assert!(record_review_decision(
            &snapshot,
            &mut progress,
            &task,
            invalid_result(Some(json!({"code": 4})))
        )
        .is_ok());
    }

    #[test]
    fn rejection_and_changes_requested_veto_without_waiting_for_threshold() {
        let snapshot = approval_policy(vec![stage("review", 3)])
            .snapshot()
            .unwrap();
        let request_id = Uuid::from_u128(100);
        for (decision_kind, expected) in [
            (
                ReviewerDecisionKind::Reject {
                    outcome: "rejected".to_owned(),
                    reason: Some("unsafe".to_owned()),
                    result: None,
                },
                ReviewSettlement::Rejected {
                    outcome: "rejected".to_owned(),
                    result: None,
                },
            ),
            (
                ReviewerDecisionKind::ChangesRequested {
                    outcome: "changes-requested".to_owned(),
                    reason: Some("correct target".to_owned()),
                    result: None,
                },
                ReviewSettlement::ChangesRequested {
                    outcome: "changes-requested".to_owned(),
                    result: None,
                },
            ),
        ] {
            let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
            let task = task(request_id, 0, "review", 1, "reviewer");
            let decision = ReviewerDecision {
                task_id: task.task_id,
                request_id,
                stage_id: "review".to_owned(),
                reviewer: person("reviewer"),
                profile_id: "reviewer".to_owned(),
                decision: decision_kind,
            };
            assert_eq!(
                record_review_decision(&snapshot, &mut progress, &task, decision),
                Ok(ReviewTransition::Settled {
                    settlement: expected
                })
            );
        }
    }

    #[test]
    fn answer_policies_require_a_configured_outcome() {
        let mut policy = answer_policy();
        policy.outcomes.clear();
        assert_eq!(policy.check(), Err(ReviewPolicyError::AnswerOutcomes));
    }
}
