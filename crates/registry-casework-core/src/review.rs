use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use chrono::{DateTime, Utc};
use jsonschema::{Draft, JSONSchema};
use registry_review_protocol::{ContentDigest, PolicyBinding, ReviewResultStatus, SubjectBinding};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use uuid::Uuid;

use crate::{ClockPolicy, IssuerPrincipal, SourceBinding};

pub const MAXIMUM_REVIEW_KINDS: usize = 64;
pub const MAXIMUM_REVIEW_RETENTION_DAYS: u32 = 3_650;
pub const MAXIMUM_REVIEW_STAGES: usize = 32;
pub const MAXIMUM_REVIEW_PROFILES_PER_STAGE: usize = 32;
pub const MAXIMUM_REVIEW_APPROVALS_PER_STAGE: u16 = 32;
/// The canonical snapshot envelope stored with every accepted review request.
///
/// Two individually bounded 64 KiB schemas plus the largest accepted stages,
/// clocks, outcomes, and identity encode to at most 216,809 bytes. The 256 KiB
/// envelope preserves those field limits and leaves a closed bound for storage.
pub const MAXIMUM_REVIEW_POLICY_SNAPSHOT_BYTES: usize = 256 * 1024;

const MAXIMUM_REVIEW_OUTCOMES: usize = 16;
const MAXIMUM_REVIEW_SCHEMA_BYTES: usize = 64 * 1024;
const MAXIMUM_REVIEW_DISPLAY_BYTES: usize = 16 * 1024;
const MAXIMUM_REVIEW_VALUE_DEPTH: usize = 16;
const MAXIMUM_REVIEW_REASON_BYTES: usize = 2_000;
const MAXIMUM_REVIEW_RESULT_BYTES: usize = 16 * 1024;
const MAXIMUM_REVIEW_RESULT_CONSTRAINTS_BYTES: usize = 16 * 1024;
const MAXIMUM_REVIEW_CONSTRAINT_CHOICES: usize = 64;
const MAXIMUM_REVIEW_CONSTRAINT_TITLE_CHARS: usize = 120;

const RESULT_PATH: &str = "$.result";
const RESULT_CONSTRAINTS_PATH: &str = "$.resultConstraints";

pub type ReviewPolicyDigest = ContentDigest;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewRetentionPolicy {
    pub terminal_days: u32,
    pub accountability_days: u32,
}

impl ReviewRetentionPolicy {
    fn check(&self) -> Result<(), ReviewPolicyError> {
        if self.terminal_days == 0
            || self.accountability_days < self.terminal_days
            || self.accountability_days > MAXIMUM_REVIEW_RETENTION_DAYS
        {
            return Err(ReviewPolicyError::Retention);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "scope",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
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
    fn is_valid(&self) -> bool {
        valid_identifier(&self.id)
            && !self.label.trim().is_empty()
            && self.label.len() <= 120
            && self.label.chars().all(|character| !character.is_control())
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
        if !valid_identifier(&self.id) || !valid_version(&self.version) {
            return Err(ReviewPolicyError::Identity);
        }
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

        self.retention.check()?;
        check_closed_object_schema(&self.display_schema)?;
        if let Some(result_schema) = &self.result_schema {
            check_closed_object_schema(result_schema)?;
        }
        if self.outcomes.len() > MAXIMUM_REVIEW_OUTCOMES
            || !all_unique(self.outcomes.iter().map(|outcome| outcome.id.as_str()))
            || self.outcomes.iter().any(|outcome| !outcome.is_valid())
            || (self.result_schema.is_none()
                && self.outcomes.iter().any(|outcome| outcome.result_required))
        {
            return Err(ReviewPolicyError::Outcomes);
        }
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
        let snapshot = ReviewKindPolicySnapshot {
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
        };
        snapshot.check_encoding_bound()?;
        Ok(snapshot)
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
        self.check_encoding_bound()?;
        let policy = self.as_policy();
        if policy.policy_digest()? != self.identity.digest {
            return Err(ReviewPolicyError::DigestMismatch);
        }
        Ok(())
    }

    fn check_encoding_bound(&self) -> Result<(), ReviewPolicyError> {
        let value = serde_json::to_value(self).map_err(|_| ReviewPolicyError::Canonical)?;
        let bytes = registry_platform_canonical_json::canonicalize_json(&value)
            .map_err(|_| ReviewPolicyError::Canonical)?;
        if bytes.len() > MAXIMUM_REVIEW_POLICY_SNAPSHOT_BYTES {
            return Err(ReviewPolicyError::SnapshotSize);
        }
        Ok(())
    }

    pub fn validate_display(&self, display: &Value) -> Result<(), ReviewDecisionValidationError> {
        self.verify()?;
        validate_display(&self.display_schema, display)?;
        Ok(())
    }

    pub fn validate_result_constraints(
        &self,
        constraints: &Value,
    ) -> Result<(), ReviewDecisionValidationError> {
        self.verify()?;
        validate_result_constraints(self.result_schema.as_ref(), constraints)?;
        Ok(())
    }

    fn validate_outcome(
        &self,
        outcome: &str,
        reason: Option<&str>,
        result: Option<&Value>,
        constraints: Option<&Value>,
    ) -> Result<(), ReviewDecisionValidationError> {
        self.verify()?;
        let outcome_policy = self
            .outcomes
            .iter()
            .find(|candidate| candidate.id == outcome)
            .ok_or_else(|| {
                ReviewValidationError::new("$.outcome", ReviewValidationReason::OutcomeNotDeclared)
            })?;
        if reason.is_some_and(|reason| !bounded_text(reason, MAXIMUM_REVIEW_REASON_BYTES)) {
            return Err(ReviewValidationError::new(
                "$.reason",
                ReviewValidationReason::TextInvalid,
            )
            .into());
        }
        if outcome_policy.reason_required && reason.is_none_or(|reason| reason.trim().is_empty()) {
            return Err(ReviewValidationError::new(
                "$.reason",
                ReviewValidationReason::ReasonRequired,
            )
            .into());
        }
        match (result, self.result_schema.as_ref()) {
            (Some(result), Some(schema)) => {
                validate_result(schema, result)?;
                if let Some(constraints) = constraints {
                    validate_result_narrowing(constraints, result)?;
                }
            }
            (Some(_), None) => {
                return Err(ReviewValidationError::new(
                    RESULT_PATH,
                    ReviewValidationReason::ResultNotDeclared,
                )
                .into());
            }
            (None, Some(_)) if outcome_policy.result_required => {
                return Err(ReviewValidationError::new(
                    RESULT_PATH,
                    ReviewValidationReason::ResultRequired,
                )
                .into());
            }
            (None, _) => {}
        }
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSourceBindingStatus {
    Current,
    BindingChanged,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewSourceProjection {
    pub binding: SourceBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_reference: Option<String>,
    #[serde(default)]
    /// Exact source values from the current human caller's read, limited by
    /// the authored source context projection and the pinned kind schema.
    pub display: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "strategy",
    rename_all = "snake_case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ReviewTaskContextData {
    Submitted {
        snapshot: Value,
    },
    Source {
        reference: String,
        binding_status: ReviewSourceBindingStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        projection: Option<ReviewSourceProjection>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewTaskContext {
    pub task_id: Uuid,
    pub request_id: Uuid,
    pub subject: SubjectBinding,
    pub requester_reference: String,
    pub policy: PolicyBinding,
    pub policy_snapshot: ReviewKindPolicySnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_constraints: Option<Value>,
    pub context: ReviewTaskContextData,
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewClockState {
    Running,
    Paused,
    Completed,
    Cancelled,
    SourceFactsMissing,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewClockOccurrence {
    pub clock_occurrence_id: Uuid,
    pub clock_id: String,
    pub request_id: Uuid,
    pub correlation: ReviewClockCorrelation,
    pub state: ReviewClockState,
    pub policy_digest: ContentDigest,
    pub anchor_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at_risk_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewerDecisionKind {
    Approve,
    Reject {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_present_value",
            skip_serializing_if = "Option::is_none"
        )]
        result: Option<Value>,
    },
    ChangesRequested {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_present_value",
            skip_serializing_if = "Option::is_none"
        )]
        result: Option<Value>,
    },
    Answer {
        outcome: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
        #[serde(
            default,
            deserialize_with = "deserialize_present_value",
            skip_serializing_if = "Option::is_none"
        )]
        result: Option<Value>,
    },
}

/// Preserve an explicitly present JSON `null` so semantic validation can
/// reject it as a non-object instead of treating it like an omitted field.
fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
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
    ) -> Result<Self, ReviewDecisionValidationError> {
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

/// Checks that `reviewer` currently holds a task, independent of policy
/// verification, stage matching, or any other decision validation. Both
/// [`record_review_decision`] and the store's task-fetch path call this first
/// so a non-holder is refused before any expensive policy re-verification.
pub fn check_task_holder(
    task_state: &ReviewerTaskState,
    reviewer: &IssuerPrincipal,
) -> Result<(), ReviewDecisionError> {
    match task_state {
        ReviewerTaskState::Open => Err(ReviewDecisionError::TaskNotHeld),
        ReviewerTaskState::Held { holder } if holder == reviewer => Ok(()),
        ReviewerTaskState::Held { .. } => Err(ReviewDecisionError::HolderMismatch),
        ReviewerTaskState::Decided => Err(ReviewDecisionError::TaskAlreadyDecided),
    }
}

pub fn record_review_decision(
    policy: &ReviewKindPolicySnapshot,
    progress: &mut ReviewProgress,
    task: &ReviewerTask,
    decision: ReviewerDecision,
) -> Result<ReviewTransition, ReviewDecisionError> {
    check_task_holder(&task.state, &decision.reviewer)?;
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
    #[error("the review policy identity is invalid")]
    Identity,
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
    #[error("the review retention policy is invalid")]
    Retention,
    #[error("a review display or result schema is invalid or unbounded")]
    Schema,
    #[error("the review outcomes are invalid")]
    Outcomes,
    #[error("the review policy could not be canonically encoded")]
    Canonical,
    #[error("the review policy snapshot exceeds the bounded canonical encoding")]
    SnapshotSize,
    #[error("the review policy snapshot digest does not match its contents")]
    DigestMismatch,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReviewDecisionValidationError {
    #[error(transparent)]
    Policy(#[from] ReviewPolicyError),
    #[error(transparent)]
    Structured(#[from] ReviewValidationError),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewValidationReason {
    KindNotAllowed,
    ReferenceInvalid,
    ObjectRequired,
    MaximumBytesExceeded,
    MaximumDepthExceeded,
    SchemaMismatch,
    OutcomeNotDeclared,
    ReasonRequired,
    TextInvalid,
    ResultNotDeclared,
    ResultRequired,
    FieldNotDeclared,
    ConstraintInvalid,
    ConstraintViolated,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewValidationError {
    pub path: String,
    pub reason: ReviewValidationReason,
}

impl ReviewValidationError {
    pub fn new(path: impl Into<String>, reason: ReviewValidationReason) -> Self {
        Self::with_fallback(path, reason, "$.display")
    }

    fn result_error(path: impl Into<String>, reason: ReviewValidationReason) -> Self {
        Self::with_fallback(path, reason, RESULT_PATH)
    }

    fn with_fallback(
        path: impl Into<String>,
        reason: ReviewValidationReason,
        fallback: &str,
    ) -> Self {
        let path = path.into();
        Self {
            path: if path.len() <= 256 && path.bytes().all(valid_path_byte) {
                path
            } else {
                fallback.to_owned()
            },
            reason,
        }
    }
}

impl fmt::Display for ReviewValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "review request validation failed at {}",
            self.path
        )
    }
}

impl std::error::Error for ReviewValidationError {}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ReviewDecisionError {
    #[error(transparent)]
    Policy(#[from] ReviewPolicyError),
    #[error(transparent)]
    Validation(#[from] ReviewDecisionValidationError),
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

fn check_closed_object_schema(schema: &Value) -> Result<(), ReviewPolicyError> {
    let root = schema.as_object().ok_or(ReviewPolicyError::Schema)?;
    if root.get("type") != Some(&Value::String("object".to_owned()))
        || root.get("additionalProperties") != Some(&Value::Bool(false))
        || !bounded_json(schema, MAXIMUM_REVIEW_VALUE_DEPTH)
        || !schema_refs_are_local(schema)
        || !object_schemas_are_closed(schema)
        || !registry_platform_canonical_json::canonicalize_json(schema)
            .is_ok_and(|bytes| bytes.len() <= MAXIMUM_REVIEW_SCHEMA_BYTES)
        || JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(schema)
            .is_err()
    {
        return Err(ReviewPolicyError::Schema);
    }
    Ok(())
}

fn validate_display(schema: &Value, display: &Value) -> Result<(), ReviewValidationError> {
    if !display.is_object() {
        return Err(ReviewValidationError::new(
            "$.display",
            ReviewValidationReason::ObjectRequired,
        ));
    }
    if !bounded_json(display, MAXIMUM_REVIEW_VALUE_DEPTH) {
        return Err(ReviewValidationError::new(
            "$.display",
            ReviewValidationReason::MaximumDepthExceeded,
        ));
    }
    if !registry_platform_canonical_json::canonicalize_json(display)
        .is_ok_and(|bytes| bytes.len() <= MAXIMUM_REVIEW_DISPLAY_BYTES)
    {
        return Err(ReviewValidationError::new(
            "$.display",
            ReviewValidationReason::MaximumBytesExceeded,
        ));
    }
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .map_err(|_| {
            ReviewValidationError::new("$.display", ReviewValidationReason::SchemaMismatch)
        })?;
    if let Err(errors) = compiled.validate(display) {
        let path = errors
            .into_iter()
            .next()
            .map(|error| {
                let path = error.instance_path.to_string();
                if path.is_empty() {
                    "$.display".to_owned()
                } else {
                    format!("$.display{path}")
                }
            })
            .unwrap_or_else(|| "$.display".to_owned());
        return Err(ReviewValidationError::new(
            path,
            ReviewValidationReason::SchemaMismatch,
        ));
    }
    Ok(())
}

fn validate_result(schema: &Value, result: &Value) -> Result<(), ReviewValidationError> {
    if !result.is_object() {
        return Err(ReviewValidationError::result_error(
            RESULT_PATH,
            ReviewValidationReason::ObjectRequired,
        ));
    }
    if !bounded_json(result, MAXIMUM_REVIEW_VALUE_DEPTH) {
        return Err(ReviewValidationError::result_error(
            RESULT_PATH,
            ReviewValidationReason::MaximumDepthExceeded,
        ));
    }
    if !registry_platform_canonical_json::canonicalize_json(result)
        .is_ok_and(|bytes| bytes.len() <= MAXIMUM_REVIEW_RESULT_BYTES)
    {
        return Err(ReviewValidationError::result_error(
            RESULT_PATH,
            ReviewValidationReason::MaximumBytesExceeded,
        ));
    }
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(schema)
        .map_err(|_| {
            ReviewValidationError::result_error(RESULT_PATH, ReviewValidationReason::SchemaMismatch)
        })?;
    if let Err(errors) = compiled.validate(result) {
        let path = errors
            .into_iter()
            .next()
            .map(|error| {
                let path = error.instance_path.to_string();
                if path.is_empty() {
                    RESULT_PATH.to_owned()
                } else {
                    format!("{RESULT_PATH}{path}")
                }
            })
            .unwrap_or_else(|| RESULT_PATH.to_owned());
        return Err(ReviewValidationError::result_error(
            path,
            ReviewValidationReason::SchemaMismatch,
        ));
    }
    Ok(())
}

/// A requester may only narrow a kind's declared result fields. Choice values
/// must satisfy the kind schema, and bounds must remain inside its bounds.
fn validate_result_constraints(
    schema: Option<&Value>,
    constraints: &Value,
) -> Result<(), ReviewValidationError> {
    let schema = schema.ok_or_else(|| {
        ReviewValidationError::new(
            RESULT_CONSTRAINTS_PATH,
            ReviewValidationReason::ResultNotDeclared,
        )
    })?;
    if !constraints.is_object() {
        return Err(ReviewValidationError::new(
            RESULT_CONSTRAINTS_PATH,
            ReviewValidationReason::ObjectRequired,
        ));
    }
    if !bounded_json(constraints, MAXIMUM_REVIEW_VALUE_DEPTH) {
        return Err(ReviewValidationError::new(
            RESULT_CONSTRAINTS_PATH,
            ReviewValidationReason::MaximumDepthExceeded,
        ));
    }
    if !registry_platform_canonical_json::canonicalize_json(constraints)
        .is_ok_and(|bytes| bytes.len() <= MAXIMUM_REVIEW_RESULT_CONSTRAINTS_BYTES)
    {
        return Err(ReviewValidationError::new(
            RESULT_CONSTRAINTS_PATH,
            ReviewValidationReason::MaximumBytesExceeded,
        ));
    }
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .ok_or_else(|| constraint_invalid(RESULT_CONSTRAINTS_PATH))?;
    let mut relaxed = schema.clone();
    if let Some(object) = relaxed.as_object_mut() {
        object.remove("required");
    }
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&relaxed)
        .map_err(|_| constraint_invalid(RESULT_CONSTRAINTS_PATH))?;
    for (field, constraint) in constraints.as_object().expect("checked as an object above") {
        let field_path = result_field_path(RESULT_CONSTRAINTS_PATH, field);
        let subschema = properties.get(field).ok_or_else(|| {
            ReviewValidationError::new(field_path.clone(), ReviewValidationReason::FieldNotDeclared)
        })?;
        let constraint = constraint
            .as_object()
            .ok_or_else(|| constraint_invalid(&field_path))?;
        for keyword in constraint.keys() {
            if !matches!(
                keyword.as_str(),
                "enum" | "oneOf" | "minimum" | "maximum" | "minLength" | "maxLength"
            ) {
                return Err(constraint_invalid(&field_path));
            }
        }
        let has_enum = constraint.contains_key("enum");
        let has_one_of = constraint.contains_key("oneOf");
        if has_enum && has_one_of {
            return Err(constraint_invalid(&field_path));
        }
        if has_enum {
            let values = constraint["enum"]
                .as_array()
                .ok_or_else(|| constraint_invalid(&field_path))?;
            if values.is_empty() || values.len() > MAXIMUM_REVIEW_CONSTRAINT_CHOICES {
                return Err(constraint_invalid(&field_path));
            }
            for value in values {
                if !is_scalar(value) {
                    return Err(constraint_invalid(&field_path));
                }
                validate_constraint_value(&compiled, field, value)
                    .map_err(|()| constraint_invalid(&field_path))?;
            }
        }
        if has_one_of {
            let entries = constraint["oneOf"]
                .as_array()
                .ok_or_else(|| constraint_invalid(&field_path))?;
            if entries.is_empty() || entries.len() > MAXIMUM_REVIEW_CONSTRAINT_CHOICES {
                return Err(constraint_invalid(&field_path));
            }
            for entry in entries {
                let entry = entry
                    .as_object()
                    .ok_or_else(|| constraint_invalid(&field_path))?;
                let has_const = entry.contains_key("const");
                let has_title = entry.contains_key("title");
                if !has_const || entry.len() > 2 || (entry.len() == 2 && !has_title) {
                    return Err(constraint_invalid(&field_path));
                }
                let value = entry
                    .get("const")
                    .filter(|value| is_scalar(value))
                    .ok_or_else(|| constraint_invalid(&field_path))?;
                if let Some(title) = entry.get("title") {
                    let title = title
                        .as_str()
                        .ok_or_else(|| constraint_invalid(&field_path))?;
                    if title.chars().count() > MAXIMUM_REVIEW_CONSTRAINT_TITLE_CHARS
                        || title.chars().any(char::is_control)
                    {
                        return Err(ReviewValidationError::new(
                            field_path.clone(),
                            ReviewValidationReason::TextInvalid,
                        ));
                    }
                }
                validate_constraint_value(&compiled, field, value)
                    .map_err(|()| constraint_invalid(&field_path))?;
            }
        }
        check_constraint_bounds(&field_path, subschema, constraint)?;
    }
    Ok(())
}

fn check_constraint_bounds(
    field_path: &str,
    subschema: &Value,
    constraint: &serde_json::Map<String, Value>,
) -> Result<(), ReviewValidationError> {
    let declares_type = |wanted: &[&str]| {
        subschema.get("type").is_some_and(|value| match value {
            Value::String(name) => wanted.contains(&name.as_str()),
            Value::Array(names) => names
                .iter()
                .any(|name| name.as_str().is_some_and(|item| wanted.contains(&item))),
            _ => false,
        })
    };
    let minimum = constraint.get("minimum");
    let maximum = constraint.get("maximum");
    if minimum.is_some() || maximum.is_some() {
        if !declares_type(&["number", "integer"]) || !plain_inline_bounds(subschema) {
            return Err(constraint_invalid(field_path));
        }
        let minimum = minimum.filter(|value| value.is_number());
        let maximum = maximum.filter(|value| value.is_number());
        if constraint.contains_key("minimum") && minimum.is_none()
            || constraint.contains_key("maximum") && maximum.is_none()
            || minimum.zip(maximum).is_some_and(|(minimum, maximum)| {
                compare_json_numbers(minimum, maximum) == Some(Ordering::Greater)
            })
            || minimum
                .zip(subschema.get("minimum"))
                .is_some_and(|(minimum, schema_minimum)| {
                    compare_json_numbers(schema_minimum, minimum) == Some(Ordering::Greater)
                })
            || maximum
                .zip(subschema.get("maximum"))
                .is_some_and(|(maximum, schema_maximum)| {
                    compare_json_numbers(maximum, schema_maximum) == Some(Ordering::Greater)
                })
        {
            return Err(constraint_invalid(field_path));
        }
    }
    let min_length = constraint.get("minLength");
    let max_length = constraint.get("maxLength");
    if min_length.is_some() || max_length.is_some() {
        if !declares_type(&["string"]) || !plain_inline_bounds(subschema) {
            return Err(constraint_invalid(field_path));
        }
        let min_length = min_length
            .filter(|value| value.is_number())
            .and_then(Value::as_u64);
        let max_length = max_length
            .filter(|value| value.is_number())
            .and_then(Value::as_u64);
        if constraint.contains_key("minLength") && min_length.is_none()
            || constraint.contains_key("maxLength") && max_length.is_none()
            || min_length
                .zip(max_length)
                .is_some_and(|(minimum, maximum)| minimum > maximum)
            || min_length
                .zip(subschema.get("minLength").and_then(Value::as_u64))
                .is_some_and(|(minimum, schema_minimum)| schema_minimum > minimum)
            || max_length
                .zip(subschema.get("maxLength").and_then(Value::as_u64))
                .is_some_and(|(maximum, schema_maximum)| maximum > schema_maximum)
        {
            return Err(constraint_invalid(field_path));
        }
    }
    Ok(())
}

fn validate_constraint_value(compiled: &JSONSchema, field: &str, value: &Value) -> Result<(), ()> {
    let mut instance = serde_json::Map::new();
    instance.insert(field.to_owned(), value.clone());
    compiled.validate(&Value::Object(instance)).map_err(|_| ())
}

fn plain_inline_bounds(subschema: &Value) -> bool {
    subschema.as_object().is_some_and(|object| {
        !object.contains_key("$ref")
            && !object.contains_key("allOf")
            && !object.contains_key("anyOf")
            && !object.contains_key("oneOf")
    })
}

fn validate_result_narrowing(
    constraints: &Value,
    result: &Value,
) -> Result<(), ReviewValidationError> {
    let Some(fields) = constraints.as_object() else {
        return Ok(());
    };
    let result_fields = result.as_object().expect("result validated as an object");
    for (field, constraint) in fields {
        let Some(value) = result_fields.get(field) else {
            continue;
        };
        let field_path = result_field_path(RESULT_PATH, field);
        let violated = || {
            ReviewValidationError::result_error(
                field_path.clone(),
                ReviewValidationReason::ConstraintViolated,
            )
        };
        if constraint
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|choices| {
                !choices
                    .iter()
                    .any(|allowed| constraint_value_equals(allowed, value))
            })
            || constraint
                .get("oneOf")
                .and_then(Value::as_array)
                .is_some_and(|entries| {
                    !entries
                        .iter()
                        .filter_map(|entry| entry.get("const"))
                        .any(|allowed| constraint_value_equals(allowed, value))
                })
            || constraint
                .get("minimum")
                .is_some_and(|minimum| compare_json_numbers(value, minimum) == Some(Ordering::Less))
            || constraint.get("maximum").is_some_and(|maximum| {
                compare_json_numbers(value, maximum) == Some(Ordering::Greater)
            })
            || constraint
                .get("minLength")
                .and_then(Value::as_u64)
                .is_some_and(|minimum| {
                    value
                        .as_str()
                        .is_some_and(|text| character_count(text) < minimum)
                })
            || constraint
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|maximum| {
                    value
                        .as_str()
                        .is_some_and(|text| character_count(text) > maximum)
                })
        {
            return Err(violated());
        }
    }
    Ok(())
}

fn constraint_value_equals(allowed: &Value, actual: &Value) -> bool {
    if allowed.is_number() && actual.is_number() {
        compare_json_numbers(allowed, actual) == Some(Ordering::Equal)
    } else {
        allowed == actual
    }
}

fn compare_json_numbers(left: &Value, right: &Value) -> Option<Ordering> {
    let left = decimal_parts(left.as_number()?.to_string().as_str())?;
    let right = decimal_parts(right.as_number()?.to_string().as_str())?;
    if left.negative != right.negative {
        return Some(if left.negative {
            Ordering::Less
        } else {
            Ordering::Greater
        });
    }
    let magnitude = compare_decimal_magnitude(&left, &right);
    Some(if left.negative {
        magnitude.reverse()
    } else {
        magnitude
    })
}

struct DecimalParts {
    negative: bool,
    digits: Vec<u8>,
    scale: i64,
}

fn decimal_parts(value: &str) -> Option<DecimalParts> {
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let (coefficient, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or(Some((unsigned, 0_i64)), |(coefficient, exponent)| {
            Some((coefficient, exponent.parse().ok()?))
        })?;
    let (integer, fraction) = coefficient
        .split_once('.')
        .map_or((coefficient, ""), |(integer, fraction)| (integer, fraction));
    let combined = format!("{integer}{fraction}");
    let trimmed = combined.trim_start_matches('0');
    if trimmed.is_empty() {
        return Some(DecimalParts {
            negative: false,
            digits: vec![b'0'],
            scale: 0,
        });
    }
    if !trimmed.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    Some(DecimalParts {
        negative,
        digits: trimmed.as_bytes().to_vec(),
        scale: exponent.checked_sub(i64::try_from(fraction.len()).ok()?)?,
    })
}

fn compare_decimal_magnitude(left: &DecimalParts, right: &DecimalParts) -> Ordering {
    let left_zero = left.digits == [b'0'];
    let right_zero = right.digits == [b'0'];
    match (left_zero, right_zero) {
        (true, true) => return Ordering::Equal,
        (true, false) => return Ordering::Less,
        (false, true) => return Ordering::Greater,
        (false, false) => {}
    }
    let left_extent = i64::try_from(left.digits.len())
        .unwrap_or(i64::MAX)
        .saturating_add(left.scale);
    let right_extent = i64::try_from(right.digits.len())
        .unwrap_or(i64::MAX)
        .saturating_add(right.scale);
    left_extent.cmp(&right_extent).then_with(|| {
        let width = left.digits.len().max(right.digits.len());
        (0..width)
            .map(|index| {
                left.digits
                    .get(index)
                    .copied()
                    .unwrap_or(b'0')
                    .cmp(&right.digits.get(index).copied().unwrap_or(b'0'))
            })
            .find(|ordering| *ordering != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    })
}

fn character_count(text: &str) -> u64 {
    u64::try_from(text.chars().count()).unwrap_or(u64::MAX)
}

fn is_scalar(value: &Value) -> bool {
    matches!(value, Value::Bool(_) | Value::Number(_) | Value::String(_))
}

fn result_field_path(prefix: &str, field: &str) -> String {
    if !field.bytes().all(valid_path_byte) {
        return prefix.to_owned();
    }
    let escaped_len = field.bytes().try_fold(0usize, |length, byte| {
        length.checked_add(if matches!(byte, b'/' | b'~') { 2 } else { 1 })
    });
    if escaped_len
        .and_then(|length| prefix.len().checked_add(length + 1))
        .is_none_or(|length| length > 256)
    {
        return prefix.to_owned();
    }
    let mut path = String::with_capacity(prefix.len() + escaped_len.unwrap_or_default() + 1);
    path.push_str(prefix);
    path.push('/');
    for byte in field.bytes() {
        match byte {
            b'~' => path.push_str("~0"),
            b'/' => path.push_str("~1"),
            _ => path.push(char::from(byte)),
        }
    }
    path
}

fn constraint_invalid(path: impl Into<String>) -> ReviewValidationError {
    ReviewValidationError::with_fallback(
        path,
        ReviewValidationReason::ConstraintInvalid,
        RESULT_CONSTRAINTS_PATH,
    )
}

fn bounded_json(value: &Value, maximum_depth: usize) -> bool {
    let mut pending = vec![(value, 1_usize)];
    while let Some((value, depth)) = pending.pop() {
        if depth > maximum_depth {
            return false;
        }
        match value {
            Value::Array(values) => {
                pending.extend(values.iter().map(|value| (value, depth + 1)));
            }
            Value::Object(values) => {
                pending.extend(values.values().map(|value| (value, depth + 1)));
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    true
}

fn schema_refs_are_local(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().all(|(key, value)| {
            if key == "$ref" {
                value
                    .as_str()
                    .is_some_and(|reference| reference == "#" || reference.starts_with("#/"))
            } else {
                schema_refs_are_local(value)
            }
        }),
        Value::Array(values) => values.iter().all(schema_refs_are_local),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

fn object_schemas_are_closed(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            let declares_object = object.get("type").is_some_and(|value| match value {
                Value::String(value) => value == "object",
                Value::Array(values) => values.iter().any(|value| value == "object"),
                _ => false,
            });
            let uses_object_keywords = [
                "properties",
                "patternProperties",
                "required",
                "minProperties",
                "maxProperties",
                "dependentRequired",
                "dependentSchemas",
                "propertyNames",
            ]
            .iter()
            .any(|keyword| object.contains_key(*keyword));
            let closed = if declares_object || uses_object_keywords {
                object.get("additionalProperties") == Some(&Value::Bool(false))
            } else {
                true
            };
            closed
                && object
                    .iter()
                    .all(|(keyword, value)| match keyword.as_str() {
                        "properties" | "patternProperties" | "dependentSchemas" | "$defs"
                        | "definitions" => value
                            .as_object()
                            .is_none_or(|schemas| schemas.values().all(object_schemas_are_closed)),
                        "allOf" | "anyOf" | "oneOf" | "prefixItems" => value
                            .as_array()
                            .is_none_or(|schemas| schemas.iter().all(object_schemas_are_closed)),
                        "additionalProperties"
                        | "unevaluatedProperties"
                        | "propertyNames"
                        | "contains"
                        | "items"
                        | "additionalItems"
                        | "unevaluatedItems"
                        | "not"
                        | "if"
                        | "then"
                        | "else"
                        | "contentSchema" => object_schemas_are_closed(value),
                        _ => true,
                    })
        }
        Value::Array(values) => values.iter().all(object_schemas_are_closed),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
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

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn bounded_text(value: &str, maximum_bytes: usize) -> bool {
    !value.trim().is_empty()
        && value.len() <= maximum_bytes
        && value.chars().all(|character| !character.is_control())
}

fn valid_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'$' | b'.' | b'/' | b'_' | b'-' | b'~')
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
            retention: ReviewRetentionPolicy {
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
            retention: ReviewRetentionPolicy {
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

        let mut oversized = approval_policy(vec![stage("first", 1)]).snapshot().unwrap();
        oversized.display_schema = Value::String("x".repeat(MAXIMUM_REVIEW_POLICY_SNAPSHOT_BYTES));
        assert_eq!(oversized.verify(), Err(ReviewPolicyError::SnapshotSize));
    }

    #[test]
    fn accepted_policy_fields_fit_the_snapshot_envelope() {
        fn identifier(prefix: char, index: usize) -> String {
            let suffix = format!("{index:02}");
            format!("{prefix}{}{suffix}", "a".repeat(63 - suffix.len()))
        }

        let schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {}
        });
        let mut policy = approval_policy(
            (0..MAXIMUM_REVIEW_STAGES)
                .map(|stage_index| ReviewStagePolicy {
                    id: identifier('s', stage_index),
                    queue: identifier('q', stage_index),
                    deciding_profiles: (0..MAXIMUM_REVIEW_PROFILES_PER_STAGE)
                        .map(|profile_index| identifier('p', profile_index))
                        .collect(),
                    required_approvals: MAXIMUM_REVIEW_APPROVALS_PER_STAGE,
                    exclude_initiator: true,
                    exclude_previous_stage_reviewers: true,
                })
                .collect(),
        );
        policy.id = "a".repeat(64);
        policy.version = "v".repeat(64);
        policy.context_strategy = ReviewContextStrategy::Submitted;
        policy.clocks = (0..32).map(|index| identifier('c', index)).collect();
        policy.retention = ReviewRetentionPolicy {
            terminal_days: MAXIMUM_REVIEW_RETENTION_DAYS,
            accountability_days: MAXIMUM_REVIEW_RETENTION_DAYS,
        };
        policy.display_schema = schema.clone();
        policy.result_schema = Some(schema.clone());
        policy.outcomes = (0..MAXIMUM_REVIEW_OUTCOMES)
            .map(|index| ReviewOutcomePolicy {
                id: identifier('o', index),
                label: "\"".repeat(120),
                settlement: ReviewOutcomeSettlement::ChangesRequested,
                reason_required: true,
                result_required: true,
            })
            .collect();

        let snapshot = policy.snapshot().expect("maximum bounded policy metadata");
        let snapshot_bytes = registry_platform_canonical_json::canonicalize_json(
            &serde_json::to_value(snapshot).expect("snapshot value"),
        )
        .expect("canonical snapshot");
        let schema_bytes = registry_platform_canonical_json::canonicalize_json(&schema)
            .expect("canonical schema")
            .len();
        let maximum_accepted_bytes =
            snapshot_bytes.len() - 2 * schema_bytes + 2 * MAXIMUM_REVIEW_SCHEMA_BYTES;
        assert_eq!(maximum_accepted_bytes, 216_809);
        assert!(maximum_accepted_bytes <= MAXIMUM_REVIEW_POLICY_SNAPSHOT_BYTES);
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
    fn review_clock_correlation_uses_camel_case_wire_fields() {
        assert_eq!(
            serde_json::to_value(ReviewClockCorrelation::Subject {
                source: "registry".to_owned(),
                subject_type: "record".to_owned(),
                id: "record-1".to_owned(),
            })
            .unwrap(),
            json!({
                "scope": "subject",
                "source": "registry",
                "subjectType": "record",
                "id": "record-1",
            })
        );
        assert_eq!(
            serde_json::to_value(ReviewClockCorrelation::Activity {
                task_id: Uuid::from_u128(1),
                stage_id: "review".to_owned(),
            })
            .unwrap(),
            json!({
                "scope": "activity",
                "taskId": "00000000-0000-0000-0000-000000000001",
                "stageId": "review",
            })
        );
    }

    #[test]
    fn review_outcome_omits_result_required_when_false() {
        let mut outcome = approval_policy(vec![stage("review", 1)]).outcomes.remove(0);
        let omitted = serde_json::to_value(&outcome).unwrap();
        assert!(!omitted.as_object().unwrap().contains_key("resultRequired"));

        outcome.result_required = true;
        assert_eq!(
            serde_json::to_value(outcome).unwrap()["resultRequired"],
            true
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

    /// Corrupts a snapshot's stored digest so `ReviewKindPolicySnapshot::verify`
    /// fails, without touching the valid snapshot the caller already used to
    /// build `ReviewProgress`. Used to prove the cheap task-state/holder check
    /// runs before the expensive policy re-verification in
    /// `record_review_decision`.
    fn corrupted(mut snapshot: ReviewKindPolicySnapshot) -> ReviewKindPolicySnapshot {
        snapshot.identity.digest = ContentDigest::for_bytes(b"tampered-policy-snapshot");
        snapshot
    }

    #[test]
    fn holder_mismatch_is_refused_before_policy_verification() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .snapshot()
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let held_task = task(request_id, 0, "review", 1, "holder-a");
        let decision = approve(&held_task, person("holder-b"));

        assert_eq!(
            record_review_decision(&corrupted(snapshot), &mut progress, &held_task, decision),
            Err(ReviewDecisionError::HolderMismatch)
        );
        assert!(progress.decisions.is_empty());
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn open_task_is_refused_before_policy_verification() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .snapshot()
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let mut open_task = task(request_id, 0, "review", 1, "reviewer");
        open_task.state = ReviewerTaskState::Open;
        let decision = approve(&open_task, person("reviewer"));

        assert_eq!(
            record_review_decision(&corrupted(snapshot), &mut progress, &open_task, decision),
            Err(ReviewDecisionError::TaskNotHeld)
        );
        assert!(progress.decisions.is_empty());
        assert!(progress.settlement.is_none());
    }

    #[test]
    fn decided_task_is_refused_before_policy_verification() {
        let snapshot = approval_policy(vec![stage("review", 1)])
            .snapshot()
            .unwrap();
        let request_id = Uuid::from_u128(100);
        let mut progress = ReviewProgress::new(request_id, None, None, &snapshot).unwrap();
        let mut decided_task = task(request_id, 0, "review", 1, "reviewer");
        decided_task.state = ReviewerTaskState::Decided;
        let decision = approve(&decided_task, person("reviewer"));

        assert_eq!(
            record_review_decision(&corrupted(snapshot), &mut progress, &decided_task, decision),
            Err(ReviewDecisionError::TaskAlreadyDecided)
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
                    ReviewDecisionValidationError::Structured(_)
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
    fn review_schemas_are_closed_and_display_errors_are_bounded() {
        let mut policy = answer_policy();
        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"details": {"properties": {"secret": {"type": "string"}}}}
        });
        assert_eq!(policy.check(), Err(ReviewPolicyError::Schema));

        policy.display_schema = json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"details": {"$ref": "https://example.test/details.json"}}
        });
        assert_eq!(policy.check(), Err(ReviewPolicyError::Schema));

        let snapshot = answer_policy().snapshot().unwrap();
        let secret = "sensitive-display-value".repeat(20);
        let error = snapshot
            .validate_display(&json!({"question": secret}))
            .expect_err("the display schema bounds question text");
        let ReviewDecisionValidationError::Structured(error) = error else {
            panic!("expected structured display validation failure");
        };
        assert_eq!(error.path, "$.display/question");
        assert_eq!(error.reason, ReviewValidationReason::SchemaMismatch);
        assert!(!error.to_string().contains("sensitive-display-value"));
        assert!(!error.to_string().contains("hosted"));
    }

    #[test]
    fn result_constraints_refuse_widening_and_apply_after_schema_validation() {
        assert_eq!(
            compare_json_numbers(
                &json!(9_007_199_254_740_992_u64),
                &json!(9_007_199_254_740_993_u64)
            ),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_json_numbers(
                &json!(-9_007_199_254_740_993_i64),
                &json!(-9_007_199_254_740_992_i64)
            ),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_json_numbers(&json!(0), &json!(0.5)),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare_json_numbers(&json!(0.5), &json!(0)),
            Some(Ordering::Greater)
        );
        let snapshot = answer_policy().snapshot().unwrap();
        assert_eq!(
            snapshot.validate_result_constraints(&json!({
                "code": {"minimum": 4, "maximum": 6}
            })),
            Ok(())
        );
        for (constraints, expected) in [
            (
                json!({"code": {"minimum": 0}}),
                ReviewValidationReason::ConstraintInvalid,
            ),
            (
                json!({"undeclared": {"enum": [4]}}),
                ReviewValidationReason::FieldNotDeclared,
            ),
        ] {
            let error = snapshot
                .validate_result_constraints(&constraints)
                .expect_err("constraints cannot widen the pinned result schema");
            let ReviewDecisionValidationError::Structured(error) = error else {
                panic!("expected structured constraint validation failure");
            };
            assert_eq!(error.reason, expected);
        }

        let request_id = Uuid::from_u128(100);
        let task = task(request_id, 0, "answer", 1, "answerer");
        let decide = |result: Value| ReviewerDecision {
            task_id: task.task_id,
            request_id,
            stage_id: "answer".to_owned(),
            reviewer: person("answerer"),
            profile_id: "reviewer".to_owned(),
            decision: ReviewerDecisionKind::Answer {
                outcome: "approved".to_owned(),
                reason: None,
                result: Some(result),
            },
        };
        for (result, expected) in [
            (
                json!({"code": "not-an-integer"}),
                ReviewValidationReason::SchemaMismatch,
            ),
            (
                json!({"code": 7}),
                ReviewValidationReason::ConstraintViolated,
            ),
        ] {
            let mut progress = ReviewProgress::new(
                request_id,
                None,
                Some(json!({"code": {"minimum": 4, "maximum": 6}})),
                &snapshot,
            )
            .unwrap();
            let error = record_review_decision(&snapshot, &mut progress, &task, decide(result))
                .expect_err("the result must satisfy the schema and its narrowing");
            let ReviewDecisionError::Validation(ReviewDecisionValidationError::Structured(error)) =
                error
            else {
                panic!("expected structured decision validation failure");
            };
            assert_eq!(error.reason, expected);
            assert!(progress.decisions.is_empty());
            assert!(progress.settlement.is_none());
        }
    }

    #[test]
    fn numeric_choices_use_json_schema_value_equality() {
        let mut policy = answer_policy();
        policy.result_schema = Some(json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["score"],
            "properties": {"score": {"type": "number"}}
        }));
        let snapshot = policy.snapshot().expect("numeric-choice policy snapshots");
        let request_id = Uuid::from_u128(100);
        let task = task(request_id, 0, "answer", 1, "answerer");

        for constraints in [
            json!({"score": {"enum": [1]}}),
            json!({"score": {"oneOf": [{"const": 1, "title": "One"}]}}),
        ] {
            snapshot
                .validate_result_constraints(&constraints)
                .expect("integer notation is a valid numeric narrowing");
            let mut progress =
                ReviewProgress::new(request_id, None, Some(constraints), &snapshot).unwrap();
            let decision = ReviewerDecision {
                task_id: task.task_id,
                request_id,
                stage_id: "answer".to_owned(),
                reviewer: person("answerer"),
                profile_id: "reviewer".to_owned(),
                decision: ReviewerDecisionKind::Answer {
                    outcome: "approved".to_owned(),
                    reason: None,
                    result: Some(json!({"score": 1.0})),
                },
            };
            record_review_decision(&snapshot, &mut progress, &task, decision)
                .expect("1 and 1.0 are equal JSON Schema numbers");
        }
    }

    #[test]
    fn decision_deserialization_preserves_explicit_null_result() {
        let explicit_null: ReviewerDecisionKind = serde_json::from_value(json!({
            "type": "answer",
            "outcome": "approved",
            "result": null
        }))
        .expect("explicit null remains a semantic validation input");
        assert!(matches!(
            explicit_null,
            ReviewerDecisionKind::Answer {
                result: Some(Value::Null),
                ..
            }
        ));

        let omitted: ReviewerDecisionKind = serde_json::from_value(json!({
            "type": "answer",
            "outcome": "approved"
        }))
        .expect("an omitted optional result remains absent");
        assert!(matches!(
            omitted,
            ReviewerDecisionKind::Answer { result: None, .. }
        ));
    }

    #[test]
    fn result_paths_escape_json_pointer_segments() {
        assert_eq!(
            result_field_path(RESULT_PATH, "path/segment"),
            "$.result/path~1segment"
        );
        assert_eq!(
            result_field_path(RESULT_CONSTRAINTS_PATH, "tilde~segment"),
            "$.resultConstraints/tilde~0segment"
        );
    }

    #[test]
    fn review_retention_and_outcome_vocabulary_are_bounded() {
        let mut policy = answer_policy();
        policy.retention.accountability_days = policy.retention.terminal_days - 1;
        assert_eq!(policy.check(), Err(ReviewPolicyError::Retention));

        let mut policy = answer_policy();
        policy.outcomes.push(policy.outcomes[0].clone());
        assert_eq!(policy.check(), Err(ReviewPolicyError::Outcomes));
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
