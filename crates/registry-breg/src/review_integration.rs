// SPDX-License-Identifier: Apache-2.0

//! Source-owned state for submitting frozen BReg proposals to a review authority.
//!
//! These records deliberately contain no review policy evaluator. They retain
//! the exact protocol bindings needed to make submission idempotent, correlate
//! a terminal result, and refuse mismatched or unsolicited completions.

use uuid::Uuid;

use crate::model::CompiledChangeRequestOnApprovedMode;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HumanIdentityBinding {
    pub issuer: String,
    pub subject: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceContextBinding {
    pub reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewSubjectBinding {
    pub source: String,
    pub subject_type: String,
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewPolicyBinding {
    pub id: String,
    pub version: String,
    pub digest: String,
}

/// Binding returned by the authority and retained by BReg after a successful
/// idempotent create. Every field participates in result correlation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedReviewBinding {
    pub authority: String,
    pub request_id: Uuid,
    pub subject: ReviewSubjectBinding,
    pub policy: ReviewPolicyBinding,
    pub submission_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewSubmissionJob {
    pub job_id: Uuid,
    pub request_entity_id: String,
    pub request_id: Uuid,
    pub proposal_version: u32,
    pub authority: String,
    pub policy_id: String,
    pub idempotency_key: String,
    pub expected_submission_digest: String,
    pub initiator: Option<HumanIdentityBinding>,
    pub source_context: SourceContextBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewCancellationJob {
    pub job_id: Uuid,
    pub request_entity_id: String,
    pub request_id: Uuid,
    pub proposal_version: u32,
    pub accepted: AcceptedReviewBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalReviewStatus {
    Approved,
    Rejected,
    ChangesRequested,
    Answered,
    Cancelled,
    Superseded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewResultEnvelope {
    pub result_id: Uuid,
    pub request_id: Uuid,
    pub subject: ReviewSubjectBinding,
    pub policy: ReviewPolicyBinding,
    pub submission_digest: String,
    pub status: TerminalReviewStatus,
    pub completed_at: String,
    pub available_until: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorrelationError {
    Authority,
    Request,
    Subject,
    Policy,
    SubmissionDigest,
    Status,
}

impl AcceptedReviewBinding {
    /// Verifies the complete immutable binding. A request ID match by itself is
    /// never sufficient evidence that a result belongs to this proposal.
    pub fn correlate(
        &self,
        authority: &str,
        result: &ReviewResultEnvelope,
    ) -> Result<(), CorrelationError> {
        if self.authority != authority {
            return Err(CorrelationError::Authority);
        }
        if self.request_id != result.request_id {
            return Err(CorrelationError::Request);
        }
        if self.subject != result.subject {
            return Err(CorrelationError::Subject);
        }
        if self.policy != result.policy {
            return Err(CorrelationError::Policy);
        }
        if self.submission_digest != result.submission_digest {
            return Err(CorrelationError::SubmissionDigest);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedReviewEvidence {
    authority: String,
    review_request_id: Uuid,
    result_id: Uuid,
    subject: ReviewSubjectBinding,
    policy: ReviewPolicyBinding,
    submission_digest: String,
    completed_at: String,
}

impl AcceptedReviewEvidence {
    #[cfg(feature = "runtime")]
    pub fn from_protocol(
        authority: &str,
        accepted: &registry_review_client::ReviewRequestAccepted,
        result: &registry_review_client::ReviewResult,
    ) -> Result<Self, CorrelationError> {
        let accepted = AcceptedReviewBinding {
            authority: authority.to_owned(),
            request_id: accepted.request_id,
            subject: ReviewSubjectBinding {
                source: accepted.subject.source.clone(),
                subject_type: accepted.subject.subject_type.clone(),
                id: accepted.subject.id.clone(),
                version: accepted.subject.version.clone(),
                digest: accepted.subject.digest.as_str().to_owned(),
            },
            policy: ReviewPolicyBinding {
                id: accepted.policy.id.clone(),
                version: accepted.policy.version.clone(),
                digest: accepted.policy.digest.as_str().to_owned(),
            },
            submission_digest: accepted.submission_digest.as_str().to_owned(),
        };
        let result = ReviewResultEnvelope {
            result_id: result.result_id,
            request_id: result.request_id,
            subject: ReviewSubjectBinding {
                source: result.subject.source.clone(),
                subject_type: result.subject.subject_type.clone(),
                id: result.subject.id.clone(),
                version: result.subject.version.clone(),
                digest: result.subject.digest.as_str().to_owned(),
            },
            policy: ReviewPolicyBinding {
                id: result.policy.id.clone(),
                version: result.policy.version.clone(),
                digest: result.policy.digest.as_str().to_owned(),
            },
            submission_digest: result.submission_digest.as_str().to_owned(),
            status: match result.status {
                registry_review_client::ReviewResultStatus::Approved => {
                    TerminalReviewStatus::Approved
                }
                registry_review_client::ReviewResultStatus::Rejected => {
                    TerminalReviewStatus::Rejected
                }
                registry_review_client::ReviewResultStatus::ChangesRequested => {
                    TerminalReviewStatus::ChangesRequested
                }
                registry_review_client::ReviewResultStatus::Answered => {
                    TerminalReviewStatus::Answered
                }
                registry_review_client::ReviewResultStatus::Cancelled => {
                    TerminalReviewStatus::Cancelled
                }
                registry_review_client::ReviewResultStatus::Superseded => {
                    TerminalReviewStatus::Superseded
                }
            },
            completed_at: result.completed_at.to_rfc3339(),
            available_until: result.available_until.to_rfc3339(),
        };
        Self::from_approved(authority, &accepted, &result)
    }

    pub fn from_approved(
        authority: &str,
        accepted: &AcceptedReviewBinding,
        result: &ReviewResultEnvelope,
    ) -> Result<Self, CorrelationError> {
        accepted.correlate(authority, result)?;
        if result.status != TerminalReviewStatus::Approved {
            return Err(CorrelationError::Status);
        }
        Ok(Self {
            authority: authority.to_owned(),
            review_request_id: result.request_id,
            result_id: result.result_id,
            subject: result.subject.clone(),
            policy: result.policy.clone(),
            submission_digest: result.submission_digest.clone(),
            completed_at: result.completed_at.clone(),
        })
    }

    pub fn matches_proposal(
        &self,
        authority: &str,
        policy_id: &str,
        request_id: &str,
        proposal_version: u32,
        proposal_digest: &str,
    ) -> bool {
        self.authority == authority
            && self.policy.id == policy_id
            && self.subject.id == request_id
            && self.subject.version == proposal_version.to_string()
            && self.subject.digest == proposal_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompletionInboxState {
    Pending,
    Correlated,
    Unmatched,
    Applied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewCompletionInboxEntry {
    pub event_id: Uuid,
    pub authority: String,
    pub review_request_id: Uuid,
    pub result_id: Uuid,
    pub completed_at: String,
    pub state: CompletionInboxState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewFeedCheckpoint {
    pub authority: String,
    pub cursor: Option<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalApplicationJob {
    pub job_id: Uuid,
    pub request_entity_id: String,
    pub request_id: Uuid,
    pub proposal_version: u32,
    pub proposal_digest: String,
    pub executor: String,
    pub evidence: AcceptedReviewEvidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationBindingError {
    ManualExecutor,
    AutomaticExecutor,
}

pub fn validate_application_binding(
    mode: CompiledChangeRequestOnApprovedMode,
    executor: Option<&str>,
) -> Result<(), ApplicationBindingError> {
    match (mode, executor) {
        (CompiledChangeRequestOnApprovedMode::Manual, None) => Ok(()),
        (CompiledChangeRequestOnApprovedMode::Manual, Some(_)) => {
            Err(ApplicationBindingError::ManualExecutor)
        }
        (CompiledChangeRequestOnApprovedMode::Automatic, Some(executor))
            if !executor.trim().is_empty() =>
        {
            Ok(())
        }
        (CompiledChangeRequestOnApprovedMode::Automatic, _) => {
            Err(ApplicationBindingError::AutomaticExecutor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted() -> AcceptedReviewBinding {
        AcceptedReviewBinding {
            authority: "casework-main".to_owned(),
            request_id: Uuid::nil(),
            subject: ReviewSubjectBinding {
                source: "breg".to_owned(),
                subject_type: "change_request".to_owned(),
                id: "request-1".to_owned(),
                version: "3".to_owned(),
                digest: format!("sha256:{}", "a".repeat(64)),
            },
            policy: ReviewPolicyBinding {
                id: "request-review".to_owned(),
                version: "7".to_owned(),
                digest: format!("sha256:{}", "b".repeat(64)),
            },
            submission_digest: format!("sha256:{}", "c".repeat(64)),
        }
    }

    fn result() -> ReviewResultEnvelope {
        let accepted = accepted();
        ReviewResultEnvelope {
            result_id: Uuid::from_u128(1),
            request_id: accepted.request_id,
            subject: accepted.subject,
            policy: accepted.policy,
            submission_digest: accepted.submission_digest,
            status: TerminalReviewStatus::Approved,
            completed_at: "2026-09-19T00:00:00Z".to_owned(),
            available_until: "2026-09-20T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn result_correlation_requires_every_frozen_binding() {
        let accepted = accepted();
        assert_eq!(accepted.correlate("casework-main", &result()), Ok(()));

        assert_eq!(
            accepted.correlate("casework-secondary", &result()),
            Err(CorrelationError::Authority)
        );
        let mut mismatched = result();
        mismatched.request_id = Uuid::from_u128(2);
        assert_eq!(
            accepted.correlate("casework-main", &mismatched),
            Err(CorrelationError::Request)
        );
        let mut mismatched = result();
        mismatched.subject.version = "8".to_owned();
        assert_eq!(
            accepted.correlate("casework-main", &mismatched),
            Err(CorrelationError::Subject)
        );
        let mut mismatched = result();
        mismatched.policy.version = "8".to_owned();
        assert_eq!(
            accepted.correlate("casework-main", &mismatched),
            Err(CorrelationError::Policy)
        );
        let mut mismatched = result();
        mismatched.submission_digest = format!("sha256:{}", "d".repeat(64));
        assert_eq!(
            accepted.correlate("casework-main", &mismatched),
            Err(CorrelationError::SubmissionDigest)
        );
        let mut mismatched = result();
        mismatched.status = TerminalReviewStatus::Rejected;
        assert_eq!(
            AcceptedReviewEvidence::from_approved("casework-main", &accepted, &mismatched),
            Err(CorrelationError::Status)
        );
    }

    #[test]
    fn executor_is_owned_only_by_automatic_application() {
        assert_eq!(
            validate_application_binding(CompiledChangeRequestOnApprovedMode::Manual, None),
            Ok(())
        );
        assert_eq!(
            validate_application_binding(
                CompiledChangeRequestOnApprovedMode::Manual,
                Some("breg-apply")
            ),
            Err(ApplicationBindingError::ManualExecutor)
        );
        assert_eq!(
            validate_application_binding(
                CompiledChangeRequestOnApprovedMode::Automatic,
                Some("breg-apply")
            ),
            Ok(())
        );
    }
}
