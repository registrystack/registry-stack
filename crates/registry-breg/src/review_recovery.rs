// SPDX-License-Identifier: Apache-2.0

//! Operator recovery for a lost review or a transient application failure.
//!
//! A review environment that was restored from an older backup, or replaced
//! by a fresh one, no longer holds the reviews BReg submitted to it. The
//! result poller names such a review `result-unknown-to-authority`, and the
//! poll budget eventually fails it. These operations give the operator two
//! supported answers: resubmit the exact retained review request, or close a
//! review that will never be answered. An existing acceptance is immutable; a
//! provider that lost it requires a new Proposal submission. A built-in automatic application may
//! retry a transient dependency failure within its original attempt budget,
//! preserving its frozen submission and idempotency key.
//! Each runs in one verified migration transaction under the Registry lock,
//! with an audit `request` entry accepted before the transaction opens and its
//! `response` written after the commit.

use std::path::Path;

use registry_platform_audit::AuditEntry;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::proposal_retention::{ProposalRetentionError, ProposalRetentionOperatorService};

/// Codes a failed review may carry and still be resubmitted: each one means
/// BReg gave up waiting, never that the authority refused or decided.
const RESUBMITTABLE_FAILURE_CODES: [&str; 3] = [
    "result-poll-attempts-exhausted",
    "submission-recovery-expired",
    "operator-closed",
];
const UNKNOWN_TO_AUTHORITY: &str = "result-unknown-to-authority";
const OPERATOR_CLOSED: &str = "operator-closed";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReviewRecoveryError {
    /// Configuration, package, database identity, or lock verification failed.
    Unavailable,
    /// No review or application exists for this exact Proposal version.
    NotFound,
    /// The retained review or application does not qualify for this operation.
    Ineligible {
        reason: ReviewRecoveryRefusal,
        state: String,
        code: Option<String>,
    },
    /// The recovery committed, but the audit destination refused its
    /// `response` entry.
    RecoveryUnaudited,
}

/// Why a retained review or application refuses an operator recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewRecoveryRefusal {
    /// The proposal was withdrawn, so its review is being cancelled.
    Withdrawn,
    /// A review result is already recorded for the proposal.
    ResultRecorded,
    /// Retention erased the review request, so there is nothing to resubmit.
    DetailErased,
    /// The request no longer awaits review for this proposal version.
    ProposalNotSubmitted,
    /// Activation blocked the current submission; its requester must Rebase or Cancel.
    PackageChanged,
    /// The submission's state and code do not call for this operation.
    SubmissionState,
    /// The application job has no transient failure with remaining attempts.
    ApplicationState,
    /// The exact proposal no longer has an unexpired approval.
    ApprovalUnavailable,
}

impl ReviewRecoveryRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Withdrawn => "withdrawn",
            Self::ResultRecorded => "result-recorded",
            Self::DetailErased => "detail-erased",
            Self::ProposalNotSubmitted => "proposal-not-submitted",
            Self::PackageChanged => "package-changed",
            Self::SubmissionState => "submission-state",
            Self::ApplicationState => "application-state",
            Self::ApprovalUnavailable => "approval-unavailable",
        }
    }
}

pub type Result<T> = std::result::Result<T, ReviewRecoveryError>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReviewRecoveryScope<'a> {
    pub action_id: &'a str,
    pub proposal_id: Uuid,
    pub submission_version: i64,
}

/// The retained review or application before and after one operator recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReviewRecovery {
    pub action_id: String,
    pub proposal_id: String,
    pub submission_version: i64,
    pub authority: String,
    pub previous_state: String,
    pub previous_code: Option<String>,
    pub state: &'static str,
    pub code: Option<&'static str>,
}

/// Where a recovery that did not finish stopped.
enum Stopped {
    /// Before the commit, so nothing committed.
    BeforeCommit(ReviewRecoveryError),
    /// At a commit that returned an error, which may still have committed.
    AtCommit,
}

impl From<ReviewRecoveryError> for Stopped {
    fn from(error: ReviewRecoveryError) -> Self {
        Self::BeforeCommit(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Operation {
    Resubmit,
    Close,
    RetryApplication,
}

impl Operation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Resubmit => "resubmit",
            Self::Close => "close",
            Self::RetryApplication => "retry-application",
        }
    }
}

/// Package-bound operator boundary used by `bregctl review-recovery`.
///
/// Construction verifies the same runtime configuration, package, database
/// identity, managed catalog, and migration role as request retention.
pub struct ReviewRecoveryOperatorService {
    verified: ProposalRetentionOperatorService,
}

impl ReviewRecoveryOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self> {
        ProposalRetentionOperatorService::from_runtime_config(path)
            .await
            .map(|verified| Self { verified })
            .map_err(|_| ReviewRecoveryError::Unavailable)
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn over_retention_service_for_test(verified: ProposalRetentionOperatorService) -> Self {
        Self { verified }
    }

    /// Returns the review to `pending` so the submission worker sends the
    /// exact retained request again under its original idempotency key.
    ///
    /// Accepted only for a review the authority answered as unknown, or one
    /// BReg failed for waiting too long, while its proposal still awaits
    /// review. The authority that still holds the request replays its
    /// original acceptance. If a previously accepted request was lost, a new
    /// acceptance is refused and the author must submit a new Proposal version.
    pub async fn resubmit(&self, scope: ReviewRecoveryScope<'_>) -> Result<ReviewRecovery> {
        self.recover(scope, Operation::Resubmit).await
    }

    /// Fails an accepted review that will never be answered, keeping its
    /// binding so an operator can find the review at the authority. A result
    /// the authority delivers for it afterwards is refused, not recorded.
    /// BReg sends nothing to the authority.
    pub async fn close(&self, scope: ReviewRecoveryScope<'_>) -> Result<ReviewRecovery> {
        self.recover(scope, Operation::Close).await
    }

    /// Retry a transient dependency failure within the frozen attempt budget.
    /// The exact job, submission, key and consumed attempts survive. The
    /// built-in coordinator checks current authority and fresh approval again.
    pub async fn retry_application(
        &self,
        scope: ReviewRecoveryScope<'_>,
    ) -> Result<ReviewRecovery> {
        self.recover(scope, Operation::RetryApplication).await
    }

    async fn recover(
        &self,
        scope: ReviewRecoveryScope<'_>,
        operation: Operation,
    ) -> Result<ReviewRecovery> {
        if scope.submission_version <= 0 {
            return Err(ReviewRecoveryError::NotFound);
        }
        self.verified
            .proposal_policy(scope.action_id)
            .map_err(|_| ReviewRecoveryError::NotFound)?;
        // The request entry is accepted before the recovery transaction
        // opens, so an audit outage changes no review; the response shares
        // its correlation. A recovery that ends without one writes the
        // unfinished outcome when the held request is dropped.
        let audit = self.verified.audit();
        let package_revision = self.verified.package_revision();
        let record_reference = audit
            .profile()
            .key_hasher()
            .audit_reference_hash(
                "breg-record-v1",
                package_revision,
                &scope.proposal_id.to_string(),
            )
            .map_err(|_| ReviewRecoveryError::Unavailable)?;
        let correlation = Uuid::new_v4().to_string();
        let request = serde_json::json!({
            "kind":"reviewRecovery", "operation":operation.as_str(),
            "activationId":package_revision,
            "actor":"breg:review-recovery-operator",
            "correlation":correlation,
            "actionId":scope.action_id, "recordReference":record_reference,
            "submissionVersion":scope.submission_version,
        });
        let mut attempt = audit
            .begin(
                AuditEntry::request(
                    crate::audit::AUDIT_SCHEMA,
                    correlation.clone(),
                    request.clone(),
                ),
                with_outcome(&request, "unfinished", Value::Null),
            )
            .await
            .map_err(|_| ReviewRecoveryError::Unavailable)?;
        match self.recover_in_transaction(scope, operation).await {
            Ok(recovery) => {
                let committed = with_outcome(
                    &request,
                    "committed",
                    serde_json::json!({
                        "authority":recovery.authority,
                        "previousState":recovery.previous_state,
                        "previousCode":recovery.previous_code,
                        "state":recovery.state, "code":recovery.code,
                    }),
                );
                attempt
                    .respond(committed)
                    .await
                    .map_err(|_| ReviewRecoveryError::RecoveryUnaudited)?;
                Ok(recovery)
            }
            Err(Stopped::BeforeCommit(error)) => {
                let outcome = if error == ReviewRecoveryError::Unavailable {
                    "failed"
                } else {
                    "refused"
                };
                if attempt
                    .respond(with_outcome(&request, outcome, Value::Null))
                    .await
                    .is_err()
                {
                    tracing::error!(
                        "the stopped review recovery's response audit entry was not recorded"
                    );
                }
                Err(error)
            }
            Err(Stopped::AtCommit) => {
                if attempt
                    .respond(with_outcome(&request, "unfinished", Value::Null))
                    .await
                    .is_err()
                {
                    tracing::error!(
                        "the unacknowledged review recovery's response audit entry was not recorded"
                    );
                }
                Err(ReviewRecoveryError::Unavailable)
            }
        }
    }

    async fn recover_in_transaction(
        &self,
        scope: ReviewRecoveryScope<'_>,
        operation: Operation,
    ) -> std::result::Result<ReviewRecovery, Stopped> {
        let mut client = self
            .verified
            .migration_client()
            .await
            .map_err(unavailable)?;
        let transaction = self
            .verified
            .begin_verified_transaction(&mut client)
            .await
            .map_err(unavailable)?;
        if operation == Operation::RetryApplication {
            let recovery = retry_application_in_transaction(&transaction, scope).await?;
            transaction.commit().await.map_err(|_| Stopped::AtCommit)?;
            return Ok(recovery);
        }
        let row = transaction
            .query_opt(
                "SELECT s.state,s.last_error_code,s.withdrawn,s.authority,
                        s.create_request <> '{}'::jsonb,
                        EXISTS (
                            SELECT 1 FROM registry_internal.registry_proposal_review_results r
                             WHERE (r.action_id,r.proposal_id,r.submission_version)
                                   =(s.action_id,s.proposal_id,s.submission_version)),
                        w.state='submitted' AND w.submission_version=s.submission_version,
                        CASE WHEN w.submission_version=s.submission_version THEN w.blocked_reason END
                   FROM registry_internal.registry_proposal_review_submissions s
                   LEFT JOIN registry_internal.registry_proposal_state w
                     ON (w.action_id,w.proposal_id)=(s.action_id,s.proposal_id)
                  WHERE s.action_id=$1 AND s.proposal_id=$2 AND s.submission_version=$3
                  FOR UPDATE OF s",
                &[
                    &scope.action_id,
                    &scope.proposal_id,
                    &scope.submission_version,
                ],
            )
            .await
            .map_err(|_| ReviewRecoveryError::Unavailable)?
            .ok_or(ReviewRecoveryError::NotFound)?;
        let state: String = row.get(0);
        let code: Option<String> = row.get(1);
        let withdrawn: bool = row.get(2);
        let authority: String = row.get(3);
        let request_retained: bool = row.get(4);
        let result_recorded: bool = row.get(5);
        let proposal_submitted = row.get::<_, Option<bool>>(6) == Some(true);
        if operation == Operation::Resubmit && row.get::<_, Option<String>>(7).is_some() {
            return Err(ReviewRecoveryError::Ineligible {
                reason: ReviewRecoveryRefusal::PackageChanged,
                state,
                code,
            }
            .into());
        }
        let refusal = eligibility(
            operation,
            &state,
            code.as_deref(),
            withdrawn,
            result_recorded,
            request_retained,
            proposal_submitted,
        );
        if let Some(reason) = refusal {
            return Err(ReviewRecoveryError::Ineligible {
                reason,
                state,
                code,
            }
            .into());
        }
        let (next_state, next_code) = match operation {
            Operation::RetryApplication => unreachable!("application recovery handled above"),
            Operation::Resubmit => {
                // Retry the original request and key while preserving any concrete
                // acceptance. A different acceptance cannot replace it even
                // when the original selector delegated policy selection.
                // Only the delivery budgets and recovery window restart.
                transaction
                    .execute(
                        "UPDATE registry_internal.registry_proposal_review_submissions
                            SET state='pending',attempt_count=0,
                                result_poll_attempts=0,lease_until=NULL,last_error_code=NULL,
                                next_attempt_at=transaction_timestamp(),
                                next_result_poll_at=transaction_timestamp(),
                                recovery_deadline=transaction_timestamp()
                                    +(recovery_deadline-created_at),
                                updated_at=transaction_timestamp()
                          WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                        &[
                            &scope.action_id,
                            &scope.proposal_id,
                            &scope.submission_version,
                        ],
                    )
                    .await
                    .map_err(|_| ReviewRecoveryError::Unavailable)?;
                ("pending", None)
            }
            Operation::Close => {
                transaction
                    .execute(
                        "UPDATE registry_internal.registry_proposal_review_submissions
                            SET state='failed',lease_until=NULL,last_error_code=$4,
                                updated_at=transaction_timestamp()
                          WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
                        &[
                            &scope.action_id,
                            &scope.proposal_id,
                            &scope.submission_version,
                            &OPERATOR_CLOSED,
                        ],
                    )
                    .await
                    .map_err(|_| ReviewRecoveryError::Unavailable)?;
                ("failed", Some(OPERATOR_CLOSED))
            }
        };
        transaction.commit().await.map_err(|_| Stopped::AtCommit)?;
        Ok(ReviewRecovery {
            action_id: scope.action_id.to_owned(),
            proposal_id: scope.proposal_id.to_string(),
            submission_version: scope.submission_version,
            authority,
            previous_state: state,
            previous_code: code,
            state: next_state,
            code: next_code,
        })
    }
}

async fn retry_application_in_transaction(
    transaction: &tokio_postgres::Transaction<'_>,
    scope: ReviewRecoveryScope<'_>,
) -> Result<ReviewRecovery> {
    let row = transaction
        .query_opt(
            "SELECT j.state,j.last_error_code,COALESCE(s.authority,'builtin'),COALESCE(s.withdrawn,false),
                w.state='submitted' AND w.submission_version=j.submission_version,
                p.effect_digest=j.proposal_digest AND p.snapshot IS NOT NULL
                    AND p.snapshot->>'systemGrantRevision'=j.system_grant_revision,
                j.attempt_count<j.maximum_attempts,
                CASE WHEN w.submission_version=j.submission_version THEN w.blocked_reason END
           FROM registry_internal.registry_proposal_application_jobs j
           LEFT JOIN registry_internal.registry_proposal_review_submissions s
             USING (action_id,proposal_id,submission_version)
           JOIN registry_internal.registry_proposal_submissions p
             USING (action_id,proposal_id,submission_version)
           JOIN registry_internal.registry_proposal_state w
             USING (action_id,proposal_id)
          WHERE j.action_id=$1 AND j.proposal_id=$2 AND j.submission_version=$3
          FOR UPDATE OF j,p,w",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(|_| ReviewRecoveryError::Unavailable)?
        .ok_or(ReviewRecoveryError::NotFound)?;
    let state: String = row.get(0);
    let code: Option<String> = row.get(1);
    let reason = if row.get::<_, Option<String>>(7).is_some() {
        Some(ReviewRecoveryRefusal::PackageChanged)
    } else if row.get::<_, bool>(3) {
        Some(ReviewRecoveryRefusal::Withdrawn)
    } else if !row.get::<_, bool>(4) {
        Some(ReviewRecoveryRefusal::ProposalNotSubmitted)
    } else if row.get::<_, Option<bool>>(5) != Some(true) {
        Some(ReviewRecoveryRefusal::DetailErased)
    } else if state != "blocked"
        || !row.get::<_, bool>(6)
        || !matches!(
            code.as_deref(),
            Some("dependency-outage" | "source-unavailable" | "lease-expired")
        )
    {
        Some(ReviewRecoveryRefusal::ApplicationState)
    } else {
        None
    };
    if let Some(reason) = reason {
        return Err(ReviewRecoveryError::Ineligible {
            reason,
            state,
            code,
        });
    }
    transaction
        .execute(
            "UPDATE registry_internal.registry_proposal_application_jobs
            SET state='queued',claim_token=NULL,last_error_code=NULL,next_attempt_at=transaction_timestamp(),
                updated_at=transaction_timestamp()
          WHERE action_id=$1 AND proposal_id=$2 AND submission_version=$3",
            &[
                &scope.action_id,
                &scope.proposal_id,
                &scope.submission_version,
            ],
        )
        .await
        .map_err(|_| ReviewRecoveryError::Unavailable)?;
    Ok(ReviewRecovery {
        action_id: scope.action_id.to_owned(),
        proposal_id: scope.proposal_id.to_string(),
        submission_version: scope.submission_version,
        authority: row.get(2),
        previous_state: state,
        previous_code: code,
        state: "queued",
        code: None,
    })
}

#[cfg(feature = "postgres-test")]
#[doc(hidden)]
pub async fn retry_application_for_test(
    transaction: &tokio_postgres::Transaction<'_>,
    scope: ReviewRecoveryScope<'_>,
) -> Result<ReviewRecovery> {
    retry_application_in_transaction(transaction, scope).await
}

/// One `response` record: the request's fields with `outcome` and, for a
/// committed recovery, the submission before and after it.
fn with_outcome(request: &Value, outcome: &str, fields: Value) -> Value {
    let mut record = request.clone();
    if let Some(record) = record.as_object_mut() {
        record.insert("outcome".to_owned(), Value::from(outcome));
        if let Value::Object(fields) = fields {
            record.extend(fields);
        }
    }
    record
}

fn eligibility(
    operation: Operation,
    state: &str,
    code: Option<&str>,
    withdrawn: bool,
    result_recorded: bool,
    request_retained: bool,
    proposal_submitted: bool,
) -> Option<ReviewRecoveryRefusal> {
    if withdrawn {
        return Some(ReviewRecoveryRefusal::Withdrawn);
    }
    if result_recorded {
        return Some(ReviewRecoveryRefusal::ResultRecorded);
    }
    match operation {
        Operation::RetryApplication => Some(ReviewRecoveryRefusal::ApplicationState),
        Operation::Close => (state != "accepted").then_some(ReviewRecoveryRefusal::SubmissionState),
        Operation::Resubmit => {
            let lost = match (state, code) {
                ("accepted", Some(code)) => code == UNKNOWN_TO_AUTHORITY,
                ("failed", Some(code)) => RESUBMITTABLE_FAILURE_CODES.contains(&code),
                _ => false,
            };
            if !lost {
                Some(ReviewRecoveryRefusal::SubmissionState)
            } else if !request_retained {
                Some(ReviewRecoveryRefusal::DetailErased)
            } else if !proposal_submitted {
                Some(ReviewRecoveryRefusal::ProposalNotSubmitted)
            } else {
                None
            }
        }
    }
}

fn unavailable(_error: ProposalRetentionError) -> ReviewRecoveryError {
    ReviewRecoveryError::Unavailable
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resubmit(state: &str, code: Option<&str>) -> Option<ReviewRecoveryRefusal> {
        eligibility(Operation::Resubmit, state, code, false, false, true, true)
    }

    #[test]
    fn resubmit_accepts_only_reviews_the_authority_lost_or_breg_stopped_waiting_for() {
        assert_eq!(resubmit("accepted", Some(UNKNOWN_TO_AUTHORITY)), None);
        for code in RESUBMITTABLE_FAILURE_CODES {
            assert_eq!(resubmit("failed", Some(code)), None, "{code}");
        }
        for (state, code) in [
            ("accepted", None),
            ("accepted", Some("result-lookup-uncertain")),
            ("failed", Some("remote-refused")),
            ("failed", Some("result-expired")),
            ("pending", None),
            ("uncertain", Some("remote-uncertain")),
            ("cancelling", None),
            ("cancelled", None),
        ] {
            assert_eq!(
                resubmit(state, code),
                Some(ReviewRecoveryRefusal::SubmissionState),
                "{state} {code:?}"
            );
        }
        let lost = ("accepted", Some(UNKNOWN_TO_AUTHORITY));
        for (withdrawn, result, retained, submitted, refusal) in [
            (true, false, true, true, ReviewRecoveryRefusal::Withdrawn),
            (
                false,
                true,
                true,
                true,
                ReviewRecoveryRefusal::ResultRecorded,
            ),
            (
                false,
                false,
                false,
                true,
                ReviewRecoveryRefusal::DetailErased,
            ),
            (
                false,
                false,
                true,
                false,
                ReviewRecoveryRefusal::ProposalNotSubmitted,
            ),
        ] {
            assert_eq!(
                eligibility(
                    Operation::Resubmit,
                    lost.0,
                    lost.1,
                    withdrawn,
                    result,
                    retained,
                    submitted
                ),
                Some(refusal)
            );
        }
    }

    #[test]
    fn close_accepts_only_an_accepted_review_without_a_result() {
        let close = |state, withdrawn, result| {
            eligibility(Operation::Close, state, None, withdrawn, result, true, true)
        };
        assert_eq!(close("accepted", false, false), None);
        assert_eq!(
            close("accepted", true, false),
            Some(ReviewRecoveryRefusal::Withdrawn)
        );
        assert_eq!(
            close("accepted", false, true),
            Some(ReviewRecoveryRefusal::ResultRecorded)
        );
        for state in ["pending", "submitting", "uncertain", "cancelling", "failed"] {
            assert_eq!(
                close(state, false, false),
                Some(ReviewRecoveryRefusal::SubmissionState),
                "{state}"
            );
        }
    }
}
