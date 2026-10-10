// SPDX-License-Identifier: Apache-2.0

//! The seams a consumer implements: its store (connection, decoding, audit,
//! and extra columns) and its transport.

use std::ops::DerefMut;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use super::sql::Columns;
use super::table::{JobKey, JobState};
use crate::outcome::{DispatchError, Sent};
use crate::retry::{remaining_attempt_budget, JobPolicy, UncertainOutcome};

/// One PostgreSQL client the store lends the core for one transaction.
pub type DispatchConnection = Box<dyn DerefMut<Target = tokio_postgres::Client> + Send>;

/// A decoded consumer row: the policy the job was captured with and the
/// consumer's own value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded<T> {
    pub policy: JobPolicy,
    pub job: T,
}

/// Why the store refused a claimed row. A store that
/// [quarantines](DispatchStore::quarantines) has the row quarantined
/// instead, and the claim goes on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimRefusal {
    /// The row could not be read. The claim fails without an operational
    /// event.
    Unavailable,
    /// The row's captured policy is not one this consumer accepts. The
    /// claim fails with [`TransitionCode::ClaimPolicyRefused`].
    PolicyRefused,
}

/// One leased job, frozen between the lease commit and its finish.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LeasedJob<J> {
    pub key: JobKey,
    pub generation: i64,
    /// This attempt, counted from one.
    pub attempt: i16,
    /// The database clock when the lease was taken.
    pub attempt_started_at: SystemTime,
    pub lease_token: Uuid,
    pub policy: JobPolicy,
    pub job: J,
}

impl<J> LeasedJob<J> {
    /// The fence every write on behalf of this lease carries.
    #[must_use]
    pub fn fence(&self) -> Fence<'_> {
        Fence {
            id: self.key.id(),
            part: self.key.part(),
            generation: self.generation,
            attempt: self.attempt,
            lease_token: self.lease_token,
        }
    }

    /// The attempt budget left at `now`, or `None` once it is spent.
    #[must_use]
    pub fn remaining_budget(&self, now: SystemTime) -> Option<Duration> {
        remaining_attempt_budget(self.policy.attempt_timeout, self.attempt_started_at, now)
    }
}

/// The identity of one lease: a write that carries a stale fence matches no
/// row, so a worker that lost its lease can never overwrite the work of the
/// worker that replaced it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fence<'a> {
    pub id: Uuid,
    pub part: &'a str,
    pub generation: i64,
    pub attempt: i16,
    pub lease_token: Uuid,
}

/// A lease that lapsed before its worker finished it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LapsedJob<R> {
    pub key: JobKey,
    pub generation: i64,
    pub attempt: i16,
    pub lease_token: Uuid,
    pub policy: JobPolicy,
    pub record: R,
}

/// The disposition one transition leaves a job in, as the audit states it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Disposition {
    Leased,
    Delivered,
    RetryPending,
    DeadLettered,
    Unknown,
    Expired,
    ReplayPending,
    Cancelled,
}

impl Disposition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leased => "leased",
            Self::Delivered => "delivered",
            Self::RetryPending => "retry-pending",
            Self::DeadLettered => "dead-lettered",
            Self::Unknown => "unknown",
            Self::Expired => "expired",
            Self::ReplayPending => "replay-pending",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A transition the core makes without a worker's send: recovery, expiry,
/// and cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transition {
    /// A lease lapsed and the job moved to the disposition its policy owed.
    LeaseLapsed(Disposition),
    /// An undispatched job reached its expiry in `from` and moved to
    /// `disposition`: [`Disposition::Expired`], or [`Disposition::Unknown`]
    /// when its policy holds uncertain attempts and an earlier attempt may
    /// have reached its receiver.
    Expired {
        from: JobState,
        disposition: Disposition,
    },
    /// A pending job was withdrawn.
    Cancelled,
}

impl Transition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseLapsed(_) => "lease-lapsed",
            Self::Expired { .. } => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub const fn disposition(self) -> Disposition {
        match self {
            Self::LeaseLapsed(disposition) => disposition,
            Self::Expired { disposition, .. } => disposition,
            Self::Cancelled => Disposition::Cancelled,
        }
    }
}

/// One non-send transition's audit identity and intended disposition.
#[derive(Clone, Debug)]
pub struct TransitionAudit<R> {
    pub key: JobKey,
    /// The generation the job has after the transition.
    pub generation: i64,
    /// The attempt the job has after the transition.
    pub attempt: i16,
    pub record: R,
    pub transition: Transition,
}

/// What became of a requested non-send transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionOutcome {
    Committed,
    Refused,
    Unfinished,
}

/// One attempt's direct audit lifecycle.
#[derive(Clone, Copy, Debug)]
pub enum AttemptAudit<'a, D> {
    Started,
    Finished {
        sent: &'a Sent<D>,
        disposition: Disposition,
    },
    /// A lease request whose commit rolled back or could not be resolved.
    Interrupted {
        disposition: Disposition,
    },
}

/// The request/response lifecycle of one operator replay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayOutcome {
    Requested,
    Committed,
    Refused,
    Unfinished,
}

/// One direct replay audit entry.
#[derive(Clone, Debug)]
pub struct ReplayAudit<R> {
    pub key: JobKey,
    /// The generation the replay would create.
    pub generation: i64,
    pub record: R,
    pub from: JobState,
    pub outcome: ReplayOutcome,
}

/// One consumer quarantine's audit identity and intended disposition.
#[derive(Clone, Debug)]
pub struct QuarantineAudit {
    pub key: JobKey,
    pub generation: i64,
    pub attempt: i16,
    pub from: JobState,
    pub reason: QuarantineReason,
    pub disposition: Option<JobState>,
}

/// Which operator action a target row is read for.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetAction {
    Replay,
    Cancel,
}

/// The claim-path step that refused, reported through the store's
/// operational event hook.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TransitionCode {
    ClaimIdentityRefused,
    ClaimRecoveryFailed,
    ClaimSelectFailed,
    ClaimPolicyRefused,
    ClaimUpdateFailed,
    ClaimAuditFailed,
    ClaimCommitFailed,
}

/// A value-free operational event.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DispatchEvent {
    /// One worker iteration failed.
    IterationFailed,
    /// One claim-path transition refused.
    TransitionFailed(TransitionCode),
    /// One job expired undispatched, reported after its transition
    /// committed.
    JobExpired,
    /// One job was quarantined, reported after its quarantine committed.
    JobQuarantined(QuarantineReason),
}

/// Which step failed on a row the core quarantined.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum QuarantineReason {
    /// Recovering the row's lapsed lease failed.
    RecoveryFailed,
    /// The expiry sweep failed on the row.
    ExpiryFailed,
    /// The claimed row could not be read as a claimable job.
    ClaimUnreadable,
    /// The claimed row's captured policy is not one the consumer accepts.
    PolicyRefused,
    /// Expiring the claimed row past its captured policy's expiry failed.
    ClaimExpiryFailed,
}

/// One row the core asks the store to quarantine. The claim transaction
/// holds the row locked, and every write the failed step made to it has
/// been rolled back.
#[derive(Clone, Copy, Debug)]
pub struct Quarantine<'a> {
    pub key: &'a JobKey,
    pub generation: i64,
    pub attempt: i16,
    /// The state the row was selected in.
    pub from: JobState,
    pub reason: QuarantineReason,
    /// Whether an attempt of the row's generation may have reached its
    /// receiver: the row was leased, or
    /// [`DispatchStore::may_have_reached_receiver`] said so.
    pub may_have_reached_receiver: bool,
}

/// What the store did with a row the core asked it to quarantine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuarantineDisposition {
    /// The store does not quarantine: the claim fails as it would have
    /// without the request.
    Unsupported,
    /// The store moved the row to this terminal state and audited it.
    Quarantined(JobState),
}

/// Everything product-owned the core needs.
///
/// Transaction callbacks keep consumer relational writes atomic with the
/// transition. Audit callbacks write directly: request entries are accepted
/// before their protected transition and outcome entries only after commit is
/// established.
#[async_trait]
pub trait DispatchStore: Send + Sync + 'static {
    /// What a claim decodes for the transport.
    type Job: Clone + Send + Sync + 'static;
    /// What a recovery, expiry, or operator row decodes for the audit.
    type Record: Clone + Send + Sync + 'static;
    /// The product's own detail of one send, handed back to its audit and
    /// columns.
    type Detail: Clone + Send + Sync + 'static;
    /// Product context captured before work moves into an owned task.
    type Context: Clone + Send + Sync + 'static;

    /// Capture task-local product context before an owned transition starts.
    fn capture_context(&self) -> Self::Context;

    /// Lend one client for one transaction.
    async fn connection(&self) -> Result<DispatchConnection, DispatchError>;

    /// Check the transaction is connected to the database the product
    /// expects, before any read or write.
    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DispatchError>;

    /// Decode the claim columns from index `first`.
    fn decode_claim(&self, row: &Row, first: usize) -> Result<Decoded<Self::Job>, ClaimRefusal>;

    /// The audit record of a claimed job, used when the claim expires it
    /// instead of leasing it.
    fn claim_record(&self, job: &Self::Job) -> Self::Record;

    /// Decode the lapsed-lease columns from index `first`.
    fn decode_lapsed(
        &self,
        row: &Row,
        first: usize,
    ) -> Result<Decoded<Self::Record>, DispatchError>;

    /// Decode the expiry columns from index `first`.
    fn decode_expired(&self, row: &Row, first: usize) -> Result<Self::Record, DispatchError>;

    /// Decode the captured uncertain-outcome policy of the job an expiry
    /// sweep selected, from the same columns [`DispatchStore::decode_expired`]
    /// reads. A pending job under [`UncertainOutcome::RetryThenHold`] that
    /// [`DispatchStore::may_have_reached_receiver`] answers `true` for is
    /// held `unknown` instead of expired. The default answers
    /// [`UncertainOutcome::Retry`], so every selected job expires, which
    /// suits a consumer whose expiry selection carries no policy.
    fn decode_expired_on_uncertain(
        &self,
        _row: &Row,
        _first: usize,
    ) -> Result<UncertainOutcome, DispatchError> {
        Ok(UncertainOutcome::Retry)
    }

    /// Decode the operator target columns from index `first`, or refuse the
    /// action with `None`.
    fn decode_target(
        &self,
        row: &Row,
        first: usize,
        key: &JobKey,
        action: TargetAction,
    ) -> Result<Option<Self::Record>, DispatchError>;

    /// Apply consumer relational attempt writes in the transition transaction.
    async fn write_attempt(
        &self,
        _transaction: &Transaction<'_>,
        _job: &LeasedJob<Self::Job>,
        _audit: AttemptAudit<'_, Self::Detail>,
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    /// Apply consumer relational transition writes in the transition transaction.
    async fn write_transition(
        &self,
        _transaction: &Transaction<'_>,
        _audit: &TransitionAudit<Self::Record>,
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    /// Audit an attempt start or outcome directly.
    async fn record_attempt_audit(
        &self,
        job: &LeasedJob<Self::Job>,
        audit: AttemptAudit<'_, Self::Detail>,
        context: &Self::Context,
    ) -> Result<(), DispatchError>;

    /// Audit a committed transition that is not an attempt.
    async fn record_transition_audit(
        &self,
        audit: &TransitionAudit<Self::Record>,
        outcome: TransitionOutcome,
        context: &Self::Context,
    ) -> Result<(), DispatchError>;

    /// Accept the intent audit before a non-send transition mutates its row.
    async fn begin_transition_audit(
        &self,
        _audit: &TransitionAudit<Self::Record>,
        _context: &Self::Context,
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    /// Audit one replay request or response directly.
    async fn record_replay_audit(
        &self,
        audit: &ReplayAudit<Self::Record>,
        context: &Self::Context,
    ) -> Result<(), DispatchError>;

    /// Audit one committed quarantine directly.
    async fn record_quarantine_audit(
        &self,
        _audit: &QuarantineAudit,
        _outcome: TransitionOutcome,
        _context: &Self::Context,
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    /// Accept quarantine intent before the consumer mutates the selected row.
    async fn begin_quarantine_audit(
        &self,
        _quarantine: Quarantine<'_>,
        _context: &Self::Context,
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    /// Report one value-free operational event.
    fn operational_event(&self, event: DispatchEvent);

    /// Extra columns for a lapsed-lease transition, computed inside the
    /// recovery transaction before its audit.
    async fn lapsed_columns(
        &self,
        _transaction: &Transaction<'_>,
        _lapsed: &LapsedJob<Self::Record>,
        _disposition: Disposition,
    ) -> Result<Columns, DispatchError> {
        Ok(Columns::new())
    }

    /// Extra columns for a finished attempt, computed after its audit.
    fn finished_columns(
        &self,
        _job: &LeasedJob<Self::Job>,
        _sent: &Sent<Self::Detail>,
        _disposition: Disposition,
    ) -> Result<Columns, DispatchError> {
        Ok(Columns::new())
    }

    /// Product writes after a finished attempt's transition, in the same
    /// transaction.
    async fn after_finished(
        &self,
        _transaction: &Transaction<'_>,
        _job: &LeasedJob<Self::Job>,
        _disposition: Disposition,
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    /// Product writes after an expiry transition that expired the job, in
    /// the same transaction. A job held `unknown` at its expiry keeps what
    /// an operator needs to settle it, so this is not called for it.
    async fn after_expired(
        &self,
        _transaction: &Transaction<'_>,
        _key: &JobKey,
        _record: &Self::Record,
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    /// Whether any attempt of the job's current generation numbered at most
    /// `attempt` may have reached its receiver, read in the transaction that
    /// holds the job's row locked or its lease fenced: for example one
    /// answered [`crate::SendOutcome::MaybeSent`] or cut off by a lapsed
    /// lease, that the job's policy then retried. The core refuses to cancel
    /// a pending job this answers `true` for, holds such a job `unknown` at
    /// its expiry when its policy is [`UncertainOutcome::RetryThenHold`], and
    /// hands the answer to [`DispatchStore::quarantine`]; each of these asks
    /// about the job's latest attempt. A finish under
    /// [`UncertainOutcome::RetryThenHold`] whose transient or permanent
    /// answer would dead-letter or expire the job asks about the attempts
    /// before the finishing one, and holds the job `unknown` when this
    /// answers `true`.
    ///
    /// The default answers `true` whenever `attempt` is at least one. A
    /// consumer that records which attempts were definitely not sent
    /// overrides it, so a job that only failed transiently stays
    /// cancellable and still dead-letters or expires.
    async fn may_have_reached_receiver(
        &self,
        _transaction: &Transaction<'_>,
        _key: &JobKey,
        _generation: i64,
        attempt: i16,
    ) -> Result<bool, DispatchError> {
        Ok(attempt > 0)
    }

    /// Whether this consumer quarantines rows the claim cannot take.
    ///
    /// When it does, the claim runs each selected row's lease recovery,
    /// expiry, and claim decoding inside a savepoint, and a row whose step
    /// fails is rolled back to the savepoint and handed to
    /// [`DispatchStore::quarantine`] instead of failing the claim, so one
    /// poisoned row no longer stalls every row behind it. When it does not,
    /// no savepoint is taken and a failing row fails the claim.
    fn quarantines(&self) -> bool {
        false
    }

    /// Move one row the claim cannot take to a terminal state of this
    /// consumer's choosing, inside the claim transaction.
    ///
    /// The state must be `dead-lettered`, `expired`, `unknown`, or
    /// `cancelled`, and a state the expiry sweep selects must have
    /// `expired_at` stamped, so the row leaves the claim, recovery, and
    /// sweep sets for good; the core checks the row afterwards and fails the
    /// claim when it could be selected again. Whether an operator may replay
    /// the row is the consumer's [`DispatchConfig::replayable`] set.
    ///
    /// [`DispatchConfig::replayable`]: super::DispatchConfig::replayable
    async fn quarantine(
        &self,
        _transaction: &Transaction<'_>,
        _quarantine: Quarantine<'_>,
    ) -> Result<QuarantineDisposition, DispatchError> {
        Ok(QuarantineDisposition::Unsupported)
    }
}

/// The send half of dispatch: one attempt of one leased job.
///
/// The transport runs after the lease and its attempt audit have committed,
/// within the budget [`LeasedJob::remaining_budget`] reports. An `Err`
/// records nothing and leaves the lease to lapse, so lease-expiry recovery
/// decides the attempt under the job's uncertain-outcome policy.
#[async_trait]
pub trait DispatchTransport: Send + Sync {
    type Job: Send + Sync;
    type Detail: Send;

    async fn send(&self, job: &LeasedJob<Self::Job>) -> Result<Sent<Self::Detail>, DispatchError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_disposition_is_spelled_in_kebab_case() {
        let spellings = [
            (Disposition::Leased, "leased"),
            (Disposition::Delivered, "delivered"),
            (Disposition::RetryPending, "retry-pending"),
            (Disposition::DeadLettered, "dead-lettered"),
            (Disposition::Unknown, "unknown"),
            (Disposition::Expired, "expired"),
            (Disposition::ReplayPending, "replay-pending"),
            (Disposition::Cancelled, "cancelled"),
        ];
        for (disposition, spelling) in spellings {
            assert_eq!(disposition.as_str(), spelling);
        }
    }

    #[test]
    fn every_transition_is_spelled_in_kebab_case() {
        let spellings = [
            (
                Transition::LeaseLapsed(Disposition::Unknown),
                "lease-lapsed",
            ),
            (
                Transition::Expired {
                    from: JobState::Pending,
                    disposition: Disposition::Expired,
                },
                "expired",
            ),
            (Transition::Cancelled, "cancelled"),
        ];
        for (transition, spelling) in spellings {
            assert_eq!(transition.as_str(), spelling);
        }
    }

    #[test]
    fn a_dead_lettered_disposition_is_spelled_like_its_stored_state() {
        assert_eq!(
            Disposition::DeadLettered.as_str(),
            JobState::DeadLettered.as_str()
        );
    }
}
