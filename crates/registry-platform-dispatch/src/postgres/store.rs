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
use crate::retry::{remaining_attempt_budget, JobPolicy};

/// One PostgreSQL client the store lends the core for one transaction.
pub type DispatchConnection = Box<dyn DerefMut<Target = tokio_postgres::Client> + Send>;

/// A decoded consumer row: the policy the job was captured with and the
/// consumer's own value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded<T> {
    pub policy: JobPolicy,
    pub job: T,
}

/// Why the store refused a claimed row.
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
            Self::RetryPending => "retry_pending",
            Self::DeadLettered => "dead_lettered",
            Self::Unknown => "unknown",
            Self::Expired => "expired",
            Self::ReplayPending => "replay_pending",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A transition the core makes without a worker's send: recovery, expiry,
/// replay, and cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transition {
    /// A lease lapsed and the job moved to the disposition its policy owed.
    LeaseLapsed(Disposition),
    /// An undispatched job expired from `from`.
    Expired { from: JobState },
    /// An operator replayed a terminal job from `from`.
    Replayed { from: JobState },
    /// A pending job was withdrawn.
    Cancelled,
}

impl Transition {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeaseLapsed(_) => "lease_lapsed",
            Self::Expired { .. } => "expired",
            Self::Replayed { .. } => "replayed",
            Self::Cancelled => "cancelled",
        }
    }

    #[must_use]
    pub const fn disposition(self) -> Disposition {
        match self {
            Self::LeaseLapsed(disposition) => disposition,
            Self::Expired { .. } => Disposition::Expired,
            Self::Replayed { .. } => Disposition::ReplayPending,
            Self::Cancelled => Disposition::Cancelled,
        }
    }
}

/// The audit of one transition that is not an attempt, written inside the
/// transition's own transaction.
#[derive(Clone, Copy, Debug)]
pub struct TransitionAudit<'a, R> {
    pub key: &'a JobKey,
    /// The generation the job has after the transition.
    pub generation: i64,
    /// The attempt the job has after the transition.
    pub attempt: i16,
    pub record: &'a R,
    pub transition: Transition,
}

/// The audit of one attempt, written inside the claim transaction before
/// egress and inside the finish transaction after it.
#[derive(Clone, Copy, Debug)]
pub enum AttemptAudit<'a, D> {
    Started,
    Finished {
        sent: &'a Sent<D>,
        disposition: Disposition,
    },
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
}

/// Everything product-owned the core's transactions need.
///
/// Every audit hook runs inside the transaction whose transition it
/// records, so an audit that fails rolls the transition back, and an attempt
/// is audited and committed before any send.
#[async_trait]
pub trait DispatchStore: Send + Sync + 'static {
    /// What a claim decodes for the transport.
    type Job: Send + Sync + 'static;
    /// What a recovery, expiry, or operator row decodes for the audit.
    type Record: Send + Sync + 'static;
    /// The product's own detail of one send, handed back to its audit and
    /// columns.
    type Detail: Send + Sync + 'static;

    /// Lend one client for one transaction.
    async fn connection(&self) -> Result<DispatchConnection, DispatchError>;

    /// Check the transaction is connected to the database the product
    /// expects, before any read or write.
    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DispatchError>;

    /// Decode the claim columns from index `first`.
    fn decode_claim(&self, row: &Row, first: usize) -> Result<Decoded<Self::Job>, ClaimRefusal>;

    /// Decode the lapsed-lease columns from index `first`.
    fn decode_lapsed(
        &self,
        row: &Row,
        first: usize,
    ) -> Result<Decoded<Self::Record>, DispatchError>;

    /// Decode the expiry columns from index `first`.
    fn decode_expired(&self, row: &Row, first: usize) -> Result<Self::Record, DispatchError>;

    /// Decode the operator target columns from index `first`, or refuse the
    /// action with `None`.
    fn decode_target(
        &self,
        row: &Row,
        first: usize,
        key: &JobKey,
        action: TargetAction,
    ) -> Result<Option<Self::Record>, DispatchError>;

    /// Audit an attempt start or finish.
    async fn record_attempt_audit(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<Self::Job>,
        audit: AttemptAudit<'_, Self::Detail>,
    ) -> Result<(), DispatchError>;

    /// Audit a transition that is not an attempt.
    async fn record_transition_audit(
        &self,
        transaction: &Transaction<'_>,
        audit: TransitionAudit<'_, Self::Record>,
    ) -> Result<(), DispatchError>;

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

    /// Product writes after an expiry transition, in the same transaction.
    async fn after_expired(
        &self,
        _transaction: &Transaction<'_>,
        _key: &JobKey,
        _record: &Self::Record,
    ) -> Result<(), DispatchError> {
        Ok(())
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
