// SPDX-License-Identifier: Apache-2.0

//! The fenced lease machine: claim, finish, lease-expiry recovery, expiry,
//! replay, and cancellation over one product's job table.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio_postgres::types::ToSql;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use super::sql::{state_list, Columns, DispatchSql, SelectSql};
use super::store::{
    AttemptAudit, ClaimRefusal, Decoded, DispatchEvent, DispatchStore, DispatchTransport,
    Disposition, Fence, LapsedJob, LeasedJob, Quarantine, QuarantineAudit, QuarantineDisposition,
    QuarantineReason, ReplayAudit, ReplayOutcome, TargetAction, Transition, TransitionAudit,
    TransitionCode, TransitionOutcome,
};
use super::table::{JobKey, JobState, JobTable};
use crate::outcome::{ConfigError, DispatchError, SendOutcome, Sent};
use crate::retry::{AttemptTimeoutBound, JobPolicy, UncertainOutcome};

/// How long a lease outlives its attempt timeout, so the worker that sent
/// can still record the outcome before recovery may take the job over.
pub const LEASE_FINALIZATION_ALLOWANCE: Duration = Duration::from_secs(5);

/// Short bounded waits between fresh reads after PostgreSQL returned a COMMIT
/// error. A caller is already failing while these run.
const READ_BACK_BACKOFF: [Duration; 2] = [Duration::from_millis(50), Duration::from_millis(100)];

/// One consumer's dispatch configuration.
#[derive(Clone, Debug)]
pub struct DispatchConfig {
    pub table: JobTable,
    pub sql: DispatchSql,
    /// The attempt timeouts this consumer accepts from captured policies.
    pub attempt_timeout: AttemptTimeoutBound,
    /// The terminal states an operator may replay. Only
    /// [`JobState::DeadLettered`] and [`JobState::Unknown`] are accepted.
    pub replayable: &'static [JobState],
}

/// What one dispatch iteration did.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DispatchOutcome {
    /// No job was due.
    Idle,
    Delivered,
    RetryScheduled,
    DeadLettered,
    Unknown,
    Expired,
}

/// What one claim did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Claim<J> {
    /// No job was due.
    Idle,
    /// A job is leased and its attempt audit committed: the caller may send
    /// it.
    Leased(LeasedJob<J>),
    /// The due job's captured policy had expired, so the claim expired it
    /// instead of leasing it, or held it `unknown` when an earlier attempt
    /// may have reached its receiver. Nothing may be sent.
    Expired,
}

impl<J> Claim<J> {
    /// The leased job, when the claim leased one.
    #[must_use]
    pub fn leased(self) -> Option<LeasedJob<J>> {
        match self {
            Self::Leased(job) => Some(job),
            Self::Idle | Self::Expired => None,
        }
    }
}

/// What a cancellation did.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CancelOutcome {
    Cancelled,
    /// The job had already left `pending`: it was claimed, finished, or
    /// withdrawn first. The state it was found in is returned.
    NotCancellable(JobState),
    /// The job is pending, but an earlier attempt of its generation may
    /// have reached its receiver, so it was left pending.
    MayHaveReachedReceiver,
}

/// Why a fenced read of a leased job returned nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LeasedReadError<E> {
    /// The lease is gone or stale, or the database was unavailable.
    Unavailable,
    /// The row was read under the lease and the consumer's decoder refused
    /// it.
    Refused(E),
}

/// The transition a lease ends in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Next {
    Delivered,
    Retry { delay_ms: i64 },
    DeadLettered,
    Unknown,
    Expired,
}

impl Next {
    const fn disposition(self) -> Disposition {
        match self {
            Self::Delivered => Disposition::Delivered,
            Self::Retry { .. } => Disposition::RetryPending,
            Self::DeadLettered => Disposition::DeadLettered,
            Self::Unknown => Disposition::Unknown,
            Self::Expired => Disposition::Expired,
        }
    }

    const fn outcome(self) -> DispatchOutcome {
        match self {
            Self::Delivered => DispatchOutcome::Delivered,
            Self::Retry { .. } => DispatchOutcome::RetryScheduled,
            Self::DeadLettered => DispatchOutcome::DeadLettered,
            Self::Unknown => DispatchOutcome::Unknown,
            Self::Expired => DispatchOutcome::Expired,
        }
    }
}

struct Statements {
    claim: String,
    lease: String,
    /// Expires a claimed pending job whose captured policy has expired.
    expire_claimed: String,
    /// Holds `unknown` a pending job that reached its expiry after an
    /// attempt that may have reached its receiver.
    hold_expiring: String,
    lapsed: String,
    expiry: Option<(String, String)>,
    target: String,
    /// Reads back a quarantined row's state when it is terminal and no
    /// claim, recovery, or sweep would select it again.
    quarantined: String,
}

/// One row a claim transaction selected and holds locked.
struct Selected {
    key: JobKey,
    generation: i64,
    attempt: i16,
    from: JobState,
}

impl Selected {
    /// Read the key, generation, and attempt every claim-path selection
    /// starts with.
    fn read(row: &Row, from: JobState) -> Result<Self, DispatchError> {
        Ok(Self {
            key: read_key(row)?,
            generation: row.try_get::<_, i64>(2)?,
            attempt: row.try_get::<_, i16>(3)?,
            from,
        })
    }
}

/// Why one selected row could not be taken: the reason a quarantining
/// store is given, and the refusal a claim reports when the row is not
/// quarantined.
#[derive(Clone, Copy)]
struct RowFailure {
    reason: QuarantineReason,
    refusal: Option<TransitionCode>,
}

/// What a claim does with its due row.
enum Taken<J, R> {
    /// The row expired at claim instead of being leased.
    Expired(TransitionAudit<R>),
    /// The row is due for `attempt`.
    Due { decoded: Decoded<J>, attempt: i16 },
}

/// The events a claim transaction reports once it has committed.
struct Committed<R> {
    transitions: Vec<TransitionAudit<R>>,
    quarantines: Vec<QuarantineAudit>,
}

impl<R> Default for Committed<R> {
    fn default() -> Self {
        Self {
            transitions: Vec::new(),
            quarantines: Vec::new(),
        }
    }
}

/// One locked job an expiry transition is about to take.
struct Expiring<'a, R> {
    key: &'a JobKey,
    generation: i64,
    attempt: i16,
    from: JobState,
    disposition: Disposition,
    record: &'a R,
}

/// One job row read on a fresh connection after COMMIT returned an error.
struct ObservedJob {
    state: JobState,
    generation: i64,
    attempt: i16,
    lease_token: Option<Uuid>,
    expired: bool,
}

struct Inner<S> {
    store: S,
    table: JobTable,
    bound: AttemptTimeoutBound,
    replayable: &'static [JobState],
    statements: Statements,
}

/// The dispatch core over one consumer's store and job table.
pub struct Dispatcher<S: DispatchStore> {
    inner: Arc<Inner<S>>,
}

impl<S: DispatchStore> Clone for Dispatcher<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: DispatchStore> Dispatcher<S> {
    /// Bind the core to one consumer. Every statement is rendered and
    /// checked here, once.
    ///
    /// # Errors
    ///
    /// [`ConfigError::SqlFragment`] when a SQL fragment could escape its
    /// statement, and [`ConfigError::StateSet`] when the expiry or replay
    /// state set names a state its transition cannot start from.
    pub fn new(store: S, config: DispatchConfig) -> Result<Self, ConfigError> {
        let DispatchConfig {
            table,
            sql,
            attempt_timeout,
            replayable,
        } = config;
        if replayable
            .iter()
            .any(|state| !matches!(state, JobState::DeadLettered | JobState::Unknown))
        {
            return Err(ConfigError::StateSet);
        }
        let statements = render_statements(&table, &sql)?;
        Ok(Self {
            inner: Arc::new(Inner {
                store,
                table,
                bound: attempt_timeout,
                replayable,
                statements,
            }),
        })
    }

    #[must_use]
    pub fn store(&self) -> &S {
        &self.inner.store
    }

    #[must_use]
    pub fn table(&self) -> &JobTable {
        &self.inner.table
    }

    /// Claim, send, and finish at most one due job.
    ///
    /// The lease and its attempt audit commit before the transport runs, so
    /// dispatch is at-least-once when a process stops after the send and
    /// before the finish; lease-expiry recovery then decides the attempt
    /// under the job's uncertain-outcome policy. A transport `Err` records
    /// nothing and leaves the lease to that recovery.
    ///
    /// # Errors
    ///
    /// [`DispatchError::Unavailable`] when the claim, the send, or the
    /// finish fails.
    pub async fn dispatch_once<T>(&self, transport: &T) -> Result<DispatchOutcome, DispatchError>
    where
        T: DispatchTransport<Job = S::Job, Detail = S::Detail> + ?Sized,
    {
        let job = match self.claim().await? {
            Claim::Idle => return Ok(DispatchOutcome::Idle),
            Claim::Expired => return Ok(DispatchOutcome::Expired),
            Claim::Leased(job) => job,
        };
        let sent = transport.send(&job).await?;
        self.finish(&job, sent).await
    }

    /// Lease at most one due job and commit its attempt audit.
    ///
    /// The claim transaction first recovers at most one lapsed lease and
    /// expires at most one undispatched job, so both make progress on every
    /// poll. A due job whose captured policy has expired is expired here,
    /// whatever the consumer's claim selection says, and is never leased. A
    /// leased job is committed as leased: the caller may send it.
    ///
    /// For a store that [quarantines](DispatchStore::quarantines), a row
    /// whose recovery, expiry, or claim decoding fails is quarantined and
    /// the claim goes on to the next row, so one poisoned row does not stall
    /// the rows behind it. Every quarantine moves a row out of the claim
    /// set for good, so the claim ends.
    ///
    /// # Errors
    ///
    /// [`DispatchError::Unavailable`] on any refusal. Refusals an operator
    /// must see are reported through [`DispatchStore::operational_event`].
    pub async fn claim(&self) -> Result<Claim<S::Job>, DispatchError> {
        let context = self.inner.store.capture_context();
        let dispatcher = self.clone();
        tokio::spawn(async move { dispatcher.claim_owned(&context).await })
            .await
            .map_err(|_| DispatchError::Unavailable)?
    }

    async fn claim_owned(&self, context: &S::Context) -> Result<Claim<S::Job>, DispatchError> {
        loop {
            if let Some(claim) = self.claim_in_transaction(context).await? {
                return Ok(claim);
            }
        }
    }

    /// One claim transaction, or `None` when its due row was quarantined
    /// and the claim should select the next.
    async fn claim_in_transaction(
        &self,
        context: &S::Context,
    ) -> Result<Option<Claim<S::Job>>, DispatchError> {
        let store = &self.inner.store;
        let mut client = store.connection().await?;
        let transaction = client.transaction().await?;
        if store.verify_transaction(&transaction).await.is_err() {
            self.refused(TransitionCode::ClaimIdentityRefused);
            return Err(DispatchError::Unavailable);
        }
        let mut committed = Committed::default();
        self.recover_lapsed_lease(&transaction, &mut committed, context)
            .await?;
        self.expire_one(&transaction, &mut committed, context)
            .await?;
        let row = transaction
            .query_opt(&self.inner.statements.claim, &[])
            .await
            .map_err(|_| {
                self.refused(TransitionCode::ClaimSelectFailed);
                DispatchError::Unavailable
            })?;
        let Some(row) = row else {
            if transaction.commit().await.is_err() {
                self.record_resolved(committed, context).await;
                self.refused(TransitionCode::ClaimCommitFailed);
                return Err(DispatchError::Unavailable);
            }
            self.record_committed(&committed, context).await?;
            self.report(&committed);
            return Ok(Some(Claim::Idle));
        };
        let selected = Selected::read(&row, JobState::Pending)?;
        let taken = self
            .guarded(
                &transaction,
                &selected,
                &mut committed,
                context,
                self.take_claimed(&transaction, &row, &selected, context),
            )
            .await?;
        let (decoded, attempt) = match taken {
            None => {
                if transaction.commit().await.is_err() {
                    self.record_resolved(committed, context).await;
                    self.refused(TransitionCode::ClaimCommitFailed);
                    return Err(DispatchError::Unavailable);
                }
                self.record_committed(&committed, context).await?;
                self.report(&committed);
                return Ok(None);
            }
            Some(Taken::Expired(audit)) => {
                committed.transitions.push(audit);
                if transaction.commit().await.is_err() {
                    self.record_resolved(committed, context).await;
                    self.refused(TransitionCode::ClaimCommitFailed);
                    return Err(DispatchError::Unavailable);
                }
                self.record_committed(&committed, context).await?;
                self.report(&committed);
                return Ok(Some(Claim::Expired));
            }
            Some(Taken::Due { decoded, attempt }) => (decoded, attempt),
        };
        let Selected {
            key,
            generation,
            attempt: prior_attempt,
            ..
        } = selected;
        let attempt_timeout_ms = milliseconds(decoded.policy.attempt_timeout)?;
        let allowance_ms = milliseconds(LEASE_FINALIZATION_ALLOWANCE)?;
        let lease_token = Uuid::new_v4();
        let changed = transaction
            .execute(
                &self.inner.statements.lease,
                &[
                    &key.id(),
                    &key.part(),
                    &generation,
                    &prior_attempt,
                    &attempt,
                    &attempt_timeout_ms,
                    &allowance_ms,
                    &lease_token,
                ],
            )
            .await
            .map_err(|_| {
                self.refused(TransitionCode::ClaimUpdateFailed);
                DispatchError::Unavailable
            })?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        let attempt_started_at = database_now(&transaction).await?;
        let job = LeasedJob {
            key,
            generation,
            attempt,
            attempt_started_at,
            lease_token,
            policy: decoded.policy,
            job: decoded.job,
        };
        if store
            .record_attempt_audit(&job, AttemptAudit::Started, context)
            .await
            .is_err()
        {
            self.refused(TransitionCode::ClaimAuditFailed);
            return Err(DispatchError::Unavailable);
        }
        if store
            .write_attempt(&transaction, &job, AttemptAudit::Started)
            .await
            .is_err()
        {
            let _ = store
                .record_attempt_audit(
                    &job,
                    AttemptAudit::Interrupted {
                        disposition: Disposition::RetryPending,
                    },
                    context,
                )
                .await;
            return Err(DispatchError::Unavailable);
        }
        if transaction.commit().await.is_err() {
            self.refused(TransitionCode::ClaimCommitFailed);
            self.record_resolved(committed, context).await;
            let disposition = match self.attempt_started_committed(&job).await {
                Some(true) => None,
                Some(false) => Some(Disposition::RetryPending),
                None => Some(Disposition::Unknown),
            };
            if let Some(disposition) = disposition {
                let _ = store
                    .record_attempt_audit(&job, AttemptAudit::Interrupted { disposition }, context)
                    .await;
            }
            return Err(DispatchError::Unavailable);
        }
        self.record_committed(&committed, context).await?;
        self.report(&committed);
        Ok(Some(Claim::Leased(job)))
    }

    /// Decode one claimed row and decide what the claim does with it:
    /// expire it past its captured policy's expiry, or take it for its next
    /// attempt.
    async fn take_claimed(
        &self,
        transaction: &Transaction<'_>,
        row: &Row,
        selected: &Selected,
        context: &S::Context,
    ) -> Result<Taken<S::Job, S::Record>, RowFailure> {
        let store = &self.inner.store;
        let unreadable = RowFailure {
            reason: QuarantineReason::ClaimUnreadable,
            refusal: None,
        };
        let refused = RowFailure {
            reason: QuarantineReason::PolicyRefused,
            refusal: Some(TransitionCode::ClaimPolicyRefused),
        };
        let expiry_failed = RowFailure {
            reason: QuarantineReason::ClaimExpiryFailed,
            refusal: None,
        };
        let decoded = store
            .decode_claim(row, 4)
            .map_err(|refusal| match refusal {
                ClaimRefusal::Unavailable => unreadable,
                ClaimRefusal::PolicyRefused => refused,
            })?;
        if let Some(expires_at) = decoded.policy.expires_at {
            let now = database_now(transaction).await.map_err(|_| expiry_failed)?;
            if expires_at <= now {
                let record = store.claim_record(&decoded.job);
                let disposition = self
                    .expiry_disposition(
                        transaction,
                        selected,
                        JobState::Pending,
                        decoded.policy.on_uncertain,
                    )
                    .await
                    .map_err(|_| expiry_failed)?;
                let update = match disposition {
                    Disposition::Unknown => &self.inner.statements.hold_expiring,
                    _ => &self.inner.statements.expire_claimed,
                };
                let audit = self
                    .expire_locked(
                        transaction,
                        &Expiring {
                            key: &selected.key,
                            generation: selected.generation,
                            attempt: selected.attempt,
                            from: JobState::Pending,
                            disposition,
                            record: &record,
                        },
                        update,
                        &[
                            &selected.key.id(),
                            &selected.key.part(),
                            &selected.generation,
                            &selected.attempt,
                        ],
                        context,
                    )
                    .await
                    .map_err(|_| expiry_failed)?;
                return Ok(Taken::Expired(audit));
            }
        }
        let attempt = selected
            .attempt
            .checked_add(1)
            .filter(|attempt| *attempt <= decoded.policy.maximum_attempts)
            .ok_or(unreadable)?;
        if !decoded.policy.is_valid(&self.inner.bound) {
            return Err(refused);
        }
        Ok(Taken::Due { decoded, attempt })
    }

    /// Run one selected row's step.
    ///
    /// Without quarantine, a failing step reports its refusal and fails the
    /// claim. With it, the step runs inside a savepoint; a failing step is
    /// rolled back, the row is quarantined and `None` returned, and only a
    /// quarantine that fails reports the refusal and fails the claim.
    async fn guarded<T, F>(
        &self,
        transaction: &Transaction<'_>,
        selected: &Selected,
        committed: &mut Committed<S::Record>,
        context: &S::Context,
        step: F,
    ) -> Result<Option<T>, DispatchError>
    where
        F: Future<Output = Result<T, RowFailure>>,
    {
        if !self.inner.store.quarantines() {
            return match step.await {
                Ok(value) => Ok(Some(value)),
                Err(failure) => Err(self.fail(failure)),
            };
        }
        transaction.batch_execute("SAVEPOINT dispatch_row").await?;
        match step.await {
            Ok(value) => {
                transaction
                    .batch_execute("RELEASE SAVEPOINT dispatch_row")
                    .await?;
                Ok(Some(value))
            }
            Err(failure) => {
                transaction
                    .batch_execute("ROLLBACK TO SAVEPOINT dispatch_row")
                    .await?;
                let audit = self
                    .quarantine(transaction, selected, failure.reason, context)
                    .await
                    .map_err(|_| self.fail(failure))?;
                committed.quarantines.push(audit);
                Ok(None)
            }
        }
    }

    /// Hand one row to the store's quarantine and check the row left the
    /// claim, recovery, and sweep sets.
    async fn quarantine(
        &self,
        transaction: &Transaction<'_>,
        selected: &Selected,
        reason: QuarantineReason,
        context: &S::Context,
    ) -> Result<QuarantineAudit, DispatchError> {
        let may_have_reached_receiver = selected.from == JobState::Leased
            || self
                .inner
                .store
                .may_have_reached_receiver(
                    transaction,
                    &selected.key,
                    selected.generation,
                    selected.attempt,
                )
                .await?;
        let intent = Quarantine {
            key: &selected.key,
            generation: selected.generation,
            attempt: selected.attempt,
            from: selected.from,
            reason,
            may_have_reached_receiver,
        };
        self.inner
            .store
            .begin_quarantine_audit(intent, context)
            .await?;
        let disposition = self.inner.store.quarantine(transaction, intent).await;
        let disposition = match disposition {
            Ok(disposition) => disposition,
            Err(error) => {
                let refused = QuarantineAudit {
                    key: selected.key.clone(),
                    generation: selected.generation,
                    attempt: selected.attempt,
                    from: selected.from,
                    reason,
                    disposition: None,
                };
                let _ = self
                    .inner
                    .store
                    .record_quarantine_audit(&refused, TransitionOutcome::Refused, context)
                    .await;
                return Err(error);
            }
        };
        let QuarantineDisposition::Quarantined(state) = disposition else {
            let refused = QuarantineAudit {
                key: selected.key.clone(),
                generation: selected.generation,
                attempt: selected.attempt,
                from: selected.from,
                reason,
                disposition: None,
            };
            let _ = self
                .inner
                .store
                .record_quarantine_audit(&refused, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        };
        let settled = transaction
            .query_opt(
                &self.inner.statements.quarantined,
                &[
                    &selected.key.id(),
                    &selected.key.part(),
                    &selected.generation,
                ],
            )
            .await
            .and_then(|row| row.map(|row| row.try_get::<_, String>(0)).transpose());
        let settled = match settled {
            Ok(settled) => settled,
            Err(_) => {
                let refused = QuarantineAudit {
                    key: selected.key.clone(),
                    generation: selected.generation,
                    attempt: selected.attempt,
                    from: selected.from,
                    reason,
                    disposition: Some(state),
                };
                let _ = self
                    .inner
                    .store
                    .record_quarantine_audit(&refused, TransitionOutcome::Refused, context)
                    .await;
                return Err(DispatchError::Unavailable);
            }
        };
        if settled.as_deref() != Some(state.as_str()) {
            let refused = QuarantineAudit {
                key: selected.key.clone(),
                generation: selected.generation,
                attempt: selected.attempt,
                from: selected.from,
                reason,
                disposition: Some(state),
            };
            let _ = self
                .inner
                .store
                .record_quarantine_audit(&refused, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        }
        Ok(QuarantineAudit {
            key: selected.key.clone(),
            generation: selected.generation,
            attempt: selected.attempt,
            from: selected.from,
            reason,
            disposition: Some(state),
        })
    }

    /// Report a failing row's refusal, if it has one.
    fn fail(&self, failure: RowFailure) -> DispatchError {
        if let Some(code) = failure.refusal {
            self.refused(code);
        }
        DispatchError::Unavailable
    }

    /// Record what one send of a leased job did, under its fence.
    ///
    /// An accepted send is delivered; a permanent failure dead-letters now;
    /// a maybe-sent answer follows the job's uncertain-outcome policy; a
    /// transient failure retries after the scheduled delay, dead-letters
    /// once the attempts are spent, and expires when the retry would land at
    /// or after the job's expiry. Under
    /// [`UncertainOutcome::RetryThenHold`], a transient or permanent failure
    /// that would dead-letter or expire the job holds it `unknown` instead
    /// when an earlier attempt of its generation may have reached its
    /// receiver ([`DispatchStore::may_have_reached_receiver`]). A stale
    /// fence matches no row, so the finish is refused and its audit rolls
    /// back with it.
    ///
    /// # Errors
    ///
    /// [`DispatchError::Unavailable`] when the fence is stale or any write
    /// fails.
    pub async fn finish(
        &self,
        job: &LeasedJob<S::Job>,
        sent: Sent<S::Detail>,
    ) -> Result<DispatchOutcome, DispatchError> {
        let context = self.inner.store.capture_context();
        let dispatcher = self.clone();
        let job = job.clone();
        tokio::spawn(async move { dispatcher.finish_owned(job, sent, &context).await })
            .await
            .map_err(|_| DispatchError::Unavailable)?
    }

    async fn finish_owned(
        &self,
        job: LeasedJob<S::Job>,
        sent: Sent<S::Detail>,
        context: &S::Context,
    ) -> Result<DispatchOutcome, DispatchError> {
        let store = &self.inner.store;
        let mut client = store.connection().await?;
        let transaction = client.transaction().await?;
        store.verify_transaction(&transaction).await?;
        let next = match &sent.outcome {
            SendOutcome::Accepted { .. } => Next::Delivered,
            SendOutcome::Permanent { .. } => Next::DeadLettered,
            SendOutcome::MaybeSent => {
                after_uncertain(&transaction, &job.policy, job.attempt).await?
            }
            SendOutcome::Transient { retry_after } => {
                after_failure(&transaction, &job.policy, job.attempt, *retry_after).await?
            }
        };
        let next = self
            .hold_after_earlier_uncertain(&transaction, &job, next)
            .await?;
        let disposition = next.disposition();
        store
            .write_attempt(
                &transaction,
                &job,
                AttemptAudit::Finished {
                    sent: &sent,
                    disposition,
                },
            )
            .await?;
        let columns = store.finished_columns(&job, &sent, disposition)?;
        let changed = self
            .transition(&transaction, job.fence(), next, &columns, false)
            .await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        store
            .after_finished(&transaction, &job, disposition)
            .await?;
        if transaction.commit().await.is_err() {
            match self.attempt_finished_committed(&job, disposition).await {
                Some(true) => {}
                Some(false) => return Err(DispatchError::Unavailable),
                None => {
                    let _ = store
                        .record_attempt_audit(
                            &job,
                            AttemptAudit::Interrupted {
                                disposition: Disposition::Unknown,
                            },
                            context,
                        )
                        .await;
                    return Err(DispatchError::Unavailable);
                }
            }
        }
        store
            .record_attempt_audit(
                &job,
                AttemptAudit::Finished {
                    sent: &sent,
                    disposition,
                },
                context,
            )
            .await?;
        Ok(next.outcome())
    }

    /// Hold `unknown` a job that `next` would dead-letter or expire after a
    /// transient or permanent answer, when its policy is
    /// [`UncertainOutcome::RetryThenHold`] and an earlier attempt of its
    /// generation may have reached its receiver. A later refusal does not
    /// prove the earlier attempt did not land, so an operator retry could
    /// otherwise send it twice. Read in the finish transaction before the
    /// attempt's own answer is written, while the store may still record the
    /// current attempt in progress, so only the attempts before it are asked
    /// about.
    async fn hold_after_earlier_uncertain(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<S::Job>,
        next: Next,
    ) -> Result<Next, DispatchError> {
        if job.policy.on_uncertain != UncertainOutcome::RetryThenHold
            || !matches!(next, Next::DeadLettered | Next::Expired)
        {
            return Ok(next);
        }
        let held = self
            .inner
            .store
            .may_have_reached_receiver(
                transaction,
                &job.key,
                job.generation,
                job.attempt.saturating_sub(1),
            )
            .await?;
        Ok(if held { Next::Unknown } else { next })
    }

    /// Read a consumer's rows for a job while its lease is live, under the
    /// lease's fence and a shared lock.
    ///
    /// The statement selects `state.<id column>` first, then `select`'s
    /// columns, so `decode` reads the consumer's columns from index one. The
    /// decoder runs before the read transaction commits.
    ///
    /// # Errors
    ///
    /// [`LeasedReadError::Unavailable`] when the lease is stale or lapsed,
    /// `select` does not match, or the database fails, and
    /// [`LeasedReadError::Refused`] with the decoder's own error.
    pub async fn read_leased<T, E, F>(
        &self,
        fence: Fence<'_>,
        select: &SelectSql,
        decode: F,
    ) -> Result<T, LeasedReadError<E>>
    where
        F: FnOnce(&Row, usize) -> Result<T, E> + Send,
        T: Send,
        E: Send,
    {
        let table = &self.inner.table;
        let rendered = select
            .render(table)
            .map_err(|_| LeasedReadError::Unavailable)?;
        let statement = format!(
            "SELECT state.{id}{columns}
               FROM {qualified} AS state
               {joins}
              WHERE state.{id} = $1
                AND state.{part} = $2
                AND state.generation = $3
                AND state.attempt = $4
                AND state.lease_token = $5
                AND state.state = 'leased'
                AND state.lease_expires_at > transaction_timestamp()
                AND ({predicate})
              FOR SHARE OF state",
            id = table.id_column(),
            part = table.part_column(),
            qualified = table.qualified(),
            columns = rendered.columns,
            joins = rendered.joins,
            predicate = rendered.predicate,
        );
        let store = &self.inner.store;
        let mut client = store
            .connection()
            .await
            .map_err(|_| LeasedReadError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| LeasedReadError::Unavailable)?;
        store
            .verify_transaction(&transaction)
            .await
            .map_err(|_| LeasedReadError::Unavailable)?;
        let row = transaction
            .query_opt(
                &statement,
                &[
                    &fence.id,
                    &fence.part,
                    &fence.generation,
                    &fence.attempt,
                    &fence.lease_token,
                ],
            )
            .await
            .map_err(|_| LeasedReadError::Unavailable)?
            .ok_or(LeasedReadError::Unavailable)?;
        let value = decode(&row, 1).map_err(LeasedReadError::Refused)?;
        transaction
            .commit()
            .await
            .map_err(|_| LeasedReadError::Unavailable)?;
        Ok(value)
    }

    /// Reset one terminal job for an operator replay and return the
    /// committed replacement generation.
    ///
    /// The replay starts a new generation at attempt zero, so a product
    /// that puts the generation in its idempotency key sends the replay
    /// under a new key. Every absent, stale, refused, or nonterminal target
    /// returns the same value-free refusal.
    ///
    /// # Errors
    ///
    /// [`DispatchError::Unavailable`] on any refusal.
    pub async fn replay(
        &self,
        key: &JobKey,
        expected_generation: i64,
    ) -> Result<i64, DispatchError> {
        let context = self.inner.store.capture_context();
        let dispatcher = self.clone();
        let key = key.clone();
        tokio::spawn(async move {
            dispatcher
                .replay_owned(key, expected_generation, &context)
                .await
        })
        .await
        .map_err(|_| DispatchError::Unavailable)?
    }

    async fn replay_owned(
        &self,
        key: JobKey,
        expected_generation: i64,
        context: &S::Context,
    ) -> Result<i64, DispatchError> {
        if expected_generation <= 0 {
            return Err(DispatchError::Unavailable);
        }
        let store = &self.inner.store;
        let mut client = store.connection().await?;
        let transaction = client.transaction().await?;
        store.verify_transaction(&transaction).await?;
        let (generation, state, _attempt, record) = self
            .read_target(&transaction, &key, TargetAction::Replay)
            .await?;
        let Some(record) = record else {
            return Err(DispatchError::Unavailable);
        };
        if generation != expected_generation || !self.inner.replayable.contains(&state) {
            return Err(DispatchError::Unavailable);
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(DispatchError::Unavailable)?;
        let replay = ReplayAudit {
            key: key.clone(),
            generation: next_generation,
            record,
            from: state,
            outcome: ReplayOutcome::Requested,
        };
        store.record_replay_audit(&replay, context).await?;
        let table = &self.inner.table;
        let changed = transaction
            .execute(
                &format!(
                    "UPDATE {qualified}
                        SET generation = $4,
                            state = 'pending',
                            attempt = 0,
                            next_attempt_at = transaction_timestamp(),
                            attempt_started_at = NULL,
                            lease_expires_at = NULL,
                            lease_token = NULL,
                            delivered_at = NULL,
                            dead_lettered_at = NULL,
                            expired_at = NULL,
                            updated_at = transaction_timestamp()
                      WHERE {id} = $1
                        AND {part} = $2
                        AND generation = $3
                        AND state = '{from}'",
                    qualified = table.qualified(),
                    id = table.id_column(),
                    part = table.part_column(),
                    from = state.as_str(),
                ),
                &[&key.id(), &key.part(), &generation, &next_generation],
            )
            .await;
        let changed = match changed {
            Ok(changed) => changed,
            Err(_) => {
                let mut refused = replay.clone();
                refused.outcome = ReplayOutcome::Refused;
                let _ = store.record_replay_audit(&refused, context).await;
                return Err(DispatchError::Unavailable);
            }
        };
        if changed != 1 {
            let mut refused = replay;
            refused.outcome = ReplayOutcome::Refused;
            let _ = store.record_replay_audit(&refused, context).await;
            return Err(DispatchError::Unavailable);
        }
        if store.write_replay(&transaction, &replay).await.is_err() {
            let mut refused = replay;
            refused.outcome = ReplayOutcome::Refused;
            let _ = store.record_replay_audit(&refused, context).await;
            return Err(DispatchError::Unavailable);
        }
        let outcome = if transaction.commit().await.is_ok() {
            ReplayOutcome::Committed
        } else {
            match self.replay_committed(&replay).await {
                Some(true) => ReplayOutcome::Committed,
                Some(false) => ReplayOutcome::Refused,
                None => ReplayOutcome::Unfinished,
            }
        };
        let mut response = replay;
        response.outcome = outcome;
        let recorded = store.record_replay_audit(&response, context).await;
        if outcome != ReplayOutcome::Committed {
            return Err(DispatchError::Unavailable);
        }
        recorded?;
        Ok(next_generation)
    }

    /// Withdraw one pending job.
    ///
    /// The cancel locks the row and waits for a concurrent claim, and a
    /// claim skips a row the cancel holds, so exactly one of the two wins: a
    /// cancelled job is never sent again, and a leased job is never
    /// cancelled.
    ///
    /// A pending job may already have been attempted. When the store
    /// reports that an earlier attempt of its generation may have reached
    /// its receiver ([`DispatchStore::may_have_reached_receiver`]), the job
    /// is left pending and [`CancelOutcome::MayHaveReachedReceiver`] is
    /// returned, so `cancelled` always means never sent in that generation.
    /// A scheduled retry after attempts that were definitely not sent stays
    /// cancellable.
    ///
    /// # Errors
    ///
    /// [`DispatchError::Unavailable`] when the job is absent, the consumer
    /// refuses the cancellation, or a write fails.
    pub async fn cancel(&self, key: &JobKey) -> Result<CancelOutcome, DispatchError> {
        let context = self.inner.store.capture_context();
        let dispatcher = self.clone();
        let key = key.clone();
        tokio::spawn(async move { dispatcher.cancel_owned(key, &context).await })
            .await
            .map_err(|_| DispatchError::Unavailable)?
    }

    async fn cancel_owned(
        &self,
        key: JobKey,
        context: &S::Context,
    ) -> Result<CancelOutcome, DispatchError> {
        let store = &self.inner.store;
        let mut client = store.connection().await?;
        let transaction = client.transaction().await?;
        store.verify_transaction(&transaction).await?;
        let (generation, state, attempt, record) = self
            .read_target(&transaction, &key, TargetAction::Cancel)
            .await?;
        let Some(record) = record else {
            return Err(DispatchError::Unavailable);
        };
        if state != JobState::Pending {
            transaction.commit().await?;
            return Ok(CancelOutcome::NotCancellable(state));
        }
        if store
            .may_have_reached_receiver(&transaction, &key, generation, attempt)
            .await?
        {
            transaction.commit().await?;
            return Ok(CancelOutcome::MayHaveReachedReceiver);
        }
        let audit = TransitionAudit {
            key: key.clone(),
            generation,
            attempt,
            record,
            transition: Transition::Cancelled,
        };
        store.begin_transition_audit(&audit, context).await?;
        if store.write_transition(&transaction, &audit).await.is_err() {
            let _ = store
                .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        }
        let table = &self.inner.table;
        let changed = transaction
            .execute(
                &format!(
                    "UPDATE {qualified}
                        SET state = 'cancelled',
                            next_attempt_at = NULL,
                            updated_at = transaction_timestamp()
                      WHERE {id} = $1
                        AND {part} = $2
                        AND generation = $3
                        AND state = 'pending'",
                    qualified = table.qualified(),
                    id = table.id_column(),
                    part = table.part_column(),
                ),
                &[&key.id(), &key.part(), &generation],
            )
            .await;
        let changed = match changed {
            Ok(changed) => changed,
            Err(_) => {
                let _ = store
                    .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                    .await;
                return Err(DispatchError::Unavailable);
            }
        };
        if changed != 1 {
            let _ = store
                .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        }
        let outcome = if transaction.commit().await.is_ok() {
            TransitionOutcome::Committed
        } else {
            match self.transition_committed(&audit).await {
                Some(true) => TransitionOutcome::Committed,
                Some(false) => TransitionOutcome::Refused,
                None => TransitionOutcome::Unfinished,
            }
        };
        store
            .record_transition_audit(&audit, outcome, context)
            .await?;
        if outcome != TransitionOutcome::Committed {
            return Err(DispatchError::Unavailable);
        }
        Ok(CancelOutcome::Cancelled)
    }

    /// Lock one operator target and decode it.
    async fn read_target(
        &self,
        transaction: &Transaction<'_>,
        key: &JobKey,
        action: TargetAction,
    ) -> Result<(i64, JobState, i16, Option<S::Record>), DispatchError> {
        let row = transaction
            .query_opt(&self.inner.statements.target, &[&key.id(), &key.part()])
            .await?
            .ok_or(DispatchError::Unavailable)?;
        let generation = row.try_get::<_, i64>(0)?;
        let state =
            JobState::parse(&row.try_get::<_, String>(1)?).ok_or(DispatchError::Unavailable)?;
        let attempt = row.try_get::<_, i16>(2)?;
        let record = self.inner.store.decode_target(&row, 3, key, action)?;
        Ok((generation, state, attempt, record))
    }

    /// Move at most one lapsed lease to the disposition its policy owes:
    /// `unknown` for a job that holds uncertain attempts, otherwise the
    /// retry, dead letter, or expiry a transient failure would have earned.
    async fn recover_lapsed_lease(
        &self,
        transaction: &Transaction<'_>,
        committed: &mut Committed<S::Record>,
        context: &S::Context,
    ) -> Result<(), DispatchError> {
        let failure = RowFailure {
            reason: QuarantineReason::RecoveryFailed,
            refusal: Some(TransitionCode::ClaimRecoveryFailed),
        };
        let row = transaction
            .query_opt(&self.inner.statements.lapsed, &[])
            .await
            .map_err(|_| self.fail(failure))?;
        let Some(row) = row else {
            return Ok(());
        };
        let selected = Selected::read(&row, JobState::Leased).map_err(|_| self.fail(failure))?;
        let recovered = self
            .guarded(transaction, &selected, committed, context, async {
                self.recover(transaction, &row, &selected, context)
                    .await
                    .map_err(|_| failure)
            })
            .await?;
        if let Some(audit) = recovered {
            committed.transitions.push(audit);
        }
        Ok(())
    }

    /// Recover one lapsed lease this transaction holds locked.
    async fn recover(
        &self,
        transaction: &Transaction<'_>,
        row: &Row,
        selected: &Selected,
        context: &S::Context,
    ) -> Result<TransitionAudit<S::Record>, DispatchError> {
        let store = &self.inner.store;
        let key = selected.key.clone();
        let generation = selected.generation;
        let attempt = selected.attempt;
        let lease_token = row.try_get::<_, Uuid>(4)?;
        let decoded = store.decode_lapsed(row, 5)?;
        if !decoded.policy.is_valid(&self.inner.bound) {
            return Err(DispatchError::Unavailable);
        }
        let next = after_uncertain(transaction, &decoded.policy, attempt).await?;
        let disposition = next.disposition();
        let lapsed = LapsedJob {
            key,
            generation,
            attempt,
            lease_token,
            policy: decoded.policy,
            record: decoded.job,
        };
        let columns = store
            .lapsed_columns(transaction, &lapsed, disposition)
            .await?;
        let audit = TransitionAudit {
            key: lapsed.key.clone(),
            generation,
            attempt,
            record: lapsed.record.clone(),
            transition: Transition::LeaseLapsed(disposition),
        };
        store.begin_transition_audit(&audit, context).await?;
        if store.write_transition(transaction, &audit).await.is_err() {
            let _ = store
                .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        }
        let fence = Fence {
            id: lapsed.key.id(),
            part: lapsed.key.part(),
            generation,
            attempt,
            lease_token,
        };
        let changed = self
            .transition(transaction, fence, next, &columns, true)
            .await;
        let changed = match changed {
            Ok(changed) => changed,
            Err(error) => {
                let _ = store
                    .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                    .await;
                return Err(error);
            }
        };
        if changed != 1 {
            let _ = store
                .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        }
        Ok(audit)
    }

    /// Expire at most one undispatched job whose consumer selection says it
    /// has expired.
    async fn expire_one(
        &self,
        transaction: &Transaction<'_>,
        committed: &mut Committed<S::Record>,
        context: &S::Context,
    ) -> Result<(), DispatchError> {
        let Some((select, update)) = &self.inner.statements.expiry else {
            return Ok(());
        };
        let Some(row) = transaction.query_opt(select, &[]).await? else {
            return Ok(());
        };
        let from =
            JobState::parse(&row.try_get::<_, String>(4)?).ok_or(DispatchError::Unavailable)?;
        let selected = Selected::read(&row, from)?;
        let failure = RowFailure {
            reason: QuarantineReason::ExpiryFailed,
            refusal: None,
        };
        let expired = self
            .guarded(transaction, &selected, committed, context, async {
                let store = &self.inner.store;
                let record = store.decode_expired(&row, 5).map_err(|_| failure)?;
                let on_uncertain = store
                    .decode_expired_on_uncertain(&row, 5)
                    .map_err(|_| failure)?;
                let disposition = self
                    .expiry_disposition(transaction, &selected, from, on_uncertain)
                    .await
                    .map_err(|_| failure)?;
                let expiring = Expiring {
                    key: &selected.key,
                    generation: selected.generation,
                    attempt: selected.attempt,
                    from,
                    disposition,
                    record: &record,
                };
                let held = match disposition {
                    Disposition::Unknown => {
                        self.expire_locked(
                            transaction,
                            &expiring,
                            &self.inner.statements.hold_expiring,
                            &[
                                &selected.key.id(),
                                &selected.key.part(),
                                &selected.generation,
                                &selected.attempt,
                            ],
                            context,
                        )
                        .await
                    }
                    _ => {
                        self.expire_locked(
                            transaction,
                            &expiring,
                            update,
                            &[
                                &selected.key.id(),
                                &selected.key.part(),
                                &selected.generation,
                            ],
                            context,
                        )
                        .await
                    }
                };
                held.map_err(|_| failure)
            })
            .await?;
        if let Some(audit) = expired {
            committed.transitions.push(audit);
        }
        Ok(())
    }

    /// What a job reaching its expiry in `from` becomes: `unknown` when it is
    /// pending under [`UncertainOutcome::RetryThenHold`] and an earlier
    /// attempt of its generation may have reached its receiver, since an
    /// operator requeue would resend it without deduplication, and
    /// `expired` otherwise. Read under the row lock the expiry holds.
    async fn expiry_disposition(
        &self,
        transaction: &Transaction<'_>,
        selected: &Selected,
        from: JobState,
        on_uncertain: UncertainOutcome,
    ) -> Result<Disposition, DispatchError> {
        let held = from == JobState::Pending
            && on_uncertain == UncertainOutcome::RetryThenHold
            && self
                .inner
                .store
                .may_have_reached_receiver(
                    transaction,
                    &selected.key,
                    selected.generation,
                    selected.attempt,
                )
                .await?;
        Ok(if held {
            Disposition::Unknown
        } else {
            Disposition::Expired
        })
    }

    /// Audit, write, and finish one expiry of a job this transaction holds
    /// locked. `update` must change exactly that job's row, to the
    /// expiring disposition.
    async fn expire_locked(
        &self,
        transaction: &Transaction<'_>,
        expiring: &Expiring<'_, S::Record>,
        update: &str,
        values: &[&(dyn ToSql + Sync)],
        context: &S::Context,
    ) -> Result<TransitionAudit<S::Record>, DispatchError> {
        let store = &self.inner.store;
        let audit = TransitionAudit {
            key: expiring.key.clone(),
            generation: expiring.generation,
            attempt: expiring.attempt,
            record: expiring.record.clone(),
            transition: Transition::Expired {
                from: expiring.from,
                disposition: expiring.disposition,
            },
        };
        store.begin_transition_audit(&audit, context).await?;
        if store.write_transition(transaction, &audit).await.is_err() {
            let _ = store
                .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        }
        let changed = match transaction.execute(update, values).await {
            Ok(changed) => changed,
            Err(_) => {
                let _ = store
                    .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                    .await;
                return Err(DispatchError::Unavailable);
            }
        };
        if changed != 1 {
            let _ = store
                .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        }
        if expiring.disposition == Disposition::Expired
            && store
                .after_expired(transaction, expiring.key, expiring.record)
                .await
                .is_err()
        {
            let _ = store
                .record_transition_audit(&audit, TransitionOutcome::Refused, context)
                .await;
            return Err(DispatchError::Unavailable);
        }
        Ok(audit)
    }

    /// Record direct audit entries after a claim transaction committed.
    async fn record_committed(
        &self,
        committed: &Committed<S::Record>,
        context: &S::Context,
    ) -> Result<(), DispatchError> {
        for audit in &committed.transitions {
            self.inner
                .store
                .record_transition_audit(audit, TransitionOutcome::Committed, context)
                .await?;
        }
        for audit in &committed.quarantines {
            self.inner
                .store
                .record_quarantine_audit(audit, TransitionOutcome::Committed, context)
                .await?;
        }
        Ok(())
    }

    /// After a failed COMMIT acknowledgement, record refusal only when a
    /// bounded fresh read proves the pre-state unchanged. A matching target
    /// state may belong to another invocation and remains unfinished.
    async fn record_resolved(&self, committed: Committed<S::Record>, context: &S::Context) {
        for audit in committed.transitions {
            let outcome = match self.transition_committed(&audit).await {
                Some(true) => TransitionOutcome::Committed,
                Some(false) => TransitionOutcome::Refused,
                None => TransitionOutcome::Unfinished,
            };
            let _ = self
                .inner
                .store
                .record_transition_audit(&audit, outcome, context)
                .await;
        }
        for audit in committed.quarantines {
            let outcome = match self.quarantine_committed(&audit).await {
                Some(true) => TransitionOutcome::Committed,
                Some(false) => TransitionOutcome::Refused,
                None => TransitionOutcome::Unfinished,
            };
            let _ = self
                .inner
                .store
                .record_quarantine_audit(&audit, outcome, context)
                .await;
        }
    }

    async fn attempt_started_committed(&self, job: &LeasedJob<S::Job>) -> Option<bool> {
        let observed = self.observe(&job.key).await?;
        Some(
            observed.generation == job.generation
                && observed.attempt == job.attempt
                && observed.state == JobState::Leased
                && observed.lease_token == Some(job.lease_token),
        )
    }

    async fn attempt_finished_committed(
        &self,
        job: &LeasedJob<S::Job>,
        _disposition: Disposition,
    ) -> Option<bool> {
        let observed = self.observe(&job.key).await?;
        (observed.generation == job.generation
            && observed.attempt == job.attempt
            && observed.state == JobState::Leased
            && observed.lease_token == Some(job.lease_token))
        .then_some(false)
    }

    async fn transition_committed(&self, audit: &TransitionAudit<S::Record>) -> Option<bool> {
        let observed = self.observe(&audit.key).await?;
        let unchanged = observed.generation == audit.generation
            && observed.attempt == audit.attempt
            && match audit.transition {
                Transition::LeaseLapsed(_) => observed.state == JobState::Leased,
                Transition::Expired { from, .. } => observed.state == from && !observed.expired,
                Transition::Cancelled => observed.state == JobState::Pending,
            };
        unchanged.then_some(false)
    }

    async fn replay_committed(&self, audit: &ReplayAudit<S::Record>) -> Option<bool> {
        let observed = self.observe(&audit.key).await?;
        (observed.generation < audit.generation).then_some(false)
    }

    async fn quarantine_committed(&self, audit: &QuarantineAudit) -> Option<bool> {
        let observed = self.observe(&audit.key).await?;
        (observed.generation == audit.generation
            && observed.attempt == audit.attempt
            && observed.state == audit.from)
            .then_some(false)
    }

    /// Read one row on fresh connections. `Some(false)` is represented by a
    /// missing row at the caller; `None` means every bounded read failed.
    async fn observe(&self, key: &JobKey) -> Option<ObservedJob> {
        let table = &self.inner.table;
        let statement = format!(
            "SELECT state, generation, attempt, lease_token, expired_at IS NOT NULL
               FROM {qualified}
              WHERE {id} = $1 AND {part} = $2",
            qualified = table.qualified(),
            id = table.id_column(),
            part = table.part_column(),
        );
        for read_back in 0..=READ_BACK_BACKOFF.len() {
            if let Some(wait) = read_back
                .checked_sub(1)
                .and_then(|index| READ_BACK_BACKOFF.get(index))
            {
                tokio::time::sleep(*wait).await;
            }
            let Ok(client) = self.inner.store.connection().await else {
                continue;
            };
            let Ok(row) = client
                .query_opt(&statement, &[&key.id(), &key.part()])
                .await
            else {
                continue;
            };
            let Some(row) = row else {
                return Some(ObservedJob {
                    state: JobState::Cancelled,
                    generation: i64::MIN,
                    attempt: i16::MIN,
                    lease_token: None,
                    expired: false,
                });
            };
            let state = JobState::parse(&row.try_get::<_, String>(0).ok()?)?;
            return Some(ObservedJob {
                state,
                generation: row.try_get(1).ok()?,
                attempt: row.try_get(2).ok()?,
                lease_token: row.try_get(3).ok()?,
                expired: row.try_get(4).ok()?,
            });
        }
        None
    }

    /// Report what a claim transaction did, once it has committed.
    fn report(&self, committed: &Committed<S::Record>) {
        let store = &self.inner.store;
        for audit in &committed.transitions {
            if matches!(
                audit.transition,
                Transition::Expired {
                    disposition: Disposition::Expired,
                    ..
                }
            ) {
                store.operational_event(DispatchEvent::JobExpired);
            }
        }
        for audit in &committed.quarantines {
            store.operational_event(DispatchEvent::JobQuarantined(audit.reason));
        }
    }

    /// Write one lease-ending transition under `fence`, with the consumer's
    /// extra columns. `lapsed` additionally requires the lease to have
    /// expired, so recovery never takes over a live lease.
    async fn transition(
        &self,
        transaction: &Transaction<'_>,
        fence: Fence<'_>,
        next: Next,
        columns: &Columns,
        lapsed: bool,
    ) -> Result<u64, DispatchError> {
        let table = &self.inner.table;
        let delay_ms;
        let mut values: Vec<&(dyn ToSql + Sync)> = vec![
            &fence.id,
            &fence.part,
            &fence.generation,
            &fence.attempt,
            &fence.lease_token,
        ];
        let (state, next_attempt_at, stamp) = match next {
            Next::Delivered => (
                "delivered",
                "NULL",
                "delivered_at = transaction_timestamp(),",
            ),
            Next::DeadLettered => (
                "dead-lettered",
                "NULL",
                "dead_lettered_at = transaction_timestamp(),",
            ),
            Next::Unknown => ("unknown", "NULL", ""),
            Next::Expired => ("expired", "NULL", "expired_at = transaction_timestamp(),"),
            Next::Retry { delay_ms: delay } => {
                delay_ms = delay;
                values.push(&delay_ms);
                (
                    "pending",
                    "transaction_timestamp() + $6::bigint * interval '1 millisecond'",
                    "",
                )
            }
        };
        let (extras, extra_values) = columns.render(table, values.len() + 1)?;
        values.extend(extra_values);
        let lapsed_predicate = if lapsed {
            "\n                        AND lease_expires_at <= transaction_timestamp()"
        } else {
            ""
        };
        let statement = format!(
            "UPDATE {qualified}
                SET state = '{state}',
                    next_attempt_at = {next_attempt_at},
                    attempt_started_at = NULL,
                    lease_expires_at = NULL,
                    lease_token = NULL,
                    {stamp}
                    updated_at = transaction_timestamp(){extras}
              WHERE {id} = $1
                AND {part} = $2
                AND generation = $3
                AND attempt = $4
                AND lease_token = $5
                AND state = 'leased'{lapsed_predicate}",
            qualified = table.qualified(),
            id = table.id_column(),
            part = table.part_column(),
        );
        Ok(transaction.execute(&statement, &values).await?)
    }

    fn refused(&self, code: TransitionCode) {
        self.inner
            .store
            .operational_event(DispatchEvent::TransitionFailed(code));
    }
}

/// The transition an attempt whose fate is unknown earns under the job's
/// [`UncertainOutcome`] policy.
async fn after_uncertain(
    transaction: &Transaction<'_>,
    policy: &JobPolicy,
    attempt: i16,
) -> Result<Next, DispatchError> {
    Ok(match policy.on_uncertain {
        UncertainOutcome::Hold => Next::Unknown,
        UncertainOutcome::Retry => after_failure(transaction, policy, attempt, None).await?,
        UncertainOutcome::RetryThenHold => {
            match after_failure(transaction, policy, attempt, None).await? {
                Next::DeadLettered | Next::Expired => Next::Unknown,
                next => next,
            }
        }
    })
}

/// The transition a failed attempt earns: a dead letter once the attempts
/// are spent, an expiry when the retry would land at or after the job's
/// expiry, and otherwise a retry after the scheduled delay.
async fn after_failure(
    transaction: &Transaction<'_>,
    policy: &JobPolicy,
    attempt: i16,
    retry_after: Option<Duration>,
) -> Result<Next, DispatchError> {
    if attempt >= policy.maximum_attempts {
        return Ok(Next::DeadLettered);
    }
    let sample = if policy.retry.needs_sample() {
        random_sample()?
    } else {
        0
    };
    let delay_ms = policy.retry.delay_after(attempt, retry_after, sample)?;
    if let Some(expires_at) = policy.expires_at {
        let delay =
            Duration::from_millis(u64::try_from(delay_ms).map_err(|_| DispatchError::Unavailable)?);
        let retry_at = database_now(transaction)
            .await?
            .checked_add(delay)
            .ok_or(DispatchError::Unavailable)?;
        if retry_at >= expires_at {
            return Ok(Next::Expired);
        }
    }
    Ok(Next::Retry { delay_ms })
}

fn random_sample() -> Result<u64, DispatchError> {
    let mut bytes = [0_u8; 8];
    getrandom::fill(&mut bytes).map_err(|_| DispatchError::Unavailable)?;
    Ok(u64::from_le_bytes(bytes))
}

async fn database_now(transaction: &Transaction<'_>) -> Result<SystemTime, DispatchError> {
    Ok(transaction
        .query_one("SELECT transaction_timestamp()", &[])
        .await?
        .try_get::<_, SystemTime>(0)?)
}

fn read_key(row: &Row) -> Result<JobKey, DispatchError> {
    let id = row.try_get::<_, Uuid>(0)?;
    let part = row.try_get::<_, String>(1)?;
    JobKey::new(id, part).map_err(|_| DispatchError::Unavailable)
}

fn milliseconds(duration: Duration) -> Result<i64, DispatchError> {
    i64::try_from(duration.as_millis()).map_err(|_| DispatchError::Unavailable)
}

fn render_statements(table: &JobTable, sql: &DispatchSql) -> Result<Statements, ConfigError> {
    let qualified = table.qualified();
    let id = table.id_column();
    let part = table.part_column();
    let claim = sql.claim.render(table)?;
    let lapsed = sql.lapsed.render(table)?;
    let target = sql.target.render(table)?;
    let expiry = match &sql.expiry {
        None => None,
        Some(expiry) => {
            expiry.validate()?;
            let select = expiry.select.render(table)?;
            let states = expiry.state_list();
            Some((
                format!(
                    "SELECT state.{id}, state.{part}, state.generation, state.attempt,
                            state.state{columns}
                       FROM {qualified} AS state
                       {joins}
                      WHERE state.state IN ({states})
                        AND state.expired_at IS NULL
                        AND ({predicate})
                      ORDER BY {order_by}, state.{id}, state.{part}
                      FOR UPDATE OF {lock_of} SKIP LOCKED
                      LIMIT 1",
                    columns = select.columns,
                    joins = select.joins,
                    predicate = select.predicate,
                    order_by = expiry.order_by.replace("{schema}", table.schema()),
                    lock_of = expiry.lock_of,
                ),
                format!(
                    "UPDATE {qualified}
                        SET state = CASE WHEN state = 'pending' THEN 'expired' ELSE state END,
                            next_attempt_at = NULL,
                            attempt_started_at = NULL,
                            lease_expires_at = NULL,
                            lease_token = NULL,
                            expired_at = transaction_timestamp(),
                            updated_at = transaction_timestamp()
                      WHERE {id} = $1
                        AND {part} = $2
                        AND generation = $3
                        AND state IN ({states})"
                ),
            ))
        }
    };
    let unswept = match &sql.expiry {
        None => String::new(),
        Some(expiry) => format!(
            "\n                AND NOT (state IN ({states}) AND expired_at IS NULL)",
            states = expiry.state_list(),
        ),
    };
    Ok(Statements {
        claim: format!(
            "SELECT state.{id}, state.{part}, state.generation, state.attempt{columns}
               FROM {qualified} AS state
               {joins}
              WHERE state.state = 'pending'
                AND state.next_attempt_at <= transaction_timestamp()
                AND ({predicate})
              ORDER BY state.next_attempt_at, state.{id}, state.{part}
              FOR UPDATE OF state SKIP LOCKED
              LIMIT 1",
            columns = claim.columns,
            joins = claim.joins,
            predicate = claim.predicate,
        ),
        lease: format!(
            "UPDATE {qualified}
                SET state = 'leased',
                    attempt = $5,
                    next_attempt_at = NULL,
                    attempt_started_at = transaction_timestamp(),
                    lease_expires_at = transaction_timestamp()
                        + ($6::bigint + $7::bigint) * interval '1 millisecond',
                    lease_token = $8,
                    updated_at = transaction_timestamp()
              WHERE {id} = $1
                AND {part} = $2
                AND generation = $3
                AND state = 'pending'
                AND attempt = $4"
        ),
        expire_claimed: format!(
            "UPDATE {qualified}
                SET state = 'expired',
                    next_attempt_at = NULL,
                    expired_at = transaction_timestamp(),
                    updated_at = transaction_timestamp()
              WHERE {id} = $1
                AND {part} = $2
                AND generation = $3
                AND attempt = $4
                AND state = 'pending'"
        ),
        hold_expiring: format!(
            "UPDATE {qualified}
                SET state = 'unknown',
                    next_attempt_at = NULL,
                    attempt_started_at = NULL,
                    lease_expires_at = NULL,
                    lease_token = NULL,
                    updated_at = transaction_timestamp()
              WHERE {id} = $1
                AND {part} = $2
                AND generation = $3
                AND attempt = $4
                AND state = 'pending'"
        ),
        lapsed: format!(
            "SELECT state.{id}, state.{part}, state.generation, state.attempt,
                    state.lease_token{columns}
               FROM {qualified} AS state
               {joins}
              WHERE state.state = 'leased'
                AND state.lease_expires_at <= transaction_timestamp()
                AND ({predicate})
              ORDER BY state.lease_expires_at, state.{id}, state.{part}
              FOR UPDATE OF state SKIP LOCKED
              LIMIT 1",
            columns = lapsed.columns,
            joins = lapsed.joins,
            predicate = lapsed.predicate,
        ),
        expiry,
        target: format!(
            "SELECT state.generation, state.state, state.attempt{columns}
               FROM {qualified} AS state
               {joins}
              WHERE state.{id} = $1
                AND state.{part} = $2
                AND ({predicate})
              FOR UPDATE OF state",
            columns = target.columns,
            joins = target.joins,
            predicate = target.predicate,
        ),
        quarantined: format!(
            "SELECT state
               FROM {qualified}
              WHERE {id} = $1
                AND {part} = $2
                AND generation = $3
                AND state IN ({terminal}){unswept}",
            terminal = state_list(&[
                JobState::DeadLettered,
                JobState::Expired,
                JobState::Unknown,
                JobState::Cancelled,
            ]),
        ),
    })
}
