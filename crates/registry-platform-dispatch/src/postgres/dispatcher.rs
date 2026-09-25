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
    Disposition, Fence, LapsedJob, LeasedJob, Quarantine, QuarantineDisposition, QuarantineReason,
    TargetAction, Transition, TransitionAudit, TransitionCode,
};
use super::table::{JobKey, JobState, JobTable};
use crate::outcome::{ConfigError, DispatchError, SendOutcome, Sent};
use crate::retry::{AttemptTimeoutBound, JobPolicy, UncertainOutcome};

/// How long a lease outlives its attempt timeout, so the worker that sent
/// can still record the outcome before recovery may take the job over.
pub const LEASE_FINALIZATION_ALLOWANCE: Duration = Duration::from_secs(5);

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
    /// instead of leasing it. Nothing may be sent.
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
enum Taken<J> {
    /// The row expired at claim instead of being leased.
    Expired,
    /// The row is due for `attempt`.
    Due { decoded: Decoded<J>, attempt: i16 },
}

/// The events a claim transaction reports once it has committed.
#[derive(Default)]
struct Committed {
    expired: usize,
    quarantined: Vec<QuarantineReason>,
}

/// One locked job an expiry transition is about to take.
struct Expiring<'a, R> {
    key: &'a JobKey,
    generation: i64,
    attempt: i16,
    from: JobState,
    record: &'a R,
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
        loop {
            if let Some(claim) = self.claim_in_transaction().await? {
                return Ok(claim);
            }
        }
    }

    /// One claim transaction, or `None` when its due row was quarantined
    /// and the claim should select the next.
    async fn claim_in_transaction(&self) -> Result<Option<Claim<S::Job>>, DispatchError> {
        let store = &self.inner.store;
        let mut client = store.connection().await?;
        let transaction = client.transaction().await?;
        if store.verify_transaction(&transaction).await.is_err() {
            self.refused(TransitionCode::ClaimIdentityRefused);
            return Err(DispatchError::Unavailable);
        }
        let mut committed = Committed::default();
        self.recover_lapsed_lease(&transaction, &mut committed)
            .await?;
        self.expire_one(&transaction, &mut committed).await?;
        let row = transaction
            .query_opt(&self.inner.statements.claim, &[])
            .await
            .map_err(|_| {
                self.refused(TransitionCode::ClaimSelectFailed);
                DispatchError::Unavailable
            })?;
        let Some(row) = row else {
            transaction.commit().await?;
            self.report(committed);
            return Ok(Some(Claim::Idle));
        };
        let selected = Selected::read(&row, JobState::Pending)?;
        let taken = self
            .guarded(
                &transaction,
                &selected,
                &mut committed,
                self.take_claimed(&transaction, &row, &selected),
            )
            .await?;
        let (decoded, attempt) = match taken {
            None => {
                transaction.commit().await?;
                self.report(committed);
                return Ok(None);
            }
            Some(Taken::Expired) => {
                transaction.commit().await?;
                committed.expired += 1;
                self.report(committed);
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
            .record_attempt_audit(&transaction, &job, AttemptAudit::Started)
            .await
            .is_err()
        {
            self.refused(TransitionCode::ClaimAuditFailed);
            return Err(DispatchError::Unavailable);
        }
        transaction.commit().await.map_err(|_| {
            self.refused(TransitionCode::ClaimCommitFailed);
            DispatchError::Unavailable
        })?;
        self.report(committed);
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
    ) -> Result<Taken<S::Job>, RowFailure> {
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
                self.expire_locked(
                    transaction,
                    &Expiring {
                        key: &selected.key,
                        generation: selected.generation,
                        attempt: selected.attempt,
                        from: JobState::Pending,
                        record: &record,
                    },
                    &self.inner.statements.expire_claimed,
                    &[
                        &selected.key.id(),
                        &selected.key.part(),
                        &selected.generation,
                        &selected.attempt,
                    ],
                )
                .await
                .map_err(|_| expiry_failed)?;
                return Ok(Taken::Expired);
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
        committed: &mut Committed,
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
                if self
                    .quarantine(transaction, selected, failure.reason)
                    .await
                    .is_err()
                {
                    return Err(self.fail(failure));
                }
                committed.quarantined.push(failure.reason);
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
    ) -> Result<(), DispatchError> {
        let disposition = self
            .inner
            .store
            .quarantine(
                transaction,
                Quarantine {
                    key: &selected.key,
                    generation: selected.generation,
                    attempt: selected.attempt,
                    from: selected.from,
                    reason,
                },
            )
            .await?;
        let QuarantineDisposition::Quarantined(state) = disposition else {
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
            .await?
            .map(|row| row.try_get::<_, String>(0))
            .transpose()?;
        if settled.as_deref() != Some(state.as_str()) {
            return Err(DispatchError::Unavailable);
        }
        Ok(())
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
    /// or after the job's expiry. A stale fence matches no row, so the
    /// finish is refused and its audit rolls back with it.
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
        let store = &self.inner.store;
        let mut client = store.connection().await?;
        let transaction = client.transaction().await?;
        store.verify_transaction(&transaction).await?;
        let next = match &sent.outcome {
            SendOutcome::Accepted { .. } => Next::Delivered,
            SendOutcome::Permanent { .. } => Next::DeadLettered,
            SendOutcome::MaybeSent => match job.policy.on_uncertain {
                UncertainOutcome::Hold => Next::Unknown,
                UncertainOutcome::Retry => {
                    after_failure(&transaction, &job.policy, job.attempt, None).await?
                }
            },
            SendOutcome::Transient { retry_after } => {
                after_failure(&transaction, &job.policy, job.attempt, *retry_after).await?
            }
        };
        let disposition = next.disposition();
        store
            .record_attempt_audit(
                &transaction,
                job,
                AttemptAudit::Finished {
                    sent: &sent,
                    disposition,
                },
            )
            .await?;
        let columns = store.finished_columns(job, &sent, disposition)?;
        let changed = self
            .transition(&transaction, job.fence(), next, &columns, false)
            .await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        store.after_finished(&transaction, job, disposition).await?;
        transaction.commit().await?;
        Ok(next.outcome())
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
        if expected_generation <= 0 {
            return Err(DispatchError::Unavailable);
        }
        let store = &self.inner.store;
        let mut client = store.connection().await?;
        let transaction = client.transaction().await?;
        store.verify_transaction(&transaction).await?;
        let (generation, state, _attempt, record) = self
            .read_target(&transaction, key, TargetAction::Replay)
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
        store
            .record_transition_audit(
                &transaction,
                TransitionAudit {
                    key,
                    generation: next_generation,
                    attempt: 0,
                    record: &record,
                    transition: Transition::Replayed { from: state },
                },
            )
            .await?;
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
            .await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        transaction.commit().await?;
        Ok(next_generation)
    }

    /// Withdraw one pending job.
    ///
    /// The cancel locks the row and waits for a concurrent claim, and a
    /// claim skips a row the cancel holds, so exactly one of the two wins: a
    /// cancelled job is never sent again, and a leased job is never
    /// cancelled.
    ///
    /// A pending job may already have been attempted: a scheduled retry,
    /// including one after a maybe-sent answer, is pending and cancellable.
    /// A cancelled job with an attempt above zero may therefore have
    /// reached its receiver; `cancelled` does not mean never sent.
    ///
    /// # Errors
    ///
    /// [`DispatchError::Unavailable`] when the job is absent, the consumer
    /// refuses the cancellation, or a write fails.
    pub async fn cancel(&self, key: &JobKey) -> Result<CancelOutcome, DispatchError> {
        let store = &self.inner.store;
        let mut client = store.connection().await?;
        let transaction = client.transaction().await?;
        store.verify_transaction(&transaction).await?;
        let (generation, state, attempt, record) = self
            .read_target(&transaction, key, TargetAction::Cancel)
            .await?;
        let Some(record) = record else {
            return Err(DispatchError::Unavailable);
        };
        if state != JobState::Pending {
            transaction.commit().await?;
            return Ok(CancelOutcome::NotCancellable(state));
        }
        store
            .record_transition_audit(
                &transaction,
                TransitionAudit {
                    key,
                    generation,
                    attempt,
                    record: &record,
                    transition: Transition::Cancelled,
                },
            )
            .await?;
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
            .await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        transaction.commit().await?;
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
        committed: &mut Committed,
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
        self.guarded(transaction, &selected, committed, async {
            self.recover(transaction, &row, &selected)
                .await
                .map_err(|_| failure)
        })
        .await?;
        Ok(())
    }

    /// Recover one lapsed lease this transaction holds locked.
    async fn recover(
        &self,
        transaction: &Transaction<'_>,
        row: &Row,
        selected: &Selected,
    ) -> Result<(), DispatchError> {
        let store = &self.inner.store;
        let key = selected.key.clone();
        let generation = selected.generation;
        let attempt = selected.attempt;
        let lease_token = row.try_get::<_, Uuid>(4)?;
        let decoded = store.decode_lapsed(row, 5)?;
        if !decoded.policy.is_valid(&self.inner.bound) {
            return Err(DispatchError::Unavailable);
        }
        let next = match decoded.policy.on_uncertain {
            UncertainOutcome::Hold => Next::Unknown,
            UncertainOutcome::Retry => {
                after_failure(transaction, &decoded.policy, attempt, None).await?
            }
        };
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
        store
            .record_transition_audit(
                transaction,
                TransitionAudit {
                    key: &lapsed.key,
                    generation,
                    attempt,
                    record: &lapsed.record,
                    transition: Transition::LeaseLapsed(disposition),
                },
            )
            .await?;
        let fence = Fence {
            id: lapsed.key.id(),
            part: lapsed.key.part(),
            generation,
            attempt,
            lease_token,
        };
        let changed = self
            .transition(transaction, fence, next, &columns, true)
            .await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        Ok(())
    }

    /// Expire at most one undispatched job whose consumer selection says it
    /// has expired.
    async fn expire_one(
        &self,
        transaction: &Transaction<'_>,
        committed: &mut Committed,
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
            .guarded(transaction, &selected, committed, async {
                let record = self
                    .inner
                    .store
                    .decode_expired(&row, 5)
                    .map_err(|_| failure)?;
                self.expire_locked(
                    transaction,
                    &Expiring {
                        key: &selected.key,
                        generation: selected.generation,
                        attempt: selected.attempt,
                        from,
                        record: &record,
                    },
                    update,
                    &[
                        &selected.key.id(),
                        &selected.key.part(),
                        &selected.generation,
                    ],
                )
                .await
                .map_err(|_| failure)
            })
            .await?;
        if expired.is_some() {
            committed.expired += 1;
        }
        Ok(())
    }

    /// Audit, write, and finish one expiry of a job this transaction holds
    /// locked. `update` must change exactly that job's row.
    async fn expire_locked(
        &self,
        transaction: &Transaction<'_>,
        expiring: &Expiring<'_, S::Record>,
        update: &str,
        values: &[&(dyn ToSql + Sync)],
    ) -> Result<(), DispatchError> {
        let store = &self.inner.store;
        store
            .record_transition_audit(
                transaction,
                TransitionAudit {
                    key: expiring.key,
                    generation: expiring.generation,
                    attempt: expiring.attempt,
                    record: expiring.record,
                    transition: Transition::Expired {
                        from: expiring.from,
                    },
                },
            )
            .await?;
        let changed = transaction.execute(update, values).await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        store
            .after_expired(transaction, expiring.key, expiring.record)
            .await
    }

    /// Report what a claim transaction did, once it has committed.
    fn report(&self, committed: Committed) {
        let store = &self.inner.store;
        for _ in 0..committed.expired {
            store.operational_event(DispatchEvent::JobExpired);
        }
        for reason in committed.quarantined {
            store.operational_event(DispatchEvent::JobQuarantined(reason));
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
                "dead_lettered",
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
