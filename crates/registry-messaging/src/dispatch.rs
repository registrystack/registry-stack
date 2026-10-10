// SPDX-License-Identifier: Apache-2.0

//! Dispatch: the worker that sends accepted messages, over the platform
//! dispatch core, and the transport seam a provider kind implements.
//!
//! # The transport seam
//!
//! A provider kind plugs into the worker through one trait,
//! [`MessageTransport`], registered under its provider id in
//! [`Transports`]:
//!
//! ```text
//! #[async_trait]
//! pub trait MessageTransport: Send + Sync {
//!     fn attempt_timeout(&self) -> Duration { DEFAULT_ATTEMPT_TIMEOUT }
//!     fn rate_per_second(&self) -> Option<u32> { None }
//!     fn concurrency_limit(&self) -> Option<NonZeroUsize> { None }
//!     async fn send(&self, message: &OutboundMessage) -> SendOutcome;
//! }
//! ```
//!
//! The worker calls `send` once per leased attempt with the content the
//! message was accepted with: the recipient and the parts rendered at
//! acceptance, read from the payload row under the attempt's lease. A later
//! package never changes what a retry sends. The transport classifies the
//! attempt into the platform's neutral [`SendOutcome`]:
//!
//! - `Accepted` when the provider took the message, with its reference when
//!   it names one;
//! - `Transient` when the send definitely did not happen or was refused in a
//!   way a later attempt may overcome, with the provider's pause hint;
//! - `Permanent` when no retry can change the answer;
//! - `MaybeSent` when the request may have reached the provider and its fate
//!   is unknown.
//!
//! The transport never sees the database, the audit journal, or the lease.
//! It must finish within [`OutboundMessage::budget`] and classify its own
//! deadline, because only it knows whether the request was written: a send
//! that ran out of time before anything left is `Transient`, and one cut off
//! after it left is `MaybeSent`. The worker stops waiting
//! [`TRANSPORT_OVERRUN_ALLOWANCE`] after the budget is spent and records a
//! transport that overran it as `MaybeSent`, because a send cut off
//! mid-flight may have reached the provider.
//! [`OutboundMessage::idempotency_key`] is stable across every attempt of one
//! generation and changes when an operator requeues the message, so a
//! provider that deduplicates on it never delivers one generation twice.
//!
//! A transport that declares a `rate_per_second` is paced: each attempt
//! waits for the provider's next send slot, in turn, before `send` is
//! called (see [`crate::limits`]). When it also declares a
//! `concurrency_limit`, the attempt first waits for one of that many
//! in-flight slots and holds it until `send` returns, so the rate spaces
//! the requests as they leave the transport rather than as they queue for
//! it. The wait is not taken from the send's budget: the job's attempt
//! timeout is the transport's plus [`PACING_ALLOWANCE`], at most sixty
//! seconds, and `send` is still given only the transport's own timeout. An
//! attempt whose slot does not open in that allowance is `Transient`, with
//! the wait as its pause hint: nothing reached the provider. One replica
//! runs at most eight attempts at once, so an attempt that finds every
//! in-flight slot free waits at most seven send intervals, under the
//! allowance at every rate the package accepts; one queued behind slow
//! sends may not, and is retried.
//!
//! The wait is also bounded by the message's `expiresAt`, and no attempt
//! reaches `send` once it has passed: the attempt is `Transient`, which
//! lets the core expire the message, or hold it `unknown` when an earlier
//! attempt may have been sent and its policy retries.
//!
//! A message whose provider has no registered transport is refused
//! permanently with the failure code `provider-unconfigured`, and a message
//! whose payload retention already erased is refused with `payload-erased`.
//!
//! # Policy
//!
//! Each message carries the dispatch policy its sender profile had at
//! acceptance: the attempt count, the backoff bounds, and the
//! uncertain-outcome rule. The worker maps it onto the platform
//! [`JobPolicy`]: exponential backoff doubling from the initial delay, equal
//! jitter, a provider pause hint honoured up to the maximum delay, the
//! message's `expiresAt` as the job's expiry, and the transport's attempt
//! timeout.
//!
//! # Audit
//!
//! Every protected transition accepts a direct intent audit before its write
//! and records its outcome only after commit is established. Consumer attempt
//! rows and provider-reference locks remain in the database transaction. The
//! audit carries identifiers, classes, and dispositions, never a contact, a
//! message part, or provider response text. An attempt's lease token correlates
//! its request and response. Every maintenance or operator invocation captures
//! a fresh UUID, so a rolled-back claim or repeated refused replay cannot reuse
//! an earlier request's correlation.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::num::NonZeroUsize;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use registry_messaging_core::{Channel, RenderedParts};
use registry_platform_audit::AuditEntry;
use registry_platform_dispatch::postgres::{
    AttemptAudit, ClaimRefusal, Decoded, DispatchConfig, DispatchConnection, DispatchEvent,
    DispatchSql, DispatchStore, DispatchTransport, Dispatcher, Disposition, ExpirySql, JobKey,
    JobState, JobTable, LeasedJob, LeasedReadError, Quarantine, QuarantineAudit,
    QuarantineDisposition, QuarantineReason, ReplayAudit, ReplayOutcome, SelectSql, TargetAction,
    Transition, TransitionAudit, TransitionOutcome,
};
use registry_platform_dispatch::{
    idempotency_key, AttemptTimeoutBound, Backoff, ConfigError, DispatchError, FailureCode, Jitter,
    JobPolicy, RetrySchedule, SendOutcome, Sent, UncertainOutcome, MAX_ATTEMPT_TIMEOUT,
};
use serde_json::{json, Value};
use thiserror::Error;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::audit::{MessagingAudit, MESSAGING_AUDIT_SCHEMA};
use crate::http_provider::MAXIMUM_RATE_PER_SECOND;
use crate::limits::{LimitRefusal, PacedSlot, ProviderPacer, PACING_ALLOWANCE};
use crate::metrics::{AttemptOutcome, LimitKind, Metrics};
use crate::store::PostgresStore;

/// The attempt timeout of a transport that does not declare its own.
pub const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

/// The shortest attempt timeout a transport may declare.
pub const MINIMUM_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);

/// How long past an attempt's budget the worker still waits for the
/// transport. The transport classifies its own deadline, since only it knows
/// whether the request was written; this backstop only catches a transport
/// that overruns its budget, and stays well inside the lease's finalization
/// allowance.
pub const TRANSPORT_OVERRUN_ALLOWANCE: Duration = Duration::from_secs(1);

/// The job table's name.
pub const JOB_TABLE: &str = "messaging_dispatch_jobs";

/// The one part every message's job is keyed by.
pub const MESSAGE_PART: &str = "message";

/// The failure code of a message whose provider has no registered
/// transport.
pub const PROVIDER_UNCONFIGURED: &str = "provider-unconfigured";

/// The failure code of a message whose payload was erased before it was
/// sent.
pub const PAYLOAD_ERASED: &str = "payload-erased";

/// The audit events dispatch writes.
pub const ATTEMPT_STARTED_EVENT: &str = "messaging.attempt.started";
pub const ATTEMPT_FINISHED_EVENT: &str = "messaging.attempt.finished";
pub const DISPATCH_TRANSITION_EVENT: &str = "messaging.dispatch.transition";
pub const MESSAGE_QUARANTINED_EVENT: &str = "messaging.message.quarantined";

const PAYLOAD_DOMAIN: &[u8] = b"registry-messaging-payload-v1";
const PROVIDER_KEY_DOMAIN: &[u8] = b"registry-messaging-provider-v1";

const MESSAGE_JOIN: &str =
    "JOIN {schema}.messaging_messages AS message ON message.message_id = state.message_id";
const POLICY_COLUMNS: &str = "message.provider, message.sender_profile, \
     message.maximum_attempts, message.initial_retry_delay_ms, \
     message.maximum_retry_delay_ms, message.on_uncertain, message.expires_at";
const PAYLOAD_SELECT: SelectSql = SelectSql {
    columns: "message.channel, message.sender_profile, message.sender, payload.recipient, \
              payload.subject, payload.text_body, payload.html_body, payload.erased_at IS NOT NULL, \
              message.provider_idempotent_submit",
    joins: "JOIN {schema}.messaging_messages AS message \
                ON message.message_id = state.message_id \
            JOIN {schema}.messaging_message_payloads AS payload \
                ON payload.message_id = state.message_id",
    predicate: "TRUE",
};

/// One attempt of one message, as a transport receives it.
///
/// Its `Debug` names the message and the attempt only: the recipient and
/// the parts never reach a log through it.
#[derive(Clone)]
pub struct OutboundMessage {
    pub message_id: Uuid,
    /// The requeue generation, counted from one.
    pub generation: i64,
    /// This attempt within its generation, counted from one.
    pub attempt: i16,
    pub channel: Channel,
    /// The provider id the sender profile names.
    pub provider: String,
    pub sender_profile: String,
    /// The from address for email, the sender identifier for SMS.
    pub sender: String,
    /// The email address or E.164 number the message goes to.
    pub recipient: String,
    /// The parts rendered at acceptance.
    pub parts: RenderedParts,
    /// A key stable across every attempt of this generation, for a provider
    /// that deduplicates submissions.
    pub idempotency_key: String,
    /// Whether the provider declared idempotent submission when this message
    /// was accepted. A later package cannot withdraw the key from a retry.
    pub provider_idempotent_submit: bool,
    /// What is left of the attempt's timeout. The transport classifies its
    /// own deadline within it; the worker stops waiting
    /// [`TRANSPORT_OVERRUN_ALLOWANCE`] after it is spent.
    pub budget: Duration,
}

impl fmt::Debug for OutboundMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundMessage")
            .field("message_id", &self.message_id)
            .field("generation", &self.generation)
            .field("attempt", &self.attempt)
            .field("channel", &self.channel)
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

/// The send half a provider kind implements. See the module documentation.
#[async_trait]
pub trait MessageTransport: Send + Sync {
    /// The whole budget of one attempt, between one and sixty seconds.
    fn attempt_timeout(&self) -> Duration {
        DEFAULT_ATTEMPT_TIMEOUT
    }

    /// The most sends per second the provider accepts, when it declares a
    /// limit.
    fn rate_per_second(&self) -> Option<u32> {
        None
    }

    /// The most sends the provider has in flight at once, when it bounds
    /// them.
    fn concurrency_limit(&self) -> Option<NonZeroUsize> {
        None
    }

    /// Make one attempt and classify it.
    async fn send(&self, message: &OutboundMessage) -> SendOutcome;
}

/// Why a transport could not be registered.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum TransportRegistrationError {
    #[error("a transport is already registered for this provider")]
    Duplicate,
    #[error("a transport's attempt timeout must be between one and sixty seconds")]
    AttemptTimeout,
    #[error("a transport's rate must be between one and one thousand sends per second")]
    Rate,
}

/// The transports the worker sends through, by provider id.
#[derive(Clone, Default)]
pub struct Transports {
    by_provider: BTreeMap<String, Arc<dyn MessageTransport>>,
    pacers: BTreeMap<String, Arc<ProviderPacer>>,
}

impl fmt::Debug for Transports {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_set()
            .entries(self.by_provider.keys())
            .finish()
    }
}

impl Transports {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `transport` for `provider`.
    ///
    /// # Errors
    ///
    /// [`TransportRegistrationError`] when the provider already has one,
    /// the transport's attempt timeout is outside one to sixty seconds, or
    /// its rate is outside one to one thousand sends per second.
    pub fn insert(
        &mut self,
        provider: impl Into<String>,
        transport: Arc<dyn MessageTransport>,
    ) -> Result<(), TransportRegistrationError> {
        if !attempt_bound().contains(transport.attempt_timeout()) {
            return Err(TransportRegistrationError::AttemptTimeout);
        }
        let provider = provider.into();
        if self.by_provider.contains_key(&provider) {
            return Err(TransportRegistrationError::Duplicate);
        }
        if let Some(rate) = transport.rate_per_second() {
            if rate > MAXIMUM_RATE_PER_SECOND {
                return Err(TransportRegistrationError::Rate);
            }
            let pacer = ProviderPacer::new(&provider, rate, transport.concurrency_limit())
                .map_err(|_| TransportRegistrationError::Rate)?;
            self.pacers.insert(provider.clone(), Arc::new(pacer));
        }
        self.by_provider.insert(provider, transport);
        Ok(())
    }

    #[must_use]
    pub fn get(&self, provider: &str) -> Option<&Arc<dyn MessageTransport>> {
        self.by_provider.get(provider)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_provider.is_empty()
    }

    /// The job's attempt timeout: the transport's, plus the pacing
    /// allowance for a paced provider, at most sixty seconds.
    fn attempt_timeout(&self, provider: &str) -> Duration {
        let send = self
            .get(provider)
            .map_or(DEFAULT_ATTEMPT_TIMEOUT, |transport| {
                transport.attempt_timeout()
            });
        if self.pacers.contains_key(provider) {
            (send + PACING_ALLOWANCE).min(MAX_ATTEMPT_TIMEOUT)
        } else {
            send
        }
    }

    fn pacer(&self, provider: &str) -> Option<&ProviderPacer> {
        self.pacers.get(provider).map(Arc::as_ref)
    }
}

fn attempt_bound() -> AttemptTimeoutBound {
    // Both bounds are constants inside the platform's range.
    AttemptTimeoutBound::new(MINIMUM_ATTEMPT_TIMEOUT, MAX_ATTEMPT_TIMEOUT)
        .unwrap_or_else(|_| unreachable!("the messaging attempt bound is valid"))
}

/// Who asked for a transition the worker does not make itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Actor {
    /// The dispatch worker: claims, finishes, recovery, and expiry.
    Worker,
    /// An authenticated caller, named by its keyed pseudonym.
    Caller {
        access_profile: String,
        principal_pseudonym: String,
    },
    /// An operator through `messagingctl`.
    OperatorTool,
}

impl Actor {
    pub(crate) fn to_json(&self) -> Value {
        match self {
            Self::Worker => json!({"kind": "worker"}),
            Self::Caller {
                access_profile,
                principal_pseudonym,
            } => json!({
                "kind": "caller",
                "accessProfile": access_profile,
                "principalPseudonym": principal_pseudonym,
            }),
            Self::OperatorTool => json!({"kind": "operator-tool"}),
        }
    }
}

tokio::task_local! {
    static ACTOR: Actor;
}

/// Run `future` with `actor` named in every transition audit it writes.
pub async fn acting_as<F: Future>(actor: Actor, future: F) -> F::Output {
    ACTOR.scope(actor, future).await
}

fn captured_actor() -> Actor {
    ACTOR.try_with(Clone::clone).unwrap_or(Actor::Worker)
}

#[derive(Clone, Debug)]
#[doc(hidden)]
pub struct MessageAuditContext {
    actor: Actor,
    invocation_id: Uuid,
}

/// What a claim decodes: the provider and sender profile the message was
/// accepted for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageJob {
    pub provider: String,
    pub sender_profile: String,
}

/// One pooled runtime client framed for the dispatch core's connection
/// seam. The pool receives the client back when this wrapper is dropped.
struct PooledClient(deadpool_postgres::Client);

impl Deref for PooledClient {
    type Target = tokio_postgres::Client;

    fn deref(&self) -> &tokio_postgres::Client {
        &self.0
    }
}

impl DerefMut for PooledClient {
    fn deref_mut(&mut self) -> &mut tokio_postgres::Client {
        &mut self.0
    }
}

/// The Messaging consumer of the platform dispatch core.
pub struct MessageDispatchStore {
    store: PostgresStore,
    schema: String,
    transports: Arc<Transports>,
    audit: Arc<MessagingAudit>,
}

impl fmt::Debug for MessageDispatchStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageDispatchStore")
            .field("schema", &self.schema)
            .finish_non_exhaustive()
    }
}

pub type MessageDispatcher = Dispatcher<MessageDispatchStore>;

/// The dispatcher over `store`'s job table in `schema`, the schema the
/// store's sessions resolve names in.
///
/// # Errors
///
/// [`ConfigError`] when `schema` is not a plain identifier.
pub fn dispatcher(
    store: PostgresStore,
    schema: &str,
    transports: Arc<Transports>,
    audit: Arc<MessagingAudit>,
) -> Result<MessageDispatcher, ConfigError> {
    let table = JobTable::new(schema, JOB_TABLE, "message_id", "part")?;
    Dispatcher::new(
        MessageDispatchStore {
            store,
            schema: schema.to_owned(),
            transports,
            audit,
        },
        DispatchConfig {
            table,
            sql: dispatch_sql(),
            attempt_timeout: attempt_bound(),
            replayable: &[JobState::DeadLettered, JobState::Unknown],
        },
    )
}

fn dispatch_sql() -> DispatchSql {
    let policy = SelectSql {
        columns: POLICY_COLUMNS,
        joins: MESSAGE_JOIN,
        predicate: "TRUE",
    };
    let record = SelectSql {
        columns: "message.provider, message.sender_profile",
        joins: MESSAGE_JOIN,
        predicate: "TRUE",
    };
    DispatchSql {
        claim: policy,
        lapsed: policy,
        expiry: Some(ExpirySql {
            states: &[JobState::Pending],
            select: SelectSql {
                predicate: "message.expires_at <= transaction_timestamp()",
                ..policy
            },
            order_by: "message.expires_at",
            lock_of: "state",
        }),
        target: record,
    }
}

impl MessageDispatchStore {
    fn decode_policy(&self, row: &Row, first: usize) -> Result<Decoded<MessageJob>, DispatchError> {
        let provider = row.try_get::<_, String>(first)?;
        let sender_profile = row.try_get::<_, String>(first + 1)?;
        let maximum_attempts = row.try_get::<_, i16>(first + 2)?;
        let initial_ms = row.try_get::<_, i64>(first + 3)?;
        let maximum_ms = row.try_get::<_, i64>(first + 4)?;
        let on_uncertain = row.try_get::<_, String>(first + 5)?;
        let expires_at = row.try_get::<_, SystemTime>(first + 6)?;
        let millis = |value: i64| {
            u64::try_from(value)
                .map(Duration::from_millis)
                .map_err(|_| DispatchError::Unavailable)
        };
        let policy = JobPolicy {
            attempt_timeout: self.transports.attempt_timeout(&provider),
            maximum_attempts,
            retry: RetrySchedule::Backoff(Backoff {
                initial: millis(initial_ms)?,
                maximum: millis(maximum_ms)?,
                multiplier: 2,
                jitter: Jitter::Equal,
            }),
            on_uncertain: match on_uncertain.as_str() {
                "hold" => UncertainOutcome::Hold,
                "retry" => UncertainOutcome::RetryThenHold,
                _ => return Err(DispatchError::Unavailable),
            },
            expires_at: Some(expires_at),
        };
        Ok(Decoded {
            policy,
            job: MessageJob {
                provider,
                sender_profile,
            },
        })
    }
}

fn decode_record(row: &Row, first: usize) -> Result<MessageJob, DispatchError> {
    Ok(MessageJob {
        provider: row.try_get::<_, String>(first)?,
        sender_profile: row.try_get::<_, String>(first + 1)?,
    })
}

const fn attempt_outcome(outcome: &SendOutcome) -> AttemptOutcome {
    match outcome {
        SendOutcome::Accepted { .. } => AttemptOutcome::Accepted,
        SendOutcome::Transient { .. } => AttemptOutcome::Transient,
        SendOutcome::Permanent { .. } => AttemptOutcome::Permanent,
        SendOutcome::MaybeSent => AttemptOutcome::MaybeSent,
    }
}

const fn outcome_class(outcome: &SendOutcome) -> &'static str {
    attempt_outcome(outcome).as_str()
}

const fn quarantine_reason(reason: QuarantineReason) -> &'static str {
    match reason {
        QuarantineReason::RecoveryFailed => "recovery-failed",
        QuarantineReason::ExpiryFailed => "expiry-failed",
        QuarantineReason::ClaimUnreadable => "claim-unreadable",
        QuarantineReason::PolicyRefused => "policy-refused",
        QuarantineReason::ClaimExpiryFailed => "claim-expiry-failed",
    }
}

const fn event_name(event: DispatchEvent) -> &'static str {
    match event {
        DispatchEvent::IterationFailed => "iteration-failed",
        DispatchEvent::TransitionFailed(_) => "transition-failed",
        DispatchEvent::JobExpired => "job-expired",
        DispatchEvent::JobQuarantined(_) => "job-quarantined",
    }
}

fn attempt_correlation(job: &LeasedJob<MessageJob>) -> String {
    format!(
        "dispatch/{}/{}/{}/{}/attempt",
        job.key.id(),
        job.generation,
        job.attempt,
        job.lease_token
    )
}

fn transition_correlation(
    audit: &TransitionAudit<MessageJob>,
    context: &MessageAuditContext,
) -> String {
    format!(
        "dispatch/{}/{}/{}/{}/{}",
        audit.key.id(),
        audit.generation,
        audit.attempt,
        context.invocation_id,
        audit.transition.as_str()
    )
}

fn replay_correlation(audit: &ReplayAudit<MessageJob>, context: &MessageAuditContext) -> String {
    format!(
        "dispatch/{}/{}/0/{}/replay",
        audit.key.id(),
        audit.generation,
        context.invocation_id
    )
}

fn quarantine_correlation(
    key: &JobKey,
    generation: i64,
    attempt: i16,
    context: &MessageAuditContext,
) -> String {
    format!(
        "dispatch/{}/{}/{generation}/{attempt}/{}/quarantine",
        key.id(),
        key.part(),
        context.invocation_id
    )
}

const fn transition_outcome(outcome: TransitionOutcome) -> &'static str {
    match outcome {
        TransitionOutcome::Committed => "committed",
        TransitionOutcome::Refused => "refused",
        TransitionOutcome::Unfinished => "unfinished",
    }
}

const fn replay_outcome(outcome: ReplayOutcome) -> &'static str {
    match outcome {
        ReplayOutcome::Requested => "requested",
        ReplayOutcome::Committed => "committed",
        ReplayOutcome::Refused => "refused",
        ReplayOutcome::Unfinished => "unfinished",
    }
}

const fn transition_disposition(
    transition: Transition,
    outcome: TransitionOutcome,
) -> &'static str {
    match outcome {
        TransitionOutcome::Committed => transition.disposition().as_str(),
        TransitionOutcome::Refused => match transition {
            Transition::LeaseLapsed(_) => JobState::Leased.as_str(),
            Transition::Expired { from, .. } => from.as_str(),
            Transition::Cancelled => JobState::Pending.as_str(),
        },
        TransitionOutcome::Unfinished => Disposition::Unknown.as_str(),
    }
}

const fn replay_disposition(from: JobState, outcome: ReplayOutcome) -> &'static str {
    match outcome {
        ReplayOutcome::Requested | ReplayOutcome::Committed => Disposition::ReplayPending.as_str(),
        ReplayOutcome::Refused => from.as_str(),
        ReplayOutcome::Unfinished => Disposition::Unknown.as_str(),
    }
}

#[async_trait]
impl DispatchStore for MessageDispatchStore {
    type Job = MessageJob;
    type Record = MessageJob;
    type Detail = ();
    type Context = MessageAuditContext;

    fn capture_context(&self) -> MessageAuditContext {
        MessageAuditContext {
            actor: captured_actor(),
            invocation_id: Uuid::new_v4(),
        }
    }

    async fn connection(&self) -> Result<DispatchConnection, DispatchError> {
        let client = self
            .store
            .client()
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        Ok(Box::new(PooledClient(client)))
    }

    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DispatchError> {
        let schema: Option<String> = transaction
            .query_one("SELECT current_schema()", &[])
            .await?
            .try_get(0)?;
        if schema.as_deref() == Some(self.schema.as_str()) {
            Ok(())
        } else {
            Err(DispatchError::Unavailable)
        }
    }

    fn decode_claim(&self, row: &Row, first: usize) -> Result<Decoded<MessageJob>, ClaimRefusal> {
        self.decode_policy(row, first)
            .map_err(|_| ClaimRefusal::Unavailable)
    }

    fn claim_record(&self, job: &MessageJob) -> MessageJob {
        job.clone()
    }

    fn decode_lapsed(&self, row: &Row, first: usize) -> Result<Decoded<MessageJob>, DispatchError> {
        self.decode_policy(row, first)
    }

    fn decode_expired(&self, row: &Row, first: usize) -> Result<MessageJob, DispatchError> {
        decode_record(row, first)
    }

    fn decode_expired_on_uncertain(
        &self,
        row: &Row,
        first: usize,
    ) -> Result<UncertainOutcome, DispatchError> {
        self.decode_policy(row, first)
            .map(|decoded| decoded.policy.on_uncertain)
    }

    fn decode_target(
        &self,
        row: &Row,
        first: usize,
        _key: &JobKey,
        _action: TargetAction,
    ) -> Result<Option<MessageJob>, DispatchError> {
        decode_record(row, first).map(Some)
    }

    async fn write_attempt(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<MessageJob>,
        audit: AttemptAudit<'_, ()>,
    ) -> Result<(), DispatchError> {
        let message_id = job.key.id();
        match audit {
            AttemptAudit::Started => {
                transaction
                    .execute(
                        "INSERT INTO messaging_attempts \
                             (message_id, generation, attempt, started_at, outcome) \
                         VALUES ($1, $2, $3, $4, 'in-progress')",
                        &[
                            &message_id,
                            &job.generation,
                            &job.attempt,
                            &job.attempt_started_at,
                        ],
                    )
                    .await?;
            }
            AttemptAudit::Finished {
                sent,
                disposition: _,
            } => {
                let (reference, failure) = match &sent.outcome {
                    SendOutcome::Accepted { receiver_reference } => (
                        receiver_reference
                            .as_ref()
                            .map(|reference| reference.as_str().to_owned()),
                        None,
                    ),
                    SendOutcome::Permanent { code } => (None, Some(code.as_str().to_owned())),
                    SendOutcome::Transient { .. } | SendOutcome::MaybeSent => (None, None),
                };
                let class = outcome_class(&sent.outcome);
                if let Some(reference) = &reference {
                    crate::receipts::lock_provider_reference(
                        transaction,
                        &job.job.provider,
                        reference,
                    )
                    .await?;
                }
                let changed = transaction
                    .execute(
                        "UPDATE messaging_attempts \
                            SET outcome = $4, finished_at = transaction_timestamp(), \
                                provider_reference = $5, failure_code = $6 \
                          WHERE message_id = $1 AND generation = $2 AND attempt = $3 \
                            AND outcome = 'in-progress'",
                        &[
                            &message_id,
                            &job.generation,
                            &job.attempt,
                            &class,
                            &reference,
                            &failure,
                        ],
                    )
                    .await?;
                if changed != 1 {
                    return Err(DispatchError::Unavailable);
                }
            }
            AttemptAudit::Interrupted { .. } => {}
        }
        Ok(())
    }

    async fn write_transition(
        &self,
        transaction: &Transaction<'_>,
        audit: &TransitionAudit<MessageJob>,
    ) -> Result<(), DispatchError> {
        let message_id = audit.key.id();
        if let Transition::LeaseLapsed(_) = audit.transition {
            transaction
                .execute(
                    "UPDATE messaging_attempts \
                        SET outcome = 'interrupted', finished_at = transaction_timestamp() \
                      WHERE message_id = $1 AND generation = $2 AND attempt = $3 \
                        AND outcome = 'in-progress'",
                    &[&message_id, &audit.generation, &audit.attempt],
                )
                .await?;
        }
        Ok(())
    }

    async fn record_attempt_audit(
        &self,
        job: &LeasedJob<MessageJob>,
        audit: AttemptAudit<'_, ()>,
        context: &MessageAuditContext,
    ) -> Result<(), DispatchError> {
        let (kind, record) = match audit {
            AttemptAudit::Started => (
                true,
                json!({
                    "event": ATTEMPT_STARTED_EVENT,
                    "messageId": job.key.id().to_string(),
                    "generation": job.generation,
                    "attempt": job.attempt,
                    "provider": job.job.provider,
                    "senderProfile": job.job.sender_profile,
                    "outcome": "requested",
                    "disposition": Disposition::Leased.as_str(),
                    "actor": context.actor.to_json(),
                }),
            ),
            AttemptAudit::Finished { sent, disposition } => {
                let failure = match &sent.outcome {
                    SendOutcome::Permanent { code } => Some(code.as_str()),
                    _ => None,
                };
                let provider_reference = matches!(
                    sent.outcome,
                    SendOutcome::Accepted {
                        receiver_reference: Some(_)
                    }
                );
                (
                    false,
                    json!({
                        "event": ATTEMPT_FINISHED_EVENT,
                        "messageId": job.key.id().to_string(),
                        "generation": job.generation,
                        "attempt": job.attempt,
                        "attemptOutcome": outcome_class(&sent.outcome),
                        "providerReference": provider_reference,
                        "failureCode": failure,
                        "outcome": "committed",
                        "disposition": disposition.as_str(),
                        "actor": context.actor.to_json(),
                    }),
                )
            }
            AttemptAudit::Interrupted { disposition } => (
                false,
                json!({
                    "event": ATTEMPT_FINISHED_EVENT,
                    "messageId": job.key.id().to_string(),
                    "generation": job.generation,
                    "attempt": job.attempt,
                    "attemptOutcome": "interrupted",
                    "outcome": if disposition == Disposition::Unknown { "unfinished" } else { "refused" },
                    "disposition": disposition.as_str(),
                    "actor": context.actor.to_json(),
                }),
            ),
        };
        let correlation = attempt_correlation(job);
        let entry = if kind {
            AuditEntry::request(MESSAGING_AUDIT_SCHEMA, correlation, record)
        } else {
            AuditEntry::response(MESSAGING_AUDIT_SCHEMA, correlation, record)
        };
        self.audit
            .append(entry)
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    async fn begin_transition_audit(
        &self,
        audit: &TransitionAudit<MessageJob>,
        context: &MessageAuditContext,
    ) -> Result<(), DispatchError> {
        let from = match audit.transition {
            Transition::Expired { from, .. } => from.as_str(),
            Transition::LeaseLapsed(_) => JobState::Leased.as_str(),
            Transition::Cancelled => JobState::Pending.as_str(),
        };
        self.audit
            .append(AuditEntry::request(
                MESSAGING_AUDIT_SCHEMA,
                transition_correlation(audit, context),
                json!({
                    "event": DISPATCH_TRANSITION_EVENT,
                    "messageId": audit.key.id().to_string(),
                    "generation": audit.generation,
                    "attempt": audit.attempt,
                    "transition": audit.transition.as_str(),
                    "from": from,
                    "outcome": "requested",
                    "disposition": audit.transition.disposition().as_str(),
                    "senderProfile": audit.record.sender_profile,
                    "actor": context.actor.to_json(),
                }),
            ))
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    async fn record_transition_audit(
        &self,
        audit: &TransitionAudit<MessageJob>,
        outcome: TransitionOutcome,
        context: &MessageAuditContext,
    ) -> Result<(), DispatchError> {
        let disposition = transition_disposition(audit.transition, outcome);
        self.audit
            .append(AuditEntry::response(
                MESSAGING_AUDIT_SCHEMA,
                transition_correlation(audit, context),
                json!({
                    "event": DISPATCH_TRANSITION_EVENT,
                    "messageId": audit.key.id().to_string(),
                    "generation": audit.generation,
                    "attempt": audit.attempt,
                    "transition": audit.transition.as_str(),
                    "outcome": transition_outcome(outcome),
                    "disposition": disposition,
                    "senderProfile": audit.record.sender_profile,
                    "actor": context.actor.to_json(),
                }),
            ))
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    async fn record_replay_audit(
        &self,
        audit: &ReplayAudit<MessageJob>,
        context: &MessageAuditContext,
    ) -> Result<(), DispatchError> {
        let disposition = replay_disposition(audit.from, audit.outcome);
        let record = json!({
            "event": DISPATCH_TRANSITION_EVENT,
            "messageId": audit.key.id().to_string(),
            "generation": audit.generation,
            "attempt": 0,
            "transition": "replayed",
            "from": audit.from.as_str(),
            "outcome": replay_outcome(audit.outcome),
            "disposition": disposition,
            "senderProfile": audit.record.sender_profile,
            "actor": context.actor.to_json(),
        });
        let correlation = replay_correlation(audit, context);
        let entry = if audit.outcome == ReplayOutcome::Requested {
            AuditEntry::request(MESSAGING_AUDIT_SCHEMA, correlation, record)
        } else {
            AuditEntry::response(MESSAGING_AUDIT_SCHEMA, correlation, record)
        };
        self.audit
            .append(entry)
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    fn operational_event(&self, event: DispatchEvent) {
        let reason = match event {
            DispatchEvent::JobQuarantined(reason) => Some(quarantine_reason(reason)),
            DispatchEvent::IterationFailed
            | DispatchEvent::TransitionFailed(_)
            | DispatchEvent::JobExpired => None,
        };
        match event {
            DispatchEvent::JobExpired => {
                tracing::info!(
                    event = event_name(event),
                    "a Messaging message expired unsent"
                );
            }
            _ => tracing::warn!(
                event = event_name(event),
                reason,
                "the Messaging dispatch worker reported an event"
            ),
        }
    }

    fn quarantines(&self) -> bool {
        true
    }

    async fn may_have_reached_receiver(
        &self,
        transaction: &Transaction<'_>,
        key: &JobKey,
        generation: i64,
        attempt: i16,
    ) -> Result<bool, DispatchError> {
        // Only an attempt that ended transient or permanent is known not to
        // have reached the provider; one still in progress, answered
        // maybe-sent, or interrupted by a lapsed lease may have.
        Ok(transaction
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM messaging_attempts \
                  WHERE message_id = $1 AND generation = $2 AND attempt <= $3 \
                    AND outcome IN ('in-progress', 'maybe-sent', 'interrupted'))",
                &[&key.id(), &generation, &attempt],
            )
            .await?
            .try_get(0)?)
    }

    async fn begin_quarantine_audit(
        &self,
        quarantine: Quarantine<'_>,
        context: &MessageAuditContext,
    ) -> Result<(), DispatchError> {
        let (disposition, _) = quarantine_state(&quarantine);
        self.audit
            .append(AuditEntry::request(
                MESSAGING_AUDIT_SCHEMA,
                quarantine_correlation(
                    quarantine.key,
                    quarantine.generation,
                    quarantine.attempt,
                    context,
                ),
                json!({
                    "event": MESSAGE_QUARANTINED_EVENT,
                    "messageId": quarantine.key.id().to_string(),
                    "generation": quarantine.generation,
                    "attempt": quarantine.attempt,
                    "from": quarantine.from.as_str(),
                    "reason": quarantine_reason(quarantine.reason),
                    "outcome": "requested",
                    "disposition": disposition.as_str(),
                    "actor": context.actor.to_json(),
                }),
            ))
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    async fn record_quarantine_audit(
        &self,
        audit: &QuarantineAudit,
        outcome: TransitionOutcome,
        context: &MessageAuditContext,
    ) -> Result<(), DispatchError> {
        let disposition = match outcome {
            TransitionOutcome::Committed => audit.disposition.unwrap_or(audit.from),
            TransitionOutcome::Refused => audit.from,
            TransitionOutcome::Unfinished => JobState::Unknown,
        };
        self.audit
            .append(AuditEntry::response(
                MESSAGING_AUDIT_SCHEMA,
                quarantine_correlation(&audit.key, audit.generation, audit.attempt, context),
                json!({
                    "event": MESSAGE_QUARANTINED_EVENT,
                    "messageId": audit.key.id().to_string(),
                    "generation": audit.generation,
                    "attempt": audit.attempt,
                    "from": audit.from.as_str(),
                    "reason": quarantine_reason(audit.reason),
                    "outcome": transition_outcome(outcome),
                    "disposition": disposition.as_str(),
                    "actor": context.actor.to_json(),
                }),
            ))
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    async fn quarantine(
        &self,
        transaction: &Transaction<'_>,
        quarantine: Quarantine<'_>,
    ) -> Result<QuarantineDisposition, DispatchError> {
        let (state, stamp) = quarantine_state(&quarantine);
        let message_id = quarantine.key.id();
        let changed = transaction
            .execute(
                &format!(
                    "UPDATE {JOB_TABLE} \
                        SET state = $4, next_attempt_at = NULL, attempt_started_at = NULL, \
                            lease_expires_at = NULL, lease_token = NULL, \
                            {stamp}updated_at = transaction_timestamp() \
                      WHERE message_id = $1 AND part = $2 AND generation = $3"
                ),
                &[
                    &message_id,
                    &quarantine.key.part(),
                    &quarantine.generation,
                    &state.as_str(),
                ],
            )
            .await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        transaction
            .execute(
                "UPDATE messaging_attempts \
                    SET outcome = 'interrupted', finished_at = transaction_timestamp() \
                  WHERE message_id = $1 AND generation = $2 AND outcome = 'in-progress'",
                &[&message_id, &quarantine.generation],
            )
            .await?;
        Ok(QuarantineDisposition::Quarantined(state))
    }
}

/// The state a quarantined row is set aside in, with the SQL assignment
/// that stamps it. A row that may have reached its provider becomes
/// `unknown` for an operator to settle; one attempted only without reaching
/// it becomes a failure an operator can requeue; one never attempted
/// expires, since nothing was sent.
fn quarantine_state(quarantine: &Quarantine<'_>) -> (JobState, &'static str) {
    if quarantine.may_have_reached_receiver {
        (JobState::Unknown, "")
    } else if quarantine.attempt > 0 {
        (
            JobState::DeadLettered,
            "dead_lettered_at = transaction_timestamp(), ",
        )
    } else {
        (JobState::Expired, "expired_at = transaction_timestamp(), ")
    }
}

/// The persisted content of one leased message.
struct Payload {
    channel: Channel,
    sender_profile: String,
    sender: String,
    recipient: String,
    parts: RenderedParts,
    provider_idempotent_submit: bool,
}

fn decode_payload(row: &Row, first: usize) -> Result<Option<Payload>, DispatchError> {
    if row.try_get::<_, bool>(first + 7)? {
        return Ok(None);
    }
    let channel = match row.try_get::<_, String>(first)?.as_str() {
        "email" => Channel::Email,
        "sms" => Channel::Sms,
        _ => return Err(DispatchError::Unavailable),
    };
    let recipient = row
        .try_get::<_, Option<String>>(first + 3)?
        .ok_or(DispatchError::Unavailable)?;
    let text = row
        .try_get::<_, Option<String>>(first + 5)?
        .ok_or(DispatchError::Unavailable)?;
    Ok(Some(Payload {
        channel,
        sender_profile: row.try_get(first + 1)?,
        sender: row.try_get(first + 2)?,
        recipient,
        parts: RenderedParts {
            subject: row.try_get(first + 4)?,
            text,
            html: row.try_get(first + 6)?,
        },
        provider_idempotent_submit: row.try_get(first + 8)?,
    }))
}

/// The key a provider may deduplicate on: the message, its generation, and
/// a digest of the content it carries.
fn provider_idempotency_key(message_id: Uuid, generation: i64, payload: &Payload) -> String {
    let digest = idempotency_key(
        PAYLOAD_DOMAIN,
        &[
            payload.recipient.as_bytes(),
            payload.parts.subject.as_deref().unwrap_or("").as_bytes(),
            payload.parts.text.as_bytes(),
            payload.parts.html.as_deref().unwrap_or("").as_bytes(),
        ],
    );
    idempotency_key(
        PROVIDER_KEY_DOMAIN,
        &[
            message_id.as_bytes(),
            &generation.to_be_bytes(),
            digest.as_bytes(),
        ],
    )
}

fn permanent(code: &'static str) -> Sent<()> {
    Sent {
        outcome: SendOutcome::Permanent {
            code: FailureCode::new(code)
                .unwrap_or_else(|_| unreachable!("the messaging failure codes are valid")),
        },
        detail: (),
    }
}

const fn transient() -> Sent<()> {
    Sent {
        outcome: SendOutcome::Transient { retry_after: None },
        detail: (),
    }
}

/// The dispatch core's transport: reads a leased message's payload and
/// hands it to the transport its provider is registered with, counting
/// every attempt's outcome and every pacing refusal.
#[derive(Clone)]
pub struct MessageSender {
    dispatcher: MessageDispatcher,
    transports: Arc<Transports>,
    metrics: Arc<Metrics>,
}

impl MessageSender {
    #[must_use]
    pub fn new(
        dispatcher: MessageDispatcher,
        transports: Arc<Transports>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            dispatcher,
            transports,
            metrics,
        }
    }

    /// Wait for the paced provider's next send slot, or refuse the attempt
    /// with the outcome it records.
    async fn pace(
        &self,
        pacer: &ProviderPacer,
        transport: &dyn MessageTransport,
        job: &LeasedJob<MessageJob>,
    ) -> Result<PacedSlot, Sent<()>> {
        let Some(budget) = job.remaining_budget(SystemTime::now()) else {
            return Err(transient());
        };
        // The wait is bounded by what the budget holds beyond the send's
        // own timeout, so pacing never shortens the send, and by the
        // message's expiry, so a slot that opens too late is refused now.
        let mut wait = budget.saturating_sub(transport.attempt_timeout());
        if let Some(expires_at) = job.policy.expires_at {
            let Ok(left) = expires_at.duration_since(SystemTime::now()) else {
                return Err(transient());
            };
            wait = wait.min(left);
        }
        match pacer.acquire(tokio::time::Instant::now() + wait).await {
            Ok(slot) => Ok(slot),
            Err(LimitRefusal::Exceeded { retry_after }) => {
                self.metrics.record_limit_refusal(LimitKind::Pacing);
                Err(Sent {
                    outcome: SendOutcome::Transient {
                        retry_after: Some(retry_after),
                    },
                    detail: (),
                })
            }
            Err(LimitRefusal::Unavailable) => Err(transient()),
        }
    }

    async fn attempt(&self, job: &LeasedJob<MessageJob>) -> Sent<()> {
        let Some(transport) = self.transports.get(&job.job.provider) else {
            tracing::warn!(
                failure = PROVIDER_UNCONFIGURED,
                "a Messaging message names a provider with no transport"
            );
            return permanent(PROVIDER_UNCONFIGURED);
        };
        let payload = match self
            .dispatcher
            .read_leased(job.fence(), &PAYLOAD_SELECT, decode_payload)
            .await
        {
            Ok(Some(payload)) => payload,
            Ok(None) => return permanent(PAYLOAD_ERASED),
            // Nothing was sent: the attempt is retried under its policy.
            Err(LeasedReadError::Unavailable | LeasedReadError::Refused(_)) => {
                return transient();
            }
        };
        // Held through the send, so a provider's in-flight bound counts the
        // paced sends as they leave.
        let _paced = match self.transports.pacer(&job.job.provider) {
            Some(pacer) => match self.pace(pacer, transport.as_ref(), job).await {
                Ok(slot) => Some(slot),
                Err(refused) => return refused,
            },
            None => None,
        };
        // Nothing reaches the provider once the message has expired; the
        // transient failure lets the core expire it.
        if expired(job.policy.expires_at) {
            return transient();
        }
        let Some(budget) = job.remaining_budget(SystemTime::now()) else {
            return transient();
        };
        let budget = budget.min(transport.attempt_timeout());
        let idempotency_key = provider_idempotency_key(job.key.id(), job.generation, &payload);
        let message = OutboundMessage {
            message_id: job.key.id(),
            generation: job.generation,
            attempt: job.attempt,
            channel: payload.channel,
            provider: job.job.provider.clone(),
            sender_profile: payload.sender_profile,
            sender: payload.sender,
            idempotency_key,
            provider_idempotent_submit: payload.provider_idempotent_submit,
            recipient: payload.recipient,
            parts: payload.parts,
            budget,
        };
        Sent {
            outcome: send_within_budget(transport.as_ref(), &message).await,
            detail: (),
        }
    }
}

/// Whether `expires_at` names a moment already past.
fn expired(expires_at: Option<SystemTime>) -> bool {
    expires_at.is_some_and(|expires_at| expires_at <= SystemTime::now())
}

/// Make one attempt through `transport`, which classifies its own deadline
/// within `message.budget`. The worker stops waiting only
/// [`TRANSPORT_OVERRUN_ALLOWANCE`] later, and records an attempt cut off
/// there as `MaybeSent`.
pub(crate) async fn send_within_budget(
    transport: &dyn MessageTransport,
    message: &OutboundMessage,
) -> SendOutcome {
    let backstop = message.budget + TRANSPORT_OVERRUN_ALLOWANCE;
    match tokio::time::timeout(backstop, transport.send(message)).await {
        Ok(outcome) => outcome,
        // A send cut off mid-flight may have reached the provider.
        Err(_elapsed) => SendOutcome::MaybeSent,
    }
}

#[async_trait]
impl DispatchTransport for MessageSender {
    type Job = MessageJob;
    type Detail = ();

    async fn send(&self, job: &LeasedJob<MessageJob>) -> Result<Sent<()>, DispatchError> {
        let sent = self.attempt(job).await;
        self.metrics.record_attempt(attempt_outcome(&sent.outcome));
        Ok(sent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(Duration);

    #[async_trait]
    impl MessageTransport for Fixed {
        fn attempt_timeout(&self) -> Duration {
            self.0
        }

        async fn send(&self, _message: &OutboundMessage) -> SendOutcome {
            SendOutcome::MaybeSent
        }
    }

    #[test]
    fn a_transport_timeout_outside_one_to_sixty_seconds_is_refused() {
        let mut transports = Transports::new();
        for timeout in [Duration::from_millis(999), Duration::from_secs(61)] {
            assert_eq!(
                transports.insert("relay", Arc::new(Fixed(timeout))),
                Err(TransportRegistrationError::AttemptTimeout)
            );
        }
        transports
            .insert("relay", Arc::new(Fixed(Duration::from_secs(60))))
            .unwrap();
        assert_eq!(
            transports.insert("relay", Arc::new(Fixed(Duration::from_secs(5)))),
            Err(TransportRegistrationError::Duplicate)
        );
        assert_eq!(transports.attempt_timeout("relay"), Duration::from_secs(60));
        assert_eq!(
            transports.attempt_timeout("absent"),
            DEFAULT_ATTEMPT_TIMEOUT
        );
    }

    struct Paced(Duration, u32);

    #[async_trait]
    impl MessageTransport for Paced {
        fn attempt_timeout(&self) -> Duration {
            self.0
        }

        fn rate_per_second(&self) -> Option<u32> {
            Some(self.1)
        }

        async fn send(&self, _message: &OutboundMessage) -> SendOutcome {
            SendOutcome::MaybeSent
        }
    }

    #[test]
    fn a_paced_provider_gets_the_pacing_allowance_within_the_attempt_bound() {
        let mut transports = Transports::new();
        for rate in [0, MAXIMUM_RATE_PER_SECOND + 1] {
            assert_eq!(
                transports.insert("gateway", Arc::new(Paced(Duration::from_secs(5), rate))),
                Err(TransportRegistrationError::Rate)
            );
        }
        assert!(transports.get("gateway").is_none());
        transports
            .insert("gateway", Arc::new(Paced(Duration::from_secs(5), 20)))
            .unwrap();
        transports
            .insert("slow-gateway", Arc::new(Paced(Duration::from_secs(55), 20)))
            .unwrap();
        transports
            .insert("relay", Arc::new(Fixed(Duration::from_secs(5))))
            .unwrap();
        assert_eq!(
            transports.attempt_timeout("gateway"),
            Duration::from_secs(5) + PACING_ALLOWANCE
        );
        assert_eq!(
            transports.attempt_timeout("slow-gateway"),
            MAX_ATTEMPT_TIMEOUT
        );
        assert_eq!(transports.attempt_timeout("relay"), Duration::from_secs(5));
        assert!(transports.pacer("gateway").is_some());
        assert!(transports.pacer("relay").is_none());
    }

    #[test]
    fn the_provider_key_is_stable_per_generation_and_binds_the_content() {
        let id = Uuid::from_u128(7);
        let payload = |text: &str| Payload {
            channel: Channel::Sms,
            sender_profile: "sms".to_owned(),
            sender: "Registry".to_owned(),
            recipient: "+15550100".to_owned(),
            parts: RenderedParts {
                subject: None,
                text: text.to_owned(),
                html: None,
            },
            provider_idempotent_submit: true,
        };
        let first = provider_idempotency_key(id, 1, &payload("hello"));
        assert_eq!(first, provider_idempotency_key(id, 1, &payload("hello")));
        assert_ne!(first, provider_idempotency_key(id, 2, &payload("hello")));
        assert_ne!(first, provider_idempotency_key(id, 1, &payload("other")));
        assert!(!first.contains("15550100"));
    }

    #[test]
    fn an_outbound_message_debug_never_prints_the_contact_or_the_parts() {
        let message = OutboundMessage {
            message_id: Uuid::from_u128(7),
            generation: 1,
            attempt: 1,
            channel: Channel::Email,
            provider: "relay".to_owned(),
            sender_profile: "email".to_owned(),
            sender: "sender@example.test".to_owned(),
            recipient: "person@example.test".to_owned(),
            parts: RenderedParts {
                subject: Some("secret subject".to_owned()),
                text: "secret body".to_owned(),
                html: None,
            },
            idempotency_key: "sha256:00".to_owned(),
            provider_idempotent_submit: true,
            budget: Duration::from_secs(1),
        };
        let debug = format!("{message:?}");
        for value in ["person@example.test", "secret subject", "secret body"] {
            assert!(!debug.contains(value), "{debug}");
        }
    }

    /// A transport that answers `outcome` after `after`, or never.
    struct Late {
        after: Option<Duration>,
        outcome: SendOutcome,
    }

    #[async_trait]
    impl MessageTransport for Late {
        async fn send(&self, _message: &OutboundMessage) -> SendOutcome {
            match self.after {
                Some(after) => {
                    tokio::time::sleep(after).await;
                    self.outcome.clone()
                }
                None => std::future::pending().await,
            }
        }
    }

    fn budgeted(budget: Duration) -> OutboundMessage {
        OutboundMessage {
            message_id: Uuid::from_u128(7),
            generation: 1,
            attempt: 1,
            channel: Channel::Sms,
            provider: "gateway".to_owned(),
            sender_profile: "sms".to_owned(),
            sender: "Registry".to_owned(),
            recipient: "+15550100".to_owned(),
            parts: RenderedParts {
                subject: None,
                text: "hello".to_owned(),
                html: None,
            },
            idempotency_key: "sha256:00".to_owned(),
            provider_idempotent_submit: false,
            budget,
        }
    }

    #[tokio::test]
    async fn the_transport_classifies_its_own_deadline_and_the_worker_backstops_an_overrun() {
        let budget = Duration::from_millis(100);
        let not_sent = SendOutcome::Transient { retry_after: None };
        let late = Late {
            after: Some(budget + Duration::from_millis(50)),
            outcome: not_sent.clone(),
        };
        assert_eq!(send_within_budget(&late, &budgeted(budget)).await, not_sent);

        let started = std::time::Instant::now();
        let stuck = Late {
            after: None,
            outcome: not_sent,
        };
        assert_eq!(
            send_within_budget(&stuck, &budgeted(budget)).await,
            SendOutcome::MaybeSent
        );
        assert!(started.elapsed() >= budget + TRANSPORT_OVERRUN_ALLOWANCE);
    }

    #[test]
    fn the_dispatch_statements_render_against_a_schema() {
        let sql = dispatch_sql();
        let table = JobTable::new("public", JOB_TABLE, "message_id", "part").unwrap();
        for select in [sql.claim, sql.lapsed, sql.target, PAYLOAD_SELECT] {
            assert!(!select.columns.contains(';'));
            assert!(!select.joins.contains("--"));
        }
        assert_eq!(table.table(), JOB_TABLE);
    }

    #[test]
    fn audit_correlations_pair_one_lifecycle_and_distinguish_repeated_invocations() {
        let key = JobKey::new(Uuid::from_u128(7), MESSAGE_PART).expect("key");
        let record = MessageJob {
            provider: "relay".to_owned(),
            sender_profile: "email".to_owned(),
        };
        let job = |lease_token| LeasedJob {
            key: key.clone(),
            generation: 1,
            attempt: 1,
            attempt_started_at: SystemTime::UNIX_EPOCH,
            lease_token,
            policy: JobPolicy {
                attempt_timeout: Duration::from_secs(1),
                maximum_attempts: 1,
                retry: RetrySchedule::Frozen {
                    delays_ms: Vec::new(),
                },
                on_uncertain: UncertainOutcome::Hold,
                expires_at: None,
            },
            job: record.clone(),
        };
        let transition = TransitionAudit {
            key: key.clone(),
            generation: 1,
            attempt: 0,
            record: record.clone(),
            transition: Transition::Cancelled,
        };
        let replay = ReplayAudit {
            key: key.clone(),
            generation: 2,
            record: record.clone(),
            from: JobState::DeadLettered,
            outcome: ReplayOutcome::Requested,
        };
        let first = MessageAuditContext {
            actor: Actor::Worker,
            invocation_id: Uuid::from_u128(11),
        };
        let second = MessageAuditContext {
            actor: Actor::Worker,
            invocation_id: Uuid::from_u128(12),
        };

        assert_ne!(
            attempt_correlation(&job(Uuid::from_u128(21))),
            attempt_correlation(&job(Uuid::from_u128(22))),
            "a rolled-back claim retry receives a fresh attempt correlation"
        );
        assert_eq!(
            transition_correlation(&transition, &first),
            transition_correlation(&transition, &first),
            "one request and response share their invocation correlation"
        );
        assert_ne!(
            transition_correlation(&transition, &first),
            transition_correlation(&transition, &second),
            "a repeated transition is a fresh invocation"
        );
        assert_ne!(
            replay_correlation(&replay, &first),
            replay_correlation(&replay, &second),
            "repeated refused replays cannot collapse into one pair"
        );
        assert_ne!(
            quarantine_correlation(&key, 1, 0, &first),
            quarantine_correlation(&key, 1, 0, &second)
        );
    }

    #[test]
    fn refused_dispatch_audits_keep_the_truthful_prior_disposition() {
        assert_eq!(
            transition_disposition(Transition::Cancelled, TransitionOutcome::Refused),
            "pending"
        );
        assert_eq!(
            transition_disposition(
                Transition::Expired {
                    from: JobState::Pending,
                    disposition: Disposition::Expired,
                },
                TransitionOutcome::Refused,
            ),
            "pending"
        );
        assert_eq!(
            transition_disposition(
                Transition::LeaseLapsed(Disposition::RetryPending),
                TransitionOutcome::Refused,
            ),
            "leased"
        );
        assert_eq!(
            replay_disposition(JobState::Unknown, ReplayOutcome::Refused),
            "unknown"
        );
        assert_eq!(
            replay_disposition(JobState::DeadLettered, ReplayOutcome::Refused),
            "dead-lettered"
        );
    }
}
