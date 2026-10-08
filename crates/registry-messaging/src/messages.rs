// SPDX-License-Identifier: Apache-2.0

//! Accepted messages: the submission with its idempotency record, the
//! status view, cancellation, and the operator actions `messagingctl
//! messages` drives.
//!
//! A submission is checked, authorized, and rendered before the store is
//! reached: the request is strict JSON in the closed submission shape, the
//! caller's access profile must list the sender profile and the template,
//! and the parts are rendered from the active package at acceptance. One
//! transaction then records the idempotency key, the message, its payload,
//! and its dispatch job. The HTTP edge records the accepted outcome after
//! that transaction commits.
//!
//! The idempotency key is scoped to the caller's issuer and subject, and
//! recorded and found under a digest of the two with the key, which
//! outlives the raw values once retention erases the receipt. The
//! same key with the same canonical request replays the stored status and
//! receipt; the same key with another request is refused with
//! `idempotency.key-reused`, whatever the key's age; the same request under
//! a key whose receipt is older than `retention.submissionReceiptRetentionDays` is
//! refused with `idempotency.expired`. A replay is authorized and rendered again against
//! the active package before its receipt is answered.
//!
//! The status view and every operator report name the recipient's kind
//! only, with the contact masked, and never return a part or template data.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use registry_messaging_core::{
    derive_status, AttemptOutcome, AttemptSummary, Caller, CallerIdentity, Channel, ContentRefusal,
    ContentSource, DeliveryReport, MessageDispatch, MessageLinks, MessageReceipt, MessageReport,
    MessageStatus, MessageView, Package, PreparedContent, ProblemCode, Recipient, SenderProfile,
    SubmissionContent, SubmitMessageRequest, TemplateMessageRequest, TemplateReference,
    MAXIMUM_IDEMPOTENCY_KEY_BYTES,
};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_dispatch::postgres::{enqueue, CancelOutcome, JobKey, JobState};
use registry_platform_dispatch::{idempotency_key, DispatchError};
use serde::Serialize;
use serde_json::{json, Value};
use thiserror::Error;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::audit::MessagingAudit;
use crate::config::RetentionConfig;
use crate::dispatch::{acting_as, Actor, MessageDispatcher, MESSAGE_PART};
use crate::store::{PostgresStore, StoreError};

/// The idempotency operation a submission is recorded under.
pub const SUBMIT_OPERATION: &str = "submit-message";

/// The audit events of a submission.
pub const MESSAGE_ACCEPTED_EVENT: &str = "messaging.message.accepted";
pub const MESSAGE_REFUSED_EVENT: &str = "messaging.message.refused";
pub const MESSAGE_REPLAYED_EVENT: &str = "messaging.message.replayed";

/// The audit event of an operator's settlement of an unknown outcome as
/// sent.
pub const MESSAGE_SETTLED_EVENT: &str = "messaging.message.settled";

/// What every returned recipient carries in place of its contact.
pub const MASKED_CONTACT: &str = "redacted";

const REQUEST_HASH_DOMAIN: &[u8] = b"registry-messaging-submit-v1";
const KEY_REFERENCE_DOMAIN: &[u8] = b"registry-messaging-idempotency-key-v1";
const SECONDS_PER_DAY: u64 = 86_400;

/// The reference a spent idempotency key is recorded and found under: a
/// SHA-256 digest over a fixed domain and the length-prefixed issuer,
/// subject, operation, and key. It is not keyed, so rotating
/// `audit.hashKeyRef` never changes it, and it stays with the row after
/// retention clears the raw caller and key with the submission receipt, so
/// the key stays spent for that caller alone.
#[must_use]
pub fn idempotency_key_reference(caller: &CallerIdentity, operation: &str, key: &str) -> String {
    idempotency_key(
        KEY_REFERENCE_DOMAIN,
        &[
            caller.issuer.as_bytes(),
            caller.subject.as_bytes(),
            operation.as_bytes(),
            key.as_bytes(),
        ],
    )
}

/// Whether `key` is an acceptable `Idempotency-Key`: one to
/// [`MAXIMUM_IDEMPOTENCY_KEY_BYTES`] bytes of visible ASCII.
#[must_use]
pub fn valid_idempotency_key(key: &[u8]) -> bool {
    (1..=MAXIMUM_IDEMPOTENCY_KEY_BYTES).contains(&key.len())
        && key.iter().all(|byte| (0x21..=0x7e).contains(byte))
}

/// A submission that passed every check the store is not needed for.
pub struct PreparedSubmission {
    request_hash: String,
    request: SubmitMessageRequest,
    content: PreparedContent,
    profile: SenderProfile,
    provider_idempotent_submit: bool,
    not_before: Option<SystemTime>,
    expires_at: Option<SystemTime>,
}

impl std::fmt::Debug for PreparedSubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSubmission")
            .field("sender_profile", &self.profile.id)
            .field("to", &self.request.to)
            .finish_non_exhaustive()
    }
}

impl PreparedSubmission {
    /// The sender profile the submission names, once the package
    /// confirmed it.
    #[must_use]
    pub fn sender_profile(&self) -> &str {
        &self.profile.id
    }
}

/// Check, authorize, and render one submission body against `package`.
///
/// # Errors
///
/// `request.invalid` for a body that is not strict JSON,
/// `request.unprocessable` for JSON that is not the closed submission shape
/// or names a recipient its channel cannot carry, and the content refusal's
/// own problem for an unauthorized or unrenderable submission.
pub fn prepare_submission(
    package: &Package,
    caller: &Caller,
    body: &[u8],
) -> Result<PreparedSubmission, ProblemCode> {
    let value = parse_json_strict(body).map_err(|_| ProblemCode::RequestInvalid)?;
    let canonical = canonicalize_json(&value).map_err(|_| ProblemCode::RequestUnprocessable)?;
    let request_hash = idempotency_key(REQUEST_HASH_DOMAIN, &[&canonical]);
    let request: SubmitMessageRequest =
        serde_json::from_value(value).map_err(|_| ProblemCode::RequestUnprocessable)?;
    let not_before = parse_instant(request.not_before.as_deref())?;
    let expires_at = parse_instant(request.expires_at.as_deref())?;
    let content = match request.content()? {
        SubmissionContent::Template {
            template,
            locale,
            data,
        } => package.prepare_template_message(
            caller,
            &TemplateMessageRequest {
                sender_profile: request.sender_profile.clone(),
                template_id: template.id.clone(),
                version: template.version.clone(),
                locale: locale.to_owned(),
                data: data.clone(),
            },
        ),
        SubmissionContent::Direct(direct) => {
            package.prepare_direct_message(caller, &request.sender_profile, direct)
        }
    }
    .map_err(|refusal: ContentRefusal| refusal.problem())?;
    if request.to.channel() != content.channel {
        return Err(ProblemCode::RequestUnprocessable);
    }
    let profile = package
        .sender_profile(&content.sender_profile)
        .cloned()
        .ok_or(ProblemCode::ServiceUnavailable)?;
    let provider_idempotent_submit = package
        .provider(&profile.provider)
        .is_some_and(|provider| provider.idempotent_submit);
    Ok(PreparedSubmission {
        request_hash,
        request,
        content,
        profile,
        provider_idempotent_submit,
        not_before,
        expires_at,
    })
}

/// Parse an RFC 3339 instant, truncated to the microseconds PostgreSQL
/// stores, so a window is checked exactly as it will be recorded.
fn parse_instant(value: Option<&str>) -> Result<Option<SystemTime>, ProblemCode> {
    value
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|instant| {
                    let instant =
                        chrono::SubsecRound::trunc_subsecs(instant.with_timezone(&Utc), 6);
                    SystemTime::from(instant)
                })
                .map_err(|_| ProblemCode::RequestUnprocessable)
        })
        .transpose()
}

/// An RFC 3339 instant in UTC with millisecond precision.
#[must_use]
pub fn format_instant(instant: SystemTime) -> String {
    DateTime::<Utc>::from(instant).to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// The answer to a submission: the status and the receipt body, stored at
/// acceptance and answered again on a replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmissionAnswer {
    pub status: u16,
    pub receipt: Value,
    pub message_id: Uuid,
    pub replayed: bool,
    pub(crate) audit_record: Option<Value>,
}

/// Why a submission was not accepted: the problem, and for a limit, how
/// long the caller should wait before trying again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SubmissionRefusal {
    pub problem: ProblemCode,
    pub retry_after: Option<Duration>,
}

impl From<ProblemCode> for SubmissionRefusal {
    fn from(problem: ProblemCode) -> Self {
        Self {
            problem,
            retry_after: None,
        }
    }
}

/// Why the store could not answer an operator action.
#[derive(Debug, Error)]
pub enum MessageStoreError {
    /// The store could not be reached or failed before any change was
    /// committed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The store refused the transition and changed nothing: the message
    /// changed between the read and the write.
    #[error("the Messaging dispatch store refused the transition")]
    Refused,
    /// The cancellation was refused and changed nothing: the message is
    /// being sent, or an attempt of its current generation may have reached
    /// its provider.
    #[error("the Messaging message can no longer be cancelled")]
    DispatchStarted,
    /// The audit destination refused the request record, so the
    /// transition was not attempted and nothing changed.
    #[error("the Messaging audit destination refused the request record; nothing was changed")]
    AuditUnavailable,
    /// The transition may have been applied: its commit could not be
    /// confirmed, or the dispatch core could not say whether it committed.
    #[error("the Messaging transition may have been applied; its outcome could not be confirmed")]
    OutcomeUnknown,
    /// The transition was committed, and its outcome record could not be
    /// written to the audit destination.
    #[error("the Messaging transition was applied, and its audit outcome could not be recorded")]
    AuditUnconfirmed,
}

impl From<tokio_postgres::Error> for MessageStoreError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Store(StoreError::Query(error))
    }
}

/// The dispatch core answers one value-free error for an absent or stale
/// target, a refused write, a commit it could not confirm, and a committed
/// change whose outcome record failed. Only the last two may have changed
/// the message, and they cannot be told apart from the rest, so every
/// dispatch error may have applied.
impl From<DispatchError> for MessageStoreError {
    fn from(_: DispatchError) -> Self {
        Self::OutcomeUnknown
    }
}

/// One stored message: its submitter, provider, dispatch state, and view.
///
/// The store reads a message whose report no receipt has moved as `none`;
/// [`Self::settle_report_capability`] turns that into `unavailable` for a
/// provider that records no delivery receipts.
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub submitter: CallerIdentity,
    pub access_profile: String,
    pub provider: String,
    pub state: JobState,
    pub generation: i64,
    pub attempt: i16,
    pub view: MessageView,
}

impl StoredMessage {
    /// Whether an attempt of the message's current generation may have
    /// reached its provider: one still in progress, answered maybe-sent, or
    /// interrupted by a lapsed lease. The dispatcher refuses to cancel a
    /// queued message this answers `true` for.
    #[must_use]
    pub fn may_have_reached_provider(&self) -> bool {
        self.view.attempts.iter().any(|attempt| {
            attempt.generation == self.generation
                && matches!(
                    attempt.outcome,
                    AttemptOutcome::InProgress
                        | AttemptOutcome::MaybeSent
                        | AttemptOutcome::Interrupted
                )
        })
    }

    /// Settle the view's report against whether the message's provider
    /// records delivery receipts: without them, a report no receipt has
    /// moved is `unavailable`, never `none`, so a caller does not wait for a
    /// receipt that will not come. A stored report is served as stored.
    pub fn settle_report_capability(&mut self, receipt_providers: &BTreeSet<String>) {
        if self.view.report == MessageReport::None && !receipt_providers.contains(&self.provider) {
            self.view.report = MessageReport::Unavailable;
        }
    }
}

/// One row of an operator listing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSummary {
    pub id: String,
    pub status: MessageStatus,
    pub dispatch: MessageDispatch,
    pub channel: Channel,
    pub sender_profile: String,
    pub generation: i64,
    pub attempt: i16,
    pub accepted_at: String,
    pub updated_at: String,
}

/// What an operator settles an unknown outcome as.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SettleOutcome {
    /// The provider took the message: it becomes `submitted`.
    Sent,
    /// The provider did not: it is queued again under a new generation.
    NotSent,
}

/// An operator action on one message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperatorAction {
    /// Requeue a failed message under a new generation.
    Retry,
    Settle(SettleOutcome),
    Cancel,
}

impl OperatorAction {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retry => "retry",
            Self::Settle(_) => "settle",
            Self::Cancel => "cancel",
        }
    }

    /// The one dispatch state the action applies to.
    const fn applies_to(self) -> JobState {
        match self {
            Self::Retry => JobState::DeadLettered,
            Self::Settle(_) => JobState::Unknown,
            Self::Cancel => JobState::Pending,
        }
    }
}

/// What an operator action found, and did when applied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatorActionReport {
    pub id: String,
    pub action: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<SettleOutcome>,
    pub status: MessageStatus,
    pub dispatch: MessageDispatch,
    pub generation: i64,
    /// Whether the message is in the one dispatch state the action applies
    /// to.
    pub eligible: bool,
    pub applied: bool,
    /// The status the action leaves, or would leave, the message in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_status: Option<MessageStatus>,
    /// The generation a requeue starts, once applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_generation: Option<i64>,
}

/// What a cancellation found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelResult {
    Cancelled,
    /// The message is being sent, was handed to its provider, its outcome
    /// is unknown, or it waits to retry after an attempt that may have
    /// reached its provider.
    DispatchStarted,
    /// The message already reached a final state.
    Terminal,
}

/// Read-only access to stored messages and operator-action previews.
///
/// This type cannot construct a dispatcher or apply an operator action, so
/// status inspection and previews do not depend on an audit destination and
/// cannot become an unaudited mutation path.
#[derive(Clone)]
pub struct MessageReader {
    store: PostgresStore,
}

impl std::fmt::Debug for MessageReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MessageReader")
            .finish_non_exhaustive()
    }
}

/// The message store: accepted messages, their jobs, and their attempts.
#[derive(Clone)]
pub struct MessageStore {
    store: PostgresStore,
    dispatcher: MessageDispatcher,
    audit: Arc<MessagingAudit>,
}

impl std::fmt::Debug for MessageStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MessageStore")
            .finish_non_exhaustive()
    }
}

const VIEW_SELECT: &str = "SELECT message.message_id, message.submitter_issuer, \
         message.submitter_subject, message.access_profile, message.channel, \
         message.sender_profile, message.recipient_kind, message.template_id, \
         message.template_version, message.correlation_id, message.accepted_at, \
         message.not_before, message.expires_at, job.state, job.generation, job.attempt, \
         job.updated_at, message.provider, message.report, message.report_at \
    FROM messaging_messages AS message \
    JOIN messaging_dispatch_jobs AS job \
      ON job.message_id = message.message_id AND job.part = 'message'";

impl MessageReader {
    #[must_use]
    pub fn new(store: PostgresStore) -> Self {
        Self { store }
    }

    /// Read one message and its attempts, in one snapshot.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot answer.
    pub async fn read(&self, message_id: Uuid) -> Result<Option<StoredMessage>, MessageStoreError> {
        let mut client = self.store.client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        let Some(row) = transaction
            .query_opt(
                &format!("{VIEW_SELECT} WHERE message.message_id = $1"),
                &[&message_id],
            )
            .await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let attempts = transaction
            .query(
                "SELECT generation, attempt, outcome, started_at, finished_at, \
                        provider_reference IS NOT NULL \
                   FROM messaging_attempts WHERE message_id = $1 \
                  ORDER BY generation, attempt",
                &[&message_id],
            )
            .await?;
        transaction.commit().await?;
        let attempts = attempts
            .iter()
            .map(decode_attempt)
            .collect::<Result<Vec<_>, _>>()?;
        decode_message(&row, attempts).map(Some)
    }

    /// List messages, newest first, optionally only those whose derived
    /// status is `status`.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot answer.
    pub async fn list(
        &self,
        status: Option<MessageStatus>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, MessageStoreError> {
        let client = self.store.client().await?;
        let rows = client
            .query(
                &format!(
                    "SELECT message.message_id, job.state, message.channel, \
                            message.sender_profile, job.generation, job.attempt, \
                            message.accepted_at, job.updated_at, message.report \
                       FROM messaging_messages AS message \
                       JOIN messaging_dispatch_jobs AS job \
                         ON job.message_id = message.message_id AND job.part = 'message' \
                      WHERE {} \
                      ORDER BY message.accepted_at DESC, message.message_id \
                      LIMIT $1",
                    status_condition(status)
                ),
                &[&limit],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let dispatch = dispatch_of(decode_state(row, 1)?);
                let report = decode_report(row, 8)?;
                Ok(MessageSummary {
                    id: row.try_get::<_, Uuid>(0)?.to_string(),
                    status: derive_status(dispatch, report),
                    dispatch,
                    channel: decode_channel(row, 2)?,
                    sender_profile: row.try_get(3)?,
                    generation: row.try_get(4)?,
                    attempt: row.try_get(5)?,
                    accepted_at: format_instant(row.try_get(6)?),
                    updated_at: format_instant(row.try_get(7)?),
                })
            })
            .collect()
    }

    /// Report what `action` would do to one message without changing it.
    /// `None` when no such message exists.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot answer.
    pub async fn operate(
        &self,
        message_id: Uuid,
        action: OperatorAction,
    ) -> Result<Option<OperatorActionReport>, MessageStoreError> {
        let Some(message) = self.read(message_id).await? else {
            return Ok(None);
        };
        let eligible = message.state == action.applies_to()
            && !(action == OperatorAction::Cancel && message.may_have_reached_provider());
        let next_status = eligible.then_some(match action {
            OperatorAction::Retry | OperatorAction::Settle(SettleOutcome::NotSent) => {
                MessageStatus::Queued
            }
            OperatorAction::Settle(SettleOutcome::Sent) => MessageStatus::Submitted,
            OperatorAction::Cancel => MessageStatus::Cancelled,
        });
        Ok(Some(OperatorActionReport {
            id: message.view.id,
            action: action.as_str(),
            outcome: match action {
                OperatorAction::Settle(outcome) => Some(outcome),
                OperatorAction::Retry | OperatorAction::Cancel => None,
            },
            status: message.view.status,
            dispatch: message.view.dispatch,
            generation: message.generation,
            eligible,
            applied: false,
            next_status,
            next_generation: None,
        }))
    }
}

impl MessageStore {
    #[must_use]
    pub fn new(
        store: PostgresStore,
        dispatcher: MessageDispatcher,
        audit: Arc<MessagingAudit>,
    ) -> Self {
        Self {
            store,
            dispatcher,
            audit,
        }
    }

    #[must_use]
    pub fn dispatcher(&self) -> &MessageDispatcher {
        &self.dispatcher
    }

    /// Read one message and its attempts, in one snapshot.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot answer.
    pub async fn read(&self, message_id: Uuid) -> Result<Option<StoredMessage>, MessageStoreError> {
        MessageReader::new(self.store.clone())
            .read(message_id)
            .await
    }

    /// List messages, newest first, optionally only those whose derived
    /// status is `status`.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot answer.
    pub async fn list(
        &self,
        status: Option<MessageStatus>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, MessageStoreError> {
        MessageReader::new(self.store.clone())
            .list(status, limit)
            .await
    }

    /// Cancel a queued message under `actor`.
    ///
    /// # Errors
    ///
    /// [`MessageStoreError::Refused`] when the message is absent or the
    /// store fails.
    pub async fn cancel(
        &self,
        message_id: Uuid,
        actor: Actor,
    ) -> Result<CancelResult, MessageStoreError> {
        let key = job_key(message_id)?;
        let outcome = acting_as(actor, self.dispatcher.cancel(&key)).await?;
        Ok(match outcome {
            CancelOutcome::Cancelled => CancelResult::Cancelled,
            CancelOutcome::NotCancellable(
                JobState::Leased | JobState::Delivered | JobState::Unknown,
            )
            | CancelOutcome::MayHaveReachedReceiver => CancelResult::DispatchStarted,
            CancelOutcome::NotCancellable(_) => CancelResult::Terminal,
        })
    }

    /// Report what `action` would do to one message, and with `apply` do
    /// it as the operator tool. `None` when no such message exists.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot answer before any change,
    /// [`MessageStoreError::Refused`] when the message changed between the
    /// read and the write, [`MessageStoreError::DispatchStarted`] when a
    /// cancellation finds the message being sent or an attempt that may
    /// have reached its provider, [`MessageStoreError::AuditUnavailable`] when the
    /// request record is refused, [`MessageStoreError::OutcomeUnknown`]
    /// when the action may have been applied, and
    /// [`MessageStoreError::AuditUnconfirmed`] when it was applied and its
    /// outcome record failed.
    pub async fn operate(
        &self,
        message_id: Uuid,
        action: OperatorAction,
        apply: bool,
    ) -> Result<Option<OperatorActionReport>, MessageStoreError> {
        let Some(mut report) = MessageReader::new(self.store.clone())
            .operate(message_id, action)
            .await?
        else {
            return Ok(None);
        };
        if !apply || !report.eligible {
            return Ok(Some(report));
        }
        let key = job_key(message_id)?;
        match action {
            OperatorAction::Retry | OperatorAction::Settle(SettleOutcome::NotSent) => {
                let generation = acting_as(
                    Actor::OperatorTool,
                    self.dispatcher.replay(&key, report.generation),
                )
                .await?;
                report.next_generation = Some(generation);
            }
            OperatorAction::Settle(SettleOutcome::Sent) => {
                self.settle_sent(message_id, report.generation).await?;
            }
            OperatorAction::Cancel => match self.cancel(message_id, Actor::OperatorTool).await? {
                CancelResult::Cancelled => {}
                CancelResult::DispatchStarted => return Err(MessageStoreError::DispatchStarted),
                CancelResult::Terminal => return Err(MessageStoreError::Refused),
            },
        }
        report.applied = true;
        Ok(Some(report))
    }

    /// Move an unknown outcome to delivered, fenced by its generation, with
    /// a request audit before the mutation and an outcome after commit. A
    /// refused or failed write is answered `refused` in the audit; a COMMIT
    /// that fails is read back, and one whose outcome the read cannot
    /// establish is left `unfinished`.
    async fn settle_sent(
        &self,
        message_id: Uuid,
        generation: i64,
    ) -> Result<(), MessageStoreError> {
        let mut audit = self
            .audit
            .begin(json!({
                "event": "messaging.message.settle.requested",
                "messageId": message_id.to_string(),
                "generation": generation,
                "outcome": "sent",
                "actor": Actor::OperatorTool.to_json(),
            }))
            .await
            .map_err(|_| MessageStoreError::AuditUnavailable)?;
        let refused = json!({
            "event": "messaging.message.settle.requested",
            "messageId": message_id.to_string(),
            "generation": generation,
            "outcome": "refused",
            "actor": Actor::OperatorTool.to_json(),
        });
        let written = async {
            let mut client = self.store.client().await?;
            let transaction = client.transaction().await?;
            let changed = transaction
                .execute(
                    "UPDATE messaging_dispatch_jobs \
                        SET state = 'delivered', delivered_at = transaction_timestamp(), \
                            updated_at = transaction_timestamp() \
                      WHERE message_id = $1 AND part = $2 AND generation = $3 \
                        AND state = 'unknown'",
                    &[&message_id, &MESSAGE_PART, &generation],
                )
                .await?;
            Ok::<_, MessageStoreError>((changed, transaction.commit().await))
        }
        .await;
        let refusal = match written {
            Ok((1, Ok(()))) => None,
            Ok((1, Err(commit))) => match self.settled(message_id, generation).await {
                Some(true) => None,
                Some(false) => Some(StoreError::Query(commit).into()),
                // The dropped guard records the settlement `unfinished`.
                None => return Err(MessageStoreError::OutcomeUnknown),
            },
            Ok((_, _)) => Some(MessageStoreError::Refused),
            Err(error) => Some(error),
        };
        if let Some(refusal) = refusal {
            if let Err(error) = audit.respond(refused).await {
                tracing::warn!(
                    error = %error,
                    "the Messaging audit destination could not record a refused settlement"
                );
            }
            return Err(refusal);
        }
        audit
            .respond(json!({
                "event": MESSAGE_SETTLED_EVENT,
                "messageId": message_id.to_string(),
                "generation": generation,
                "outcome": "sent",
                "from": JobState::Unknown.as_str(),
                "disposition": JobState::Delivered.as_str(),
                "actor": Actor::OperatorTool.to_json(),
            }))
            .await
            .map_err(|_| MessageStoreError::AuditUnconfirmed)?;
        Ok(())
    }

    /// Whether a settlement whose COMMIT failed is in the store: `None`
    /// when the store cannot say.
    async fn settled(&self, message_id: Uuid, generation: i64) -> Option<bool> {
        let client = self.store.client().await.ok()?;
        let row = client
            .query_opt(
                "SELECT state FROM messaging_dispatch_jobs \
                  WHERE message_id = $1 AND part = $2 AND generation = $3",
                &[&message_id, &MESSAGE_PART, &generation],
            )
            .await
            .ok()?;
        match row.map(|row| row.try_get::<_, String>(0)) {
            Some(Ok(state)) if state == JobState::Delivered.as_str() => Some(true),
            Some(Ok(state)) if state == JobState::Unknown.as_str() => Some(false),
            _ => None,
        }
    }
}

fn job_key(message_id: Uuid) -> Result<JobKey, MessageStoreError> {
    JobKey::new(message_id, MESSAGE_PART).map_err(|_| MessageStoreError::Refused)
}

/// The public dispatch state of a dispatch job state. The job's
/// `delivered` means the provider accepted the message, so it is the
/// message's `submitted`.
#[must_use]
pub const fn dispatch_of(state: JobState) -> MessageDispatch {
    match state {
        JobState::Pending => MessageDispatch::Queued,
        JobState::Leased => MessageDispatch::Sending,
        JobState::Delivered => MessageDispatch::Submitted,
        JobState::DeadLettered => MessageDispatch::Failed,
        JobState::Expired => MessageDispatch::Expired,
        JobState::Unknown => MessageDispatch::Unknown,
        JobState::Cancelled => MessageDispatch::Cancelled,
    }
}

/// The listing condition that holds for a message exactly when
/// [`derive_status`] of its dispatch state and stored report is `status`.
/// The text is built from the dispatch and report names only; nothing a
/// caller sends reaches it.
fn status_condition(status: Option<MessageStatus>) -> String {
    let state = |state: JobState| format!("job.state = '{}'", state.as_str());
    let report = |report: DeliveryReport| format!("message.report = '{}'", report.as_str());
    let submitted = state(JobState::Delivered);
    match status {
        None => "true".to_owned(),
        Some(MessageStatus::Queued) => state(JobState::Pending),
        Some(MessageStatus::Sending) => state(JobState::Leased),
        Some(MessageStatus::Submitted) => format!(
            "{submitted} AND message.report IS DISTINCT FROM '{}' \
             AND message.report IS DISTINCT FROM '{}'",
            DeliveryReport::Delivered.as_str(),
            DeliveryReport::Undelivered.as_str()
        ),
        Some(MessageStatus::Delivered) => {
            format!("{submitted} AND {}", report(DeliveryReport::Delivered))
        }
        Some(MessageStatus::Failed) => format!(
            "({} OR ({submitted} AND {}))",
            state(JobState::DeadLettered),
            report(DeliveryReport::Undelivered)
        ),
        Some(MessageStatus::Expired) => state(JobState::Expired),
        Some(MessageStatus::Unknown) => state(JobState::Unknown),
        Some(MessageStatus::Cancelled) => state(JobState::Cancelled),
    }
}

fn refused<T>() -> Result<T, MessageStoreError> {
    Err(MessageStoreError::Refused)
}

fn decode_state(row: &Row, index: usize) -> Result<JobState, MessageStoreError> {
    JobState::parse(&row.try_get::<_, String>(index)?).map_or_else(refused, Ok)
}

/// The stored report, or `none` when no receipt has moved it.
fn decode_report(row: &Row, index: usize) -> Result<MessageReport, MessageStoreError> {
    match row.try_get::<_, Option<String>>(index)? {
        None => Ok(MessageReport::None),
        Some(stored) => DeliveryReport::parse(&stored)
            .map(MessageReport::from)
            .map_or_else(refused, Ok),
    }
}

fn decode_channel(row: &Row, index: usize) -> Result<Channel, MessageStoreError> {
    match row.try_get::<_, String>(index)?.as_str() {
        "email" => Ok(Channel::Email),
        "sms" => Ok(Channel::Sms),
        _ => refused(),
    }
}

fn decode_attempt(row: &Row) -> Result<AttemptSummary, MessageStoreError> {
    let outcome = match row.try_get::<_, String>(2)?.as_str() {
        "in-progress" => AttemptOutcome::InProgress,
        "accepted" => AttemptOutcome::Accepted,
        "transient" => AttemptOutcome::Transient,
        "permanent" => AttemptOutcome::Permanent,
        "maybe-sent" => AttemptOutcome::MaybeSent,
        "interrupted" => AttemptOutcome::Interrupted,
        _ => return refused(),
    };
    Ok(AttemptSummary {
        generation: row.try_get(0)?,
        attempt: row.try_get(1)?,
        outcome,
        started_at: format_instant(row.try_get(3)?),
        finished_at: row.try_get::<_, Option<SystemTime>>(4)?.map(format_instant),
        provider_reference: row.try_get(5)?,
    })
}

fn decode_message(
    row: &Row,
    attempts: Vec<AttemptSummary>,
) -> Result<StoredMessage, MessageStoreError> {
    let id = row.try_get::<_, Uuid>(0)?.to_string();
    let to = match row.try_get::<_, String>(6)?.as_str() {
        "email" => Recipient::Email(MASKED_CONTACT.to_owned()),
        "phone" => Recipient::Phone(MASKED_CONTACT.to_owned()),
        _ => return refused(),
    };
    let template = match (
        row.try_get::<_, Option<String>>(7)?,
        row.try_get::<_, Option<String>>(8)?,
    ) {
        (Some(id), Some(version)) => Some(TemplateReference { id, version }),
        _ => None,
    };
    let state = decode_state(row, 13)?;
    let dispatch = dispatch_of(state);
    let report = decode_report(row, 18)?;
    Ok(StoredMessage {
        submitter: CallerIdentity {
            issuer: row.try_get(1)?,
            subject: row.try_get(2)?,
        },
        access_profile: row.try_get(3)?,
        provider: row.try_get(17)?,
        state,
        generation: row.try_get(14)?,
        attempt: row.try_get(15)?,
        view: MessageView {
            status: derive_status(dispatch, report),
            dispatch,
            report,
            reported_at: row
                .try_get::<_, Option<SystemTime>>(19)?
                .map(format_instant),
            channel: decode_channel(row, 4)?,
            sender_profile: row.try_get(5)?,
            to,
            template,
            correlation_id: row.try_get(9)?,
            accepted_at: format_instant(row.try_get(10)?),
            not_before: row
                .try_get::<_, Option<SystemTime>>(11)?
                .map(format_instant),
            expires_at: format_instant(row.try_get(12)?),
            updated_at: format_instant(row.try_get(16)?),
            attempts,
            links: MessageLinks::for_message(&id),
            id,
        },
    })
}

/// The HTTP-facing message service: the store, the active package's
/// sender profiles, the journal's keyed references, and the retention the
/// submission windows are bounded by.
pub struct MessageService {
    messages: MessageStore,
    audit: Arc<MessagingAudit>,
    retention: RetentionConfig,
    /// The providers whose delivery receipts this runtime records.
    receipt_providers: BTreeSet<String>,
}

impl std::fmt::Debug for MessageService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MessageService")
            .finish_non_exhaustive()
    }
}

/// The idempotency record a key already holds.
struct StoredKey {
    request_hash: Option<String>,
    spent: bool,
    status: Option<i16>,
    receipt: Option<Value>,
    message_id: Option<Uuid>,
}

impl MessageService {
    /// A service over `messages`, reporting delivery receipts for the
    /// messages of `receipt_providers` and `unavailable` for every other
    /// provider's.
    #[must_use]
    pub fn new(
        messages: MessageStore,
        audit: Arc<MessagingAudit>,
        retention: RetentionConfig,
        receipt_providers: BTreeSet<String>,
    ) -> Self {
        Self {
            messages,
            audit,
            retention,
            receipt_providers,
        }
    }

    #[must_use]
    pub fn messages(&self) -> &MessageStore {
        &self.messages
    }

    pub async fn record_receipt(
        &self,
        provider: &str,
        receipt: &registry_messaging_core::Receipt,
    ) -> Result<crate::receipts::ReceiptOutcome, MessageStoreError> {
        crate::receipts::record_receipt(&self.messages.store, &self.audit, provider, receipt).await
    }

    /// Record one prepared submission under `key`, or answer the receipt
    /// the key already holds.
    ///
    /// # Errors
    ///
    /// `idempotency.expired`, `idempotency.key-reused`, `request.invalid`
    /// for a window the retention does not allow, `quota.exceeded` with the
    /// wait until the profile's oldest counted acceptance ages out, and
    /// `service.unavailable` when the store or audit reference key fails.
    pub async fn submit(
        &self,
        caller: &Caller,
        key: &str,
        submission: &PreparedSubmission,
    ) -> Result<SubmissionAnswer, SubmissionRefusal> {
        let unavailable = |_| ProblemCode::ServiceUnavailable;
        let principal_pseudonym = self
            .audit
            .principal_pseudonym(&caller.identity)
            .map_err(|_| ProblemCode::ServiceUnavailable)?;
        let recipient_reference = self
            .audit
            .recipient_reference(&submission.request.to)
            .map_err(unavailable)?;
        let references = References {
            principal_pseudonym,
            recipient_reference,
        };
        // A concurrent submission under the same key can win the insert
        // between this one's lookup and its own insert; the second pass
        // then finds that submission's record.
        for _ in 0..2 {
            match self.try_submit(caller, key, submission, &references).await {
                Ok(Some(answer)) => return Ok(answer),
                Ok(None) => {}
                Err(Refusal::Problem(problem)) => return Err(problem.into()),
                Err(Refusal::Quota { retry_after }) => {
                    return Err(SubmissionRefusal {
                        problem: ProblemCode::QuotaExceeded,
                        retry_after: Some(retry_after),
                    })
                }
                Err(Refusal::Store(error)) => {
                    tracing::warn!(
                        error = %error,
                        "the Messaging store could not record a submission"
                    );
                    return Err(ProblemCode::ServiceUnavailable.into());
                }
            }
        }
        Err(ProblemCode::ServiceUnavailable.into())
    }

    async fn try_submit(
        &self,
        caller: &Caller,
        key: &str,
        submission: &PreparedSubmission,
        references: &References,
    ) -> Result<Option<SubmissionAnswer>, Refusal> {
        let mut client = self.messages.store.client().await.map_err(Refusal::Store)?;
        let transaction = client.transaction().await?;
        let now: SystemTime = transaction
            .query_one("SELECT transaction_timestamp()", &[])
            .await?
            .try_get(0)?;
        let key_reference = idempotency_key_reference(&caller.identity, SUBMIT_OPERATION, key);
        if let Some(stored) = lookup_key(&transaction, &key_reference).await? {
            transaction.commit().await?;
            return replay(stored, submission).map(Some);
        }
        let window = Window::new(now, submission, &self.retention)?;
        if let Some(limit) = caller.profile.maximum_messages_per_day {
            lock_daily_limit(&transaction, &caller.profile.id).await?;
            // A submission under the same key may have committed while this
            // one waited on the lock; it is replayed, never counted against.
            if let Some(stored) = lookup_key(&transaction, &key_reference).await? {
                transaction.commit().await?;
                return replay(stored, submission).map(Some);
            }
            check_daily_limit(&transaction, &caller.profile.id, limit, now).await?;
        }
        let message_id = Uuid::new_v4();
        let receipt = serde_json::to_value(MessageReceipt {
            id: message_id.to_string(),
            status: MessageStatus::Queued,
            links: MessageLinks::for_message(&message_id.to_string()),
        })
        .map_err(|_| Refusal::Problem(ProblemCode::ServiceUnavailable))?;
        let receipt_expires = now + days(self.retention.submission_receipt_retention_days);
        let inserted = transaction
            .execute(
                "INSERT INTO messaging_idempotency \
                     (key_reference, submitter_issuer, submitter_subject, operation, \
                      idempotency_key, request_hash, message_id, status_code, receipt, \
                      created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 202, $8, transaction_timestamp(), $9) \
                 ON CONFLICT DO NOTHING",
                &[
                    &key_reference,
                    &caller.identity.issuer,
                    &caller.identity.subject,
                    &SUBMIT_OPERATION,
                    &key,
                    &submission.request_hash,
                    &message_id,
                    &receipt,
                    &receipt_expires,
                ],
            )
            .await?;
        if inserted != 1 {
            transaction.rollback().await?;
            return Ok(None);
        }
        insert_message(&transaction, caller, message_id, submission, &window).await?;
        let job = JobKey::new(message_id, MESSAGE_PART)
            .map_err(|_| Refusal::Problem(ProblemCode::ServiceUnavailable))?;
        enqueue(
            &transaction,
            self.messages.dispatcher.table(),
            &job,
            window.not_before,
        )
        .await
        .map_err(Refusal::dispatch)?;
        transaction.commit().await?;
        Ok(Some(SubmissionAnswer {
            status: 202,
            receipt,
            message_id,
            replayed: false,
            audit_record: Some(accepted_record(
                caller, message_id, submission, &window, references,
            )),
        }))
    }

    /// Read one message for `caller`, answering exactly alike for a message
    /// that does not exist and one the caller may not see.
    ///
    /// # Errors
    ///
    /// `message.not-visible`, or `service.unavailable` when the store
    /// cannot answer.
    pub async fn visible_message(
        &self,
        caller: &Caller,
        message_id: &str,
    ) -> Result<StoredMessage, ProblemCode> {
        let Ok(message_id) = Uuid::parse_str(message_id) else {
            return Err(ProblemCode::MessageNotVisible);
        };
        let message = self.messages.read(message_id).await.map_err(|error| {
            tracing::warn!(error = %error, "the Messaging store could not read a message");
            ProblemCode::ServiceUnavailable
        })?;
        registry_messaging_core::check_message_visibility(
            caller,
            message.as_ref().map(|message| &message.submitter),
        )?;
        let mut message = message.ok_or(ProblemCode::MessageNotVisible)?;
        message.settle_report_capability(&self.receipt_providers);
        Ok(message)
    }

    /// Cancel one message for `caller`, after the visibility check.
    ///
    /// # Errors
    ///
    /// `message.not-visible`, `message.dispatch-started`,
    /// `message.terminal`, or `service.unavailable`.
    pub async fn cancel(
        &self,
        caller: &Caller,
        message_id: &str,
    ) -> Result<MessageView, ProblemCode> {
        let message = self.visible_message(caller, message_id).await?;
        let id = Uuid::parse_str(&message.view.id).map_err(|_| ProblemCode::MessageNotVisible)?;
        let principal_pseudonym = self
            .audit
            .principal_pseudonym(&caller.identity)
            .map_err(|_| ProblemCode::ServiceUnavailable)?;
        let actor = Actor::Caller {
            access_profile: caller.profile.id.clone(),
            principal_pseudonym,
        };
        match self.messages.cancel(id, actor).await {
            Ok(CancelResult::Cancelled) => {}
            Ok(CancelResult::DispatchStarted) => return Err(ProblemCode::MessageDispatchStarted),
            Ok(CancelResult::Terminal) => return Err(ProblemCode::MessageTerminal),
            Err(error) => {
                tracing::warn!(error = %error, "the Messaging store could not cancel a message");
                return Err(ProblemCode::ServiceUnavailable);
            }
        }
        Ok(self.visible_message(caller, message_id).await?.view)
    }
}

/// The keyed references an acceptance record names.
struct References {
    principal_pseudonym: String,
    recipient_reference: String,
}

enum Refusal {
    Problem(ProblemCode),
    /// The access profile accepted its daily limit; the oldest counted
    /// acceptance ages out after `retry_after`.
    Quota {
        retry_after: Duration,
    },
    Store(StoreError),
}

impl Refusal {
    fn dispatch(_: DispatchError) -> Self {
        Self::Problem(ProblemCode::ServiceUnavailable)
    }
}

impl From<tokio_postgres::Error> for Refusal {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Store(StoreError::Query(error))
    }
}

const fn days(count: u16) -> Duration {
    Duration::from_secs(count as u64 * SECONDS_PER_DAY)
}

/// The window a `maximumMessagesPerDay` counts over.
const DAILY_WINDOW: Duration = Duration::from_secs(SECONDS_PER_DAY);

/// Take the transaction-scoped advisory lock `profile`'s daily count runs
/// under, so two submissions of one profile are counted one after the other
/// and cannot both take the last place; the lock is released when the
/// acceptance commits or rolls back.
async fn lock_daily_limit(
    transaction: &tokio_postgres::Transaction<'_>,
    profile: &str,
) -> Result<(), Refusal> {
    transaction
        .execute(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))",
            &[&format!("{DAILY_LIMIT_LOCK_NAMESPACE}{profile}")],
        )
        .await?;
    Ok(())
}

/// Refuse a submission once `profile` accepted `limit` messages in the last
/// 24 hours. The caller holds the profile's lock from [`lock_daily_limit`].
/// The count is the accepted messages themselves, so it survives a restart
/// without a counter.
async fn check_daily_limit(
    transaction: &tokio_postgres::Transaction<'_>,
    profile: &str,
    limit: u32,
    now: SystemTime,
) -> Result<(), Refusal> {
    let window_start = now - DAILY_WINDOW;
    let row = transaction
        .query_one(
            "SELECT count(*), min(accepted_at) FROM messaging_messages \
              WHERE access_profile = $1 AND accepted_at > $2",
            &[&profile, &window_start],
        )
        .await?;
    let accepted: i64 = row.try_get(0)?;
    if accepted < i64::from(limit) {
        return Ok(());
    }
    let oldest: SystemTime = row.try_get(1)?;
    // `now` is this transaction's start, so an acceptance another
    // transaction committed after it can carry a later instant; the wait
    // never exceeds the window or falls below one second.
    let retry_after = (oldest + DAILY_WINDOW)
        .duration_since(now)
        .unwrap_or(Duration::ZERO)
        .clamp(Duration::from_secs(1), DAILY_WINDOW);
    Err(Refusal::Quota { retry_after })
}

/// The advisory-lock name prefix a profile's daily count is taken under.
const DAILY_LIMIT_LOCK_NAMESPACE: &str = "registry-messaging.daily-limit:";

/// The idempotency record under `key_reference`, the
/// [`idempotency_key_reference`] of the caller's verified issuer and
/// subject and the key. The record is found by the caller itself, not by
/// its keyed audit pseudonym, so rotating `audit.hashKeyRef` never frees a
/// spent key, and by the digest rather than the raw values, so a key stays
/// spent after retention clears them.
async fn lookup_key(
    transaction: &tokio_postgres::Transaction<'_>,
    key_reference: &str,
) -> Result<Option<StoredKey>, Refusal> {
    let row = transaction
        .query_opt(
            "SELECT request_hash, \
                    erased_at IS NOT NULL OR expires_at <= transaction_timestamp(), \
                    status_code, receipt, message_id \
               FROM messaging_idempotency \
              WHERE key_reference = $1",
            &[&key_reference],
        )
        .await?;
    row.map(|row| {
        Ok(StoredKey {
            request_hash: row.try_get(0)?,
            spent: row.try_get(1)?,
            status: row.try_get(2)?,
            receipt: row.try_get(3)?,
            message_id: row.try_get(4)?,
        })
    })
    .transpose()
}

/// Answer a submission under a key `stored` already holds. A different
/// request under the key is a reuse whether or not its receipt is still
/// held, as Base Registry Engine, Scheduling, and Casework answer it: the
/// caller is told the key is not theirs to re-aim before being told the
/// answer is gone. Only the exact request past the receipt horizon is
/// refused as expired, and so is every request once retention deleted the
/// message and its request hash with it, since none can then be told apart
/// from the first.
fn replay(stored: StoredKey, submission: &PreparedSubmission) -> Result<SubmissionAnswer, Refusal> {
    match stored.request_hash.as_deref() {
        Some(hash) if hash != submission.request_hash => {
            return Err(Refusal::Problem(ProblemCode::IdempotencyKeyReused));
        }
        Some(_) if !stored.spent => {}
        _ => return Err(Refusal::Problem(ProblemCode::IdempotencyExpired)),
    }
    match (
        stored.status.and_then(|status| u16::try_from(status).ok()),
        stored.receipt,
        stored.message_id,
    ) {
        (Some(status), Some(receipt), Some(message_id)) => Ok(SubmissionAnswer {
            status,
            receipt,
            message_id,
            replayed: true,
            audit_record: None,
        }),
        _ => Err(Refusal::Problem(ProblemCode::IdempotencyExpired)),
    }
}

/// The instants one accepted message is bounded by.
struct Window {
    not_before: Option<SystemTime>,
    expires_at: SystemTime,
}

impl Window {
    /// `expiresAt` must lie after acceptance and within the payload
    /// retention counted from acceptance, and defaults to the sender
    /// profile's expiry capped by that retention; `notBefore` must precede
    /// it. The cap keeps a message from waiting in the queue longer than
    /// its payload would be kept once it ends; the payload itself is erased
    /// `payloadRetentionDays` after the message reaches a terminal state (see
    /// [`crate::retention`]).
    fn new(
        now: SystemTime,
        submission: &PreparedSubmission,
        retention: &RetentionConfig,
    ) -> Result<Self, Refusal> {
        let invalid = || Refusal::Problem(ProblemCode::RequestUnprocessable);
        let payload = days(retention.payload_retention_days);
        let latest = now + payload;
        let expires_at = match submission.expires_at {
            Some(expires_at) if expires_at <= now || expires_at > latest => return Err(invalid()),
            Some(expires_at) => expires_at,
            None => {
                now + Duration::from_secs(u64::from(submission.profile.expiry_seconds()))
                    .min(payload)
            }
        };
        if submission
            .not_before
            .is_some_and(|not_before| not_before >= expires_at)
        {
            return Err(invalid());
        }
        Ok(Self {
            not_before: submission.not_before,
            expires_at,
        })
    }
}

async fn insert_message(
    transaction: &tokio_postgres::Transaction<'_>,
    caller: &Caller,
    message_id: Uuid,
    submission: &PreparedSubmission,
    window: &Window,
) -> Result<(), Refusal> {
    let content = &submission.content;
    let profile = &submission.profile;
    let policy = profile.retry_policy();
    let (template_id, template_version, template_locale) = match &content.source {
        ContentSource::Template {
            id,
            version,
            locale,
        } => (
            Some(id.as_str()),
            Some(version.as_str()),
            Some(locale.as_str()),
        ),
        ContentSource::Direct => (None, None, None),
    };
    let segments = content
        .sms
        .map(|sms| i16::try_from(sms.segments))
        .transpose()
        .map_err(|_| Refusal::Problem(ProblemCode::ServiceUnavailable))?;
    let initial_ms = i64::from(policy.initial_delay_seconds) * 1000;
    let maximum_ms = i64::from(policy.maximum_delay_seconds) * 1000;
    let maximum_attempts = i16::from(policy.maximum_attempts);
    transaction
        .execute(
            "INSERT INTO messaging_messages \
                 (message_id, submitter_issuer, submitter_subject, access_profile, \
                  sender_profile, channel, provider, sender, recipient_kind, content_source, \
                  template_id, template_version, template_locale, package_digest, \
                  correlation_id, sms_segments, maximum_attempts, initial_retry_delay_ms, \
                  maximum_retry_delay_ms, on_uncertain, provider_idempotent_submit, accepted_at, \
                  not_before, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
                     $17, $18, $19, $20, $21, transaction_timestamp(), $22, $23)",
            &[
                &message_id,
                &caller.identity.issuer,
                &caller.identity.subject,
                &caller.profile.id,
                &profile.id,
                &content.channel.as_str(),
                &profile.provider,
                &profile.sender,
                &submission.request.to.kind(),
                &content.source.as_str(),
                &template_id,
                &template_version,
                &template_locale,
                &content.package_digest,
                &submission.request.correlation_id,
                &segments,
                &maximum_attempts,
                &initial_ms,
                &maximum_ms,
                &profile.on_uncertain.as_str(),
                &submission.provider_idempotent_submit,
                &window.not_before,
                &window.expires_at,
            ],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO messaging_message_payloads \
                 (message_id, recipient, subject, text_body, html_body) \
             VALUES ($1, $2, $3, $4, $5)",
            &[
                &message_id,
                &submission.request.to.contact(),
                &content.parts.subject,
                &content.parts.text,
                &content.parts.html,
            ],
        )
        .await?;
    Ok(())
}

fn accepted_record(
    caller: &Caller,
    message_id: Uuid,
    submission: &PreparedSubmission,
    window: &Window,
    references: &References,
) -> Value {
    let content = &submission.content;
    let template = match &content.source {
        ContentSource::Template {
            id,
            version,
            locale,
        } => json!({"id": id, "version": version, "locale": locale}),
        ContentSource::Direct => Value::Null,
    };
    json!({
        "event": MESSAGE_ACCEPTED_EVENT,
        "messageId": message_id.to_string(),
        "accessProfile": caller.profile.id,
        "principalPseudonym": references.principal_pseudonym,
        "senderProfile": submission.profile.id,
        "provider": submission.profile.provider,
        "channel": content.channel.as_str(),
        "contentSource": content.source.as_str(),
        "template": template,
        "packageDigest": content.package_digest,
        "correlationId": submission.request.correlation_id,
        "recipientReference": references.recipient_reference,
        "smsSegments": content.sms.map(|sms| sms.segments),
        "notBefore": window.not_before.map(format_instant),
        "expiresAt": format_instant(window.expires_at),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_idempotency_key_is_bounded_visible_ascii() {
        assert!(valid_idempotency_key(b"a"));
        assert!(valid_idempotency_key(
            &[b'~'; MAXIMUM_IDEMPOTENCY_KEY_BYTES]
        ));
        for refused in [
            &b""[..],
            &[b'a'; MAXIMUM_IDEMPOTENCY_KEY_BYTES + 1][..],
            b"has space",
            b"tab\t",
            "caf\u{e9}".as_bytes(),
        ] {
            assert!(!valid_idempotency_key(refused), "{refused:?}");
        }
    }

    fn caller(issuer: &str, subject: &str) -> CallerIdentity {
        CallerIdentity {
            issuer: issuer.to_owned(),
            subject: subject.to_owned(),
        }
    }

    #[test]
    fn a_key_reference_digests_a_domain_and_the_length_prefixed_caller_operation_and_key() {
        let issuer = "https://identity.example.test";
        let subject = "staff.member@example.org";
        let mut preimage = b"registry-messaging-idempotency-key-v1".to_vec();
        for part in [issuer, subject, SUBMIT_OPERATION, "key-1"] {
            preimage.extend_from_slice(&u64::try_from(part.len()).unwrap().to_be_bytes());
            preimage.extend_from_slice(part.as_bytes());
        }
        let reference =
            idempotency_key_reference(&caller(issuer, subject), SUBMIT_OPERATION, "key-1");
        assert_eq!(
            reference,
            format!(
                "sha256:{}",
                hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&preimage))
            )
        );
    }

    #[test]
    fn a_key_reference_keeps_every_caller_and_key_apart() {
        let references = [
            idempotency_key_reference(&caller("issuer", "subject"), SUBMIT_OPERATION, "key"),
            // A boundary moved between the issuer and the subject.
            idempotency_key_reference(&caller("issue", "rsubject"), SUBMIT_OPERATION, "key"),
            idempotency_key_reference(&caller("other", "subject"), SUBMIT_OPERATION, "key"),
            idempotency_key_reference(&caller("issuer", "other"), SUBMIT_OPERATION, "key"),
            idempotency_key_reference(&caller("issuer", "subject"), SUBMIT_OPERATION, "other"),
            idempotency_key_reference(&caller("issuer", "subject"), "other-operation", "key"),
        ];
        let distinct: BTreeSet<&String> = references.iter().collect();
        assert_eq!(distinct.len(), references.len(), "{references:?}");
        assert_eq!(
            references[0],
            idempotency_key_reference(&caller("issuer", "subject"), SUBMIT_OPERATION, "key"),
            "one caller's key always has one reference"
        );
    }

    #[test]
    fn every_job_state_is_one_dispatch_state() {
        let states = [
            JobState::Pending,
            JobState::Leased,
            JobState::Delivered,
            JobState::DeadLettered,
            JobState::Expired,
            JobState::Unknown,
            JobState::Cancelled,
        ];
        let dispatched: BTreeSet<&str> = states
            .into_iter()
            .map(|state| dispatch_of(state).as_str())
            .collect();
        assert_eq!(dispatched.len(), MessageDispatch::ALL.len());
        assert_eq!(dispatch_of(JobState::Delivered), MessageDispatch::Submitted);
        assert_eq!(dispatch_of(JobState::DeadLettered), MessageDispatch::Failed);
    }

    #[test]
    fn a_status_filter_names_only_stored_state_and_report_names() {
        assert_eq!(status_condition(None), "true");
        assert_eq!(
            status_condition(Some(MessageStatus::Failed)),
            "(job.state = 'dead_lettered' OR (job.state = 'delivered' AND message.report = \
             'undelivered'))"
        );
        assert_eq!(
            status_condition(Some(MessageStatus::Delivered)),
            "job.state = 'delivered' AND message.report = 'delivered'"
        );
    }

    #[test]
    fn a_report_no_receipt_moved_is_unavailable_only_without_receipts() {
        let mut message = StoredMessage {
            submitter: CallerIdentity {
                issuer: "https://issuer.example".to_owned(),
                subject: "caller".to_owned(),
            },
            access_profile: "sender".to_owned(),
            provider: "mail-relay".to_owned(),
            state: JobState::Delivered,
            generation: 1,
            attempt: 1,
            view: MessageView {
                id: "0b5c".to_owned(),
                status: MessageStatus::Submitted,
                dispatch: MessageDispatch::Submitted,
                report: MessageReport::None,
                reported_at: None,
                channel: Channel::Email,
                sender_profile: "email-default".to_owned(),
                to: Recipient::Email(MASKED_CONTACT.to_owned()),
                template: None,
                correlation_id: None,
                accepted_at: "2026-09-25T10:00:00Z".to_owned(),
                not_before: None,
                expires_at: "2026-09-26T10:00:00Z".to_owned(),
                updated_at: "2026-09-25T10:00:01Z".to_owned(),
                attempts: Vec::new(),
                links: MessageLinks::for_message("0b5c"),
            },
        };
        let receipts = BTreeSet::from(["sms-gateway".to_owned()]);
        let mut receiving = message.clone();
        receiving.provider = "sms-gateway".to_owned();
        receiving.settle_report_capability(&receipts);
        assert_eq!(receiving.view.report, MessageReport::None);

        let mut reported = receiving.clone();
        reported.view.report = MessageReport::Delivered;
        reported.provider = "mail-relay".to_owned();
        reported.settle_report_capability(&receipts);
        assert_eq!(reported.view.report, MessageReport::Delivered);

        message.settle_report_capability(&receipts);
        assert_eq!(message.view.report, MessageReport::Unavailable);
        assert_eq!(message.view.status, MessageStatus::Submitted);
    }

    #[test]
    fn instants_parse_as_rfc3339_and_format_in_utc() {
        let parsed = parse_instant(Some("2026-10-01T09:30:00+02:00"))
            .unwrap()
            .unwrap();
        assert_eq!(format_instant(parsed), "2026-10-01T07:30:00.000Z");
        assert_eq!(parse_instant(None).unwrap(), None);
        for refused in ["2026-10-01", "tomorrow", "2026-10-01T07:30:00"] {
            assert_eq!(
                parse_instant(Some(refused)).unwrap_err(),
                ProblemCode::RequestUnprocessable
            );
        }
    }

    #[test]
    fn instants_parse_at_the_microsecond_precision_postgresql_stores() {
        let whole = parse_instant(Some("2026-10-01T07:30:00Z")).unwrap();
        assert_eq!(
            parse_instant(Some("2026-10-01T07:30:00.0000009Z")).unwrap(),
            whole
        );
        assert_eq!(
            parse_instant(Some("2026-10-01T07:30:00.0000019Z")).unwrap(),
            whole.map(|instant| instant + Duration::from_micros(1))
        );
    }
}
