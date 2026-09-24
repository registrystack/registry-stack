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
//! its dispatch job, and the acceptance audit, so an accepted message is
//! either wholly recorded or not at all.
//!
//! The idempotency key is scoped to the caller's issuer and subject. The
//! same key with the same canonical request replays the stored status and
//! receipt; the same key with another request is refused with
//! `idempotency.key-reused`; a key whose receipt is older than
//! `retention.submissionReceiptDays` is spent and refused with
//! `idempotency.expired`. A replay is authorized and rendered again against
//! the active package before its receipt is answered.
//!
//! The status view and every operator report name the recipient's kind
//! only, with the contact masked, and never return a part or template data.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, SecondsFormat, Utc};
use registry_messaging_core::{
    AttemptOutcome, AttemptSummary, Caller, CallerIdentity, Channel, ContentRefusal, ContentSource,
    MessageLinks, MessageReceipt, MessageReport, MessageStatus, MessageView, Package,
    PreparedContent, ProblemCode, Recipient, SenderProfile, SubmissionContent,
    SubmitMessageRequest, TemplateMessageRequest, TemplateReference, MAXIMUM_IDEMPOTENCY_KEY_BYTES,
};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_dispatch::postgres::{enqueue, CancelOutcome, JobKey, JobState};
use registry_platform_dispatch::{idempotency_key, DispatchError};
use serde::Serialize;
use serde_json::{json, Value};
use thiserror::Error;
use tokio_postgres::Row;
use uuid::Uuid;

use crate::audit::AuditJournal;
use crate::config::RetentionConfig;
use crate::dispatch::{acting_as, Actor, MessageDispatcher, MESSAGE_PART};
use crate::outbox;
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
const SECONDS_PER_DAY: u64 = 86_400;

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
    Ok(PreparedSubmission {
        request_hash,
        request,
        content,
        profile,
        not_before,
        expires_at,
    })
}

fn parse_instant(value: Option<&str>) -> Result<Option<SystemTime>, ProblemCode> {
    value
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|instant| SystemTime::from(instant.with_timezone(&Utc)))
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
}

/// Why the store could not answer an operator action.
#[derive(Debug, Error)]
pub enum MessageStoreError {
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The dispatch core refused the transition: the message changed
    /// between the read and the write, or the store failed.
    #[error("the Messaging dispatch store refused the transition")]
    Refused,
}

impl From<tokio_postgres::Error> for MessageStoreError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Store(StoreError::Query(error))
    }
}

impl From<DispatchError> for MessageStoreError {
    fn from(_: DispatchError) -> Self {
        Self::Refused
    }
}

/// One stored message: its submitter, dispatch state, and view.
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub submitter: CallerIdentity,
    pub access_profile: String,
    pub state: JobState,
    pub generation: i64,
    pub attempt: i16,
    pub view: MessageView,
}

/// One row of an operator listing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSummary {
    pub id: String,
    pub status: MessageStatus,
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
    pub generation: i64,
    /// Whether the message is in the one state the action applies to.
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
    /// The message is being sent, was handed to its provider, or its
    /// outcome is unknown.
    DispatchStarted,
    /// The message already reached a final state.
    Terminal,
}

/// The message store: accepted messages, their jobs, and their attempts.
#[derive(Clone)]
pub struct MessageStore {
    store: PostgresStore,
    dispatcher: MessageDispatcher,
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
         job.updated_at \
    FROM messaging_messages AS message \
    JOIN messaging_dispatch_jobs AS job \
      ON job.message_id = message.message_id AND job.part = 'message'";

impl MessageStore {
    #[must_use]
    pub fn new(store: PostgresStore, dispatcher: MessageDispatcher) -> Self {
        Self { store, dispatcher }
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

    /// List messages, newest first, optionally only those with `status`.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot answer.
    pub async fn list(
        &self,
        status: Option<MessageStatus>,
        limit: i64,
    ) -> Result<Vec<MessageSummary>, MessageStoreError> {
        let state = match status {
            Some(status) => match state_of(status) {
                Some(state) => Some(state.as_str()),
                // No stored message carries a status only receipts report.
                None => return Ok(Vec::new()),
            },
            None => None,
        };
        let client = self.store.client().await?;
        let rows = client
            .query(
                "SELECT message.message_id, job.state, message.channel, message.sender_profile, \
                        job.generation, job.attempt, message.accepted_at, job.updated_at \
                   FROM messaging_messages AS message \
                   JOIN messaging_dispatch_jobs AS job \
                     ON job.message_id = message.message_id AND job.part = 'message' \
                  WHERE $1::text IS NULL OR job.state = $1 \
                  ORDER BY message.accepted_at DESC, message.message_id \
                  LIMIT $2",
                &[&state, &limit],
            )
            .await?;
        rows.iter()
            .map(|row| {
                let state = decode_state(row, 1)?;
                Ok(MessageSummary {
                    id: row.try_get::<_, Uuid>(0)?.to_string(),
                    status: status_of(state),
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
            ) => CancelResult::DispatchStarted,
            CancelOutcome::NotCancellable(_) => CancelResult::Terminal,
        })
    }

    /// Report what `action` would do to one message, and with `apply` do
    /// it as the operator tool. `None` when no such message exists.
    ///
    /// # Errors
    ///
    /// The store's error when it cannot answer, and
    /// [`MessageStoreError::Refused`] when the message changed between the
    /// read and the write.
    pub async fn operate(
        &self,
        message_id: Uuid,
        action: OperatorAction,
        apply: bool,
    ) -> Result<Option<OperatorActionReport>, MessageStoreError> {
        let Some(message) = self.read(message_id).await? else {
            return Ok(None);
        };
        let eligible = message.state == action.applies_to();
        let next_status = eligible.then_some(match action {
            OperatorAction::Retry | OperatorAction::Settle(SettleOutcome::NotSent) => {
                MessageStatus::Queued
            }
            OperatorAction::Settle(SettleOutcome::Sent) => MessageStatus::Submitted,
            OperatorAction::Cancel => MessageStatus::Cancelled,
        });
        let mut report = OperatorActionReport {
            id: message.view.id.clone(),
            action: action.as_str(),
            outcome: match action {
                OperatorAction::Settle(outcome) => Some(outcome),
                OperatorAction::Retry | OperatorAction::Cancel => None,
            },
            status: message.view.status,
            generation: message.generation,
            eligible,
            applied: false,
            next_status,
            next_generation: None,
        };
        if !apply || !eligible {
            return Ok(Some(report));
        }
        let key = job_key(message_id)?;
        match action {
            OperatorAction::Retry | OperatorAction::Settle(SettleOutcome::NotSent) => {
                let generation = acting_as(
                    Actor::OperatorTool,
                    self.dispatcher.replay(&key, message.generation),
                )
                .await?;
                report.next_generation = Some(generation);
            }
            OperatorAction::Settle(SettleOutcome::Sent) => {
                self.settle_sent(message_id, message.generation).await?;
            }
            OperatorAction::Cancel => {
                if self.cancel(message_id, Actor::OperatorTool).await? != CancelResult::Cancelled {
                    return Err(MessageStoreError::Refused);
                }
            }
        }
        report.applied = true;
        Ok(Some(report))
    }

    /// Move an unknown outcome to delivered, fenced by its generation, with
    /// its audit in the same transaction.
    async fn settle_sent(
        &self,
        message_id: Uuid,
        generation: i64,
    ) -> Result<(), MessageStoreError> {
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
        if changed != 1 {
            return Err(MessageStoreError::Refused);
        }
        outbox::write(
            &transaction,
            json!({
                "event": MESSAGE_SETTLED_EVENT,
                "messageId": message_id.to_string(),
                "generation": generation,
                "outcome": "sent",
                "from": JobState::Unknown.as_str(),
                "disposition": JobState::Delivered.as_str(),
                "actor": Actor::OperatorTool.to_json(),
            }),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}

fn job_key(message_id: Uuid) -> Result<JobKey, MessageStoreError> {
    JobKey::new(message_id, MESSAGE_PART).map_err(|_| MessageStoreError::Refused)
}

/// The public status of a dispatch state. Delivery receipts are not
/// recorded, so an accepted send reports `submitted`.
#[must_use]
pub const fn status_of(state: JobState) -> MessageStatus {
    match state {
        JobState::Pending => MessageStatus::Queued,
        JobState::Leased => MessageStatus::Sending,
        JobState::Delivered => MessageStatus::Submitted,
        JobState::DeadLettered => MessageStatus::Failed,
        JobState::Expired => MessageStatus::Expired,
        JobState::Unknown => MessageStatus::Unknown,
        JobState::Cancelled => MessageStatus::Cancelled,
    }
}

const fn state_of(status: MessageStatus) -> Option<JobState> {
    match status {
        MessageStatus::Queued => Some(JobState::Pending),
        MessageStatus::Sending => Some(JobState::Leased),
        MessageStatus::Submitted => Some(JobState::Delivered),
        MessageStatus::Failed => Some(JobState::DeadLettered),
        MessageStatus::Expired => Some(JobState::Expired),
        MessageStatus::Unknown => Some(JobState::Unknown),
        MessageStatus::Cancelled => Some(JobState::Cancelled),
        MessageStatus::Delivered => None,
    }
}

fn refused<T>() -> Result<T, MessageStoreError> {
    Err(MessageStoreError::Refused)
}

fn decode_state(row: &Row, index: usize) -> Result<JobState, MessageStoreError> {
    JobState::parse(&row.try_get::<_, String>(index)?).map_or_else(refused, Ok)
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
    Ok(StoredMessage {
        submitter: CallerIdentity {
            issuer: row.try_get(1)?,
            subject: row.try_get(2)?,
        },
        access_profile: row.try_get(3)?,
        state,
        generation: row.try_get(14)?,
        attempt: row.try_get(15)?,
        view: MessageView {
            status: status_of(state),
            report: MessageReport::Unavailable,
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
    audit: Arc<AuditJournal>,
    retention: RetentionConfig,
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
    request_hash: String,
    spent: bool,
    status: Option<i16>,
    receipt: Option<Value>,
    message_id: Uuid,
}

impl MessageService {
    #[must_use]
    pub fn new(
        messages: MessageStore,
        audit: Arc<AuditJournal>,
        retention: RetentionConfig,
    ) -> Self {
        Self {
            messages,
            audit,
            retention,
        }
    }

    #[must_use]
    pub fn messages(&self) -> &MessageStore {
        &self.messages
    }

    /// Record one prepared submission under `key`, or answer the receipt
    /// the key already holds.
    ///
    /// # Errors
    ///
    /// `idempotency.expired`, `idempotency.key-reused`, `request.invalid`
    /// for a window the retention does not allow, and `service.unavailable`
    /// when the store or the journal's keys fail.
    pub async fn submit(
        &self,
        caller: &Caller,
        key: &str,
        submission: &PreparedSubmission,
    ) -> Result<SubmissionAnswer, ProblemCode> {
        let unavailable = |_| ProblemCode::ServiceUnavailable;
        let principal_pseudonym = self
            .audit
            .principal_pseudonym(&caller.identity)
            .map_err(unavailable)?;
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
                Err(Refusal::Problem(problem)) => return Err(problem),
                Err(Refusal::Store(error)) => {
                    tracing::warn!(
                        error = %error,
                        "the Messaging store could not record a submission"
                    );
                    return Err(ProblemCode::ServiceUnavailable);
                }
            }
        }
        Err(ProblemCode::ServiceUnavailable)
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
        if let Some(stored) = lookup_key(&transaction, &caller.identity, key).await? {
            transaction.commit().await?;
            return replay(stored, submission).map(Some);
        }
        let window = Window::new(now, submission, &self.retention)?;
        let message_id = Uuid::new_v4();
        let receipt = serde_json::to_value(MessageReceipt {
            id: message_id.to_string(),
            status: MessageStatus::Queued,
            links: MessageLinks::for_message(&message_id.to_string()),
        })
        .map_err(|_| Refusal::Problem(ProblemCode::ServiceUnavailable))?;
        let receipt_expires = now + days(self.retention.submission_receipt_days);
        let inserted = transaction
            .execute(
                "INSERT INTO messaging_idempotency \
                     (issuer, subject, operation, idempotency_key, request_hash, message_id, \
                      status_code, receipt, created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, 202, $7, transaction_timestamp(), $8) \
                 ON CONFLICT DO NOTHING",
                &[
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
        outbox::write(
            &transaction,
            accepted_record(caller, message_id, submission, &window, references),
        )
        .await
        .map_err(Refusal::dispatch)?;
        transaction.commit().await?;
        Ok(Some(SubmissionAnswer {
            status: 202,
            receipt,
            message_id,
            replayed: false,
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
        message.ok_or(ProblemCode::MessageNotVisible)
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

async fn lookup_key(
    transaction: &tokio_postgres::Transaction<'_>,
    identity: &CallerIdentity,
    key: &str,
) -> Result<Option<StoredKey>, Refusal> {
    let row = transaction
        .query_opt(
            "SELECT request_hash, \
                    erased_at IS NOT NULL OR expires_at <= transaction_timestamp(), \
                    status_code, receipt, message_id \
               FROM messaging_idempotency \
              WHERE issuer = $1 AND subject = $2 AND operation = $3 AND idempotency_key = $4",
            &[&identity.issuer, &identity.subject, &SUBMIT_OPERATION, &key],
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

fn replay(stored: StoredKey, submission: &PreparedSubmission) -> Result<SubmissionAnswer, Refusal> {
    if stored.spent {
        return Err(Refusal::Problem(ProblemCode::IdempotencyExpired));
    }
    if stored.request_hash != submission.request_hash {
        return Err(Refusal::Problem(ProblemCode::IdempotencyKeyReused));
    }
    match (
        stored.status.and_then(|status| u16::try_from(status).ok()),
        stored.receipt,
    ) {
        (Some(status), Some(receipt)) => Ok(SubmissionAnswer {
            status,
            receipt,
            message_id: stored.message_id,
            replayed: true,
        }),
        _ => Err(Refusal::Problem(ProblemCode::IdempotencyExpired)),
    }
}

/// The instants one accepted message is bounded by.
struct Window {
    not_before: Option<SystemTime>,
    expires_at: SystemTime,
    erase_after: SystemTime,
}

impl Window {
    /// `expiresAt` must lie after acceptance and within the payload
    /// retention, and defaults to the sender profile's expiry capped by
    /// that retention; `notBefore` must precede it.
    fn new(
        now: SystemTime,
        submission: &PreparedSubmission,
        retention: &RetentionConfig,
    ) -> Result<Self, Refusal> {
        let invalid = || Refusal::Problem(ProblemCode::RequestUnprocessable);
        let payload = days(retention.payload_days);
        let erase_after = now + payload;
        let expires_at = match submission.expires_at {
            Some(expires_at) if expires_at <= now || expires_at > erase_after => {
                return Err(invalid())
            }
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
            erase_after,
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
                  maximum_retry_delay_ms, on_uncertain, accepted_at, not_before, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
                     $17, $18, $19, $20, transaction_timestamp(), $21, $22)",
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
                &window.not_before,
                &window.expires_at,
            ],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO messaging_message_payloads \
                 (message_id, recipient, subject, text_body, html_body, erase_after) \
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &message_id,
                &submission.request.to.contact(),
                &content.parts.subject,
                &content.parts.text,
                &content.parts.html,
                &window.erase_after,
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

    #[test]
    fn every_dispatch_state_has_one_status_and_back() {
        for state in [
            JobState::Pending,
            JobState::Leased,
            JobState::Delivered,
            JobState::DeadLettered,
            JobState::Expired,
            JobState::Unknown,
            JobState::Cancelled,
        ] {
            assert_eq!(state_of(status_of(state)), Some(state));
        }
        assert_eq!(state_of(MessageStatus::Delivered), None);
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
}
