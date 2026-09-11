use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::{
    ActorContext, CallerSubjectView, EphemeralCredential, OccurrenceKind, OccurrenceState,
    OperationName, RoutingContext, RoutingSourceMetadata, SourceBinding, SourceReceipt, SubjectRef,
};

/// A verified event is only an invalidation and revision hint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionHint {
    pub subject: SubjectRef,
    pub deduplication_key: String,
    pub ordered_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EventRequest {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// The source-neutral lifecycle facts derived from an authoritative read.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritativeObservation {
    pub subject: SubjectRef,
    /// Adapter-owned identity for one occurrence within this subject. The
    /// store treats it as opaque and never extracts source-specific fields.
    pub occurrence_key: String,
    pub ordered_revision: i64,
    /// The source response's opaque strong representation ETag. This only
    /// distinguishes representations at an equal ordered revision.
    pub representation_etag: String,
    pub binding: SourceBinding,
    /// Explicitly configured, bounded source value retained only for exact
    /// candidate lookup. Public projection requires a caller-scoped read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_reference: Option<String>,
    pub occurrence_kind: OccurrenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// Current-proposal submission time supplied by the source. This is not
    /// synthesized from Casework observation time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_at: Option<DateTime<Utc>>,
    /// Entry time of the current pending stage, when the source has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_entered_at: Option<DateTime<Utc>>,
    /// Request-wide timing retained by the source across corrections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_timing: Option<crate::ReviewTiming>,
    /// Ephemeral source values used only to choose a queue. They are never
    /// serialized into stored observations or public work-item projections.
    #[serde(skip)]
    pub routing_context: Option<RoutingContext>,
    pub state: OccurrenceState,
    #[serde(default)]
    pub remaining_actions: Vec<OperationName>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DiscoveryCursor(pub String);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveSubjectsPage {
    pub subjects: Vec<SubjectRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<DiscoveryCursor>,
}

/// Adapter-owned bytes sufficient to recover the exact prepared attempt.
///
/// They are inert outside the adapter and must exclude bearer credentials and
/// source request/record content.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecoveryEvidence(Vec<u8>);

impl RecoveryEvidence {
    pub const MAX_BYTES: usize = 64 * 1024;

    pub fn new(bytes: Vec<u8>) -> Result<Self, SourceAdapterError> {
        if bytes.is_empty() || bytes.len() > Self::MAX_BYTES {
            return Err(SourceAdapterError::Invalid);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for RecoveryEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryEvidence")
            .field("bytes", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedSourceAttempt {
    pub source_binding: SourceBinding,
    pub recovery_evidence: RecoveryEvidence,
}

pub struct PrepareActionRequest<'a> {
    pub subject: &'a SubjectRef,
    pub displayed_binding: &'a SourceBinding,
    pub operation: OperationName,
    pub reason: Option<&'a str>,
    pub actor: &'a ActorContext,
    pub source_profile_id: &'a str,
    pub idempotency_key: &'a str,
    pub credential: EphemeralCredential<'a>,
}

impl std::fmt::Debug for PrepareActionRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrepareActionRequest")
            .field("subject", self.subject)
            .field("displayed_binding", self.displayed_binding)
            .field("operation", &self.operation)
            .field("reason_present", &self.reason.is_some())
            .field("actor", self.actor)
            .field("source_profile_id", &self.source_profile_id)
            .field("idempotency_key", &"<redacted>")
            .field("credential", &self.credential)
            .finish()
    }
}

pub struct ExecutePreparedRequest<'a> {
    pub prepared: &'a PreparedSourceAttempt,
    pub execution: PreparedExecution,
    pub actor: &'a ActorContext,
    pub source_profile_id: &'a str,
    pub idempotency_key: &'a str,
    pub credential: EphemeralCredential<'a>,
}

impl std::fmt::Debug for ExecutePreparedRequest<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecutePreparedRequest")
            .field("prepared", self.prepared)
            .field("execution", &self.execution)
            .field("actor", self.actor)
            .field("source_profile_id", &self.source_profile_id)
            .field("idempotency_key", &"<redacted>")
            .field("credential", &self.credential)
            .finish()
    }
}

/// Whether an adapter is making the first network attempt or recovering an
/// outcome that might already have committed. A refusal can prove the former
/// failed without proving that an earlier attempt did not commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedExecution {
    Initial,
    Recovery,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum SourceAdapterError {
    #[error("the subject is not visible")]
    Concealed,
    #[error("the source refused this operation")]
    Denied,
    /// The source definitively refused the original prepared write. Adapters
    /// must not use this for a failed recovery or metadata preflight.
    #[error("the source definitively refused the original operation")]
    DefinitiveRefusal,
    #[error("the source is temporarily unavailable")]
    Unavailable,
    #[error("the displayed source binding is no longer current")]
    BindingMoved,
    #[error("the prepared source operation has an uncertain result")]
    Uncertain,
    #[error("the source response is invalid")]
    Invalid,
}

/// Internal seam implemented by each source protocol adapter.
#[async_trait]
pub trait SourceAdapter: Send + Sync {
    fn source_id(&self) -> &str;
    fn binding_generation(&self) -> &str;

    /// Imported source metadata used to validate and evaluate routing policy.
    /// Implementations must not treat this descriptive metadata as authority.
    fn routing_metadata(&self) -> Option<&RoutingSourceMetadata> {
        None
    }

    async fn verify_transition(
        &self,
        request: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError>;

    async fn read_authoritative(
        &self,
        subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError>;

    async fn discover_active(
        &self,
        cursor: Option<&DiscoveryCursor>,
        limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError>;

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        source_profile_id: &str,
        credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError>;

    /// Freshly read, compare the displayed binding, promote the native action,
    /// and return an inert exact-attempt capsule. This performs no source write.
    async fn prepare_action(
        &self,
        request: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError>;

    /// Execute or recover only the exact prepared action represented by the
    /// capsule. It may never create a fresh action with a changed binding.
    async fn execute_prepared(
        &self,
        request: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError>;
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DurableEvent {
    pub event_id: uuid::Uuid,
    pub item_id: uuid::Uuid,
    pub item_revision: i64,
    pub kind: String,
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub actor_reference: Option<String>,
    pub detail: Value,
}
