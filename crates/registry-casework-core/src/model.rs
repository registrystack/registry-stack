use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// A person is qualified by the issuer that authenticated the subject.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerPrincipal {
    pub issuer: String,
    pub subject: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseworkRole {
    Staff,
    Supervisor,
    Administrator,
    Requester,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActorContext {
    pub principal: IssuerPrincipal,
    pub profile_id: String,
    pub role: CaseworkRole,
}

/// A bearer credential may exist only for the duration of one request.
pub struct EphemeralCredential<'a>(&'a str);

impl<'a> EphemeralCredential<'a> {
    #[must_use]
    pub fn new(value: &'a str) -> Self {
        Self(value)
    }

    #[must_use]
    pub fn expose(self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for EphemeralCredential<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralCredential(<redacted>)")
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SubjectRef {
    pub source_id: String,
    pub kind: String,
    pub id: String,
}

/// The exact source facts displayed before a person confirms an action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceBinding {
    pub source_revision: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integrity: Option<String>,
    pub generation: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceKind {
    Review,
    Application,
    Hosted,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OccurrenceState {
    Open,
    Claimed,
    WaitingApplicant,
    WaitingApplication,
    Synchronizing,
    Completed,
    Superseded,
    Cancelled,
}

impl OccurrenceState {
    #[must_use]
    pub fn is_active(self) -> bool {
        !matches!(self, Self::Completed | Self::Superseded | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkItem {
    pub item_id: Uuid,
    pub subject: SubjectRef,
    pub occurrence_kind: OccurrenceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    pub binding: SourceBinding,
    /// A stable, non-authoritative correlation reference for this exact
    /// subject and displayed source binding.
    pub binding_reference: String,
    pub state: OccurrenceState,
    pub queue_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<IssuerPrincipal>,
    pub revision: i64,
    pub first_observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passive_due_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    /// Hosted context safe for a deciding person's inbox. Requester ownership
    /// and accountable actor identity are retained outside this projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosted: Option<crate::HostedWorkItemContext>,
    #[serde(default)]
    pub actions: Vec<CaseworkAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_copy: Option<CorrectionRoutingCopy>,
    /// The pending or uncertain attempt owned by the authenticated caller.
    /// Services must leave this absent for every other actor and profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_attempt: Option<AttemptStatus>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CorrectionRoutingCopy {
    pub source_binding: SourceBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub flagged_fields: Vec<String>,
}

/// One caller-filtered Casework action. The route and precondition are emitted
/// by the service so a client does not infer eligibility or compose a route.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaseworkAction {
    pub operation: String,
    pub href: String,
    pub if_match: String,
}

#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationName(String);

impl OperationName {
    pub const MAX_LENGTH: usize = 64;

    pub fn parse(value: &str) -> Result<Self, InvalidOperationName> {
        let input = value.as_bytes();
        if input.is_empty()
            || input.len() > Self::MAX_LENGTH
            || !input[0].is_ascii_lowercase()
            || input[1..]
                .iter()
                .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_'))
        {
            return Err(InvalidOperationName);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OperationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("OperationName")
            .field(&self.as_str())
            .finish()
    }
}

impl fmt::Display for OperationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for OperationName {
    type Err = InvalidOperationName;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl TryFrom<String> for OperationName {
    type Error = InvalidOperationName;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl Serialize for OperationName {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for OperationName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidOperationName;

impl fmt::Display for InvalidOperationName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operation name must match [a-z][a-z0-9_]{0,63}")
    }
}

impl std::error::Error for InvalidOperationName {}

#[cfg(test)]
mod operation_name_tests {
    use super::*;

    #[test]
    fn operation_names_are_open_bounded_and_wire_compatible() {
        let custom = OperationName::parse("verify_documents_2").expect("custom operation");
        assert_eq!(custom.as_str(), "verify_documents_2");
        assert_eq!(
            serde_json::to_string(&custom).expect("serialize"),
            "\"verify_documents_2\""
        );
        assert_eq!(
            serde_json::from_str::<OperationName>("\"approve\"").expect("deserialize"),
            OperationName::parse("approve").expect("approve")
        );
    }

    #[test]
    fn operation_names_refuse_unbounded_or_ambiguous_values() {
        for invalid in [
            "",
            "Approve",
            "approve-request",
            "_approve",
            "apply request",
        ] {
            assert!(OperationName::parse(invalid).is_err(), "{invalid}");
        }
        assert!(OperationName::parse(&"a".repeat(65)).is_err());
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallerSubjectView {
    pub subject: SubjectRef,
    pub binding: SourceBinding,
    #[serde(default)]
    pub disclosed: BTreeMap<String, Value>,
    #[serde(default)]
    pub permitted_operations: Vec<OperationName>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryKind {
    Observed,
    Opened,
    Claimed,
    Released,
    DraftSaved,
    AttemptReserved,
    AttemptUncertain,
    ActionCompleted,
    Superseded,
    Completed,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryEntry {
    pub event_id: Uuid,
    pub item_id: Uuid,
    pub item_revision: i64,
    pub kind: HistoryKind,
    pub occurred_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<IssuerPrincipal>,
    pub profile_id: String,
    /// Event-specific bounded data. Attempt events include the original
    /// `bindingReference`; successful completion also includes `sourceReceipt`.
    #[serde(default)]
    pub detail: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Draft {
    pub item_id: Uuid,
    pub author: IssuerPrincipal,
    pub binding: SourceBinding,
    pub reason: String,
    #[serde(default)]
    pub flagged_fields: Vec<String>,
    pub revision: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptState {
    Pending,
    Uncertain,
    Completed,
    Refused,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptStatus {
    pub attempt_id: Uuid,
    pub item_id: Uuid,
    pub state: AttemptState,
    pub item_revision: i64,
    pub operation: OperationName,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<SourceReceipt>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PageStatus {
    Complete,
    BudgetExhausted,
    SourceUnavailable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub status: PageStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoldingSummary {
    pub principal: IssuerPrincipal,
    pub queue_id: String,
    pub active_items: u32,
    pub overdue_items: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QueueRecord {
    pub id: String,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TeamRecord {
    pub id: String,
    pub members: Vec<IssuerPrincipal>,
    pub supervisors: Vec<IssuerPrincipal>,
    pub served_queues: Vec<String>,
    pub revision: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceReceipt {
    pub source_revision: String,
    pub resulting_state: String,
    pub binding: SourceBinding,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_reference: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}
