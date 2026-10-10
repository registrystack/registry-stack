use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// A person is qualified by the issuer that authenticated the subject.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerPrincipal {
    pub issuer: String,
    pub subject: String,
}

/// A directory-scoped presentation of a person. The optional name belongs to
/// one team membership and never enters accountable actor identity.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectoryMember {
    pub issuer: String,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl From<IssuerPrincipal> for DirectoryMember {
    fn from(principal: IssuerPrincipal) -> Self {
        Self {
            issuer: principal.issuer,
            subject: principal.subject,
            display_name: None,
        }
    }
}

#[cfg(test)]
mod directory_member_tests {
    use super::*;

    #[test]
    fn display_names_remain_directory_scoped() {
        let member: DirectoryMember = serde_json::from_value(serde_json::json!({
            "issuer": "https://issuer.example",
            "subject": "officer-1",
            "displayName": "Officer One"
        }))
        .expect("directory member with display name");
        assert_eq!(member.display_name.as_deref(), Some("Officer One"));

        let unnamed: DirectoryMember = IssuerPrincipal {
            issuer: member.issuer.clone(),
            subject: member.subject.clone(),
        }
        .into();
        assert_eq!(
            serde_json::to_value(unnamed).expect("unnamed member"),
            serde_json::json!({
                "issuer": "https://issuer.example",
                "subject": "officer-1"
            })
        );
        assert!(
            serde_json::from_value::<IssuerPrincipal>(serde_json::json!({
                "issuer": "https://issuer.example",
                "subject": "officer-1",
                "displayName": "must not enter accountable identity"
            }))
            .is_err()
        );
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
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
#[serde(rename_all = "kebab-case")]
pub enum OccurrenceKind {
    Review,
    Application,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
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
    /// Every declared occurrence state, in a fixed order the lifecycle
    /// description and its tests iterate against.
    ///
    /// Rust cannot enumerate an enum's variants, so this list is what
    /// `occurrence_lifecycle` walks. A new variant missing from here is
    /// missing from the published lifecycle too. The exhaustive match in
    /// `lifecycle::occurrence_state_id` is what catches that: it has no
    /// wildcard arm, so adding a variant fails the build there, and adding
    /// it here is the other half of that same edit.
    pub const ALL: [Self; 8] = [
        Self::Open,
        Self::Claimed,
        Self::WaitingApplicant,
        Self::WaitingApplication,
        Self::Synchronizing,
        Self::Completed,
        Self::Superseded,
        Self::Cancelled,
    ];

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
    /// Human-facing source reference disclosed by the source to this caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_reference: Option<String>,
    pub state: OccurrenceState,
    pub queue_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub holder: Option<IssuerPrincipal>,
    /// When the current holder took responsibility for this item. This is
    /// absent whenever the item has no holder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_since: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignment: Option<AssignmentContext>,
    pub revision: i64,
    pub first_observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passive_due_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    /// The routing decision recorded when this item was first observed. This
    /// contains policy-authored explanation only, never source predicate data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<WorkItemRouting>,
    /// Caller-safe clock summaries populated after current source visibility
    /// has been confirmed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clock_occurrences: Vec<crate::ClockOccurrenceView>,
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
pub struct WorkItemRouting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub because: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<String>,
}

/// Staff-visible routing context for a personal assignment.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AssignmentContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<IssuerPrincipal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_by: Option<IssuerPrincipal>,
    #[serde(default)]
    pub absence_ids: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub staffing_diagnostic: Option<StaffingDiagnostic>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaffingDiagnostic {
    NoCoverAvailable,
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

    /// The source action that sends a subject back for correction. When an
    /// action of this name completes, Casework retains the reason and the
    /// flagged fields the officer gave as the correction context of the work
    /// item. A source adapter that offers that action offers it under this
    /// name; no other name carries that meaning.
    pub const REQUEST_CORRECTION: &'static str = "request-correction";

    pub fn parse(value: &str) -> Result<Self, InvalidOperationName> {
        if !crate::typed::valid_local_identifier(value) {
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
        formatter.write_str("operation name must match [a-z][a-z0-9_-]{0,63}")
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
    fn the_correction_action_is_named_in_kebab_case() {
        assert_eq!(OperationName::REQUEST_CORRECTION, "request-correction");
        assert_eq!(
            OperationName::parse(OperationName::REQUEST_CORRECTION)
                .expect("the correction action is an operation name")
                .as_str(),
            "request-correction"
        );
    }

    #[test]
    fn cfg_id_1_an_operation_name_is_a_local_identifier() {
        for valid in [
            "approve",
            "approve-request",
            "request-correction",
            "request_correction",
            "verify-documents-2",
            "a",
        ] {
            let name = OperationName::parse(valid).unwrap_or_else(|_| panic!("{valid}"));
            assert_eq!(name.as_str(), valid);
            assert_eq!(
                serde_json::from_value::<OperationName>(serde_json::json!(valid)).ok(),
                Some(name),
                "{valid}"
            );
        }
        assert!(OperationName::parse(&"a".repeat(OperationName::MAX_LENGTH)).is_ok());
    }

    #[test]
    fn operation_names_refuse_unbounded_or_ambiguous_values() {
        for invalid in [
            "",
            "Approve",
            "approve-Request",
            "_approve",
            "-approve",
            "2approve",
            "apply request",
            "apply.request",
            "apply:request",
            "apply/request",
            "apply-*",
            "appl\u{e9}",
        ] {
            assert!(OperationName::parse(invalid).is_err(), "{invalid}");
            assert!(
                serde_json::from_value::<OperationName>(serde_json::json!(invalid)).is_err(),
                "{invalid}"
            );
        }
        assert!(OperationName::parse(&"a".repeat(OperationName::MAX_LENGTH + 1)).is_err());
        assert_eq!(
            InvalidOperationName.to_string(),
            "operation name must match [a-z][a-z0-9_-]{0,63}"
        );
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CallerSubjectView {
    pub subject: SubjectRef,
    pub binding: SourceBinding,
    /// Present only when the current caller's source response disclosed the
    /// configured field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_reference: Option<String>,
    #[serde(default)]
    pub disclosed: BTreeMap<String, Value>,
    #[serde(default)]
    pub permitted_operations: Vec<OperationName>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HistoryKind {
    Observed,
    Opened,
    Claimed,
    Assigned,
    Delegated,
    CaseloadMoved,
    Released,
    DraftSaved,
    TaskApproved,
    TaskRevoked,
    TaskInvalidated,
    AttemptReserved,
    AttemptUncertain,
    ActionCompleted,
    AttemptSettled,
    ClockReminder,
    ClockStepApplied,
    ClockRecomputed,
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
    /// An operator settlement records `outcome`, `reason`, and `decidedBy`
    /// and carries no actor.
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
#[serde(rename_all = "kebab-case")]
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
#[serde(rename_all = "kebab-case")]
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
    pub members: Vec<DirectoryMember>,
    pub supervisors: Vec<DirectoryMember>,
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

#[cfg(test)]
mod history_kind_tests {
    use super::*;

    #[test]
    fn every_history_kind_is_kebab_case() {
        let expected = [
            (HistoryKind::Observed, "observed"),
            (HistoryKind::Opened, "opened"),
            (HistoryKind::Claimed, "claimed"),
            (HistoryKind::Assigned, "assigned"),
            (HistoryKind::Delegated, "delegated"),
            (HistoryKind::CaseloadMoved, "caseload-moved"),
            (HistoryKind::Released, "released"),
            (HistoryKind::DraftSaved, "draft-saved"),
            (HistoryKind::TaskApproved, "task-approved"),
            (HistoryKind::TaskRevoked, "task-revoked"),
            (HistoryKind::TaskInvalidated, "task-invalidated"),
            (HistoryKind::AttemptReserved, "attempt-reserved"),
            (HistoryKind::AttemptUncertain, "attempt-uncertain"),
            (HistoryKind::ActionCompleted, "action-completed"),
            (HistoryKind::AttemptSettled, "attempt-settled"),
            (HistoryKind::ClockReminder, "clock-reminder"),
            (HistoryKind::ClockStepApplied, "clock-step-applied"),
            (HistoryKind::ClockRecomputed, "clock-recomputed"),
            (HistoryKind::Superseded, "superseded"),
            (HistoryKind::Completed, "completed"),
        ];
        for (kind, word) in expected {
            assert_eq!(serde_json::to_value(kind).unwrap(), word);
            assert_eq!(
                serde_json::from_value::<HistoryKind>(serde_json::json!(word)).unwrap(),
                kind
            );
            if word.contains('-') {
                let previous = word.replace('-', "_");
                assert!(
                    serde_json::from_value::<HistoryKind>(serde_json::json!(previous)).is_err(),
                    "{previous} is not read"
                );
            }
        }
    }
}
