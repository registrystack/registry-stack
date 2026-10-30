//! Client-owned tolerant response wire models.
//!
//! Casework core models remain closed because the runtime uses them for
//! governed input. These shapes exist only at the HTTP client boundary, where
//! additive response members are compatible. Each DTO is serialized back to
//! its known shape and decoded through the strict core model so known field
//! bounds and semantic readers still run. Governed policy closures bypass
//! these DTOs because their complete contents are digest-covered.

use std::{collections::BTreeMap, marker::PhantomData};

use registry_casework_core::ReviewPolicyClosure;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

pub(crate) trait ClientResponse: Sized {
    type Wire: serde::de::DeserializeOwned;

    fn from_wire(wire: Self::Wire) -> Self;
}

pub(crate) struct Validated<T, W> {
    value: T,
    _wire: PhantomData<W>,
}

impl<T, W> Validated<T, W> {
    fn into_inner(self) -> T {
        self.value
    }
}

impl<'de, T, W> Deserialize<'de> for Validated<T, W>
where
    T: DeserializeOwned,
    W: Deserialize<'de> + Serialize,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = W::deserialize(deserializer)?;
        let known = serde_json::to_value(wire).map_err(serde::de::Error::custom)?;
        let value = serde_json::from_value(known).map_err(serde::de::Error::custom)?;
        Ok(Self {
            value,
            _wire: PhantomData,
        })
    }
}

macro_rules! response_wire {
    ($wire:ident => $response:ty { $($(#[$attribute:meta])* $field:ident: $field_type:ty),+ $(,)? }) => {
        #[derive(Deserialize, Serialize)]
        #[serde(rename_all = "camelCase")]
        pub(crate) struct $wire {
            $($(#[$attribute])* $field: $field_type),+
        }

        impl ClientResponse for $response {
            type Wire = Validated<$response, $wire>;

            fn from_wire(wire: Self::Wire) -> Self {
                wire.into_inner()
            }
        }
    };
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssuerPrincipalWire {
    issuer: String,
    subject: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubjectBindingWire {
    source: String,
    #[serde(rename = "type")]
    subject_type: String,
    id: String,
    version: String,
    digest: registry_casework_core::ContentDigest,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyBindingWire {
    id: String,
    version: String,
    digest: registry_casework_core::ContentDigest,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryMemberWire {
    issuer: String,
    subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct QueueRecordWire {
    id: String,
    label: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewContextContractWire {
    id: String,
    revision: registry_casework_core::ContentDigest,
    schema_digest: registry_casework_core::ContentDigest,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum ReviewContextPolicyWire {
    Submitted {},
    CurrentSource {
        provider: String,
        contract: ReviewContextContractWire,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoutingConditionWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stage: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    fields: BTreeMap<String, RoutingPredicateWire>,
}

enum RoutingPredicateWire {
    Equals(Value),
    OneOf(Vec<Value>),
}

impl<'de> Deserialize<'de> for RoutingPredicateWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut object = serde_json::Map::<String, Value>::deserialize(deserializer)?;
        match (object.remove("equals"), object.remove("oneOf")) {
            (Some(value), None) => Ok(Self::Equals(value)),
            (None, Some(Value::Array(values))) => Ok(Self::OneOf(values)),
            _ => Err(serde::de::Error::custom("invalid routing predicate")),
        }
    }
}

impl Serialize for RoutingPredicateWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = match self {
            Self::Equals(value) => serde_json::json!({"equals": value}),
            Self::OneOf(values) => serde_json::json!({"oneOf": values}),
        };
        value.serialize(serializer)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct RoutingRuleWire {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    because: String,
    when: RoutingConditionWire,
    queue: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewStagePolicyWire {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    queue: String,
    deciding_profiles: Vec<String>,
    required_approvals: u16,
    #[serde(default)]
    negative_decisions: registry_casework_core::ReviewNegativeDecisionMode,
    #[serde(default)]
    exclude_initiator: bool,
    #[serde(default)]
    exclude_previous_stage_reviewers: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewRetentionPolicyWire {
    terminal_retention_days: u32,
    accountability_retention_days: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewOutcomePolicyWire {
    id: String,
    label: String,
    settlement: registry_casework_core::ReviewOutcomeSettlement,
    reason_required: bool,
    public_reason: registry_casework_core::ReviewPublicReasonRule,
    #[serde(default)]
    result_required: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewPolicyWire {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    version: String,
    purpose: registry_casework_core::ReviewPurpose,
    context: ReviewContextPolicyWire,
    #[serde(default)]
    routing: Vec<RoutingRuleWire>,
    stages: Vec<ReviewStagePolicyWire>,
    #[serde(default)]
    clocks: Vec<String>,
    retention: ReviewRetentionPolicyWire,
    display_schema: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_schema: Option<Value>,
    #[serde(default)]
    outcomes: Vec<ReviewOutcomePolicyWire>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewContextProviderPolicyWire {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    capabilities: Vec<registry_casework_core::ReviewContextCapability>,
    source_namespace: String,
    deployment_ref: String,
    #[serde(default)]
    service_profiles: BTreeMap<registry_casework_core::ReviewContextCapability, String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct CalendarPolicyWire {
    id: String,
    timezone: String,
    working_weekdays: Vec<registry_casework_core::WorkingWeekday>,
    holiday_set: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SubjectClockAnchorWire {
    #[serde(rename = "type")]
    kind: registry_casework_core::SubjectClockAnchorType,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct StageClockAnchorWire {
    #[serde(rename = "type")]
    kind: registry_casework_core::StageClockAnchorType,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ElapsedDurationWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    minutes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hours: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    days: Option<u32>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkingDaysWire {
    working_days: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct WorkingDaysBeforeWire {
    before: WorkingDaysWire,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClockReminderWire {
    id: String,
    before: WorkingDaysWire,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClockReassignmentWire {
    queue: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClockStepActionWire {
    reassign: ClockReassignmentWire,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ClockStepWire {
    id: String,
    because: String,
    at: registry_casework_core::ClockStepInstant,
    action: ClockStepActionWire,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum ClockPolicyWire {
    Subject {
        id: String,
        anchor: SubjectClockAnchorWire,
        after: ElapsedDurationWire,
    },
    Stage {
        id: String,
        anchor: StageClockAnchorWire,
        calendar: String,
        after: WorkingDaysWire,
        due_time: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at_risk: Option<WorkingDaysBeforeWire>,
        #[serde(default)]
        reminders: Vec<ClockReminderWire>,
        #[serde(default)]
        steps: Vec<ClockStepWire>,
    },
}

response_wire!(DescriptionWire => registry_casework_core::Description {
    project_id: String,
    policy_version: String,
    queues: Vec<QueueRecordWire>,
    review_policies: Vec<ReviewPolicyWire>,
    context_providers: Vec<ReviewContextProviderPolicyWire>,
    #[serde(default)] calendars: Vec<CalendarPolicyWire>,
    #[serde(default)] clocks: Vec<ClockPolicyWire>,
});

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamRecordWire {
    id: String,
    members: Vec<DirectoryMemberWire>,
    supervisors: Vec<DirectoryMemberWire>,
    served_queues: Vec<String>,
    revision: i64,
}

response_wire!(DirectoryResponseWire => registry_casework_core::DirectoryResponse {
    revision: i64,
    teams: Vec<TeamRecordWire>,
});

response_wire!(AbsenceRecordWire => registry_casework_core::AbsenceRecord {
    absence_id: uuid::Uuid,
    person: IssuerPrincipalWire,
    from: chrono::DateTime<chrono::Utc>,
    until: chrono::DateTime<chrono::Utc>,
    cover: IssuerPrincipalWire,
    revision: i64,
});

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AbsenceListWire {
    directory_revision: i64,
    items: Vec<AbsenceRecordWire>,
    #[serde(default)]
    next_cursor: Option<String>,
}

impl ClientResponse for registry_casework_core::AbsenceList {
    type Wire = Validated<Self, AbsenceListWire>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskPermissionWire {
    collection: String,
    operations: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SchedulingTaskPermissionWire {
    service: String,
    location: String,
    actions: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum TaskGrantBoundsWire {
    Evidence {
        requirement: String,
    },
    Breg {
        permissions: Vec<TaskPermissionWire>,
    },
    Scheduling {
        permissions: Vec<SchedulingTaskPermissionWire>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceRequesterContextWire {
    requester_tags: Vec<String>,
    audience: String,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskTemplatePreviewWire {
    id: String,
    version: String,
    label: String,
    agent: IssuerPrincipalWire,
    client: String,
    resource: String,
    scopes: Vec<String>,
    purpose: String,
    bounds: TaskGrantBoundsWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence_context: Option<EvidenceRequesterContextWire>,
    subjects: BTreeMap<String, Value>,
    #[serde(default)]
    authorization_mode: registry_casework_core::TaskAuthorizationMode,
    lifetime_seconds: u64,
}

response_wire!(TaskTemplatePreviewsWire => registry_casework_core::TaskTemplatePreviews {
    task_revision: i64,
    templates: Vec<TaskTemplatePreviewWire>,
});

response_wire!(TaskGrantViewWire => registry_casework_core::TaskGrantView {
    id: uuid::Uuid,
    template_id: String,
    template_version: String,
    agent: IssuerPrincipalWire,
    client: String,
    resource: String,
    scopes: Vec<String>,
    purpose: String,
    bounds: TaskGrantBoundsWire,
    #[serde(default)] evidence_context: Option<EvidenceRequesterContextWire>,
    #[serde(default)] authorization_mode: registry_casework_core::TaskAuthorizationMode,
    expires_at: u64,
    invalidated: bool,
});

#[derive(Deserialize, Serialize)]
pub(crate) struct TaskGrantListWire {
    grants: Vec<TaskGrantViewWire>,
}

impl ClientResponse for registry_casework_core::TaskGrantList {
    type Wire = Validated<Self, TaskGrantListWire>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}

response_wire!(TaskGrantRevocationWire => registry_casework_core::TaskGrantRevocation {
    id: uuid::Uuid,
    invalidated: bool,
});

response_wire!(TaskAssertionResponseWire => registry_casework_core::TaskAssertionResponse {
    assertion: String,
    expires_at: u64,
    grant_expires_at: u64,
});

response_wire!(TaskGrantStatusWire => registry_casework_core::TaskGrantStatus {
    active: bool,
    #[serde(default)] grant: Option<TaskGrantStatusDetailsWire>,
});

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct TaskGrantStatusDetailsWire {
    grant_id: uuid::Uuid,
    source_issuer: String,
    principal: String,
    client: String,
    resource: String,
    purpose: String,
    bounds: TaskGrantBoundsWire,
    subjects: BTreeMap<String, Value>,
    expires_at: u64,
}

response_wire!(ReviewTaskDraftWire => registry_casework_core::ReviewTaskDraft {
    task_id: uuid::Uuid,
    author: IssuerPrincipalWire,
    body: Value,
    revision: i64,
    updated_at: chrono::DateTime<chrono::Utc>,
});

response_wire!(ReviewHistoryEntryWire => registry_casework_core::ReviewHistoryEntry {
    event_id: uuid::Uuid,
    request_id: uuid::Uuid,
    #[serde(default)] task_id: Option<uuid::Uuid>,
    kind: String,
    #[serde(default)] actor_ref: Option<String>,
    #[serde(default)] detail: Value,
    occurred_at: chrono::DateTime<chrono::Utc>,
});

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewHistoryPageWire {
    items: Vec<ReviewHistoryEntryWire>,
    #[serde(default)]
    next_cursor: Option<uuid::Uuid>,
}

impl ClientResponse for registry_casework_core::ReviewHistoryPage {
    type Wire = Validated<Self, ReviewHistoryPageWire>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}

enum ReviewTaskStateWire {
    Open,
    Held { holder: IssuerPrincipalWire },
    Decided,
}

#[derive(Deserialize)]
struct HeldStateWire {
    holder: IssuerPrincipalWire,
}

impl<'de> Deserialize<'de> for ReviewTaskStateWire {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut value = Value::deserialize(deserializer)?;
        if let Some(state) = value.as_str() {
            return match state {
                "open" => Ok(Self::Open),
                "decided" => Ok(Self::Decided),
                _ => Err(serde::de::Error::custom("unknown review task state")),
            };
        }
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("invalid review task state"))?;
        let held = object
            .remove("held")
            .ok_or_else(|| serde::de::Error::custom("missing held review task state"))?;
        let held: HeldStateWire = serde_json::from_value(held).map_err(serde::de::Error::custom)?;
        Ok(Self::Held {
            holder: held.holder,
        })
    }
}

impl Serialize for ReviewTaskStateWire {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Open => "open".serialize(serializer),
            Self::Decided => "decided".serialize(serializer),
            Self::Held { holder } => {
                #[derive(Serialize)]
                struct Held<'a> {
                    holder: &'a IssuerPrincipalWire,
                }
                #[derive(Serialize)]
                struct State<'a> {
                    held: Held<'a>,
                }
                State {
                    held: Held { holder },
                }
                .serialize(serializer)
            }
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewDecisionReceiptWire {
    policy: PolicyBindingWire,
    decision: registry_casework_core::ReviewDecisionType,
    outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome_label: Option<String>,
    decided_at: chrono::DateTime<chrono::Utc>,
}

response_wire!(ReviewTaskWire => registry_casework_core::ReviewTask {
    subject: SubjectBindingWire,
    requester_reference: String,
    deadline_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)] display_reference: Option<String>,
    task_id: uuid::Uuid,
    request_id: uuid::Uuid,
    stage_index: u16,
    stage_id: String,
    queue: String,
    revision: i64,
    eligible_profiles: Vec<String>,
    state: ReviewTaskStateWire,
    #[serde(default)] staffing_diagnostic: Option<registry_casework_core::StaffingDiagnostic>,
    #[serde(default)] decided_by_caller: Option<bool>,
    #[serde(default)] decision_receipt: Option<ReviewDecisionReceiptWire>,
});

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewTaskPageWire {
    items: Vec<ReviewTaskWire>,
    #[serde(default)]
    next_cursor: Option<uuid::Uuid>,
    status: registry_casework_core::PageStatus,
}

impl ClientResponse for registry_casework_core::ReviewTaskPage {
    type Wire = Validated<Self, ReviewTaskPageWire>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}

impl ClientResponse for Option<registry_casework_core::ReviewTask> {
    type Wire = Option<Validated<registry_casework_core::ReviewTask, ReviewTaskWire>>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.map(Validated::into_inner)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnReviewDecisionWire {
    task_id: uuid::Uuid,
    request_id: uuid::Uuid,
    queue: String,
    requester_reference: String,
    decision_receipt: ReviewDecisionReceiptWire,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    private_reason: Option<Value>,
    #[serde(
        default,
        deserialize_with = "deserialize_present_value",
        skip_serializing_if = "Option::is_none"
    )]
    result_digest: Option<Value>,
}

fn deserialize_present_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OwnReviewDecisionPageWire {
    items: Vec<OwnReviewDecisionWire>,
    #[serde(default)]
    next_cursor: Option<uuid::Uuid>,
    status: registry_casework_core::PageStatus,
}

impl ClientResponse for registry_casework_core::OwnReviewDecisionPage {
    type Wire = Validated<Self, OwnReviewDecisionPageWire>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct SupervisoryReviewTaskWire {
    task_id: uuid::Uuid,
    request_id: uuid::Uuid,
    queue: String,
    revision: i64,
    state: registry_casework_core::SupervisoryReviewTaskState,
    #[serde(default)]
    staffing_diagnostic: Option<registry_casework_core::StaffingDiagnostic>,
    #[serde(default)]
    accountability_event_id: Option<uuid::Uuid>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SupervisoryReviewTaskPageWire {
    items: Vec<SupervisoryReviewTaskWire>,
    #[serde(default)]
    next_cursor: Option<uuid::Uuid>,
    status: registry_casework_core::PageStatus,
}

impl ClientResponse for registry_casework_core::SupervisoryReviewTaskPage {
    type Wire = Validated<Self, SupervisoryReviewTaskPageWire>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DirectoryTargetPageWire {
    items: Vec<DirectoryMemberWire>,
    #[serde(default)]
    next_cursor: Option<String>,
    status: registry_casework_core::PageStatus,
}

impl ClientResponse for registry_casework_core::DirectoryTargetPage {
    type Wire = Validated<Self, DirectoryTargetPageWire>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "scope",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum ReviewClockCorrelationWire {
    Subject {
        source: String,
        subject_type: String,
        id: String,
    },
    Activity {
        task_id: uuid::Uuid,
        stage_id: String,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewClockOccurrenceWire {
    clock_occurrence_id: uuid::Uuid,
    clock_id: String,
    request_id: uuid::Uuid,
    correlation: ReviewClockCorrelationWire,
    state: registry_casework_core::ReviewClockState,
    policy_digest: registry_casework_core::ContentDigest,
    anchor_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    due_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    at_risk_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl ClientResponse for Vec<registry_casework_core::ReviewClockOccurrence> {
    type Wire = Validated<Self, Vec<ReviewClockOccurrenceWire>>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}

response_wire!(ReviewAccountabilityRecordWire => registry_casework_core::ReviewAccountabilityRecord {
    event_id: uuid::Uuid,
    request_id: uuid::Uuid,
    task_id: uuid::Uuid,
    actor_ref: String,
    actor: IssuerPrincipalWire,
    profile_id: String,
    decision: String,
    #[serde(default)] decision_receipt: Option<ReviewDecisionReceiptWire>,
    #[serde(default)] private_reason: Option<String>,
    #[serde(default)] result_digest: Option<String>,
    occurred_at: chrono::DateTime<chrono::Utc>,
    retained_until: chrono::DateTime<chrono::Utc>,
});

response_wire!(HolidaySetDocumentWire => registry_casework_core::HolidaySetDocument {
    holiday_set: String,
    revision: u64,
    dates: Vec<String>,
});

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewCaseloadTaskWire {
    task_id: uuid::Uuid,
    revision: i64,
}

response_wire!(ReviewCaseloadPreviewWire => registry_casework_core::ReviewCaseloadPreview {
    preview_id: uuid::Uuid,
    directory_revision: i64,
    tasks: Vec<ReviewCaseloadTaskWire>,
    expires_at: chrono::DateTime<chrono::Utc>,
});

response_wire!(ReviewCaseloadResultWire => registry_casework_core::ReviewCaseloadResult {
    moved: Vec<ReviewCaseloadTaskWire>,
});

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewClockRecomputeTaskWire {
    task_id: uuid::Uuid,
    revision: i64,
    deadline_at: Option<chrono::DateTime<chrono::Utc>>,
}

response_wire!(ReviewClockRecomputePreviewWire => registry_casework_core::ReviewClockRecomputePreview {
    preview_id: uuid::Uuid,
    directory_revision: i64,
    tasks: Vec<ReviewClockRecomputeTaskWire>,
    expires_at: chrono::DateTime<chrono::Utc>,
});

response_wire!(ReviewClockRecomputeResultWire => registry_casework_core::ReviewClockRecomputeResult {
    tasks: Vec<ReviewClockRecomputeTaskWire>,
});

// The closure digest covers the complete policy and dependency graph. Decode
// it strictly so an unknown governed member is never erased before `verify`.
impl ClientResponse for ReviewPolicyClosure {
    type Wire = ReviewPolicyClosure;

    fn from_wire(wire: Self::Wire) -> Self {
        wire
    }
}

impl ClientResponse for Vec<ReviewPolicyClosure> {
    type Wire = Vec<ReviewPolicyClosure>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReviewSourceProjectionWire {
    binding: SubjectBindingWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_reference: Option<String>,
    #[serde(default)]
    display: BTreeMap<String, Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "mode",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
enum ReviewTaskContextDataWire {
    Submitted {
        snapshot: Value,
    },
    CurrentSource {
        reference: String,
        binding_status: registry_casework_core::ReviewSourceBindingStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        projection: Option<ReviewSourceProjectionWire>,
    },
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReviewTaskContextWire {
    task_id: uuid::Uuid,
    request_id: uuid::Uuid,
    subject: SubjectBindingWire,
    requester_reference: String,
    policy: PolicyBindingWire,
    policy_closure: ReviewPolicyClosure,
    #[serde(default)]
    result_constraints: Option<Value>,
    context: ReviewTaskContextDataWire,
}

impl ClientResponse for registry_casework_core::ReviewTaskContext {
    type Wire = Validated<Self, ReviewTaskContextWire>;

    fn from_wire(wire: Self::Wire) -> Self {
        wire.into_inner()
    }
}
