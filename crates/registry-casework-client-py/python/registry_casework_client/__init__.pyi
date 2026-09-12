from typing import Generic, Literal, NotRequired, TypeAlias, TypedDict, TypeVar

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]

InboxView: TypeAlias = Literal["mine", "my_teams", "team_holdings", "overdue", "completed_by_me"]
InboxSort: TypeAlias = Literal["due", "age", "type"]
OccurrenceState: TypeAlias = Literal[
    "open", "claimed", "waiting_applicant", "waiting_application", "synchronizing",
    "completed", "superseded", "cancelled",
]
PageStatus: TypeAlias = Literal["complete", "budget_exhausted", "source_unavailable"]
HistoryKind: TypeAlias = Literal[
    "observed", "opened", "claimed", "assigned", "delegated", "caseload_moved",
    "clock_reminder", "clock_step_applied", "clock_recomputed", "released",
    "draft_saved", "attempt_reserved", "attempt_uncertain", "action_completed",
    "attempt_settled", "superseded", "completed",
]

class IssuerPrincipal(TypedDict):
    issuer: str
    subject: str

class TaskPermission(TypedDict):
    collection: str
    operations: list[str]
class EvidenceTaskBounds(TypedDict):
    type: Literal["evidence"]
    requirement: str
class BregTaskBounds(TypedDict):
    type: Literal["breg"]
    permissions: list[TaskPermission]
TaskGrantBounds: TypeAlias = EvidenceTaskBounds | BregTaskBounds
class EvidenceRequesterContext(TypedDict):
    requesterTags: list[str]
    audience: str
class TaskApprovalRequest(TypedDict):
    templateId: str
    templateVersion: str
class TaskTemplatePreview(TypedDict):
    id: str
    version: str
    label: str
    agent: IssuerPrincipal
    client: str
    resource: str
    scopes: list[str]
    evidenceContext: NotRequired[EvidenceRequesterContext]
    purpose: str
    bounds: TaskGrantBounds
    subjects: dict[str, str | int | bool]
    lifetimeSeconds: int
class TaskTemplatePreviews(TypedDict):
    itemRevision: int
    templates: list[TaskTemplatePreview]
class TaskGrantView(TypedDict):
    id: str
    templateId: str
    templateVersion: str
    agent: IssuerPrincipal
    client: str
    resource: str
    scopes: list[str]
    evidenceContext: NotRequired[EvidenceRequesterContext]
    purpose: str
    bounds: TaskGrantBounds
    expiresAt: int
    invalidated: bool
class TaskGrantList(TypedDict):
    grants: list[TaskGrantView]
class TaskGrantRevocation(TypedDict):
    id: str
    invalidated: bool
class TaskAssertionResponse(TypedDict):
    assertion: str
    expiresAt: int
    grantExpiresAt: int
class TaskGrantStatusDetails(TypedDict):
    grantId: str
    authority: str
    sourceIssuer: str
    principal: str
    client: str
    resource: str
    purpose: str
    bounds: TaskGrantBounds
    subjects: dict[str, str | int | bool]
    expiresAt: int
class _TaskGrantStatusOptional(TypedDict, total=False):
    grant: TaskGrantStatusDetails
class TaskGrantStatus(_TaskGrantStatusOptional):
    active: bool

class _DirectoryMemberOptional(TypedDict, total=False):
    displayName: str | None

class DirectoryMember(_DirectoryMemberOptional):
    issuer: str
    subject: str

class _SourceBindingOptional(TypedDict, total=False):
    integrity: str

class SourceBinding(_SourceBindingOptional):
    sourceRevision: str
    version: str
    generation: str

class SubjectRef(TypedDict):
    sourceId: str
    kind: str
    id: str

ClockRuntimeState: TypeAlias = Literal[
    "running", "paused", "completed", "cancelled", "verification_pending",
    "source_facts_missing",
]

class ClockReminderNextEffect(TypedDict):
    kind: Literal["reminder"]
    id: str
    at: str

class ClockReassignNextEffect(TypedDict):
    kind: Literal["reassign"]
    id: str
    at: str
    because: str
    queueId: str

ClockNextEffect: TypeAlias = ClockReminderNextEffect | ClockReassignNextEffect

class _ClockOccurrenceViewOptional(TypedDict, total=False):
    anchorAt: str
    startedAt: str
    dueAt: str
    atRiskAt: str
    completedAt: str
    nextEffect: ClockNextEffect
    upcomingEffects: list[ClockNextEffect]

class ClockOccurrenceView(_ClockOccurrenceViewOptional):
    clockOccurrenceId: str
    subject: SubjectRef
    clockId: str
    state: ClockRuntimeState
    policyDigest: str
    calculationGeneration: int
    recomputeGeneration: int

class HolidaySetDocument(TypedDict):
    holidaySet: str
    revision: int
    dates: list[str]

class HolidaySetRevisionInput(TypedDict):
    document: HolidaySetDocument

class ClockRecomputeRequest(TypedDict):
    clockId: str
    holidaySet: str
    holidayRevision: int

class ClockRecomputeChange(TypedDict):
    clockOccurrenceId: str
    itemId: str
    expectedCalculationGeneration: int
    oldDueAt: str
    proposedDueAt: str

class ClockRecomputePreview(TypedDict):
    previewId: str
    clockId: str
    holidaySet: str
    holidayRevision: int
    expiresAt: str
    changes: list[ClockRecomputeChange]

class ClockRecomputeApplyRequest(TypedDict):
    previewId: str

class ClockRecomputeResult(TypedDict):
    previewId: str
    appliedOccurrences: list[str]

class CaseworkAction(TypedDict):
    operation: str
    href: str
    ifMatch: str

class _CorrectionRoutingCopyOptional(TypedDict, total=False):
    reason: str

class CorrectionRoutingCopy(_CorrectionRoutingCopyOptional):
    sourceBinding: SourceBinding
    flaggedFields: list[str]

class HostedOutcomePolicy(TypedDict):
    id: str
    label: str
    reasonRequired: bool

class HostedWorkItemContext(TypedDict):
    requesterReference: str
    kind: str
    version: str
    display: JsonValue
    kindPolicyDigest: str
    outcomes: list[HostedOutcomePolicy]

class _AssignmentContextOptional(TypedDict, total=False):
    owner: IssuerPrincipal
    assignedBy: IssuerPrincipal
    staffingDiagnostic: Literal["no_cover_available"]

class AssignmentContext(_AssignmentContextOptional):
    absenceIds: list[str]

class _WorkItemRoutingOptional(TypedDict, total=False):
    ruleId: str
    because: str
    policyDigest: str

class WorkItemRouting(_WorkItemRoutingOptional):
    pass

class _WorkItemOptional(TypedDict, total=False):
    stage: str
    displayReference: str
    holder: IssuerPrincipal
    heldSince: str
    assignment: AssignmentContext
    passiveDueAt: str
    routingCopy: CorrectionRoutingCopy
    hosted: HostedWorkItemContext
    routing: WorkItemRouting
    clockOccurrences: list[ClockOccurrenceView]
    liveAttempt: "AttemptStatus"

class WorkItem(_WorkItemOptional):
    itemId: str
    subject: SubjectRef
    occurrenceKind: Literal["review", "application", "hosted"]
    binding: SourceBinding
    bindingReference: str
    state: OccurrenceState
    queueId: str
    revision: int
    firstObservedAt: str
    updatedAt: str
    actions: list[CaseworkAction]

class _WorkItemPageOptional(TypedDict, total=False):
    nextCursor: str

class WorkItemPage(_WorkItemPageOptional):
    items: list[WorkItem]
    servedQueues: list[str]
    status: PageStatus

class HostedCreateRequest(TypedDict):
    kind: str
    requesterReference: str
    display: JsonValue

class HostedNoteRequest(TypedDict):
    note: str

class HostedCancelRequest(TypedDict):
    reason: str

class _HostedDecisionRequestOptional(TypedDict, total=False):
    reason: str

class HostedDecisionRequest(_HostedDecisionRequestOptional):
    outcome: str

class HostedPageQuery(TypedDict, total=False):
    cursor: str
    limit: int

class HostedTerminalQuery(TypedDict, total=False):
    cursor: str
    limit: int

DirectoryTargetPurpose: TypeAlias = Literal["assignment", "absence_person", "absence_cover"]

class _DirectoryTargetsPageOptional(TypedDict, total=False):
    cursor: str
    limit: int

class DirectoryAssignmentTargetsQuery(_DirectoryTargetsPageOptional):
    purpose: Literal["assignment"]
    queue: str

class DirectoryAbsencePersonTargetsQuery(_DirectoryTargetsPageOptional):
    purpose: Literal["absence_person"]

class DirectoryAbsenceCoverTargetsQuery(_DirectoryTargetsPageOptional):
    purpose: Literal["absence_cover"]
    personIssuer: str
    personSubject: str

DirectoryTargetsQuery: TypeAlias = DirectoryAssignmentTargetsQuery | DirectoryAbsencePersonTargetsQuery | DirectoryAbsenceCoverTargetsQuery

class _ListWorkItemsQueryOptional(TypedDict, total=False):
    sort: InboxSort
    queue: str
    cursor: str
    limit: int

class _ListWorkItemsQueryBase(_ListWorkItemsQueryOptional):
    view: InboxView

class ListWorkItemsUnfilteredQuery(_ListWorkItemsQueryBase):
    pass

class ListWorkItemsBySubjectQuery(_ListWorkItemsQueryBase):
    sourceId: str
    subjectKind: str
    subjectId: str

class ListWorkItemsByReferenceQuery(_ListWorkItemsQueryBase):
    reference: str

ListWorkItemsQuery: TypeAlias = ListWorkItemsUnfilteredQuery | ListWorkItemsBySubjectQuery | ListWorkItemsByReferenceQuery

class NextWorkItemQuery(TypedDict, total=False):
    queue: str
    cursor: str

class HoldingsQuery(TypedDict, total=False):
    cursor: str
    limit: int

class _SaveDraftRequestOptional(TypedDict, total=False):
    flaggedFields: list[str]

class SaveDraftRequest(_SaveDraftRequestOptional):
    binding: SourceBinding
    reason: str

class _DecideRequestOptional(TypedDict, total=False):
    reason: str
    flaggedFields: list[str]

class DecideRequest(_DecideRequestOptional):
    displayedBinding: SourceBinding
    sourceProfileId: str
    operation: str

class RecoverAttemptRequest(TypedDict):
    sourceProfileId: str

class BootstrapDirectoryRequest(TypedDict):
    teamId: str
    staff: list[IssuerPrincipal]
    supervisors: list[IssuerPrincipal]
    queueId: str

class DirectoryTeamUpdateRequest(TypedDict):
    staff: list[DirectoryMember]
    supervisors: list[DirectoryMember]
    servedQueues: list[str]

AbsenceInput = TypedDict("AbsenceInput", {
    "person": IssuerPrincipal,
    "from": str,
    "until": str,
    "cover": IssuerPrincipal,
})

AbsenceRecord = TypedDict("AbsenceRecord", {
    "absenceId": str,
    "person": IssuerPrincipal,
    "from": str,
    "until": str,
    "cover": IssuerPrincipal,
    "revision": int,
})

class AbsencesQuery(TypedDict, total=False):
    cursor: str
    limit: int

class _AbsenceListOptional(TypedDict, total=False):
    nextCursor: str

class AbsenceList(_AbsenceListOptional):
    directoryRevision: int
    items: list[AbsenceRecord]

class _AssignmentRequestOptional(TypedDict, total=False):
    reason: str

class AssignmentRequest(_AssignmentRequestOptional):
    assignee: IssuerPrincipal

class _DelegateRequestOptional(TypedDict, total=False):
    reason: str

class DelegateRequest(_DelegateRequestOptional):
    delegate: IssuerPrincipal

_CaseloadMoveRequestRequired = TypedDict("_CaseloadMoveRequestRequired", {
    "from": IssuerPrincipal,
    "to": IssuerPrincipal,
    "reason": str,
})

class CaseloadMoveRequest(_CaseloadMoveRequestRequired, total=False):
    queueId: str

class CaseloadPreviewQuery(TypedDict, total=False):
    cursor: str
    limit: int

class CaseloadItemSelection(TypedDict):
    itemId: str
    expectedRevision: int

class CaseloadApplyRequest(TypedDict):
    movement: CaseloadMoveRequest
    items: list[CaseloadItemSelection]

class _CaseloadItemResultOptional(TypedDict, total=False):
    revision: int

class CaseloadItemResult(_CaseloadItemResultOptional):
    itemId: str
    result: Literal["moved", "not_visible", "not_eligible", "attempt_in_progress", "conflict"]

class RequesterHostedItem(TypedDict):
    itemId: str
    requesterReference: str
    kind: str
    version: str
    display: JsonValue
    state: OccurrenceState
    revision: int
    kindPolicyDigest: str
    createdAt: str
    updatedAt: str

class HostedNote(TypedDict):
    noteId: str
    itemId: str
    note: str
    itemRevision: int
    recordedAt: str

class HostedCompletedTerminalResult(TypedDict):
    itemId: str
    eventId: str
    requesterReference: str
    kindPolicyDigest: str
    terminalAt: str
    state: Literal["completed"]
    outcome: str
    actorRef: str

class HostedCancelledTerminalResult(TypedDict):
    itemId: str
    eventId: str
    requesterReference: str
    kindPolicyDigest: str
    terminalAt: str
    state: Literal["cancelled"]
    cancellationReason: str

HostedTerminalResult: TypeAlias = (
    HostedCompletedTerminalResult | HostedCancelledTerminalResult
)

class _HostedHistoryEntryOptional(TypedDict, total=False):
    actorRef: str
    assignment: AssignmentContext
    note: str
    outcome: str
    reason: str
    cancellationReason: str

class HostedHistoryEntry(_HostedHistoryEntryOptional):
    eventId: str
    itemId: str
    itemRevision: int
    kind: Literal[
        "created", "claimed", "assigned", "delegated", "caseload_moved",
        "released", "note_added", "completed", "cancelled",
    ]
    occurredAt: str

class _HostedAccountabilityRecordOptional(TypedDict, total=False):
    reason: str

class HostedAccountabilityRecord(_HostedAccountabilityRecordOptional):
    itemId: str
    eventId: str
    actorRef: str
    actor: IssuerPrincipal
    profileId: str
    outcome: str
    recordedAt: str
    retainedUntil: str

class _SourceReceiptOptional(TypedDict, total=False):
    actorReference: str

class SourceReceipt(_SourceReceiptOptional):
    sourceRevision: str
    resultingState: str
    binding: SourceBinding
    metadata: dict[str, str]

class _AttemptStatusOptional(TypedDict, total=False):
    receipt: SourceReceipt

class AttemptStatus(_AttemptStatusOptional):
    attemptId: str
    itemId: str
    state: Literal["pending", "uncertain", "completed", "refused"]
    itemRevision: int
    operation: str
    createdAt: str

class _MutationResponseOptional(TypedDict, total=False):
    attempt: AttemptStatus

class MutationResponse(_MutationResponseOptional):
    item: WorkItem

class Draft(TypedDict):
    itemId: str
    author: IssuerPrincipal
    binding: SourceBinding
    reason: str
    flaggedFields: list[str]
    revision: int
    updatedAt: str

class DraftResponse(TypedDict):
    draft: Draft

class HoldingSummary(TypedDict):
    principal: IssuerPrincipal
    queueId: str
    activeItems: int
    overdueItems: int

class TeamRecord(TypedDict):
    id: str
    members: list[DirectoryMember]
    supervisors: list[DirectoryMember]
    servedQueues: list[str]
    revision: int

class DirectoryResponse(TypedDict):
    revision: int
    teams: list[TeamRecord]

class QueueRecord(TypedDict):
    id: str
    label: str

class ElapsedDuration(TypedDict):
    elapsed: str

class PassiveTargetPolicy(TypedDict):
    id: str
    after: ElapsedDuration

RoutingActivity: TypeAlias = Literal["review", "apply"]

class EqualsPredicate(TypedDict):
    equals: JsonValue

class OneOfPredicate(TypedDict):
    oneOf: list[JsonValue]

RoutingPredicate: TypeAlias = EqualsPredicate | OneOfPredicate

class RoutingCondition(TypedDict, total=False):
    activity: RoutingActivity
    stage: str
    fields: dict[str, RoutingPredicate]

class RoutingRule(TypedDict):
    id: str
    because: str
    when: RoutingCondition
    queue: str

class _SourceRequestPolicyOptional(TypedDict, total=False):
    projection: list[str]
    routing: list[RoutingRule]
    displayReference: "DisplayReferencePolicy"
    clock: str
    target: PassiveTargetPolicy

class DisplayReferencePolicy(TypedDict):
    field: str

class SourceRequestPolicy(_SourceRequestPolicyOptional):
    entity: str
    queue: str

class SourcePolicy(TypedDict):
    id: str
    adapter: str
    description: str
    requests: list[SourceRequestPolicy]

class HostedRetentionPolicy(TypedDict):
    terminalDays: int
    accountabilityDays: int

class HostedKindPolicy(TypedDict):
    id: str
    version: str
    queue: str
    decidingProfiles: list[str]
    retention: HostedRetentionPolicy
    displaySchema: JsonValue
    outcomes: list[HostedOutcomePolicy]

WorkingWeekday: TypeAlias = Literal[
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
]

class CalendarPolicy(TypedDict):
    id: str
    timezone: str
    workingWeekdays: list[WorkingWeekday]
    holidaySet: str

class SubjectClockPolicy(TypedDict):
    scope: Literal["subject"]
    id: str
    anchor: Literal["firstSubmittedAt"]
    completeOn: Literal["reviewCompleted"]
    after: ElapsedDuration
    pauseWhile: list[Literal["awaitingApplicant"]]

class WorkingDaysAfter(TypedDict):
    workingDays: int

class WorkingDaysBefore(TypedDict):
    workingDaysBefore: int

class ClockReminder(TypedDict):
    id: str
    workingDaysBefore: int

class ClockReassignment(TypedDict):
    queue: str

class ClockStepAction(TypedDict):
    reassign: ClockReassignment

class ClockStep(TypedDict):
    id: str
    because: str
    at: Literal["due"]
    action: ClockStepAction

class _ActivityClockPolicyOptional(TypedDict, total=False):
    atRisk: WorkingDaysBefore
    reminders: list[ClockReminder]
    steps: list[ClockStep]

class ActivityClockPolicy(_ActivityClockPolicyOptional):
    scope: Literal["activity"]
    id: str
    anchor: Literal["stageEnteredAt"]
    calendar: str
    after: WorkingDaysAfter
    dueTime: str

ClockPolicy: TypeAlias = SubjectClockPolicy | ActivityClockPolicy

class Description(TypedDict):
    projectId: str
    policyVersion: str
    queues: list[QueueRecord]
    sources: list[SourcePolicy]
    calendars: list[CalendarPolicy]
    clocks: list[ClockPolicy]
    hostedKinds: list[HostedKindPolicy]

class _HistoryEntryOptional(TypedDict, total=False):
    actor: IssuerPrincipal

class HistoryEntry(_HistoryEntryOptional):
    eventId: str
    itemId: str
    itemRevision: int
    kind: HistoryKind
    occurredAt: str
    profileId: str
    detail: JsonValue

T = TypeVar("T")

class Complete(TypedDict, Generic[T]):
    kind: Literal["complete"]
    value: T
    trace_id: str

class _PageOptional(TypedDict, total=False):
    nextCursor: str

class Page(_PageOptional, Generic[T]):
    items: list[T]
    status: PageStatus

DirectoryTargetPage: TypeAlias = Page[DirectoryMember]

CaseworkErrorKind: TypeAlias = Literal[
    "configuration", "invalid_request", "transport", "problem", "protocol",
]
KnownCaseworkProblemCode: TypeAlias = Literal[
    "absence.cover-cycle",
    "absence.invalid-period",
    "absence.overlap",
    "absence.self-cover",
    "authentication.refused",
    "clock.recompute-preview-expired",
    "cursor.expired",
    "cursor.invalid",
    "idempotency.expired",
    "idempotency.key-reused",
    "operation.not-authorized",
    "precondition.failed",
    "precondition.required",
    "profile.not-authorized",
    "profile.not-human",
    "request.body-too-large",
    "request.invalid",
    "request.method-not-allowed",
    "request.not-found",
    "request.unprocessable",
    "request.unsupported-media-type",
    "runtime.failure",
    "service.unavailable",
    "source.bad-gateway",
    "source.not-found",
    "source.signature-invalid",
    "work-item.already-claimed",
    "work-item.not-holder",
    "work-item.not-offered",
    "work-item.not-visible",
    "work-item.proposal-changed",
    "work-item.recovery-pending",
    "work-item.source-unavailable",
    "work-item.superseded",
]
# A newer Casework service can answer a code this release does not name, so the
# attribute widens the closed catalogue the way the Node typings do.
CaseworkProblemCode: TypeAlias = KnownCaseworkProblemCode | str
HostedValidationReason: TypeAlias = Literal[
    "kind_not_allowed",
    "reference_invalid",
    "object_required",
    "maximum_bytes_exceeded",
    "maximum_depth_exceeded",
    "schema_mismatch",
    "outcome_not_declared",
    "reason_required",
    "text_invalid",
]

class ValidationDetail(TypedDict):
    path: str
    reason: HostedValidationReason

class CaseworkClientError(Exception):
    kind: CaseworkErrorKind
    code: CaseworkProblemCode | None
    detail: str | None
    status: int | None
    trace_id: str | None
    original_attempt_id: str | None
    validation: ValidationDetail | None
    transport_kind: str | None
    protocol_failure: str | None

class CaseworkClient:
    def __init__(self, base_url: str, request_timeout_seconds: float | None = None, connect_timeout_seconds: float | None = None, max_response_bytes: int | None = None, user_agent: str | None = None, trusted_root_certificates: bytes | None = None) -> None: ...
    def description(self, token: str, profile: str) -> Complete[Description]: ...
    def create_hosted_item(self, token: str, profile: str, idempotency_key: str, request: HostedCreateRequest) -> Complete[RequesterHostedItem]: ...
    def get_hosted_item(self, token: str, profile: str, item_id: str) -> Complete[RequesterHostedItem]: ...
    def add_hosted_note(self, token: str, profile: str, item_id: str, expected_revision: int, idempotency_key: str, note: HostedNoteRequest) -> Complete[RequesterHostedItem]: ...
    def requester_hosted_notes(self, token: str, profile: str, item_id: str, query: HostedPageQuery | None = None) -> Complete[Page[HostedNote]]: ...
    def cancel_hosted_item(self, token: str, profile: str, item_id: str, expected_revision: int, idempotency_key: str, cancellation: HostedCancelRequest) -> Complete[HostedTerminalResult]: ...
    def hosted_terminal_items(self, token: str, profile: str, query: HostedTerminalQuery | None = None) -> Complete[Page[HostedTerminalResult]]: ...
    def list_hosted_work_items(self, token: str, profile: str, query: ListWorkItemsQuery) -> Complete[WorkItemPage]: ...
    def get_hosted_work_item(self, token: str, profile: str, item_id: str) -> Complete[WorkItem]: ...
    def hosted_work_item_history(self, token: str, profile: str, item_id: str, query: HostedPageQuery | None = None) -> Complete[Page[HostedHistoryEntry]]: ...
    def hosted_accountability_record(self, token: str, profile: str, event_id: str) -> Complete[HostedAccountabilityRecord]: ...
    def claim_hosted_work_item(self, token: str, profile: str, action: CaseworkAction, idempotency_key: str) -> Complete[MutationResponse]: ...
    def release_hosted_work_item(self, token: str, profile: str, action: CaseworkAction, idempotency_key: str) -> Complete[MutationResponse]: ...
    def decide_hosted_work_item(self, token: str, profile: str, action: CaseworkAction, idempotency_key: str, decision: HostedDecisionRequest) -> Complete[HostedTerminalResult]: ...
    def list_work_items(self, token: str, profile: str, source_profile: str, query: ListWorkItemsQuery) -> Complete[WorkItemPage]: ...
    def next_work_item(self, token: str, profile: str, source_profile: str, query: NextWorkItemQuery | None = None) -> Complete[WorkItemPage]: ...
    def get_work_item(self, token: str, profile: str, source_profile: str, item_id: str) -> Complete[WorkItem]: ...
    def preview_task_templates(self, token: str, profile: str, source_profile: str, item_id: str) -> Complete[TaskTemplatePreviews]: ...
    def list_task_grants(self, token: str, profile: str, source_profile: str, item_id: str) -> Complete[TaskGrantList]: ...
    def approve_task_grant(self, token: str, profile: str, source_profile: str, item_id: str, expected_revision: int, idempotency_key: str, approval: TaskApprovalRequest) -> Complete[TaskGrantView]: ...
    def revoke_task_grant(self, token: str, profile: str, source_profile: str, item_id: str, grant_id: str) -> Complete[TaskGrantRevocation]: ...
    def task_assertion(self, token: str, grant_id: str) -> Complete[TaskAssertionResponse]: ...
    def task_grant_status(self, token: str, grant_id: str) -> Complete[TaskGrantStatus]: ...
    def claim_work_item(self, token: str, profile: str, source_profile: str, action: CaseworkAction, idempotency_key: str) -> Complete[MutationResponse]: ...
    def release_work_item(self, token: str, profile: str, source_profile: str, action: CaseworkAction, idempotency_key: str) -> Complete[MutationResponse]: ...
    def get_draft(self, token: str, profile: str, source_profile: str, item_id: str) -> Complete[DraftResponse]: ...
    def save_draft(self, token: str, profile: str, source_profile: str, item_id: str, expected_revision: int, idempotency_key: str, draft: SaveDraftRequest) -> Complete[DraftResponse]: ...
    def delete_draft(self, token: str, profile: str, source_profile: str, item_id: str, expected_revision: int, idempotency_key: str) -> Complete[None]: ...
    def decide_work_item(self, token: str, profile: str, source_profile: str, action: CaseworkAction, idempotency_key: str, decision: DecideRequest) -> Complete[MutationResponse]: ...
    def recover_decision(self, token: str, profile: str, source_profile: str, item_id: str, attempt_id: str, recovery: RecoverAttemptRequest) -> Complete[MutationResponse]: ...
    def recover_decision_by_key(self, token: str, profile: str, source_profile: str, item_id: str, idempotency_key: str, recovery: RecoverAttemptRequest) -> Complete[MutationResponse]: ...
    def work_item_history(self, token: str, profile: str, source_profile: str, item_id: str, query: HostedPageQuery | None = None) -> Complete[Page[HistoryEntry]]: ...
    def holdings(self, token: str, profile: str, source_profile: str, query: HoldingsQuery | None = None) -> Complete[Page[HoldingSummary]]: ...
    def directory(self, token: str, profile: str) -> Complete[DirectoryResponse]: ...
    def directory_targets(self, token: str, profile: str, query: DirectoryTargetsQuery) -> Complete[DirectoryTargetPage]: ...
    def bootstrap_directory(self, token: str, profile: str, expected_revision: int, idempotency_key: str, request: BootstrapDirectoryRequest) -> Complete[DirectoryResponse]: ...
    def update_directory_team(self, token: str, profile: str, team_id: str, expected_directory_revision: int, idempotency_key: str, request: DirectoryTeamUpdateRequest) -> Complete[DirectoryResponse]: ...
    def absences(self, token: str, profile: str, source_profile: str | None = None, query: AbsencesQuery | None = None) -> Complete[AbsenceList]: ...
    def create_absence(self, token: str, profile: str, expected_directory_revision: int, idempotency_key: str, absence: AbsenceInput, source_profile: str | None = None) -> Complete[AbsenceRecord]: ...
    def update_absence(self, token: str, profile: str, absence_id: str, expected_directory_revision: int, idempotency_key: str, absence: AbsenceInput, source_profile: str | None = None) -> Complete[AbsenceRecord]: ...
    def delete_absence(self, token: str, profile: str, absence_id: str, expected_directory_revision: int, idempotency_key: str, source_profile: str | None = None) -> Complete[None]: ...
    def assign_work_item(self, token: str, profile: str, item_id: str, expected_revision: int, idempotency_key: str, request: AssignmentRequest, source_profile: str | None = None) -> Complete[MutationResponse]: ...
    def delegate_work_item(self, token: str, profile: str, item_id: str, expected_revision: int, idempotency_key: str, request: DelegateRequest, source_profile: str | None = None) -> Complete[MutationResponse]: ...
    def preview_caseload_move(self, token: str, profile: str, movement: CaseloadMoveRequest, query: CaseloadPreviewQuery | None = None, source_profile: str | None = None) -> Complete[Page[WorkItem]]: ...
    def apply_caseload_move(self, token: str, profile: str, idempotency_key: str, request: CaseloadApplyRequest, source_profile: str | None = None) -> Complete[list[CaseloadItemResult]]: ...
    def work_item_clocks(self, token: str, profile: str, source_profile: str, item_id: str) -> Complete[list[ClockOccurrenceView]]: ...
    def holiday_revision(self, token: str, profile: str, holiday_set: str, revision: int) -> Complete[HolidaySetDocument]: ...
    def create_holiday_revision(self, token: str, profile: str, idempotency_key: str, request: HolidaySetRevisionInput) -> Complete[HolidaySetDocument]: ...
    def preview_clock_recompute(self, token: str, profile: str, request: ClockRecomputeRequest) -> Complete[ClockRecomputePreview]: ...
    def apply_clock_recompute(self, token: str, profile: str, idempotency_key: str, request: ClockRecomputeApplyRequest) -> Complete[ClockRecomputeResult]: ...

__version__: str
