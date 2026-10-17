from typing import Never, NotRequired, Generic, Literal, TypeAlias, TypedDict, TypeVar

JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
# Integers crossing the review wire are validated against this exact portable domain.
SafeInteger: TypeAlias = int
# UUID strings are parsed by the native binding before any request is sent.
Uuid: TypeAlias = str

PageStatus: TypeAlias = Literal["complete", "budget-exhausted", "source-unavailable"]

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
class SchedulingTaskPermission(TypedDict):
    service: str
    location: str
    actions: list[str]
class SchedulingTaskBounds(TypedDict):
    type: Literal["scheduling"]
    permissions: list[SchedulingTaskPermission]
TaskGrantBounds: TypeAlias = EvidenceTaskBounds | BregTaskBounds | SchedulingTaskBounds
class EvidenceRequesterContext(TypedDict):
    requesterTags: list[str]
    audience: str
class TaskApprovalRequest(TypedDict):
    templateId: str
    templateVersion: str
TaskAuthorizationMode: TypeAlias = Literal["immediate", "deferred"]
class _TaskGrantOptional(TypedDict, total=False):
    evidenceContext: EvidenceRequesterContext
    # Omitted for the existing immediate mode; does not change credential TTLs.
    authorizationMode: TaskAuthorizationMode
class TaskTemplatePreview(_TaskGrantOptional):
    id: str
    version: str
    label: str
    agent: IssuerPrincipal
    client: str
    resource: str
    scopes: list[str]
    purpose: str
    bounds: TaskGrantBounds
    subjects: dict[str, str | int | bool]
    lifetimeSeconds: int
class TaskTemplatePreviews(TypedDict):
    taskRevision: int
    templates: list[TaskTemplatePreview]
class TaskGrantView(_TaskGrantOptional):
    id: str
    templateId: str
    templateVersion: str
    agent: IssuerPrincipal
    client: str
    resource: str
    scopes: list[str]
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

ClockRuntimeState: TypeAlias = Literal[
    "running", "completed", "cancelled", "verification-pending",
    "source-facts-missing",
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

class HolidaySetDocument(TypedDict):
    holidaySet: str
    revision: int
    dates: list[str]

class HolidaySetRevisionInput(TypedDict):
    document: HolidaySetDocument

StaffingDiagnostic: TypeAlias = Literal["no-cover-available", "insufficient-distinct-approvers"]

DirectoryTargetPurpose: TypeAlias = Literal["assignment", "absence-person", "absence-cover"]

class _DirectoryTargetsPageOptional(TypedDict, total=False):
    cursor: str
    limit: int

class DirectoryAssignmentTargetsQuery(_DirectoryTargetsPageOptional):
    purpose: Literal["assignment"]
    queue: str

class DirectoryAbsencePersonTargetsQuery(_DirectoryTargetsPageOptional):
    purpose: Literal["absence-person"]

class DirectoryAbsenceCoverTargetsQuery(_DirectoryTargetsPageOptional):
    purpose: Literal["absence-cover"]
    personIssuer: str
    personSubject: str

DirectoryTargetsQuery: TypeAlias = DirectoryAssignmentTargetsQuery | DirectoryAbsencePersonTargetsQuery | DirectoryAbsenceCoverTargetsQuery

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

class ElapsedMinutes(TypedDict):
    minutes: int

class ElapsedHours(TypedDict):
    hours: int

class ElapsedDays(TypedDict):
    days: int

ElapsedDuration: TypeAlias = ElapsedMinutes | ElapsedHours | ElapsedDays

class EqualsPredicate(TypedDict):
    equals: JsonValue

class OneOfPredicate(TypedDict):
    oneOf: list[JsonValue]

RoutingPredicate: TypeAlias = EqualsPredicate | OneOfPredicate

class RoutingCondition(TypedDict, total=False):
    stage: str
    fields: dict[str, RoutingPredicate]

class RoutingRule(TypedDict):
    id: str
    because: str
    when: RoutingCondition
    queue: str

WorkingWeekday: TypeAlias = Literal[
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
]

class CalendarPolicy(TypedDict):
    id: str
    timezone: str
    workingWeekdays: list[WorkingWeekday]
    holidaySet: str

class SubjectClockAnchor(TypedDict):
    type: Literal["request-accepted"]

class SubjectClockPolicy(TypedDict):
    type: Literal["subject"]
    id: str
    anchor: SubjectClockAnchor
    after: ElapsedDuration

class WorkingDays(TypedDict):
    workingDays: int

class WorkingDaysBefore(TypedDict):
    before: WorkingDays

class ClockReminder(TypedDict):
    id: str
    before: WorkingDays

class ClockReassignment(TypedDict):
    queue: str

class ClockStepAction(TypedDict):
    reassign: ClockReassignment

class ClockStep(TypedDict):
    id: str
    because: str
    at: Literal["due"]
    action: ClockStepAction

class StageClockAnchor(TypedDict):
    type: Literal["stage-entered"]

class _StageClockPolicyOptional(TypedDict, total=False):
    atRisk: WorkingDaysBefore
    reminders: list[ClockReminder]
    steps: list[ClockStep]

class StageClockPolicy(_StageClockPolicyOptional):
    type: Literal["stage"]
    id: str
    anchor: StageClockAnchor
    calendar: str
    after: WorkingDays
    dueTime: str

ClockPolicy: TypeAlias = SubjectClockPolicy | StageClockPolicy

class Description(TypedDict):
    projectId: str
    policyVersion: str
    queues: list[QueueRecord]
    reviewPolicies: list[ReviewPolicy]
    contextProviders: list[ReviewContextProviderPolicy]
    calendars: list[CalendarPolicy]
    clocks: list[ClockPolicy]

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
    "configuration", "invalid-request", "transport", "problem", "protocol",
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
    "request.limit-out-of-range",
    "request.method-not-allowed",
    "request.not-found",
    "request.unprocessable",
    "request.unsupported-media-type",
    "review.distinct-approver-required", "review.initiator-excluded",
    "review.initiator-required",
    "review.query-too-broad",
    "review.policy-mismatch",
    "review.result-expired",
    "review.submission-conflict",
    "review.task-not-held",
    "runtime.failure",
    "service.unavailable",
    "source-profile.not-applicable",
    "source-profile.required",
    "source.bad-gateway",
    "source.version-mismatch",
    "source.version-unavailable",
]
# A newer Casework service can answer a code this release does not name, so the
# attribute widens the closed catalogue the way the Node typings do.
CaseworkProblemCode: TypeAlias = KnownCaseworkProblemCode | str
CaseworkProtocolFailure: TypeAlias = Literal[
    "header-bounds", "trace-context", "media-type", "body", "problem", "status", "protocol",
]
ReviewValidationReason: TypeAlias = Literal[
    "policy-not-allowed",
    "reference-invalid",
    "object-required",
    "maximum-bytes-exceeded",
    "maximum-depth-exceeded",
    "schema-mismatch",
    "outcome-not-declared",
    "reason-required",
    "text-invalid",
    "result-not-declared",
    "result-required",
    "field-not-declared",
    "constraint-invalid",
    "constraint-violated",
    "public-reason-required",
    "public-reason-not-declared",
    "approval-outcome-differs",
]

class ValidationDetail(TypedDict):
    path: str
    reason: ReviewValidationReason
    # The outcome identifiers the review policy declares for the requested
    # settlement when an outcome is refused; empty otherwise.
    allowed: list[str]

class CaseworkClientError(Exception):
    kind: CaseworkErrorKind
    code: CaseworkProblemCode | None
    detail: str | None
    status: SafeInteger | None
    trace_id: str | None
    validation: ValidationDetail | None
    transport_kind: str | None
    protocol_failure: CaseworkProtocolFailure | None
    # Whether the request may have taken effect although this error was
    # raised: a timeout or broken exchange after sending, an unusable answer,
    # or a 5xx. When True, recover a keyed request by sending it again under
    # the same idempotency key; a new key could apply it twice. False for a
    # configuration or request defect, a connection never established, and
    # every 4xx refusal. It is False for `410 idempotency.expired` too, but
    # there an earlier attempt under the key committed and only its stored
    # response was erased by retention: reconcile the original operation, by
    # reading the item, review request, or directory, before choosing a new
    # key.
    outcome_unknown: bool

ContentDigest: TypeAlias = str
ReviewRequestLifecycle: TypeAlias = Literal["reviewing", "approved", "rejected", "changes-requested", "answered", "cancelled", "superseded"]
ReviewResultStatus: TypeAlias = Literal["approved", "rejected", "changes-requested", "answered", "cancelled", "superseded"]
ReviewHistoryAudience: TypeAlias = Literal["reviewers", "requester"]

class SubjectBinding(TypedDict):
    source: str
    type: str
    id: str
    version: str
    digest: ContentDigest
class PolicyBinding(TypedDict):
    id: str
    version: str
    digest: ContentDigest
class PolicyIdSelection(TypedDict):
    id: str
    version: NotRequired[Never]
    digest: NotRequired[Never]
# A strict selector supplies the complete version/digest pair.
PolicySelection: TypeAlias = PolicyIdSelection | PolicyBinding
class HumanIdentity(TypedDict):
    issuer: str
    subject: str
class SourceContextBinding(TypedDict):
    reference: str
class ReviewSubmittedCreateContext(TypedDict):
    mode: Literal["submitted"]
    snapshot: JsonObject
class ReviewSourceCreateContext(TypedDict):
    mode: Literal["current-source"]
    binding: SourceContextBinding
ReviewContext: TypeAlias = ReviewSubmittedCreateContext | ReviewSourceCreateContext
class _ReviewCreateRequestOptional(TypedDict, total=False):
    initiator: HumanIdentity
    resultConstraints: JsonObject | None

class ReviewCreateRequest(_ReviewCreateRequestOptional):
    policy: PolicySelection
    subject: SubjectBinding
    requesterReference: str
    context: ReviewContext
class ReviewRequestAccepted(TypedDict):
    requestId: Uuid
    subject: SubjectBinding
    policy: PolicyBinding
    submissionDigest: ContentDigest
class _ReviewRequestViewOptional(TypedDict, total=False):
    activeStage: str
class ReviewRequestView(ReviewRequestAccepted, _ReviewRequestViewOptional):
    requesterReference: str
    lifecycle: ReviewRequestLifecycle
    createdAt: str
    updatedAt: str
class _ReviewResultOptional(TypedDict, total=False):
    outcome: str
    publicReason: str
    result: JsonObject

class ReviewResult(ReviewRequestAccepted, _ReviewResultOptional):
    resultId: Uuid
    status: ReviewResultStatus
    completedAt: str
    availableUntil: str
class ReviewResultAvailable(TypedDict):
    kind: Literal["available"]
    value: ReviewResult
    trace_id: str
class ReviewResultPending(TypedDict):
    kind: Literal["pending"]
    value: None
    trace_id: str
class ReviewResultConcealedOrUnknown(TypedDict):
    kind: Literal["concealed_or_unknown"]
    value: None
    trace_id: str
class ReviewResultExpired(TypedDict):
    kind: Literal["expired"]
    value: None
    trace_id: str
ReviewResultOutcome: TypeAlias = ReviewResultAvailable | ReviewResultPending | ReviewResultConcealedOrUnknown | ReviewResultExpired
class ReviewPageQuery(TypedDict, total=False):
    cursor: Uuid
    limit: SafeInteger
ReviewTaskOwnership: TypeAlias = Literal["assigned-to-me", "unclaimed"]
ReviewTaskSort: TypeAlias = Literal["due", "subject", "reference"]
class ReviewStaffingQuery(ReviewPageQuery, total=False):
    subjectSource: str
    subjectType: str
    subjectId: str
    subjectVersion: str
    subjectDigest: ContentDigest
    reference: str
    sort: ReviewTaskSort
    queue: str
    ownership: ReviewTaskOwnership
class SupervisoryReviewTaskQuery(ReviewPageQuery, total=False):
    queue: str
    requestId: Uuid
class OwnReviewDecisionQuery(ReviewPageQuery, total=False):
    queue: str

class ReviewResultFeedEntry(TypedDict):
    eventId: Uuid
    requestId: Uuid
    resultId: Uuid
    completedAt: str
class _ReviewResultFeedPageOptional(TypedDict, total=False):
    nextCursor: Uuid
class ReviewResultFeedPage(_ReviewResultFeedPageOptional):
    items: list[ReviewResultFeedEntry]
class ReviewCancelRequest(TypedDict):
    subject: SubjectBinding
    reason: str
class ReviewCancelledResponse(TypedDict):
    outcome: Literal["cancelled"]
    result: ReviewResult
class ReviewAlreadyTerminalResponse(TypedDict):
    outcome: Literal["already-terminal"]
    result: ReviewResult
ReviewCancelResponse: TypeAlias = ReviewCancelledResponse | ReviewAlreadyTerminalResponse
class ReviewHeldTaskStateValue(TypedDict):
    holder: IssuerPrincipal
class ReviewHeldTaskState(TypedDict):
    held: ReviewHeldTaskStateValue
ReviewTaskState: TypeAlias = Literal["open", "decided"] | ReviewHeldTaskState
ReviewDecisionType: TypeAlias = Literal["approve", "reject", "changes-requested", "answer"]
class _ReviewDecisionReceiptOptional(TypedDict, total=False):
    outcomeLabel: str
class ReviewDecisionReceipt(_ReviewDecisionReceiptOptional):
    policy: PolicyBinding
    decision: ReviewDecisionType
    outcome: str
    decidedAt: str
class OwnReviewDecision(TypedDict):
    taskId: Uuid
    requestId: Uuid
    queue: str
    requesterReference: str
    decisionReceipt: ReviewDecisionReceipt
class _OwnReviewDecisionPageOptional(TypedDict, total=False):
    nextCursor: Uuid
class OwnReviewDecisionPage(_OwnReviewDecisionPageOptional):
    items: list[OwnReviewDecision]
    status: PageStatus
class _ReviewTaskOptional(TypedDict, total=False):
    staffingDiagnostic: StaffingDiagnostic
    deadlineAt: str | None
    displayReference: str
    decidedByCaller: bool
    decisionReceipt: ReviewDecisionReceipt
class ReviewTask(_ReviewTaskOptional):
    subject: SubjectBinding
    requesterReference: str
    createdAt: str
    taskId: Uuid
    requestId: Uuid
    stageIndex: SafeInteger
    stageId: str
    queue: str
    revision: SafeInteger
    eligibleProfiles: list[str]
    state: ReviewTaskState
class _ReviewTaskPageOptional(TypedDict, total=False):
    nextCursor: Uuid
class ReviewTaskPage(_ReviewTaskPageOptional):
    items: list[ReviewTask]
    status: PageStatus
class _SupervisoryReviewTaskOptional(TypedDict, total=False):
    staffingDiagnostic: StaffingDiagnostic
    accountabilityEventId: Uuid
SupervisoryReviewTaskState: TypeAlias = Literal["open", "held", "decided"]
class SupervisoryReviewTask(_SupervisoryReviewTaskOptional):
    taskId: Uuid
    requestId: Uuid
    queue: str
    revision: SafeInteger
    state: SupervisoryReviewTaskState
class _SupervisoryReviewTaskPageOptional(TypedDict, total=False):
    nextCursor: Uuid
class SupervisoryReviewTaskPage(_SupervisoryReviewTaskPageOptional):
    items: list[SupervisoryReviewTask]
    status: PageStatus
ReviewSourceBindingStatus: TypeAlias = Literal["current", "binding-changed"]
class _ReviewSourceProjectionOptional(TypedDict, total=False):
    displayReference: str
class ReviewSourceProjection(_ReviewSourceProjectionOptional):
    binding: SubjectBinding
    display: dict[str, JsonValue]
class ReviewSubmittedContext(TypedDict):
    mode: Literal["submitted"]
    snapshot: JsonObject
class _ReviewSourceContextOptional(TypedDict, total=False):
    projection: ReviewSourceProjection
class ReviewSourceContext(_ReviewSourceContextOptional):
    mode: Literal["current-source"]
    reference: str
    bindingStatus: ReviewSourceBindingStatus
ReviewTaskContextData: TypeAlias = ReviewSubmittedContext | ReviewSourceContext
class _ReviewTaskContextOptional(TypedDict, total=False):
    resultConstraints: JsonObject
class ReviewTaskContext(_ReviewTaskContextOptional):
    taskId: Uuid
    requestId: Uuid
    subject: SubjectBinding
    requesterReference: str
    policy: PolicyBinding
    policyClosure: ReviewPolicyClosure
    context: ReviewTaskContextData
class ReviewSubjectClockCorrelation(TypedDict):
    scope: Literal["subject"]
    source: str
    subjectType: str
    id: str
class ReviewActivityClockCorrelation(TypedDict):
    scope: Literal["activity"]
    taskId: Uuid
    stageId: str
ReviewClockCorrelation: TypeAlias = ReviewSubjectClockCorrelation | ReviewActivityClockCorrelation
class _ReviewClockOccurrenceOptional(TypedDict, total=False):
    dueAt: str
    atRiskAt: str
    completedAt: str
class ReviewClockOccurrence(_ReviewClockOccurrenceOptional):
    clockOccurrenceId: Uuid
    clockId: str
    requestId: Uuid
    correlation: ReviewClockCorrelation
    state: Literal["running", "completed", "cancelled", "source-facts-missing"]
    policyDigest: ContentDigest
    anchorAt: str
class ReviewTaskDraftInput(TypedDict):
    body: JsonValue
class ReviewTaskDraft(TypedDict):
    taskId: Uuid
    author: IssuerPrincipal
    body: JsonValue
    revision: SafeInteger
    updatedAt: str
class ReviewApproveDecision(TypedDict):
    type: Literal["approve"]
    outcome: str
    publicReason: NotRequired[str | None]
class _ReviewOutcomeDecisionOptional(TypedDict, total=False):
    reason: str | None
    publicReason: str | None
    result: JsonObject | None
class ReviewRejectDecision(_ReviewOutcomeDecisionOptional):
    type: Literal["reject"]
    outcome: str
class ReviewChangesRequestedDecision(_ReviewOutcomeDecisionOptional):
    type: Literal["changes-requested"]
    outcome: str
class ReviewAnswerDecision(_ReviewOutcomeDecisionOptional):
    type: Literal["answer"]
    outcome: str
DecisionKind: TypeAlias = ReviewApproveDecision | ReviewRejectDecision | ReviewChangesRequestedDecision | ReviewAnswerDecision
class Decision(TypedDict):
    taskId: Uuid
    requestId: Uuid
    stageId: str
    reviewer: IssuerPrincipal
    profileId: str
    decision: DecisionKind
class ReviewTaskDecisionRequest(TypedDict):
    decision: DecisionKind
class ReviewNoteRequest(TypedDict):
    audience: ReviewHistoryAudience
    note: str
class _ReviewHistoryEntryOptional(TypedDict, total=False):
    taskId: Uuid
    actorRef: str
class ReviewHistoryEntry(_ReviewHistoryEntryOptional):
    eventId: Uuid
    requestId: Uuid
    kind: str
    detail: JsonValue
    occurredAt: str
class _ReviewHistoryPageOptional(TypedDict, total=False):
    nextCursor: Uuid
class ReviewHistoryPage(_ReviewHistoryPageOptional):
    items: list[ReviewHistoryEntry]
class _ReviewAccountabilityRecordOptional(TypedDict, total=False):
    privateReason: str
    resultDigest: str
    decisionReceipt: ReviewDecisionReceipt
class ReviewAccountabilityRecord(_ReviewAccountabilityRecordOptional):
    eventId: Uuid
    requestId: Uuid
    taskId: Uuid
    actorRef: str
    actor: IssuerPrincipal
    profileId: str
    decision: str
    occurredAt: str
    retainedUntil: str
class ReviewContextContract(TypedDict):
    id: str
    revision: ContentDigest
    schemaDigest: ContentDigest
class SubmittedContextPolicy(TypedDict):
    mode: Literal["submitted"]
class CurrentSourceContextPolicy(TypedDict):
    mode: Literal["current-source"]
    provider: str
    contract: ReviewContextContract
ReviewContextPolicy: TypeAlias = SubmittedContextPolicy | CurrentSourceContextPolicy
ReviewContextCapability: TypeAlias = Literal["human-display", "service-status", "task-grant-context", "routing-context"]
class ReviewContextProviderPolicy(TypedDict):
    id: str
    capabilities: list[ReviewContextCapability]
    sourceNamespace: str
    deploymentRef: str
    serviceProfiles: NotRequired[dict[ReviewContextCapability, str]]
class ReviewStagePolicy(TypedDict):
    id: str
    queue: str
    decidingProfiles: list[str]
    requiredApprovals: SafeInteger
    excludeInitiator: NotRequired[bool]
    excludePreviousStageReviewers: NotRequired[bool]
class ReviewRetentionPolicy(TypedDict):
    terminalRetentionDays: SafeInteger
    accountabilityRetentionDays: SafeInteger
class ReviewOutcomePolicy(TypedDict):
    id: str
    label: str
    settlement: Literal["approved", "rejected", "changes-requested", "answered"]
    reasonRequired: bool
    publicReason: Literal["required", "optional", "none"]
    resultRequired: NotRequired[bool]
class _ReviewPolicyOptional(TypedDict, total=False):
    routing: list[RoutingRule]
    clocks: list[str]
    resultSchema: JsonValue
    outcomes: list[ReviewOutcomePolicy]
class ReviewPolicy(_ReviewPolicyOptional):
    id: str
    version: str
    purpose: Literal["approval", "answer"]
    context: ReviewContextPolicy
    stages: list[ReviewStagePolicy]
    retention: ReviewRetentionPolicy
    displaySchema: JsonValue
class ReviewPolicyClosure(_ReviewPolicyOptional):
    identity: PolicyBinding
    purpose: Literal["approval", "answer"]
    context: ReviewContextPolicy
    stages: list[ReviewStagePolicy]
    retention: ReviewRetentionPolicy
    displaySchema: JsonValue
    dependencies: JsonObject
ReviewCaseloadMoveRequest = TypedDict("ReviewCaseloadMoveRequest", {"from": IssuerPrincipal, "to": IssuerPrincipal, "reason": str, "queue": NotRequired[str]})
class ReviewCaseloadTask(TypedDict):
    taskId: Uuid
    revision: SafeInteger
class ReviewCaseloadPreview(TypedDict):
    previewId: Uuid
    directoryRevision: SafeInteger
    tasks: list[ReviewCaseloadTask]
    expiresAt: str
class ReviewCaseloadApplyRequest(TypedDict):
    previewId: Uuid
class ReviewCaseloadResult(TypedDict):
    moved: list[ReviewCaseloadTask]
class ReviewClockRecomputeRequest(TypedDict):
    taskIds: list[Uuid]
class ReviewClockRecomputeTask(TypedDict):
    taskId: Uuid
    revision: SafeInteger
    deadlineAt: str | None
class ReviewClockRecomputePreview(TypedDict):
    previewId: Uuid
    directoryRevision: SafeInteger
    tasks: list[ReviewClockRecomputeTask]
    expiresAt: str
class ReviewClockRecomputeApplyRequest(TypedDict):
    previewId: Uuid
class ReviewClockRecomputeResult(TypedDict):
    tasks: list[ReviewClockRecomputeTask]

def submission_digest(producer: str, source_namespace: str, request: ReviewCreateRequest) -> ContentDigest: ...

class CaseworkClient:
    def __init__(self, base_url: str, request_timeout_seconds: float | None = None, connect_timeout_seconds: float | None = None, max_response_bytes: int | None = None, user_agent: str | None = None, trusted_root_certificates: bytes | None = None, max_mutation_retries: int | None = None) -> None: ...
    def description(self, token: str, profile: str) -> Complete[Description]: ...
    def create_or_recover_review_request(self, token: str, profile: str, idempotency_key: str, request: ReviewCreateRequest, expected_submission_digest: ContentDigest) -> Complete[ReviewRequestAccepted]: ...
    def review_request(self, token: str, profile: str, request_id: Uuid) -> Complete[ReviewRequestView]: ...
    def review_result(self, token: str, profile: str, accepted: ReviewRequestAccepted) -> ReviewResultOutcome: ...
    def review_results(self, token: str, profile: str, query: ReviewPageQuery | None = None) -> Complete[ReviewResultFeedPage]: ...
    def cancel_review_request(self, token: str, profile: str, accepted: ReviewRequestAccepted, idempotency_key: str, request: ReviewCancelRequest) -> Complete[ReviewCancelResponse]: ...
    def review_policies(self, token: str, profile: str) -> Complete[list[ReviewPolicyClosure]]: ...
    def review_policy(self, token: str, profile: str, policy_id: str) -> Complete[ReviewPolicyClosure]: ...
    def next_review_task(self, token: str, profile: str, query: ReviewStaffingQuery | None = None, source_profile: str | None = None) -> Complete[ReviewTask | None]: ...
    def review_task_holdings(self, token: str, profile: str, query: ReviewStaffingQuery | None = None, source_profile: str | None = None) -> Complete[ReviewTaskPage]: ...
    def review_tasks(self, token: str, profile: str, query: ReviewStaffingQuery | None = None, source_profile: str | None = None) -> Complete[ReviewTaskPage]: ...
    def supervisory_review_tasks(self, token: str, profile: str, query: SupervisoryReviewTaskQuery | None = None, source_profile: str | None = None) -> Complete[SupervisoryReviewTaskPage]: ...
    def own_review_decisions(self, token: str, profile: str, query: OwnReviewDecisionQuery | None = None, source_profile: str | None = None) -> Complete[OwnReviewDecisionPage]: ...
    def review_task(self, token: str, profile: str, task_id: Uuid, source_profile: str | None = None) -> Complete[ReviewTask]: ...
    def review_task_context(self, token: str, profile: str, task_id: Uuid, source_profile: str | None = None) -> Complete[ReviewTaskContext]: ...
    def preview_review_task_templates(self, token: str, profile: str, task_id: Uuid, *, source_profile: str | None = None) -> Complete[TaskTemplatePreviews]: ...
    def list_review_task_grants(self, token: str, profile: str, task_id: Uuid, *, source_profile: str | None = None) -> Complete[TaskGrantList]: ...
    def approve_review_task_grant(self, token: str, profile: str, task_id: Uuid, expected_revision: SafeInteger, idempotency_key: str, approval: TaskApprovalRequest, source_profile: str | None = None) -> Complete[TaskGrantView]: ...
    def revoke_review_task_grant(self, token: str, profile: str, task_id: Uuid, grant_id: str) -> Complete[TaskGrantRevocation]: ...
    def claim_review_task(self, token: str, profile: str, task_id: Uuid, expected_revision: SafeInteger, idempotency_key: str, source_profile: str | None = None) -> Complete[ReviewTask]: ...
    def release_review_task(self, token: str, profile: str, task_id: Uuid, expected_revision: SafeInteger, idempotency_key: str) -> Complete[ReviewTask]: ...
    def assign_review_task(self, token: str, profile: str, task_id: Uuid, expected_revision: SafeInteger, idempotency_key: str, request: AssignmentRequest, source_profile: str | None = None) -> Complete[ReviewTask]: ...
    def delegate_review_task(self, token: str, profile: str, task_id: Uuid, expected_revision: SafeInteger, idempotency_key: str, request: DelegateRequest, source_profile: str | None = None) -> Complete[ReviewTask]: ...
    def review_task_draft(self, token: str, profile: str, task_id: Uuid, source_profile: str | None = None) -> Complete[ReviewTaskDraft | None]: ...
    def save_review_task_draft(self, token: str, profile: str, task_id: Uuid, expected_revision: SafeInteger, idempotency_key: str, draft: ReviewTaskDraftInput, source_profile: str | None = None) -> Complete[ReviewTaskDraft]: ...
    def delete_review_task_draft(self, token: str, profile: str, task_id: Uuid, expected_revision: SafeInteger, idempotency_key: str, source_profile: str | None = None) -> Complete[None]: ...
    def decide_review_task(self, token: str, profile: str, task_id: Uuid, expected_revision: SafeInteger, idempotency_key: str, decision: ReviewTaskDecisionRequest, source_profile: str | None = None) -> Complete[None]: ...
    def review_history(self, token: str, profile: str, request_id: Uuid, query: ReviewPageQuery | None = None, source_profile: str | None = None) -> Complete[ReviewHistoryPage]: ...
    def add_review_note(self, token: str, profile: str, request_id: Uuid, idempotency_key: str, note: ReviewNoteRequest, source_profile: str | None = None) -> Complete[ReviewHistoryEntry]: ...
    def review_clocks(self, token: str, profile: str, request_id: Uuid, source_profile: str | None = None) -> Complete[list[ReviewClockOccurrence]]: ...
    def review_accountability(self, token: str, profile: str, event_id: Uuid) -> Complete[ReviewAccountabilityRecord]: ...
    def task_assertion(self, token: str, grant_id: str) -> Complete[TaskAssertionResponse]: ...
    def task_assertion_endpoint(self, grant_id: str) -> str: ...
    def task_grant_status(self, token: str, grant_id: str) -> Complete[TaskGrantStatus]: ...
    def directory(self, token: str, profile: str) -> Complete[DirectoryResponse]: ...
    def directory_targets(self, token: str, profile: str, query: DirectoryTargetsQuery) -> Complete[DirectoryTargetPage]: ...
    def bootstrap_directory(self, token: str, profile: str, expected_revision: int, idempotency_key: str, request: BootstrapDirectoryRequest) -> Complete[DirectoryResponse]: ...
    def update_directory_team(self, token: str, profile: str, team_id: str, expected_directory_revision: int, idempotency_key: str, request: DirectoryTeamUpdateRequest) -> Complete[DirectoryResponse]: ...
    def absences(self, token: str, profile: str, source_profile: str | None = None, query: AbsencesQuery | None = None) -> Complete[AbsenceList]: ...
    def create_absence(self, token: str, profile: str, expected_directory_revision: int, idempotency_key: str, absence: AbsenceInput, source_profile: str | None = None) -> Complete[AbsenceRecord]: ...
    def update_absence(self, token: str, profile: str, absence_id: str, expected_directory_revision: int, idempotency_key: str, absence: AbsenceInput, source_profile: str | None = None) -> Complete[AbsenceRecord]: ...
    def delete_absence(self, token: str, profile: str, absence_id: str, expected_directory_revision: int, idempotency_key: str, source_profile: str | None = None) -> Complete[None]: ...
    def preview_caseload_move(self, token: str, profile: str, movement: ReviewCaseloadMoveRequest, source_profile: str | None = None) -> Complete[ReviewCaseloadPreview]: ...
    def apply_caseload_move(self, token: str, profile: str, idempotency_key: str, request: ReviewCaseloadApplyRequest, source_profile: str | None = None) -> Complete[ReviewCaseloadResult]: ...
    def holiday_revision(self, token: str, profile: str, holiday_set: str, revision: int) -> Complete[HolidaySetDocument]: ...
    def create_holiday_revision(self, token: str, profile: str, idempotency_key: str, request: HolidaySetRevisionInput) -> Complete[HolidaySetDocument]: ...
    def preview_clock_recompute(self, token: str, profile: str, request: ReviewClockRecomputeRequest) -> Complete[ReviewClockRecomputePreview]: ...
    def apply_clock_recompute(self, token: str, profile: str, idempotency_key: str, request: ReviewClockRecomputeApplyRequest) -> Complete[ReviewClockRecomputeResult]: ...

__version__: str
