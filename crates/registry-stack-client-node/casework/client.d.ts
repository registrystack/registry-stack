/** An integer for which `Number.isSafeInteger` is true. */
export type SafeInteger = number
/** A string validated as an RFC 9562 UUID by the native binding. */
export type Uuid = string
export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }
export type JsonObject = { readonly [key: string]: JsonValue }

export interface CaseworkClientConfig {
  baseUrl: string
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  maxResponseBytes?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
  /**
   * How many times an idempotency-keyed mutation whose outcome is unknown is
   * resent, identically and under the same key, before its error is
   * returned: a whole number from 0 to 2, default 2; 0 sends it once. Reads,
   * unkeyed operations, and review request create and cancel are never
   * resent. Any other value is a `configuration` error.
   */
  maxMutationRetries?: SafeInteger | null
}

export type PageStatus = 'complete' | 'budget-exhausted' | 'source-unavailable'
export interface IssuerPrincipal { issuer: string; subject: string }
export type TaskGrantBounds = { type: 'evidence'; requirement: string } | { type: 'breg'; permissions: ReadonlyArray<TaskPermission> } | { type: 'scheduling'; permissions: ReadonlyArray<SchedulingTaskPermission> }
export interface TaskPermission { collection: string; operations: ReadonlyArray<string> }
export interface SchedulingTaskPermission { service: string; location: string; actions: ReadonlyArray<string> }
export interface EvidenceRequesterContext { requesterTags: ReadonlyArray<string>; audience: string }
export interface TaskApprovalRequest { templateId: string; templateVersion: string }
/** Deferred authority keeps its approved deadline; execution credentials stay short-lived. */
export type TaskAuthorizationMode = 'immediate' | 'deferred'
export interface TaskTemplatePreview {
  id: string; version: string; label: string; agent: IssuerPrincipal; client: string; resource: string; scopes: ReadonlyArray<string>; purpose: string
  evidenceContext?: EvidenceRequesterContext; bounds: TaskGrantBounds; subjects: { readonly [key: string]: Exclude<JsonScalar, null> }; lifetimeSeconds: SafeInteger
  /** Omitted for the existing immediate mode. */
  authorizationMode?: TaskAuthorizationMode
}
export interface TaskTemplatePreviews { taskRevision: SafeInteger; templates: ReadonlyArray<TaskTemplatePreview> }
/** Grant metadata deliberately excludes stored subject values. */
export interface TaskGrantView {
  id: string; templateId: string; templateVersion: string; agent: IssuerPrincipal; client: string; resource: string; scopes: ReadonlyArray<string>; purpose: string
  evidenceContext?: EvidenceRequesterContext; bounds: TaskGrantBounds; expiresAt: SafeInteger; invalidated: boolean
  /** Omitted for the existing immediate mode. */
  authorizationMode?: TaskAuthorizationMode
}
export interface TaskGrantList { grants: ReadonlyArray<TaskGrantView> }
export interface TaskGrantRevocation { id: string; invalidated: boolean }
/** A short-lived credential. Do not persist or log the assertion. */
export interface TaskAssertionResponse { assertion: string; expiresAt: SafeInteger; grantExpiresAt: SafeInteger }
export interface TaskGrantStatusDetails {
  grantId: string; sourceIssuer: string; principal: string; client: string; resource: string; purpose: string
  bounds: TaskGrantBounds; subjects: { readonly [key: string]: Exclude<JsonScalar, null> }; expiresAt: SafeInteger
}
export interface TaskGrantStatus { active: boolean; grant?: TaskGrantStatusDetails }

export interface DirectoryMember { issuer: string; subject: string; displayName?: string | null }
export interface Page<T> { items: ReadonlyArray<T>; nextCursor?: string; status: PageStatus }
export type DirectoryTargetPurpose = 'assignment' | 'absence-person' | 'absence-cover'
export type DirectoryTargetsQuery = {
  cursor?: string
  limit?: SafeInteger
} & (
  | { purpose: 'assignment'; queue: string; personIssuer?: never; personSubject?: never }
  | { purpose: 'absence-person'; queue?: never; personIssuer?: never; personSubject?: never }
  | { purpose: 'absence-cover'; queue?: never; personIssuer: string; personSubject: string }
)
export type DirectoryTargetPage = Page<DirectoryMember>
/** The Registry-Source-Profile header selects the source profile; the body is empty. */
export interface QueueRecord { id: string; label: string }
export type RoutingPredicate = { equals: JsonValue } | { oneOf: ReadonlyArray<JsonValue> }
export interface RoutingCondition { activity?: 'review' | 'apply'; stage?: string; fields?: Readonly<Record<string, RoutingPredicate>> }
export interface RoutingRule { id: string; because: string; when: RoutingCondition; queue: string }
export type WorkingWeekday = 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday'
export interface CalendarPolicy { id: string; timezone: string; workingWeekdays: ReadonlyArray<WorkingWeekday>; holidaySet: string }
export interface ClockReminder { id: string; workingDaysBefore: SafeInteger }
export interface ClockStep { id: string; because: string; at: 'due'; action: { reassign: { queue: string } } }
export type ClockPolicy = {
  type: 'subject'; id: string; anchor: 'request-accepted-at'; completeOn: 'result-terminal'; after: { elapsed: string }
} | {
  type: 'activity'; id: string; anchor: 'stage-entered-at'; calendar: string; after: { workingDays: SafeInteger }; dueTime: string;
  atRisk?: { workingDaysBefore: SafeInteger }; reminders?: ReadonlyArray<ClockReminder>; steps?: ReadonlyArray<ClockStep>
}
export interface Description {
  projectId: string
  policyVersion: string
  queues: ReadonlyArray<QueueRecord>
  reviewPolicies: ReadonlyArray<ReviewPolicy>
  contextProviders: ReadonlyArray<ReviewContextProviderPolicy>
  calendars: ReadonlyArray<CalendarPolicy>
  clocks: ReadonlyArray<ClockPolicy>
}
export interface TeamRecord {
  id: string
  members: ReadonlyArray<DirectoryMember>
  supervisors: ReadonlyArray<DirectoryMember>
  servedQueues: ReadonlyArray<string>
  revision: SafeInteger
}
export interface DirectoryTeamUpdateRequest { staff: ReadonlyArray<DirectoryMember>; supervisors: ReadonlyArray<DirectoryMember>; servedQueues: ReadonlyArray<string> }
export interface DirectoryResponse { revision: SafeInteger; teams: ReadonlyArray<TeamRecord> }
export interface AbsenceInput { person: IssuerPrincipal; from: string; until: string; cover: IssuerPrincipal }
export interface AbsenceRecord extends AbsenceInput { absenceId: string; revision: SafeInteger }
export interface AbsencesQuery { cursor?: string; limit?: SafeInteger }
export interface AbsenceList { directoryRevision: SafeInteger; items: ReadonlyArray<AbsenceRecord>; nextCursor?: string }
export interface AssignmentContext { owner?: IssuerPrincipal; assignedBy?: IssuerPrincipal; absenceIds: ReadonlyArray<string>; staffingDiagnostic?: 'no-cover-available' }
export interface AssignmentRequest { assignee: IssuerPrincipal; reason?: string }
export interface DelegateRequest { delegate: IssuerPrincipal; reason?: string }
export interface ReviewCaseloadMoveRequest { from: IssuerPrincipal; to: IssuerPrincipal; queue?: string; reason: string }
export interface ReviewCaseloadTask { taskId: Uuid; revision: SafeInteger }
export interface ReviewCaseloadPreview { previewId: Uuid; directoryRevision: SafeInteger; tasks: ReadonlyArray<ReviewCaseloadTask>; expiresAt: string }
export interface ReviewCaseloadApplyRequest { previewId: Uuid }
export interface ReviewCaseloadResult { moved: ReadonlyArray<ReviewCaseloadTask> }
export interface BootstrapDirectoryRequest {
  teamId: string
  staff: ReadonlyArray<IssuerPrincipal>
  supervisors: ReadonlyArray<IssuerPrincipal>
  queueId: string
}
export interface CaseworkOutcome<T> { kind: 'complete'; value: T; traceId: string }

export type KnownCaseworkProblemCode =
  | 'absence.cover-cycle'
  | 'absence.invalid-period'
  | 'absence.overlap'
  | 'absence.self-cover'
  | 'authentication.refused'
  | 'clock.recompute-preview-expired' | 'cursor.expired'
  | 'cursor.invalid'
  | 'idempotency.expired'
  | 'idempotency.key-reused'
  | 'operation.not-authorized'
  | 'precondition.failed'
  | 'precondition.required'
  | 'profile.not-authorized'
  | 'profile.not-human'
  | 'request.body-too-large'
  | 'request.invalid'
  | 'request.limit-out-of-range'
  | 'request.method-not-allowed'
  | 'request.not-found'
  | 'request.unprocessable'
  | 'request.unsupported-media-type'
  | 'review.initiator-excluded'
  | 'review.initiator-required'
  | 'review.query-too-broad'
  | 'review.policy-mismatch'
  | 'review.result-expired'
  | 'review.submission-conflict'
  | 'review.task-not-held'
  | 'runtime.failure'
  | 'service.unavailable'
  | 'source-profile.not-applicable'
  | 'source-profile.required'
  | 'source.bad-gateway'
export type CaseworkProblemCode = KnownCaseworkProblemCode | (string & {})
export type CaseworkProtocolFailure = 'header-bounds' | 'trace-context' | 'media-type' | 'body' | 'problem' | 'status' | 'protocol'

export class CaseworkClientError extends Error {
  readonly kind: 'configuration' | 'invalid-request' | 'transport' | 'problem' | 'protocol'
  /**
   * Whether the request may have taken effect although this error was
   * raised: a timeout or broken exchange after sending, an unusable answer,
   * or a 5xx. When true, recover a keyed request by sending it again under
   * the same idempotency key; a new key could apply it twice. False for a
   * configuration or request defect, a connection never established, and
   * every 4xx refusal. It is false for `410 idempotency.expired` too, but
   * there an earlier attempt under the key committed and only its stored
   * response was erased by retention: reconcile the original operation, by
   * reading the item, review request, or directory, before choosing a new
   * key.
   */
  readonly outcomeUnknown: boolean
  readonly code?: CaseworkProblemCode
  readonly detail?: string
  readonly status?: SafeInteger
  readonly traceId?: string
  readonly validation?: {
    readonly path: string
    readonly reason: 'policy-not-allowed' | 'reference-invalid' | 'object-required' | 'maximum-bytes-exceeded' | 'maximum-depth-exceeded' | 'schema-mismatch' | 'outcome-not-declared' | 'reason-required' | 'text-invalid' | 'result-not-declared' | 'result-required' | 'field-not-declared' | 'constraint-invalid' | 'constraint-violated'
  }
  readonly transportKind?: string
  readonly protocolFailure?: CaseworkProtocolFailure
}

export type ClockRuntimeState = 'running' | 'paused' | 'completed' | 'cancelled' | 'verification-pending' | 'source-facts-missing'
export type ClockNextEffect =
  | { kind: 'reminder'; id: string; at: string }
  | { kind: 'reassign'; id: string; at: string; because: string; queueId: string }
export interface HolidaySetDocument { holidaySet: string; revision: SafeInteger; dates: ReadonlyArray<string> }
export interface HolidaySetRevisionInput { document: HolidaySetDocument }
export interface ReviewClockRecomputeRequest { taskIds: ReadonlyArray<Uuid> }
export interface ReviewClockRecomputeTask { taskId: Uuid; revision: SafeInteger; deadlineAt?: string }
export interface ReviewClockRecomputePreview { previewId: Uuid; directoryRevision: SafeInteger; tasks: ReadonlyArray<ReviewClockRecomputeTask>; expiresAt: string }
export interface ReviewClockRecomputeApplyRequest { previewId: Uuid }
export interface ReviewClockRecomputeResult { tasks: ReadonlyArray<ReviewClockRecomputeTask> }

export type ContentDigest = `sha256:${string}`
export interface SubjectBinding { source: string; type: string; id: string; version: string; digest: ContentDigest }
export interface PolicyBinding { id: string; version: string; digest: ContentDigest }
export interface HumanIdentity { issuer: string; subject: string }
export type ReviewContext =
  | { mode: 'submitted'; snapshot: Readonly<Record<string, JsonValue>> }
  | { mode: 'current-source'; binding: { reference: string } }
export interface ReviewCreateRequest {
  policy: PolicyBinding
  subject: SubjectBinding
  requesterReference: string
  initiator?: HumanIdentity
  context: ReviewContext
  resultConstraints?: JsonObject | null
}
export interface ReviewRequestAccepted {
  requestId: Uuid
  subject: SubjectBinding
  policy: PolicyBinding
  submissionDigest: ContentDigest
}
export type ReviewRequestLifecycle = 'reviewing' | 'approved' | 'rejected' | 'changes-requested' | 'answered' | 'cancelled' | 'superseded'
export interface ReviewRequestView extends ReviewRequestAccepted {
  requesterReference: string
  lifecycle: ReviewRequestLifecycle
  activeStage?: string
  createdAt: string
  updatedAt: string
}
export type ReviewResultStatus = 'approved' | 'rejected' | 'changes-requested' | 'answered' | 'cancelled' | 'superseded'
export interface ReviewResult extends ReviewRequestAccepted {
  resultId: Uuid
  status: ReviewResultStatus
  outcome?: string
  result?: JsonObject
  completedAt: string
  availableUntil: string
}
export type ReviewResultOutcome =
  | { kind: 'available'; value: ReviewResult; traceId: string }
  | { kind: 'pending' | 'concealed_or_unknown' | 'expired'; value: null; traceId: string }
export interface ReviewResultFeedEntry { eventId: Uuid; requestId: Uuid; resultId: Uuid; completedAt: string }
export interface ReviewResultFeedPage { items: ReadonlyArray<ReviewResultFeedEntry>; nextCursor?: Uuid }
export interface ReviewCancelRequest { subject: SubjectBinding; reason: string }
export type ReviewCancelResponse =
  | { outcome: 'cancelled'; result: ReviewResult }
  | { outcome: 'already-terminal'; result: ReviewResult }
export interface ReviewPageQuery { cursor?: Uuid; limit?: SafeInteger }
export type ReviewTaskOwnership = 'assigned-to-me' | 'unclaimed'
export type ReviewTaskSort = 'due' | 'subject' | 'reference'
export interface ReviewStaffingPageQuery { queue?: string; ownership?: ReviewTaskOwnership; reference?: string; sort?: ReviewTaskSort; cursor?: Uuid; limit?: SafeInteger }
/** A subject selector is absent or names every component of its immutable binding. */
export type ReviewStaffingQuery = ReviewStaffingPageQuery & (
  | { subjectSource?: never; subjectType?: never; subjectId?: never; subjectVersion?: never; subjectDigest?: never }
  | { subjectSource: string; subjectType: string; subjectId: string; subjectVersion: string; subjectDigest: ContentDigest }
)
export interface SupervisoryReviewTaskQuery extends ReviewPageQuery { queue?: string; requestId?: Uuid }
export interface OwnReviewDecisionQuery extends ReviewPageQuery { queue?: string }
export type ReviewTaskState = 'open' | { held: { holder: IssuerPrincipal } } | 'decided'
export type ReviewDecisionType = 'approve' | 'reject' | 'changes-requested' | 'answer'
export interface ReviewDecisionReceipt {
  policy: PolicyBinding
  decision: ReviewDecisionType
  outcome?: string
  outcomeLabel?: string
  decidedAt: string
}
export interface OwnReviewDecision {
  taskId: Uuid
  requestId: Uuid
  queue: string
  requesterReference: string
  decisionReceipt: ReviewDecisionReceipt
}
export interface OwnReviewDecisionPage { items: ReadonlyArray<OwnReviewDecision>; nextCursor?: Uuid; status: PageStatus }
export interface ReviewTask {
  subject: SubjectBinding
  requesterReference: string
  deadlineAt?: string | null
  createdAt: string
  displayReference?: string
  taskId: Uuid
  requestId: Uuid
  stageIndex: SafeInteger
  stageId: string
  queue: string
  revision: SafeInteger
  eligibleProfiles: ReadonlyArray<string>
  state: ReviewTaskState
  decidedByCaller?: boolean
  decisionReceipt?: ReviewDecisionReceipt
}
export interface ReviewTaskPage { items: ReadonlyArray<ReviewTask>; nextCursor?: Uuid; status: PageStatus }
export type SupervisoryReviewTaskState = 'open' | 'held' | 'decided'
export interface SupervisoryReviewTask {
  taskId: Uuid
  requestId: Uuid
  subject: SubjectBinding
  requesterReference: string
  deadlineAt?: string
  createdAt: string
  displayReference?: string
  queue: string
  revision: SafeInteger
  state: SupervisoryReviewTaskState
  accountabilityEventId?: Uuid
}
export interface SupervisoryReviewTaskPage { items: ReadonlyArray<SupervisoryReviewTask>; nextCursor?: Uuid; status: PageStatus }
export type ReviewSourceBindingStatus = 'current' | 'binding-changed'
export interface ReviewSourceProjection { binding: SubjectBinding; displayReference?: string; display: Readonly<Record<string, JsonValue>> }
export type ReviewTaskContextData =
  | { mode: 'submitted'; snapshot: Readonly<Record<string, JsonValue>> }
  | { mode: 'current-source'; reference: string; bindingStatus: ReviewSourceBindingStatus; projection?: ReviewSourceProjection }
export interface ReviewTaskContext {
  taskId: Uuid
  requestId: Uuid
  subject: SubjectBinding
  requesterReference: string
  policy: PolicyBinding
  policyClosure: ReviewPolicyClosure
  resultConstraints?: JsonObject
  context: ReviewTaskContextData
}
export type ReviewClockCorrelation =
  | { scope: 'subject'; source: string; subjectType: string; id: string }
  | { scope: 'activity'; taskId: Uuid; stageId: string }
export interface ReviewClockOccurrence {
  clockOccurrenceId: Uuid
  clockId: string
  requestId: Uuid
  correlation: ReviewClockCorrelation
  state: 'running' | 'paused' | 'completed' | 'cancelled' | 'source-facts-missing'
  policyDigest: ContentDigest
  anchorAt: string
  dueAt?: string
  atRiskAt?: string
  completedAt?: string
}
export interface ReviewTaskDraftInput { body: JsonValue }
export interface ReviewTaskDraft { taskId: Uuid; author: IssuerPrincipal; body: JsonValue; revision: SafeInteger; updatedAt: string }
export type DecisionKind =
  | { type: 'approve' }
  | { type: 'reject' | 'changes-requested' | 'answer'; outcome: string; reason?: string | null; result?: JsonObject | null }
export interface Decision { taskId: Uuid; requestId: Uuid; stageId: string; reviewer: IssuerPrincipal; profileId: string; decision: DecisionKind }
export interface ReviewTaskDecisionRequest { decision: DecisionKind }
export type ReviewHistoryAudience = 'reviewers' | 'requester'
export interface ReviewNoteRequest { audience: ReviewHistoryAudience; note: string }
export interface ReviewHistoryEntry { eventId: Uuid; requestId: Uuid; taskId?: Uuid; kind: string; actorRef?: string; detail: JsonValue; occurredAt: string }
export interface ReviewHistoryPage { items: ReadonlyArray<ReviewHistoryEntry>; nextCursor?: Uuid }
export interface ReviewAccountabilityRecord {
  eventId: Uuid; requestId: Uuid; taskId: Uuid; actorRef: string; actor: IssuerPrincipal
  profileId: string; decision: string; privateReason?: string; resultDigest?: string
  occurredAt: string; retainedUntil: string
  decisionReceipt?: ReviewDecisionReceipt
}
export interface ReviewStagePolicy { id: string; queue: string; decidingProfiles: ReadonlyArray<string>; requiredApprovals: SafeInteger; excludeInitiator?: boolean; excludePreviousStageReviewers?: boolean }
export interface ReviewRetentionPolicy { terminalDays: SafeInteger; accountabilityDays: SafeInteger }
export interface ReviewContextContract { id: string; revision: ContentDigest; schemaDigest: ContentDigest }
export type ReviewContextPolicy = { mode: 'submitted' } | { mode: 'current-source'; provider: string; contract: ReviewContextContract }
export type ReviewContextCapability = 'human-display' | 'service-status' | 'task-grant-context' | 'routing-context'
export interface ReviewContextProviderPolicy { id: string; capabilities: ReadonlyArray<ReviewContextCapability>; sourceNamespace: string; deploymentRef: string; serviceProfiles?: Partial<Record<ReviewContextCapability, string>> }
export interface ReviewPolicy { id: string; version: string; purpose: 'approval' | 'answer'; context: ReviewContextPolicy; routing?: ReadonlyArray<RoutingRule>; stages: ReadonlyArray<ReviewStagePolicy>; clocks?: ReadonlyArray<string>; retention: ReviewRetentionPolicy; displaySchema: JsonValue; resultSchema?: JsonValue; outcomes?: ReadonlyArray<{ id: string; label: string; settlement: 'rejected' | 'changes-requested' | 'answered'; reasonRequired: boolean; resultRequired?: boolean }> }
export interface ReviewPolicyClosure {
  identity: PolicyBinding
  purpose: 'approval' | 'answer'
  context: ReviewContextPolicy
  routing?: ReadonlyArray<RoutingRule>
  dependencies: JsonObject
  stages: ReadonlyArray<ReviewStagePolicy>
  clocks?: ReadonlyArray<string>
  retention: ReviewRetentionPolicy
  displaySchema: JsonValue
  resultSchema?: JsonValue
  outcomes?: ReadonlyArray<{ id: string; label: string; settlement: 'rejected' | 'changes-requested' | 'answered'; reasonRequired: boolean; resultRequired?: boolean }>
}

/** Compute the canonical producer submission digest locally, without I/O. */
export function submissionDigest(producer: string, sourceNamespace: string, request: ReviewCreateRequest): ContentDigest

export class CaseworkClient {
  constructor(config: CaseworkClientConfig)
  description(token: string, profile: string): Promise<CaseworkOutcome<Description>>
  createOrRecoverReviewRequest(token: string, profile: string, idempotencyKey: string, request: ReviewCreateRequest, expectedSubmissionDigest: ContentDigest): Promise<CaseworkOutcome<ReviewRequestAccepted>>
  reviewRequest(token: string, profile: string, requestId: Uuid): Promise<CaseworkOutcome<ReviewRequestView>>
  reviewResult(token: string, profile: string, accepted: ReviewRequestAccepted): Promise<ReviewResultOutcome>
  reviewResults(token: string, profile: string, query?: ReviewPageQuery | null): Promise<CaseworkOutcome<ReviewResultFeedPage>>
  cancelReviewRequest(token: string, profile: string, accepted: ReviewRequestAccepted, idempotencyKey: string, request: ReviewCancelRequest): Promise<CaseworkOutcome<ReviewCancelResponse>>
  reviewPolicies(token: string, profile: string): Promise<CaseworkOutcome<ReadonlyArray<ReviewPolicyClosure>>>
  reviewPolicy(token: string, profile: string, policyId: string): Promise<CaseworkOutcome<ReviewPolicyClosure>>
  nextReviewTask(token: string, profile: string, query?: ReviewStaffingQuery | null, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewTask | null>>
  reviewTasks(token: string, profile: string, query?: ReviewStaffingQuery | null, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewTaskPage>>
  supervisoryReviewTasks(token: string, profile: string, query?: SupervisoryReviewTaskQuery | null, sourceProfile?: string | null): Promise<CaseworkOutcome<SupervisoryReviewTaskPage>>
  ownReviewDecisions(token: string, profile: string, query?: OwnReviewDecisionQuery | null, sourceProfile?: string | null): Promise<CaseworkOutcome<OwnReviewDecisionPage>>
  reviewTask(token: string, profile: string, taskId: Uuid, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewTask>>
  reviewTaskContext(token: string, profile: string, taskId: Uuid, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewTaskContext>>
  previewReviewTaskTemplates(token: string, profile: string, taskId: Uuid, sourceProfile?: string | null): Promise<CaseworkOutcome<TaskTemplatePreviews>>
  listReviewTaskGrants(token: string, profile: string, taskId: Uuid, sourceProfile?: string | null): Promise<CaseworkOutcome<TaskGrantList>>
  approveReviewTaskGrant(token: string, profile: string, taskId: Uuid, expectedRevision: SafeInteger, idempotencyKey: string, approval: TaskApprovalRequest, sourceProfile?: string | null): Promise<CaseworkOutcome<TaskGrantView>>
  revokeReviewTaskGrant(token: string, profile: string, taskId: Uuid, grantId: string): Promise<CaseworkOutcome<TaskGrantRevocation>>
  claimReviewTask(token: string, profile: string, taskId: Uuid, expectedRevision: SafeInteger, idempotencyKey: string, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewTask>>
  releaseReviewTask(token: string, profile: string, taskId: Uuid, expectedRevision: SafeInteger, idempotencyKey: string): Promise<CaseworkOutcome<ReviewTask>>
  assignReviewTask(token: string, profile: string, taskId: Uuid, expectedRevision: SafeInteger, idempotencyKey: string, request: AssignmentRequest, sourceProfile?: string): Promise<CaseworkOutcome<ReviewTask>>
  delegateReviewTask(token: string, profile: string, taskId: Uuid, expectedRevision: SafeInteger, idempotencyKey: string, request: DelegateRequest, sourceProfile?: string): Promise<CaseworkOutcome<ReviewTask>>
  reviewTaskDraft(token: string, profile: string, taskId: Uuid, sourceProfile?: string): Promise<CaseworkOutcome<ReviewTaskDraft | null>>
  saveReviewTaskDraft(token: string, profile: string, taskId: Uuid, expectedRevision: SafeInteger, idempotencyKey: string, draft: ReviewTaskDraftInput, sourceProfile?: string): Promise<CaseworkOutcome<ReviewTaskDraft>>
  deleteReviewTaskDraft(token: string, profile: string, taskId: Uuid, expectedRevision: SafeInteger, idempotencyKey: string, sourceProfile?: string): Promise<CaseworkOutcome<null>>
  decideReviewTask(token: string, profile: string, taskId: Uuid, expectedRevision: SafeInteger, idempotencyKey: string, decision: ReviewTaskDecisionRequest, sourceProfile?: string | null): Promise<CaseworkOutcome<null>>
  reviewHistory(token: string, profile: string, requestId: Uuid, query?: ReviewPageQuery | null, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewHistoryPage>>
  addReviewNote(token: string, profile: string, requestId: Uuid, idempotencyKey: string, note: ReviewNoteRequest, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewHistoryEntry>>
  reviewClocks(token: string, profile: string, requestId: Uuid, sourceProfile?: string | null): Promise<CaseworkOutcome<ReadonlyArray<ReviewClockOccurrence>>>
  reviewAccountability(token: string, profile: string, eventId: Uuid): Promise<CaseworkOutcome<ReviewAccountabilityRecord>>
  taskAssertion(token: string, grantId: string): Promise<CaseworkOutcome<TaskAssertionResponse>>
  /** Exact empty-POST authority route for the shared remote exchange provider. */
  taskAssertionEndpoint(grantId: string): string
  taskGrantStatus(token: string, grantId: string): Promise<CaseworkOutcome<TaskGrantStatus>>
  reviewTaskHoldings(token: string, profile: string, query?: ReviewStaffingQuery | null, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewTaskPage>>
  directory(token: string, profile: string): Promise<CaseworkOutcome<DirectoryResponse>>
  directoryTargets(token: string, profile: string, query: DirectoryTargetsQuery): Promise<CaseworkOutcome<DirectoryTargetPage>>
  bootstrapDirectory(token: string, profile: string, expectedRevision: SafeInteger, idempotencyKey: string, request: BootstrapDirectoryRequest): Promise<CaseworkOutcome<DirectoryResponse>>
  updateDirectoryTeam(token: string, profile: string, teamId: string, expectedRevision: SafeInteger, idempotencyKey: string, request: DirectoryTeamUpdateRequest): Promise<CaseworkOutcome<DirectoryResponse>>
  holidayRevision(token: string, profile: string, holidaySet: string, revision: SafeInteger): Promise<CaseworkOutcome<HolidaySetDocument>>
  createHolidayRevision(token: string, profile: string, idempotencyKey: string, request: HolidaySetRevisionInput): Promise<CaseworkOutcome<HolidaySetDocument>>
  previewClockRecompute(token: string, profile: string, request: ReviewClockRecomputeRequest): Promise<CaseworkOutcome<ReviewClockRecomputePreview>>
  applyClockRecompute(token: string, profile: string, idempotencyKey: string, request: ReviewClockRecomputeApplyRequest): Promise<CaseworkOutcome<ReviewClockRecomputeResult>>
  absences(token: string, profile: string, query?: AbsencesQuery | null): Promise<CaseworkOutcome<AbsenceList>>
  createAbsence(token: string, profile: string, expectedRevision: SafeInteger, idempotencyKey: string, request: AbsenceInput): Promise<CaseworkOutcome<AbsenceRecord>>
  updateAbsence(token: string, profile: string, absenceId: string, expectedRevision: SafeInteger, idempotencyKey: string, request: AbsenceInput): Promise<CaseworkOutcome<AbsenceRecord>>
  deleteAbsence(token: string, profile: string, absenceId: string, expectedRevision: SafeInteger, idempotencyKey: string): Promise<CaseworkOutcome<null>>
  previewCaseloadMove(token: string, profile: string, movement: ReviewCaseloadMoveRequest, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewCaseloadPreview>>
  applyCaseloadMove(token: string, profile: string, idempotencyKey: string, request: ReviewCaseloadApplyRequest, sourceProfile?: string | null): Promise<CaseworkOutcome<ReviewCaseloadResult>>
}
