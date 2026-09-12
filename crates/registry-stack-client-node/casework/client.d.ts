export type SafeInteger = number
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
}

export type InboxView = 'mine' | 'my_teams' | 'team_holdings' | 'overdue' | 'completed_by_me'
export type OccurrenceKind = 'review' | 'application' | 'hosted'
export type OccurrenceState = 'open' | 'claimed' | 'waiting_applicant' | 'waiting_application' | 'synchronizing' | 'completed' | 'superseded' | 'cancelled'
export type OperationName = string
export type AttemptState = 'pending' | 'uncertain' | 'completed' | 'refused'
export type PageStatus = 'complete' | 'budget_exhausted' | 'source_unavailable'
export type HistoryKind = 'observed' | 'opened' | 'claimed' | 'assigned' | 'delegated' | 'caseload_moved' | 'clock_reminder' | 'clock_step_applied' | 'clock_recomputed' | 'released' | 'draft_saved' | 'attempt_reserved' | 'attempt_uncertain' | 'action_completed' | 'attempt_settled' | 'superseded' | 'completed'

export interface IssuerPrincipal { issuer: string; subject: string }
export type TaskGrantBounds = { type: 'evidence'; requirement: string } | { type: 'breg'; permissions: ReadonlyArray<TaskPermission> }
export interface TaskPermission { collection: string; operations: ReadonlyArray<string> }
export interface TaskApprovalRequest { templateId: string; templateVersion: string }
export interface TaskTemplatePreview {
  id: string; version: string; label: string; agent: IssuerPrincipal; client: string; resource: string; scopes: ReadonlyArray<string>; purpose: string
  bounds: TaskGrantBounds; subjects: { readonly [key: string]: Exclude<JsonScalar, null> }; lifetimeSeconds: SafeInteger
}
export interface TaskTemplatePreviews { itemRevision: SafeInteger; templates: ReadonlyArray<TaskTemplatePreview> }
/** Grant metadata deliberately excludes stored subject values. */
export interface TaskGrantView {
  id: string; templateId: string; templateVersion: string; agent: IssuerPrincipal; client: string; resource: string; scopes: ReadonlyArray<string>; purpose: string
  bounds: TaskGrantBounds; expiresAt: SafeInteger; invalidated: boolean
}
export interface TaskGrantList { grants: ReadonlyArray<TaskGrantView> }
export interface TaskGrantRevocation { id: string; invalidated: boolean }
/** A short-lived credential. Do not persist or log the assertion. */
export interface TaskAssertionResponse { assertion: string; expiresAt: SafeInteger; grantExpiresAt: SafeInteger }
export interface TaskGrantStatusDetails {
  grantId: string; authority: string; sourceIssuer: string; principal: string; client: string; resource: string; purpose: string
  bounds: TaskGrantBounds; subjects: { readonly [key: string]: Exclude<JsonScalar, null> }; expiresAt: SafeInteger
}
export interface TaskGrantStatus { active: boolean; grant?: TaskGrantStatusDetails }

export interface DirectoryMember { issuer: string; subject: string; displayName?: string | null }
export interface SubjectRef { sourceId: string; kind: string; id: string }
export interface SourceBinding {
  sourceRevision: string
  version: string
  integrity?: string
  generation: string
}
export type CaseworkActionName = 'claim' | 'release' | OperationName
export interface CaseworkAction { operation: CaseworkActionName; href: string; ifMatch: string }
export interface CorrectionRoutingCopy {
  sourceBinding: SourceBinding
  reason?: string
  flaggedFields: ReadonlyArray<string>
}
export interface WorkItemRouting {
  ruleId?: string
  because?: string
  policyDigest?: string
}
export interface WorkItem {
  itemId: string
  subject: SubjectRef
  occurrenceKind: OccurrenceKind
  stage?: string
  binding: SourceBinding
  bindingReference: string
  displayReference?: string
  state: OccurrenceState
  queueId: string
  holder?: IssuerPrincipal
  heldSince?: string
  assignment?: AssignmentContext
  revision: SafeInteger
  firstObservedAt: string
  passiveDueAt?: string
  updatedAt: string
  actions: ReadonlyArray<CaseworkAction>
  routingCopy?: CorrectionRoutingCopy
  hosted?: HostedWorkItemContext
  routing?: WorkItemRouting
  clockOccurrences?: ReadonlyArray<ClockOccurrenceView>
  liveAttempt?: AttemptStatus
}
export interface Page<T> { items: ReadonlyArray<T>; nextCursor?: string; status: PageStatus }
export interface WorkItemPage extends Page<WorkItem> { servedQueues: ReadonlyArray<string> }
export type DirectoryTargetPurpose = 'assignment' | 'absence_person' | 'absence_cover'
export type DirectoryTargetsQuery = {
  cursor?: string
  limit?: SafeInteger
} & (
  | { purpose: 'assignment'; queue: string; personIssuer?: never; personSubject?: never }
  | { purpose: 'absence_person'; queue?: never; personIssuer?: never; personSubject?: never }
  | { purpose: 'absence_cover'; queue?: never; personIssuer: string; personSubject: string }
)
export type DirectoryTargetPage = Page<DirectoryMember>
export type ListWorkItemsQuery = {
  view: InboxView
  sort?: InboxSort
  queue?: string
  cursor?: string
  limit?: SafeInteger
} & (
  | { sourceId: string; subjectKind: string; subjectId: string; reference?: never }
  | { reference: string; sourceId?: never; subjectKind?: never; subjectId?: never }
  | { reference?: never; sourceId?: never; subjectKind?: never; subjectId?: never }
)
export type InboxSort = 'due' | 'age' | 'type'
export interface NextWorkItemQuery { queue?: string; cursor?: string }
export interface SaveDraftRequest {
  binding: SourceBinding
  reason: string
  flaggedFields?: ReadonlyArray<string>
}
export interface Draft {
  itemId: string
  author: IssuerPrincipal
  binding: SourceBinding
  reason: string
  flaggedFields: ReadonlyArray<string>
  revision: SafeInteger
  updatedAt: string
}
export interface DraftResponse { draft: Draft }
export interface DecideRequest {
  displayedBinding: SourceBinding
  sourceProfileId: string
  operation: OperationName
  reason?: string
  flaggedFields?: ReadonlyArray<string>
}
export interface RecoverAttemptRequest { sourceProfileId: string }
export interface SourceReceipt {
  sourceRevision: string
  resultingState: string
  binding: SourceBinding
  actorReference?: string
  metadata: Readonly<Record<string, string>>
}
export interface AttemptStatus {
  attemptId: string
  itemId: string
  state: AttemptState
  itemRevision: SafeInteger
  operation: OperationName
  createdAt: string
  receipt?: SourceReceipt
}
export interface MutationResponse { item: WorkItem; attempt?: AttemptStatus }
export interface HistoryEntryBase {
  eventId: string
  itemId: string
  itemRevision: SafeInteger
  kind: HistoryKind
  occurredAt: string
  actor?: IssuerPrincipal
  profileId: string
}
export interface AttemptReservedHistoryEntry extends HistoryEntryBase {
  kind: 'attempt_reserved'
  detail: JsonObject & { attemptId: string; bindingReference: string; operation: OperationName }
}
export interface AttemptUncertainHistoryEntry extends HistoryEntryBase {
  kind: 'attempt_uncertain'
  detail: JsonObject & { attemptId: string; bindingReference: string; sourceRevision?: string | null; definitivelyRefused?: boolean }
}
export interface ActionCompletedHistoryEntry extends HistoryEntryBase {
  kind: 'action_completed'
  detail: JsonObject & { attemptId: string; bindingReference: string; sourceRevision: string; sourceReceipt: SourceReceipt }
}
export interface AttemptSettledHistoryEntry extends HistoryEntryBase {
  kind: 'attempt_settled'
  detail: JsonObject & { attemptId: string; bindingReference: string; operation: OperationName; outcome: 'applied' | 'not_applied'; reason: string; decidedBy: string }
}
export interface OtherHistoryEntry extends HistoryEntryBase {
  kind: Exclude<HistoryKind, 'attempt_reserved' | 'attempt_uncertain' | 'action_completed' | 'attempt_settled'>
  detail: JsonValue
}
export type HistoryEntry = AttemptReservedHistoryEntry | AttemptUncertainHistoryEntry | ActionCompletedHistoryEntry | AttemptSettledHistoryEntry | OtherHistoryEntry
export interface HoldingSummary {
  principal: IssuerPrincipal
  queueId: string
  activeItems: SafeInteger
  overdueItems: SafeInteger
}
export interface QueueRecord { id: string; label: string }
export interface PassiveTargetPolicy { id: string; after: { elapsed: string } }
export type RoutingPredicate = { equals: JsonValue } | { oneOf: ReadonlyArray<JsonValue> }
export interface RoutingCondition { activity?: 'review' | 'apply'; stage?: string; fields?: Readonly<Record<string, RoutingPredicate>> }
export interface RoutingRule { id: string; because: string; when: RoutingCondition; queue: string }
export interface DisplayReferencePolicy { field: string }
export interface SourceRequestPolicy { entity: string; queue: string; projection?: ReadonlyArray<string>; routing?: ReadonlyArray<RoutingRule>; displayReference?: DisplayReferencePolicy; clock?: string; target?: PassiveTargetPolicy }
export type WorkingWeekday = 'monday' | 'tuesday' | 'wednesday' | 'thursday' | 'friday' | 'saturday' | 'sunday'
export interface CalendarPolicy { id: string; timezone: string; workingWeekdays: ReadonlyArray<WorkingWeekday>; holidaySet: string }
export interface ClockReminder { id: string; workingDaysBefore: SafeInteger }
export interface ClockStep { id: string; because: string; at: 'due'; action: { reassign: { queue: string } } }
export type ClockPolicy = {
  scope: 'subject'; id: string; anchor: 'firstSubmittedAt'; completeOn: 'reviewCompleted'; after: { elapsed: string }; pauseWhile: ReadonlyArray<'awaitingApplicant'>
} | {
  scope: 'activity'; id: string; anchor: 'stageEnteredAt'; calendar: string; after: { workingDays: SafeInteger }; dueTime: string;
  atRisk?: { workingDaysBefore: SafeInteger }; reminders?: ReadonlyArray<ClockReminder>; steps?: ReadonlyArray<ClockStep>
}
export interface SourcePolicy {
  id: string
  adapter: string
  description: string
  requests: ReadonlyArray<SourceRequestPolicy>
}
export interface HostedRetentionPolicy { terminalDays: SafeInteger; accountabilityDays: SafeInteger }
export interface HostedOutcomePolicy { id: string; label: string; reasonRequired: boolean }
export interface HostedKindPolicy {
  id: string
  version: string
  queue: string
  decidingProfiles: ReadonlyArray<string>
  retention: HostedRetentionPolicy
  displaySchema: JsonValue
  outcomes: ReadonlyArray<HostedOutcomePolicy>
}
export interface HostedWorkItemContext {
  requesterReference: string
  kind: string
  version: string
  display: JsonValue
  kindPolicyDigest: string
  outcomes: ReadonlyArray<HostedOutcomePolicy>
}
export interface HostedCreateRequest { kind: string; requesterReference: string; display: JsonValue }
export interface HostedNoteRequest { note: string }
export interface HostedCancelRequest { reason: string }
export interface HostedDecisionRequest { outcome: string; reason?: string }
export interface RequesterHostedItem {
  itemId: string
  requesterReference: string
  kind: string
  version: string
  display: JsonValue
  state: OccurrenceState
  revision: SafeInteger
  kindPolicyDigest: string
  createdAt: string
  updatedAt: string
}
export type HostedTerminalResult = {
  itemId: string
  eventId: string
  requesterReference: string
  kindPolicyDigest: string
  terminalAt: string
} & (
  | { state: 'completed'; outcome: string; actorRef: string }
  | { state: 'cancelled'; cancellationReason: string }
)
export interface HostedTerminalQuery { cursor?: string; limit?: SafeInteger }
export interface HostedPageQuery { cursor?: string; limit?: SafeInteger }
export interface HostedNote {
  noteId: string
  itemId: string
  note: string
  itemRevision: SafeInteger
  recordedAt: string
}
export type HostedHistoryKind = 'created' | 'claimed' | 'assigned' | 'delegated' | 'caseload_moved' | 'released' | 'note_added' | 'completed' | 'cancelled'
export interface HostedHistoryEntry {
  eventId: string
  itemId: string
  itemRevision: SafeInteger
  kind: HostedHistoryKind
  occurredAt: string
  actorRef?: string
  assignment?: AssignmentContext
  note?: string
  outcome?: string
  reason?: string
  cancellationReason?: string
}
export interface HostedAccountabilityRecord {
  itemId: string
  eventId: string
  actorRef: string
  actor: IssuerPrincipal
  profileId: string
  outcome: string
  reason?: string
  recordedAt: string
  retainedUntil: string
}
export interface Description {
  projectId: string
  policyVersion: string
  queues: ReadonlyArray<QueueRecord>
  sources: ReadonlyArray<SourcePolicy>
  calendars: ReadonlyArray<CalendarPolicy>
  clocks: ReadonlyArray<ClockPolicy>
  hostedKinds: ReadonlyArray<HostedKindPolicy>
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
export interface AssignmentContext { owner?: IssuerPrincipal; assignedBy?: IssuerPrincipal; absenceIds: ReadonlyArray<string>; staffingDiagnostic?: 'no_cover_available' }
export interface AssignmentRequest { assignee: IssuerPrincipal; reason?: string }
export interface DelegateRequest { delegate: IssuerPrincipal; reason?: string }
export interface CaseloadMoveRequest { from: IssuerPrincipal; to: IssuerPrincipal; queueId?: string; reason: string }
export interface CaseloadItemSelection { itemId: string; expectedRevision: SafeInteger }
export interface CaseloadApplyRequest { movement: CaseloadMoveRequest; items: ReadonlyArray<CaseloadItemSelection> }
export interface CaseloadPreviewQuery { cursor?: string; limit?: SafeInteger }
export interface CaseloadItemResult { itemId: string; result: 'moved' | 'not_visible' | 'not_eligible' | 'attempt_in_progress' | 'conflict'; revision?: SafeInteger }
export interface BootstrapDirectoryRequest {
  teamId: string
  staff: ReadonlyArray<IssuerPrincipal>
  supervisors: ReadonlyArray<IssuerPrincipal>
  queueId: string
}
export interface HoldingsQuery { cursor?: string; limit?: SafeInteger }
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
  | 'request.method-not-allowed'
  | 'request.not-found'
  | 'request.reason-unsupported'
  | 'request.source-rejected'
  | 'request.unprocessable'
  | 'request.unsupported-media-type'
  | 'runtime.failure'
  | 'service.unavailable'
  | 'source-profile.not-applicable'
  | 'source-profile.required'
  | 'source.bad-gateway'
  | 'source.not-found'
  | 'source.record-missing'
  | 'source.reviewer-not-authorized'
  | 'source.signature-invalid'
  | 'work-item.already-claimed'
  | 'work-item.not-holder'
  | 'work-item.not-offered'
  | 'work-item.not-visible'
  | 'work-item.proposal-changed'
  | 'work-item.recovery-pending'
  | 'work-item.source-unavailable'
  | 'work-item.superseded'
export type CaseworkProblemCode = KnownCaseworkProblemCode | (string & {})

export class CaseworkClientError extends Error {
  readonly kind: 'configuration' | 'invalid_request' | 'transport' | 'problem' | 'protocol'
  readonly code?: CaseworkProblemCode
  readonly detail?: string
  readonly status?: SafeInteger
  readonly traceId?: string
  readonly originalAttemptId?: string
  readonly validation?: {
    readonly path: string
    readonly reason: 'kind_not_allowed' | 'reference_invalid' | 'object_required' | 'maximum_bytes_exceeded' | 'maximum_depth_exceeded' | 'schema_mismatch' | 'outcome_not_declared' | 'reason_required' | 'text_invalid'
  }
  readonly transportKind?: string
  readonly protocolFailure?: string
}

export type ClockRuntimeState = 'running' | 'paused' | 'completed' | 'cancelled' | 'verification_pending' | 'source_facts_missing'
export type ClockNextEffect =
  | { kind: 'reminder'; id: string; at: string }
  | { kind: 'reassign'; id: string; at: string; because: string; queueId: string }
export interface ClockOccurrenceView {
  clockOccurrenceId: string
  subject: SubjectRef
  clockId: string
  state: ClockRuntimeState
  policyDigest: string
  calculationGeneration: SafeInteger
  recomputeGeneration: SafeInteger
  anchorAt?: string
  startedAt?: string
  dueAt?: string
  atRiskAt?: string
  completedAt?: string
  nextEffect?: ClockNextEffect
  upcomingEffects?: ReadonlyArray<ClockNextEffect>
}
export interface HolidaySetDocument { holidaySet: string; revision: SafeInteger; dates: ReadonlyArray<string> }
export interface HolidaySetRevisionInput { document: HolidaySetDocument }
export interface ClockRecomputeRequest { clockId: string; holidaySet: string; holidayRevision: SafeInteger }
export interface ClockRecomputeChange { clockOccurrenceId: string; itemId: string; expectedCalculationGeneration: SafeInteger; oldDueAt: string; proposedDueAt: string }
export interface ClockRecomputePreview { previewId: string; clockId: string; holidaySet: string; holidayRevision: SafeInteger; expiresAt: string; changes: ReadonlyArray<ClockRecomputeChange> }
export interface ClockRecomputeApplyRequest { previewId: string }
export interface ClockRecomputeResult { previewId: string; appliedOccurrences: ReadonlyArray<string> }

export class CaseworkClient {
  constructor(config: CaseworkClientConfig)
  description(token: string, profile: string): Promise<CaseworkOutcome<Description>>
  createHostedItem(token: string, profile: string, idempotencyKey: string, request: HostedCreateRequest): Promise<CaseworkOutcome<RequesterHostedItem>>
  getHostedItem(token: string, profile: string, itemId: string): Promise<CaseworkOutcome<RequesterHostedItem>>
  addHostedNote(token: string, profile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, note: HostedNoteRequest): Promise<CaseworkOutcome<RequesterHostedItem>>
  requesterHostedNotes(token: string, profile: string, itemId: string, query?: HostedPageQuery | null): Promise<CaseworkOutcome<Page<HostedNote>>>
  cancelHostedItem(token: string, profile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, cancellation: HostedCancelRequest): Promise<CaseworkOutcome<HostedTerminalResult>>
  hostedTerminalItems(token: string, profile: string, query?: HostedTerminalQuery | null): Promise<CaseworkOutcome<Page<HostedTerminalResult>>>
  listHostedWorkItems(token: string, profile: string, query: ListWorkItemsQuery): Promise<CaseworkOutcome<WorkItemPage>>
  getHostedWorkItem(token: string, profile: string, itemId: string): Promise<CaseworkOutcome<WorkItem>>
  hostedWorkItemHistory(token: string, profile: string, itemId: string, query?: HostedPageQuery | null): Promise<CaseworkOutcome<Page<HostedHistoryEntry>>>
  hostedAccountabilityRecord(token: string, profile: string, eventId: string): Promise<CaseworkOutcome<HostedAccountabilityRecord>>
  claimHostedWorkItem(token: string, profile: string, action: CaseworkAction, idempotencyKey: string): Promise<CaseworkOutcome<MutationResponse>>
  releaseHostedWorkItem(token: string, profile: string, action: CaseworkAction, idempotencyKey: string): Promise<CaseworkOutcome<MutationResponse>>
  decideHostedWorkItem(token: string, profile: string, action: CaseworkAction, idempotencyKey: string, decision: HostedDecisionRequest): Promise<CaseworkOutcome<HostedTerminalResult>>
  listWorkItems(token: string, profile: string, sourceProfile: string, query: ListWorkItemsQuery): Promise<CaseworkOutcome<WorkItemPage>>
  nextWorkItem(token: string, profile: string, sourceProfile: string, query?: NextWorkItemQuery | null): Promise<CaseworkOutcome<WorkItemPage>>
  getWorkItem(token: string, profile: string, sourceProfile: string, itemId: string): Promise<CaseworkOutcome<WorkItem>>
  previewTaskTemplates(token: string, profile: string, sourceProfile: string, itemId: string): Promise<CaseworkOutcome<TaskTemplatePreviews>>
  listTaskGrants(token: string, profile: string, sourceProfile: string, itemId: string): Promise<CaseworkOutcome<TaskGrantList>>
  approveTaskGrant(token: string, profile: string, sourceProfile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, approval: TaskApprovalRequest): Promise<CaseworkOutcome<TaskGrantView>>
  revokeTaskGrant(token: string, profile: string, sourceProfile: string, itemId: string, grantId: string): Promise<CaseworkOutcome<TaskGrantRevocation>>
  taskAssertion(token: string, grantId: string): Promise<CaseworkOutcome<TaskAssertionResponse>>
  taskGrantStatus(token: string, grantId: string): Promise<CaseworkOutcome<TaskGrantStatus>>
  claimWorkItem(token: string, profile: string, sourceProfile: string, action: CaseworkAction, idempotencyKey: string): Promise<CaseworkOutcome<MutationResponse>>
  releaseWorkItem(token: string, profile: string, sourceProfile: string, action: CaseworkAction, idempotencyKey: string): Promise<CaseworkOutcome<MutationResponse>>
  getDraft(token: string, profile: string, sourceProfile: string, itemId: string): Promise<CaseworkOutcome<DraftResponse>>
  saveDraft(token: string, profile: string, sourceProfile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, draft: SaveDraftRequest): Promise<CaseworkOutcome<DraftResponse>>
  deleteDraft(token: string, profile: string, sourceProfile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string): Promise<CaseworkOutcome<null>>
  decideWorkItem(token: string, profile: string, sourceProfile: string, action: CaseworkAction, idempotencyKey: string, decision: DecideRequest): Promise<CaseworkOutcome<MutationResponse>>
  recoverDecision(token: string, profile: string, sourceProfile: string, itemId: string, attemptId: string, recovery: RecoverAttemptRequest): Promise<CaseworkOutcome<MutationResponse>>
  recoverDecisionByKey(token: string, profile: string, sourceProfile: string, itemId: string, idempotencyKey: string, recovery: RecoverAttemptRequest): Promise<CaseworkOutcome<MutationResponse>>
  workItemHistory(token: string, profile: string, sourceProfile: string, itemId: string, query?: HostedPageQuery | null): Promise<CaseworkOutcome<Page<HistoryEntry>>>
  holdings(token: string, profile: string, sourceProfile: string, query?: HoldingsQuery | null): Promise<CaseworkOutcome<Page<HoldingSummary>>>
  directory(token: string, profile: string): Promise<CaseworkOutcome<DirectoryResponse>>
  directoryTargets(token: string, profile: string, query: DirectoryTargetsQuery): Promise<CaseworkOutcome<DirectoryTargetPage>>
  bootstrapDirectory(token: string, profile: string, expectedRevision: SafeInteger, idempotencyKey: string, request: BootstrapDirectoryRequest): Promise<CaseworkOutcome<DirectoryResponse>>
  updateDirectoryTeam(token: string, profile: string, teamId: string, expectedRevision: SafeInteger, idempotencyKey: string, request: DirectoryTeamUpdateRequest): Promise<CaseworkOutcome<DirectoryResponse>>
  workItemClocks(token: string, profile: string, sourceProfile: string, itemId: string): Promise<CaseworkOutcome<ReadonlyArray<ClockOccurrenceView>>>
  holidayRevision(token: string, profile: string, holidaySet: string, revision: SafeInteger): Promise<CaseworkOutcome<HolidaySetDocument>>
  createHolidayRevision(token: string, profile: string, idempotencyKey: string, request: HolidaySetRevisionInput): Promise<CaseworkOutcome<HolidaySetDocument>>
  previewClockRecompute(token: string, profile: string, request: ClockRecomputeRequest): Promise<CaseworkOutcome<ClockRecomputePreview>>
  applyClockRecompute(token: string, profile: string, idempotencyKey: string, request: ClockRecomputeApplyRequest): Promise<CaseworkOutcome<ClockRecomputeResult>>
  absences(token: string, profile: string, query?: AbsencesQuery | null): Promise<CaseworkOutcome<AbsenceList>>
  createAbsence(token: string, profile: string, expectedRevision: SafeInteger, idempotencyKey: string, request: AbsenceInput): Promise<CaseworkOutcome<AbsenceRecord>>
  updateAbsence(token: string, profile: string, absenceId: string, expectedRevision: SafeInteger, idempotencyKey: string, request: AbsenceInput): Promise<CaseworkOutcome<AbsenceRecord>>
  deleteAbsence(token: string, profile: string, absenceId: string, expectedRevision: SafeInteger, idempotencyKey: string): Promise<CaseworkOutcome<null>>
  assignWorkItem(token: string, profile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, request: AssignmentRequest, sourceProfile?: string | null): Promise<CaseworkOutcome<MutationResponse>>
  delegateWorkItem(token: string, profile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, request: DelegateRequest, sourceProfile?: string | null): Promise<CaseworkOutcome<MutationResponse>>
  previewCaseloadMove(token: string, profile: string, movement: CaseloadMoveRequest, query?: CaseloadPreviewQuery | null, sourceProfile?: string | null): Promise<CaseworkOutcome<Page<WorkItem>>>
  applyCaseloadMove(token: string, profile: string, idempotencyKey: string, request: CaseloadApplyRequest, sourceProfile?: string | null): Promise<CaseworkOutcome<ReadonlyArray<CaseloadItemResult>>>
}
