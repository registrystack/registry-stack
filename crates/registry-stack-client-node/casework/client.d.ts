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
export type HistoryKind = 'observed' | 'opened' | 'claimed' | 'released' | 'draft_saved' | 'attempt_reserved' | 'attempt_uncertain' | 'action_completed' | 'superseded' | 'completed'

export interface IssuerPrincipal { issuer: string; subject: string }
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
export interface WorkItem {
  itemId: string
  subject: SubjectRef
  occurrenceKind: OccurrenceKind
  stage?: string
  binding: SourceBinding
  bindingReference: string
  state: OccurrenceState
  queueId: string
  holder?: IssuerPrincipal
  revision: SafeInteger
  firstObservedAt: string
  passiveDueAt?: string
  updatedAt: string
  actions: ReadonlyArray<CaseworkAction>
  routingCopy?: CorrectionRoutingCopy
  hosted?: HostedWorkItemContext
}
export interface Page<T> { items: ReadonlyArray<T>; nextCursor?: string; status: PageStatus }
export interface ListWorkItemsQuery {
  view: InboxView
  queue?: string
  cursor?: string
  limit?: SafeInteger
}
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
export interface OtherHistoryEntry extends HistoryEntryBase {
  kind: Exclude<HistoryKind, 'attempt_reserved' | 'attempt_uncertain' | 'action_completed'>
  detail: JsonValue
}
export type HistoryEntry = AttemptReservedHistoryEntry | AttemptUncertainHistoryEntry | ActionCompletedHistoryEntry | OtherHistoryEntry
export interface HoldingSummary {
  principal: IssuerPrincipal
  queueId: string
  activeItems: SafeInteger
  overdueItems: SafeInteger
}
export interface QueueRecord { id: string; label: string }
export interface PassiveTargetPolicy { id: string; after: { elapsed: string } }
export interface SourceRequestPolicy { entity: string; queue: string; target?: PassiveTargetPolicy }
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
export type HostedHistoryKind = 'created' | 'claimed' | 'released' | 'note_added' | 'completed' | 'cancelled'
export interface HostedHistoryEntry {
  eventId: string
  itemId: string
  itemRevision: SafeInteger
  kind: HostedHistoryKind
  occurredAt: string
  actorRef?: string
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
  hostedKinds: ReadonlyArray<HostedKindPolicy>
}
export interface TeamRecord {
  id: string
  members: ReadonlyArray<IssuerPrincipal>
  supervisors: ReadonlyArray<IssuerPrincipal>
  servedQueues: ReadonlyArray<string>
  revision: SafeInteger
}
export interface DirectoryResponse { revision: SafeInteger; teams: ReadonlyArray<TeamRecord> }
export interface BootstrapDirectoryRequest {
  teamId: string
  staff: ReadonlyArray<IssuerPrincipal>
  supervisors: ReadonlyArray<IssuerPrincipal>
  queueId: string
}
export interface HoldingsQuery { cursor?: string }
export interface CaseworkOutcome<T> { kind: 'complete'; value: T; traceId: string }

export type KnownCaseworkProblemCode =
  | 'authentication.refused'
  | 'cursor.expired'
  | 'cursor.invalid'
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
  | 'request.unprocessable'
  | 'request.unsupported-media-type'
  | 'runtime.failure'
  | 'service.unavailable'
  | 'source.bad-gateway'
  | 'source.not-found'
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

export class CaseworkClient {
  constructor(config: CaseworkClientConfig)
  description(token: string, profile: string): Promise<CaseworkOutcome<Description>>
  createHostedItem(token: string, profile: string, idempotencyKey: string, request: HostedCreateRequest): Promise<CaseworkOutcome<RequesterHostedItem>>
  getHostedItem(token: string, profile: string, itemId: string): Promise<CaseworkOutcome<RequesterHostedItem>>
  addHostedNote(token: string, profile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, note: HostedNoteRequest): Promise<CaseworkOutcome<RequesterHostedItem>>
  requesterHostedNotes(token: string, profile: string, itemId: string, query?: HostedPageQuery | null): Promise<CaseworkOutcome<Page<HostedNote>>>
  cancelHostedItem(token: string, profile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, cancellation: HostedCancelRequest): Promise<CaseworkOutcome<HostedTerminalResult>>
  hostedTerminalItems(token: string, profile: string, query?: HostedTerminalQuery | null): Promise<CaseworkOutcome<Page<HostedTerminalResult>>>
  listHostedWorkItems(token: string, profile: string, query: ListWorkItemsQuery): Promise<CaseworkOutcome<Page<WorkItem>>>
  getHostedWorkItem(token: string, profile: string, itemId: string): Promise<CaseworkOutcome<WorkItem>>
  hostedWorkItemHistory(token: string, profile: string, itemId: string, query?: HostedPageQuery | null): Promise<CaseworkOutcome<Page<HostedHistoryEntry>>>
  hostedAccountabilityRecord(token: string, profile: string, eventId: string): Promise<CaseworkOutcome<HostedAccountabilityRecord>>
  claimHostedWorkItem(token: string, profile: string, action: CaseworkAction, idempotencyKey: string): Promise<CaseworkOutcome<MutationResponse>>
  releaseHostedWorkItem(token: string, profile: string, action: CaseworkAction, idempotencyKey: string): Promise<CaseworkOutcome<MutationResponse>>
  decideHostedWorkItem(token: string, profile: string, action: CaseworkAction, idempotencyKey: string, decision: HostedDecisionRequest): Promise<CaseworkOutcome<HostedTerminalResult>>
  listWorkItems(token: string, profile: string, sourceProfile: string, query: ListWorkItemsQuery): Promise<CaseworkOutcome<Page<WorkItem>>>
  nextWorkItem(token: string, profile: string, sourceProfile: string, query?: NextWorkItemQuery | null): Promise<CaseworkOutcome<WorkItem | null>>
  getWorkItem(token: string, profile: string, sourceProfile: string, itemId: string): Promise<CaseworkOutcome<WorkItem>>
  claimWorkItem(token: string, profile: string, sourceProfile: string, action: CaseworkAction, idempotencyKey: string): Promise<CaseworkOutcome<MutationResponse>>
  releaseWorkItem(token: string, profile: string, sourceProfile: string, action: CaseworkAction, idempotencyKey: string): Promise<CaseworkOutcome<MutationResponse>>
  getDraft(token: string, profile: string, sourceProfile: string, itemId: string): Promise<CaseworkOutcome<DraftResponse>>
  saveDraft(token: string, profile: string, sourceProfile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string, draft: SaveDraftRequest): Promise<CaseworkOutcome<DraftResponse>>
  deleteDraft(token: string, profile: string, sourceProfile: string, itemId: string, expectedRevision: SafeInteger, idempotencyKey: string): Promise<CaseworkOutcome<null>>
  decideWorkItem(token: string, profile: string, sourceProfile: string, action: CaseworkAction, idempotencyKey: string, decision: DecideRequest): Promise<CaseworkOutcome<MutationResponse>>
  recoverDecision(token: string, profile: string, sourceProfile: string, itemId: string, attemptId: string, recovery: RecoverAttemptRequest): Promise<CaseworkOutcome<MutationResponse>>
  recoverDecisionByKey(token: string, profile: string, sourceProfile: string, itemId: string, idempotencyKey: string, recovery: RecoverAttemptRequest): Promise<CaseworkOutcome<MutationResponse>>
  workItemHistory(token: string, profile: string, sourceProfile: string, itemId: string): Promise<CaseworkOutcome<Page<HistoryEntry>>>
  holdings(token: string, profile: string, sourceProfile: string, query?: HoldingsQuery | null): Promise<CaseworkOutcome<Page<HoldingSummary>>>
  directory(token: string, profile: string): Promise<CaseworkOutcome<DirectoryResponse>>
  bootstrapDirectory(token: string, profile: string, expectedRevision: SafeInteger, idempotencyKey: string, request: BootstrapDirectoryRequest): Promise<CaseworkOutcome<DirectoryResponse>>
}
