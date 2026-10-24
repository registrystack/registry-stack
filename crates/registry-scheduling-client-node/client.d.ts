/** An integer for which `Number.isSafeInteger` is true. */
export type SafeInteger = number
/**
 * An RFC 3339 instant. Instants the binding sends are parsed and normalized
 * to UTC before any request; instants it answers are UTC.
 */
export type Instant = string
export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }

export interface SchedulingClientConfig {
  baseUrl: string
  attemptTimeoutMilliseconds?: SafeInteger
  connectTimeoutMilliseconds?: SafeInteger
  maximumResponseBytes?: SafeInteger
  userAgent?: string
  /** Additional trust roots for the deployment, as PEM text. */
  trustedRootCertificates?: string
  /**
   * How many times a keyed command (hold, appointment create, reschedule,
   * cancel) whose outcome is unknown is resent, identically and under the
   * same idempotency key, before its error is returned: a whole number from 0
   * to 2, default 2; 0 sends it once. Any other value is a `configuration`
   * error.
   */
  maximumMutationRetries?: SafeInteger
}

/** An opaque record link Scheduling retains with a hold or appointment. */
export interface ExternalReference {
  product: string
  recordType: string
  identifier: string
}

export interface PartyCounts { recipients: SafeInteger; attendees: SafeInteger }
export interface BusyCoverage { start: Instant; end: Instant; resources: ReadonlyArray<string> }
export interface BusyIntervalInput { externalUid: string; externalRevision: string; resource: string; start: Instant; end: Instant }
export interface BusyReconciliationRequest {
  expectedRevision: SafeInteger
  observedAt: Instant
  freshUntil?: Instant | null
  coverage: BusyCoverage
  status: 'fresh' | 'unavailable'
  records: ReadonlyArray<BusyIntervalInput>
}
export interface BusyCommitmentImpact { kind: string; resource: string; occupiedStart: Instant; occupiedEnd: Instant }
export interface BusyImpactSummary {
  total: SafeInteger
  detailsAvailable: boolean
  truncated: boolean
  items?: ReadonlyArray<BusyCommitmentImpact>
}
export interface BusyReconciliationCounts {
  sourceId: string
  requestDigest: string
  added: SafeInteger
  changed: SafeInteger
  deleted: SafeInteger
  retainedOutsideAuthority: SafeInteger
  retainedAcrossCoverageBoundary: SafeInteger
  impacts: BusyImpactSummary
}
export interface BusyReconciliationPreview extends BusyReconciliationCounts {
  expectedRevision: SafeInteger
  currentRevision: SafeInteger
}
export interface BusyApplyOutcome extends BusyReconciliationCounts {
  kind: 'applied' | 'already-applied'
  revision: SafeInteger
}
/** A secondary physical requirement, committed with the primary offering. */
export interface AdditionalAllocationRequest {
  offering: string
  resource?: string
  units?: SafeInteger
}
export type AllocationRequirementDocument =
  | { kind: 'primary' }
  | { kind: 'additional'; index: SafeInteger }
export interface AllocationDocument {
  requirement: AllocationRequirementDocument
  offering: string
  resource: string
  units: SafeInteger
  occupiedStart: Instant
  occupiedEnd: Instant
}
export interface OperationalAllocationDocument extends Omit<AllocationDocument, 'resource'> {
  resource?: string
}
/** Physical advice only. This read never grants admission or reserves capacity. */
export interface AvailabilityPreviewRequest {
  offering: string
  start: Instant
  durationMinutes?: SafeInteger
  resource?: string
  resourceUnits?: SafeInteger
  additionalAllocations?: ReadonlyArray<AdditionalAllocationRequest>
  party?: PartyCounts
}
export interface AvailabilityPreviewDocument {
  offering: string
  start: Instant
  end: Instant
  capacityAvailable: boolean
  publicCode?: string
}
/** A fixed verified-grant selector, never a caller-supplied manager identifier. */
export type ManagerSelection = 'schedulingManager'
/** Source-owned booking data. It grants no relationship or appointment authority. */
export interface PartyReference {
  role: 'beneficiary' | 'organization'
  reference: ExternalReference
}

/** One admission: the offering, start, and party a hold or booking asks capacity for. */
export interface AdmissionRequest {
  offering: string
  start: Instant
  durationMinutes?: SafeInteger
  resource?: string
  /** Physical units, default 1. People are counted separately. */
  resourceUnits?: SafeInteger
  additionalAllocations?: ReadonlyArray<AdditionalAllocationRequest>
  party?: PartyCounts
  manager?: ManagerSelection
  partyReferences?: ReadonlyArray<PartyReference>
  channel?: string | null
  duplicateKey?: string | null
  policyRevision: SafeInteger
  windowRevision?: SafeInteger | null
  capabilities: ReadonlyArray<string>
  prerequisites: ReadonlyArray<string>
  externalReferences?: ReadonlyArray<ExternalReference>
}

/** Exactly one of `hold` (confirm a held claim) or `admission` (book directly). */
export type CreateAppointmentRequest =
  | { hold: string; admission?: null }
  | { admission: AdmissionRequest; hold?: null }

export interface RescheduleAppointmentRequest { observedRevision: SafeInteger; admission: AdmissionRequest }
export interface CancelAppointmentRequest { observedRevision: SafeInteger; reason?: string | null }
export type AttendanceState = 'arrived' | 'completed' | 'no-show'
export interface RecordAttendanceRequest {
  observedAppointmentRevision: SafeInteger
  observedRevision: SafeInteger
  state: AttendanceState
  observedAt: Instant
}
export interface AttendanceDocument {
  appointmentId: string
  appointmentRevision: SafeInteger
  revision: SafeInteger
  state: AttendanceState
  observedAt: Instant
  recordedAt: Instant
}

export interface AvailabilitySelection {
  durationMinutes?: SafeInteger | null
  resource?: string | null
}
export interface AvailabilityQuery extends AvailabilitySelection {
  start?: Instant | null
  end?: Instant | null
  cursor?: string | null
  limit?: SafeInteger | null
}
export interface PageQuery { cursor?: string | null; limit?: SafeInteger | null }
export type OperationalTimeBasis = 'displayed' | 'occupied'
export interface OperationalAppointmentQuery {
  service: string
  location: string
  start: Instant
  end: Instant
  timeBasis: OperationalTimeBasis
  offering?: string
  state?: AppointmentState
  resource?: string
  externalReference?: ExternalReference
  profile?: string
  cursor?: string
  limit?: SafeInteger
}

export interface SchedulingServiceDocument { schedulingId: string; policyRevision: SafeInteger; policyDigest: string }
export interface ServiceDocument { id: string; label: string }
export type SchedulingMode = 'exact-time' | 'arrival-window'
export type OpeningCoverage = 'service-interval' | 'occupied-interval'
export interface ReminderDocument { minutesBefore: SafeInteger }
export interface DurationSelectionDocument {
  minimumMinutes: SafeInteger
  maximumMinutes: SafeInteger
  incrementMinutes: SafeInteger
}
export interface WindowDocument { id: string; revision: SafeInteger; start: Instant; end: Instant; units: SafeInteger }
export interface OfferingDocument {
  id: string
  service: string
  label: string
  mode: SchedulingMode
  location: string
  pool?: string
  leadTimeMinutes: SafeInteger
  horizonDays: SafeInteger
  cancellationCutoffMinutes: SafeInteger
  durationMinutes: SafeInteger | null
  durationSelection?: DurationSelectionDocument
  openingCoverage?: OpeningCoverage
  allowResourceSelection?: boolean
  partyCounts?: 'required' | 'optional'
  bufferBeforeMinutes: SafeInteger | null
  bufferAfterMinutes: SafeInteger | null
  startIncrementMinutes: SafeInteger | null
  maxRecipients: SafeInteger | null
  window: WindowDocument | null
  windows?: ReadonlyArray<WindowDocument>
  reminders: ReadonlyArray<ReminderDocument>
  requiresCapabilities: ReadonlyArray<string>
  prerequisites: ReadonlyArray<string>
}
export interface ResourceDocument { resourceId: string; pool: string; capabilities: ReadonlyArray<string>; available: boolean; capacityUnits?: SafeInteger }
export interface LocationDocument { locationId: string; timezone: string }

/** Exact-time offerings answer grid slots; arrival-window offerings answer windows. */
export type AvailabilityEntry =
  | { kind: 'slot'; start: Instant; end: Instant; free: SafeInteger; availableUnits?: SafeInteger }
  | { kind: 'window'; window: string; start: Instant; end: Instant; remaining: SafeInteger; channelRemaining: SafeInteger | null }

export interface PageDocument<T> { items: ReadonlyArray<T>; nextCursor: string | null }

export interface HoldDocument {
  allocations?: ReadonlyArray<AllocationDocument>
  holdId: string
  offering: string
  start: Instant
  end: Instant
  resource: string | null
  units: SafeInteger
  party?: PartyCounts
  manager?: ManagerSelection
  partyReferences?: ReadonlyArray<PartyReference>
  expiresAt: Instant
  policyRevision: SafeInteger
  externalReferences: ReadonlyArray<ExternalReference>
}

export type AppointmentState = 'confirmed' | 'cancelled'
export interface AppointmentDocument {
  attendance?: AttendanceDocument
  allocations?: ReadonlyArray<AllocationDocument>
  appointmentId: string
  offering: string
  start: Instant
  end: Instant
  resource: string | null
  units: SafeInteger
  party?: PartyCounts
  manager?: ManagerSelection
  partyReferences?: ReadonlyArray<PartyReference>
  channel: string | null
  revision: SafeInteger
  state: AppointmentState
  policyRevision: SafeInteger
  createdAt: Instant
  cancelledAt: Instant | null
  externalReferences: ReadonlyArray<ExternalReference>
}
export interface OperationalAppointmentDocument {
  attendance?: AttendanceDocument
  allocations?: ReadonlyArray<OperationalAllocationDocument>
  appointmentId: string
  revision: SafeInteger
  service: string
  location: string
  offering: string
  state: AppointmentState
  displayedStart: Instant
  displayedEnd: Instant
  occupiedStart?: Instant
  occupiedEnd?: Instant
  resource?: string
  units?: SafeInteger
  party?: PartyCounts
  externalReferences?: ExternalReference[]
}

export interface AppointmentHistoryEntryDocument {
  eventId: string
  kind: string
  revision: SafeInteger
  occurredAt: Instant
  actor: string | null
  detail: JsonValue
}

export interface ExplainDocument {
  offering: string
  start: Instant
  publicCode?: string
  detailedCode?: string
  explanation?: string
}

export interface SchedulingOutcome<T> { kind: 'complete'; value: T; traceId: string }

/** The closed catalogue: the client answers any other code as a protocol failure. */
export type SchedulingProblemCode =
  | 'authentication.refused'
  | 'booking.duplicate-active'
  | 'cancellation.cutoff-passed'
  | 'capability.unmatched'
  | 'capacity.exhausted'
  | 'cursor.expired'
  | 'cursor.invalid'
  | 'eligibility.unavailable'
  | 'hold.expired'
  | 'hold.released'
  | 'hook.unavailable'
  | 'horizon.outside'
  | 'idempotency.expired'
  | 'idempotency.key-reused'
  | 'location.closed'
  | 'operation.not-authorized'
  | 'party.capacity-inadequate'
  | 'policy.changed'
  | 'precondition.failed'
  | 'precondition.required'
  | 'prerequisite.missing'
  | 'profile.not-authorized'
  | 'receipt.unresolved'
  | 'request.body-too-large'
  | 'request.invalid'
  | 'request.method-not-allowed'
  | 'request.not-found'
  | 'request.unprocessable'
  | 'request.unsupported-media-type'
  | 'resource.unavailable'
  | 'revision.mismatch'
  | 'schedule.unpublished'
  | 'service.unavailable'
export type SchedulingProtocolFailure = 'header-bounds' | 'trace-context' | 'media-type' | 'body' | 'problem' | 'status' | 'protocol'

export class SchedulingClientError extends Error {
  readonly kind: 'configuration' | 'invalid-request' | 'transport' | 'problem' | 'protocol'
  /**
   * Whether the request may have taken effect although this error was
   * raised: a timeout or broken exchange after sending, an unusable answer,
   * or a 5xx. When true, recover a keyed request by sending it again under
   * the same idempotency key; a new key could apply it twice. False for a
   * configuration or request defect, a connection never established, and
   * every 4xx refusal. It is false for `410 idempotency.expired` too, but
   * there an earlier attempt under the key was answered and may have
   * committed: read an appointment by its external reference or identifier
   * before choosing a new key. A hold cannot be read and expires on its own,
   * so start a new request.
   */
  readonly outcomeUnknown: boolean
  readonly code?: SchedulingProblemCode
  readonly title?: string
  readonly detail?: string
  readonly status?: SafeInteger
  readonly traceId?: string
  readonly transportKind?: string
  readonly protocolFailure?: SchedulingProtocolFailure
}

export class SchedulingClient {
  constructor(config: SchedulingClientConfig)
  getScheduling(token: string): Promise<SchedulingOutcome<SchedulingServiceDocument>>
  listServices(token: string, cursor?: string | null): Promise<SchedulingOutcome<PageDocument<ServiceDocument>>>
  listOfferings(token: string, cursor?: string | null): Promise<SchedulingOutcome<PageDocument<OfferingDocument>>>
  availability(token: string, offering: string, query?: AvailabilityQuery | null): Promise<SchedulingOutcome<PageDocument<AvailabilityEntry>>>
  previewAvailability(token: string, request: AvailabilityPreviewRequest): Promise<SchedulingOutcome<AvailabilityPreviewDocument>>
  previewSourceBusy(token: string, profile: string, request: BusyReconciliationRequest): Promise<SchedulingOutcome<BusyReconciliationPreview>>
  /** Apply once; recover uncertainty with the exact body and expected revision. */
  applySourceBusy(token: string, profile: string, request: BusyReconciliationRequest): Promise<SchedulingOutcome<BusyApplyOutcome>>
  explain(token: string, offering: string, start: Instant, selection?: AvailabilitySelection | null): Promise<SchedulingOutcome<ExplainDocument>>
  createHold(token: string, idempotencyKey: string, request: AdmissionRequest): Promise<SchedulingOutcome<HoldDocument>>
  releaseHold(token: string, holdId: string): Promise<SchedulingOutcome<null>>
  createAppointment(token: string, idempotencyKey: string, request: CreateAppointmentRequest): Promise<SchedulingOutcome<AppointmentDocument>>
  /** Observe the original success using the same body/key and current token; never resend or mutate. */
  appointmentReceipt(token: string, idempotencyKey: string, request: CreateAppointmentRequest): Promise<SchedulingOutcome<AppointmentDocument>>
  getAppointment(token: string, appointmentId: string): Promise<SchedulingOutcome<AppointmentDocument>>
  listAppointments(token: string, reference: ExternalReference, page?: PageQuery | null): Promise<SchedulingOutcome<PageDocument<AppointmentDocument>>>
  listOperationalAppointments(token: string, query: OperationalAppointmentQuery): Promise<SchedulingOutcome<PageDocument<OperationalAppointmentDocument>>>
  rescheduleAppointment(token: string, appointmentId: string, idempotencyKey: string, request: RescheduleAppointmentRequest): Promise<SchedulingOutcome<AppointmentDocument>>
  cancelAppointment(token: string, appointmentId: string, idempotencyKey: string, request: CancelAppointmentRequest): Promise<SchedulingOutcome<AppointmentDocument>>
  recordAttendance(token: string, appointmentId: string, idempotencyKey: string, request: RecordAttendanceRequest): Promise<SchedulingOutcome<AttendanceDocument>>
  appointmentHistory(token: string, appointmentId: string, cursor?: string | null): Promise<SchedulingOutcome<PageDocument<AppointmentHistoryEntryDocument>>>
  listResources(token: string, cursor?: string | null): Promise<SchedulingOutcome<PageDocument<ResourceDocument>>>
  listLocations(token: string, cursor?: string | null): Promise<SchedulingOutcome<PageDocument<LocationDocument>>>
}
