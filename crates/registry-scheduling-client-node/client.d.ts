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
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  maxResponseBytes?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
  /**
   * How many times a keyed command (hold, appointment create, reschedule,
   * cancel) whose outcome is unknown is resent, identically and under the
   * same idempotency key, before its error is returned: a whole number from 0
   * to 2, default 2; 0 sends it once. Any other value is a `configuration`
   * error.
   */
  maxMutationRetries?: SafeInteger | null
}

/** An opaque record link Scheduling retains with a hold or appointment. */
export interface ExternalReference {
  product: string
  recordType: string
  identifier: string
}

export interface PartyCounts { recipients: SafeInteger; attendees: SafeInteger }

/** One admission: the offering, start, and party a hold or booking asks capacity for. */
export interface AdmissionRequest {
  offering: string
  start: Instant
  party: PartyCounts
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

export interface AvailabilityQuery {
  start?: Instant | null
  end?: Instant | null
  cursor?: string | null
  limit?: SafeInteger | null
}
export interface PageQuery { cursor?: string | null; limit?: SafeInteger | null }

export interface SchedulingServiceDocument { schedulingId: string; policyRevision: SafeInteger; policyDigest: string }
export interface ServiceDocument { id: string; label: string }
export type SchedulingMode = 'exact-time' | 'arrival-window'
export interface ReminderDocument { minutesBefore: SafeInteger }
export interface WindowDocument { id: string; revision: SafeInteger; start: Instant; end: Instant; units: SafeInteger }
export interface OfferingDocument {
  id: string
  service: string
  label: string
  mode: SchedulingMode
  location: string
  leadTimeMinutes: SafeInteger
  horizonDays: SafeInteger
  cancellationCutoffMinutes: SafeInteger
  durationMinutes: SafeInteger | null
  bufferBeforeMinutes: SafeInteger | null
  bufferAfterMinutes: SafeInteger | null
  startIncrementMinutes: SafeInteger | null
  maxRecipients: SafeInteger | null
  window: WindowDocument | null
  reminders: ReadonlyArray<ReminderDocument>
  requiresCapabilities: ReadonlyArray<string>
  prerequisites: ReadonlyArray<string>
}
export interface ResourceDocument { resourceId: string; pool: string; capabilities: ReadonlyArray<string>; available: boolean }
export interface LocationDocument { locationId: string; timezone: string }

/** Exact-time offerings answer grid slots; arrival-window offerings answer windows. */
export type AvailabilityEntry =
  | { kind: 'slot'; start: Instant; end: Instant; free: SafeInteger }
  | { kind: 'window'; window: string; start: Instant; end: Instant; remaining: SafeInteger; channelRemaining: SafeInteger | null }

export interface PageDocument<T> { items: ReadonlyArray<T>; nextCursor: string | null }

export interface HoldDocument {
  holdId: string
  offering: string
  start: Instant
  end: Instant
  resource: string | null
  units: SafeInteger
  expiresAt: Instant
  policyRevision: SafeInteger
  externalReferences: ReadonlyArray<ExternalReference>
}

export type AppointmentState = 'confirmed' | 'cancelled'
export interface AppointmentDocument {
  appointmentId: string
  offering: string
  start: Instant
  end: Instant
  resource: string | null
  units: SafeInteger
  channel: string | null
  revision: SafeInteger
  state: AppointmentState
  policyRevision: SafeInteger
  createdAt: Instant
  cancelledAt: Instant | null
  externalReferences: ReadonlyArray<ExternalReference>
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
export type SchedulingProtocolFailure = 'header_bounds' | 'trace_context' | 'media_type' | 'body' | 'problem' | 'status' | 'protocol'

export class SchedulingClientError extends Error {
  readonly kind: 'configuration' | 'invalid_request' | 'transport' | 'problem' | 'protocol'
  /**
   * Whether the request may have taken effect although this error was
   * raised: a timeout or broken exchange after sending, an unusable answer,
   * or a 5xx. When true, recover a keyed request by sending it again under
   * the same idempotency key; a new key could apply it twice. False for a
   * configuration or request defect, a connection never established, and
   * every 4xx refusal.
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
  explain(token: string, offering: string, start: Instant): Promise<SchedulingOutcome<ExplainDocument>>
  createHold(token: string, idempotencyKey: string, request: AdmissionRequest): Promise<SchedulingOutcome<HoldDocument>>
  releaseHold(token: string, holdId: string): Promise<SchedulingOutcome<null>>
  createAppointment(token: string, idempotencyKey: string, request: CreateAppointmentRequest): Promise<SchedulingOutcome<AppointmentDocument>>
  getAppointment(token: string, appointmentId: string): Promise<SchedulingOutcome<AppointmentDocument>>
  listAppointments(token: string, reference: ExternalReference, page?: PageQuery | null): Promise<SchedulingOutcome<PageDocument<AppointmentDocument>>>
  rescheduleAppointment(token: string, appointmentId: string, idempotencyKey: string, request: RescheduleAppointmentRequest): Promise<SchedulingOutcome<AppointmentDocument>>
  cancelAppointment(token: string, appointmentId: string, idempotencyKey: string, request: CancelAppointmentRequest): Promise<SchedulingOutcome<AppointmentDocument>>
  appointmentHistory(token: string, appointmentId: string, cursor?: string | null): Promise<SchedulingOutcome<PageDocument<AppointmentHistoryEntryDocument>>>
  listResources(token: string, cursor?: string | null): Promise<SchedulingOutcome<PageDocument<ResourceDocument>>>
  listLocations(token: string, cursor?: string | null): Promise<SchedulingOutcome<PageDocument<LocationDocument>>>
}
