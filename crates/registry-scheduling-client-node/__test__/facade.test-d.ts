import {
  SchedulingClient,
  SchedulingClientError,
  type AdmissionRequest,
  type AllocationDocument,
  type AppointmentDocument,
  type AvailabilityEntry,
  type AvailabilityPreviewRequest,
  type AvailabilityPreviewDocument,
  type BusyReconciliationRequest,
  type BusyReconciliationPreview,
  type BusyApplyOutcome,
  type OperationalAllocationDocument,
  type ExternalReference,
  type HoldDocument,
  type OfferingDocument,
  type OperationalAppointmentDocument,
  type OperationalAppointmentQuery,
  type PageDocument,
  type SchedulingOutcome,
  type SchedulingProblemCode,
  type SchedulingProtocolFailure,
  type SchedulingServiceDocument,
} from '../client'

const client = new SchedulingClient({ baseUrl: 'https://scheduling.example.test/' })
const configWithAlignedNames = new SchedulingClient({
  baseUrl: 'https://scheduling.example.test/',
  maximumResponseBytes: 1500,
  trustedRootCertificates: '-----BEGIN CERTIFICATE-----\nplaceholder\n-----END CERTIFICATE-----',
})
// @ts-expect-error the public response-bound name is maximumResponseBytes
new SchedulingClient({ baseUrl: 'https://scheduling.example.test/', maxResponseBytes: 1500 })
// @ts-expect-error null is not an omission in JavaScript configuration
new SchedulingClient({ baseUrl: 'https://scheduling.example.test/', attemptTimeoutMilliseconds: null })
void configWithAlignedNames
const once = new SchedulingClient({ baseUrl: 'https://scheduling.example.test/', maximumMutationRetries: 0 })
void once
const token: string = 'header.payload.signature'
const busy: BusyReconciliationRequest = {
  expectedRevision: 0, observedAt: '2026-10-05T08:00:00Z', status: 'unavailable',
  coverage: { start: '2026-10-05T00:00:00Z', end: '2026-10-06T00:00:00Z', resources: ['room-a'] },
  records: [],
}
const busyPreview: Promise<SchedulingOutcome<BusyReconciliationPreview>> = client.previewSourceBusy(token, 'calendar-main', busy)
const busyApplied: Promise<SchedulingOutcome<BusyApplyOutcome>> = client.applySourceBusy(token, 'calendar-main', busy)
void [busyPreview, busyApplied]
// @ts-expect-error Descriptions and attendees are outside the minimized busy contract.
const invalidBusy: BusyReconciliationRequest = { ...busy, attendees: [] }
void invalidBusy
const appointmentId = '0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0f'
const reference: ExternalReference = { product: 'casework', recordType: 'review-task', identifier: 'case:1234' }
const admission: AdmissionRequest = {
  offering: 'registry-update-30',
  start: '2026-10-05T09:00:00Z',
  durationMinutes: 1500,
  resource: 'clerk-2',
  resourceUnits: 1,
  additionalAllocations: [{ offering: 'chairs', units: 30 }],
  party: { recipients: 1, attendees: 1 },
  policyRevision: 3,
  capabilities: [],
  prerequisites: [],
  externalReferences: [reference],
}
const roomAdmission: AdmissionRequest = {
  offering: 'meeting-room',
  start: '2026-11-05T09:00:00Z',
  policyRevision: 3,
  capabilities: [],
  prerequisites: [],
  manager: 'schedulingManager',
  partyReferences: [{ role: 'organization', reference }],
}
void roomAdmission
const preview: AvailabilityPreviewRequest = {
  offering: 'meeting-room', start: admission.start,
  additionalAllocations: [{ offering: 'chairs', units: 30 }],
}
const previewAnswer: Promise<SchedulingOutcome<AvailabilityPreviewDocument>> = client.previewAvailability(token, preview)
const projectedAllocation: OperationalAllocationDocument = {
  requirement: { kind: 'primary' }, offering: 'meeting-room', units: 1,
  occupiedStart: admission.start, occupiedEnd: '2026-10-05T10:00:00Z',
}
void previewAnswer
void projectedAllocation
const allocation: AllocationDocument = {
  requirement: { kind: 'additional', index: 0 },
  offering: 'chairs',
  resource: 'chairs-a',
  units: 30,
  occupiedStart: '2026-10-05T09:00:00Z',
  occupiedEnd: '2026-10-05T11:00:00Z',
}
void allocation
const offering: OfferingDocument = {
  id: 'registry-update-30',
  service: 'registry-update',
  label: 'Registry update',
  mode: 'exact-time',
  location: 'office-1',
  pool: 'clerks',
  leadTimeMinutes: 60,
  horizonDays: 30,
  cancellationCutoffMinutes: 120,
  durationMinutes: 30,
  durationSelection: { minimumMinutes: 15, maximumMinutes: 10_080, incrementMinutes: 15 },
  openingCoverage: 'occupied-interval',
  allowResourceSelection: true,
  bufferBeforeMinutes: 5,
  bufferAfterMinutes: 5,
  startIncrementMinutes: 15,
  maxRecipients: 1,
  window: null,
  reminders: [],
  requiresCapabilities: [],
  prerequisites: [],
}
void offering
const distribution: OfferingDocument = {
  id: 'distribution-day',
  service: 'food-distribution',
  label: 'Distribution day',
  mode: 'arrival-window',
  location: 'office-1',
  leadTimeMinutes: 60,
  horizonDays: 30,
  cancellationCutoffMinutes: 0,
  durationMinutes: null,
  bufferBeforeMinutes: null,
  bufferAfterMinutes: null,
  startIncrementMinutes: null,
  maxRecipients: null,
  window: null,
  windows: [
    { id: 'day-one', revision: 1, start: '2026-10-05T09:00:00Z', end: '2026-10-05T11:00:00Z', units: 12 },
    { id: 'day-two', revision: 2, start: '2026-10-12T09:00:00Z', end: '2026-10-12T11:00:00Z', units: 8 },
  ],
  reminders: [],
  requiresCapabilities: [],
  prerequisites: [],
}
void distribution

const service: Promise<SchedulingOutcome<SchedulingServiceDocument>> = client.getScheduling(token)
const slots: Promise<SchedulingOutcome<PageDocument<AvailabilityEntry>>> = client.availability(
  token,
  'registry-update-30',
  { start: '2026-10-05T08:00:00Z', limit: 25, durationMinutes: 45, resource: 'clerk-2' },
)
const hold: Promise<SchedulingOutcome<HoldDocument>> = client.createHold(token, 'hold-1', admission)
const operationalQuery: OperationalAppointmentQuery = {
  service: 'registry-update',
  location: 'office-1',
  start: '2026-10-05T09:00:00Z',
  end: '2026-10-07T09:00:00Z',
  timeBasis: 'occupied',
  externalReference: reference,
  profile: 'desk',
}
const operational: Promise<SchedulingOutcome<PageDocument<OperationalAppointmentDocument>>> =
  client.listOperationalAppointments(token, operationalQuery)
const released: Promise<SchedulingOutcome<null>> = client.releaseHold(token, 'hold-id')
const confirmed: Promise<SchedulingOutcome<AppointmentDocument>> = client.createAppointment(token, 'confirm-1', { hold: 'hold-id' })
const direct: Promise<SchedulingOutcome<AppointmentDocument>> = client.createAppointment(token, 'direct-1', { admission })
const listed: Promise<SchedulingOutcome<PageDocument<AppointmentDocument>>> = client.listAppointments(token, reference, { limit: 10 })
const cancelled: Promise<SchedulingOutcome<AppointmentDocument>> = client.cancelAppointment(
  token,
  appointmentId,
  'cancel-1',
  { observedRevision: 1, reason: 'moved away' },
)
void service
void slots
void hold
void operational
void released
void confirmed
void direct
void listed
void cancelled
void client.listServices(token)
void client.listOfferings(token, 'cursor-1')
void client.explain(token, 'registry-update-30', '2026-10-05T09:00:00Z', { durationMinutes: 45, resource: 'clerk-2' })
void client.getAppointment(token, appointmentId)
void client.rescheduleAppointment(token, appointmentId, 'move-1', { observedRevision: 1, admission })
void client.appointmentHistory(token, appointmentId)
void client.listResources(token)
void client.listLocations(token, null)

async function freeAt(): Promise<number> {
  const outcome = await client.availability(token, 'registry-update-30')
  const traceId: string = outcome.traceId
  void traceId
  let free = 0
  for (const entry of outcome.value.items) {
    free += entry.kind === 'slot' ? entry.free : entry.remaining
  }
  return free
}
void freeAt

function recover(error: unknown): SchedulingProblemCode | SchedulingProtocolFailure | undefined {
  if (!(error instanceof SchedulingClientError)) return undefined
  if (error.kind === 'problem') return error.code
  return error.protocolFailure
}
void recover

const known: SchedulingProblemCode = 'capacity.exhausted'
void known

// @ts-expect-error the closed catalogue names no rate limit
const unknown: SchedulingProblemCode = 'rate-limit.exceeded'
void unknown
// @ts-expect-error an appointment confirms a hold or books from an admission
void client.createAppointment(token, 'confirm-2', {})
// @ts-expect-error the idempotency key is required
void client.createHold(token, admission)
// @ts-expect-error a cancellation names the revision it observed
void client.cancelAppointment(token, appointmentId, 'cancel-2', {})

function mayHaveTakenEffect(error: SchedulingClientError): boolean {
  const unknown: boolean = error.outcomeUnknown
  return unknown
}
void mayHaveTakenEffect

const observedReceipt: Promise<SchedulingOutcome<AppointmentDocument>> = client.appointmentReceipt(token, 'original-key', { admission })
void observedReceipt
const unresolved: SchedulingProblemCode = 'receipt.unresolved'
void unresolved
// @ts-expect-error receipt observation requires the original caller key
void client.appointmentReceipt(token, { admission })

void client.recordAttendance(token, appointmentId, 'observation-1', {
  observedAppointmentRevision: 7,
  observedRevision: 0,
  state: 'arrived',
  observedAt: '2026-10-05T09:05:00Z',
}).then(outcome => {
  const state: import('../client').AttendanceState = outcome.value.state
  const observedVisit: number = outcome.value.appointmentRevision
  void state
  void observedVisit
})
