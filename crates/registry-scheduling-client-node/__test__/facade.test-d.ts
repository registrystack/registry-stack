import {
  SchedulingClient,
  SchedulingClientError,
  type AdmissionRequest,
  type AppointmentDocument,
  type AvailabilityEntry,
  type ExternalReference,
  type HoldDocument,
  type PageDocument,
  type SchedulingOutcome,
  type SchedulingProblemCode,
  type SchedulingProtocolFailure,
  type SchedulingServiceDocument,
} from '../client'

const client = new SchedulingClient({ baseUrl: 'https://scheduling.example.test/' })
const once = new SchedulingClient({ baseUrl: 'https://scheduling.example.test/', maxMutationRetries: 0 })
void once
const token: string = 'header.payload.signature'
const appointmentId = '0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0f'
const reference: ExternalReference = { product: 'casework', recordType: 'review-task', identifier: 'case:1234' }
const admission: AdmissionRequest = {
  offering: 'registry-update-30',
  start: '2026-10-05T09:00:00Z',
  party: { recipients: 1, attendees: 1 },
  policyRevision: 3,
  capabilities: [],
  prerequisites: [],
  externalReferences: [reference],
}

const service: Promise<SchedulingOutcome<SchedulingServiceDocument>> = client.getScheduling(token)
const slots: Promise<SchedulingOutcome<PageDocument<AvailabilityEntry>>> = client.availability(
  token,
  'registry-update-30',
  { start: '2026-10-05T08:00:00Z', limit: 25 },
)
const hold: Promise<SchedulingOutcome<HoldDocument>> = client.createHold(token, 'hold-1', admission)
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
void released
void confirmed
void direct
void listed
void cancelled
void client.listServices(token)
void client.listOfferings(token, 'cursor-1')
void client.explain(token, 'registry-update-30', '2026-10-05T09:00:00Z')
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
