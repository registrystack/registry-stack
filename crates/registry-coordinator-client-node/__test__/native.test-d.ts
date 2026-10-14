import { CoordinatorClient } from '../index'
import type {
  CoordinatorOutcome,
  RetryScheduled,
  RunInspection,
  RunList,
  RunStatus,
} from '../client'

const client = new CoordinatorClient({
  baseUrl: 'https://coordinator.example.invalid/',
  requestTimeoutMilliseconds: 5_000,
})

const started: Promise<CoordinatorOutcome<RunStatus>> = client.start(
  'header.payload.signature',
  'admission 42',
  { workflow: 'decision-follow-up', "workflowRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000", input: { caseId: 'case-42' } },
)
const status: Promise<CoordinatorOutcome<RunStatus>> = client.status(
  'header.payload.signature',
  '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d',
)
const inspected: Promise<CoordinatorOutcome<RunInspection>> = client.inspect(
  'header.payload.signature',
  '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d',
)
const reconciled: Promise<CoordinatorOutcome<RunInspection>> = client.reconcile(
  'header.payload.signature',
  '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d',
  'operator reviewed the original receipt',
)
const listed: Promise<CoordinatorOutcome<RunList>> = client.list('header.payload.signature', 20)
const attention: Promise<CoordinatorOutcome<RunList>> = client.list(
  'header.payload.signature', 20, 'opaque', 'attention', true,
)
const retried: Promise<CoordinatorOutcome<RetryScheduled>> = client.retrySame(
  'header.payload.signature',
  '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d',
  'operator reviewed the inspection',
)
const cancelled: Promise<CoordinatorOutcome<RunStatus>> = client.cancel(
  'header.payload.signature',
  '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d',
  'caller withdrew the request',
)
void [started, status, inspected, reconciled, listed, attention, retried, cancelled]

// @ts-expect-error Coordinator start requires a caller-selected idempotency key.
client.start('header.payload.signature', { workflow: 'decision-follow-up', "workflowRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000", input: {} })
const once = new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', maxMutationRetries: 0 })
void once
// @ts-expect-error The retry count is a number, never a string.
new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', maxMutationRetries: '2' })
// @ts-expect-error Operator routes belong to coordinatorctl, not the client.
client.doctor('header.payload.signature')
