import { CoordinatorClient } from '../index'
import type {
  CoordinatorOutcome,
  RunInspection,
  RunStatus,
} from '../client'

const client = new CoordinatorClient({
  baseUrl: 'https://coordinator.example.invalid/',
  requestTimeoutMilliseconds: 5_000,
})

const started: Promise<CoordinatorOutcome<RunStatus>> = client.start(
  'header.payload.signature',
  'admission 42',
  { flow: 'decision-follow-up', input: { caseId: 'case-42' } },
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
void [started, status, inspected, reconciled]

// @ts-expect-error Coordinator start requires a caller-selected idempotency key.
client.start('header.payload.signature', { flow: 'decision-follow-up', input: {} })
// @ts-expect-error Coordinator has no retry count because it never retries calls.
new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', maxMutationRetries: 2 })
// @ts-expect-error Coordinator exposes only its four maintained operations.
client.retry('header.payload.signature', '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d')
