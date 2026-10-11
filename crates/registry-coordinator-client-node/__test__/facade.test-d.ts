import {
  CoordinatorClient,
  CoordinatorClientError,
  type CoordinatorOutcome,
  type RetryScheduled,
  type RunInspection,
  type RunList,
  type RunStatus,
  type StepStatus,
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
const listed: Promise<CoordinatorOutcome<RunList>> = client.list('header.payload.signature', 20)
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
void [started, status, inspected, reconciled, listed, retried, cancelled]

declare const run: RunStatus
declare const step: StepStatus
const runFailurePath: string | null | undefined = run.failurePath
const stepFailurePath: string | null | undefined = step.failurePath
void [runFailurePath, stepFailurePath]

declare const error: CoordinatorClientError
if (error.kind === 'problem') {
  const code: string | undefined = error.code
  void code
}

// @ts-expect-error Coordinator start requires a caller-selected idempotency key.
client.start('header.payload.signature', { flow: 'decision-follow-up', input: {} })
const once = new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', maxMutationRetries: 0 })
void once
// @ts-expect-error The retry count is a number, never a string.
new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', maxMutationRetries: '2' })
