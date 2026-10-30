import {
  CoordinatorClient,
  CoordinatorClientError,
  type CoordinatorOutcome,
  type RetryScheduled,
  type RunInspection,
  type RunList,
  type RunStatus,
  type StepStatus,
  type WaitStatus,
  type WorkflowContract,
} from '../client'

const client = new CoordinatorClient({
  baseUrl: 'https://coordinator.example.invalid/',
  attemptTimeoutMilliseconds: 5_000,
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
const followed: Promise<CoordinatorOutcome<RunList>> = client.list(
  'header.payload.signature', 20, null, null, null, '0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d', 'official',
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
void [started, status, inspected, reconciled, listed, attention, followed, retried, cancelled]

declare const run: RunStatus
declare const step: StepStatus
const runFailurePath: string | null | undefined = run.failurePath
const stepFailurePath: string | null | undefined = step.failurePath
void [runFailurePath, stepFailurePath]
const heldOn: string | undefined = step.holdDetail?.date
const inForce: string[] | undefined = step.holdDetail?.recordIdentifiers
void [heldOn, inForce]

declare const wait: WaitStatus
const turn: string | undefined = wait.lastObservation?.turn
const submissionVersion: number | undefined = wait.lastObservation?.submissionVersion
const requestLink: string | undefined = wait.requestLink
void [turn, submissionVersion, requestLink]
// @ts-expect-error a turn filter is one of party, official or nobody
client.list('header.payload.signature', 20, null, null, null, null, 'someone')

declare const error: CoordinatorClientError
if (error.kind === 'problem') {
  const code: string | undefined = error.code
  void code
}

// @ts-expect-error Coordinator start requires a caller-selected idempotency key.
client.start('header.payload.signature', { workflow: 'decision-follow-up', "workflowRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000", input: {} })
const once = new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', maximumMutationRetries: 0 })
void once
// @ts-expect-error The retry count is a number, never a string.
new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', maximumMutationRetries: '2' })
// @ts-expect-error null is a value, not omission, for configuration members.
new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', attemptTimeoutMilliseconds: null })
// @ts-expect-error trusted roots are PEM text, not binary data.
new CoordinatorClient({ baseUrl: 'https://coordinator.example.invalid/', trustedRootCertificates: Buffer.from('not PEM text') })

const workflow: Promise<CoordinatorOutcome<WorkflowContract>> = client.workflow('token', 'decision-follow-up')
declare const contract: WorkflowContract
// @ts-expect-error a workflow contract carries no review policy
void contract.reviewPolicy
// @ts-expect-error a new admission always pins the computed workflow revision
client.start('token', 'key', { workflow: 'decision-follow-up', input: {} })
void workflow
