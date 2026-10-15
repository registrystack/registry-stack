/** An integer for which `Number.isSafeInteger` is true. */
export type SafeInteger = number
/** A lowercase hyphenated UUID, checked before any request is sent. */
export type RunId = string
/** An RFC 3339 instant returned by Coordinator. */
export type Instant = string
export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }

export interface CoordinatorClientConfig {
  baseUrl: string
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  maxResponseBytes?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
  /**
   * How many times an admission whose outcome is unknown is resent,
   * identically and under the same idempotency key, before its error is
   * returned: a whole number from 0 to 2, default 2; 0 sends it once. Any
   * other value is a `configuration` error.
   */
  maxMutationRetries?: SafeInteger | null
}

export interface StartRunRequest { workflow: string; workflowRevision: string; input: JsonValue }

/** The active compiled contract under current start authority. */
export interface WorkflowContract {
  workflow: string
  workflowRevision: string
  input: JsonValue
  outcomes: { readonly [name: string]: JsonValue }
}

export interface RunStatus {
  runId: RunId
  workflow: string
  workflowRevision: string

  bindingDigest: string
  step: string
  state: string
  outcome?: string | null
  output?: JsonValue | null
  failureCode?: string | null
  /** Where a refused call input left its operation contract, as an RFC 6901 pointer that names no value. */
  failurePath?: string | null
  admittedAt: Instant
  deadlineAt: Instant
  nextDueAt?: Instant | null
  uncertain: boolean
  restoreReviewRequired: boolean
  cancelRequested: boolean
  authoredCancelRequested: boolean
}

export interface StepStatus {
  step: string
  state: string
  generation: SafeInteger
  attempt: SafeInteger
  nextDueAt?: Instant | null
  leaseExpiresAt?: Instant | null
  commandPrepared: boolean
  uncertain: boolean
  receiptExpired: boolean
  failureCode?: string | null
  /** Where a refused call input left its operation contract, as an RFC 6901 pointer that names no value. */
  failurePath?: string | null
}

export type RetryBlockReason =
  | 'not-recoverable'
  | 'deadline-reached'
  | 'receipt-expired'
  | 'binding-changed'
  | 'other-binding-live'
  | 'snapshot-incompatible'
  | 'cancelled'
  | 'restore-hold'
  | 'restore-review-required'
  | 'payload-erased'
  | 'evaluation-uncertain'

/** Coordinator-authored operation identifier. */
export type OperationId = string
export type OperationEffect = 'read' | 'mutation' | 'evaluation'
export type OperationKeyRequirement = 'none' | 'required'
export type OperationRecovery = 'read-again' | 'same-command-and-receipt' | 'same-command' | 'hold-after-dispatch'

/** Pinned public contract metadata. It does not establish current authority. */
export interface OperationIdentity {
  id: OperationId
  version: SafeInteger
  product: string
  effect: OperationEffect
  keyRequirement: OperationKeyRequirement
  requiresPreparation: boolean
  recovery: OperationRecovery
  readReceipt: boolean
}

export interface RecoveryStatus {
  retryAllowed: boolean
  reason?: RetryBlockReason | null
  operation?: OperationIdentity
}

export type EffectState = 'accepted' | 'unknown'
export interface EffectStatus {
  step: string
  operation: OperationIdentity
  operationRevision: string
  state: EffectState
}
export interface WaitStatus {
  step: string
  acceptedStep: string
  completion: string
  completionRevision: string
  timeoutAt: Instant
  nextObservationAt: Instant | null
  notBefore: Instant
  minimumIntervalSeconds: SafeInteger
  observations: SafeInteger
  observationLimit: SafeInteger
}

export interface RunInspection {
  run: RunStatus
  steps: ReadonlyArray<StepStatus>
  effects: ReadonlyArray<EffectStatus>
  waits: ReadonlyArray<WaitStatus>
  recovery: RecoveryStatus
}

export type RunListState =
  | 'running'
  | 'finished'
  | 'failed'
  | 'cancelled'
  | 'cancelled-after-effect'
  | 'expired'
  | 'attention'
  | 'cancel-requested'

/** One stable page of runs the caller may read, newest admission first. */
export interface RunList { runs: ReadonlyArray<RunStatus>; nextCursor?: string }

/** The runtime accepted a same-command retry; the worker has not run it yet. */
export interface RetryScheduled { runId: RunId; status: 'retry-scheduled' }

export interface CoordinatorOutcome<T> { kind: 'complete'; value: T }
export type CoordinatorProtocolFailure = 'header-bounds' | 'media-type' | 'body' | 'problem' | 'status' | 'protocol'

export class CoordinatorClientError extends Error {
  readonly kind: 'configuration' | 'invalid-request' | 'transport' | 'problem' | 'protocol'
  /**
   * Whether the call may have taken effect although this error was raised:
   * a timeout or broken exchange after sending, an unusable answer, or a
   * 5xx. When true for `start`, recover by sending the same workflow, revision, and input
   * again under the same idempotency key; a new key could admit a second
   * run. When true for `retrySame` or `cancel`, which take no key and are
   * never resent, read the run before asking again. False for a
   * configuration or request defect, a connection never established, and
   * every 4xx refusal.
   */
  readonly outcomeUnknown: boolean
  /**
   * The `family.reason` code of the RFC 9457 problem document the service
   * answered, such as `run.not-visible`, present only when `kind` is
   * `'problem'`. The service's title and detail are never copied.
   */
  readonly code?: string
  readonly status?: SafeInteger
  readonly transportKind?: string
  readonly protocolFailure?: CoordinatorProtocolFailure
}

export class CoordinatorClient {
  constructor(config: CoordinatorClientConfig)
  /**
   * Admit `{workflow, workflowRevision, input}` under the caller's key. Fresh
   * starts must match the active revision. Recover unknown admissions with the
   * original revision even after activation changes. An unknown outcome is resent with
   * the same key and body at most `maxMutationRetries` times; a 4xx is never
   * resent. The key is scoped to the caller and the workflow, so the same key
   * under two workflows starts two runs, and an allowed workflow the deployment does
   * not serve is refused with 404 `workflow.not-served`, a known outcome never resent.
   */
  start(token: string, idempotencyKey: string, request: StartRunRequest): Promise<CoordinatorOutcome<RunStatus>>
  /** Discover the active typed contract under current start authority; starts no run. */
  workflow(token: string, workflow: string): Promise<CoordinatorOutcome<WorkflowContract>>
  status(token: string, runId: RunId): Promise<CoordinatorOutcome<RunStatus>>
  inspect(token: string, runId: RunId): Promise<CoordinatorOutcome<RunInspection>>
  /** Read the original operation's receipt and update recovery state. Never resubmits the operation. */
  reconcile(token: string, runId: RunId, reason: string): Promise<CoordinatorOutcome<RunInspection>>
  /**
   * Read one stable page of caller-visible runs. Pass `nextCursor` unchanged
   * with the same caller, `state`, and `attention` values. `attention: true`
   * selects the effective states `attention` and `failed`.
   */
  list(token: string, limit: SafeInteger, cursor?: string | null, state?: RunListState | null, attention?: boolean | null): Promise<CoordinatorOutcome<RunList>>
  /**
   * Schedule the run's saved command again, unchanged, when its inspection
   * allows a retry. Takes no idempotency key, so it is sent exactly once. `reason` is
   * 1 to 256 bytes without control characters, checked before sending.
   */
  retrySame(token: string, runId: RunId, reason: string): Promise<CoordinatorOutcome<RetryScheduled>>
  /**
   * Stop further progression. Never undoes a product effect. Takes no
   * idempotency key, so it is sent exactly once. `reason` is 1 to 256 bytes
   * without control characters, checked before sending.
   */
  cancel(token: string, runId: RunId, reason: string): Promise<CoordinatorOutcome<RunStatus>>
}
