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
}

export interface StartRunRequest { flow: string; input: JsonValue }

export interface RunStatus {
  runId: RunId
  workflowId: string
  workflowVersion: string
  definitionDigest: string
  bindingDigest: string
  step: string
  state: string
  outcome?: string | null
  output?: JsonValue | null
  failureCode?: string | null
  admittedAt: Instant
  deadlineAt: Instant
  nextDueAt?: Instant | null
  uncertain: boolean
  restoreReviewRequired: boolean
  cancelRequested: boolean
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

export interface RunInspection {
  run: RunStatus
  steps: ReadonlyArray<StepStatus>
  recovery: RecoveryStatus
}

export interface CoordinatorOutcome<T> { kind: 'complete'; value: T }
export type CoordinatorProtocolFailure = 'header_bounds' | 'media_type' | 'body' | 'problem' | 'status' | 'protocol'

export class CoordinatorClientError extends Error {
  readonly kind: 'configuration' | 'invalid_request' | 'transport' | 'problem' | 'protocol'
  /** Whether the call may have taken effect. The client never retries it. */
  readonly outcomeUnknown: boolean
  readonly code?: string
  readonly status?: SafeInteger
  readonly transportKind?: string
  readonly protocolFailure?: CoordinatorProtocolFailure
}

export class CoordinatorClient {
  constructor(config: CoordinatorClientConfig)
  /** Start exactly once with the caller's unchanged key and input. */
  start(token: string, idempotencyKey: string, request: StartRunRequest): Promise<CoordinatorOutcome<RunStatus>>
  status(token: string, runId: RunId): Promise<CoordinatorOutcome<RunStatus>>
  inspect(token: string, runId: RunId): Promise<CoordinatorOutcome<RunInspection>>
  /** Read the original operation's receipt and update recovery state. Never resubmits the operation. */
  reconcile(token: string, runId: RunId, reason: string): Promise<CoordinatorOutcome<RunInspection>>
}
