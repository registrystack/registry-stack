/** An integer for which `Number.isSafeInteger` is true. */
export type SafeInteger = number
/** A lowercase hyphenated UUID, checked by the native binding before any request is sent. */
export type MessageId = string
/** An RFC 3339 instant, parsed by the runtime. */
export type Instant = string
export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }

export interface MessagingClientConfig {
  baseUrl: string
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  maxResponseBytes?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
  /**
   * How many times a submission whose outcome is unknown is resent,
   * identically and under the same idempotency key, before its error is
   * returned: a whole number from 0 to 2, default 2; 0 sends it once. Any
   * other value is a `configuration` error.
   */
  maxMutationRetries?: SafeInteger | null
}

export type Channel = 'email' | 'sms'
export type MessageStatus = 'queued' | 'sending' | 'submitted' | 'delivered' | 'failed' | 'expired' | 'cancelled' | 'unknown'
export type MessageDispatch = 'queued' | 'sending' | 'submitted' | 'failed' | 'unknown' | 'cancelled' | 'expired'
export type MessageReport = 'none' | 'sent' | 'delivered' | 'undelivered' | 'unavailable'
export type AttemptOutcome = 'in-progress' | 'accepted' | 'transient' | 'permanent' | 'maybe-sent' | 'interrupted'

/** Exactly one email address or one E.164 phone number. */
export type Recipient = { email: string; phone?: never } | { phone: string; email?: never }
export interface TemplateReference { id: string; version: string }
export interface DirectContent { subject?: string; text: string }

/** Exactly one of `template` or `content`; `locale` and `data` accompany a template. */
export interface SubmitMessageRequest {
  senderProfile: string
  to: Recipient
  template?: TemplateReference
  locale?: string
  data?: JsonValue
  content?: DirectContent
  notBefore?: Instant
  expiresAt?: Instant
  correlationId?: string
}

export interface MessageLinks { self: string; cancel: string }
export interface MessageReceipt { id: MessageId; status: MessageStatus; links: MessageLinks }
export interface AttemptSummary {
  generation: SafeInteger
  attempt: SafeInteger
  outcome: AttemptOutcome
  startedAt: Instant
  finishedAt?: Instant
  providerReference: boolean
}
export interface MessageView {
  id: MessageId
  status: MessageStatus
  dispatch: MessageDispatch
  report: MessageReport
  reportedAt?: Instant
  channel: Channel
  senderProfile: string
  to: Recipient
  template?: TemplateReference
  correlationId?: string
  acceptedAt: Instant
  notBefore?: Instant
  expiresAt: Instant
  updatedAt: Instant
  attempts: ReadonlyArray<AttemptSummary>
  links: MessageLinks
}

export interface TemplatePreviewRequest { locale: string; data: JsonValue }
export type SmsEncoding = 'gsm7' | 'ucs2'
/** Septets for GSM-7, UTF-16 code units for UCS-2. */
export interface SegmentCount { encoding: SmsEncoding; units: SafeInteger; segments: SafeInteger }
export interface RenderedParts { subject?: string; text: string; html?: string }
export interface TemplatePreview {
  template: TemplateReference
  locale: string
  channel: Channel
  packageDigest: string
  parts: RenderedParts
  sms?: SegmentCount
}

export interface MessagingOutcome<T> { kind: 'complete'; value: T; traceId: string }

/** The closed catalogue: the client answers any other code as a protocol failure. */
export type MessagingProblemCode =
  | 'authentication.refused'
  | 'callback.unreadable'
  | 'callback.unverified'
  | 'content.invalid'
  | 'content.too-large'
  | 'content.too-many-segments'
  | 'idempotency.expired'
  | 'idempotency.key-reused'
  | 'message.dispatch-started'
  | 'message.not-visible'
  | 'message.terminal'
  | 'operation.not-authorized'
  | 'profile.not-authorized'
  | 'quota.exceeded'
  | 'rate-limit.exceeded'
  | 'request.body-too-large'
  | 'request.invalid'
  | 'request.method-not-allowed'
  | 'request.not-found'
  | 'request.unprocessable'
  | 'request.unsupported-media-type'
  | 'service.unavailable'
  | 'template.data-invalid'
  | 'template.locale-unavailable'
  | 'template.not-found'
  | 'template.render-refused'
export type MessagingProtocolFailure = 'header-bounds' | 'trace-context' | 'media-type' | 'body' | 'problem' | 'status' | 'protocol'

export class MessagingClientError extends Error {
  readonly kind: 'configuration' | 'invalid-request' | 'transport' | 'problem' | 'protocol'
  /**
   * Whether the request may have taken effect although this error was
   * raised: a timeout or broken exchange after sending, an unusable answer,
   * or a 5xx. When true, recover a keyed request by sending it again under
   * the same idempotency key; a new key could apply it twice. False for a
   * configuration or request defect, a connection never established, and
   * every 4xx refusal. It is false for `410 idempotency.expired` too, but
   * there an earlier submission under the key was accepted and its message
   * may have been sent: reconcile that submission before choosing a new key.
   */
  readonly outcomeUnknown: boolean
  readonly code?: MessagingProblemCode
  readonly title?: string
  readonly detail?: string
  readonly status?: SafeInteger
  readonly traceId?: string
  /**
   * Whole seconds a 429 limit refusal asked the caller to wait, from
   * `Retry-After`, at most one day. Absent on every other failure. The
   * client never waits on a 429 or retries it; the wait is the caller's to
   * honor.
   */
  readonly retryAfterSeconds?: SafeInteger
  readonly transportKind?: string
  readonly protocolFailure?: MessagingProtocolFailure
}

export class MessagingClient {
  constructor(config: MessagingClientConfig)
  health(): Promise<MessagingOutcome<null>>
  ready(): Promise<MessagingOutcome<null>>
  submit(token: string, idempotencyKey: string, request: SubmitMessageRequest): Promise<MessagingOutcome<MessageReceipt>>
  message(token: string, messageId: MessageId): Promise<MessagingOutcome<MessageView>>
  cancel(token: string, messageId: MessageId): Promise<MessagingOutcome<MessageView>>
  preview(token: string, templateId: string, version: string, request: TemplatePreviewRequest): Promise<MessagingOutcome<TemplatePreview>>
}
