export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }
export type JsonObject = { readonly [key: string]: JsonValue }
/** An integer that satisfies `Number.isSafeInteger` and the option's documented bounds. */
export type SafeInteger = number

export interface PrivateJwk {
  readonly kty: string
  readonly kid: string
  readonly alg: string
  readonly [member: string]: JsonValue
}

export interface PrivateKeyJwtConfig {
  tokenEndpoint: string
  clientId: string
  clientKey: PrivateJwk
  audience?: string | null
  assertionLifetimeSeconds?: SafeInteger | null
  refreshMarginSeconds?: SafeInteger | null
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
}

export type BaseRegistryAuthorization =
  | { static: string }
  | { privateKeyJwt: PrivateKeyJwtConfig }

export interface BaseRegistryClientConfig {
  baseUrl: string
  authorization?: BaseRegistryAuthorization | null
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  maxResponseBytes?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
}

export type RecordFormat = 'json' | 'json-ld'

export interface RecordOptions {
  select?: ReadonlyArray<string> | null
  accessProfile?: string | null
  format?: RecordFormat | null
}

export interface ListOptions extends RecordOptions {
  top?: SafeInteger | null
  filter?: string | null
  orderby?: string | null
  count?: boolean | null
}

export interface ListContinuation {
  route: string
  skiptoken: string
  format: RecordFormat
  accessProfile?: string | null
  registryIdentifier: string
  datasetIdentifier: string
  entityTypeIdentifier: string
}

export interface RegistryRecord {
  recordIdentifier: string
  revisionIdentifier: string
  domainData: Readonly<Record<string, JsonValue>>
  readonly [member: string]: JsonValue | undefined
}

export interface RecordMetadata {
  registryIdentifier: string
  datasetIdentifier: string
  entityTypeIdentifier: string
  readonly [member: string]: JsonValue | undefined
}

export interface RecordEnvelope {
  data: RegistryRecord
  meta: RecordMetadata
  '@context'?: string
}

export interface RecordPageInfo {
  nextCursor: string | null
  readonly [member: string]: JsonValue | undefined
}

export interface RecordCollection {
  items: ReadonlyArray<RegistryRecord>
  pageInfo: RecordPageInfo
  meta: RecordMetadata
  count?: SafeInteger
  '@context'?: string
}

export interface ProbeStatus { status: string }

export interface CompleteOutcome<T> {
  kind: 'complete'
  value: T
  traceId: string
  etag?: string
  location?: string
}

export interface PageOutcome {
  kind: 'complete'
  value: RecordCollection
  continuation?: ListContinuation
  traceId: string
  etag?: string
}

export interface RawOutcome {
  kind: 'complete'
  body: Buffer
  mediaType: string
  traceId: string
  etag?: string
}

export interface PatchOperation {
  op: 'add' | 'replace' | 'test'
  field: string
  value: JsonValue
}

export interface RemovePatchOperation {
  op: 'remove'
  field: string
}

export interface LifecycleReviewTarget {
  entityIdentifier: string
  recordIdentifier: string
  operation: 'create' | 'patch'
  baseRevision?: SafeInteger
  before?: Readonly<Record<string, JsonValue>>
  after: Readonly<Record<string, JsonValue>>
}

export interface LifecycleReview { targets: ReadonlyArray<LifecycleReviewTarget> }

export interface LifecycleReceipt extends JsonObject {
  id: string
  revision: SafeInteger
  snapshot: string
  request: JsonObject
}

/** Opaque write authority selected from metadata fetched by this client source. */
export declare class BRegCreateBinding {
  private constructor()
  private readonly __opaque: void
}
/** Opaque write authority selected from metadata fetched by this client source. */
export declare class BRegPatchBinding {
  private constructor()
  private readonly __opaque: void
}
/** Opaque lifecycle authority selected from metadata fetched by this client source. */
export declare class BRegLifecycleAuthority {
  private constructor()
  private readonly __opaque: void
}

/** Opaque executable action promoted from a metadata authority and one record. */
export declare class BRegLifecycleAction {
  private constructor()
  private readonly __opaque: void
  readonly operation: string
  readonly stage: string | null
  readonly href: string
  readonly body: JsonObject
  readonly review: LifecycleReview | null
}

/** Caller-filtered metadata bound to the exact client source that fetched it. */
export declare class BRegMetadata {
  private constructor()
  private readonly __opaque: void
  readonly registryIdentifier: string
  readonly registryVersion: string
  readonly registryRevision: string
  readonly traceId: string
  readonly etag: string | null
  selectCreate(operationIdentifier: string, expectedProfile: string): BRegCreateBinding
  selectPatch(operationIdentifier: string, expectedProfile: string): BRegPatchBinding
  selectLifecycle(entityIdentifier: string, expectedProfile: string): BRegLifecycleAuthority
}

export interface BaseRegistryClientFailure extends Error {
  readonly kind: string
  readonly code?: string
  readonly planRefusal?: string
  readonly status?: number
  readonly traceId?: string
  readonly transportKind?: string
  readonly tokenKind?: string
}

export declare class BaseRegistryClientError extends Error implements BaseRegistryClientFailure {
  readonly kind: string
  readonly code?: string
  readonly planRefusal?: string
  readonly status?: number
  readonly traceId?: string
  readonly transportKind?: string
  readonly tokenKind?: string
}

export declare class BaseRegistryClient {
  constructor(config: BaseRegistryClientConfig)
  health(): Promise<CompleteOutcome<ProbeStatus>>
  ready(): Promise<CompleteOutcome<ProbeStatus>>
  openapi(accessProfile?: string | null): Promise<RawOutcome>
  registryMetadata(accessProfile?: string | null): Promise<RawOutcome>
  registryContract(accessProfile?: string | null): Promise<BRegMetadata>
  entitySchema(entityIdentifier: string, accessProfile?: string | null): Promise<RawOutcome>
  getRecord(entityRoute: string, recordIdentifier: string, options?: RecordOptions | null): Promise<CompleteOutcome<RecordEnvelope>>
  listRecords(entityRoute: string, options?: ListOptions | null): Promise<PageOutcome>
  continueList(continuation: ListContinuation): Promise<PageOutcome>
  lookupRecord(entityRoute: string, selector: string, values?: JsonObject | null, options?: RecordOptions | null): Promise<CompleteOutcome<RecordEnvelope>>
  createRecord(binding: BRegCreateBinding, data: JsonObject, idempotencyKey: string, format?: RecordFormat | null): Promise<CompleteOutcome<RecordEnvelope>>
  patchRecord(binding: BRegPatchBinding, recordIdentifier: string, etag: string, operations: ReadonlyArray<PatchOperation | RemovePatchOperation>, idempotencyKey: string, format?: RecordFormat | null): Promise<CompleteOutcome<RecordEnvelope>>
  lifecycleActions(authority: BRegLifecycleAuthority, record: RecordEnvelope, format?: RecordFormat | null): ReadonlyArray<BRegLifecycleAction>
  executeLifecycleAction(action: BRegLifecycleAction, idempotencyKey: string): Promise<CompleteOutcome<LifecycleReceipt>>
}
