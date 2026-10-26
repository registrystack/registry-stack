export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }
/** Structured mutation inputs reject integer-valued numbers outside
 * `Number.isSafeInteger`. Use the corresponding `...Json` method for exact
 * wider integer values. */
export type JsonObject = { readonly [key: string]: JsonValue }
/** An integer that satisfies `Number.isSafeInteger` and the option's documented bounds. */
export type SafeInteger = number

export type HookVerificationRefusalCode =
  | 'missing-header'
  | 'invalid-delivery-time'
  | 'duplicate-header'
  | 'body-too-large'
  | 'invalid-key'
  | 'malformed-signature'
  | 'signature-mismatch'
  | 'unsupported-version'

export interface HookDeliveryInput {
  method: string
  path: string
  headers: Readonly<Record<string, string>>
  /** Exact bytes in a non-shared backing store. */
  body: Buffer
  /** Secret bytes in a non-shared backing store. */
  key: Buffer
}

export interface VerifiedHookDelivery {
  readonly id: string
  readonly source: string
  readonly type: string
  readonly time: string
  readonly dataschema: string
  readonly generation: string
  readonly attempt: string
  readonly deliveryTime: string
  readonly idempotencyKey: string
  readonly body: Buffer
}

/**
 * Authenticate one exact Base Registry Engine Version 1 hook delivery.
 * Apply delivery-time skew and idempotency policy before acting on the body.
 */
export declare function verifyHookDelivery(input: HookDeliveryInput): VerifiedHookDelivery

/**
 * Project one record revision into the occurrence view. `argumentsJson` is a
 * JSON object with `registryRevision`, `recordType`, `descriptor`, `record`
 * and optional `creationRevision`, `actionReceipts` and
 * `proposalApplications`. The result is the view document as JSON text.
 * Failures carry kind `occurrence` and one of the codes `not-an-occurrence`,
 * `unsupported-version`, `malformed-descriptor`, `wrong-record-evidence`,
 * `revision-mismatch`, `incompatible-metadata` or `invalid-input`.
 */
export declare function occurrenceView(argumentsJson: string): string

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
  /**
   * The audience of the client assertion (who checks the client's
   * authentication). Defaults to the token endpoint URL. This is not the
   * `resource` of the token request.
   */
  audience?: string
  /**
   * The RFC 8707 resource indicator the token is requested for: the resource
   * server's registered identifier, not a URL to fetch.
   */
  resource?: string
  /**
   * The scopes requested for the token, sent as one space-delimited `scope`
   * parameter. A requested scope may narrow the client's registered
   * permission set; it can never widen it.
   */
  scopes?: ReadonlyArray<string>
  assertionLifetimeSeconds?: SafeInteger
  refreshMarginSeconds?: SafeInteger
  attemptTimeoutMilliseconds?: SafeInteger
  connectTimeoutMilliseconds?: SafeInteger
  userAgent?: string
  trustedRootCertificates?: string
}

/** OAuth credentials are returned to the caller. Keep them out of logs and persistence. */
export class PrivateKeyJwt {
  constructor(config: PrivateKeyJwtConfig)
  /** Fresh RFC 8693 exchange. Requires resource and scopes; never shares the service cache. */
  exchange(subjectToken: string): Promise<string>
  /** Client credentials with the shared provider's bounded service-token cache. */
  bearerToken(): Promise<string>
}

/** One immutable verified person or grant context. Reconstruct after host source facts change. */
export interface ExchangeContext {
  issuer: string
  subject: string
  audience: string
  generation: string
  deadlineSeconds: SafeInteger
  grantId?: string
}

export type ExchangePrivateKeyJwtConfig = PrivateKeyJwtConfig & {
  resource: string
  scopes: ReadonlyArray<string>
}

export interface FirstPartyExchangeSource {
  key: PrivateJwk
  /** Reviewed host attributes; registry_actor_kind must be human and grant claims are refused. */
  attributes: Readonly<Record<string, JsonValue>>
}

export interface RemoteExchangeSource {
  /** Exact assertion URL supplied by the authority client, such as Casework.taskAssertionEndpoint. */
  endpoint: string
  bootstrap: ExchangePrivateKeyJwtConfig
  bootstrapResource: string
  bootstrapScope: string
  attemptTimeoutMilliseconds?: SafeInteger
  connectTimeoutMilliseconds?: SafeInteger
  userAgent?: string
  trustedRootCertificates?: string
}

export type ExchangeAuthorizationConfig =
  | { client: ExchangePrivateKeyJwtConfig; context: ExchangeContext; firstParty: FirstPartyExchangeSource }
  | { client: ExchangePrivateKeyJwtConfig; context: ExchangeContext; remote: RemoteExchangeSource }

export type BaseRegistryAuthorization =
  | { static: string }
  | { privateKeyJwt: PrivateKeyJwtConfig }
  | { exchange: ExchangeAuthorizationConfig }

export interface BaseRegistryClientConfig {
  baseUrl: string
  authorization?: BaseRegistryAuthorization
  attemptTimeoutMilliseconds?: SafeInteger
  connectTimeoutMilliseconds?: SafeInteger
  maximumResponseBytes?: SafeInteger
  userAgent?: string
  trustedRootCertificates?: string
  /**
   * How many times a keyed mutation (create, patch, attachment upload or
   * delete, lifecycle action, immediate action, batch, tombstone, statistics
   * publish or withdraw) whose outcome is unknown is resent, identically and
   * under the same idempotency key, before its error is returned: a whole
   * number from 0 to 2, default 2; 0 sends it once. Any other value is a
   * `configuration` error.
   */
  maximumMutationRetries?: SafeInteger
}

export type RecordFormat = 'json' | 'json-ld'

export interface BRegStatisticalDimensionDescriptor {
  readonly field: string
  readonly vocabulary: string
  readonly codes: ReadonlyArray<string>
}

export interface BRegStatisticalDatasetDescriptor {
  readonly id: string
  readonly unit: string
  readonly periodKind: 'flow' | 'stock'
  readonly granularity: 'day' | 'month' | 'quarter' | 'year'
  readonly firstPeriod: string
  readonly dimensions: ReadonlyArray<BRegStatisticalDimensionDescriptor>
  readonly definitionDigest: string
  readonly operations: ReadonlyArray<
    | 'read-live'
    | 'list-releases'
    | 'read-released-series'
    | 'read-latest-release'
    | 'read-release-version'
    | 'publish-release'
    | 'withdraw-release'
  >
}

export interface RecordProjectionOptions {
  select?: ReadonlyArray<string> | null
  accessProfile?: string | null
  format?: RecordFormat | null
}

export interface RecordOptions extends RecordProjectionOptions {
}

export interface ListOptions extends RecordProjectionOptions {
  top?: SafeInteger | null
  filter?: string | null
  orderby?: string | null
  count?: boolean | null
  bbox?: BoundingBox | null
}

export interface CollectionOptions extends RecordProjectionOptions {
  top?: SafeInteger | null
  filter?: string | null
  orderby?: string | null
  count?: boolean | null
}
export interface AsOfListOptions extends CollectionOptions { asOf: string }
export interface SnapshotListOptions extends CollectionOptions {
  snapshot?: string | null
  validAt?: string | null
}
export type BoundingBox = readonly [west: string, south: string, east: string, north: string]
export interface GeoJsonOptions {
  select?: ReadonlyArray<string> | null
  accessProfile?: string | null
}
export interface GeoJsonListOptions extends GeoJsonOptions {
  top?: SafeInteger | null
  filter?: string | null
  orderby?: string | null
  count?: boolean | null
  bbox?: BoundingBox | null
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
export type CurrentListContinuation = ListContinuation
export interface AsOfListContinuation extends ListContinuation { asOf: string }
export interface SnapshotListContinuation extends ListContinuation {
  snapshot: string
  validAt?: string
}
export interface RelationshipListContinuation extends ListContinuation {
  rootRecordIdentifier: string
  pathRoute: string
}
export interface GeoJsonListContinuation {
  route: string
  skiptoken: string
  accessProfile?: string
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

export interface PageOutcome<T = RecordCollection, C = ListContinuation> {
  kind: 'complete'
  value: T
  continuation?: C
  traceId: string
  etag?: string
  snapshot?: string
  validAt?: string
}

export interface RawOutcome {
  kind: 'complete'
  body: Buffer
  mediaType: string
  traceId: string
  etag?: string
  reprDigest?: string
}

export type StatisticsFormat = 'json' | 'csv'
export type StatisticsReleaseStatus = 'provisional' | 'final'
export type StatisticsReleaseSelection = 'any' | 'final'
export type StatisticsWithdrawalReason =
  | 'computation-error'
  | 'source-data-error'
  | 'disclosure-risk'

export interface PatchOperation {
  op: 'add' | 'replace' | 'test'
  field: string
  value: JsonValue
}

export interface RemovePatchOperation {
  op: 'remove'
  field: string
}

/** Exact validated JSON text, serialized before conversion to JavaScript numbers.
 * Decode with a lossless JSON library if inspecting values outside the safe integer range.
 * Decimal fields remain fixed-scale JSON strings. */
export interface JsonOutcome<C = ListContinuation> {
  kind: 'complete'
  valueJson: string
  continuation?: C
  traceId: string
  etag?: string
  location?: string
  snapshot?: string
  validAt?: string
}

export interface GeoJsonPoint {
  readonly type: 'Point'
  readonly coordinates: readonly [number, number]
}
export interface GeoJsonFeature {
  readonly type: 'Feature'
  readonly id: string
  readonly geometry: GeoJsonPoint | null
  readonly properties: Readonly<Record<string, JsonValue>>
  readonly registry: { readonly revision: SafeInteger }
}
export interface GeoJsonFeatureCollection {
  readonly type: 'FeatureCollection'
  readonly features: ReadonlyArray<GeoJsonFeature>
  readonly numberReturned: SafeInteger
  readonly registry: {
    readonly pageInfo: { readonly nextCursor: string | null }
    readonly count?: SafeInteger
  }
}

export interface BRegFieldDescriptor {
  readonly id: string
  readonly apiName: string
  readonly label: string
  readonly schemaJson: string
  readonly required: boolean
  readonly nullable: boolean
  readonly readOnly: boolean
  readonly removable: boolean
  readonly referenceTargetRecordType: string | null
  readonly codeLabels: Readonly<Record<string, string>>
  readonly storageValidation: {
    readonly kind: string
    readonly pattern: string
  } | null
  readonly reference: {
    readonly name: string | null
    readonly cardinality: 'one' | 'optional-one' | 'many' | null
    readonly inverseName: string | null
    readonly manualEntry: boolean
    readonly targetRecordType: string | null
    readonly operations: ReadonlyArray<{
      readonly operationId: string
      readonly accessProfile: string
      readonly labelFields: ReadonlyArray<string>
    }>
  } | null
}
export interface BRegQueryField {
  readonly id: string
  readonly apiName: string
  readonly operators?: ReadonlyArray<string>
  readonly directions?: ReadonlyArray<string>
}
export interface BRegQueryDescriptor {
  readonly kind: string
  readonly selectableFields: ReadonlyArray<BRegQueryField>
  readonly filterableFields: ReadonlyArray<BRegQueryField>
  readonly sortableFields: ReadonlyArray<BRegQueryField>
  readonly allowCount: boolean
  readonly defaultPageSize: number
  readonly maximumPageSize: number
  readonly maximumFilterClauses: number
  readonly maximumInValues: number
  readonly pagination: { readonly parameter: string; readonly responsePath: string; readonly exclusive: boolean }
  readonly temporal: JsonObject | null
  readonly spatialQueries?: {
    readonly bbox: {
      readonly geometryProperty: string
      readonly maximumLongitudeSpanDegrees: number
      readonly maximumLatitudeSpanDegrees: number
      readonly coordinateReferenceSystem: string
      readonly semantics: string
    } | null
  }
}
export interface BRegLookupSelectorFieldDescriptor {
  readonly id: string
  readonly apiName: string
  readonly label: string
  readonly schemaJson: string
  readonly required: boolean
}
export interface BRegLookupSelectorDescriptor {
  readonly id: string
  readonly label: string
  readonly valueOrigin: string
  readonly fields: ReadonlyArray<BRegLookupSelectorFieldDescriptor>
  readonly requestFields: ReadonlyArray<string>
}
export interface BRegOperationDescriptor {
  readonly id: string
  readonly method: string
  readonly path: string
  readonly kind: string
  readonly sourceRecordType: string
  readonly responseRecordType: string
  readonly accessProfile: string
  readonly recordTypeLabel: string
  readonly titleFields: ReadonlyArray<string>
  readonly requiredCapabilities: ReadonlyArray<string>
  readonly fields: ReadonlyArray<BRegFieldDescriptor>
  readonly readableFields: ReadonlyArray<string>
  readonly createWritableFields: ReadonlyArray<string>
  readonly patchWritableFields: ReadonlyArray<string>
  readonly query: BRegQueryDescriptor | null
  readonly selectors: ReadonlyArray<BRegLookupSelectorDescriptor>
  readonly readPath: { readonly id: string; readonly label: string } | null
  readonly request: {
    readonly fieldNames: string | null
    readonly queryParameters: ReadonlyArray<string>
    readonly body: string | null
    readonly contentType: string | null
    readonly schemaJson: string | null
    readonly idempotencyKeyRequired: boolean | null
    readonly ifMatchRequired: boolean | null
    readonly mutationSemantics: string | null
    readonly patchPathPrefix: string | null
    readonly patchOperations: ReadonlyArray<string>
    readonly removeSemantics: string | null
    readonly maximumItems: SafeInteger | null
    readonly maximumBodyBytes: SafeInteger | null
    readonly allowCreate: boolean | null
    readonly allowPatch: boolean | null
  }
}

export interface BRegProposalActionDescriptor {
  readonly actionId: string
  readonly accessProfile: string
  readonly operations: ReadonlyArray<string>
  readonly readableInputs: ReadonlyArray<string>
  readonly readableContextFields: ReadonlyArray<string>
}

export interface BRegActionAttachmentDescriptor {
  readonly id: string
  readonly required: boolean
  readonly contentTypes: ReadonlyArray<string>
  readonly maximumBytes: SafeInteger
}

export interface BRegActionDescriptor {
  readonly attachments: ReadonlyArray<BRegActionAttachmentDescriptor>
  readonly apiName: string
  readonly revision: string
  readonly display: Readonly<{label?: string; description?: string}>
  readonly mode: 'immediate' | 'proposal'
  readonly id: string
  readonly inputMode: string | null
  readonly maximumInputStringBytes: SafeInteger | null
  readonly inputs: ReadonlyArray<{
    readonly id: string
    readonly apiName: string
    readonly fieldTypeJson: string
    readonly label: string
    readonly description: string | null
    readonly schemaJson: string
    readonly required: boolean
    readonly nullable: boolean | null
    readonly classification: string
  }>
  readonly referenceInputs: ReadonlyArray<{
    readonly input: string
    readonly apiName: string
    readonly targetRecordType: string
  }>
  readonly requiredConditionKeys: ReadonlyArray<string>
  readonly resultEffects: ReadonlyArray<{
    readonly effect: string
    readonly recordType: string
    readonly operation: string
  }>
  readonly accessProfile: string
  readonly invokePath: string | null
  readonly targetConditionsPath: string | null
  readonly availabilityPath: string | null
  readonly bounds: {
    readonly maximumTargets: SafeInteger
    readonly maximumFieldMutations: SafeInteger
    readonly maximumSnapshotBytes: SafeInteger
  }
}

export interface BRegActionReceipt {
  readonly action: string
  readonly applicationId: string
  readonly results: Readonly<Record<string, {
    readonly recordType: string
    readonly recordId: string
    readonly revision: SafeInteger
  }>>
}

export type BRegActionAvailability =
  | { readonly available: true; readonly observedRevision: number }
  | { readonly available: false; readonly observedRevision: number; readonly reason: 'guard-not-satisfied'; readonly guardReason?: string; readonly recovery: 'none' }
  | { readonly available: null; readonly observedRevision: number; readonly reason: 'input-required'; readonly recovery: 'correct-input'; readonly missingInputs: ReadonlyArray<string> }
  | { readonly available: null; readonly observedRevision: null; readonly reason: 'not-disclosed'; readonly recovery: 'none' }

export interface BRegBatchCreateItem {
  readonly operation: 'create'
  readonly data: JsonObject
}
export interface BRegBatchPatchItem {
  readonly operation: 'patch'
  readonly recordIdentifier: string
  readonly etag: string
  readonly operations: ReadonlyArray<PatchOperation | RemovePatchOperation>
}
export type BRegBatchItem = BRegBatchCreateItem | BRegBatchPatchItem
export type BRegChangeContext =
  | {
      readonly kind: 'change'
      readonly reasonText?: string
      readonly sourceReferences?: ReadonlyArray<string>
    }
  | {
      readonly kind: 'correction'
      readonly reasonCode: string
      readonly reasonText?: string
      readonly sourceReferences?: ReadonlyArray<string>
    }
export interface BRegBatchInput {
  readonly items: ReadonlyArray<BRegBatchItem>
  readonly changeContext?: BRegChangeContext
}
export interface BRegBatchReceipt {
  readonly snapshot: string
  readonly results: ReadonlyArray<{
    readonly operation: 'create' | 'patch'
    readonly id: string
    readonly revision: SafeInteger
    readonly etag: string
    readonly data: Readonly<Record<string, JsonValue>>
  }>
}

export type BRegIngestionOperation = 'create' | 'patch'
export type BRegIngestionRunStatus = 'open' | 'complete' | 'cancelled' | 'blocked'
export type BRegIngestionAttemptOutcome =
  | 'committed'
  | 'replayed'
  | 'invalidItem'
  | 'refused'
  | 'bindingChanged'
  | 'importAuthorityClosed'
  | 'chunkMismatch'
  | 'runNotOpen'
  | 'unavailable'

/** The whole-input announcement that opens one durable ingestion run. */
export interface BRegIngestionRunInput {
  operation: BRegIngestionOperation
  profileId: string
  packageRevision: string
  schemaFingerprint: string
  /** Lowercase SHA-256 of the complete raw source input. */
  inputDigest: string
  inputLength: SafeInteger
  itemCount: SafeInteger
  chunkCount: SafeInteger
  /** The only accepted value is `greedy-canonical-http-batch-v1`. */
  chunkAlgorithmVersion: string
}

export interface BRegIngestionRunListInput {
  accessProfile?: string | null
  limit?: SafeInteger | null
  cursor?: string | null
  status?: BRegIngestionRunStatus | null
  inputDigest?: string | null
}

export interface BRegIngestionAttempt {
  readonly outcome: BRegIngestionAttemptOutcome
  readonly chunkIndex: SafeInteger | null
}

/** Value-free durable state of one ingestion run: no source rows, no record values. */
export interface BRegIngestionRun {
  readonly runId: string
  readonly status: BRegIngestionRunStatus
  readonly blockedReason: string | null
  readonly recordType: string
  readonly operation: BRegIngestionOperation
  readonly profileId: string
  readonly packageRevision: string
  readonly schemaFingerprint: string
  readonly inputDigest: string
  readonly inputLength: SafeInteger
  readonly itemCount: SafeInteger
  readonly chunkCount: SafeInteger
  readonly chunkAlgorithmVersion: string
  readonly maximumItems: SafeInteger
  readonly maximumBytes: SafeInteger
  readonly nextChunkIndex: SafeInteger
  readonly committedItems: SafeInteger
  readonly committedPrefixDigest: string
  readonly lastAttempt: BRegIngestionAttempt | null
  readonly createdAt: string
  readonly updatedAt: string
  readonly complete: boolean
}

export interface BRegIngestionRunPage {
  readonly runs: ReadonlyArray<BRegIngestionRun>
  readonly hasMore: boolean
  readonly nextCursor: string | null
}

export interface BRegIngestionReceiptBatch {
  readonly snapshot: string
  readonly results: ReadonlyArray<JsonObject>
}

export interface BRegIngestionChunkReceipt {
  readonly chunkIndex: SafeInteger
  readonly digest: string
  readonly replayed: boolean
  readonly erased: boolean
  readonly batch: BRegIngestionReceiptBatch
}

export interface BRegIngestionChunkSubmission {
  readonly run: BRegIngestionRun
  readonly receipt: BRegIngestionChunkReceipt
}

/**
 * One bounded, digest-bound chunk of an ingestion run. The chunk digest is
 * derived in Rust from the exact canonical batch body the items hash to.
 */
export declare class BRegIngestionChunk {
  private constructor()
  private readonly __opaque: void
  readonly chunkIndex: SafeInteger
  readonly itemCount: SafeInteger
  readonly digest: string
  readonly prefixDigest: string
}

/**
 * Accumulate the raw source bytes of one ingestion input and derive the
 * rolling prefix digest the run binds: the lowercase SHA-256 of everything
 * absorbed through the end of the current chunk. The digest of an empty
 * accumulation is `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
 */
export declare class BRegIngestionPrefixDigest {
  constructor()
  update(data: Buffer): void
  digest(): string
}

/**
 * Encode one ingestion chunk submission: derive its digest in Rust and bind
 * the announced prefix digest into the exact wire body. `items` are the same
 * batch items the entity's atomic batch route executes.
 */
export declare function encodeIngestionChunk(
  chunkIndex: SafeInteger,
  items: ReadonlyArray<BRegBatchItem>,
  prefixDigest: string,
): BRegIngestionChunk

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
/** Opaque authority for one metadata-selected immediate action. */
export declare class BRegActionBinding {
  private constructor()
  private readonly __opaque: void
}
/** Opaque target conditions obtained for one selected action and input set. */
export declare class BRegActionTargetConditions {
  private constructor()
  private readonly __opaque: void
  readonly preconditionKeys: ReadonlyArray<string>
  readonly valueJson: string
  readonly traceId: string
}
/** Opaque authority for one metadata-selected Tombstone operation. */
export declare class BRegTombstoneBinding {
  private constructor()
  private readonly __opaque: void
}
/** Opaque authority for one metadata-selected atomic Batch operation. */
export declare class BRegBatchBinding {
  private constructor()
  private readonly __opaque: void
}

/**
 * Inert bounded immediate-action evidence: inputs, saved target conditions,
 * and the idempotency key. Persist these bytes with owner-only access before
 * invoking.
 */
export declare class BRegPreparedAction {
  private constructor()
  private readonly __opaque: void
  static fromBytes(bytes: Buffer): BRegPreparedAction
  toBytes(): Buffer
}

/** Inert bounded Create evidence. Persist these bytes with owner-only access. */
export declare class BRegPreparedCreate {
  private constructor()
  private readonly __opaque: void
  static fromBytes(bytes: Buffer): BRegPreparedCreate
  toBytes(): Buffer
}

/** Revalidated action invocation and key. It still requires fresh metadata authority to send. */
export declare class BRegRecoveredAction {
  private constructor()
  private readonly __opaque: void
}

/** Revalidated Create request. It still requires fresh metadata authority to send. */
export declare class BRegRecoveredCreate {
  private constructor()
  private readonly __opaque: void
}

/** Caller-filtered metadata bound to the exact client source that fetched it. */
export declare class BRegMetadata {
  selectProposals(profile: string): BRegProposalCollection
  selectProposalGet(profile: string): BRegProposalGetBinding
  selectProposalReviewContext(profile: string, action: string): BRegProposalReviewBinding
  selectProposalReviewStatus(profile: string, action: string): BRegProposalReviewBinding
  private constructor()
  private readonly __opaque: void
  readonly operations: ReadonlyArray<BRegOperationDescriptor>
  readonly proposalActions: ReadonlyArray<BRegProposalActionDescriptor>
  readonly actions: ReadonlyArray<BRegActionDescriptor>
  readonly actionsJson: string | null
  /** Validated caller-filtered inert descriptions. They never grant entity authority. */
  readonly statisticalDatasets: ReadonlyArray<BRegStatisticalDatasetDescriptor> | null
  readonly registryIdentifier: string
  readonly registryVersion: string
  readonly registryRevision: string
  readonly traceId: string
  readonly etag: string | null
  selectCreate(operationIdentifier: string, expectedProfile: string): BRegCreateBinding
  selectPatch(operationIdentifier: string, expectedProfile: string): BRegPatchBinding
  selectAction(actionIdentifier: string, expectedProfile: string): BRegActionBinding
  selectTombstone(recordTypeIdentifier: string, expectedProfile: string): BRegTombstoneBinding
  selectBatch(recordTypeIdentifier: string, expectedProfile: string): BRegBatchBinding
  /** The occurrence descriptor declared for a record type, as JSON text. */
  occurrenceDescriptor(recordType: string): string
}

/** Bounded declared identifiers; absent when any referenced field is unreadable. */
export type BRegConstraintViolation = {
  readonly recordType: string
  readonly constraintId: string
} & ({
  readonly constraintKind: 'compare'
  readonly left: string
  readonly right: string
} | {
  readonly constraintKind: 'int-range' | 'vocabulary'
  readonly field: string
})

export interface BaseRegistryClientFailure extends Error {
  readonly kind: string
  readonly code?: string
  readonly refusalCode?: string
  readonly reasonCode?: string
  readonly guardReason?: string
  readonly fieldPath?: string
  readonly constraint?: BRegConstraintViolation
  readonly status?: number
  readonly traceId?: string
  readonly transportKind?: string
  readonly tokenKind?: string
  /**
   * Whether the request may have taken effect although this error was raised:
   * a timeout or broken exchange after sending, an unusable answer, or a 5xx
   * other than `action.handler_failed` and
   * `statistical_dataset.domain_violation`, which the engine returns only with
   * the attempt rolled back. When true, recover a keyed mutation by sending it
   * again under the same idempotency key; a new key could apply it twice.
   * False for a configuration or request defect, a credential the token
   * provider could not supply, a connection never established, and every 4xx
   * refusal. It is false for `410 idempotency.expired` too, but there an
   * earlier attempt under the key committed and only its held response is
   * gone: read the resource before choosing a new key.
   */
  readonly outcomeUnknown: boolean
}

export declare class BaseRegistryClientError extends Error implements BaseRegistryClientFailure {
  readonly kind: string
  readonly code?: string
  readonly refusalCode?: string
  readonly reasonCode?: string
  readonly guardReason?: string
  readonly fieldPath?: string
  readonly constraint?: BRegConstraintViolation
  readonly status?: number
  readonly traceId?: string
  readonly transportKind?: string
  readonly tokenKind?: string
  /**
   * Whether the request may have taken effect although this error was raised:
   * a timeout or broken exchange after sending, an unusable answer, or a 5xx
   * other than `action.handler_failed` and
   * `statistical_dataset.domain_violation`, which the engine returns only with
   * the attempt rolled back. When true, recover a keyed mutation by sending it
   * again under the same idempotency key; a new key could apply it twice.
   * False for a configuration or request defect, a credential the token
   * provider could not supply, a connection never established, and every 4xx
   * refusal. It is false for `410 idempotency.expired` too, but there an
   * earlier attempt under the key committed and only its held response is
   * gone: read the resource before choosing a new key.
   */
  readonly outcomeUnknown: boolean
}

export declare class BaseRegistryClient {
  startProposal(binding: BRegActionBinding, inputsJson: string, key: string): Promise<BRegProposal>
  getProposal(binding: BRegProposalGetBinding, id: string): Promise<BRegProposal>
  readProposal(proposal: BRegProposal): Promise<BRegProposal>
  /** Read one retained submission version under the access profile of the Proposal's self link. */
  readProposalSubmission(proposal: BRegProposal, version: number): Promise<CompleteOutcome<BRegProposalSubmission>>
  listProposals(collection: BRegProposalCollection, queryJson: string): Promise<BRegProposalPage>
  prepareProposal(proposal: BRegProposal, operation: BRegProposalTransition, bodyJson: string, key: string): BRegPreparedProposal
  recoverProposal(proposal: BRegProposal, attempt: BRegPreparedProposal): BRegPreparedProposal
  executeProposal(attempt: BRegPreparedProposal): Promise<BRegProposal>
  constructor(config: BaseRegistryClientConfig)
  health(): Promise<CompleteOutcome<ProbeStatus>>
  ready(): Promise<CompleteOutcome<ProbeStatus>>
  openapi(accessProfile?: string | null): Promise<RawOutcome>
  registryMetadata(accessProfile?: string | null): Promise<RawOutcome>
  /**
   * The first revision of a record as
   * `{recordType, recordId, revision, createdAt}` JSON text, or null when the
   * caller may not read it (403 or 404).
   */
  occurrenceCreationRevision(entityRoute: string, recordIdentifier: string, accessProfile?: string | null): Promise<string | null>
  statisticsLive(dataset: string, from?: string | null, to?: string | null, accessProfile?: string | null, format?: StatisticsFormat | null): Promise<RawOutcome>
  statisticsReleases(dataset: string, top?: SafeInteger | null, skipToken?: string | null, accessProfile?: string | null): Promise<RawOutcome>
  statisticsLatestRelease(dataset: string, period: string, selection: StatisticsReleaseSelection, accessProfile?: string | null, format?: StatisticsFormat | null): Promise<RawOutcome>
  statisticsReleaseVersion(dataset: string, period: string, version: SafeInteger, accessProfile?: string | null, format?: StatisticsFormat | null): Promise<RawOutcome>
  statisticsReleaseSeries(dataset: string, from: string, to: string, selection: StatisticsReleaseSelection, accessProfile?: string | null, format?: StatisticsFormat | null): Promise<RawOutcome>
  statisticsPublish(dataset: string, period: string, status: StatisticsReleaseStatus, accessProfile: string, idempotencyKey: string): Promise<RawOutcome>
  statisticsWithdraw(dataset: string, period: string, version: SafeInteger, reason: StatisticsWithdrawalReason, accessProfile: string, idempotencyKey: string): Promise<RawOutcome>
  registryContract(accessProfile?: string | null): Promise<BRegMetadata>
  entitySchema(recordTypeIdentifier: string, accessProfile?: string | null): Promise<RawOutcome>
  recordRevisions(entityRoute: string, recordIdentifier: string, accessProfile?: string | null): Promise<RawOutcome>
  getRecordRevision(entityRoute: string, recordIdentifier: string, revision: SafeInteger, options?: RecordProjectionOptions | null): Promise<RawOutcome>
  getRecord(entityRoute: string, recordIdentifier: string, options?: RecordOptions | null): Promise<CompleteOutcome<RecordEnvelope>>
  listRecords(entityRoute: string, options?: ListOptions | null): Promise<PageOutcome>
  continueList(continuation: ListContinuation): Promise<PageOutcome>
  getGeoJsonRecord(entityRoute: string, recordIdentifier: string, options?: GeoJsonOptions | null): Promise<CompleteOutcome<GeoJsonFeature>>
  listGeoJsonRecords(entityRoute: string, options?: GeoJsonListOptions | null): Promise<PageOutcome<GeoJsonFeatureCollection, GeoJsonListContinuation>>
  continueGeoJsonList(continuation: GeoJsonListContinuation): Promise<PageOutcome<GeoJsonFeatureCollection, GeoJsonListContinuation>>
  listCurrentRecords(entityRoute: string, options?: CollectionOptions | null): Promise<PageOutcome<RecordCollection, CurrentListContinuation>>
  continueCurrentList(continuation: CurrentListContinuation): Promise<PageOutcome<RecordCollection, CurrentListContinuation>>
  listRecordsAsOf(entityRoute: string, options: AsOfListOptions): Promise<PageOutcome<RecordCollection, AsOfListContinuation>>
  continueAsOfList(continuation: AsOfListContinuation): Promise<PageOutcome<RecordCollection, AsOfListContinuation>>
  listSnapshotRecords(entityRoute: string, options?: SnapshotListOptions | null): Promise<PageOutcome<RecordCollection, SnapshotListContinuation>>
  continueSnapshotList(continuation: SnapshotListContinuation): Promise<PageOutcome<RecordCollection, SnapshotListContinuation>>
  listRelationshipRecords(entityRoute: string, recordIdentifier: string, pathRoute: string, options?: CollectionOptions | null): Promise<PageOutcome<RecordCollection, RelationshipListContinuation>>
  continueRelationshipList(continuation: RelationshipListContinuation): Promise<PageOutcome<RecordCollection, RelationshipListContinuation>>
  lookupRecord(entityRoute: string, selector: string, values?: JsonObject | null, options?: RecordProjectionOptions | null): Promise<CompleteOutcome<RecordEnvelope>>
  actionTargetConditions(binding: BRegActionBinding, inputs: JsonObject): Promise<BRegActionTargetConditions>
  actionTargetConditionsJson(binding: BRegActionBinding, inputsJson: string): Promise<BRegActionTargetConditions>
  actionAvailability(binding: BRegActionBinding, targetInput: string, inputs: JsonObject): Promise<CompleteOutcome<BRegActionAvailability>>
  actionAvailabilityJson(binding: BRegActionBinding, targetInput: string, inputsJson: string): Promise<JsonOutcome>
  invokeAction(binding: BRegActionBinding, inputs: JsonObject, idempotencyKey: string, conditions?: BRegActionTargetConditions | null): Promise<CompleteOutcome<BRegActionReceipt>>
  invokeActionJson(binding: BRegActionBinding, inputsJson: string, idempotencyKey: string, conditions?: BRegActionTargetConditions | null): Promise<JsonOutcome>
  /** Validate and retain one invocation before any I/O, for recovery after a lost response. */
  prepareAction(binding: BRegActionBinding, inputs: JsonObject, idempotencyKey: string, conditions?: BRegActionTargetConditions | null): BRegPreparedAction
  prepareActionJson(binding: BRegActionBinding, inputsJson: string, idempotencyKey: string, conditions?: BRegActionTargetConditions | null): BRegPreparedAction
  /** Revalidate saved evidence against fresh authority and the original inputs and key. Performs no I/O. */
  recoverAction(binding: BRegActionBinding, prepared: BRegPreparedAction, inputs: JsonObject, idempotencyKey: string): BRegRecoveredAction
  recoverActionJson(binding: BRegActionBinding, prepared: BRegPreparedAction, inputsJson: string, idempotencyKey: string): BRegRecoveredAction
  executeRecoveredAction(binding: BRegActionBinding, recovered: BRegRecoveredAction): Promise<CompleteOutcome<BRegActionReceipt>>
  executeRecoveredProposalStart(binding: BRegActionBinding, recovered: BRegRecoveredAction): Promise<BRegProposal>
  downloadProposalAttachment(proposal: BRegProposal, slot: string): Promise<RawOutcome>
  readProposalReviewStatus(proposal: BRegProposal): Promise<CompleteOutcome<BRegProposalReviewDocument>>
  readProposalReviewContext(proposal: BRegProposal): Promise<CompleteOutcome<BRegProposalReviewDocument>>
  readProposalReviewContextBatch(binding: BRegProposalReviewBinding, ids: string[]): Promise<CompleteOutcome<Array<BRegProposalReviewDocument | null>>>
  readProposalReviewById(binding: BRegProposalReviewBinding, id: string): Promise<CompleteOutcome<BRegProposalReviewDocument>>
  downloadProposalReviewDocument(binding: BRegProposalReviewBinding, context: BRegProposalReviewDocument, field: string): Promise<RawOutcome>
  uploadProposalAttachment(proposal: BRegProposal, slot: string, contentType: string, bytes: Buffer, key: string): Promise<BRegProposal>
  deleteProposalAttachment(proposal: BRegProposal, slot: string, key: string): Promise<BRegProposal>
  executeRecoveredActionJson(binding: BRegActionBinding, recovered: BRegRecoveredAction): Promise<JsonOutcome>
  createRecord(binding: BRegCreateBinding, data: JsonObject, idempotencyKey: string, format?: RecordFormat | null): Promise<CompleteOutcome<RecordEnvelope>>
  prepareCreate(binding: BRegCreateBinding, data: JsonObject, idempotencyKey: string, format?: RecordFormat | null): BRegPreparedCreate
  prepareCreateJson(binding: BRegCreateBinding, dataJson: string, idempotencyKey: string, format?: RecordFormat | null): BRegPreparedCreate
  recoverCreate(binding: BRegCreateBinding, prepared: BRegPreparedCreate): BRegRecoveredCreate
  executeRecoveredCreate(binding: BRegCreateBinding, recovered: BRegRecoveredCreate): Promise<CompleteOutcome<RecordEnvelope>>
  executeRecoveredCreateJson(binding: BRegCreateBinding, recovered: BRegRecoveredCreate): Promise<JsonOutcome>
  patchRecord(binding: BRegPatchBinding, recordIdentifier: string, etag: string, operations: ReadonlyArray<PatchOperation | RemovePatchOperation>, idempotencyKey: string, format?: RecordFormat | null): Promise<CompleteOutcome<RecordEnvelope>>
  batchRecords(binding: BRegBatchBinding, request: BRegBatchInput, idempotencyKey: string): Promise<CompleteOutcome<BRegBatchReceipt>>
  batchRecordsJson(binding: BRegBatchBinding, requestJson: string, idempotencyKey: string): Promise<JsonOutcome>
  createIngestionRun(entityRoute: string, request: BRegIngestionRunInput): Promise<CompleteOutcome<BRegIngestionRun>>
  listIngestionRuns(entityRoute: string, query?: BRegIngestionRunListInput | null): Promise<CompleteOutcome<BRegIngestionRunPage>>
  readIngestionRun(entityRoute: string, runId: string, accessProfile?: string | null): Promise<CompleteOutcome<BRegIngestionRun>>
  submitIngestionChunk(entityRoute: string, runId: string, chunk: BRegIngestionChunk, profileId: string): Promise<CompleteOutcome<BRegIngestionChunkSubmission>>
  cancelIngestionRun(entityRoute: string, runId: string, accessProfile?: string | null): Promise<CompleteOutcome<BRegIngestionRun>>
  ingestionChunkReceipt(entityRoute: string, runId: string, chunkIndex: SafeInteger, profileId: string): Promise<CompleteOutcome<BRegIngestionChunkReceipt>>
  tombstoneRecord(binding: BRegTombstoneBinding, recordIdentifier: string, etag: string, idempotencyKey: string, format?: RecordFormat | null): Promise<CompleteOutcome<RecordEnvelope>>
  tombstoneRecordJson(binding: BRegTombstoneBinding, recordIdentifier: string, etag: string, idempotencyKey: string, format?: RecordFormat | null): Promise<JsonOutcome>
  getRecordJson(entityRoute: string, recordIdentifier: string, options?: RecordOptions | null): Promise<JsonOutcome>
  listRecordsJson(entityRoute: string, options?: ListOptions | null): Promise<JsonOutcome>
  continueListJson(continuation: ListContinuation): Promise<JsonOutcome>
  getGeoJsonRecordJson(entityRoute: string, recordIdentifier: string, options?: GeoJsonOptions | null): Promise<JsonOutcome>
  listGeoJsonRecordsJson(entityRoute: string, options?: GeoJsonListOptions | null): Promise<JsonOutcome<GeoJsonListContinuation>>
  continueGeoJsonListJson(continuation: GeoJsonListContinuation): Promise<JsonOutcome<GeoJsonListContinuation>>
  listCurrentRecordsJson(entityRoute: string, options?: CollectionOptions | null): Promise<JsonOutcome<CurrentListContinuation>>
  continueCurrentListJson(continuation: CurrentListContinuation): Promise<JsonOutcome<CurrentListContinuation>>
  listRecordsAsOfJson(entityRoute: string, options: AsOfListOptions): Promise<JsonOutcome<AsOfListContinuation>>
  continueAsOfListJson(continuation: AsOfListContinuation): Promise<JsonOutcome<AsOfListContinuation>>
  listSnapshotRecordsJson(entityRoute: string, options?: SnapshotListOptions | null): Promise<JsonOutcome<SnapshotListContinuation>>
  continueSnapshotListJson(continuation: SnapshotListContinuation): Promise<JsonOutcome<SnapshotListContinuation>>
  listRelationshipRecordsJson(entityRoute: string, recordIdentifier: string, pathRoute: string, options?: CollectionOptions | null): Promise<JsonOutcome<RelationshipListContinuation>>
  continueRelationshipListJson(continuation: RelationshipListContinuation): Promise<JsonOutcome<RelationshipListContinuation>>
  lookupRecordJson(entityRoute: string, selector: string, valuesJson?: string | null, options?: RecordProjectionOptions | null): Promise<JsonOutcome>
  createRecordJson(binding: BRegCreateBinding, dataJson: string, idempotencyKey: string, format?: RecordFormat | null): Promise<JsonOutcome>
  patchRecordJson(binding: BRegPatchBinding, recordIdentifier: string, etag: string, operationsJson: string, idempotencyKey: string, format?: RecordFormat | null): Promise<JsonOutcome>
}

export type BRegProposalTransition = 'edit' | 'submit' | 'revise' | 'rebase' | 'retry' | 'cancel' | 'apply'
export type BRegAvailabilityReason = 'pending-review' | 'review-rejected' | 'review-changes-requested' | 'review-ended' | 'stale-revision' | 'contract-changed' | 'dependency-outage' | 'invalid-input' | 'already-applied'
export type BRegRecoveryHint = 'refresh' | 'revise' | 'retry' | 'correct-input' | 'receipt-only'
export type BRegAvailability =
  | { readonly available: true; readonly observedRevision: number }
  | { readonly available: false; readonly observedRevision: number; readonly reason: BRegAvailabilityReason; readonly recovery: BRegRecoveryHint }
export interface BRegProposalLink { readonly method: 'GET' | 'POST'; readonly path: string; readonly accessProfile: string; readonly operation: string; readonly ifMatch?: string; readonly availability?: BRegAvailability }
export interface BRegProposalAttachment {
  readonly id: string; readonly required: boolean; readonly maximumBytes: number
  readonly contentTypes: ReadonlyArray<string>; readonly classification: 'public' | 'internal' | 'restricted'
  readonly links: Readonly<Partial<Record<'download' | 'upload' | 'remove', Omit<BRegProposalLink, 'method'> & {readonly method: 'GET' | 'PATCH' | 'DELETE'}>>>
  readonly value?: {readonly submissionVersion: number; readonly sha256: string; readonly contentType: string; readonly byteSize: number; readonly uploadedAt?: string; readonly verificationStatus: 'notRequired' | 'pending' | 'approved' | 'rejected'}
}
export interface BRegProposalApplication {
  readonly applicationId: string; readonly submissionVersion: number; readonly effectDigest: string
  readonly appliedBy?: string; readonly appliedAt?: string
  readonly resultLinks: ReadonlyArray<{readonly recordType: string; readonly recordId: string; readonly revision: number}>
}
export interface BRegProposalApplicationStatus {
  readonly state: 'awaiting-review' | 'pending' | 'applying' | 'blocked' | 'applied' | 'cancelled' | 'rejected'
  readonly mode: 'automatic' | 'manual'
  readonly reason?: 'contract-changed' | 'dependency-outage' | 'lease-expired' | 'application-refused' | 'attempts-exhausted'
  readonly recovery?: 'retry' | 'correct-input'
  readonly automaticRetry?: {readonly scheduled: boolean; readonly attempts: number; readonly maximumAttempts: number}
}
export interface BRegProposalReviewDocument {
  readonly id: string; readonly actionId: string; readonly actionRevision: string
  readonly submissionVersion: number; readonly revision: number; readonly effectDigest: string; readonly reviewable: boolean
  readonly subject: {readonly source: string; readonly subjectType: 'proposal'; readonly id: string; readonly version: string; readonly digest: string}
  readonly context: {readonly reference: string; readonly contract?: {readonly id: string; readonly revision: string; readonly schemaDigest: string}; readonly fields?: Readonly<Record<string, JsonValue>>}
  readonly requestId?: string
  readonly authority?: string; readonly policy?: {readonly id: string; readonly version: string; readonly digest: string}
  readonly result?: {readonly state: 'pending' | 'approved' | 'rejected' | 'changes-requested' | 'answered' | 'cancelled' | 'superseded' | 'expired'; readonly resultId?: string; readonly completedAt?: string; readonly availableUntil?: string}
}
/** Who is expected to act next, derived by BReg. */
export type BRegProposalTurn = 'party' | 'official' | 'nobody'
/** The review decision on one submission. The public reason is the only reviewer text BReg serves. */
export interface BRegProposalDecision { readonly status: 'approved' | 'rejected' | 'changes-requested' | 'answered'; readonly decidedAt: string; readonly publicReason?: string }
export interface BRegProposalSubmission {
  readonly id: string; readonly actionId: string; readonly submissionVersion: number; readonly current: boolean; readonly effectDigest: string
  readonly review: NonNullable<BRegProposalReviewDocument['result']> | null
  readonly application: (Omit<BRegProposalApplicationStatus, 'mode'> & {readonly mode?: BRegProposalApplicationStatus['mode']; readonly applicationId?: string; readonly appliedBy?: string; readonly appliedAt?: string}) | null
  readonly decision?: BRegProposalDecision
}
export interface BRegProposalDocument { readonly id: string; readonly actionId: string; readonly actionRevision: string; readonly submissionVersion: number; readonly revision: number; readonly state: 'draft' | 'submitted' | 'cancelled' | 'applied' | 'rejected'; readonly turn?: BRegProposalTurn; readonly decision?: BRegProposalDecision; readonly title?: string; readonly input?: JsonObject; readonly blockedReason?: 'package-changed'; readonly effectDigest?: string; readonly application?: BRegProposalApplication; readonly applicationStatus?: BRegProposalApplicationStatus; readonly links: Readonly<Partial<Record<BRegProposalTransition | 'self' | 'reviewContext' | 'reviewStatus', BRegProposalLink>>>; readonly attachments?: Readonly<Record<string, BRegProposalAttachment>> }
export declare class BRegProposal { private constructor(); private readonly __opaque: void; readonly identifier: string; readonly actionIdentifier: string; readonly documentJson: string; readonly inputJson?: string | null }
export declare class BRegProposalGetBinding { private constructor(); private readonly __opaque: void }
export declare class BRegProposalReviewBinding { private constructor(); private readonly __opaque: void }

/** Inert document value projected by an authored Review context field. */
export interface BRegProposalReviewAttachment {
  readonly type: 'document'
  readonly slotId: string
  readonly sha256: string
  readonly contentType: string
  readonly byteSize: number
  readonly download: {
    readonly method: 'GET'
    readonly operation: 'get-review-context'
    readonly accessProfile: string
    readonly path: string
  }
}
export declare class BRegProposalCollection { private constructor(); private readonly __opaque: void }
export interface BRegProposalPage { readonly items: ReadonlyArray<BRegProposal>; readonly nextCursor?: string }
export declare class BRegPreparedProposal { private constructor(); private readonly __opaque: void; static fromBytes(bytes: Buffer): BRegPreparedProposal; toBytes(): Buffer }
