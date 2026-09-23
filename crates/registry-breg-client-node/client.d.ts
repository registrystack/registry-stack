export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }
/** Structured mutation inputs reject integer-valued numbers outside
 * `Number.isSafeInteger`. Use the corresponding `...Json` method for exact
 * wider integer values. */
export type JsonObject = { readonly [key: string]: JsonValue }
/** An integer that satisfies `Number.isSafeInteger` and the option's documented bounds. */
export type SafeInteger = number

export type WebhookVerificationRefusalCode =
  | 'missing_header'
  | 'malformed_signature'
  | 'signature_mismatch'
  | 'unsupported_version'

export interface WebhookDeliveryInput {
  method: string
  path: string
  headers: Readonly<Record<string, string>>
  /** Exact bytes in a non-shared backing store. */
  body: Buffer
  /** Secret bytes in a non-shared backing store. */
  key: Buffer
}

export interface VerifiedWebhookDelivery {
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
 * Authenticate one exact Base Registry Engine Version 1 webhook delivery.
 * Apply delivery-time skew and idempotency policy before acting on the body.
 */
export declare function verifyWebhookDelivery(input: WebhookDeliveryInput): VerifiedWebhookDelivery

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
  audience?: string | null
  /**
   * The RFC 8707 resource indicator the token is requested for: the resource
   * server's registered identifier, not a URL to fetch.
   */
  resource?: string | null
  /**
   * The scopes requested for the token, sent as one space-delimited `scope`
   * parameter. A requested scope may narrow the client's registered
   * permission set; it can never widen it.
   */
  scopes?: ReadonlyArray<string> | null
  assertionLifetimeSeconds?: SafeInteger | null
  refreshMarginSeconds?: SafeInteger | null
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
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
  grantId?: string | null
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
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
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
  authorization?: BaseRegistryAuthorization | null
  requestTimeoutMilliseconds?: SafeInteger | null
  connectTimeoutMilliseconds?: SafeInteger | null
  maxResponseBytes?: SafeInteger | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
}

export type RecordFormat = 'json' | 'json-ld'

export interface RecordProjectionOptions {
  select?: ReadonlyArray<string> | null
  accessProfile?: string | null
  format?: RecordFormat | null
}

export interface RecordOptions extends RecordProjectionOptions {
  requestHistoryAfterProposalVersion?: SafeInteger | null
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
  request?: BRegRequestMetadata
  readonly [member: string]: JsonValue | undefined
}

export type BRegRequestResultReferenceData = JsonObject & {
  readonly targetEntityId: string
  readonly targetRecordId: string
  /** Revision written by the application, not a current ETag or precondition. */
  readonly targetRevision: SafeInteger
}
export type BRegRequestState = 'draft' | 'submitted' | 'cancelled' | 'applied'
export type BRegRequestReviewRequirement =
  | Readonly<{ mode: 'none' }>
  | Readonly<{ authority: string; policyId: string }>
export type BRegExternalReviewStatus = Readonly<{
  submission: Readonly<{
    state: 'pending' | 'accepted' | 'uncertain' | 'cancelling' | 'cancelled' | 'failed'
    authority: string
    requestId?: string
    submissionDigest?: string
    /** Fixed recovery deadline for the durable submission. */
    recoveryDeadline?: string
    policy?: Readonly<{ id: string; version: string; digest: string }>
  }>
  result: Readonly<{
    state: 'pending' | 'approved' | 'rejected' | 'changesRequested' | 'answered' | 'cancelled' | 'superseded'
    resultId?: string
    completedAt?: string
    availableUntil?: string
  }>
  delivery: Readonly<{
    state: 'polling' | 'received' | 'reconciled' | 'unmatched' | 'exhausted'
    eventId?: string
    receivedAt?: string
  }>
  application: Readonly<{
    mode: 'manual' | 'automatic'
    state: 'awaitingReview' | 'ready' | 'queued' | 'applying' | 'applied' | 'blocked' | 'expired'
    executor?: string
    applicationId?: string
    /** Durable automatic-application attempts, from 0 through 1000. */
    attempts?: SafeInteger
    /** Present only while an automatic application is queued or applying. */
    nextAttemptAt?: string
    /** Present when the applied receipt was recovered from already-applied source state. */
    receiptRecovered?: true
  }>
  recovery: Readonly<{
    state: 'none' | 'operatorAttention'
    code?: string
  }>
}>
export type BRegRetainedRequestProposal = JsonObject & {
  readonly requestEntityId: string
  readonly requestId: string
  readonly proposalVersion: SafeInteger
  readonly bregState: BRegRequestState
  readonly current: boolean
  readonly contractFingerprint: string
  readonly detailErased: boolean
  readonly applicationId: string | null
  readonly resultLinkCount: SafeInteger
  readonly resultLinks: ReadonlyArray<BRegRequestResultReferenceData>
  readonly effectDigest?: string
  readonly proposal?: Readonly<{ review: BRegRequestReviewRequirement }>
}
export type BRegRetainedRequestHistory = JsonObject & {
  readonly proposals: ReadonlyArray<BRegRetainedRequestProposal>
  readonly nextAfterProposalVersion: SafeInteger | null
}
export type BRegRequestMetadata = JsonObject & {
  readonly bregState: BRegRequestState
  readonly proposalVersion: SafeInteger
  readonly effectDigest?: string | null
  readonly proposal?: Readonly<{ review: BRegRequestReviewRequirement }> | null
  readonly editable: boolean
  readonly detailErased?: true
  readonly actions?: ReadonlyArray<JsonObject>
  readonly application?: JsonObject | null
  readonly history?: BRegRetainedRequestHistory | null
  readonly review?: BRegExternalReviewStatus
  readonly submitterReference?: string
  readonly applierReference?: string
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

export type LifecycleReceipt = JsonObject & {
  readonly id: string
  readonly revision: SafeInteger
  readonly snapshot: string
  readonly actorReference?: string
  readonly request: BRegLifecycleReceiptRequest
}

export type BRegLifecycleReceiptRequest = JsonObject & {
  readonly bregState: BRegRequestState
  readonly proposalVersion: SafeInteger | null
  readonly effectDigest: string | null
  readonly proposal?: JsonObject | null
  readonly application: JsonObject | null
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
  readonly referenceTargetEntity: string | null
  readonly codeLabels: Readonly<Record<string, string>>
  readonly storageValidation: {
    readonly kind: string
    readonly pattern: string
  } | null
  readonly reference: {
    readonly manualEntry: boolean
    readonly targetEntity: string | null
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
  readonly maxPageSize: number
  readonly maxFilterClauses: number
  readonly maxInValues: number
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
  readonly sourceEntity: string
  readonly responseEntity: string
  readonly accessProfile: string
  readonly entityLabel: string
  readonly titleFields: ReadonlyArray<string>
  readonly requiredCapabilities: ReadonlyArray<string>
  readonly fields: ReadonlyArray<BRegFieldDescriptor>
  readonly readableFields: ReadonlyArray<string>
  readonly readableRequestFields: ReadonlyArray<string>
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

export interface BRegImmediateActionDescriptor {
  readonly id: string
  readonly contractFingerprint: string
  readonly inputMode: string | null
  readonly maximumInputStringBytes: SafeInteger | null
  readonly inputs: ReadonlyArray<{
    readonly id: string
    readonly apiName: string
    readonly fieldTypeJson: string
    readonly required: boolean
    readonly nullable: boolean | null
    readonly classification: string
  }>
  readonly referenceInputs: ReadonlyArray<{
    readonly input: string
    readonly apiName: string
    readonly targetEntity: string
  }>
  readonly requiredConditionKeys: ReadonlyArray<string>
  readonly resultEffects: ReadonlyArray<{
    readonly effect: string
    readonly entity: string
    readonly operation: string
  }>
  readonly accessProfile: string
  readonly invokePath: string
  readonly targetConditionsPath: string | null
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
    readonly entity: string
    readonly recordId: string
    readonly revision: SafeInteger
  }>>
}

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
  after?: string | null
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
  readonly entityId: string
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
  readonly nextAfter: string | null
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

/**
 * Where a change-request target or value comes from, present only when the
 * caller may read it: a request-entity field, or the record another effect
 * of the same request creates.
 */
export type BRegChangeRequestBinding =
  | { readonly fromField: string; readonly fromEffect?: never }
  | { readonly fromEffect: string; readonly fromField?: never }
  | { readonly fromField?: never; readonly fromEffect?: never }

export type BRegChangeRequestTarget = { readonly entity: string } & BRegChangeRequestBinding

/**
 * One declared change-request effect on an entity the caller may read. Only
 * target fields the caller may read are named; the value is descriptive and
 * cannot create target-write authority.
 */
export interface BRegChangeRequestEffect {
  readonly id: string
  readonly operation: 'create' | 'patch'
  readonly target: BRegChangeRequestTarget
  readonly set: ReadonlyArray<{ readonly field: string } & BRegChangeRequestBinding>
  readonly clear: ReadonlyArray<string>
}

/** One declared planner write, filtered to fields the caller may read. */
export interface BRegChangeRequestPlannerWrite {
  /** A planner write targets a stored record, never another effect. */
  readonly target: { readonly entity: string; readonly fromField?: string; readonly fromEffect?: never }
  readonly operation: 'create' | 'patch'
  readonly fields: ReadonlyArray<string>
}

export interface BRegChangeRequestCapability {
  readonly planner: {
    readonly kind: 'declarative' | 'rhai'
    readonly abi: string | null
    readonly limits: {
      readonly maximumTargets: SafeInteger
      readonly maximumFieldMutations: SafeInteger
      readonly maximumSnapshotBytes: SafeInteger
      readonly maximumSourceBytes: SafeInteger
      readonly maximumOperations: SafeInteger
      readonly maximumCallDepth: SafeInteger
      readonly maximumExpressionDepth: SafeInteger
      readonly maximumStringBytes: SafeInteger
      readonly maximumArrayItems: SafeInteger
      readonly maximumMapEntries: SafeInteger
      readonly maximumModules: SafeInteger
    } | null
    readonly possibleWriteCount: SafeInteger | null
    readonly possibleWriteOperations: ReadonlyArray<string>
    readonly writes: ReadonlyArray<BRegChangeRequestPlannerWrite>
  }
  readonly effects: ReadonlyArray<BRegChangeRequestEffect>
  readonly review: BRegRequestReviewRequirement
  readonly onApproved: {
    readonly mode: 'manual' | 'automatic'
    readonly executor: string | null
  }
  readonly application: {
    readonly preconditions: JsonValue | null
  }
}

export type BRegAttachmentVerificationStatus = 'notRequired' | 'pending' | 'approved' | 'rejected'

export type BRegAttachmentClassification = 'public' | 'internal' | 'restricted'

/** Engine-owned state of one filled slot, read from a record's domain data. */
export interface BRegAttachmentState {
  readonly slotIdentifier: string
  readonly proposalVersion: SafeInteger
  readonly erased: boolean
  readonly byteSize: SafeInteger
  readonly sha256: string
  readonly contentType: string | null
  readonly uploadedAt: string | null
  readonly uploadedBy: string | null
  readonly verificationStatus: BRegAttachmentVerificationStatus | null
}

/** What one record projection says about one slot. */
export type BRegAttachmentSlotValue =
  | { readonly kind: 'not_selected'; readonly value: null }
  | { readonly kind: 'empty'; readonly value: null }
  | { readonly kind: 'filled'; readonly value: BRegAttachmentState }

/** Opaque bytes already accepted by one slot's served upload policy. */
export declare class BRegAttachmentUpload {
  private constructor()
  private readonly __opaque: void
  readonly contentType: string
  readonly byteSize: SafeInteger
}

/** Opaque governed attachment slot selected from metadata fetched by this client source. */
export declare class BRegAttachmentSlot {
  private constructor()
  private readonly __opaque: void
  readonly slotIdentifier: string
  readonly entityIdentifier: string
  readonly accessProfile: string
  readonly requiredForSubmit: boolean
  readonly maximumBytes: SafeInteger
  readonly contentTypes: ReadonlyArray<string>
  readonly classification: BRegAttachmentClassification
  readonly canDownload: boolean
  readonly canUpload: boolean
  readonly canRemove: boolean
  acceptsContentType(contentType: string): boolean
  prepareUpload(contentType: string, body: Buffer): BRegAttachmentUpload
  valueIn(record: RecordEnvelope, format?: RecordFormat | null): BRegAttachmentSlotValue
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
/** Opaque authority for one metadata-selected immediate action. */
export declare class BRegImmediateActionBinding {
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
/** Opaque lifecycle authority selected from metadata fetched by this client source. */
export declare class BRegLifecycleAuthority {
  private constructor()
  private readonly __opaque: void
}

/** Inert caller-visible target provenance. It grants no read authority. */
export declare class BRegRequestResultReference {
  private constructor()
  private readonly __opaque: void
  readonly targetEntityIdentifier: string
  readonly targetRecordIdentifier: string
  /** Revision written by the application, not a current ETag or precondition. */
  readonly targetRevision: SafeInteger
  toString(): string
}

/** One exact retained proposal from an explicitly loaded history page. */
export declare class BRegRetainedRequestProposalView {
  private constructor()
  private readonly __opaque: void
  readonly requestEntityIdentifier: string
  readonly requestIdentifier: string
  readonly proposalVersion: SafeInteger
  readonly bregState: BRegRequestState
  readonly current: boolean
  readonly detailErased: boolean
  readonly applicationIdentifier: string | null
  /** Caller-visible count, never an undisclosed application total. */
  readonly resultLinkCount: SafeInteger
  readonly resultReferences: ReadonlyArray<BRegRequestResultReference>
  toString(): string
}

/** One page only. Call getRecord with its cursor to load another page. */
export declare class BRegRetainedRequestHistoryPage {
  private constructor()
  private readonly __opaque: void
  readonly proposals: ReadonlyArray<BRegRetainedRequestProposalView>
  readonly nextAfterProposalVersion: SafeInteger | null
  findProposal(requestEntityIdentifier: string, requestIdentifier: string, proposalVersion: SafeInteger): BRegRetainedRequestProposalView | null
  findApplication(requestEntityIdentifier: string, requestIdentifier: string, proposalVersion: SafeInteger, applicationIdentifier: string): BRegRetainedRequestProposalView | null
  toString(): string
}

/** Opaque executable action promoted from a metadata authority and one record. */
export declare class BRegLifecycleAction {
  withReason(reason: string): BRegLifecycleAction
  private constructor()
  private readonly __opaque: void
  readonly operation: string
  readonly href: string
  readonly bodyJson: string
  readonly body: JsonObject
}

/** Inert bounded Create evidence. Persist these bytes with owner-only access. */
export declare class BRegPreparedCreate {
  private constructor()
  private readonly __opaque: void
  static fromBytes(bytes: Buffer): BRegPreparedCreate
  toBytes(): Buffer
}

/** Inert bounded lifecycle evidence. Persist these bytes with owner-only access. */
export declare class BRegPreparedLifecycle {
  private constructor()
  private readonly __opaque: void
  static fromBytes(bytes: Buffer): BRegPreparedLifecycle
  toBytes(): Buffer
}

/** Revalidated Create request. It still requires fresh metadata authority to send. */
export declare class BRegRecoveredCreate {
  private constructor()
  private readonly __opaque: void
}

/** Revalidated lifecycle action. It remains inert until explicitly sent. */
export declare class BRegRecoveredLifecycle {
  private constructor()
  private readonly __opaque: void
}

/** Caller-filtered metadata bound to the exact client source that fetched it. */
export declare class BRegMetadata {
  private constructor()
  private readonly __opaque: void
  readonly operations: ReadonlyArray<BRegOperationDescriptor>
  readonly immediateActions: ReadonlyArray<BRegImmediateActionDescriptor>
  readonly actionsJson: string | null
  readonly registryIdentifier: string
  readonly registryVersion: string
  readonly registryRevision: string
  readonly traceId: string
  readonly etag: string | null
  changeRequestCapability(entityIdentifier: string): BRegChangeRequestCapability | null
  selectCreate(operationIdentifier: string, expectedProfile: string): BRegCreateBinding
  selectPatch(operationIdentifier: string, expectedProfile: string): BRegPatchBinding
  selectLifecycle(entityIdentifier: string, expectedProfile: string): BRegLifecycleAuthority
  selectAttachments(entityIdentifier: string, expectedProfile: string): ReadonlyArray<BRegAttachmentSlot>
  selectImmediateAction(actionIdentifier: string, expectedProfile: string): BRegImmediateActionBinding
  selectTombstone(entityIdentifier: string, expectedProfile: string): BRegTombstoneBinding
  selectBatch(entityIdentifier: string, expectedProfile: string): BRegBatchBinding
}

export interface BaseRegistryClientFailure extends Error {
  readonly kind: string
  readonly code?: string
  readonly planRefusal?: string
  readonly refusalCode?: string
  readonly status?: number
  readonly traceId?: string
  readonly transportKind?: string
  readonly tokenKind?: string
}

export declare class BaseRegistryClientError extends Error implements BaseRegistryClientFailure {
  readonly kind: string
  readonly code?: string
  readonly planRefusal?: string
  readonly refusalCode?: string
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
  actionTargetConditions(binding: BRegImmediateActionBinding, inputs: JsonObject): Promise<BRegActionTargetConditions>
  actionTargetConditionsJson(binding: BRegImmediateActionBinding, inputsJson: string): Promise<BRegActionTargetConditions>
  invokeAction(binding: BRegImmediateActionBinding, inputs: JsonObject, idempotencyKey: string, conditions?: BRegActionTargetConditions | null): Promise<CompleteOutcome<BRegActionReceipt>>
  invokeActionJson(binding: BRegImmediateActionBinding, inputsJson: string, idempotencyKey: string, conditions?: BRegActionTargetConditions | null): Promise<JsonOutcome>
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
  lifecycleActions(authority: BRegLifecycleAuthority, record: RecordEnvelope, format?: RecordFormat | null): ReadonlyArray<BRegLifecycleAction>
  /** Pure typed projection of one already loaded page. Performs no I/O. */
  requestHistory(record: RecordEnvelope, format?: RecordFormat | null): BRegRetainedRequestHistoryPage | null
  prepareLifecycleAction(authority: BRegLifecycleAuthority, record: RecordEnvelope, action: BRegLifecycleAction, idempotencyKey: string, format?: RecordFormat | null): BRegPreparedLifecycle
  prepareLifecycleActionJson(authority: BRegLifecycleAuthority, recordJson: string, action: BRegLifecycleAction, idempotencyKey: string, format?: RecordFormat | null): BRegPreparedLifecycle
  recoverLifecycleAction(authority: BRegLifecycleAuthority, prepared: BRegPreparedLifecycle): BRegRecoveredLifecycle
  executeRecoveredLifecycleAction(recovered: BRegRecoveredLifecycle): Promise<CompleteOutcome<LifecycleReceipt>>
  executeRecoveredLifecycleActionJson(recovered: BRegRecoveredLifecycle): Promise<JsonOutcome>
  uploadAttachment(slot: BRegAttachmentSlot, recordIdentifier: string, etag: string, upload: BRegAttachmentUpload, idempotencyKey: string, format?: RecordFormat | null): Promise<CompleteOutcome<RecordEnvelope>>
  downloadAttachment(slot: BRegAttachmentSlot, recordIdentifier: string, proposalVersion: SafeInteger): Promise<RawOutcome>
  deleteAttachment(slot: BRegAttachmentSlot, recordIdentifier: string, etag: string, idempotencyKey: string, format?: RecordFormat | null): Promise<CompleteOutcome<RecordEnvelope>>
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
  uploadAttachmentJson(slot: BRegAttachmentSlot, recordIdentifier: string, etag: string, upload: BRegAttachmentUpload, idempotencyKey: string, format?: RecordFormat | null): Promise<JsonOutcome>
  deleteAttachmentJson(slot: BRegAttachmentSlot, recordIdentifier: string, etag: string, idempotencyKey: string, format?: RecordFormat | null): Promise<JsonOutcome>
  lifecycleActionsJson(authority: BRegLifecycleAuthority, recordJson: string, format?: RecordFormat | null): ReadonlyArray<BRegLifecycleAction>
  executeLifecycleActionJson(action: BRegLifecycleAction, idempotencyKey: string): Promise<JsonOutcome>
  executeLifecycleAction(action: BRegLifecycleAction, idempotencyKey: string): Promise<CompleteOutcome<LifecycleReceipt>>
}
