export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }
/** Structured mutation inputs reject integer-valued numbers outside
 * `Number.isSafeInteger`. Use the corresponding `...Json` method for exact
 * wider integer values. */
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
  }
  readonly reviewMode: 'none' | 'staged'
  readonly application: {
    readonly mode: 'manual' | 'automatic' | 'planner'
    readonly allowedDispositions: ReadonlyArray<'apply' | 'queue'>
    readonly queueReasons: ReadonlyArray<{ readonly code: string; readonly label: string }>
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

/** Opaque executable action promoted from a metadata authority and one record. */
export declare class BRegLifecycleAction {
  withReason(reason: string): BRegLifecycleAction
  private constructor()
  private readonly __opaque: void
  readonly operation: string
  readonly stage: string | null
  readonly href: string
  readonly bodyJson: string
  readonly reviewJson: string | null
  readonly body: JsonObject
  readonly review: LifecycleReview | null
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
  tombstoneRecord(binding: BRegTombstoneBinding, recordIdentifier: string, etag: string, idempotencyKey: string, format?: RecordFormat | null): Promise<CompleteOutcome<RecordEnvelope>>
  tombstoneRecordJson(binding: BRegTombstoneBinding, recordIdentifier: string, etag: string, idempotencyKey: string, format?: RecordFormat | null): Promise<JsonOutcome>
  lifecycleActions(authority: BRegLifecycleAuthority, record: RecordEnvelope, format?: RecordFormat | null): ReadonlyArray<BRegLifecycleAction>
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
