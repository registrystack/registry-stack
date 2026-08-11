export type JsonScalar = string | number | boolean | null
export type JsonValue = JsonScalar | ReadonlyArray<JsonValue> | { readonly [key: string]: JsonValue }

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
  assertionLifetimeSeconds?: number | null
  refreshMarginSeconds?: number | null
  requestTimeoutMilliseconds?: number | null
  connectTimeoutMilliseconds?: number | null
  userAgent?: string | null
  trustedRootCertificates?: string | null
}

export type RelayAuthorization =
  | { static: string }
  | { privateKeyJwt: PrivateKeyJwtConfig }

export interface RelayClientConfig {
  baseUrl: string
  authorization?: RelayAuthorization | null
  requestTimeoutMilliseconds?: number | null
  connectTimeoutMilliseconds?: number | null
  userAgent?: string | null
  maxResponseBytes?: number | null
  trustedRootCertificates?: string | null
}

export type RecordFormat = 'json' | 'json-ld' | 'geojson' | 'geo-json-rfc7946' | 'json-fg'

export interface ResourceListOptions {
  pageSize?: number | null
}

export interface ResourceContinuation {
  cursor: string
}

export interface RecordOptions {
  fields?: ReadonlyArray<string> | null
  accessProfile?: string | null
  format?: RecordFormat | null
}

export interface ListOptions extends RecordOptions {
  pageSize?: number | null
  filters?: Readonly<Record<string, string>> | null
}

export interface SearchOptions extends RecordOptions {
  pageSize?: number | null
  /** `[west, south, east, north]` in WGS84 longitude/latitude degrees. */
  bbox: readonly [number, number, number, number]
}

/** Numeric selectors must satisfy `Number.isSafeInteger`. */
export type LookupSelector = string | number | boolean
export type LookupSelectors = Readonly<Record<string, LookupSelector>>

export interface RecordsRoute {
  kind: 'records'
  resource: string
}

export interface SearchRoute {
  kind: 'search'
  resource: string
  search: string
}

export interface CollectionContinuation<Route extends RecordsRoute | SearchRoute = RecordsRoute | SearchRoute> {
  route: Route
  cursor: string
  format: 'json' | 'json-ld' | 'geojson-rfc7946' | 'json-fg'
  accessProfile?: string
}

export interface SdmxDataRequest {
  agency: string
  resource: string
  /** A three-part `x.y.z` SDMX version. */
  version: string
  key?: string | null
  constraints?: Readonly<Record<string, string>> | null
  offset?: number | null
  limit?: number | null
  dimensionAtObservation?: string | null
  format?: 'json' | 'csv' | null
}

export interface SdmxStructureRequest {
  kind: 'dataflow' | 'datastructure' | 'data-structure'
  agency: string
  resource: string
  /** A three-part `x.y.z` SDMX version. */
  version: string
}

export interface ProbeStatus {
  status: string
}

export interface Institution {
  identifier: string
  name: string
}

export interface ServiceMetadata {
  registryIdentifier: string
  name: string
  authority: Institution
  operator: Institution | null
  authoritativeScope: string
  product: { name: string; version: string }
  apiBinding: { name: string; version: string }
  alignmentTargets: ReadonlyArray<JsonValue>
  capabilities: ReadonlyArray<JsonValue>
  links: { self: string; resources: string; openapi: string }
}

export interface ResourceDocument {
  resourceIdentifier: string
  title: string
  description: string
  semanticClass: string
  enumerationPosture: string
  capabilities: ReadonlyArray<JsonValue>
  links: { self: string }
}

export interface ResourceCollection {
  items: ReadonlyArray<ResourceDocument>
  pageInfo: { nextCursor: string | null }
  meta: { registryIdentifier: string }
}

export interface ResourceEnvelope {
  data: ResourceDocument
  meta: { registryIdentifier: string }
}

export interface RegistryRecord {
  registryIdentifier: string
  recordIdentifier: string
  revisionIdentifier: string
  lifecycleState: string
  schemaReference: string
  semanticModelReference: string
  authorityIdentifier: string
  recordedAt: string
  domainData: Readonly<Record<string, JsonValue>>
  '@id'?: string
  '@type'?: string
}

export type RecordResponse = JsonValue
export type RecordCollectionResponse = JsonValue

export interface CompleteOutcome<T> {
  kind: 'complete'
  value: T
  traceId: string
  etag?: string
}

export interface NotModifiedOutcome {
  kind: 'notModified'
  etag: string
  traceId: string
}

export type Outcome<T> = CompleteOutcome<T> | NotModifiedOutcome

export interface ResourcePageCompleteOutcome {
  kind: 'complete'
  value: ResourceCollection
  continuation?: ResourceContinuation
  traceId: string
  etag?: string
}

export type ResourcePageOutcome = ResourcePageCompleteOutcome | NotModifiedOutcome

export interface CollectionPageCompleteOutcome {
  kind: 'complete'
  value: RecordCollectionResponse
  continuation?: CollectionContinuation
  traceId: string
  etag?: string
}

export type CollectionPageOutcome = CollectionPageCompleteOutcome | NotModifiedOutcome

export interface RawCompleteOutcome {
  kind: 'complete'
  body: Buffer
  mediaType: string
  traceId: string
  etag?: string
}

export type RawOutcome = RawCompleteOutcome | NotModifiedOutcome

export interface RelayClientFailure extends Error {
  readonly kind: string
  readonly code?: string
  readonly status?: number
  readonly traceId?: string
  readonly retryAfterSeconds?: number
  readonly transportKind?: string
  readonly tokenKind?: string
}

export declare class RelayClientError extends Error implements RelayClientFailure {
  readonly kind: string
  readonly code?: string
  readonly status?: number
  readonly traceId?: string
  readonly retryAfterSeconds?: number
  readonly transportKind?: string
  readonly tokenKind?: string
}

export declare class RelayClient {
  constructor(config: RelayClientConfig)
  health(): Promise<CompleteOutcome<ProbeStatus>>
  ready(): Promise<CompleteOutcome<ProbeStatus>>
  openapi(etag?: string | null): Promise<RawOutcome>
  serviceMetadata(etag?: string | null): Promise<Outcome<ServiceMetadata>>
  resources(options?: ResourceListOptions | null, etag?: string | null): Promise<ResourcePageOutcome>
  continueResources(continuation: ResourceContinuation, etag?: string | null): Promise<ResourcePageOutcome>
  resource(resource: string, etag?: string | null): Promise<Outcome<ResourceEnvelope>>
  listRecords(resource: string, options?: ListOptions | null, etag?: string | null): Promise<CollectionPageOutcome>
  continueListRecords(continuation: CollectionContinuation<RecordsRoute>, etag?: string | null): Promise<CollectionPageOutcome>
  readRecord(resource: string, recordIdentifier: string, options?: RecordOptions | null, etag?: string | null): Promise<Outcome<RecordResponse>>
  lookup(resource: string, lookup: string, selectors: LookupSelectors, options?: RecordOptions | null, etag?: string | null): Promise<Outcome<RecordResponse>>
  search(resource: string, search: string, options: SearchOptions, etag?: string | null): Promise<CollectionPageOutcome>
  continueSearch(continuation: CollectionContinuation<SearchRoute>, etag?: string | null): Promise<CollectionPageOutcome>
  artifact(artifactIdentifier: string, etag?: string | null): Promise<RawOutcome>
  sdmxData(request: SdmxDataRequest, etag?: string | null): Promise<RawOutcome>
  sdmxStructure(request: SdmxStructureRequest, etag?: string | null): Promise<RawOutcome>
}
