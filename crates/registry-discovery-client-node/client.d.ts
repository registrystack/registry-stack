export type ServiceKind = 'evidence' | 'relay';

export interface DiscoveryClientOptions {
  baseUrl: string;
  requestTimeoutMilliseconds?: number;
  connectTimeoutMilliseconds?: number;
  maximumResponseBytes?: number;
  trustedRootCertificates?: Buffer;
}

export interface EvidenceTypeResolveRequest {
  requirementId: string;
  jurisdiction?: string;
}

export interface ResolvedAlternative {
  evidenceTypeListId: string;
  evidenceTypeIds: string[];
  mappingId: string;
  mappingAuthorityId: string;
}

export interface EvidenceTypeResolveResponse extends EvidenceTypeResolveRequest {
  mappingRevision: string;
  alternatives: ResolvedAlternative[];
}

export interface ServiceFilters {
  recordId?: string[];
  serviceId?: string[];
  serviceKind?: ServiceKind[];
  jurisdiction?: string[];
  conformsTo?: string[];
  evidenceType?: string[];
  semanticClass?: string[];
  operationFamily?: string[];
}

export interface EvidenceServiceQuery {
  evidenceTypeId: string;
  jurisdiction?: string;
  serviceIds?: string[];
  conformsTo?: string[];
}

interface RelayServiceQueryOptions {
  jurisdiction?: string;
  serviceIds?: string[];
  conformsTo?: string[];
}

export type RelayServiceQuery = RelayServiceQueryOptions & (
  | { semanticClassId: string; operationFamilyId?: string }
  | { semanticClassId?: string; operationFamilyId: string }
);

export interface ServiceRecord {
  recordId: string;
  bindingId: string;
  serviceId: string;
  serviceKind: ServiceKind;
  title: string;
  description: string;
  endpointUrl: string;
  publisherId?: string;
  operatorId?: string;
  registryAuthorityId?: string;
  legalIssuerId?: string;
  technicalProviderId?: string;
  jurisdictions: string[];
  conformsTo: string[];
  evidenceTypeIds: string[];
  semanticClassIds: string[];
  operationFamilyIds: string[];
  originId: string;
  originUrl: string;
  originContentDigest: string;
  originFetchedAt: string;
}

export interface ServiceSearchResponse {
  catalogRevision: string;
  items: ServiceRecord[];
}

export type MatchedCapability =
  | { kind: 'evidence-type'; id: string }
  | { kind: 'semantic-class'; id: string }
  | { kind: 'operation-family'; id: string };

export interface SelectionRequest {
  recordId: string;
  matchedCapability: MatchedCapability;
  mappingRevision?: string;
}

export interface EvidenceResolutionContext {
  requirementId: string;
  jurisdiction?: string;
  mappingRevision: string;
  evidenceTypeListId: string;
  evidenceTypeIds: string[];
  mappingId: string;
  mappingAuthorityId: string;
}

export interface EvidenceSelectionRequest {
  recordId: string;
  evidenceTypeId: string;
  resolution?: EvidenceResolutionContext;
}

export type RelayCapabilityMatch =
  | { semanticClassId: string; operationFamilyId?: string }
  | { semanticClassId?: string; operationFamilyId: string };

export interface RelaySelectionRequest {
  recordId: string;
  capabilityMatch: RelayCapabilityMatch;
}

export interface CommonServiceSelection extends Omit<ServiceRecord, 'title' | 'description'> {
  matchedCapability: MatchedCapability;
  catalogRevision: string;
  mappingRevision?: string;
}

export interface EvidenceServiceSelection extends CommonServiceSelection {
  serviceKind: 'evidence';
  matchedCapability: { kind: 'evidence-type'; id: string };
  evidenceResolution?: EvidenceResolutionContext;
}

export interface RelayServiceSelection extends CommonServiceSelection {
  serviceKind: 'relay';
  matchedCapability:
    | { kind: 'semantic-class'; id: string }
    | { kind: 'operation-family'; id: string };
  relayCapabilityMatch: RelayCapabilityMatch;
}

export type ServiceSelection = CommonServiceSelection;

export type DiscoveryClientErrorKind =
  | 'configuration'
  | 'query'
  | 'no_matching_service'
  | 'ambiguous_selection'
  | 'no_matching_alternative'
  | 'ambiguous_alternative'
  | 'capability_mismatch'
  | 'local_acceptance_refused'
  | 'selection_changed'
  | 'transport'
  | 'problem'
  | 'protocol'
  | 'client';

export class DiscoveryClientError extends Error {
  readonly kind: DiscoveryClientErrorKind;
  readonly status?: number;
  readonly problem?: string;
  readonly transportKind?: string;
}

export class DiscoveryClient {
  constructor(options: string | DiscoveryClientOptions);
  resolveEvidenceTypes(request: EvidenceTypeResolveRequest): Promise<EvidenceTypeResolveResponse>;
  searchServices(filters?: ServiceFilters): Promise<ServiceSearchResponse>;
  searchEvidenceServices(query: EvidenceServiceQuery): Promise<ServiceSearchResponse>;
  searchRelayServices(query: RelayServiceQuery): Promise<ServiceSearchResponse>;
  selectExact(response: ServiceSearchResponse, request: SelectionRequest): CommonServiceSelection;
  selectEvidenceAlternative(
    response: EvidenceTypeResolveResponse,
    evidenceTypeListId?: string,
  ): EvidenceResolutionContext;
  selectEvidenceService(
    response: ServiceSearchResponse,
    request: EvidenceSelectionRequest,
  ): EvidenceServiceSelection;
  selectRelayService(
    response: ServiceSearchResponse,
    request: RelaySelectionRequest,
  ): RelayServiceSelection;
}

export function selectExact(
  response: ServiceSearchResponse,
  request: SelectionRequest,
): CommonServiceSelection;

export function selectEvidenceAlternative(
  response: EvidenceTypeResolveResponse,
  evidenceTypeListId?: string,
): EvidenceResolutionContext;

export function selectEvidenceService(
  response: ServiceSearchResponse,
  request: EvidenceSelectionRequest,
): EvidenceServiceSelection;

export function selectRelayService(
  response: ServiceSearchResponse,
  request: RelaySelectionRequest,
): RelayServiceSelection;

/**
 * Validate closed shape and capability binding only.
 *
 * This does not prove origin authenticity, catalog currentness, mapping
 * currency, authorization, or adopter trust.
 */
export function validateSelectionStructure<T extends CommonServiceSelection>(selection: T): T;

/** @deprecated Use validateSelectionStructure. This operation is structural, not trust. */
export function validateSelection<T extends CommonServiceSelection>(selection: T): T;

export class AcceptedServiceSelection<T extends CommonServiceSelection> {
  private constructor();
  private readonly __acceptedServiceSelectionBrand: void;
  readonly endpointUrl: string;
  readonly selection: T;
}

/** Apply a synchronous adopter-owned local policy after structural validation. */
export function acceptSelection<T extends CommonServiceSelection>(
  selection: T,
  accepts: (selection: T) => boolean,
): AcceptedServiceSelection<T>;

/**
 * Return a freshly reselected service only when its trust-relevant semantics
 * are unchanged. The current selection must come from a new online lookup.
 */
export function renewUnchangedSelection<T extends CommonServiceSelection>(
  previous: T,
  current: T,
): T;
