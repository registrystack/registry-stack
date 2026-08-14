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

export interface ServiceSelection extends Omit<ServiceRecord, 'title' | 'description'> {
  matchedCapability: MatchedCapability;
  catalogRevision: string;
  mappingRevision?: string;
}

export type DiscoveryClientErrorKind =
  | 'configuration'
  | 'query'
  | 'no_matching_service'
  | 'ambiguous_selection'
  | 'capability_mismatch'
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
  selectExact(response: ServiceSearchResponse, request: SelectionRequest): ServiceSelection;
}

export function selectExact(
  response: ServiceSearchResponse,
  request: SelectionRequest,
): ServiceSelection;
