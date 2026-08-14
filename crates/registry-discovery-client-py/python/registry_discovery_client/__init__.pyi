from typing import Literal, TypedDict

ServiceKind = Literal["evidence", "relay"]

class _EvidenceTypeResolveRequestRequired(TypedDict):
    requirementId: str

class EvidenceTypeResolveRequest(_EvidenceTypeResolveRequestRequired, total=False):
    jurisdiction: str

class ResolvedAlternative(TypedDict):
    evidenceTypeListId: str
    evidenceTypeIds: list[str]
    mappingId: str
    mappingAuthorityId: str

class EvidenceTypeResolveResponse(EvidenceTypeResolveRequest):
    mappingRevision: str
    alternatives: list[ResolvedAlternative]

class ServiceFilters(TypedDict, total=False):
    recordId: list[str]
    serviceId: list[str]
    serviceKind: list[ServiceKind]
    jurisdiction: list[str]
    conformsTo: list[str]
    evidenceType: list[str]
    semanticClass: list[str]
    operationFamily: list[str]

class _ServiceRecordRequired(TypedDict):
    recordId: str
    bindingId: str
    serviceId: str
    serviceKind: ServiceKind
    title: str
    description: str
    endpointUrl: str
    jurisdictions: list[str]
    conformsTo: list[str]
    evidenceTypeIds: list[str]
    semanticClassIds: list[str]
    operationFamilyIds: list[str]
    originId: str
    originUrl: str
    originContentDigest: str
    originFetchedAt: str

class ServiceRecord(_ServiceRecordRequired, total=False):
    publisherId: str
    operatorId: str
    registryAuthorityId: str
    legalIssuerId: str
    technicalProviderId: str

class ServiceSearchResponse(TypedDict):
    catalogRevision: str
    items: list[ServiceRecord]

class MatchedCapability(TypedDict):
    kind: Literal["evidence-type", "semantic-class", "operation-family"]
    id: str

class _SelectionRequestRequired(TypedDict):
    recordId: str
    matchedCapability: MatchedCapability

class SelectionRequest(_SelectionRequestRequired, total=False):
    mappingRevision: str

class _ServiceSelectionRequired(TypedDict):
    recordId: str
    bindingId: str
    serviceId: str
    serviceKind: ServiceKind
    endpointUrl: str
    jurisdictions: list[str]
    conformsTo: list[str]
    evidenceTypeIds: list[str]
    semanticClassIds: list[str]
    operationFamilyIds: list[str]
    matchedCapability: MatchedCapability
    originId: str
    originUrl: str
    originContentDigest: str
    originFetchedAt: str
    catalogRevision: str

class ServiceSelection(_ServiceSelectionRequired, total=False):
    publisherId: str
    operatorId: str
    registryAuthorityId: str
    legalIssuerId: str
    technicalProviderId: str
    mappingRevision: str

class DiscoveryClientError(Exception):
    """A stable, value-free Discovery client failure."""
    kind: Literal[
        "configuration",
        "query",
        "no_matching_service",
        "ambiguous_selection",
        "capability_mismatch",
        "transport",
        "problem",
        "protocol",
        "client",
    ]
    status: int | None
    problem: str | None
    transport_kind: str | None

class DiscoveryClient:
    def __init__(
        self,
        base_url: str,
        request_timeout_seconds: float | None = ...,
        connect_timeout_seconds: float | None = ...,
        maximum_response_bytes: int | None = ...,
        trusted_root_certificates: bytes | None = ...,
    ) -> None: ...
    def resolve_evidence_types(self, request: EvidenceTypeResolveRequest) -> EvidenceTypeResolveResponse: ...
    def search_services(self, filters: ServiceFilters) -> ServiceSearchResponse: ...
    def select_exact(self, response: ServiceSearchResponse, request: SelectionRequest) -> ServiceSelection: ...

def select_exact(response: ServiceSearchResponse, request: SelectionRequest) -> ServiceSelection: ...
