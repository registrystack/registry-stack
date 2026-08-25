from typing import Callable, Generic, Literal, TypeVar, TypedDict

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

class _EvidenceServiceQueryRequired(TypedDict):
    evidenceTypeId: str

class EvidenceServiceQuery(_EvidenceServiceQueryRequired, total=False):
    jurisdiction: str
    serviceIds: list[str]
    conformsTo: list[str]

class _RelayServiceQueryOptions(TypedDict, total=False):
    jurisdiction: str
    serviceIds: list[str]
    conformsTo: list[str]

class _RelaySemanticServiceQuery(_RelayServiceQueryOptions):
    semanticClassId: str

class _RelayOperationServiceQuery(_RelayServiceQueryOptions):
    operationFamilyId: str

class _RelayCombinedServiceQuery(_RelayServiceQueryOptions):
    semanticClassId: str
    operationFamilyId: str

RelayServiceQuery = (
    _RelaySemanticServiceQuery | _RelayOperationServiceQuery | _RelayCombinedServiceQuery
)

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

class EvidenceMatchedCapability(TypedDict):
    kind: Literal["evidence-type"]
    id: str

class RelayMatchedCapability(TypedDict):
    kind: Literal["semantic-class", "operation-family"]
    id: str

MatchedCapability = EvidenceMatchedCapability | RelayMatchedCapability

class _SelectionRequestRequired(TypedDict):
    recordId: str
    matchedCapability: MatchedCapability

class SelectionRequest(_SelectionRequestRequired, total=False):
    mappingRevision: str

class _EvidenceResolutionContextRequired(TypedDict):
    requirementId: str
    mappingRevision: str
    evidenceTypeListId: str
    evidenceTypeIds: list[str]
    mappingId: str
    mappingAuthorityId: str

class EvidenceResolutionContext(_EvidenceResolutionContextRequired, total=False):
    jurisdiction: str

class _EvidenceSelectionRequestRequired(TypedDict):
    recordId: str
    evidenceTypeId: str

class EvidenceSelectionRequest(_EvidenceSelectionRequestRequired, total=False):
    resolution: EvidenceResolutionContext

class _RelaySemanticCapabilityMatch(TypedDict):
    semanticClassId: str

class _RelayOperationCapabilityMatch(TypedDict):
    operationFamilyId: str

class _RelayCombinedCapabilityMatch(TypedDict):
    semanticClassId: str
    operationFamilyId: str

RelayCapabilityMatch = (
    _RelaySemanticCapabilityMatch | _RelayOperationCapabilityMatch | _RelayCombinedCapabilityMatch
)

class RelaySelectionRequest(TypedDict):
    recordId: str
    capabilityMatch: RelayCapabilityMatch

class _CommonServiceSelectionRequired(TypedDict):
    recordId: str
    bindingId: str
    serviceId: str
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
    catalogRevision: str

class _CommonServiceSelectionOptional(TypedDict, total=False):
    publisherId: str
    operatorId: str
    registryAuthorityId: str
    legalIssuerId: str
    technicalProviderId: str
    mappingRevision: str

class _GenericServiceSelectionRequired(_CommonServiceSelectionRequired):
    serviceKind: ServiceKind
    matchedCapability: MatchedCapability

class CommonServiceSelection(
    _GenericServiceSelectionRequired,
    _CommonServiceSelectionOptional,
):
    pass

class _EvidenceServiceSelectionRequired(_CommonServiceSelectionRequired):
    serviceKind: Literal["evidence"]
    matchedCapability: EvidenceMatchedCapability

class EvidenceServiceSelection(
    _EvidenceServiceSelectionRequired,
    _CommonServiceSelectionOptional,
    total=False,
):
    evidenceResolution: EvidenceResolutionContext

class RelayServiceSelection(
    _CommonServiceSelectionRequired,
    _CommonServiceSelectionOptional,
):
    serviceKind: Literal["relay"]
    matchedCapability: RelayMatchedCapability
    relayCapabilityMatch: RelayCapabilityMatch

ServiceSelection = CommonServiceSelection | EvidenceServiceSelection | RelayServiceSelection
_SelectionT = TypeVar("_SelectionT", bound=ServiceSelection)

class AcceptedServiceSelection(Generic[_SelectionT]):
    @property
    def endpoint_url(self) -> str: ...
    @property
    def selection(self) -> _SelectionT: ...

class DiscoveryClientError(Exception):
    """A stable, value-free Discovery client failure."""
    kind: Literal[
        "configuration",
        "query",
        "no_matching_service",
        "ambiguous_selection",
        "no_matching_alternative",
        "ambiguous_alternative",
        "capability_mismatch",
        "local_acceptance_refused",
        "selection_changed",
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
    def search_evidence_services(self, query: EvidenceServiceQuery) -> ServiceSearchResponse: ...
    def search_relay_services(self, query: RelayServiceQuery) -> ServiceSearchResponse: ...
    def select_exact(self, response: ServiceSearchResponse, request: SelectionRequest) -> CommonServiceSelection: ...
    def select_evidence_alternative(
        self,
        response: EvidenceTypeResolveResponse,
        evidence_type_list_id: str | None = ...,
    ) -> EvidenceResolutionContext: ...
    def select_evidence_service(
        self,
        response: ServiceSearchResponse,
        request: EvidenceSelectionRequest,
    ) -> EvidenceServiceSelection: ...
    def select_relay_service(
        self,
        response: ServiceSearchResponse,
        request: RelaySelectionRequest,
    ) -> RelayServiceSelection: ...

def select_exact(response: ServiceSearchResponse, request: SelectionRequest) -> CommonServiceSelection: ...
def select_evidence_alternative(
    response: EvidenceTypeResolveResponse,
    evidence_type_list_id: str | None = ...,
) -> EvidenceResolutionContext: ...
def select_evidence_service(
    response: ServiceSearchResponse,
    request: EvidenceSelectionRequest,
) -> EvidenceServiceSelection: ...
def select_relay_service(
    response: ServiceSearchResponse,
    request: RelaySelectionRequest,
) -> RelayServiceSelection: ...
def validate_selection_structure(selection: _SelectionT) -> _SelectionT:
    """Validate closed shape and capability binding, not trust or currentness."""
    ...
def validate_selection(selection: _SelectionT) -> _SelectionT:
    """Deprecated compatibility alias for validate_selection_structure."""
    ...
def accept_selection(
    selection: _SelectionT,
    accepts: Callable[[_SelectionT], bool],
) -> AcceptedServiceSelection[_SelectionT]: ...
def renew_unchanged_selection(previous: _SelectionT, current: _SelectionT) -> _SelectionT: ...
