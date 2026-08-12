"""Types for the synchronous Registry Relay V2 client binding."""

from typing import Generic, Literal, Optional, Sequence, TypeAlias, TypeVar, TypedDict, Union

JsonScalar = Union[str, int, float, bool, None]
JsonValue = Union[JsonScalar, list["JsonValue"], dict[str, "JsonValue"]]
RecordFormat = Literal["json", "json-ld", "geojson", "json-fg"]
SdmxDataFormat = Literal["json", "csv"]
SdmxStructureKind = Literal["dataflow", "datastructure"]
Selector = Union[str, int, bool]
BoundingBox = list[float] | tuple[float, float, float, float]


class _PrivateKeyJwtRequired(TypedDict):
    token_endpoint: str
    client_id: str
    client_key: dict[str, JsonValue]


class PrivateKeyJwtConfig(_PrivateKeyJwtRequired, total=False):
    audience: Optional[str]
    assertion_lifetime_seconds: Optional[int]
    refresh_margin_seconds: Optional[int]
    request_timeout_seconds: Optional[float]
    connect_timeout_seconds: Optional[float]
    user_agent: Optional[str]
    trusted_root_certificates: bytes


StaticAuthorization = TypedDict("StaticAuthorization", {"static": str})
PrivateKeyJwtAuthorization = TypedDict(
    "PrivateKeyJwtAuthorization", {"private_key_jwt": PrivateKeyJwtConfig}
)
RelayAuthorization = Union[StaticAuthorization, PrivateKeyJwtAuthorization]

RecordsRoute = TypedDict(
    "RecordsRoute", {"kind": Literal["records"], "resource": str}
)
SearchRoute = TypedDict(
    "SearchRoute",
    {"kind": Literal["search"], "resource": str, "search": str},
)


class ResourceContinuation(TypedDict):
    cursor: str


class _CollectionContinuationRequired(TypedDict):
    route: Union[RecordsRoute, SearchRoute]
    cursor: str
    format: Literal["json", "json-ld", "geojson-rfc7946", "json-fg"]


class CollectionContinuation(_CollectionContinuationRequired, total=False):
    accessProfile: str


class ProbeStatus(TypedDict):
    status: str


class Institution(TypedDict):
    identifier: str
    name: str


class Product(TypedDict):
    name: str
    version: str


class ApiBinding(TypedDict):
    name: str
    version: str


class _AlignmentTargetRequired(TypedDict):
    name: str
    version: str
    status: str


class AlignmentTarget(_AlignmentTargetRequired, total=False):
    cfrTarget: str


ServiceLinks = TypedDict(
    "ServiceLinks", {"self": str, "resources": str, "openapi": str}
)


class ServiceMetadata(TypedDict):
    registryIdentifier: str
    name: str
    authority: Institution
    operator: Optional[Institution]
    authoritativeScope: str
    product: Product
    apiBinding: ApiBinding
    alignmentTargets: list[AlignmentTarget]
    capabilities: list[Capability]
    links: ServiceLinks


class FormatProfileCapability(TypedDict):
    id: str
    uri: str
    crs: str
    conformsTo: list[str]


class WireFormatCapability(TypedDict):
    id: str
    mediaType: str
    formatProfiles: list[FormatProfileCapability]


class BboxCapability(TypedDict):
    crs: str
    predicate: str
    maximumLongitudeSpanDegrees: float
    maximumLatitudeSpanDegrees: float


class SpatialQueryCapability(TypedDict):
    bbox: BboxCapability


class _ConsultationCapabilityRequired(TypedDict):
    family: Literal["consultation"]
    pattern: str
    resourceIdentifier: str
    operationIdentifier: str
    accessProfileIdentifier: str
    isDefault: bool
    disclosureProfile: str
    schemaReference: str
    semanticModelReference: str
    contextReference: str
    href: str
    wireFormats: list[WireFormatCapability]


class ConsultationCapability(_ConsultationCapabilityRequired, total=False):
    spatialQuery: SpatialQueryCapability
    classificationReference: str
    processingReference: str


class SdmxProfile(TypedDict):
    sdmxRestVersion: str
    sdmxDataJsonVersion: str
    sdmxDataCsvVersion: str
    sdmxStructureJsonVersion: str


class SdmxWireFormat(TypedDict):
    id: str
    mediaType: str


class SdmxStructureLinks(TypedDict):
    dataflow: str
    datastructure: str


class AggregateDataCapability(TypedDict):
    family: Literal["aggregate-data"]
    pattern: str
    statisticalDatasetIdentifier: str
    operationIdentifier: str
    profile: SdmxProfile
    wireFormats: list[SdmxWireFormat]
    href: str
    structureLinks: SdmxStructureLinks


Capability = Union[ConsultationCapability, AggregateDataCapability]

ResourceLinks = TypedDict("ResourceLinks", {"self": str})


class ResourceDocument(TypedDict):
    resourceIdentifier: str
    title: str
    description: str
    semanticClass: str
    enumerationPosture: str
    capabilities: list[Capability]
    links: ResourceLinks


class RegistryMetadata(TypedDict):
    registryIdentifier: str


class CursorPageInfo(TypedDict):
    nextCursor: Optional[str]


class ResourceCollection(TypedDict):
    items: list[ResourceDocument]
    pageInfo: CursorPageInfo
    meta: RegistryMetadata


class ResourceEnvelope(TypedDict):
    data: ResourceDocument
    meta: RegistryMetadata


class _RegistryRecordRequired(TypedDict):
    registryIdentifier: str
    recordIdentifier: str
    revisionIdentifier: str
    lifecycleState: str
    schemaReference: str
    semanticModelReference: str
    authorityIdentifier: str
    recordedAt: str
    domainData: dict[str, JsonValue]


_RegistryRecordJsonLd = TypedDict(
    "_RegistryRecordJsonLd", {"@id": str, "@type": str}, total=False
)


class RegistryRecord(_RegistryRecordRequired, _RegistryRecordJsonLd):
    pass


class SourceRevision(TypedDict):
    profile: str
    status: str
    value: Optional[str]


RecordLinks = TypedDict(
    "RecordLinks",
    {"self": str, "context": str, "schema": str, "semanticModel": str},
)


class RecordMetadata(TypedDict):
    operationIdentifier: str
    accessProfile: str
    family: str
    pattern: str
    disclosureProfile: str
    contractRevision: str
    sourceRevision: SourceRevision
    selectedFields: list[str]
    links: RecordLinks


class _RecordEnvelopeRequired(TypedDict):
    data: RegistryRecord
    meta: RecordMetadata


_RecordEnvelopeJsonLd = TypedDict(
    "_RecordEnvelopeJsonLd", {"@context": str}, total=False
)


class RecordEnvelope(_RecordEnvelopeRequired, _RecordEnvelopeJsonLd):
    pass


class _RecordCollectionRequired(TypedDict):
    items: list[RegistryRecord]
    pageInfo: CursorPageInfo
    meta: RecordMetadata


_RecordCollectionJsonLd = TypedDict(
    "_RecordCollectionJsonLd", {"@context": str}, total=False
)


class RecordCollection(_RecordCollectionRequired, _RecordCollectionJsonLd):
    pass


_GeoJsonFeatureRequired = TypedDict(
    "_GeoJsonFeatureRequired",
    {
        "type": str,
        "id": str,
        "geometry": JsonValue,
        "properties": RegistryRecord,
    },
)


class _GeoJsonFeatureOptional(TypedDict, total=False):
    meta: RecordMetadata
    conformsTo: list[str]
    featureType: str
    coordRefSys: str


class GeoJsonFeature(_GeoJsonFeatureRequired, _GeoJsonFeatureOptional):
    pass


_GeoJsonFeatureCollectionRequired = TypedDict(
    "_GeoJsonFeatureCollectionRequired",
    {
        "type": str,
        "features": list[GeoJsonFeature],
        "pageInfo": CursorPageInfo,
        "meta": RecordMetadata,
    },
)


class _GeoJsonFeatureCollectionOptional(TypedDict, total=False):
    conformsTo: list[str]
    featureType: str
    coordRefSys: str


class GeoJsonFeatureCollection(
    _GeoJsonFeatureCollectionRequired, _GeoJsonFeatureCollectionOptional
):
    pass


RecordResponse = Union[RecordEnvelope, GeoJsonFeature]
RecordCollectionResponse = Union[RecordCollection, GeoJsonFeatureCollection]

T = TypeVar("T")


class CompleteOutcome(TypedDict, Generic[T]):
    kind: Literal["complete"]
    value: T
    trace_id: str
    etag: Optional[str]


class RawCompleteOutcome(TypedDict):
    kind: Literal["complete"]
    body: bytes
    media_type: str
    trace_id: str
    etag: Optional[str]


class ResourcePageCompleteOutcome(TypedDict):
    kind: Literal["complete"]
    value: ResourceCollection
    continuation: Optional[ResourceContinuation]
    trace_id: str
    etag: Optional[str]


class CollectionPageCompleteOutcome(TypedDict):
    kind: Literal["complete"]
    value: RecordCollectionResponse
    continuation: Optional[CollectionContinuation]
    trace_id: str
    etag: Optional[str]


class NotModifiedOutcome(TypedDict):
    kind: Literal["not_modified"]
    etag: str
    trace_id: str


Outcome: TypeAlias = Union[CompleteOutcome[T], NotModifiedOutcome]
RawOutcome: TypeAlias = Union[RawCompleteOutcome, NotModifiedOutcome]
ResourcePageOutcome: TypeAlias = Union[
    ResourcePageCompleteOutcome, NotModifiedOutcome
]
CollectionPageOutcome: TypeAlias = Union[
    CollectionPageCompleteOutcome, NotModifiedOutcome
]


class RelayClientError(Exception):
    """A fixed, value-free client failure.

    `kind` is always present. Other fields are `None` when the corresponding
    Rust failure carries no such fact. No attribute contains a credential,
    response body, header value, selector, filter, or route value.
    """

    kind: str
    code: Optional[str]
    status: Optional[int]
    trace_id: Optional[str]
    retry_after_seconds: Optional[int]
    transport_kind: Optional[str]
    token_kind: Optional[str]


class RelayClient:
    def __init__(
        self,
        base_url: str,
        authorization: Optional[RelayAuthorization] = ...,
        request_timeout_seconds: Optional[float] = ...,
        connect_timeout_seconds: Optional[float] = ...,
        user_agent: Optional[str] = ...,
        max_response_bytes: Optional[int] = ...,
        trusted_root_certificates: Optional[bytes] = ...,
    ) -> None: ...

    def health(self) -> CompleteOutcome[ProbeStatus]: ...
    def ready(self) -> CompleteOutcome[ProbeStatus]: ...
    def openapi(self, etag: Optional[str] = ...) -> RawOutcome: ...
    def service_metadata(
        self, etag: Optional[str] = ...
    ) -> Outcome[ServiceMetadata]: ...
    def resources(
        self,
        page_size: Optional[int] = ...,
        etag: Optional[str] = ...,
    ) -> ResourcePageOutcome: ...
    def continue_resources(
        self, continuation: ResourceContinuation, etag: Optional[str] = ...
    ) -> ResourcePageOutcome: ...
    def resource(
        self, resource: str, etag: Optional[str] = ...
    ) -> Outcome[ResourceEnvelope]: ...
    def list_records(
        self,
        resource: str,
        *,
        page_size: Optional[int] = ...,
        fields: Optional[Sequence[str]] = ...,
        access_profile: Optional[str] = ...,
        format: RecordFormat = ...,
        filters: Optional[dict[str, str]] = ...,
        etag: Optional[str] = ...,
    ) -> CollectionPageOutcome: ...
    def continue_list_records(
        self,
        continuation: CollectionContinuation,
        etag: Optional[str] = ...,
    ) -> CollectionPageOutcome: ...
    def read_record(
        self,
        resource: str,
        record_identifier: str,
        *,
        fields: Optional[Sequence[str]] = ...,
        access_profile: Optional[str] = ...,
        format: RecordFormat = ...,
        etag: Optional[str] = ...,
    ) -> Outcome[RecordResponse]: ...
    def lookup(
        self,
        resource: str,
        lookup: str,
        selectors: dict[str, Selector],
        *,
        fields: Optional[Sequence[str]] = ...,
        access_profile: Optional[str] = ...,
        format: RecordFormat = ...,
        etag: Optional[str] = ...,
    ) -> Outcome[RecordResponse]: ...
    def search(
        self,
        resource: str,
        search: str,
        *,
        bbox: BoundingBox,
        page_size: Optional[int] = ...,
        fields: Optional[Sequence[str]] = ...,
        access_profile: Optional[str] = ...,
        format: RecordFormat = ...,
        etag: Optional[str] = ...,
    ) -> CollectionPageOutcome: ...
    def continue_search(
        self,
        continuation: CollectionContinuation,
        etag: Optional[str] = ...,
    ) -> CollectionPageOutcome: ...
    def artifact(
        self, artifact_identifier: str, etag: Optional[str] = ...
    ) -> RawOutcome: ...
    def sdmx_data(
        self,
        agency: str,
        resource: str,
        version: str,
        *,
        key: Optional[str] = ...,
        constraints: Optional[dict[str, str]] = ...,
        offset: Optional[int] = ...,
        limit: Optional[int] = ...,
        dimension_at_observation: Optional[str] = ...,
        format: SdmxDataFormat = ...,
        etag: Optional[str] = ...,
    ) -> RawOutcome: ...
    def sdmx_structure(
        self,
        kind: SdmxStructureKind,
        agency: str,
        resource: str,
        version: str,
        *,
        etag: Optional[str] = ...,
    ) -> RawOutcome: ...
