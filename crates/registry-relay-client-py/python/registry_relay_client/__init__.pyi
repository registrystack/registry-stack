"""Types for the synchronous Registry Relay V2 client binding."""

from typing import Any, Literal, Mapping, Optional, Sequence, TypedDict, Union

RecordFormat = Literal["json", "json-ld", "geojson", "json-fg"]
SdmxDataFormat = Literal["json", "csv"]
SdmxStructureKind = Literal["dataflow", "datastructure"]
Selector = Union[str, int, bool]

class _PrivateKeyJwtRequired(TypedDict):
    token_endpoint: str
    client_id: str
    client_key: Mapping[str, Any]


class PrivateKeyJwtConfig(_PrivateKeyJwtRequired, total=False):
    audience: Optional[str]
    assertion_lifetime_seconds: Optional[int]
    refresh_margin_seconds: Optional[int]
    request_timeout_seconds: Optional[float]
    connect_timeout_seconds: Optional[float]
    user_agent: Optional[str]
    trusted_root_certificates: bytes


PrivateKeyJwtAuthorization = TypedDict(
    "PrivateKeyJwtAuthorization", {"private_key_jwt": PrivateKeyJwtConfig}
)
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


CompleteOutcome = TypedDict(
    "CompleteOutcome",
    {
        "kind": Literal["complete"],
        "value": Any,
        "trace_id": str,
        "etag": Optional[str],
    },
)
RawCompleteOutcome = TypedDict(
    "RawCompleteOutcome",
    {
        "kind": Literal["complete"],
        "body": bytes,
        "media_type": str,
        "trace_id": str,
        "etag": Optional[str],
    },
)
ResourcePageCompleteOutcome = TypedDict(
    "ResourcePageCompleteOutcome",
    {
        "kind": Literal["complete"],
        "value": Any,
        "continuation": Optional[ResourceContinuation],
        "trace_id": str,
        "etag": Optional[str],
    },
)
CollectionPageCompleteOutcome = TypedDict(
    "CollectionPageCompleteOutcome",
    {
        "kind": Literal["complete"],
        "value": Any,
        "continuation": Optional[CollectionContinuation],
        "trace_id": str,
        "etag": Optional[str],
    },
)
NotModifiedOutcome = TypedDict(
    "NotModifiedOutcome",
    {"kind": Literal["not_modified"], "etag": str, "trace_id": str},
)
Outcome = Union[CompleteOutcome, NotModifiedOutcome]
RawOutcome = Union[RawCompleteOutcome, NotModifiedOutcome]
ResourcePageOutcome = Union[ResourcePageCompleteOutcome, NotModifiedOutcome]
CollectionPageOutcome = Union[CollectionPageCompleteOutcome, NotModifiedOutcome]


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
        authorization: Optional[
            Union[str, PrivateKeyJwtAuthorization]
        ] = ...,
        request_timeout_seconds: Optional[float] = ...,
        connect_timeout_seconds: Optional[float] = ...,
        user_agent: Optional[str] = ...,
        max_response_bytes: Optional[int] = ...,
        trusted_root_certificates: Optional[bytes] = ...,
    ) -> None: ...

    def health(self) -> CompleteOutcome: ...
    def ready(self) -> CompleteOutcome: ...
    def openapi(self, etag: Optional[str] = ...) -> RawOutcome: ...
    def service_metadata(self, etag: Optional[str] = ...) -> Outcome: ...
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
    ) -> Outcome: ...
    def list_records(
        self,
        resource: str,
        *,
        page_size: Optional[int] = ...,
        fields: Optional[Sequence[str]] = ...,
        access_profile: Optional[str] = ...,
        format: RecordFormat = ...,
        filters: Optional[Mapping[str, str]] = ...,
        bbox: Optional[Sequence[float]] = ...,
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
    ) -> Outcome: ...
    def lookup(
        self,
        resource: str,
        lookup: str,
        selectors: Mapping[str, Selector],
        *,
        fields: Optional[Sequence[str]] = ...,
        access_profile: Optional[str] = ...,
        format: RecordFormat = ...,
        etag: Optional[str] = ...,
    ) -> Outcome: ...
    def search(
        self,
        resource: str,
        search: str,
        *,
        page_size: Optional[int] = ...,
        fields: Optional[Sequence[str]] = ...,
        access_profile: Optional[str] = ...,
        format: RecordFormat = ...,
        filters: Optional[Mapping[str, str]] = ...,
        bbox: Optional[Sequence[float]] = ...,
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
        constraints: Optional[Mapping[str, str]] = ...,
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
