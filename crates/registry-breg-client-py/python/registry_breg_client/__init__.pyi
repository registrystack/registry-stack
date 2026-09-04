from typing import Any, Literal, Sequence

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | tuple["JsonValue", ...] | dict[str, "JsonValue"]
RecordFormat = Literal["json", "json-ld"]

class BaseRegistryClientError(Exception):
    kind: str
    code: str | None
    plan_refusal: str | None
    status: int | None
    trace_id: str | None
    transport_kind: str | None
    token_kind: str | None

class BRegCreateBinding: ...
class BRegPatchBinding: ...
class BRegLifecycleAuthority: ...

class BRegLifecycleAction:
    @property
    def operation(self) -> str: ...
    @property
    def stage(self) -> str | None: ...
    @property
    def href(self) -> str: ...
    @property
    def body(self) -> dict[str, JsonValue]: ...
    @property
    def review(self) -> dict[str, JsonValue] | None: ...

class BRegMetadata:
    @property
    def registry_identifier(self) -> str: ...
    @property
    def registry_version(self) -> str: ...
    @property
    def registry_revision(self) -> str: ...
    @property
    def trace_id(self) -> str: ...
    @property
    def etag(self) -> str | None: ...
    def select_create(self, operation_identifier: str, expected_profile: str) -> BRegCreateBinding: ...
    def select_patch(self, operation_identifier: str, expected_profile: str) -> BRegPatchBinding: ...
    def select_lifecycle(self, entity_identifier: str, expected_profile: str) -> BRegLifecycleAuthority: ...

class BaseRegistryClient:
    def __init__(
        self,
        base_url: str,
        authorization: dict[str, Any] | None = None,
        request_timeout_seconds: float | None = None,
        connect_timeout_seconds: float | None = None,
        user_agent: str | None = None,
        max_response_bytes: int | None = None,
        trusted_root_certificates: bytes | None = None,
    ) -> None: ...
    def health(self) -> dict[str, Any]: ...
    def ready(self) -> dict[str, Any]: ...
    def openapi(self, access_profile: str | None = None) -> dict[str, Any]: ...
    def registry_metadata(self, access_profile: str | None = None) -> dict[str, Any]: ...
    def registry_contract(self, access_profile: str | None = None) -> BRegMetadata: ...
    def entity_schema(self, entity_identifier: str, access_profile: str | None = None) -> dict[str, Any]: ...
    def get_record(
        self,
        entity_route: str,
        record_identifier: str,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def list_records(
        self,
        entity_route: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
    ) -> dict[str, Any]: ...
    def continue_list(self, continuation: dict[str, JsonValue]) -> dict[str, Any]: ...
    def lookup_record(
        self,
        entity_route: str,
        selector: str,
        values: dict[str, JsonValue] | None = None,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def create_record(
        self,
        binding: BRegCreateBinding,
        data: dict[str, JsonValue],
        idempotency_key: str,
        *,
        format: RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def patch_record(
        self,
        binding: BRegPatchBinding,
        record_identifier: str,
        etag: str,
        operations: list[dict[str, JsonValue]] | tuple[dict[str, JsonValue], ...],
        idempotency_key: str,
        *,
        format: RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def lifecycle_actions(
        self,
        authority: BRegLifecycleAuthority,
        record: dict[str, JsonValue],
        *,
        format: RecordFormat = "json",
    ) -> Sequence[BRegLifecycleAction]: ...
    def execute_lifecycle_action(self, action: BRegLifecycleAction, idempotency_key: str) -> dict[str, Any]: ...

__version__: str
