from typing import Any, Literal, NotRequired, Sequence, TypedDict

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | tuple["JsonValue", ...] | dict[str, "JsonValue"]
RecordFormat = Literal["json", "json-ld"]

class ExchangeContext(TypedDict):
    issuer: str
    subject: str
    audience: str
    generation: str
    deadline_seconds: int
    grant_id: NotRequired[str | None]

class ExchangeKeyClient(TypedDict):
    token_endpoint: str
    client_id: str
    client_key: dict[str, JsonValue]
    resource: str
    scopes: Sequence[str]
    audience: NotRequired[str | None]
    assertion_lifetime_seconds: NotRequired[int | None]
    refresh_margin_seconds: NotRequired[int | None]
    request_timeout_seconds: NotRequired[float | None]
    connect_timeout_seconds: NotRequired[float | None]
    user_agent: NotRequired[str | None]
    trusted_root_certificates: NotRequired[str | None]

class FirstPartyExchangeSource(TypedDict):
    key: dict[str, JsonValue]
    attributes: dict[str, JsonValue]

class RemoteExchangeSource(TypedDict):
    endpoint: str
    bootstrap: ExchangeKeyClient
    bootstrap_resource: str
    bootstrap_scope: str
    request_timeout_seconds: NotRequired[float | None]
    connect_timeout_seconds: NotRequired[float | None]
    user_agent: NotRequired[str | None]
    trusted_root_certificates: NotRequired[str | None]

class FirstPartyExchangeConfig(TypedDict):
    client: ExchangeKeyClient
    context: ExchangeContext
    first_party: FirstPartyExchangeSource

class RemoteExchangeConfig(TypedDict):
    client: ExchangeKeyClient
    context: ExchangeContext
    remote: RemoteExchangeSource

ExchangeAuthorization = TypedDict("ExchangeAuthorization", {"exchange": FirstPartyExchangeConfig | RemoteExchangeConfig})

class BaseRegistryClientError(Exception):
    kind: str
    code: str | None
    plan_refusal: str | None
    refusal_code: str | None
    status: int | None
    trace_id: str | None
    transport_kind: str | None
    token_kind: str | None

class BRegCreateBinding: ...
class BRegPatchBinding: ...
class BRegLifecycleAuthority: ...
class BRegImmediateActionBinding: ...
class BRegTombstoneBinding: ...
class BRegBatchBinding: ...

IngestionRunStatus = Literal["open", "complete", "cancelled", "blocked"]

class BRegIngestionChunk:
    @property
    def chunk_index(self) -> int: ...
    @property
    def item_count(self) -> int: ...
    @property
    def digest(self) -> str: ...
    @property
    def prefix_digest(self) -> str: ...

class BRegIngestionPrefixDigest:
    """Absorbs raw source bytes; the empty-input digest is
    e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."""

    def __init__(self) -> None: ...
    def update(self, data: bytes) -> None: ...
    def digest(self) -> str: ...

def encode_ingestion_chunk(
    chunk_index: int,
    items: Sequence[dict[str, JsonValue]],
    prefix_digest: str,
) -> BRegIngestionChunk: ...

class BRegActionTargetConditions:
    @property
    def document(self) -> dict[str, JsonValue]: ...
    @property
    def trace_id(self) -> str: ...

class BRegPreparedCreate:
    @staticmethod
    def from_bytes(value: bytes) -> BRegPreparedCreate: ...
    def to_bytes(self) -> bytes: ...

class BRegPreparedLifecycle:
    @staticmethod
    def from_bytes(value: bytes) -> BRegPreparedLifecycle: ...
    def to_bytes(self) -> bytes: ...

class BRegRecoveredCreate: ...
class BRegRecoveredLifecycle: ...

AttachmentVerificationStatus = Literal["notRequired", "pending", "approved", "rejected"]
AttachmentClassification = Literal["public", "internal", "restricted"]

class BRegAttachmentState(TypedDict):
    slot_identifier: str
    proposal_version: int
    erased: bool
    byte_size: int
    sha256: str
    content_type: str | None
    uploaded_at: str | None
    uploaded_by: str | None
    verification_status: AttachmentVerificationStatus | None

class BRegAttachmentSlotValue(TypedDict):
    kind: Literal["not_selected", "empty", "filled"]
    value: BRegAttachmentState | None

class BRegAttachmentUpload:
    @property
    def content_type(self) -> str: ...
    @property
    def byte_size(self) -> int: ...

class BRegAttachmentSlot:
    @property
    def slot_identifier(self) -> str: ...
    @property
    def entity_identifier(self) -> str: ...
    @property
    def access_profile(self) -> str: ...
    @property
    def required_for_submit(self) -> bool: ...
    @property
    def maximum_bytes(self) -> int: ...
    @property
    def content_types(self) -> list[str]: ...
    @property
    def classification(self) -> AttachmentClassification: ...
    @property
    def can_download(self) -> bool: ...
    @property
    def can_upload(self) -> bool: ...
    @property
    def can_remove(self) -> bool: ...
    def accepts_content_type(self, content_type: str) -> bool: ...
    def prepare_upload(self, content_type: str, body: bytes) -> BRegAttachmentUpload: ...
    def value_in(
        self,
        record: dict[str, JsonValue],
        *,
        format: RecordFormat = "json",
    ) -> BRegAttachmentSlotValue: ...

class BRegLifecycleAction:
    def with_reason(self, reason: str) -> BRegLifecycleAction: ...
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

class BRegRequestResultReference:
    @property
    def target_entity_identifier(self) -> str: ...
    @property
    def target_record_identifier(self) -> str: ...
    @property
    def target_revision(self) -> int: ...

class BRegRetainedRequestProposal:
    @property
    def request_entity_identifier(self) -> str: ...
    @property
    def request_identifier(self) -> str: ...
    @property
    def proposal_version(self) -> int: ...
    @property
    def breg_state(self) -> Literal["draft", "submitted", "approved", "needs_changes", "rejected", "canceled", "applied"]: ...
    @property
    def current(self) -> bool: ...
    @property
    def detail_erased(self) -> bool: ...
    @property
    def application_identifier(self) -> str | None: ...
    @property
    def result_link_count(self) -> int: ...
    @property
    def result_references(self) -> list[BRegRequestResultReference]: ...

class BRegRetainedRequestHistoryPage:
    @property
    def proposals(self) -> list[BRegRetainedRequestProposal]: ...
    @property
    def next_after_proposal_version(self) -> int | None: ...
    def find_proposal(
        self,
        request_entity_identifier: str,
        request_identifier: str,
        proposal_version: int,
    ) -> BRegRetainedRequestProposal | None: ...
    def find_application(
        self,
        request_entity_identifier: str,
        request_identifier: str,
        proposal_version: int,
        application_identifier: str,
    ) -> BRegRetainedRequestProposal | None: ...

class BRegChangeRequestStage(TypedDict):
    id: str
    approvals: int
    exclude_submitter: bool
    exclude_previous_reviewers: bool

class BRegChangeRequestCapability(TypedDict):
    planner: dict[str, JsonValue]
    review_mode: Literal["none", "staged"]
    stages: list[BRegChangeRequestStage] | None
    application: dict[str, JsonValue]

class BRegLifecycleReceiptRequest(TypedDict):
    breg_state: str
    proposal_version: int | None
    effect_digest: str | None
    proposal: dict[str, JsonValue] | None
    application: dict[str, JsonValue] | None

class _BRegLifecycleReceiptRequired(TypedDict):
    id: str
    revision: int
    snapshot: str
    request: BRegLifecycleReceiptRequest

class BRegLifecycleReceipt(_BRegLifecycleReceiptRequired, total=False):
    actor_reference: str

class BRegLifecycleComplete(TypedDict):
    kind: Literal["complete"]
    value: BRegLifecycleReceipt
    trace_id: str
    etag: str | None
    location: str | None

class BRegMetadata:
    @property
    def operations(self) -> Sequence[dict[str, JsonValue]]:
        """Operation request projections include allow_create and allow_patch as bool | None."""
        ...
    @property
    def actions(self) -> JsonValue | None: ...
    @property
    def immediate_actions(self) -> Sequence[dict[str, JsonValue]]: ...
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
    def select_immediate_action(
        self, action_identifier: str, expected_profile: str
    ) -> BRegImmediateActionBinding: ...
    def select_tombstone(
        self, entity_identifier: str, expected_profile: str
    ) -> BRegTombstoneBinding: ...
    def select_batch(
        self, entity_identifier: str, expected_profile: str
    ) -> BRegBatchBinding: ...
    def select_lifecycle(self, entity_identifier: str, expected_profile: str) -> BRegLifecycleAuthority: ...
    def select_attachments(self, entity_identifier: str, expected_profile: str) -> Sequence[BRegAttachmentSlot]: ...
    def change_request_capability(
        self, entity_identifier: str
    ) -> BRegChangeRequestCapability | None: ...

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
        request_history_after_proposal_version: int | None = None,
    ) -> dict[str, Any]: ...
    def request_history(
        self,
        record: dict[str, Any],
        *,
        format: RecordFormat = "json",
    ) -> BRegRetainedRequestHistoryPage | None: ...
    def get_geojson_record(
        self,
        entity_route: str,
        record_identifier: str,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def list_geojson_records(
        self,
        entity_route: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
        bbox: tuple[str, str, str, str] | None = None,
    ) -> dict[str, Any]: ...
    def continue_geojson_list(
        self, continuation: dict[str, JsonValue]
    ) -> dict[str, Any]: ...
    def record_revisions(
        self,
        entity_route: str,
        record_identifier: str,
        access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def get_record_revision(
        self,
        entity_route: str,
        record_identifier: str,
        revision: int,
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
        bbox: tuple[str, str, str, str] | None = None,
    ) -> dict[str, Any]: ...
    def list_current_records(
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
    def continue_current_list(
        self, continuation: dict[str, JsonValue]
    ) -> dict[str, Any]: ...
    def list_records_as_of(
        self,
        entity_route: str,
        as_of: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
    ) -> dict[str, Any]: ...
    def continue_as_of_list(
        self, continuation: dict[str, JsonValue]
    ) -> dict[str, Any]: ...
    def list_snapshot_records(
        self,
        entity_route: str,
        *,
        snapshot: str | None = None,
        valid_at: str | None = None,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
    ) -> dict[str, Any]: ...
    def continue_snapshot_list(
        self, continuation: dict[str, JsonValue]
    ) -> dict[str, Any]: ...
    def list_relationship_records(
        self,
        entity_route: str,
        record_identifier: str,
        path_route: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
    ) -> dict[str, Any]: ...
    def continue_relationship_list(
        self, continuation: dict[str, JsonValue]
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
    def prepare_create(
        self,
        binding: BRegCreateBinding,
        data: dict[str, JsonValue],
        idempotency_key: str,
        *,
        format: RecordFormat = "json",
    ) -> BRegPreparedCreate: ...
    def recover_create(
        self,
        binding: BRegCreateBinding,
        prepared: BRegPreparedCreate,
    ) -> BRegRecoveredCreate: ...
    def execute_recovered_create(
        self,
        binding: BRegCreateBinding,
        recovered: BRegRecoveredCreate,
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
    def action_target_conditions(
        self,
        binding: BRegImmediateActionBinding,
        inputs: dict[str, JsonValue],
    ) -> BRegActionTargetConditions: ...
    def invoke_action(
        self,
        binding: BRegImmediateActionBinding,
        inputs: dict[str, JsonValue],
        idempotency_key: str,
        conditions: BRegActionTargetConditions | None = None,
    ) -> dict[str, Any]: ...
    def tombstone_record(
        self,
        binding: BRegTombstoneBinding,
        record_identifier: str,
        etag: str,
        idempotency_key: str,
        *,
        format: RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def batch_records(
        self,
        binding: BRegBatchBinding,
        items: Sequence[dict[str, JsonValue]],
        idempotency_key: str,
        *,
        change_context: dict[str, JsonValue] | None = None,
    ) -> dict[str, Any]: ...
    def create_ingestion_run(
        self,
        entity_route: str,
        request: dict[str, JsonValue],
    ) -> dict[str, Any]: ...
    def list_ingestion_runs(
        self,
        entity_route: str,
        *,
        limit: int | None = None,
        after: str | None = None,
        status: IngestionRunStatus | None = None,
        input_digest: str | None = None,
        access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def read_ingestion_run(
        self,
        entity_route: str,
        run_id: str,
        access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def submit_ingestion_chunk(
        self,
        entity_route: str,
        run_id: str,
        chunk: BRegIngestionChunk,
        profile_id: str,
    ) -> dict[str, Any]: ...
    def cancel_ingestion_run(
        self,
        entity_route: str,
        run_id: str,
        access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def ingestion_chunk_receipt(
        self,
        entity_route: str,
        run_id: str,
        chunk_index: int,
        profile_id: str,
    ) -> dict[str, Any]: ...
    def lifecycle_actions(
        self,
        authority: BRegLifecycleAuthority,
        record: dict[str, JsonValue],
        *,
        format: RecordFormat = "json",
    ) -> Sequence[BRegLifecycleAction]: ...
    def prepare_lifecycle_action(
        self,
        authority: BRegLifecycleAuthority,
        record: dict[str, JsonValue],
        action: BRegLifecycleAction,
        idempotency_key: str,
        *,
        format: RecordFormat = "json",
    ) -> BRegPreparedLifecycle: ...
    def recover_lifecycle_action(
        self,
        authority: BRegLifecycleAuthority,
        prepared: BRegPreparedLifecycle,
    ) -> BRegRecoveredLifecycle: ...
    def execute_recovered_lifecycle_action(
        self,
        recovered: BRegRecoveredLifecycle,
    ) -> BRegLifecycleComplete: ...
    def execute_lifecycle_action(self, action: BRegLifecycleAction, idempotency_key: str) -> BRegLifecycleComplete: ...
    def upload_attachment(
        self,
        slot: BRegAttachmentSlot,
        record_identifier: str,
        etag: str,
        upload: BRegAttachmentUpload,
        idempotency_key: str,
        *,
        format: RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def download_attachment(
        self,
        slot: BRegAttachmentSlot,
        record_identifier: str,
        proposal_version: int,
    ) -> dict[str, Any]: ...
    def delete_attachment(
        self,
        slot: BRegAttachmentSlot,
        record_identifier: str,
        etag: str,
        idempotency_key: str,
        *,
        format: RecordFormat = "json",
    ) -> dict[str, Any]: ...

__version__: str

class PrivateKeyJwt:
    """Shared OAuth provider. Returned credentials must be kept out of logs."""
    def __init__(self, config: dict[str, Any]) -> None: ...
    def exchange(self, subject_token: str) -> str:
        """Fresh RFC 8693 exchange, requiring configured resource and scopes."""
        ...
    def bearer_token(self) -> str: ...
