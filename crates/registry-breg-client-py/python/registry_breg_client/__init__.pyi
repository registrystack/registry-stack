from typing import Any, Literal, NotRequired, Sequence, TypedDict

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | tuple["JsonValue", ...] | dict[str, "JsonValue"]
RecordFormat = Literal["json", "json-ld"]
StatisticsFormat = Literal["json", "csv"]
StatisticsReleaseStatus = Literal["provisional", "final"]
StatisticsReleaseSelection = Literal["any", "final"]
StatisticsWithdrawalReason = Literal["computation-error", "source-data-error", "disclosure-risk"]

class BRegStatisticalDimensionDescriptor(TypedDict):
    field: str
    vocabulary: str
    codes: Sequence[str]

class BRegStatisticalDatasetDescriptor(TypedDict):
    id: str
    unit: str
    periodKind: Literal["flow", "stock"]
    granularity: Literal["day", "month", "quarter", "year"]
    firstPeriod: str
    dimensions: Sequence[BRegStatisticalDimensionDescriptor]
    definitionDigest: str
    operations: Sequence[Literal[
        "read-live",
        "list-releases",
        "read-released-series",
        "read-latest-release",
        "read-release-version",
        "publish-release",
        "withdraw-release",
    ]]

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
    refusal_code: str | None
    reason_code: str | None
    field_path: str | None
    status: int | None
    trace_id: str | None
    transport_kind: str | None
    token_kind: str | None
    # Whether the request may have taken effect although this error was
    # raised: a timeout or broken exchange after sending, an unusable answer,
    # or a 5xx other than action.handler_failed and
    # statistical_dataset.domain_violation, which the engine returns only with
    # the attempt rolled back. When True, recover a keyed mutation by sending
    # it again under the same idempotency key; a new key could apply it twice.
    # False for a configuration or request defect, a credential the token
    # provider could not supply, a connection never established, and every
    # 4xx refusal. It is False for 410 idempotency.expired too, but there an
    # earlier attempt under the key committed and only its held response is
    # gone: read the resource before choosing a new key.
    outcome_unknown: bool

class BRegCreateBinding: ...
class BRegPatchBinding: ...
class BRegActionBinding: ...
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


class BRegPreparedAction:
    @staticmethod
    def from_bytes(value: bytes) -> BRegPreparedAction: ...
    def to_bytes(self) -> bytes: ...

class BRegRecoveredCreate: ...
class BRegRecoveredAction: ...

class BRegMetadata:
    def select_proposal_get(self, profile: str) -> BRegProposalGetBinding: ...
    def select_proposals(self, profile: str) -> BRegProposalCollection: ...
    @property
    def operations(self) -> Sequence[dict[str, JsonValue]]:
        """Operation request projections include allow_create and allow_patch as bool | None."""
        ...
    @property
    def action_metadata(self) -> JsonValue | None: ...
    @property
    def statistical_datasets(self) -> Sequence[BRegStatisticalDatasetDescriptor] | None:
        """Validated caller-filtered inert descriptions. They never grant entity authority."""
        ...
    @property
    def actions(self) -> Sequence[dict[str, JsonValue]]: ...
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
    def select_action(
        self, action_identifier: str, expected_profile: str
    ) -> BRegActionBinding: ...
    def select_tombstone(
        self, record_type_identifier: str, expected_profile: str
    ) -> BRegTombstoneBinding: ...
    def select_batch(
        self, record_type_identifier: str, expected_profile: str
    ) -> BRegBatchBinding: ...

class BaseRegistryClient:
    def get_proposal(self, binding: BRegProposalGetBinding, identifier: str) -> BRegProposal: ...
    def start_proposal(self, binding: BRegActionBinding, inputs: dict[str, JsonValue], key: str) -> BRegProposal: ...
    def read_proposal(self, proposal: BRegProposal) -> BRegProposal: ...
    def list_proposals(self, collection: BRegProposalCollection, query: dict[str, JsonValue]) -> BRegProposalPage: ...
    def prepare_proposal(self, proposal: BRegProposal, operation: BRegProposalTransition, body: dict[str, JsonValue], key: str) -> BRegPreparedProposal: ...
    def recover_proposal(self, proposal: BRegProposal, attempt: BRegPreparedProposal) -> BRegPreparedProposal: ...
    def execute_proposal(self, attempt: BRegPreparedProposal) -> BRegProposal: ...
    def __init__(
        self,
        base_url: str,
        authorization: dict[str, Any] | None = None,
        request_timeout_seconds: float | None = None,
        connect_timeout_seconds: float | None = None,
        user_agent: str | None = None,
        max_response_bytes: int | None = None,
        trusted_root_certificates: bytes | None = None,
        max_mutation_retries: int | None = None,
    ) -> None: ...
    def health(self) -> dict[str, Any]: ...
    def ready(self) -> dict[str, Any]: ...
    def openapi(self, access_profile: str | None = None) -> dict[str, Any]: ...
    def registry_metadata(self, access_profile: str | None = None) -> dict[str, Any]: ...
    def statistics_live(
        self, dataset: str, *, from_period: str | None = None,
        to_period: str | None = None, access_profile: str | None = None,
        format: StatisticsFormat = "json",
    ) -> dict[str, Any]: ...
    def statistics_releases(
        self, dataset: str, *, top: int | None = None,
        skip_token: str | None = None, access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def statistics_latest_release(
        self, dataset: str, period: str, selection: StatisticsReleaseSelection,
        *, access_profile: str | None = None, format: StatisticsFormat = "json",
    ) -> dict[str, Any]: ...
    def statistics_release_version(
        self, dataset: str, period: str, version: int,
        *, access_profile: str | None = None, format: StatisticsFormat = "json",
    ) -> dict[str, Any]: ...
    def statistics_release_series(
        self, dataset: str, from_period: str, to_period: str,
        selection: StatisticsReleaseSelection, *, access_profile: str | None = None,
        format: StatisticsFormat = "json",
    ) -> dict[str, Any]: ...
    def statistics_publish(
        self, dataset: str, period: str, status: StatisticsReleaseStatus,
        access_profile: str, idempotency_key: str,
    ) -> dict[str, Any]: ...
    def statistics_withdraw(
        self, dataset: str, period: str, version: int,
        reason: StatisticsWithdrawalReason, access_profile: str,
        idempotency_key: str,
    ) -> dict[str, Any]: ...
    def registry_contract(self, access_profile: str | None = None) -> BRegMetadata: ...
    def entity_schema(self, record_type_identifier: str, access_profile: str | None = None) -> dict[str, Any]: ...
    def get_record(
        self,
        entity_route: str,
        record_identifier: str,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: RecordFormat = "json",
    ) -> dict[str, Any]: ...
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
        binding: BRegActionBinding,
        inputs: dict[str, JsonValue],
    ) -> BRegActionTargetConditions: ...
    def invoke_action(
        self,
        binding: BRegActionBinding,
        inputs: dict[str, JsonValue],
        idempotency_key: str,
        conditions: BRegActionTargetConditions | None = None,
    ) -> dict[str, Any]: ...
    def prepare_action(
        self,
        binding: BRegActionBinding,
        inputs: dict[str, JsonValue],
        idempotency_key: str,
        conditions: BRegActionTargetConditions | None = None,
    ) -> BRegPreparedAction: ...
    def recover_action(
        self,
        binding: BRegActionBinding,
        prepared: BRegPreparedAction,
        inputs: dict[str, JsonValue],
        idempotency_key: str,
    ) -> BRegRecoveredAction: ...
    def execute_recovered_action(
        self,
        binding: BRegActionBinding,
        recovered: BRegRecoveredAction,
    ) -> dict[str, Any]: ...
    def execute_recovered_proposal_start(self, binding: BRegActionBinding, recovered: BRegRecoveredAction) -> BRegProposal: ...
    def download_proposal_attachment(self, proposal: BRegProposal, slot: str) -> dict[str, Any]: ...
    def read_proposal_review_status(self, proposal: BRegProposal) -> dict[str, Any]: ...
    def read_proposal_review_context(self, proposal: BRegProposal) -> dict[str, Any]: ...
    def upload_proposal_attachment(self, proposal: BRegProposal, slot: str, content_type: str, bytes: bytes, key: str) -> BRegProposal: ...
    def delete_proposal_attachment(self, proposal: BRegProposal, slot: str, key: str) -> BRegProposal: ...
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

__version__: str

class PrivateKeyJwt:
    """Shared OAuth provider. Returned credentials must be kept out of logs."""
    def __init__(self, config: dict[str, Any]) -> None: ...
    def exchange(self, subject_token: str) -> str:
        """Fresh RFC 8693 exchange, requiring configured resource and scopes."""
        ...
    def bearer_token(self) -> str: ...

BRegProposalTransition = Literal['edit', 'submit', 'revise', 'rebase', 'retry', 'cancel', 'apply']
class BRegProposal:
    @property
    def input(self) -> dict[str, JsonValue] | None: ...
    @property
    def identifier(self) -> str: ...
    @property
    def action_identifier(self) -> str: ...
    @property
    def document(self) -> dict[str, JsonValue]: ...
class BRegProposalCollection: ...
class BRegProposalGetBinding: ...
class BRegProposalPage:
    @property
    def items(self) -> list[BRegProposal]: ...
    @property
    def next_cursor(self) -> str | None: ...
class BRegPreparedProposal:
    @staticmethod
    def from_bytes(value: bytes) -> BRegPreparedProposal: ...
    def to_bytes(self) -> bytes: ...
