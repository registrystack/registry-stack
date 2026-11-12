from typing import Any, Never, Sequence

from . import breg

class BRegWorkload:
    def __init__(self, client: breg.BaseRegistryClient) -> None: ...
    def __getattr__(self, operation: str) -> Never: ...
    def get_proposal(
        self, binding: breg.BRegProposalGetBinding, identifier: str
    ) -> breg.BRegProposal: ...
    def start_proposal(
        self,
        binding: breg.BRegActionBinding,
        inputs: dict[str, breg.JsonValue],
        key: str,
    ) -> breg.BRegProposal: ...
    def read_proposal(self, proposal: breg.BRegProposal) -> breg.BRegProposal: ...
    def read_proposal_submission(
        self, proposal: breg.BRegProposal, version: int
    ) -> dict[str, Any]: ...
    def list_proposals(
        self, collection: breg.BRegProposalCollection, query: dict[str, breg.JsonValue]
    ) -> breg.BRegProposalPage: ...
    def prepare_proposal(
        self,
        proposal: breg.BRegProposal,
        operation: breg.BRegProposalTransition,
        body: dict[str, breg.JsonValue],
        key: str,
    ) -> breg.BRegPreparedProposal: ...
    def recover_proposal(
        self, proposal: breg.BRegProposal, attempt: breg.BRegPreparedProposal
    ) -> breg.BRegPreparedProposal: ...
    def execute_proposal(
        self, attempt: breg.BRegPreparedProposal
    ) -> breg.BRegProposal: ...
    def health(self) -> dict[str, Any]: ...
    def ready(self) -> dict[str, Any]: ...
    def openapi(self, access_profile: str | None = None) -> dict[str, Any]: ...
    def registry_metadata(
        self, access_profile: str | None = None
    ) -> dict[str, Any]: ...
    def event_record_creation_revision(
        self,
        record_route: str,
        record_identifier: str,
        *,
        access_profile: str | None = None,
    ) -> dict[str, str] | None: ...
    def statistics_live(
        self,
        dataset: str,
        *,
        from_period: str | None = None,
        to_period: str | None = None,
        access_profile: str | None = None,
        format: breg.StatisticsFormat = "json",
    ) -> dict[str, Any]: ...
    def statistics_releases(
        self,
        dataset: str,
        *,
        top: int | None = None,
        skip_token: str | None = None,
        access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def statistics_latest_release(
        self,
        dataset: str,
        period: str,
        selection: breg.StatisticsReleaseSelection,
        *,
        access_profile: str | None = None,
        format: breg.StatisticsFormat = "json",
    ) -> dict[str, Any]: ...
    def statistics_release_version(
        self,
        dataset: str,
        period: str,
        version: int,
        *,
        access_profile: str | None = None,
        format: breg.StatisticsFormat = "json",
    ) -> dict[str, Any]: ...
    def statistics_release_series(
        self,
        dataset: str,
        from_period: str,
        to_period: str,
        selection: breg.StatisticsReleaseSelection,
        *,
        access_profile: str | None = None,
        format: breg.StatisticsFormat = "json",
    ) -> dict[str, Any]: ...
    def statistics_publish(
        self,
        dataset: str,
        period: str,
        status: breg.StatisticsReleaseStatus,
        access_profile: str,
        idempotency_key: str,
    ) -> dict[str, Any]: ...
    def statistics_withdraw(
        self,
        dataset: str,
        period: str,
        version: int,
        reason: breg.StatisticsWithdrawalReason,
        access_profile: str,
        idempotency_key: str,
    ) -> dict[str, Any]: ...
    def registry_contract(
        self, access_profile: str | None = None
    ) -> breg.BRegMetadata: ...
    def record_schema(
        self, record_type_identifier: str, access_profile: str | None = None
    ) -> dict[str, Any]: ...
    def get_record(
        self,
        record_route: str,
        record_identifier: str,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def get_geojson_record(
        self,
        record_route: str,
        record_identifier: str,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
    ) -> breg.GeoJsonCompleteOutcome: ...
    def list_geojson_records(
        self,
        record_route: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
        bbox: tuple[str, str, str, str] | None = None,
    ) -> breg.GeoJsonPageOutcome: ...
    def continue_geojson_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> breg.GeoJsonPageOutcome: ...
    def record_revisions(
        self,
        record_route: str,
        record_identifier: str,
        access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def get_record_revision(
        self,
        record_route: str,
        record_identifier: str,
        revision: int,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def list_records(
        self,
        record_route: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
        bbox: tuple[str, str, str, str] | None = None,
    ) -> dict[str, Any]: ...
    def list_current_records(
        self,
        record_route: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
    ) -> dict[str, Any]: ...
    def continue_current_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]: ...
    def list_records_as_of(
        self,
        record_route: str,
        as_of: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
    ) -> dict[str, Any]: ...
    def continue_as_of_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]: ...
    def list_snapshot_records(
        self,
        record_route: str,
        *,
        snapshot: str | None = None,
        valid_at: str | None = None,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
    ) -> dict[str, Any]: ...
    def continue_snapshot_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]: ...
    def list_relationship_records(
        self,
        record_route: str,
        record_identifier: str,
        path_route: str,
        *,
        top: int | None = None,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
        filter: str | None = None,
        orderby: str | None = None,
        count: bool | None = None,
    ) -> dict[str, Any]: ...
    def continue_relationship_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]: ...
    def continue_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]: ...
    def lookup_record(
        self,
        record_route: str,
        selector: str,
        values: dict[str, breg.JsonValue] | None = None,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def create_record(
        self,
        binding: breg.BRegCreateBinding,
        data: dict[str, breg.JsonValue],
        idempotency_key: str,
        *,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def prepare_create(
        self,
        binding: breg.BRegCreateBinding,
        data: dict[str, breg.JsonValue],
        idempotency_key: str,
        *,
        format: breg.RecordFormat = "json",
    ) -> breg.BRegPreparedCreate: ...
    def recover_create(
        self, binding: breg.BRegCreateBinding, prepared: breg.BRegPreparedCreate
    ) -> breg.BRegRecoveredCreate: ...
    def execute_recovered_create(
        self, binding: breg.BRegCreateBinding, recovered: breg.BRegRecoveredCreate
    ) -> dict[str, Any]: ...
    def patch_record(
        self,
        binding: breg.BRegPatchBinding,
        record_identifier: str,
        etag: str,
        operations: list[dict[str, breg.JsonValue]]
        | tuple[dict[str, breg.JsonValue], ...],
        idempotency_key: str,
        *,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def action_target_conditions(
        self, binding: breg.BRegActionBinding, inputs: dict[str, breg.JsonValue]
    ) -> breg.BRegActionTargetConditions: ...
    def action_availability(
        self,
        binding: breg.BRegActionBinding,
        target_input: str,
        inputs: dict[str, breg.JsonValue],
    ) -> breg.BRegActionAvailabilityOutcome: ...
    def invoke_action(
        self,
        binding: breg.BRegActionBinding,
        inputs: dict[str, breg.JsonValue],
        idempotency_key: str,
        conditions: breg.BRegActionTargetConditions | None = None,
    ) -> dict[str, Any]: ...
    def prepare_action(
        self,
        binding: breg.BRegActionBinding,
        inputs: dict[str, breg.JsonValue],
        idempotency_key: str,
        conditions: breg.BRegActionTargetConditions | None = None,
    ) -> breg.BRegPreparedAction: ...
    def recover_action(
        self,
        binding: breg.BRegActionBinding,
        prepared: breg.BRegPreparedAction,
        inputs: dict[str, breg.JsonValue],
        idempotency_key: str,
    ) -> breg.BRegRecoveredAction: ...
    def execute_recovered_action(
        self, binding: breg.BRegActionBinding, recovered: breg.BRegRecoveredAction
    ) -> dict[str, Any]: ...
    def execute_recovered_proposal_start(
        self, binding: breg.BRegActionBinding, recovered: breg.BRegRecoveredAction
    ) -> breg.BRegProposal: ...
    def download_proposal_attachment(
        self, proposal: breg.BRegProposal, slot: str
    ) -> dict[str, Any]: ...
    def read_proposal_review_status(
        self, proposal: breg.BRegProposal
    ) -> dict[str, Any]: ...
    def read_proposal_review_status_with_progress(
        self, proposal: breg.BRegProposal
    ) -> breg.BRegProposalReviewCompleteOutcome: ...
    def read_proposal_review_context(
        self, proposal: breg.BRegProposal
    ) -> dict[str, Any]: ...
    def read_proposal_review_context_batch(
        self, binding: breg.BRegProposalReviewBinding, ids: list[str]
    ) -> dict[str, Any]: ...
    def read_proposal_review_by_id(
        self, binding: breg.BRegProposalReviewBinding, identifier: str
    ) -> dict[str, Any]: ...
    def download_proposal_review_document(
        self,
        binding: breg.BRegProposalReviewBinding,
        context: dict[str, Any],
        field: str,
    ) -> dict[str, Any]: ...
    def upload_proposal_attachment(
        self,
        proposal: breg.BRegProposal,
        slot: str,
        content_type: str,
        bytes: bytes,
        key: str,
    ) -> breg.BRegProposal: ...
    def delete_proposal_attachment(
        self, proposal: breg.BRegProposal, slot: str, key: str
    ) -> breg.BRegProposal: ...
    def tombstone_record(
        self,
        binding: breg.BRegTombstoneBinding,
        record_identifier: str,
        etag: str,
        idempotency_key: str,
        *,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]: ...
    def batch_records(
        self,
        binding: breg.BRegBatchBinding,
        items: Sequence[dict[str, breg.JsonValue]],
        idempotency_key: str,
        *,
        change_context: dict[str, breg.JsonValue] | None = None,
    ) -> dict[str, Any]: ...
    def create_ingestion_run(
        self, record_route: str, request: dict[str, breg.JsonValue]
    ) -> dict[str, Any]: ...
    def list_ingestion_runs(
        self,
        record_route: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        status: breg.IngestionRunStatus | None = None,
        input_digest: str | None = None,
        access_profile: str | None = None,
    ) -> dict[str, Any]: ...
    def read_ingestion_run(
        self, record_route: str, run_id: str, access_profile: str | None = None
    ) -> dict[str, Any]: ...
    def submit_ingestion_chunk(
        self,
        record_route: str,
        run_id: str,
        chunk: breg.BRegIngestionChunk,
        profile_id: str,
    ) -> dict[str, Any]: ...
    def cancel_ingestion_run(
        self, record_route: str, run_id: str, access_profile: str | None = None
    ) -> dict[str, Any]: ...
    def ingestion_chunk_receipt(
        self, record_route: str, run_id: str, chunk_index: int, profile_id: str
    ) -> dict[str, Any]: ...
