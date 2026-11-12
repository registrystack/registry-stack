"""Complete token-free pass-through to one authorized native BReg client."""

from __future__ import annotations

from typing import Any, Sequence, TYPE_CHECKING

from .connection import UnsupportedOperationError
from .workload import _require_sync

if TYPE_CHECKING:
    from . import breg


class BRegWorkload:
    """One immutable BReg target and workload authority."""

    __slots__ = ("_client",)

    def __init__(self, client: breg.BaseRegistryClient):
        self._client = client

    def __getattr__(self, operation: str):
        raise UnsupportedOperationError("breg", operation)

    def get_proposal(
        self, binding: breg.BRegProposalGetBinding, identifier: str
    ) -> breg.BRegProposal:
        _require_sync()
        return self._client.get_proposal(binding, identifier)

    def start_proposal(
        self,
        binding: breg.BRegActionBinding,
        inputs: dict[str, breg.JsonValue],
        key: str,
    ) -> breg.BRegProposal:
        _require_sync()
        return self._client.start_proposal(binding, inputs, key)

    def read_proposal(self, proposal: breg.BRegProposal) -> breg.BRegProposal:
        _require_sync()
        return self._client.read_proposal(proposal)

    def read_proposal_submission(
        self, proposal: breg.BRegProposal, version: int
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.read_proposal_submission(proposal, version)

    def list_proposals(
        self, collection: breg.BRegProposalCollection, query: dict[str, breg.JsonValue]
    ) -> breg.BRegProposalPage:
        _require_sync()
        return self._client.list_proposals(collection, query)

    def prepare_proposal(
        self,
        proposal: breg.BRegProposal,
        operation: breg.BRegProposalTransition,
        body: dict[str, breg.JsonValue],
        key: str,
    ) -> breg.BRegPreparedProposal:
        _require_sync()
        return self._client.prepare_proposal(proposal, operation, body, key)

    def recover_proposal(
        self, proposal: breg.BRegProposal, attempt: breg.BRegPreparedProposal
    ) -> breg.BRegPreparedProposal:
        _require_sync()
        return self._client.recover_proposal(proposal, attempt)

    def execute_proposal(self, attempt: breg.BRegPreparedProposal) -> breg.BRegProposal:
        _require_sync()
        return self._client.execute_proposal(attempt)

    def health(self) -> dict[str, Any]:
        _require_sync()
        return self._client.health()

    def ready(self) -> dict[str, Any]:
        _require_sync()
        return self._client.ready()

    def openapi(self, access_profile: str | None = None) -> dict[str, Any]:
        _require_sync()
        return self._client.openapi(access_profile)

    def registry_metadata(self, access_profile: str | None = None) -> dict[str, Any]:
        _require_sync()
        return self._client.registry_metadata(access_profile)

    def event_record_creation_revision(
        self,
        record_route: str,
        record_identifier: str,
        *,
        access_profile: str | None = None,
    ) -> dict[str, str] | None:
        _require_sync()
        return self._client.event_record_creation_revision(
            record_route, record_identifier, access_profile=access_profile
        )

    def statistics_live(
        self,
        dataset: str,
        *,
        from_period: str | None = None,
        to_period: str | None = None,
        access_profile: str | None = None,
        format: breg.StatisticsFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.statistics_live(
            dataset,
            from_period=from_period,
            to_period=to_period,
            access_profile=access_profile,
            format=format,
        )

    def statistics_releases(
        self,
        dataset: str,
        *,
        top: int | None = None,
        skip_token: str | None = None,
        access_profile: str | None = None,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.statistics_releases(
            dataset, top=top, skip_token=skip_token, access_profile=access_profile
        )

    def statistics_latest_release(
        self,
        dataset: str,
        period: str,
        selection: breg.StatisticsReleaseSelection,
        *,
        access_profile: str | None = None,
        format: breg.StatisticsFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.statistics_latest_release(
            dataset, period, selection, access_profile=access_profile, format=format
        )

    def statistics_release_version(
        self,
        dataset: str,
        period: str,
        version: int,
        *,
        access_profile: str | None = None,
        format: breg.StatisticsFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.statistics_release_version(
            dataset, period, version, access_profile=access_profile, format=format
        )

    def statistics_release_series(
        self,
        dataset: str,
        from_period: str,
        to_period: str,
        selection: breg.StatisticsReleaseSelection,
        *,
        access_profile: str | None = None,
        format: breg.StatisticsFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.statistics_release_series(
            dataset,
            from_period,
            to_period,
            selection,
            access_profile=access_profile,
            format=format,
        )

    def statistics_publish(
        self,
        dataset: str,
        period: str,
        status: breg.StatisticsReleaseStatus,
        access_profile: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.statistics_publish(
            dataset, period, status, access_profile, idempotency_key
        )

    def statistics_withdraw(
        self,
        dataset: str,
        period: str,
        version: int,
        reason: breg.StatisticsWithdrawalReason,
        access_profile: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.statistics_withdraw(
            dataset, period, version, reason, access_profile, idempotency_key
        )

    def registry_contract(self, access_profile: str | None = None) -> breg.BRegMetadata:
        _require_sync()
        return self._client.registry_contract(access_profile)

    def record_schema(
        self, record_type_identifier: str, access_profile: str | None = None
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.record_schema(record_type_identifier, access_profile)

    def get_record(
        self,
        record_route: str,
        record_identifier: str,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.get_record(
            record_route,
            record_identifier,
            select=select,
            access_profile=access_profile,
            format=format,
        )

    def get_geojson_record(
        self,
        record_route: str,
        record_identifier: str,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
    ) -> breg.GeoJsonCompleteOutcome:
        _require_sync()
        return self._client.get_geojson_record(
            record_route,
            record_identifier,
            select=select,
            access_profile=access_profile,
        )

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
    ) -> breg.GeoJsonPageOutcome:
        _require_sync()
        return self._client.list_geojson_records(
            record_route,
            top=top,
            select=select,
            access_profile=access_profile,
            filter=filter,
            orderby=orderby,
            count=count,
            bbox=bbox,
        )

    def continue_geojson_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> breg.GeoJsonPageOutcome:
        _require_sync()
        return self._client.continue_geojson_list(continuation)

    def record_revisions(
        self,
        record_route: str,
        record_identifier: str,
        access_profile: str | None = None,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.record_revisions(
            record_route, record_identifier, access_profile
        )

    def get_record_revision(
        self,
        record_route: str,
        record_identifier: str,
        revision: int,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.get_record_revision(
            record_route,
            record_identifier,
            revision,
            select=select,
            access_profile=access_profile,
            format=format,
        )

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
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.list_records(
            record_route,
            top=top,
            select=select,
            access_profile=access_profile,
            format=format,
            filter=filter,
            orderby=orderby,
            count=count,
            bbox=bbox,
        )

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
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.list_current_records(
            record_route,
            top=top,
            select=select,
            access_profile=access_profile,
            format=format,
            filter=filter,
            orderby=orderby,
            count=count,
        )

    def continue_current_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.continue_current_list(continuation)

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
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.list_records_as_of(
            record_route,
            as_of,
            top=top,
            select=select,
            access_profile=access_profile,
            format=format,
            filter=filter,
            orderby=orderby,
            count=count,
        )

    def continue_as_of_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.continue_as_of_list(continuation)

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
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.list_snapshot_records(
            record_route,
            snapshot=snapshot,
            valid_at=valid_at,
            top=top,
            select=select,
            access_profile=access_profile,
            format=format,
            filter=filter,
            orderby=orderby,
            count=count,
        )

    def continue_snapshot_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.continue_snapshot_list(continuation)

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
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.list_relationship_records(
            record_route,
            record_identifier,
            path_route,
            top=top,
            select=select,
            access_profile=access_profile,
            format=format,
            filter=filter,
            orderby=orderby,
            count=count,
        )

    def continue_relationship_list(
        self, continuation: dict[str, breg.JsonValue]
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.continue_relationship_list(continuation)

    def continue_list(self, continuation: dict[str, breg.JsonValue]) -> dict[str, Any]:
        _require_sync()
        return self._client.continue_list(continuation)

    def lookup_record(
        self,
        record_route: str,
        selector: str,
        values: dict[str, breg.JsonValue] | None = None,
        *,
        select: Sequence[str] | None = None,
        access_profile: str | None = None,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.lookup_record(
            record_route,
            selector,
            values,
            select=select,
            access_profile=access_profile,
            format=format,
        )

    def create_record(
        self,
        binding: breg.BRegCreateBinding,
        data: dict[str, breg.JsonValue],
        idempotency_key: str,
        *,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.create_record(binding, data, idempotency_key, format=format)

    def prepare_create(
        self,
        binding: breg.BRegCreateBinding,
        data: dict[str, breg.JsonValue],
        idempotency_key: str,
        *,
        format: breg.RecordFormat = "json",
    ) -> breg.BRegPreparedCreate:
        _require_sync()
        return self._client.prepare_create(
            binding, data, idempotency_key, format=format
        )

    def recover_create(
        self, binding: breg.BRegCreateBinding, prepared: breg.BRegPreparedCreate
    ) -> breg.BRegRecoveredCreate:
        _require_sync()
        return self._client.recover_create(binding, prepared)

    def execute_recovered_create(
        self, binding: breg.BRegCreateBinding, recovered: breg.BRegRecoveredCreate
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.execute_recovered_create(binding, recovered)

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
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.patch_record(
            binding, record_identifier, etag, operations, idempotency_key, format=format
        )

    def action_target_conditions(
        self, binding: breg.BRegActionBinding, inputs: dict[str, breg.JsonValue]
    ) -> breg.BRegActionTargetConditions:
        _require_sync()
        return self._client.action_target_conditions(binding, inputs)

    def action_availability(
        self,
        binding: breg.BRegActionBinding,
        target_input: str,
        inputs: dict[str, breg.JsonValue],
    ) -> breg.BRegActionAvailabilityOutcome:
        _require_sync()
        return self._client.action_availability(binding, target_input, inputs)

    def invoke_action(
        self,
        binding: breg.BRegActionBinding,
        inputs: dict[str, breg.JsonValue],
        idempotency_key: str,
        conditions: breg.BRegActionTargetConditions | None = None,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.invoke_action(binding, inputs, idempotency_key, conditions)

    def prepare_action(
        self,
        binding: breg.BRegActionBinding,
        inputs: dict[str, breg.JsonValue],
        idempotency_key: str,
        conditions: breg.BRegActionTargetConditions | None = None,
    ) -> breg.BRegPreparedAction:
        _require_sync()
        return self._client.prepare_action(binding, inputs, idempotency_key, conditions)

    def recover_action(
        self,
        binding: breg.BRegActionBinding,
        prepared: breg.BRegPreparedAction,
        inputs: dict[str, breg.JsonValue],
        idempotency_key: str,
    ) -> breg.BRegRecoveredAction:
        _require_sync()
        return self._client.recover_action(binding, prepared, inputs, idempotency_key)

    def execute_recovered_action(
        self, binding: breg.BRegActionBinding, recovered: breg.BRegRecoveredAction
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.execute_recovered_action(binding, recovered)

    def execute_recovered_proposal_start(
        self, binding: breg.BRegActionBinding, recovered: breg.BRegRecoveredAction
    ) -> breg.BRegProposal:
        _require_sync()
        return self._client.execute_recovered_proposal_start(binding, recovered)

    def download_proposal_attachment(
        self, proposal: breg.BRegProposal, slot: str
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.download_proposal_attachment(proposal, slot)

    def read_proposal_review_status(
        self, proposal: breg.BRegProposal
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.read_proposal_review_status(proposal)

    def read_proposal_review_status_with_progress(
        self, proposal: breg.BRegProposal
    ) -> breg.BRegProposalReviewCompleteOutcome:
        _require_sync()
        return self._client.read_proposal_review_status_with_progress(proposal)

    def read_proposal_review_context(
        self, proposal: breg.BRegProposal
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.read_proposal_review_context(proposal)

    def read_proposal_review_context_batch(
        self, binding: breg.BRegProposalReviewBinding, ids: list[str]
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.read_proposal_review_context_batch(binding, ids)

    def read_proposal_review_by_id(
        self, binding: breg.BRegProposalReviewBinding, identifier: str
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.read_proposal_review_by_id(binding, identifier)

    def download_proposal_review_document(
        self,
        binding: breg.BRegProposalReviewBinding,
        context: dict[str, Any],
        field: str,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.download_proposal_review_document(binding, context, field)

    def upload_proposal_attachment(
        self,
        proposal: breg.BRegProposal,
        slot: str,
        content_type: str,
        bytes: bytes,
        key: str,
    ) -> breg.BRegProposal:
        _require_sync()
        return self._client.upload_proposal_attachment(
            proposal, slot, content_type, bytes, key
        )

    def delete_proposal_attachment(
        self, proposal: breg.BRegProposal, slot: str, key: str
    ) -> breg.BRegProposal:
        _require_sync()
        return self._client.delete_proposal_attachment(proposal, slot, key)

    def tombstone_record(
        self,
        binding: breg.BRegTombstoneBinding,
        record_identifier: str,
        etag: str,
        idempotency_key: str,
        *,
        format: breg.RecordFormat = "json",
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.tombstone_record(
            binding, record_identifier, etag, idempotency_key, format=format
        )

    def batch_records(
        self,
        binding: breg.BRegBatchBinding,
        items: Sequence[dict[str, breg.JsonValue]],
        idempotency_key: str,
        *,
        change_context: dict[str, breg.JsonValue] | None = None,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.batch_records(
            binding, items, idempotency_key, change_context=change_context
        )

    def create_ingestion_run(
        self, record_route: str, request: dict[str, breg.JsonValue]
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.create_ingestion_run(record_route, request)

    def list_ingestion_runs(
        self,
        record_route: str,
        *,
        limit: int | None = None,
        cursor: str | None = None,
        status: breg.IngestionRunStatus | None = None,
        input_digest: str | None = None,
        access_profile: str | None = None,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.list_ingestion_runs(
            record_route,
            limit=limit,
            cursor=cursor,
            status=status,
            input_digest=input_digest,
            access_profile=access_profile,
        )

    def read_ingestion_run(
        self, record_route: str, run_id: str, access_profile: str | None = None
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.read_ingestion_run(record_route, run_id, access_profile)

    def submit_ingestion_chunk(
        self,
        record_route: str,
        run_id: str,
        chunk: breg.BRegIngestionChunk,
        profile_id: str,
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.submit_ingestion_chunk(
            record_route, run_id, chunk, profile_id
        )

    def cancel_ingestion_run(
        self, record_route: str, run_id: str, access_profile: str | None = None
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.cancel_ingestion_run(record_route, run_id, access_profile)

    def ingestion_chunk_receipt(
        self, record_route: str, run_id: str, chunk_index: int, profile_id: str
    ) -> dict[str, Any]:
        _require_sync()
        return self._client.ingestion_chunk_receipt(
            record_route, run_id, chunk_index, profile_id
        )
