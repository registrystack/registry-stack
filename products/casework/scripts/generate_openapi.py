#!/usr/bin/env python3
"""Generate the deterministic Registry Casework OpenAPI contract."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


ROUTES = {
    "/health",
    "/ready",
    "/v1/casework",
    "/v1/hosted-items",
    "/v1/hosted-items/terminal",
    "/v1/hosted-items/{item_id}",
    "/v1/hosted-items/{item_id}/notes",
    "/v1/hosted-items/{item_id}/cancel",
    "/v1/hosted-accountability/{event_id}",
    "/v1/work-items",
    "/v1/work-items/next",
    "/v1/work-items/{item_id}",
    "/v1/work-items/{item_id}/clocks",
    "/v1/work-items/{item_id}/claim",
    "/v1/work-items/{item_id}/assign",
    "/v1/work-items/{item_id}/delegate",
    "/v1/work-items/{item_id}/release",
    "/v1/work-items/{item_id}/draft",
    "/v1/work-items/{item_id}/decisions",
    "/v1/work-items/{item_id}/hosted-decisions",
    "/v1/work-items/{item_id}/hosted-history",
    "/v1/work-items/{item_id}/attempts/recover",
    "/v1/work-items/{item_id}/attempts/{attempt_id}/recover",
    "/v1/work-items/{item_id}/history",
    "/v1/holdings",
    "/v1/directory",
    "/v1/directory/absences",
    "/v1/directory/absences/{absence_id}",
    "/v1/directory/bootstrap",
    "/v1/directory/clocks/recompute/apply",
    "/v1/directory/clocks/recompute/preview",
    "/v1/directory/holidays",
    "/v1/directory/holidays/{id}/revisions/{revision}",
    "/v1/directory/teams/{team_id}",
    "/v1/directory/caseload/apply",
    "/v1/directory/caseload/preview",
    "/events/sources/{source_id}",
}
HEADERS = {
    "CASEWORK_PROFILE_HEADER": "registry-casework-profile",
    "SOURCE_PROFILE_HEADER": "registry-source-profile",
    "ATTEMPT_REFERENCE_HEADER": "registry-casework-attempt",
    "IDEMPOTENCY_KEY_HEADER": "idempotency-key",
    "IF_MATCH_HEADER": "if-match",
    "VALIDATION_PATH_HEADER": "registry-casework-validation-path",
    "VALIDATION_REASON_HEADER": "registry-casework-validation-reason",
}
DTO_MARKERS = {
    "ListWorkItemsQuery",
    "NextWorkItemQuery",
    "HoldingsQuery",
    "SaveDraftRequest",
    "DecideRequest",
    "RecoverAttemptRequest",
    "MutationResponse",
    "BootstrapDirectoryRequest",
    "DirectoryTeamUpdateRequest",
    "DirectoryResponse",
    "Description",
    "DraftResponse",
    "HostedTerminalQuery",
    "HostedPageQuery",
    "HostedNotePage",
    "HostedHistoryPage",
}
SCHEMA_STRUCTS = {
    "crates/registry-casework-core/src/model.rs": {
        "IssuerPrincipal": "IssuerPrincipal",
        "SourceBinding": "SourceBinding",
        "SubjectRef": "SubjectRef",
        "CaseworkAction": "CaseworkAction",
        "AssignmentContext": "AssignmentContext",
        "WorkItem": "WorkItem",
        "CorrectionRoutingCopy": "CorrectionRoutingCopy",
        "Draft": "Draft",
        "HistoryEntry": "HistoryEntry",
        "AttemptStatus": "AttemptStatus",
        "HoldingSummary": "HoldingSummary",
        "QueueRecord": "QueueRecord",
        "TeamRecord": "TeamRecord",
        "SourceReceipt": "SourceReceipt",
    },
    "crates/registry-casework-core/src/http.rs": {
        "SaveDraftRequest": "SaveDraftRequest",
        "DecideRequest": "DecideRequest",
        "RecoverAttemptRequest": "RecoverAttemptRequest",
        "MutationResponse": "MutationResponse",
        "BootstrapDirectoryRequest": "BootstrapDirectoryRequest",
        "DirectoryTeamUpdateRequest": "DirectoryTeamUpdateRequest",
        "DirectoryResponse": "DirectoryResponse",
        "Description": "Description",
        "DraftResponse": "DraftResponse",
        "HostedHistoryEntry": "HostedHistoryEntry",
    },
    "crates/registry-casework-core/src/assignment.rs": {
        "AbsenceRecord": "AbsenceRecord",
        "AbsenceInput": "AbsenceInput",
        "AssignmentRequest": "AssignmentRequest",
        "DelegateRequest": "DelegateRequest",
        "CaseloadMoveRequest": "CaseloadMoveRequest",
        "CaseloadItemSelection": "CaseloadItemSelection",
        "CaseloadApplyRequest": "CaseloadApplyRequest",
        "CaseloadItemResult": "CaseloadItemResult",
    },
    "crates/registry-casework-core/src/config.rs": {
        "CaseworkProject": "CaseworkProject",
        "CaseworkIdentity": "CaseworkIdentity",
        "AccessProfile": "AccessProfile",
        "QueuePolicy": "QueuePolicy",
        "SourcePolicy": "SourcePolicy",
        "SourceRequestPolicy": "SourceRequestPolicy",
        "PassiveTargetPolicy": "PassiveTargetPolicy",
        "ElapsedDuration": "ElapsedDuration",
        "InboxPolicy": "InboxPolicy",
    },
    "crates/registry-casework-core/src/routing.rs": {
        "RoutingRule": "RoutingRule",
        "RoutingCondition": "RoutingCondition",
        "EqualsPredicate": "EqualsPredicate",
        "OneOfPredicate": "OneOfPredicate",
    },
    "crates/registry-casework-core/src/policy.rs": {
        "CalendarPolicy": "CalendarPolicy",
        "WorkingDaysAfter": "WorkingDaysAfter",
        "WorkingDaysBefore": "WorkingDaysBefore",
        "ClockReminder": "ClockReminder",
        "ClockStep": "ClockStep",
        "ClockStepAction": "ClockStepAction",
        "ClockReassignment": "ClockReassignment",
        "HolidaySetDocument": "HolidaySetDocument",
    },
    "crates/registry-casework-core/src/clock_runtime.rs": {
        "ClockOccurrenceView": "ClockOccurrenceView",
        "HolidaySetRevisionInput": "HolidaySetRevisionInput",
        "ClockRecomputeRequest": "ClockRecomputeRequest",
        "ClockRecomputeChange": "ClockRecomputeChange",
        "ClockRecomputePreview": "ClockRecomputePreview",
        "ClockRecomputeApplyRequest": "ClockRecomputeApplyRequest",
        "ClockRecomputeResult": "ClockRecomputeResult",
    },
    "crates/registry-casework-core/src/hosted.rs": {
        "HostedRetentionPolicy": "HostedRetentionPolicy",
        "HostedOutcomePolicy": "HostedOutcomePolicy",
        "HostedKindPolicy": "HostedKindPolicy",
        "HostedWorkItemContext": "HostedWorkItemContext",
        "HostedCreateRequest": "HostedCreateRequest",
        "HostedNoteRequest": "HostedNoteRequest",
        "HostedCancelRequest": "HostedCancelRequest",
        "HostedDecisionRequest": "HostedDecisionRequest",
        "RequesterHostedItem": "RequesterHostedItem",
        "HostedNote": "HostedNote",
        "HostedAccountabilityRecord": "HostedAccountabilityRecord",
    },
}
OPERATION_IDS = {
    ("POST", "/events/sources/{source_id}"): "acceptSourceEvent",
    ("GET", "/health"): "health",
    ("GET", "/ready"): "readiness",
    ("GET", "/v1/casework"): "describeCasework",
    ("POST", "/v1/hosted-items"): "createHostedItem",
    ("GET", "/v1/hosted-items/terminal"): "listHostedTerminalResults",
    ("GET", "/v1/hosted-items/{item_id}"): "getHostedItem",
    ("GET", "/v1/hosted-items/{item_id}/notes"): "listHostedNotes",
    ("POST", "/v1/hosted-items/{item_id}/notes"): "addHostedNote",
    ("POST", "/v1/hosted-items/{item_id}/cancel"): "cancelHostedItem",
    ("GET", "/v1/hosted-accountability/{event_id}"): "getHostedAccountability",
    ("GET", "/v1/directory"): "getDirectory",
    ("GET", "/v1/directory/absences"): "listAbsences",
    ("POST", "/v1/directory/absences"): "createAbsence",
    ("DELETE", "/v1/directory/absences/{absence_id}"): "deleteAbsence",
    ("PUT", "/v1/directory/absences/{absence_id}"): "updateAbsence",
    ("POST", "/v1/directory/bootstrap"): "bootstrapDirectory",
    ("POST", "/v1/directory/clocks/recompute/apply"): "applyClockRecompute",
    ("POST", "/v1/directory/clocks/recompute/preview"): "previewClockRecompute",
    ("POST", "/v1/directory/holidays"): "createHolidayRevision",
    ("GET", "/v1/directory/holidays/{id}/revisions/{revision}"): "getHolidayRevision",
    ("PUT", "/v1/directory/teams/{team_id}"): "updateDirectoryTeam",
    ("POST", "/v1/directory/caseload/apply"): "applyCaseloadMove",
    ("POST", "/v1/directory/caseload/preview"): "previewCaseloadMove",
    ("GET", "/v1/holdings"): "getHoldings",
    ("GET", "/v1/work-items"): "listWorkItems",
    ("GET", "/v1/work-items/next"): "getNextWorkItem",
    ("GET", "/v1/work-items/{item_id}"): "getWorkItem",
    ("GET", "/v1/work-items/{item_id}/clocks"): "getWorkItemClocks",
    ("POST", "/v1/work-items/{item_id}/attempts/recover"): "recoverAttemptByKey",
    ("POST", "/v1/work-items/{item_id}/attempts/{attempt_id}/recover"): "recoverAttempt",
    ("POST", "/v1/work-items/{item_id}/claim"): "claimWorkItem",
    ("POST", "/v1/work-items/{item_id}/assign"): "assignWorkItem",
    ("POST", "/v1/work-items/{item_id}/decisions"): "decideWorkItem",
    ("POST", "/v1/work-items/{item_id}/hosted-decisions"): "decideHostedWorkItem",
    ("GET", "/v1/work-items/{item_id}/hosted-history"): "getHostedHistory",
    ("POST", "/v1/work-items/{item_id}/delegate"): "delegateWorkItem",
    ("DELETE", "/v1/work-items/{item_id}/draft"): "deleteDraft",
    ("GET", "/v1/work-items/{item_id}/draft"): "getDraft",
    ("PUT", "/v1/work-items/{item_id}/draft"): "saveDraft",
    ("GET", "/v1/work-items/{item_id}/history"): "getHistory",
    ("POST", "/v1/work-items/{item_id}/release"): "releaseWorkItem",
}
def ref(name: str) -> dict:
    return {"$ref": f"#/components/schemas/{name}"}


def header_ref(name: str) -> dict:
    return {"$ref": f"#/components/headers/{name}"}


def obj(properties: dict, required: list[str] | None = None) -> dict:
    result = {"type": "object", "additionalProperties": False, "properties": properties}
    if required:
        result["required"] = required
    return result


def array(items: dict) -> dict:
    return {"type": "array", "items": items}


def nullable(schema: dict) -> dict:
    return {"anyOf": [schema, {"type": "null"}]}


def schemas(problem_entries: list[dict]) -> dict:
    text = {"type": "string"}
    integer = {"type": "integer", "format": "int64"}
    uuid = {"type": "string", "format": "uuid"}
    instant = {"type": "string", "format": "date-time"}
    operation_name = {
        "type": "string",
        "pattern": "^[a-z][a-z0-9_]{0,63}$",
        "maxLength": 64,
    }
    authored_identifier = {
        "type": "string",
        "pattern": "^[a-z][a-z0-9-]{0,63}$",
        "maxLength": 64,
    }
    issuer = obj({"issuer": text, "subject": text}, ["issuer", "subject"])
    binding = obj(
        {"sourceRevision": text, "version": text, "integrity": nullable(text), "generation": text},
        ["sourceRevision", "version", "generation"],
    )
    subject = obj({"sourceId": text, "kind": text, "id": text}, ["sourceId", "kind", "id"])
    action = obj({"operation": text, "href": text, "ifMatch": text}, ["operation", "href", "ifMatch"])
    policy_digest = {
        "type": "string",
        "pattern": "^sha256:[0-9a-f]{64}$",
        "minLength": 71,
        "maxLength": 71,
    }
    actor_ref = {
        "type": "string",
        "pattern": "^actor_[A-Za-z0-9_-]+$",
        "minLength": 7,
        "maxLength": 128,
    }
    display = {
        "type": "object",
        "additionalProperties": True,
        "x-maximum-canonical-bytes": 16_384,
        "x-maximum-depth": 16,
    }
    reason = {
        "type": "string",
        "minLength": 1,
        "maxLength": 2000,
        "x-maximum-utf8-bytes": 2000,
    }
    hosted_outcome = obj(
        {"id": text, "label": text, "reasonRequired": {"type": "boolean"}},
        ["id", "label", "reasonRequired"],
    )
    hosted_context = obj(
        {
            "requesterReference": text,
            "kind": text,
            "version": text,
            "display": display,
            "kindPolicyDigest": policy_digest,
            "outcomes": array(ref("HostedOutcomePolicy")),
        },
        [
            "requesterReference",
            "kind",
            "version",
            "display",
            "kindPolicyDigest",
            "outcomes",
        ],
    )
    work_item = obj(
        {
            "itemId": uuid,
            "subject": ref("SubjectRef"),
            "occurrenceKind": {"type": "string", "enum": ["review", "application", "hosted"]},
            "stage": nullable(text),
            "binding": ref("SourceBinding"),
            "bindingReference": text,
            "state": {"type": "string", "enum": ["open", "claimed", "waiting_applicant", "waiting_application", "synchronizing", "completed", "superseded", "cancelled"]},
            "queueId": text,
            "holder": nullable(ref("IssuerPrincipal")),
            "assignment": nullable(ref("AssignmentContext")),
            "revision": integer,
            "firstObservedAt": instant,
            "passiveDueAt": nullable(instant),
            "updatedAt": instant,
            "hosted": nullable(ref("HostedWorkItemContext")),
            "actions": array(ref("CaseworkAction")),
            "routingCopy": nullable(ref("CorrectionRoutingCopy")),
            "liveAttempt": ref("AttemptStatus"),
        },
        ["itemId", "subject", "occurrenceKind", "binding", "bindingReference", "state", "queueId", "revision", "firstObservedAt", "updatedAt", "actions"],
    )
    page_status = {"type": "string", "enum": ["complete", "budget_exhausted", "source_unavailable"]}
    result = {
        "IssuerPrincipal": issuer,
        "OperationName": operation_name,
        "SourceBinding": binding,
        "SubjectRef": subject,
        "CaseworkAction": action,
        "StaffingDiagnostic": {
            "type": "string",
            "enum": ["no_cover_available"],
        },
        "AssignmentContext": obj(
            {
                "owner": nullable(ref("IssuerPrincipal")),
                "assignedBy": nullable(ref("IssuerPrincipal")),
                "absenceIds": array(uuid),
                "staffingDiagnostic": nullable(ref("StaffingDiagnostic")),
            },
            ["absenceIds"],
        ),
        "HostedPolicyDigest": policy_digest,
        "OpaqueActorRef": actor_ref,
        "HostedRetentionPolicy": obj(
            {
                "terminalDays": {"type": "integer", "minimum": 1, "maximum": 3650},
                "accountabilityDays": {"type": "integer", "minimum": 1, "maximum": 3650},
            },
            ["terminalDays", "accountabilityDays"],
        ),
        "HostedOutcomePolicy": hosted_outcome,
        "HostedKindPolicy": obj(
            {
                "id": text,
                "version": text,
                "queue": text,
                "decidingProfiles": array(text),
                "retention": ref("HostedRetentionPolicy"),
                "displaySchema": {
                    "type": "object",
                    "additionalProperties": True,
                    "x-maximum-canonical-bytes": 65_536,
                    "x-maximum-depth": 16,
                },
                "outcomes": array(ref("HostedOutcomePolicy")),
            },
            [
                "id",
                "version",
                "queue",
                "decidingProfiles",
                "retention",
                "displaySchema",
                "outcomes",
            ],
        ),
        "HostedWorkItemContext": hosted_context,
        "HostedCreateRequest": obj(
            {
                "kind": text,
                "requesterReference": {"type": "string", "minLength": 1, "maxLength": 128, "x-maximum-utf8-bytes": 128},
                "display": display,
            },
            ["kind", "requesterReference", "display"],
        ),
        "HostedNoteRequest": obj(
            {"note": {"type": "string", "minLength": 1, "maxLength": 2000, "x-maximum-utf8-bytes": 2000}},
            ["note"],
        ),
        "HostedCancelRequest": obj(
            {"reason": {"type": "string", "minLength": 1, "maxLength": 2000, "x-maximum-utf8-bytes": 2000}},
            ["reason"],
        ),
        "HostedDecisionRequest": obj(
            {
                "outcome": text,
                "reason": nullable(
                    {"type": "string", "minLength": 1, "maxLength": 2000, "x-maximum-utf8-bytes": 2000}
                ),
            },
            ["outcome"],
        ),
        "RequesterHostedItem": obj(
            {
                "itemId": uuid,
                "requesterReference": text,
                "kind": text,
                "version": text,
                "display": display,
                "state": {
                    "type": "string",
                    "enum": ["open", "claimed", "completed", "cancelled"],
                },
                "revision": integer,
                "kindPolicyDigest": policy_digest,
                "createdAt": instant,
                "updatedAt": instant,
            },
            [
                "itemId",
                "requesterReference",
                "kind",
                "version",
                "display",
                "state",
                "revision",
                "kindPolicyDigest",
                "createdAt",
                "updatedAt",
            ],
        ),
        "HostedNote": obj(
            {
                "noteId": uuid,
                "itemId": uuid,
                "note": text,
                "itemRevision": integer,
                "recordedAt": instant,
            },
            ["noteId", "itemId", "note", "itemRevision", "recordedAt"],
        ),
        "HostedNotePage": obj(
            {
                "items": array(ref("HostedNote")),
                "nextCursor": nullable(text),
                "status": page_status,
            },
            ["items", "status"],
        ),
        "HostedHistoryEntry": obj(
            {
                "eventId": uuid,
                "itemId": uuid,
                "itemRevision": integer,
                "kind": {
                    "type": "string",
                    "enum": [
                        "created",
                        "claimed",
                        "assigned",
                        "delegated",
                        "caseload_moved",
                        "released",
                        "note_added",
                        "completed",
                        "cancelled",
                    ],
                },
                "occurredAt": instant,
                "actorRef": nullable(actor_ref),
                "assignment": nullable(ref("AssignmentContext")),
                "note": nullable(text),
                "outcome": nullable(text),
                "reason": nullable(text),
                "cancellationReason": nullable(text),
            },
            ["eventId", "itemId", "itemRevision", "kind", "occurredAt"],
        ),
        "HostedHistoryPage": obj(
            {
                "items": array(ref("HostedHistoryEntry")),
                "nextCursor": nullable(text),
                "status": page_status,
            },
            ["items", "status"],
        ),
        "HostedAccountabilityRecord": obj(
            {
                "itemId": uuid,
                "eventId": uuid,
                "actorRef": actor_ref,
                "actor": ref("IssuerPrincipal"),
                "profileId": text,
                "outcome": text,
                "reason": nullable(text),
                "recordedAt": instant,
                "retainedUntil": instant,
            },
            [
                "itemId",
                "eventId",
                "actorRef",
                "actor",
                "profileId",
                "outcome",
                "recordedAt",
                "retainedUntil",
            ],
        ),
        "HostedTerminalCompleted": obj(
            {
                "itemId": uuid,
                "eventId": uuid,
                "requesterReference": text,
                "state": {"const": "completed"},
                "outcome": text,
                "actorRef": actor_ref,
                "kindPolicyDigest": policy_digest,
                "terminalAt": instant,
            },
            [
                "itemId",
                "eventId",
                "requesterReference",
                "state",
                "outcome",
                "actorRef",
                "kindPolicyDigest",
                "terminalAt",
            ],
        ),
        "HostedTerminalCancelled": obj(
            {
                "itemId": uuid,
                "eventId": uuid,
                "requesterReference": text,
                "state": {"const": "cancelled"},
                "cancellationReason": text,
                "kindPolicyDigest": policy_digest,
                "terminalAt": instant,
            },
            [
                "itemId",
                "eventId",
                "requesterReference",
                "state",
                "cancellationReason",
                "kindPolicyDigest",
                "terminalAt",
            ],
        ),
        "HostedTerminalResult": {
            "oneOf": [ref("HostedTerminalCompleted"), ref("HostedTerminalCancelled")],
            "discriminator": {"propertyName": "state"},
        },
        "HostedTerminalPage": obj(
            {
                "items": array(ref("HostedTerminalResult")),
                "nextCursor": nullable(text),
                "status": page_status,
            },
            ["items", "status"],
        ),
        "CorrectionRoutingCopy": obj(
            {"sourceBinding": ref("SourceBinding"), "reason": nullable(text), "flaggedFields": array(text)},
            ["sourceBinding", "flaggedFields"],
        ),
        "WorkItem": work_item,
        "WorkItemPage": obj({"items": array(ref("WorkItem")), "nextCursor": nullable(text), "status": page_status}, ["items", "status"]),
        "AbsenceRecord": obj(
            {
                "absenceId": uuid,
                "person": ref("IssuerPrincipal"),
                "from": instant,
                "until": instant,
                "cover": ref("IssuerPrincipal"),
                "revision": integer,
            },
            ["absenceId", "person", "from", "until", "cover", "revision"],
        ),
        "AbsenceRecordList": {
            "type": "array",
            "maxItems": 1000,
            "items": ref("AbsenceRecord"),
        },
        "AbsenceInput": obj(
            {
                "person": ref("IssuerPrincipal"),
                "from": instant,
                "until": instant,
                "cover": ref("IssuerPrincipal"),
            },
            ["person", "from", "until", "cover"],
        ),
        "AssignmentRequest": obj(
            {
                "assignee": ref("IssuerPrincipal"),
                "reason": nullable(reason),
            },
            ["assignee"],
        ),
        "DelegateRequest": obj(
            {
                "delegate": ref("IssuerPrincipal"),
                "reason": nullable(reason),
            },
            ["delegate"],
        ),
        "CaseloadMoveRequest": obj(
            {
                "from": ref("IssuerPrincipal"),
                "to": ref("IssuerPrincipal"),
                "queueId": nullable(text),
                "reason": reason,
            },
            ["from", "to", "reason"],
        ),
        "CaseloadItemSelection": obj(
            {
                "itemId": uuid,
                "expectedRevision": {
                    "type": "integer",
                    "format": "int64",
                    "minimum": 1,
                },
            },
            ["itemId", "expectedRevision"],
        ),
        "CaseloadApplyRequest": obj(
            {
                "movement": ref("CaseloadMoveRequest"),
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 100,
                    "uniqueItems": True,
                    "x-unique-by": "itemId",
                    "items": ref("CaseloadItemSelection"),
                },
            },
            ["movement", "items"],
        ),
        "CaseloadItemOutcome": {
            "type": "string",
            "enum": [
                "moved",
                "not_visible",
                "not_eligible",
                "attempt_in_progress",
                "conflict",
            ],
        },
        "CaseloadItemResult": obj(
            {
                "itemId": uuid,
                "result": ref("CaseloadItemOutcome"),
                "revision": nullable(integer),
            },
            ["itemId", "result"],
        ),
        "CaseloadItemResultList": array(ref("CaseloadItemResult")),
        "CaseloadPreviewPage": obj(
            {
                "items": array(ref("WorkItem")),
                "nextCursor": nullable(text),
                "status": page_status,
            },
            ["items", "status"],
        ),
        "Draft": obj(
            {"itemId": uuid, "author": ref("IssuerPrincipal"), "binding": ref("SourceBinding"), "reason": text, "flaggedFields": array(text), "revision": integer, "updatedAt": instant},
            ["itemId", "author", "binding", "reason", "flaggedFields", "revision", "updatedAt"],
        ),
        "DraftResponse": obj({"draft": ref("Draft")}, ["draft"]),
        "SaveDraftRequest": obj({"binding": ref("SourceBinding"), "reason": text, "flaggedFields": array(text)}, ["binding", "reason"]),
        "DecideRequest": obj(
            {"displayedBinding": ref("SourceBinding"), "sourceProfileId": PROFILE_SCHEMA, "operation": ref("OperationName"), "reason": nullable(text), "flaggedFields": array(text)},
            ["displayedBinding", "sourceProfileId", "operation"],
        ),
        "RecoverAttemptRequest": obj(
            {"sourceProfileId": PROFILE_SCHEMA}, ["sourceProfileId"]
        ),
        "SourceReceipt": obj(
            {"sourceRevision": text, "resultingState": text, "binding": ref("SourceBinding"), "actorReference": nullable(text), "metadata": {"type": "object", "additionalProperties": True}},
            ["sourceRevision", "resultingState", "binding", "metadata"],
        ),
        "AttemptStatus": obj(
            {"attemptId": uuid, "itemId": uuid, "state": {"type": "string", "enum": ["pending", "uncertain", "completed", "refused"]}, "itemRevision": integer, "operation": ref("OperationName"), "createdAt": instant, "receipt": nullable(ref("SourceReceipt"))},
            ["attemptId", "itemId", "state", "itemRevision", "operation", "createdAt"],
        ),
        "MutationResponse": obj({"item": ref("WorkItem"), "attempt": nullable(ref("AttemptStatus"))}, ["item"]),
        "HistoryEntry": obj(
            {"eventId": uuid, "itemId": uuid, "itemRevision": integer, "kind": {"type": "string", "enum": ["observed", "opened", "claimed", "released", "draft_saved", "attempt_reserved", "attempt_uncertain", "action_completed", "superseded", "completed"]}, "occurredAt": instant, "actor": nullable(ref("IssuerPrincipal")), "profileId": text, "detail": {}},
            ["eventId", "itemId", "itemRevision", "kind", "occurredAt", "profileId", "detail"],
        ),
        "HistoryPage": obj({"items": array(ref("HistoryEntry")), "status": {"const": "complete"}}, ["items", "status"]),
        "HoldingSummary": obj({"principal": ref("IssuerPrincipal"), "queueId": text, "activeItems": {"type": "integer", "minimum": 0}, "overdueItems": {"type": "integer", "minimum": 0}}, ["principal", "queueId", "activeItems", "overdueItems"]),
        "HoldingsPage": obj({"items": array(ref("HoldingSummary")), "nextCursor": nullable(text), "status": page_status}, ["items", "status"]),
        "TeamRecord": obj({"id": text, "members": array(ref("IssuerPrincipal")), "supervisors": array(ref("IssuerPrincipal")), "servedQueues": array(text), "revision": integer}, ["id", "members", "supervisors", "servedQueues", "revision"]),
        "DirectoryResponse": obj({"revision": integer, "teams": array(ref("TeamRecord"))}, ["revision", "teams"]),
        "BootstrapDirectoryRequest": obj({"teamId": text, "staff": array(ref("IssuerPrincipal")), "supervisors": array(ref("IssuerPrincipal")), "queueId": text}, ["teamId", "staff", "supervisors", "queueId"]),
        "DirectoryTeamPrincipal": obj(
            {
                "issuer": {"type": "string", "minLength": 1, "maxLength": 2048, "x-maximum-utf8-bytes": 2048, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"},
                "subject": {"type": "string", "minLength": 1, "maxLength": 2048, "x-maximum-utf8-bytes": 2048, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"},
            },
            ["issuer", "subject"],
        ),
        "DirectoryTeamUpdateRequest": obj(
            {
                "staff": {"type": "array", "maxItems": 100, "uniqueItems": True, "items": ref("DirectoryTeamPrincipal")},
                "supervisors": {"type": "array", "maxItems": 100, "uniqueItems": True, "items": ref("DirectoryTeamPrincipal")},
                "servedQueues": {"type": "array", "maxItems": 100, "uniqueItems": True, "items": {"type": "string", "minLength": 1, "maxLength": 128, "x-maximum-utf8-bytes": 128, "pattern": "^[A-Za-z0-9._-]+$"}},
            },
            ["staff", "supervisors", "servedQueues"],
        ),
        "CaseworkIdentity": obj({"id": text, "version": text}, ["id", "version"]),
        "AccessProfile": obj(
            {
                "id": text,
                "principalClaim": text,
                "requiredScopes": array(text),
                "role": {
                    "type": "string",
                    "enum": ["staff", "supervisor", "administrator", "requester"],
                },
                "kinds": array(text),
            },
            ["id", "principalClaim", "requiredScopes", "role"],
        ),
        "QueuePolicy": obj({"id": text, "label": text}, ["id", "label"]),
        "InboxPolicy": obj(
            {
                "defaultPageSize": {"type": "integer", "minimum": 1, "maximum": 100, "default": 25},
                "maximumCandidateScan": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100},
                "maximumSourceReads": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 25},
                "maximumConcurrentSourceReads": {"type": "integer", "minimum": 1, "maximum": 32, "default": 4},
                "pageDeadlineMilliseconds": {"type": "integer", "minimum": 100, "maximum": 30000, "default": 2000},
            },
        ),
        "RoutingActivity": {"type": "string", "enum": ["review", "apply"]},
        "EqualsPredicate": obj({"equals": {}}, ["equals"]),
        "OneOfPredicate": obj(
            {
                "oneOf": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 32,
                    "uniqueItems": True,
                    "items": {},
                }
            },
            ["oneOf"],
        ),
        "RoutingPredicate": {
            "oneOf": [ref("EqualsPredicate"), ref("OneOfPredicate")]
        },
        "RoutingCondition": obj(
            {
                "activity": nullable(ref("RoutingActivity")),
                "stage": nullable(text),
                "fields": {
                    "type": "object",
                    "maxProperties": 16,
                    "additionalProperties": ref("RoutingPredicate"),
                },
            },
        ),
        "RoutingRule": obj(
            {
                "id": authored_identifier,
                "because": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "x-maximum-utf8-bytes": 256,
                    "x-non-whitespace": True,
                },
                "when": ref("RoutingCondition"),
                "queue": text,
            },
            ["id", "because", "when", "queue"],
        ),
        "CalendarPolicy": obj(
            {
                "id": authored_identifier,
                "timezone": {"type": "string", "format": "iana-time-zone"},
                "workingWeekdays": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 7,
                    "uniqueItems": True,
                    "items": {
                        "type": "string",
                        "enum": [
                            "monday",
                            "tuesday",
                            "wednesday",
                            "thursday",
                            "friday",
                            "saturday",
                            "sunday",
                        ],
                    },
                },
                "holidaySet": authored_identifier,
            },
            ["id", "timezone", "workingWeekdays", "holidaySet"],
        ),
        "WorkingDaysAfter": obj(
            {"workingDays": {"type": "integer", "minimum": 1, "maximum": 3650}},
            ["workingDays"],
        ),
        "WorkingDaysBefore": obj(
            {"workingDaysBefore": {"type": "integer", "minimum": 1, "maximum": 3650}},
            ["workingDaysBefore"],
        ),
        "ClockReminder": obj(
            {
                "id": authored_identifier,
                "workingDaysBefore": {"type": "integer", "minimum": 1, "maximum": 3650},
            },
            ["id", "workingDaysBefore"],
        ),
        "ClockReassignment": obj({"queue": text}, ["queue"]),
        "ClockStepAction": obj(
            {"reassign": ref("ClockReassignment")}, ["reassign"]
        ),
        "ClockStep": obj(
            {
                "id": authored_identifier,
                "because": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 256,
                    "x-maximum-utf8-bytes": 256,
                    "x-non-whitespace": True,
                },
                "at": {"const": "due"},
                "action": ref("ClockStepAction"),
            },
            ["id", "because", "at", "action"],
        ),
        "SubjectClockPolicy": obj(
            {
                "id": authored_identifier,
                "scope": {"const": "subject"},
                "anchor": {"const": "firstSubmittedAt"},
                "completeOn": {"const": "reviewCompleted"},
                "after": ref("ElapsedDuration"),
                "pauseWhile": {
                    "type": "array",
                    "prefixItems": [{"const": "awaitingApplicant"}],
                    "minItems": 1,
                    "maxItems": 1,
                },
            },
            ["id", "scope", "anchor", "completeOn", "after", "pauseWhile"],
        ),
        "ActivityClockPolicy": obj(
            {
                "id": authored_identifier,
                "scope": {"const": "activity"},
                "anchor": {"const": "stageEnteredAt"},
                "calendar": authored_identifier,
                "after": ref("WorkingDaysAfter"),
                "dueTime": {
                    "type": "string",
                    "pattern": "^(?:[01][0-9]|2[0-3]):[0-5][0-9]$",
                },
                "atRisk": nullable(ref("WorkingDaysBefore")),
                "reminders": {
                    "type": "array",
                    "maxItems": 8,
                    "uniqueItems": True,
                    "x-unique-by": "id",
                    "items": ref("ClockReminder"),
                },
                "steps": {
                    "type": "array",
                    "maxItems": 8,
                    "uniqueItems": True,
                    "x-unique-by": "id",
                    "items": ref("ClockStep"),
                },
            },
            ["id", "scope", "anchor", "calendar", "after", "dueTime"],
        ),
        "ClockPolicy": {
            "oneOf": [ref("SubjectClockPolicy"), ref("ActivityClockPolicy")],
            "discriminator": {"propertyName": "scope"},
        },
        "HolidaySetDocument": obj(
            {
                "holidaySet": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                },
                "revision": {"type": "integer", "minimum": 1},
                "dates": {
                    "type": "array",
                    "maxItems": 3_660,
                    "uniqueItems": True,
                    "items": {"type": "string", "format": "date"},
                },
            },
            ["holidaySet", "revision", "dates"],
        ),
        "ClockRuntimeState": {
            "type": "string",
            "enum": [
                "running",
                "paused",
                "completed",
                "cancelled",
                "verification_pending",
                "source_facts_missing",
            ],
        },
        "ClockOccurrenceView": obj(
            {
                "clockOccurrenceId": uuid,
                "subject": ref("SubjectRef"),
                "clockId": text,
                "state": ref("ClockRuntimeState"),
                "policyDigest": policy_digest,
                "calculationGeneration": integer,
                "recomputeGeneration": integer,
                "anchorAt": nullable(instant),
                "startedAt": nullable(instant),
                "dueAt": nullable(instant),
                "atRiskAt": nullable(instant),
                "completedAt": nullable(instant),
            },
            [
                "clockOccurrenceId",
                "subject",
                "clockId",
                "state",
                "policyDigest",
                "calculationGeneration",
                "recomputeGeneration",
            ],
        ),
        "ClockOccurrenceList": {
            "type": "array",
            "maxItems": 32,
            "items": ref("ClockOccurrenceView"),
        },
        "HolidaySetRevisionInput": obj(
            {"document": ref("HolidaySetDocument")}, ["document"]
        ),
        "ClockRecomputeRequest": obj(
            {
                "clockId": text,
                "holidaySet": text,
                "holidayRevision": {"type": "integer", "minimum": 1},
            },
            ["clockId", "holidaySet", "holidayRevision"],
        ),
        "ClockRecomputeChange": obj(
            {
                "clockOccurrenceId": uuid,
                "itemId": uuid,
                "expectedCalculationGeneration": integer,
                "oldDueAt": instant,
                "proposedDueAt": instant,
            },
            [
                "clockOccurrenceId",
                "itemId",
                "expectedCalculationGeneration",
                "oldDueAt",
                "proposedDueAt",
            ],
        ),
        "ClockRecomputePreview": obj(
            {
                "previewId": uuid,
                "clockId": text,
                "holidaySet": text,
                "holidayRevision": {"type": "integer", "minimum": 1},
                "expiresAt": instant,
                "changes": {
                    "type": "array",
                    "maxItems": 100,
                    "items": ref("ClockRecomputeChange"),
                },
            },
            [
                "previewId",
                "clockId",
                "holidaySet",
                "holidayRevision",
                "expiresAt",
                "changes",
            ],
        ),
        "ClockRecomputeApplyRequest": obj(
            {"previewId": uuid}, ["previewId"]
        ),
        "ClockRecomputeResult": obj(
            {
                "previewId": uuid,
                "appliedOccurrences": {
                    "type": "array",
                    "maxItems": 100,
                    "items": uuid,
                },
            },
            ["previewId", "appliedOccurrences"],
        ),
        "CaseworkProject": obj(
            {
                "apiVersion": {"const": "registry.registrystack.org/casework/v1alpha1"},
                "kind": {"const": "CaseworkProject"},
                "casework": ref("CaseworkIdentity"),
                "accessProfiles": array(ref("AccessProfile")),
                "queues": array(ref("QueuePolicy")),
                "sources": array(ref("SourcePolicy")),
                "hostedKinds": array(ref("HostedKindPolicy")),
                "calendars": {"type": "array", "maxItems": 16, "uniqueItems": True, "x-unique-by": "id", "items": ref("CalendarPolicy")},
                "clocks": {"type": "array", "maxItems": 32, "uniqueItems": True, "x-unique-by": "id", "items": ref("ClockPolicy")},
                "inbox": ref("InboxPolicy"),
            },
            ["apiVersion", "kind", "casework", "accessProfiles", "queues"],
        ),
        "ElapsedDuration": obj({"elapsed": text}, ["elapsed"]),
        "PassiveTargetPolicy": obj({"id": text, "after": ref("ElapsedDuration")}, ["id", "after"]),
        "SourceRequestPolicy": obj(
            {
                "entity": text,
                "queue": text,
                "projection": {
                    "type": "array",
                    "maxItems": 32,
                    "uniqueItems": True,
                    "items": text,
                },
                "routing": {
                    "type": "array",
                    "maxItems": 64,
                    "uniqueItems": True,
                    "x-unique-by": "id",
                    "items": ref("RoutingRule"),
                },
                "clock": nullable(authored_identifier),
                "target": nullable(ref("PassiveTargetPolicy")),
            },
            ["entity", "queue"],
        ),
        "SourcePolicy": obj({"id": text, "adapter": text, "description": text, "requests": array(ref("SourceRequestPolicy"))}, ["id", "adapter", "description", "requests"]),
        "QueueRecord": obj({"id": text, "label": text}, ["id", "label"]),
        "Description": obj(
            {"projectId": text, "policyVersion": text, "queues": array(ref("QueueRecord")), "sources": array(ref("SourcePolicy")), "calendars": array(ref("CalendarPolicy")), "clocks": array(ref("ClockPolicy")), "hostedKinds": array(ref("HostedKindPolicy"))},
            ["projectId", "policyVersion", "queues", "sources", "calendars", "clocks", "hostedKinds"],
        ),
        "Problem": obj({"type": {"type": "string", "format": "uri"}, "title": text, "status": {"type": "integer"}, "detail": text, "code": {"type": "string", "enum": [entry["code"] for entry in problem_entries]}, "traceId": text}, ["type", "title", "status", "detail", "code", "traceId"]),
    }
    result.update(
        {
            problem_component_name(entry["code"]): problem_variant_schema(entry)
            for entry in problem_entries
        }
    )
    return result


def parameter(name: str, where: str, description: str, schema: dict | None = None, required: bool = True) -> dict:
    return {"name": name, "in": where, "required": required, "description": description, "schema": schema or {"type": "string"}}


PROFILE_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": "^[A-Za-z0-9_.:-]+$",
}
IDEMPOTENCY_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": "^[!-~]+$",
}
POSITIVE_REVISION_SCHEMA = {
    "type": "string",
    "maxLength": 21,
    "pattern": '^"[1-9][0-9]{0,18}"$',
}
NONNEGATIVE_REVISION_SCHEMA = {
    "type": "string",
    "maxLength": 21,
    "pattern": '^"(0|[1-9][0-9]{0,18})"$',
}
CASEWORK_PROFILE = parameter(
    "Registry-Casework-Profile",
    "header",
    "Explicit Casework access profile. It never selects BReg authority.",
    PROFILE_SCHEMA,
)
SOURCE_PROFILE = parameter(
    "Registry-Source-Profile",
    "header",
    "Explicit source profile used for the caller-scoped BReg read or action.",
    PROFILE_SCHEMA,
)
IF_MATCH = parameter(
    "If-Match",
    "header",
    "Quoted positive signed 64-bit Casework item revision.",
    POSITIVE_REVISION_SCHEMA,
)
IF_MATCH_ALLOW_ZERO = parameter(
    "If-Match",
    "header",
    "Quoted nonnegative signed 64-bit Casework item or directory revision.",
    NONNEGATIVE_REVISION_SCHEMA,
)
IDEMPOTENCY = parameter(
    "Idempotency-Key",
    "header",
    "Caller-selected ASCII graphic key bound to this exact mutation.",
    IDEMPOTENCY_SCHEMA,
)
HOSTED_IDEMPOTENCY = parameter(
    "Idempotency-Key",
    "header",
    "Caller-selected ASCII graphic key bound to this principal, selected profile, operation, resource, and exact request. After the item payload expires, an exact retry until the accountability retention deadline returns idempotency.expired; a changed request remains idempotency.key-reused. After that deadline the record is forgotten and the key may be reused.",
    IDEMPOTENCY_SCHEMA,
)
SHARED_HOSTED_IDEMPOTENCY = parameter(
    "Idempotency-Key",
    "header",
    "Caller-selected ASCII graphic key bound to this exact mutation. For hosted work, an exact retry after payload expiry and before the accountability retention deadline returns idempotency.expired; a changed request remains idempotency.key-reused. After that deadline the record is forgotten and the key may be reused.",
    IDEMPOTENCY_SCHEMA,
)
ITEM_ID = parameter("item_id", "path", "Casework item UUID.", {"type": "string", "format": "uuid"})
ABSENCE_ID = parameter("absence_id", "path", "Absence UUID.", {"type": "string", "format": "uuid"})
HOLIDAY_ID = parameter("id", "path", "Configured holiday-set identifier.", {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,63}$", "maxLength": 64})
HOLIDAY_REVISION = parameter("revision", "path", "Positive immutable holiday-set revision.", {"type": "integer", "minimum": 1})
TEAM_ID = parameter("team_id", "path", "Directory team identifier.", {"type": "string", "minLength": 1, "maxLength": 128, "x-maximum-utf8-bytes": 128, "pattern": "^[A-Za-z0-9._-]+$"})
EVENT_ID = parameter("event_id", "path", "Hosted terminal event UUID.", {"type": "string", "format": "uuid"})
ATTEMPT_ID = parameter("attempt_id", "path", "Original durable attempt UUID.", {"type": "string", "format": "uuid"})
SOURCE_ID = parameter("source_id", "path", "Configured source identifier.")
EVENT_HEADERS = [
    parameter("ce-specversion", "header", "CloudEvents version; exactly 1.0.", {"type": "string", "const": "1.0"}),
    parameter("ce-id", "header", "Event UUID.", {"type": "string", "format": "uuid"}),
    parameter("ce-source", "header", "Configured exact event source URI.", {"type": "string", "format": "uri", "minLength": 1, "maxLength": 512}),
    parameter("ce-type", "header", "Configured exact request-lifecycle event type.", {"type": "string", "minLength": 1, "maxLength": 512}),
    parameter("ce-time", "header", "Event timestamp.", {"type": "string", "format": "date-time"}),
    parameter("ce-dataschema", "header", "Configured event data schema URI.", {"type": "string", "format": "uri", "minLength": 1, "maxLength": 2048}),
    parameter("x-registry-event-generation", "header", "Activated positive BReg source generation.", {"type": "string", "maxLength": 19, "pattern": "^[1-9][0-9]{0,18}$"}),
    parameter("x-registry-delivery-attempt", "header", "Positive delivery attempt number.", {"type": "string", "maxLength": 19, "pattern": "^[1-9][0-9]{0,18}$"}),
    parameter("x-registry-delivery-time", "header", "Signed delivery timestamp.", {"type": "string", "format": "date-time"}),
    parameter("idempotency-key", "header", "Signed delivery key derived from the exact event, delivery, generation, payload, and destination binding.", {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$", "minLength": 71, "maxLength": 71}),
    parameter("x-registry-signature", "header", "BReg Version 1 HMAC-SHA-256 signature over the exact request.", {"type": "string", "pattern": "^v1=[A-Za-z0-9_-]{43}$", "minLength": 46, "maxLength": 46}),
]
TRACEPARENT = parameter(
    "traceparent",
    "header",
    "Optional W3C trace context continued in the response.",
    required=False,
)


def response(schema_name: str | None = None, description: str = "Success") -> dict:
    result = {
        "description": description,
        "headers": {"traceparent": header_ref("TraceparentHeader")},
    }
    if schema_name:
        result["content"] = {"application/json": {"schema": ref(schema_name)}}
    return result


def problem_component_name(code: str) -> str:
    return "Problem" + "".join(part.title() for part in re.split(r"[.-]", code))


def problem_variant_schema(entry: dict) -> dict:
    status = entry["httpStatuses"][0]
    return {
        "allOf": [
            ref("Problem"),
            {
                "type": "object",
                "properties": {
                    "type": {"const": entry["uri"]},
                    "title": {"const": entry["title"]},
                    "status": {"const": status},
                    "detail": {"const": entry["description"]},
                    "code": {"const": entry["code"]},
                },
            },
        ]
    }


def problem_variant(entry: dict) -> dict:
    return ref(problem_component_name(entry["code"]))


def problem_responses(codes: list[str], catalog: dict[str, dict]) -> dict:
    by_status: dict[int, list[dict]] = {}
    for code in codes:
        entry = catalog[code]
        by_status.setdefault(entry["httpStatuses"][0], []).append(entry)
    result = {}
    for status, entries in sorted(by_status.items()):
        variants = [problem_variant(entry) for entry in entries]
        schema = variants[0] if len(variants) == 1 else {"oneOf": variants}
        value = {
            "description": "Problem response: "
            + ", ".join(entry["code"] for entry in entries),
            "headers": {"traceparent": header_ref("TraceparentHeader")},
            "content": {"application/problem+json": {"schema": schema}},
        }
        if status == 401:
            value["headers"]["WWW-Authenticate"] = {
                "description": "Bearer authentication challenge.",
                "schema": {"const": "Bearer"},
            }
        if status == 503:
            value["headers"]["Retry-After"] = {
                "description": "Seconds before retrying the unavailable dependency.",
                "schema": {"type": "integer", "minimum": 0},
            }
        if status == 409 and any(
            entry["code"] == "work-item.recovery-pending" for entry in entries
        ):
            value["headers"]["Registry-Casework-Attempt"] = {
                "description": "Original attempt UUID, present only when the entitled recovery-pending response can disclose it.",
                "schema": {"type": "string", "format": "uuid"},
                "x-required-for-problem-code": "work-item.recovery-pending",
            }
        result[str(status)] = value
    return result


HOSTED_VALIDATION_OPERATIONS = {
    ("post", "/v1/hosted-items"),
    ("post", "/v1/hosted-items/{item_id}/notes"),
    ("post", "/v1/hosted-items/{item_id}/cancel"),
    ("post", "/v1/work-items/{item_id}/hosted-decisions"),
}
HOSTED_VALIDATION_REASONS = [
    "kind_not_allowed",
    "reference_invalid",
    "object_required",
    "maximum_bytes_exceeded",
    "maximum_depth_exceeded",
    "schema_mismatch",
    "outcome_not_declared",
    "reason_required",
    "text_invalid",
]


def apply_hosted_validation_headers(paths: dict) -> None:
    for method, path in HOSTED_VALIDATION_OPERATIONS:
        response_400 = paths[path][method]["responses"].get("400")
        if response_400 is None:
            raise ValueError(
                f"hosted validation route lacks request.invalid response: {(method, path)}"
            )
        response_400["headers"].update(
            {
                "Registry-Casework-Validation-Path": {
                    "description": "Bounded JSON path for a typed hosted validation failure. Present together with Registry-Casework-Validation-Reason; rejected values are never echoed.",
                    "schema": {"type": "string", "maxLength": 256},
                    "x-present-for-problem-code": "request.invalid",
                },
                "Registry-Casework-Validation-Reason": {
                    "description": "Stable, value-free reason for a typed hosted validation failure. Present together with Registry-Casework-Validation-Path.",
                    "schema": {"type": "string", "enum": HOSTED_VALIDATION_REASONS},
                    "x-present-for-problem-code": "request.invalid",
                },
            }
        )


def operation(summary: str, schema_name: str | None = None, *, source: bool = False, source_required: bool = True, mutation: bool = False, idempotency: bool = False, idempotency_contract: dict | None = None, allow_zero_revision: bool = False, body: str | None = None, parameters: list[dict] | None = None, status: str = "200", description: str | None = None) -> dict:
    params = [TRACEPARENT, CASEWORK_PROFILE]
    if source:
        params.append({**SOURCE_PROFILE, "required": source_required})
    if mutation:
        params.extend(
            [
                IF_MATCH_ALLOW_ZERO if allow_zero_revision else IF_MATCH,
                idempotency_contract or IDEMPOTENCY,
            ]
        )
    elif idempotency:
        params.append(idempotency_contract or IDEMPOTENCY)
    params.extend(parameters or [])
    result = {
        "summary": summary,
        "security": [{"bearerAuth": []}],
        "parameters": params,
        "responses": {status: response(schema_name)},
    }
    if description:
        result["description"] = description
    if body:
        result["requestBody"] = {"required": True, "content": {"application/json": {"schema": ref(body)}}}
    return result


def document(contract: dict) -> dict:
    entries = contract["entries"]
    catalog = {entry["code"]: entry for entry in entries}
    paths = {
        "/health": {"get": {"summary": "Liveness", "security": [], "parameters": [TRACEPARENT], "responses": {"200": response(description="Process is live.")}}},
        "/ready": {"get": {"summary": "Database readiness", "security": [], "parameters": [TRACEPARENT], "responses": {"200": response(description="Ready.")}}},
        "/v1/casework": {"get": operation("Describe the Casework project", "Description", description="Returns the configured queues, BReg sources, authored calendars and clocks, and hosted kinds visible to an authenticated profile. Requester profiles receive empty calendar and clock lists. Description data grants no item or source authority.")},
        "/v1/hosted-items": {"post": operation("Create a requester-owned hosted item", "RequesterHostedItem", idempotency=True, idempotency_contract=HOSTED_IDEMPOTENCY, body="HostedCreateRequest", status="201", description="Requester-only. The selected Requester profile and authenticated issuer-qualified service principal own the item and bound kind grant.")},
        "/v1/hosted-items/terminal": {"get": operation("List this Requester's retained terminal results", "HostedTerminalPage", parameters=[
            parameter("cursor", "query", "Opaque 15-minute cursor bound to the authenticated Requester issuer, subject, profile, and terminal feed. Malformed, unknown, or context-mismatched values are cursor.invalid. On cursor.expired, restart without it and deduplicate by eventId.", required=False),
            parameter("limit", "query", "Page size from 1 through 100; values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False),
        ], description="Requester-only. Results are ordered by terminalAt and eventId and remain available only for the hosted kind's terminal retention period.")},
        "/v1/hosted-items/{item_id}": {"get": operation("Read this Requester's hosted item", "RequesterHostedItem", parameters=[ITEM_ID])},
        "/v1/hosted-items/{item_id}/notes": {
            "get": operation("List this Requester's retained hosted notes", "HostedNotePage", parameters=[ITEM_ID, parameter("cursor", "query", "Opaque 15-minute cursor bound to the Requester principal, profile, item, and notes feed.", required=False), parameter("limit", "query", "Page size from 1 through 100; values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)], description="Requester-only. Notes are ordered by recordedAt and noteId and remain visible only while the hosted item payload is retained."),
            "post": operation("Add a note to this Requester's hosted item", "RequesterHostedItem", mutation=True, idempotency_contract=HOSTED_IDEMPOTENCY, body="HostedNoteRequest", parameters=[ITEM_ID]),
        },
        "/v1/hosted-items/{item_id}/cancel": {"post": operation("Cancel this Requester's active hosted item", "HostedTerminalResult", mutation=True, idempotency_contract=HOSTED_IDEMPOTENCY, body="HostedCancelRequest", parameters=[ITEM_ID])},
        "/v1/hosted-accountability/{event_id}": {"get": operation("Resolve one retained hosted decision actor", "HostedAccountabilityRecord", parameters=[EVENT_ID], description="Supervisor-only protected accountability read. Current team leadership is checked before returning the raw issuer-qualified actor, selected deciding profile, outcome, and staff reason. The read is audited and returns no cancellation record.")},
        "/v1/work-items": {"get": operation("List a caller-authorized inbox view", "WorkItemPage", source=True, source_required=False, parameters=[
            parameter("view", "query", "Required view evaluated before pagination.", {"type": "string", "enum": ["mine", "my_teams", "team_holdings", "overdue", "completed_by_me"]}),
            parameter("queue", "query", "Optional queue identifier.", required=False),
            parameter("cursor", "query", "Opaque cursor bound to this authorized query.", required=False),
            parameter("limit", "query", "Bounded page size; values above 100 are served as 100.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False),
        ], description="With Registry-Source-Profile, reads BReg-backed work under that separate authority. Without it, a human Staff profile reads hosted work for currently served queues in ascending createdAt and itemId order.")},
        "/v1/work-items/next": {"get": operation("Get the next caller-visible item", "WorkItem", source=True, parameters=[parameter("queue", "query", "Optional queue identifier.", required=False), parameter("cursor", "query", "Opaque cursor.", required=False)])},
        "/v1/work-items/{item_id}": {"get": operation("Read one currently visible item", "WorkItem", source=True, source_required=False, parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/clocks": {"get": operation("Read the item's clock occurrences", "ClockOccurrenceList", source=True, parameters=[ITEM_ID], description="Staff or Supervisor read under the same current source visibility as the item. Registry-Source-Profile is required. Returns at most 32 occurrences with pinned policy digest and separate calculation and recompute generations.")},
        "/v1/work-items/{item_id}/claim": {"post": operation("Claim an item", "MutationResponse", source=True, source_required=False, mutation=True, idempotency_contract=SHARED_HOSTED_IDEMPOTENCY, parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/assign": {"post": operation("Assign an item", "MutationResponse", source=True, source_required=False, mutation=True, body="AssignmentRequest", parameters=[ITEM_ID], description="Supervisor-only assignment for a currently served queue. Without Registry-Source-Profile the target is a hosted item; a source-backed item requires the source profile. The assignee is resolved through any active absence cover chain. If no eligible cover is available, the item remains open in its queue with staffingDiagnostic no_cover_available.")},
        "/v1/work-items/{item_id}/delegate": {"post": operation("Delegate a held item", "MutationResponse", source=True, source_required=False, mutation=True, body="DelegateRequest", parameters=[ITEM_ID], description="The current Staff holder delegates an item. Without Registry-Source-Profile the target is a hosted item; a source-backed item requires the source profile. Current item visibility, holder, revision, queue eligibility, and any live source attempt are checked before mutation.")},
        "/v1/work-items/{item_id}/release": {"post": operation("Release an item", "MutationResponse", source=True, source_required=False, mutation=True, idempotency_contract=SHARED_HOSTED_IDEMPOTENCY, parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/draft": {
            "get": operation("Read the current actor's private draft", "DraftResponse", source=True, parameters=[ITEM_ID]),
            "put": operation("Save the current actor's private draft", "DraftResponse", source=True, mutation=True, body="SaveDraftRequest", parameters=[ITEM_ID]),
            "delete": operation("Delete the current actor's private draft", source=True, mutation=True, parameters=[ITEM_ID], status="204"),
        },
        "/v1/work-items/{item_id}/decisions": {"post": operation("Perform a freshly authorized source action", "MutationResponse", source=True, mutation=True, allow_zero_revision=True, body="DecideRequest", parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/hosted-decisions": {"post": operation("Record a declared hosted outcome", "HostedTerminalResult", mutation=True, idempotency_contract=HOSTED_IDEMPOTENCY, body="HostedDecisionRequest", parameters=[ITEM_ID], description="A configured human Staff or Supervisor profile only. Current team service, current holder, selected deciding profile, item revision, and the item's pinned outcome policy are rechecked atomically.")},
        "/v1/work-items/{item_id}/hosted-history": {"get": operation("List retained hosted lifecycle history", "HostedHistoryPage", parameters=[ITEM_ID, parameter("cursor", "query", "Opaque 15-minute cursor bound to the human principal, profile, item, and hosted history feed.", required=False), parameter("limit", "query", "Page size from 1 through 100; values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)], description="Human Staff or Supervisor only. Current deciding-profile and served-queue authority is checked. Results are ordered by occurredAt and eventId and may include requester notes, opaque actor references, outcomes, staff reasons, or cancellation reasons according to the event kind. They never expose requester or raw actor identity.")},
        "/v1/work-items/{item_id}/attempts/recover": {"post": operation("Recover the original attempt selected by idempotency key", "MutationResponse", source=True, body="RecoverAttemptRequest", parameters=[ITEM_ID, IDEMPOTENCY])},
        "/v1/work-items/{item_id}/attempts/{attempt_id}/recover": {"post": operation("Recover this exact original attempt", "MutationResponse", source=True, body="RecoverAttemptRequest", parameters=[ITEM_ID, ATTEMPT_ID])},
        "/v1/work-items/{item_id}/history": {"get": operation("Read bounded item history", "HistoryPage", source=True, parameters=[ITEM_ID])},
        "/v1/holdings": {"get": operation("Read current caller-visible bounded holdings", "HoldingsPage", source=True, parameters=[parameter("cursor", "query", "Opaque cursor.", required=False)])},
        "/v1/directory": {"get": operation("Read the current authorized directory", "DirectoryResponse")},
        "/v1/directory/absences": {
            "get": operation("List authorized absence records", "AbsenceRecordList", description="Staff see their own absences, Supervisors see absences for staff they currently supervise, and Administrators see all absence records. The bounded result contains at most 1000 records ordered by start time and absenceId."),
            "post": operation("Record an absence", "AbsenceRecord", mutation=True, allow_zero_revision=True, body="AbsenceInput", status="201", description="Uses the directory revision in If-Match. Staff can manage their own absence with cover from the same team; Supervisors can manage currently supervised staff; Administrators can manage any directory staff. The period is start-inclusive and end-exclusive."),
        },
        "/v1/directory/absences/{absence_id}": {
            "put": operation("Replace an absence", "AbsenceRecord", mutation=True, body="AbsenceInput", parameters=[ABSENCE_ID], description="Replaces one absence under the current positive directory revision and the same authority and validation rules as creation."),
            "delete": operation("Delete an absence", mutation=True, parameters=[ABSENCE_ID], status="204", description="Deletes one authorized absence under the current positive directory revision."),
        },
        "/v1/directory/bootstrap": {"post": operation("Bootstrap the directory as an Administrator", "DirectoryResponse", mutation=True, allow_zero_revision=True, body="BootstrapDirectoryRequest")},
        "/v1/directory/holidays": {"post": operation("Create an immutable holiday-set revision", "HolidaySetDocument", idempotency=True, body="HolidaySetRevisionInput", status="201", description="Administrator-only. Stores one immutable positive revision with at most 3660 distinct ISO dates. Repeating the exact revision is idempotent; different content for an existing holiday-set revision fails its precondition.")},
        "/v1/directory/holidays/{id}/revisions/{revision}": {"get": operation("Read one holiday-set revision", "HolidaySetDocument", parameters=[HOLIDAY_ID, HOLIDAY_REVISION], description="Administrator-only read of one immutable holiday-set revision.")},
        "/v1/directory/teams/{team_id}": {"put": operation("Create or replace a directory team", "DirectoryResponse", mutation=True, allow_zero_revision=True, body="DirectoryTeamUpdateRequest", parameters=[TEAM_ID], description="Administrator-only. Replaces the named team's staff, supervisors, and served queues under the loaded directory revision. A queue already served by another team returns precondition.failed; remove it from that team before assigning it here. Authority changes take effect immediately. Casework releases newly ineligible held items through bounded maintenance, while unresolved source attempts remain held for a later retry. The response contains directory state and no work-item identifiers.")},
        "/v1/directory/clocks/recompute/preview": {"post": operation("Preview clock recalculation", "ClockRecomputePreview", body="ClockRecomputeRequest", description="Administrator-only. Recalculates at most 100 active occurrences against the named immutable holiday revision. The result is bound to the actor and selected profile for 15 minutes and records each expected calculation generation for review before apply.")},
        "/v1/directory/clocks/recompute/apply": {"post": operation("Apply a reviewed clock recalculation", "ClockRecomputeResult", idempotency=True, body="ClockRecomputeApplyRequest", description="Administrator-only. Applies the actor-bound reviewed preview atomically. An expired preview returns clock.recompute-preview-expired; an already-applied preview or changed calculation generation returns precondition.failed. Create and review a new preview after either response.")},
        "/v1/directory/caseload/preview": {"post": operation("Preview a caller-visible caseload move", "CaseloadPreviewPage", source=True, source_required=False, body="CaseloadMoveRequest", parameters=[parameter("cursor", "query", "Opaque 15-minute cursor bound to the human principal, selected Casework profile, optional source profile, and exact movement. Malformed or context-mismatched values are cursor.invalid; expired values are cursor.expired.", required=False), parameter("limit", "query", "Page size from 1 through 100; values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)], description="Supervisor-only preview for currently served queues. The from and to principals must differ. Candidates are held by movement.from and optionally restricted to queueId. Concealed, denied, or missing candidates are omitted without disclosing their count. Without Registry-Source-Profile only hosted candidates are visible; source-backed candidates require it.")},
        "/v1/directory/caseload/apply": {"post": operation("Apply a reviewed caseload move", "CaseloadItemResultList", source=True, source_required=False, idempotency=True, body="CaseloadApplyRequest", description="Supervisor-only for currently served queues. Applies only the 1 through 100 distinct item selections and expected revisions supplied after preview. There is no global If-Match. Each item is processed atomically and returns moved, not_visible, not_eligible, attempt_in_progress, or conflict; revision is present only for moved. Without Registry-Source-Profile, source-backed selections return not_visible.")},
        "/events/sources/{source_id}": {"post": {
            "summary": "Accept a signed source synchronization hint",
            "description": "Authentication uses the configured BReg webhook signature and timestamp headers. The raw body is bounded to 1 MiB and grants no authority or display content.",
            "security": [{"webhookSignature": []}],
            "x-rust-json-extractor": False,
            "x-maximum-body-bytes": 1_048_576,
            "x-maximum-signed-metadata-bytes": 32_768,
            "parameters": [TRACEPARENT, SOURCE_ID, *EVENT_HEADERS],
            "requestBody": {"required": True, "content": {"application/cloudevents+json": {"schema": {"type": "object"}}, "application/json": {"schema": {"type": "object"}}}},
            "responses": {"202": response(description="Signature accepted; authoritative readback is scheduled.")},
        }},
    }
    paths["/v1/work-items/next"]["get"]["responses"]["204"] = response(
        description="No currently visible item."
    )
    apply_operation_contract(paths, contract, catalog)
    apply_hosted_validation_headers(paths)
    result = {
        "openapi": "3.1.0",
        "info": {"title": "Registry Casework API", "version": "v1alpha1", "description": "Implemented Casework HTTP contract for BReg-backed work and source-free hosted decisions. Casework and source profiles are independent authority selections.", "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"}},
        "servers": [{"url": "https://casework.example.test", "description": "Operator-managed TLS endpoint in front of the private Casework runtime."}],
        "paths": paths,
        "components": {
            "headers": {
                "TraceparentHeader": {
                    "description": "W3C trace context for the request and response.",
                    "schema": {"type": "string"},
                }
            },
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT", "description": "A fresh trusted-issuer token. Staff, Supervisor, and Administrator profiles require the configured human identity assertion. Requester is a service integration profile exempt from that assertion; selecting it never adds human-role or decision authority."},
                "webhookSignature": {"type": "apiKey", "in": "header", "name": "X-Registry-Signature", "description": "HMAC-SHA256 signature over the exact bounded event request."},
            },
            "schemas": schemas(entries),
        },
        "x-registry-casework-framework-problems": contract["frameworkProblems"],
    }
    verify_operation_responses(result, contract, catalog)
    return result


def apply_operation_contract(paths: dict, contract: dict, catalog: dict[str, dict]) -> None:
    documented = {
        (method.upper(), path): operation
        for path, path_item in paths.items()
        for method, operation in path_item.items()
    }
    rust_operations = {
        (operation["method"], operation["path"]): operation
        for operation in contract["operations"]
    }
    if documented.keys() != rust_operations.keys():
        raise ValueError(
            "Rust/OpenAPI operation inventory drifted; "
            f"documented_only={sorted(documented.keys() - rust_operations.keys())}, "
            f"rust_only={sorted(rust_operations.keys() - documented.keys())}"
        )
    framework = set(contract["frameworkProblems"])
    for key, operation in documented.items():
        rust = rust_operations[key]
        operation["operationId"] = OPERATION_IDS[key]
        has_json = operation.pop("x-rust-json-extractor", "requestBody" in operation)
        has_path = any(
            parameter["in"] == "path" for parameter in operation.get("parameters", [])
        )
        has_query = any(
            parameter["in"] == "query" for parameter in operation.get("parameters", [])
        )
        if has_json != rust["acceptsJson"]:
            raise ValueError(f"Rust/OpenAPI JSON-body contract drifted for {key}")
        if has_path != rust["extractsPath"]:
            raise ValueError(f"Rust/OpenAPI path extraction drifted for {key}")
        if has_query != rust["extractsQuery"]:
            raise ValueError(f"Rust/OpenAPI query extraction drifted for {key}")
        documented_successes = {
            int(status) for status in operation["responses"] if int(status) < 400
        }
        rust_successes = set(rust["successStatuses"])
        if documented_successes != rust_successes:
            raise ValueError(
                f"Rust/OpenAPI success status drifted for {key}; "
                f"documented={sorted(documented_successes)}, rust={sorted(rust_successes)}"
            )
        codes = list(rust["problems"])
        codes.extend(
            code
            for code in ("request.method-not-allowed", "request.body-too-large")
            if code in framework and code not in codes
        )
        operation["responses"].update(problem_responses(codes, catalog))


def schema_problem_codes(openapi: dict, schema: dict) -> set[str]:
    variants = schema.get("oneOf", [schema])
    codes = set()
    for variant in variants:
        reference = variant.get("$ref")
        if not reference or not reference.startswith("#/components/schemas/Problem"):
            raise ValueError(f"problem response does not use a closed problem component: {schema}")
        name = reference.rsplit("/", 1)[1]
        component = openapi["components"]["schemas"][name]
        codes.add(component["allOf"][1]["properties"]["code"]["const"])
    return codes


def verify_operation_responses(
    openapi: dict, contract: dict, catalog: dict[str, dict]
) -> None:
    framework = set(contract["frameworkProblems"])
    rust_operations = {
        (operation["method"], operation["path"]): operation
        for operation in contract["operations"]
    }
    for key, rust in rust_operations.items():
        method, path = key
        responses = openapi["paths"][path][method.lower()]["responses"]
        actual_successes = {int(status) for status in responses if int(status) < 400}
        if actual_successes != set(rust["successStatuses"]):
            raise ValueError(f"generated success response drifted for {key}")
        expected_codes = set(rust["problems"])
        expected_codes.update(
            framework & {"request.method-not-allowed", "request.body-too-large"}
        )
        expected_by_status: dict[int, set[str]] = {}
        for code in expected_codes:
            expected_by_status.setdefault(catalog[code]["httpStatuses"][0], set()).add(code)
        actual_by_status = {
            int(status): schema_problem_codes(
                openapi, response["content"]["application/problem+json"]["schema"]
            )
            for status, response in responses.items()
            if int(status) >= 400
        }
        if actual_by_status != expected_by_status:
            raise ValueError(
                f"generated per-operation problem mapping drifted for {key}; "
                f"documented={actual_by_status}, rust={expected_by_status}"
            )


def load_rust_contract(repository_root: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="registry-casework-openapi-") as directory:
        output = Path(directory) / "problem-catalog.json"
        subprocess.run(
            [
                "cargo",
                "run",
                "--locked",
                "--quiet",
                "-p",
                "registry-casework",
                "--example",
                "problem-catalog",
                "--",
                "--output",
                str(output),
            ],
            cwd=repository_root,
            check=True,
        )
        contract = json.loads(output.read_text(encoding="utf-8"))
    required = {"entries", "frameworkProblems", "operations"}
    if set(contract) != required:
        raise ValueError(f"Rust problem catalog fields drifted: {sorted(contract)}")
    codes = [entry["code"] for entry in contract["entries"]]
    if codes != sorted(set(codes)):
        raise ValueError("Rust problem catalog codes are not unique and sorted")
    if any(len(entry["httpStatuses"]) != 1 for entry in contract["entries"]):
        raise ValueError("each Casework problem must have exactly one HTTP status")
    return contract


def camel_case(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part.title() for part in tail)


def rust_struct_fields(source: str, name: str) -> set[str]:
    match = re.search(rf"pub struct {re.escape(name)}(?:<[^>]+>)?\s*\{{(?P<body>.*?)^\}}", source, re.S | re.M)
    if not match:
        raise ValueError(f"Rust DTO is missing: {name}")
    return set(re.findall(r"^\s*pub\s+([a-z_]+)\s*:", match.group("body"), re.M))


def verify_dto_schemas(repository_root: Path, openapi: dict) -> None:
    openapi_schemas = openapi["components"]["schemas"]
    for relative, structs in SCHEMA_STRUCTS.items():
        source = (repository_root / relative).read_text(encoding="utf-8")
        for rust_name, schema_name in structs.items():
            rust_fields = {camel_case(field) for field in rust_struct_fields(source, rust_name)}
            schema_fields = set(openapi_schemas[schema_name]["properties"])
            if rust_fields != schema_fields:
                raise ValueError(
                    f"OpenAPI DTO shape drifted from {rust_name}; "
                    f"documented_only={sorted(schema_fields - rust_fields)}, "
                    f"rust_only={sorted(rust_fields - schema_fields)}"
                )
    page_fields = {"items", "nextCursor", "status"}
    for schema_name in (
        "WorkItemPage",
        "HoldingsPage",
        "HostedTerminalPage",
        "HostedNotePage",
        "HostedHistoryPage",
        "CaseloadPreviewPage",
    ):
        if set(openapi_schemas[schema_name]["properties"]) != page_fields:
            raise ValueError(f"OpenAPI page shape drifted for {schema_name}")
    if set(openapi_schemas["HistoryPage"]["properties"]) != {"items", "status"}:
        raise ValueError("fixed-window HistoryPage must not advertise a cursor")
    hosted_source = (
        repository_root / "crates/registry-casework-core/src/hosted.rs"
    ).read_text(encoding="utf-8")
    if rust_struct_fields(hosted_source, "HostedTerminalResult") != {
        "item_id",
        "event_id",
        "requester_reference",
        "terminal",
        "kind_policy_digest",
        "terminal_at",
    }:
        raise ValueError("OpenAPI hosted terminal common fields drifted from Rust")
    terminal_state = re.search(
        r"pub enum HostedTerminalState\s*\{(?P<body>.*?)^\}",
        hosted_source,
        re.S | re.M,
    )
    if not terminal_state or not all(
        marker in terminal_state.group("body")
        for marker in (
            "Completed {",
            "outcome: String",
            "actor_ref: OpaqueActorRef",
            "Cancelled {",
            "cancellation_reason: String",
        )
    ):
        raise ValueError("OpenAPI hosted terminal variants drifted from Rust")
    for marker in (
        'value.len() == 71',
        'value.starts_with("sha256:")',
        'value.strip_prefix("actor_")',
        "value.len() > 128",
        "pub const MAXIMUM_HOSTED_DISPLAY_BYTES: usize = 16 * 1024;",
        "pub const MAXIMUM_HOSTED_DISPLAY_DEPTH: usize = 16;",
        "pub const MAXIMUM_HOSTED_RETENTION_DAYS: u32 = 3_650;",
    ):
        if marker not in hosted_source:
            raise ValueError(f"OpenAPI hosted bound drifted from Rust: {marker}")
    operation_name = openapi_schemas["OperationName"]
    if operation_name != {
        "type": "string",
        "pattern": "^[a-z][a-z0-9_]{0,63}$",
        "maxLength": 64,
    }:
        raise ValueError("OpenAPI OperationName drifted from its Rust validation contract")
    model = (repository_root / "crates/registry-casework-core/src/model.rs").read_text(
        encoding="utf-8"
    )
    if "pub const MAX_LENGTH: usize = 64;" not in model or (
        '"operation name must match [a-z][a-z0-9_]{0,63}"' not in model
    ):
        raise ValueError("Rust OperationName validation markers drifted")
    assignment = (
        repository_root / "crates/registry-casework-core/src/assignment.rs"
    ).read_text(encoding="utf-8")
    if rust_struct_fields(assignment, "CaseloadPreviewQuery") != {"cursor", "limit"}:
        raise ValueError("OpenAPI caseload preview query drifted from Rust")
    if openapi_schemas["CaseloadApplyRequest"]["properties"]["items"] != {
        "type": "array",
        "minItems": 1,
        "maxItems": 100,
        "uniqueItems": True,
        "x-unique-by": "itemId",
        "items": ref("CaseloadItemSelection"),
    }:
        raise ValueError("OpenAPI reviewed caseload bound drifted from Rust")
    if set(openapi_schemas["CaseloadItemOutcome"]["enum"]) != {
        "moved",
        "not_visible",
        "not_eligible",
        "attempt_in_progress",
        "conflict",
    }:
        raise ValueError("OpenAPI caseload result vocabulary drifted from Rust")
    if set(openapi_schemas["CaseworkProject"]["properties"]) != {
        "apiVersion",
        "kind",
        "casework",
        "accessProfiles",
        "queues",
        "sources",
        "hostedKinds",
        "calendars",
        "clocks",
        "inbox",
    }:
        raise ValueError("OpenAPI authored CaseworkProject shape drifted from Rust")
    if set(openapi_schemas["Description"]["properties"]) != {
        "projectId",
        "policyVersion",
        "queues",
        "sources",
        "calendars",
        "clocks",
        "hostedKinds",
    }:
        raise ValueError("OpenAPI Description policy projection drifted from Rust")
    if {
        variant["$ref"].rsplit("/", 1)[1]
        for variant in openapi_schemas["ClockPolicy"]["oneOf"]
    } != {"SubjectClockPolicy", "ActivityClockPolicy"}:
        raise ValueError("OpenAPI clock policy variants drifted from Rust")


def verify_source(repository_root: Path) -> None:
    http_source = (repository_root / "crates/registry-casework/src/http.rs").read_text(encoding="utf-8")
    core_http = (repository_root / "crates/registry-casework-core/src/http.rs").read_text(encoding="utf-8")
    problem_source = (repository_root / "crates/registry-casework/src/problem.rs").read_text(encoding="utf-8")
    service_source = (repository_root / "crates/registry-casework/src/service.rs").read_text(
        encoding="utf-8"
    )
    client_source = (
        repository_root / "crates/registry-casework-client/src/client.rs"
    ).read_text(encoding="utf-8")
    assignment_source = (
        repository_root / "crates/registry-casework/src/assignment.rs"
    ).read_text(encoding="utf-8")
    policy_source = (
        repository_root / "crates/registry-casework-core/src/policy.rs"
    ).read_text(encoding="utf-8")
    routing_source = (
        repository_root / "crates/registry-casework-core/src/routing.rs"
    ).read_text(encoding="utf-8")
    webhook_crypto_source = (
        repository_root / "crates/registry-platform-crypto/src/breg_webhook.rs"
    ).read_text(encoding="utf-8")
    router_source = http_source.split("async fn http_boundary", 1)[0]
    actual_routes = set(re.findall(r'\.route\(\s*"([^"]+)"', router_source))
    if actual_routes != ROUTES:
        missing = sorted(actual_routes - ROUTES)
        stale = sorted(ROUTES - actual_routes)
        raise ValueError(f"maintained OpenAPI route inventory drifted; undocumented={missing}, unserved={stale}")
    for constant, value in HEADERS.items():
        marker = f'pub const {constant}: &str = \"{value}\";'
        if marker not in core_http:
            raise ValueError(f"maintained OpenAPI header drifted from {constant}")
    for dto in DTO_MARKERS:
        if f"pub struct {dto}" not in core_http and f"pub type {dto}" not in core_http:
            raise ValueError(f"maintained OpenAPI DTO marker is missing: {dto}")
    problem_match = re.search(r"let body = ProblemBody \{(?P<fields>.*?)\n\s*\};", http_source, re.S)
    if not problem_match:
        raise ValueError("problem response construction is missing")
    actual_problem_fields = set(
        re.findall(r"^\s*([a-z_]+)(?::|,)", problem_match.group("fields"), re.M)
    )
    expected_problem_fields = {"type_uri", "title", "status", "detail", "code", "trace_id"}
    if actual_problem_fields != expected_problem_fields:
        raise ValueError(
            f"problem response fields drifted; actual={sorted(actual_problem_fields)}"
        )
    if "pub const OPERATION_CONTRACTS: &[OperationContract]" not in problem_source:
        raise ValueError("Rust-owned operation problem contract is missing")
    if "let desired = limit.clamp(1, 100);" not in service_source:
        raise ValueError("OpenAPI page limit drifted from the Casework service")
    if "const MAXIMUM_PAGE_SIZE: usize = 100;" not in client_source:
        raise ValueError("OpenAPI page limit drifted from the Casework client")
    for marker in (
        "pub const MAXIMUM_DIRECTORY_IDENTIFIER_BYTES: usize = 128;",
        "pub const MAXIMUM_DIRECTORY_PRINCIPALS: usize = 100;",
        "pub const MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES: usize = 2_048;",
        "pub const MAXIMUM_DIRECTORY_SERVED_QUEUES: usize = 100;",
    ):
        if marker not in core_http:
            raise ValueError(f"OpenAPI directory team bound drifted from Rust: {marker}")
    for marker in (
        "const MAXIMUM_REASON_BYTES: usize = 2_000;",
        "request.items.len() > 100",
        "CaseloadItemOutcome::AttemptInProgress",
        "StaffingDiagnostic::NoCoverAvailable",
        "if rows.len() > 1_000",
        "valid_directory_identifier(team_id)",
        "valid_directory_people(&request.staff)",
        "valid_directory_people(&request.supervisors)",
        "request.served_queues.len() > MAXIMUM_DIRECTORY_SERVED_QUEUES",
    ):
        if marker not in assignment_source:
            raise ValueError(f"OpenAPI assignment contract drifted from Rust: {marker}")
    for marker in (
        "pub const MAXIMUM_CLOCKS: usize = 32;",
        "pub const MAXIMUM_CALENDARS: usize = 16;",
        "pub const MAXIMUM_CLOCK_REMINDERS: usize = 8;",
        "pub const MAXIMUM_CLOCK_STEPS: usize = 8;",
        'tag = "scope"',
        "FirstSubmittedAt",
        "ReviewCompleted",
        "AwaitingApplicant",
        "StageEnteredAt",
    ):
        if marker not in policy_source:
            raise ValueError(f"OpenAPI authored clock contract drifted from Rust: {marker}")
    for marker in (
        "pub const MAXIMUM_ROUTING_RULES: usize = 64;",
        "pub const MAXIMUM_ROUTING_PROJECTION_FIELDS: usize = 32;",
        "pub const MAXIMUM_ROUTING_PREDICATES: usize = 16;",
        "pub const MAXIMUM_ROUTING_VALUES: usize = 32;",
        "RoutingPredicate::Equals",
        "RoutingPredicate::OneOf",
    ):
        if marker not in routing_source:
            raise ValueError(f"OpenAPI authored routing contract drifted from Rust: {marker}")
    for marker in (
        "pub const MAXIMUM_CASEWORK_PROFILE_BYTES: usize = 128;",
        "pub const MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES: usize = 128;",
    ):
        if marker not in core_http:
            raise ValueError("OpenAPI bounded header contract drifted from Casework core")
    for source_name, source, markers in (
        (
            "server",
            http_source,
            (
                "value.len() > MAXIMUM_CASEWORK_PROFILE_BYTES",
                "value.len() > MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES",
                "byte.is_ascii_graphic()",
                "byte.is_ascii_alphanumeric()",
                "matches!(byte, b'-' | b'_' | b'.' | b':')",
            ),
        ),
        (
            "client",
            client_source,
            (
                "value.len() > MAXIMUM_CASEWORK_PROFILE_BYTES",
                "idempotency_key.len() > MAXIMUM_CASEWORK_IDEMPOTENCY_KEY_BYTES",
                "byte.is_ascii_graphic()",
                "byte.is_ascii_alphanumeric()",
                "matches!(byte, b'-' | b'_' | b'.' | b':')",
            ),
        ),
    ):
        for marker in markers:
            if marker not in source:
                raise ValueError(
                    f"Casework {source_name} bounded header validation drifted: {marker}"
                )
    for handler, parser in {
        "claim": "if_match",
        "release": "if_match",
        "save_draft": "if_match",
        "delete_draft": "if_match",
        "decide": "if_match_allow_zero",
        "bootstrap": "if_match_allow_zero",
    }.items():
        match = re.search(
            rf"async fn {handler}\(.*?(?=\nasync fn |\n#\[derive)",
            http_source,
            re.S,
        )
        if not match or f"{parser}(&headers)?" not in match.group(0):
            raise ValueError(f"If-Match revision floor drifted for {handler}")
    for marker in (
        "pub const MAX_BODY_BYTES: usize = 1_048_576;",
        "pub const MAX_METADATA_BYTES: usize = 32_768;",
        'const SIGNATURE_PREFIX: &str = "v1=";',
        "if encoded.len() != 43",
    ):
        if marker not in webhook_crypto_source:
            raise ValueError(f"signed event bound drifted: {marker}")
    if "RecoveryPending(Option<Uuid>)" not in http_source or (
        "ServiceError::UncertainAttempt(attempt_id)" not in http_source
    ):
        raise ValueError("recovery-pending no longer binds the original attempt reference")
    if "ATTEMPT_REFERENCE_HEADER" not in http_source:
        raise ValueError("recovery-pending no longer emits the documented attempt header")
    for marker in (
        "VALIDATION_PATH_HEADER",
        "VALIDATION_REASON_HEADER",
        "Self::Validation",
        "HostedValidationReason::KindNotAllowed",
        "HostedValidationReason::TextInvalid",
    ):
        if marker not in http_source:
            raise ValueError(f"hosted field validation response drifted: {marker}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    repository_root = Path(__file__).resolve().parents[3]
    output = repository_root / "products/casework/generated/registry-casework.openapi.json"
    try:
        verify_source(repository_root)
        contract = load_rust_contract(repository_root)
        openapi = document(contract)
        verify_dto_schemas(repository_root, openapi)
        rendered = json.dumps(openapi, indent=2, sort_keys=True) + "\n"
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"OpenAPI source check failed: {error}", file=sys.stderr)
        return 1
    if args.check:
        if not output.exists() or output.read_text(encoding="utf-8") != rendered:
            print(f"{output.relative_to(repository_root)} is stale; regenerate it", file=sys.stderr)
            return 1
        print("Registry Casework OpenAPI is current.")
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(output.relative_to(repository_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
