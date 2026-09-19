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
    "/.well-known/jwks.json",
    "/v1/task-grants/{grant_id}/assertion",
    "/v1/task-grants/{grant_id}/status",
    "/v1/work-items/{item_id}/task-grants",
    "/v1/work-items/{item_id}/task-grants/{grant_id}/revoke",
    "/v1/work-items/{item_id}/task-templates",

    "/health",
    "/ready",
    "/v1/casework",
    "/v1/review-kinds",
    "/v1/review-kinds/{kind_id}",
    "/v1/review-requests",
    "/v1/review-requests/{request_id}",
    "/v1/review-requests/{request_id}/result",
    "/v1/review-requests/{request_id}/cancel",
    "/v1/review-requests/{request_id}/history",
    "/v1/review-requests/{request_id}/clocks",
    "/v1/review-requests/{request_id}/notes",
    "/v1/review-results",
    "/v1/review-tasks",
    "/v1/review-tasks/{task_id}",
    "/v1/review-tasks/{task_id}/context",
    "/v1/review-tasks/{task_id}/claim",
    "/v1/review-tasks/{task_id}/assign",
    "/v1/review-tasks/{task_id}/delegate",
    "/v1/review-tasks/{task_id}/release",
    "/v1/review-tasks/{task_id}/draft",
    "/v1/review-tasks/{task_id}/decisions",
    "/v1/review-tasks/{task_id}/task-templates",
    "/v1/review-tasks/{task_id}/task-grants",
    "/v1/review-tasks/{task_id}/task-grants/{grant_id}/revoke",
    "/v1/review-accountability/{event_id}",
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
    "/v1/work-items/{item_id}/attempts/recover",
    "/v1/work-items/{item_id}/attempts/{attempt_id}/recover",
    "/v1/work-items/{item_id}/history",
    "/v1/holdings",
    "/v1/directory",
    "/v1/directory/targets",
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
    "AbsencesQuery",
    "SaveDraftRequest",
    "DecideRequest",
    "RecoverAttemptRequest",
    "MutationResponse",
    "BootstrapDirectoryRequest",
    "DirectoryTeamUpdateRequest",
    "DirectoryResponse",
    "DirectoryTargetsQuery",
    "DirectoryTargetPage",
    "Description",
    "DraftResponse",
    "ReviewPageQuery",
}
SCHEMA_STRUCTS = {
    "crates/registry-casework-core/src/task_grant.rs": {
        "TaskTemplate": "TaskTemplate",
        "TaskTemplatePreview": "TaskTemplatePreview",
        "TaskTemplatePreviews": "TaskTemplatePreviews",
        "TaskPermission": "TaskPermission",
        "TaskApprovalRequest": "TaskApprovalRequest",
        "TaskGrantView": "TaskGrantView",
        "TaskGrantList": "TaskGrantList",
        "TaskGrantRevocation": "TaskGrantRevocation",
        "TaskAssertionResponse": "TaskAssertionResponse",
        "TaskGrantStatus": "TaskGrantStatus",
        "TaskGrantStatusDetails": "TaskGrantStatusDetails",
    },
    "crates/registry-casework-core/src/model.rs": {
        "IssuerPrincipal": "IssuerPrincipal",
        "DirectoryMember": "DirectoryMember",
        "SourceBinding": "SourceBinding",
        "SubjectRef": "SubjectRef",
        "CaseworkAction": "CaseworkAction",
        "AssignmentContext": "AssignmentContext",
        "WorkItemRouting": "WorkItemRouting",
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
    },
    "crates/registry-casework-core/src/assignment.rs": {
        "AbsenceList": "AbsenceList",
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
        "DisplayReferencePolicy": "DisplayReferencePolicy",
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
}
OPERATION_IDS = {
    ("GET", "/.well-known/jwks.json"): "getTaskAuthorityKeys",
    ("GET", "/v1/work-items/{item_id}/task-templates"): "previewTaskTemplates",
    ("GET", "/v1/work-items/{item_id}/task-grants"): "listTaskGrants",
    ("POST", "/v1/work-items/{item_id}/task-grants"): "approveTaskGrant",
    ("POST", "/v1/work-items/{item_id}/task-grants/{grant_id}/revoke"): "revokeTaskGrant",
    ("POST", "/v1/task-grants/{grant_id}/assertion"): "getTaskAssertion",
    ("GET", "/v1/task-grants/{grant_id}/status"): "getTaskGrantStatus",

    ("POST", "/events/sources/{source_id}"): "acceptSourceEvent",
    ("GET", "/health"): "health",
    ("GET", "/ready"): "readiness",
    ("GET", "/v1/casework"): "describeCasework",
    ("GET", "/v1/review-kinds"): "listReviewKinds",
    ("GET", "/v1/review-kinds/{kind_id}"): "getReviewKind",
    ("POST", "/v1/review-requests"): "createReviewRequest",
    ("GET", "/v1/review-requests/{request_id}"): "getReviewRequest",
    ("GET", "/v1/review-requests/{request_id}/result"): "getReviewResult",
    ("POST", "/v1/review-requests/{request_id}/cancel"): "cancelReviewRequest",
    ("GET", "/v1/review-requests/{request_id}/history"): "getReviewHistory",
    ("GET", "/v1/review-requests/{request_id}/clocks"): "getReviewClocks",
    ("POST", "/v1/review-requests/{request_id}/notes"): "addReviewNote",
    ("GET", "/v1/review-results"): "listReviewResults",
    ("GET", "/v1/review-tasks"): "listReviewTasks",
    ("GET", "/v1/review-tasks/{task_id}"): "getReviewTask",
    ("GET", "/v1/review-tasks/{task_id}/context"): "getReviewTaskContext",
    ("GET", "/v1/review-tasks/{task_id}/task-templates"): "previewReviewTaskTemplates",
    ("GET", "/v1/review-tasks/{task_id}/task-grants"): "listReviewTaskGrants",
    ("POST", "/v1/review-tasks/{task_id}/task-grants"): "approveReviewTaskGrant",
    ("POST", "/v1/review-tasks/{task_id}/task-grants/{grant_id}/revoke"): "revokeReviewTaskGrant",
    ("POST", "/v1/review-tasks/{task_id}/claim"): "claimReviewTask",
    ("POST", "/v1/review-tasks/{task_id}/assign"): "assignReviewTask",
    ("POST", "/v1/review-tasks/{task_id}/delegate"): "delegateReviewTask",
    ("POST", "/v1/review-tasks/{task_id}/release"): "releaseReviewTask",
    ("GET", "/v1/review-tasks/{task_id}/draft"): "getReviewTaskDraft",
    ("PUT", "/v1/review-tasks/{task_id}/draft"): "saveReviewTaskDraft",
    ("DELETE", "/v1/review-tasks/{task_id}/draft"): "deleteReviewTaskDraft",
    ("POST", "/v1/review-tasks/{task_id}/decisions"): "decideReviewTask",
    ("GET", "/v1/review-accountability/{event_id}"): "getReviewAccountability",
    ("GET", "/v1/directory"): "getDirectory",
    ("GET", "/v1/directory/targets"): "listDirectoryTargets",
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


def review_schemas() -> dict:
    text = {"type": "string"}
    uuid = {"type": "string", "format": "uuid"}
    instant = {"type": "string", "format": "date-time"}
    integer = {"type": "integer", "format": "int64"}
    value = {}
    policy_digest = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    result_payload = nullable({"type": "object", "additionalProperties": True})
    outcome = obj(
        {
            "id": text,
            "label": text,
            "settlement": {"type": "string", "enum": ["rejected", "changes_requested", "answered"]},
            "reasonRequired": {"type": "boolean"},
            "resultRequired": {"type": "boolean"},
        },
        ["id", "label", "settlement", "reasonRequired", "resultRequired"],
    )
    stage = obj(
        {
            "id": text,
            "queue": text,
            "decidingProfiles": array(text),
            "requiredApprovals": {"type": "integer", "minimum": 1, "maximum": 32},
            "excludeInitiator": {"type": "boolean"},
            "excludePreviousStageReviewers": {"type": "boolean"},
        },
        ["id", "queue", "decidingProfiles", "requiredApprovals", "excludeInitiator", "excludePreviousStageReviewers"],
    )
    retention = obj(
        {
            "terminalDays": {"type": "integer", "minimum": 1, "maximum": 3650},
            "accountabilityDays": {"type": "integer", "minimum": 1, "maximum": 3650},
        },
        ["terminalDays", "accountabilityDays"],
    )
    policy = obj(
        {"id": text, "version": text, "digest": policy_digest},
        ["id", "version", "digest"],
    )
    subject = obj(
        {"source": text, "subjectType": text, "id": text, "version": text, "digest": policy_digest},
        ["source", "subjectType", "id", "version", "digest"],
    )
    task = obj(
        {
            "taskId": uuid,
            "requestId": uuid,
            "stageIndex": {"type": "integer", "minimum": 0},
            "stageId": text,
            "queue": text,
            "revision": integer,
            "eligibleProfiles": array(text),
            "state": value,
        },
        ["taskId", "requestId", "stageIndex", "stageId", "queue", "revision", "eligibleProfiles", "state"],
    )
    result = {
        "ReviewRetentionPolicy": retention,
        "ReviewOutcomePolicy": outcome,
        "ReviewStagePolicy": stage,
        "ReviewPolicyIdentity": policy,
        "ReviewKindPolicy": obj(
            {"id": text, "version": text, "purpose": {"type": "string", "enum": ["approval", "answer"]}, "contextStrategy": {"type": "string", "enum": ["submitted", "source"]}, "stages": array(stage), "clocks": array(text), "retention": retention, "displaySchema": value, "resultSchema": result_payload, "outcomes": array(outcome)},
            ["id", "version", "purpose", "contextStrategy", "stages", "clocks", "retention", "displaySchema", "outcomes"],
        ),
        "ReviewKindPolicySnapshot": obj(
            {"identity": policy, "purpose": {"type": "string", "enum": ["approval", "answer"]}, "contextStrategy": {"type": "string", "enum": ["submitted", "source"]}, "stages": array(stage), "clocks": array(text), "retention": retention, "displaySchema": value, "resultSchema": result_payload, "outcomes": array(outcome)},
            ["identity", "purpose", "contextStrategy", "stages", "clocks", "retention", "displaySchema", "outcomes"],
        ),
        "ReviewKindPolicySnapshotList": array(ref("ReviewKindPolicySnapshot")),
        "ReviewProducerPolicy": obj(
            {"id": text, "profile": text, "issuer": text, "subject": text, "trustedInitiatorIssuer": nullable(text), "sourceNamespaces": array(text), "kinds": array(text), "recoveryDays": {"type": "integer", "minimum": 1, "maximum": 3650}, "completion": nullable(ref("ReviewCompletionDestinationPolicy"))},
            ["id", "profile", "issuer", "subject", "sourceNamespaces", "kinds", "recoveryDays"],
        ),
        "ReviewCompletionDestinationPolicy": obj({"destinationId": text, "recipientBinding": text}, ["destinationId", "recipientBinding"]),
        "ReviewSubjectBinding": subject,
        "ReviewPolicyBinding": policy,
        "ReviewCreateRequest": obj({"kind": text, "subject": subject, "requesterReference": text, "initiator": nullable(ref("IssuerPrincipal")), "context": value, "resultConstraints": result_payload}, ["kind", "subject", "requesterReference", "context"]),
        "ReviewRequestAccepted": obj({"requestId": uuid, "subject": subject, "policy": policy, "submissionDigest": policy_digest}, ["requestId", "subject", "policy", "submissionDigest"]),
        "ReviewRequestView": obj({"requestId": uuid, "subject": subject, "policy": policy, "submissionDigest": policy_digest, "requesterReference": text, "lifecycle": {"type": "string", "enum": ["reviewing", "approved", "rejected", "changes_requested", "answered", "cancelled", "superseded"]}, "activeStage": nullable(text), "createdAt": instant, "updatedAt": instant}, ["requestId", "subject", "policy", "submissionDigest", "requesterReference", "lifecycle", "createdAt", "updatedAt"]),
        "ReviewResult": obj({"resultId": uuid, "requestId": uuid, "subject": subject, "policy": policy, "submissionDigest": policy_digest, "status": {"type": "string", "enum": ["approved", "rejected", "changes_requested", "answered", "cancelled", "superseded"]}, "outcome": nullable(text), "result": result_payload, "completedAt": instant, "availableUntil": instant}, ["resultId", "requestId", "subject", "policy", "submissionDigest", "status", "completedAt", "availableUntil"]),
        "ReviewResultFeedEntry": obj({"eventId": uuid, "requestId": uuid, "resultId": uuid, "completedAt": instant}, ["eventId", "requestId", "resultId", "completedAt"]),
        "ReviewResultFeedPage": obj({"items": array(ref("ReviewResultFeedEntry")), "nextCursor": nullable(text)}, ["items"]),
        "ReviewCancelRequest": obj({"subject": subject, "reason": text}, ["subject", "reason"]),
        "ReviewCancelResponse": value,
        "ReviewerTask": task,
        "ReviewTaskPage": obj({"items": array(task), "nextCursor": nullable(uuid)}, ["items"]),
        "ReviewTaskContext": obj({"taskId": uuid, "requestId": uuid, "subject": subject, "requesterReference": text, "policy": policy, "resultConstraints": result_payload, "context": value}, ["taskId", "requestId", "subject", "requesterReference", "policy", "context"]),
        "ReviewTaskDraftInput": obj({"body": value}, ["body"]),
        "ReviewTaskDraft": obj({"taskId": uuid, "author": ref("IssuerPrincipal"), "body": value, "revision": integer, "updatedAt": instant}, ["taskId", "author", "body", "revision", "updatedAt"]),
        "ReviewTaskDecisionRequest": value,
        "ReviewHistoryEntry": obj({"eventId": uuid, "requestId": uuid, "taskId": nullable(uuid), "kind": text, "actorRef": nullable(text), "detail": value, "occurredAt": instant}, ["eventId", "requestId", "kind", "detail", "occurredAt"]),
        "ReviewHistoryPage": obj({"items": array(ref("ReviewHistoryEntry")), "nextCursor": nullable(uuid)}, ["items"]),
        "ReviewNoteRequest": obj({"audience": {"type": "string", "enum": ["reviewers", "requester"]}, "note": text}, ["audience", "note"]),
        "ReviewAccountabilityRecord": obj({"eventId": uuid, "requestId": uuid, "taskId": uuid, "actorRef": text, "actor": ref("IssuerPrincipal"), "profileId": text, "decision": text, "privateReason": nullable(text), "resultDigest": nullable(text), "occurredAt": instant, "retainedUntil": instant}, ["eventId", "requestId", "taskId", "actorRef", "actor", "profileId", "decision", "occurredAt", "retainedUntil"]),
        "ReviewClockOccurrence": value,
        "ReviewClockOccurrenceList": array(ref("ReviewClockOccurrence")),
    }
    return result


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
    display = {
        "type": "object",
        "additionalProperties": True,
        "x-maximum-canonical-bytes": 16_384,
        "x-maximum-depth": 16,
    }
    result_payload = {
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
    work_item = obj(
        {
            "itemId": uuid,
            "subject": ref("SubjectRef"),
            "occurrenceKind": {"type": "string", "enum": ["review", "application"]},
            "stage": nullable(text),
            "binding": ref("SourceBinding"),
            "bindingReference": text,
            "displayReference": {
                "type": "string",
                "minLength": 1,
                "maxLength": 512,
                "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$",
                "description": "Human-facing source reference disclosed by the source to the current caller. Present only for source-backed items whose request policy explicitly names a reference field and whose current caller read discloses that field.",
            },
            "state": {"type": "string", "enum": ["open", "claimed", "waiting_applicant", "waiting_application", "synchronizing", "completed", "superseded", "cancelled"]},
            "queueId": text,
            "holder": nullable(ref("IssuerPrincipal")),
            "heldSince": instant,
            "assignment": nullable(ref("AssignmentContext")),
            "revision": integer,
            "firstObservedAt": instant,
            "passiveDueAt": nullable(instant),
            "updatedAt": instant,
            "routing": nullable(ref("WorkItemRouting")),
            "clockOccurrences": {
                "type": "array",
                "items": ref("ClockOccurrenceView"),
            },
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
        "WorkItemRouting": obj(
            {
                "ruleId": nullable(text),
                "because": nullable(text),
                "policyDigest": nullable(policy_digest),
            },
            [],
        ),
        "CorrectionRoutingCopy": obj(
            {"sourceBinding": ref("SourceBinding"), "reason": nullable(text), "flaggedFields": array(text)},
            ["sourceBinding", "flaggedFields"],
        ),
        "WorkItem": work_item,
        "WorkItemPage": obj(
            {
                "items": array(ref("WorkItem")),
                "servedQueues": {
                    "type": "array",
                    "uniqueItems": True,
                    "items": text,
                    "description": "Sorted unique queue identifiers currently served by the authenticated Staff or Supervisor. Present even when items is empty.",
                },
                "nextCursor": nullable(text),
                "status": page_status,
            },
            ["items", "servedQueues", "status"],
        ),
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
        "AbsenceList": obj(
            {
                "directoryRevision": integer,
                "items": {"type": "array", "maxItems": 1000, "items": ref("AbsenceRecord")},
                "nextCursor": nullable(text),
            },
            ["directoryRevision", "items"],
        ),
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
            {"eventId": uuid, "itemId": uuid, "itemRevision": integer, "kind": {"type": "string", "enum": ["observed", "opened", "claimed", "assigned", "delegated", "caseload_moved", "clock_reminder", "clock_step_applied", "clock_recomputed", "released", "draft_saved", "attempt_reserved", "attempt_uncertain", "action_completed", "attempt_settled", "superseded", "completed", "task_approved", "task_revoked", "task_invalidated"]}, "occurredAt": instant, "actor": nullable(ref("IssuerPrincipal")), "profileId": text, "detail": {}},
            ["eventId", "itemId", "itemRevision", "kind", "occurredAt", "profileId", "detail"],
        ),
        "HistoryPage": obj({"items": array(ref("HistoryEntry")), "nextCursor": nullable(text), "status": {"const": "complete"}}, ["items", "status"]),
        "HoldingSummary": obj({"principal": ref("IssuerPrincipal"), "queueId": text, "activeItems": {"type": "integer", "minimum": 0}, "overdueItems": {"type": "integer", "minimum": 0}}, ["principal", "queueId", "activeItems", "overdueItems"]),
        "HoldingsPage": obj({"items": array(ref("HoldingSummary")), "nextCursor": nullable(text), "status": page_status}, ["items", "status"]),
        "DirectoryMember": obj(
            {
                "issuer": {"type": "string", "minLength": 1, "maxLength": 2048, "x-maximum-utf8-bytes": 2048, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"},
                "subject": {"type": "string", "minLength": 1, "maxLength": 2048, "x-maximum-utf8-bytes": 2048, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"},
                "displayName": nullable({"type": "string", "minLength": 1, "maxLength": 500, "x-maximum-utf8-bytes": 500, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"}),
            },
            ["issuer", "subject"],
        ),
        "TeamRecord": obj({"id": text, "members": array(ref("DirectoryMember")), "supervisors": array(ref("DirectoryMember")), "servedQueues": array(text), "revision": integer}, ["id", "members", "supervisors", "servedQueues", "revision"]),
        "DirectoryResponse": obj({"revision": integer, "teams": array(ref("TeamRecord"))}, ["revision", "teams"]),
        "DirectoryTargetPage": obj({"items": array(ref("DirectoryMember")), "nextCursor": nullable(text), "status": page_status}, ["items", "status"]),
        "BootstrapDirectoryRequest": obj({"teamId": text, "staff": array(ref("IssuerPrincipal")), "supervisors": array(ref("IssuerPrincipal")), "queueId": text}, ["teamId", "staff", "supervisors", "queueId"]),
        "DirectoryTeamUpdateRequest": obj(
            {
                "staff": {"type": "array", "maxItems": 100, "uniqueItems": True, "items": ref("DirectoryMember")},
                "supervisors": {"type": "array", "maxItems": 100, "uniqueItems": True, "items": ref("DirectoryMember")},
                "servedQueues": {"type": "array", "maxItems": 100, "uniqueItems": True, "items": {"type": "string", "minLength": 1, "maxLength": 128, "x-maximum-utf8-bytes": 128, "pattern": "^[A-Za-z0-9._-]+$"}},
            },
            ["staff", "supervisors", "servedQueues"],
        ),
        "CaseworkIdentity": obj({"id": text, "version": text}, ["id", "version"]),
        "AccessProfile": obj(
            {
                "id": text,
                "principalClaim": text,
                "requiredScopes": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1, "maxLength": 256, "pattern": r"^[\x21\x23-\x5B\x5D-\x7E]+$"}},
                "role": {
                    "type": "string",
                    "enum": ["staff", "supervisor", "administrator", "requester"],
                },
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
        "ClockNextEffect": {
            "oneOf": [
                obj(
                    {
                        "kind": {"const": "reminder"},
                        "id": text,
                        "at": instant,
                    },
                    ["kind", "id", "at"],
                ),
                obj(
                    {
                        "kind": {"const": "reassign"},
                        "id": text,
                        "at": instant,
                        "because": text,
                        "queueId": text,
                    },
                    ["kind", "id", "at", "because", "queueId"],
                ),
            ]
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
                "nextEffect": nullable(ref("ClockNextEffect")),
                "upcomingEffects": {
                    "type": "array",
                    "maxItems": 2,
                    "items": ref("ClockNextEffect"),
                    "description": "For running or verification-pending clocks, the earliest unapplied reminder and earliest unapplied reassignment, ordered by time, effect kind, and identifier. Omitted when no firing instant can be promised, including while paused. These are pinned authored instants, not scheduler retry times.",
                },
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
                "reviewKinds": array(ref("ReviewKindPolicy")),
                "reviewProducers": array(ref("ReviewProducerPolicy")),
                "calendars": {"type": "array", "maxItems": 16, "uniqueItems": True, "x-unique-by": "id", "items": ref("CalendarPolicy")},
                "clocks": {"type": "array", "maxItems": 32, "uniqueItems": True, "x-unique-by": "id", "items": ref("ClockPolicy")},
                "inbox": ref("InboxPolicy"),
            },
            ["apiVersion", "kind", "casework", "accessProfiles", "queues"],
        ),
        "ElapsedDuration": obj({"elapsed": text}, ["elapsed"]),
        "PassiveTargetPolicy": obj({"id": text, "after": ref("ElapsedDuration")}, ["id", "after"]),
        "DisplayReferencePolicy": obj({"field": authored_identifier}, ["field"]),
        "SourceRequestPolicy": obj(
            {
                "entity": text,
                "queue": text,
                "displayReference": nullable(ref("DisplayReferencePolicy")),
                "projection": {
                    "type": "array",
                    "maxItems": 32,
                    "uniqueItems": True,
                    "items": text,
                },
                "contextProjection": {
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
            {"projectId": text, "policyVersion": text, "queues": array(ref("QueueRecord")), "sources": array(ref("SourcePolicy")), "calendars": array(ref("CalendarPolicy")), "clocks": array(ref("ClockPolicy"))},
            ["projectId", "policyVersion", "queues", "sources", "calendars", "clocks"],
        ),
        "Problem": obj({"type": {"type": "string", "format": "uri"}, "title": text, "status": {"type": "integer"}, "detail": text, "code": {"type": "string", "enum": [entry["code"] for entry in problem_entries]}, "traceId": text}, ["type", "title", "status", "detail", "code", "traceId"]),
    }
    result.update(task_schemas())
    result.update(review_schemas())
    result["CaseworkProject"]["properties"]["taskTemplates"] = {"type":"array", "maxItems":64, "items":ref("TaskTemplate")}
    result.update(
        {
            problem_component_name(entry["code"]): problem_variant_schema(entry)
            for entry in problem_entries
        }
    )
    return result


def task_schemas() -> dict:
    text = {"type":"string", "minLength":1, "maxLength":512}
    number = {"type":"integer", "minimum":0}
    uuid = {"type":"string", "format":"uuid"}
    subjects = {"type":"object", "maxProperties":32, "additionalProperties":{"type":["string","integer","boolean"]}}
    permission = obj({"collection":text, "operations":{"type":"array", "minItems":1, "maxItems":32, "uniqueItems":True, "items":text}}, ["collection","operations"])
    common = {"agent":ref("IssuerPrincipal"), "client":text, "resource":text, "scopes":{"type":"array","minItems":1,"maxItems":32,"uniqueItems":True,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":r"^[\x21\x23-\x29\x2b-\x5b\x5d-\x7e]+$"}}, "purpose":text, "bounds":ref("TaskGrantBounds")}
    evidence_context = obj({"requesterTags":{"type":"array","minItems":1,"maxItems":32,"uniqueItems":True,"items":{"type":"string","minLength":1,"maxLength":128,"pattern":r"^[a-z][a-z0-9._-]*$"}}, "audience":{"type":"string","format":"uri","minLength":1,"maxLength":4096}}, ["requesterTags","audience"])
    preview = {"id":text, "version":text, "label":text, **common, "evidenceContext":ref("EvidenceRequesterContext"), "subjects":subjects, "lifetimeSeconds":{"type":"integer","minimum":1,"maximum":900}}
    template = {**preview, "eligibleTeams":array(text), "eligibleProfiles":array(text), "source":text, "reviewKinds":array(text), "itemKinds":array(text), "itemStates":{"type":"array","items":{"enum":["claimed","waiting_applicant","waiting_application"]}}}
    template["subjects"] = {"type":"object", "minProperties":1, "maxProperties":32, "additionalProperties":text}
    view = {"id":uuid, "templateId":text, "templateVersion":text, **common, "evidenceContext":ref("EvidenceRequesterContext"), "expiresAt":number, "invalidated":{"type":"boolean"}}
    details = {"grantId":uuid, "sourceIssuer":text, "principal":text, "client":text, "resource":text, "purpose":text, "bounds":ref("TaskGrantBounds"), "subjects":subjects, "expiresAt":number}
    return {
        "EvidenceRequesterContext":evidence_context,
        "TaskTemplate":obj(template,[name for name in template if name != "evidenceContext"]),
        "TaskTemplatePreview":obj(preview,[name for name in preview if name != "evidenceContext"]),
        "TaskTemplatePreviews":obj({"itemRevision":number,"templates":array(ref("TaskTemplatePreview"))},["itemRevision","templates"]),
        "TaskPermission":permission,
        "TaskGrantBounds":{"oneOf":[obj({"type":{"const":"evidence"},"requirement":text},["type","requirement"]), obj({"type":{"const":"breg"},"permissions":{"type":"array","minItems":1,"maxItems":64,"items":ref("TaskPermission")}},["type","permissions"])]},
        "TaskApprovalRequest":obj({"templateId":text,"templateVersion":text},["templateId","templateVersion"]),
        "TaskGrantView":obj(view,[name for name in view if name != "evidenceContext"]),
        "TaskGrantList":obj({"grants":{"type":"array","maxItems":128,"items":ref("TaskGrantView")}},["grants"]),
        "TaskGrantRevocation":obj({"id":uuid,"invalidated":{"type":"boolean"}},["id","invalidated"]),
        "TaskAssertionResponse":obj({"assertion":{"type":"string","description":"Sensitive short-lived credential. Do not log or persist."},"expiresAt":number,"grantExpiresAt":number},["assertion","expiresAt","grantExpiresAt"]),
        "TaskGrantStatusDetails":obj(details,list(details)),
        "TaskGrantStatus":obj({"active":{"type":"boolean"},"grant":ref("TaskGrantStatusDetails")},["active"]),
        "TaskAuthorityJwks":obj({"keys":{"type":"array","items":{"type":"object"}}},["keys"]),
    }


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
ITEM_ID = parameter("item_id", "path", "Casework item UUID.", {"type": "string", "format": "uuid"})
TASK_ID = parameter("task_id", "path", "Unified review task UUID.", {"type": "string", "format": "uuid"})
REQUEST_ID = parameter("request_id", "path", "Unified review request UUID.", {"type": "string", "format": "uuid"})
KIND_ID = parameter("kind_id", "path", "Configured unified review kind identifier.")
ABSENCE_ID = parameter("absence_id", "path", "Absence UUID.", {"type": "string", "format": "uuid"})
HOLIDAY_ID = parameter("id", "path", "Configured holiday-set identifier.", {"type": "string", "pattern": "^[a-z][a-z0-9-]{0,63}$", "maxLength": 64})
HOLIDAY_REVISION = parameter("revision", "path", "Positive immutable holiday-set revision.", {"type": "integer", "minimum": 1})
TEAM_ID = parameter("team_id", "path", "Directory team identifier.", {"type": "string", "minLength": 1, "maxLength": 128, "x-maximum-utf8-bytes": 128, "pattern": "^[A-Za-z0-9._-]+$"})
EVENT_ID = parameter("event_id", "path", "Protected accountability event UUID.", {"type": "string", "format": "uuid"})
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


REVIEW_VALIDATION_OPERATIONS = {
    ("post", "/v1/review-requests"),
    ("post", "/v1/review-tasks/{task_id}/decisions"),
}
REVIEW_VALIDATION_REASONS = [
    "kind_not_allowed",
    "reference_invalid",
    "object_required",
    "maximum_bytes_exceeded",
    "maximum_depth_exceeded",
    "schema_mismatch",
    "outcome_not_declared",
    "reason_required",
    "text_invalid",
    "result_not_declared",
    "result_required",
    "field_not_declared",
    "constraint_invalid",
    "constraint_violated",
]
SOURCE_ATTEMPT_REFERENCE_OPERATIONS = {
    ("POST", "/v1/work-items/{item_id}/decisions"),
    ("POST", "/v1/work-items/{item_id}/attempts/recover"),
    ("POST", "/v1/work-items/{item_id}/attempts/{attempt_id}/recover"),
}


def apply_review_validation_headers(paths: dict) -> None:
    for method, path in REVIEW_VALIDATION_OPERATIONS:
        response_400 = paths[path][method]["responses"].get("400")
        if response_400 is None:
            raise ValueError(
                f"review validation route lacks request.invalid response: {(method, path)}"
            )
        response_400["headers"].update(
            {
                "Registry-Casework-Validation-Path": {
                    "description": "Bounded JSON path for a typed review validation failure. Present together with Registry-Casework-Validation-Reason; rejected values are never echoed.",
                    "schema": {"type": "string", "maxLength": 256},
                    "x-present-for-problem-code": "request.invalid",
                },
                "Registry-Casework-Validation-Reason": {
                    "description": "Stable, value-free reason for a typed review validation failure. Present together with Registry-Casework-Validation-Path.",
                    "schema": {"type": "string", "enum": REVIEW_VALIDATION_REASONS},
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
        "/v1/casework": {"get": operation("Describe the Casework project", "Description", description="Returns configured queues, source policies, calendars and clocks visible to the authenticated profile. Review kind policy is read through the dedicated review-kinds endpoints.")},
        "/v1/review-kinds": {"get": operation("List admitted review kind policies", "ReviewKindPolicySnapshotList")},
        "/v1/review-kinds/{kind_id}": {"get": operation("Read one admitted review kind policy", "ReviewKindPolicySnapshot", parameters=[KIND_ID])},
        "/v1/review-requests": {"post": operation("Create or recover a unified review request", "ReviewRequestAccepted", idempotency=True, body="ReviewCreateRequest", status="201")},
        "/v1/review-requests/{request_id}": {"get": operation("Read a requester-owned review request", "ReviewRequestView", parameters=[REQUEST_ID])},
        "/v1/review-requests/{request_id}/result": {"get": operation("Poll a requester-owned review result", "ReviewResult", parameters=[REQUEST_ID], description="Returns 200 with a retained terminal result, 202 while pending, empty 404 for concealed or unknown requests, and 410 after result retention expires.")},
        "/v1/review-requests/{request_id}/cancel": {"post": operation("Cancel a requester-owned active review", "ReviewCancelResponse", idempotency=True, body="ReviewCancelRequest", parameters=[REQUEST_ID])},
        "/v1/review-results": {"get": operation("List requester result-feed events", "ReviewResultFeedPage", parameters=[parameter("cursor", "query", "Last delivered event UUID.", required=False), parameter("limit", "query", "Bounded page size.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)])},
        "/v1/review-tasks": {"get": operation("List current reviewer tasks", "ReviewTaskPage", source=True, source_required=False, parameters=[parameter("queue", "query", "Optional queue filter.", required=False), parameter("cursor", "query", "Last delivered task UUID.", required=False), parameter("limit", "query", "Bounded page size.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)])},
        "/v1/review-tasks/{task_id}": {"get": operation("Read one current reviewer task", "ReviewerTask", source=True, source_required=False, parameters=[TASK_ID])},
        "/v1/review-tasks/{task_id}/context": {"get": operation("Read bounded review task context", "ReviewTaskContext", source=True, source_required=False, parameters=[TASK_ID], description="Submitted context returns the immutable snapshot. Source context requires the current human caller's source profile and token, exact binding, and configured contextProjection; binding changes suppress projected values.")},
        "/v1/review-tasks/{task_id}/claim": {"post": operation("Claim a review task", "ReviewerTask", source=True, source_required=False, mutation=True, parameters=[TASK_ID])},
        "/v1/review-tasks/{task_id}/assign": {"post": operation("Assign a review task", "ReviewerTask", mutation=True, body="AssignmentRequest", parameters=[TASK_ID])},
        "/v1/review-tasks/{task_id}/delegate": {"post": operation("Delegate a held review task", "ReviewerTask", mutation=True, body="DelegateRequest", parameters=[TASK_ID])},
        "/v1/review-tasks/{task_id}/release": {"post": operation("Release a held review task", "ReviewerTask", mutation=True, parameters=[TASK_ID])},
        "/v1/review-tasks/{task_id}/draft": {
            "get": operation("Read the caller's private review draft", "ReviewTaskDraft", parameters=[TASK_ID]),
            "put": operation("Save the caller's private review draft", "ReviewTaskDraft", mutation=True, body="ReviewTaskDraftInput", parameters=[TASK_ID]),
            "delete": operation("Delete the caller's private review draft", mutation=True, parameters=[TASK_ID], status="204"),
        },
        "/v1/review-tasks/{task_id}/decisions": {"post": operation("Record a held review-task decision", mutation=True, body="ReviewTaskDecisionRequest", parameters=[TASK_ID], status="204")},
        "/v1/review-requests/{request_id}/history": {"get": operation("Read audience-filtered review history", "ReviewHistoryPage", parameters=[REQUEST_ID, parameter("cursor", "query", "Last delivered history event UUID.", required=False), parameter("limit", "query", "Bounded page size.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)])},
        "/v1/review-requests/{request_id}/clocks": {"get": operation("Read review clock occurrences", "ReviewClockOccurrenceList", parameters=[REQUEST_ID])},
        "/v1/review-requests/{request_id}/notes": {"post": operation("Add an explicitly audience-bound review note", "ReviewHistoryEntry", idempotency=True, body="ReviewNoteRequest", parameters=[REQUEST_ID])},
        "/v1/review-accountability/{event_id}": {"get": operation("Resolve protected review accountability", "ReviewAccountabilityRecord", parameters=[EVENT_ID])},
        "/v1/review-tasks/{task_id}/task-templates": {"get": operation("Preview task grants for a held review task", "TaskTemplatePreviews", source=True, parameters=[TASK_ID])},
        "/v1/review-tasks/{task_id}/task-grants": {"get": operation("List grants for a held review task", "TaskGrantList", source=True, parameters=[TASK_ID]), "post": operation("Approve a grant for a held review task", "TaskGrantView", source=True, mutation=True, body="TaskApprovalRequest", parameters=[TASK_ID])},
        "/v1/review-tasks/{task_id}/task-grants/{grant_id}/revoke": {"post": operation("Revoke a review-task grant", "TaskGrantRevocation", source=True, mutation=True, parameters=[TASK_ID, parameter("grant_id", "path", "Task grant UUID.", {"type": "string", "format": "uuid"})])},
        "/v1/work-items": {"get": operation("List a caller-authorized inbox view", "WorkItemPage", source=True, source_required=False, parameters=[
            parameter("view", "query", "Required view evaluated before pagination.", {"type": "string", "enum": ["mine", "my_teams", "team_holdings", "overdue", "completed_by_me"]}),
            parameter("sort", "query", "Source-backed ordering. due orders by effective due date with undated items last, then age and item id; age orders oldest first; type orders by source-neutral subject kind, then age and item id. Defaults to due.", {"type": "string", "enum": ["due", "age", "type"], "default": "due"}, required=False),
            parameter("queue", "query", "Optional queue identifier.", required=False),
            parameter("sourceId", "query", "Exact source identifier. For source-backed requests, supply this together with subjectKind and subjectId or omit all three. The component must be nonempty and is carried without normalization.", {"type": "string", "minLength": 1}, required=False),
            parameter("subjectKind", "query", "Exact source-neutral subject kind. Supply together with sourceId and subjectId or omit all three. The component must be nonempty and is carried without normalization.", {"type": "string", "minLength": 1}, required=False),
            parameter("subjectId", "query", "Exact source-neutral subject identifier. Supply together with sourceId and subjectKind or omit all three. The component must be nonempty, is carried without normalization, and is not restricted to UUID syntax.", {"type": "string", "minLength": 1}, required=False),
            parameter("reference", "query", "Exact case-sensitive human reference. Available only for source-backed requests whose source policy explicitly names a displayReference field. Mutually exclusive with the three-part subject selector.", {"type": "string", "minLength": 1, "maxLength": 512, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"}, required=False),
            parameter("cursor", "query", "Opaque cursor bound to this authorized query.", required=False),
            parameter("limit", "query", "Bounded page size; values above 100 are served as 100.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False),
        ], description="Reads source-backed work under the separate current source authority. A complete sourceId, subjectKind, and subjectId selector filters by one exact source-neutral subject. Exact reference lookup returns an item only when the current caller read still discloses the same configured reference. The cursor is bound to the full selector and selected sort; callers follow every page until nextCursor is absent. Unified review tasks are exposed only through /v1/review-tasks.")},
        "/v1/work-items/next": {"get": operation("Get the next caller-visible item", "WorkItemPage", source=True, parameters=[parameter("queue", "query", "Optional queue identifier.", required=False), parameter("cursor", "query", "Opaque cursor bound to the authenticated actor, selected Casework and source profiles, optional queue, the next-item feed, and due ordering.", required=False)], description="Returns a WorkItemPage containing at most one caller-visible item. Empty complete and budget_exhausted pages remain successful responses; follow nextCursor when present. servedQueues is preserved on every page.")},
        "/v1/work-items/{item_id}": {"get": operation("Read one currently visible item", "WorkItem", source=True, source_required=False, parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/clocks": {"get": operation("Read the item's clock occurrences", "ClockOccurrenceList", source=True, parameters=[ITEM_ID], description="Staff or Supervisor read under the same current source visibility as the item. Registry-Source-Profile is required. Returns occurrences ordered by clockId and clockOccurrenceId with pinned policy digest and separate calculation and recompute generations.")},
        "/v1/work-items/{item_id}/claim": {"post": operation("Claim a source work item", "MutationResponse", source=True, mutation=True, parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/assign": {"post": operation("Assign a source work item", "MutationResponse", source=True, mutation=True, body="AssignmentRequest", parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/delegate": {"post": operation("Delegate a held source work item", "MutationResponse", source=True, mutation=True, body="DelegateRequest", parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/release": {"post": operation("Release a source work item", "MutationResponse", source=True, mutation=True, parameters=[ITEM_ID], description="Releases a held source work item after current source visibility, membership, holder, revision, queue authority, and live-attempt checks.")},
        "/v1/work-items/{item_id}/draft": {
            "get": operation("Read the current actor's private draft", "DraftResponse", source=True, parameters=[ITEM_ID]),
            "put": operation("Save the current actor's private draft", "DraftResponse", source=True, mutation=True, body="SaveDraftRequest", parameters=[ITEM_ID]),
            "delete": operation("Delete the current actor's private draft", source=True, mutation=True, parameters=[ITEM_ID], status="204"),
        },
        "/v1/work-items/{item_id}/decisions": {"post": operation("Perform a freshly authorized source action", "MutationResponse", source=True, mutation=True, allow_zero_revision=True, body="DecideRequest", parameters=[ITEM_ID])},
        "/v1/work-items/{item_id}/attempts/recover": {"post": operation("Recover the original attempt selected by idempotency key", "MutationResponse", source=True, body="RecoverAttemptRequest", parameters=[ITEM_ID, IDEMPOTENCY])},
        "/v1/work-items/{item_id}/attempts/{attempt_id}/recover": {"post": operation("Recover this exact original attempt", "MutationResponse", source=True, body="RecoverAttemptRequest", parameters=[ITEM_ID, ATTEMPT_ID])},
        "/v1/work-items/{item_id}/history": {"get": operation("Read paginated item history", "HistoryPage", source=True, parameters=[ITEM_ID, parameter("cursor", "query", "Opaque 15-minute cursor bound to the human principal, selected Casework profile, selected source profile, and item. Malformed, unknown, or context-mismatched values are cursor.invalid. On cursor.expired, restart without it and deduplicate by eventId.", required=False), parameter("limit", "query", "Page size from 1 through 100; values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)], description="Staff or Supervisor only under current source visibility. Results are ordered by occurredAt and eventId.")},
        "/v1/holdings": {"get": operation("Read current caller-visible bounded holdings", "HoldingsPage", source=True, parameters=[parameter("cursor", "query", "Opaque cursor for the next caller-visible holdings page. Follow every page and sum matching principal and queue groups to obtain totals across the caller-visible caseload. When status is source_unavailable, the page contains zero counts and nextCursor retries the failed page.", required=False), parameter("limit", "query", "Page size from 1 through 100; values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)], description="Supervisor-only caller-visible holdings. Counts are grouped by principal and queue within this page; the same group may occur on later pages, so consumers must follow every page and sum matching groups. A source_unavailable page contains zero counts and supplies a cursor that retries the failed page.")},
        "/v1/directory": {"get": operation("Read the current authorized directory", "DirectoryResponse", description="Administrator-only. Returns one consistent snapshot of the directory revision, teams, memberships, and served queues. The serialized JSON response is bounded to 2 MiB.")},
        "/v1/directory/targets": {"get": operation("List current directory targets", "DirectoryTargetPage", parameters=[
            parameter("purpose", "query", "Required target-discovery purpose. assignment requires queue and forbids person fields; absence_person forbids queue and person fields; absence_cover requires both exact personIssuer and personSubject and forbids queue.", {"type": "string", "enum": ["assignment", "absence_person", "absence_cover"]}),
            parameter("queue", "query", "Required nonempty queue identifier for assignment; forbidden for absence purposes.", {"type": "string", "minLength": 1}, required=False),
            parameter("personIssuer", "query", "Exact issuer of the managed absent person. Required together with personSubject for absence_cover and forbidden otherwise.", {"type": "string", "minLength": 1, "maxLength": 2048, "x-maximum-utf8-bytes": 2048, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"}, required=False),
            parameter("personSubject", "query", "Exact subject of the managed absent person. Required together with personIssuer for absence_cover and forbidden otherwise.", {"type": "string", "minLength": 1, "maxLength": 2048, "x-maximum-utf8-bytes": 2048, "pattern": "^[^\\u0000-\\u001F\\u007F-\\u009F]+$"}, required=False),
            parameter("cursor", "query", "Opaque 15-minute cursor bound to the authenticated human principal, selected Casework profile, purpose, queue, and person fields. Malformed, unknown, or context-mismatched values are cursor.invalid. On cursor.expired, restart without it and deduplicate by issuer and subject.", required=False),
            parameter("limit", "query", "Page size from 1 through 100; values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False),
        ], description="Returns only directory members currently eligible for the requested use. Each member carries an issuer-qualified identity and may carry the display name stored on an authorized team membership. assignment is available to Staff currently serving the queue and Supervisors currently supervising it, and lists current Staff serving that queue across teams; Administrators use the existing full directory for assignment discovery. absence_person lists people the caller may currently manage; absence_cover rechecks authority over the exact person and lists valid current covers under the existing absence roles. Requester profiles are refused. Empty eligible sets return a complete page. No source profile is accepted, and teams and absence details are never returned.")},
        "/v1/directory/absences": {
            "get": operation("List authorized absence records", "AbsenceList", parameters=[
                parameter("cursor", "query", "Opaque 15-minute cursor bound to the caller, selected profile, role, page size, and directory revision. On cursor.expired or a changed directory revision (cursor.invalid), restart without the cursor. Authority is checked again on every page.", required=False),
                parameter("limit", "query", "Page size from 1 through 1000; defaults to 1000. Values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 1000, "default": 1000}, required=False),
            ], description="Staff see their own absences, Supervisors see absences for staff they currently supervise, and Administrators see all absence records. The response carries the current global directoryRevision required in If-Match for a following absence write. Its items contain at most 1000 caller-authorized records ordered by start time and absenceId. The serialized page is bounded to 2 MiB and may contain fewer records than limit to fit that bound. Follow nextCursor until it is absent to enumerate every record."),
            "post": operation("Record an absence", "AbsenceRecord", mutation=True, allow_zero_revision=True, body="AbsenceInput", status="201", description="Uses the directory revision in If-Match. Staff can manage their own absence with cover from the same team; Supervisors can manage currently supervised staff; Administrators can manage any directory staff. The period is start-inclusive and end-exclusive."),
        },
        "/v1/directory/absences/{absence_id}": {
            "put": operation("Replace an absence", "AbsenceRecord", mutation=True, body="AbsenceInput", parameters=[ABSENCE_ID], description="Replaces one absence under the current positive directory revision and the same authority and validation rules as creation."),
            "delete": operation("Delete an absence", mutation=True, parameters=[ABSENCE_ID], status="204", description="Deletes one authorized absence under the current positive directory revision."),
        },
        "/v1/directory/bootstrap": {"post": operation("Bootstrap the directory as an Administrator", "DirectoryResponse", mutation=True, allow_zero_revision=True, body="BootstrapDirectoryRequest", description="Administrator-only. The resulting directory JSON must fit the 2 MiB aggregate limit; a larger directory returns request.invalid before any change commits.")},
        "/v1/directory/holidays": {"post": operation("Create an immutable holiday-set revision", "HolidaySetDocument", idempotency=True, body="HolidaySetRevisionInput", status="201", description="Administrator-only. Stores one immutable positive revision with at most 3660 distinct ISO dates. Repeating the exact revision is idempotent; different content for an existing holiday-set revision fails its precondition.")},
        "/v1/directory/holidays/{id}/revisions/{revision}": {"get": operation("Read one holiday-set revision", "HolidaySetDocument", parameters=[HOLIDAY_ID, HOLIDAY_REVISION], description="Administrator-only read of one immutable holiday-set revision.")},
        "/v1/directory/teams/{team_id}": {"put": operation("Create or replace a directory team", "DirectoryResponse", mutation=True, allow_zero_revision=True, body="DirectoryTeamUpdateRequest", parameters=[TEAM_ID], description="Administrator-only. Replaces the named team's staff, supervisors, and served queues under the loaded directory revision. A queue already served by another team returns precondition.failed; remove it from that team before assigning it here. Authority changes take effect immediately. Casework releases newly ineligible held items through bounded maintenance, while unresolved source attempts remain held for a later retry. The response contains directory state and no work-item identifiers. The resulting directory JSON must fit the 2 MiB aggregate limit; a larger directory returns request.invalid before any change commits.")},
        "/v1/directory/clocks/recompute/preview": {"post": operation("Preview clock recalculation", "ClockRecomputePreview", body="ClockRecomputeRequest", description="Administrator-only. Recalculates at most 100 active occurrences against the named immutable holiday revision. The result is bound to the actor and selected profile for 15 minutes and records each expected calculation generation for review before apply.")},
        "/v1/directory/clocks/recompute/apply": {"post": operation("Apply a reviewed clock recalculation", "ClockRecomputeResult", idempotency=True, body="ClockRecomputeApplyRequest", description="Administrator-only. Applies the actor-bound reviewed preview atomically. An expired preview returns clock.recompute-preview-expired; an already-applied preview or changed calculation generation returns precondition.failed. Create and review a new preview after either response.")},
        "/v1/directory/caseload/preview": {"post": operation("Preview a caller-visible caseload move", "CaseloadPreviewPage", source=True, body="CaseloadMoveRequest", parameters=[parameter("cursor", "query", "Opaque 15-minute cursor bound to the human principal, selected Casework and source profiles, and exact movement. Malformed or context-mismatched values are cursor.invalid; expired values are cursor.expired.", required=False), parameter("limit", "query", "Page size from 1 through 100; values outside that range are request.invalid.", {"type": "integer", "minimum": 1, "maximum": 100}, required=False)])},
        "/v1/directory/caseload/apply": {"post": operation("Apply a reviewed caseload move", "CaseloadItemResultList", source=True, idempotency=True, body="CaseloadApplyRequest", description="Each item is processed atomically under current source visibility and returns its own bounded outcome.")},
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
    paths["/v1/review-requests"]["post"]["responses"]["200"] = response(
        "ReviewRequestAccepted", "Recovered the exact existing request binding."
    )
    paths["/v1/review-requests/{request_id}/result"]["get"]["responses"].update(
        {
            "202": response(description="The review is still pending."),
            "410": response(description="The retained result has expired."),
        }
    )
    paths["/v1/review-tasks/{task_id}/draft"]["get"]["responses"]["404"] = response(
        description="No private draft exists for this caller."
    )
    paths["/v1/work-items/next"]["get"]["responses"]["200"]["content"]["application/json"]["schema"] = {
        "allOf": [
            ref("WorkItemPage"),
            {"type": "object", "properties": {"items": {"maxItems": 1}}},
        ]
    }
    grant_id = parameter("grant_id", "path", "Immutable task grant identifier.", {"type":"string","format":"uuid"})
    paths.update({
        "/.well-known/jwks.json":{"get":{"summary":"Task authority public verification keys", "security":[], "parameters":[TRACEPARENT], "responses":{"200":response("TaskAuthorityJwks")}}},
        "/v1/work-items/{item_id}/task-templates":{"get":operation("Preview eligible task authorization", "TaskTemplatePreviews", source=True, parameters=[ITEM_ID], description="Current holder and Directory eligibility are checked. Subjects come from the caller's current disclosed source read. Preview grants no authority; approval recomputes it.")},
        "/v1/work-items/{item_id}/task-grants":{"get":operation("List task grant metadata", "TaskGrantList", source=True, parameters=[ITEM_ID], description="Metadata includes immutable bounds, deadline, and recorded invalidation. It contains no stored selectors and does not establish current usability."), "post":operation("Approve an immutable task grant", "TaskGrantView", source=True, mutation=True, body="TaskApprovalRequest", parameters=[ITEM_ID], description="Only a configured template id and version are accepted. Current holder, team, profile, source disclosure and proposal are rechecked. Reusing the same idempotency key returns the original grant without extending its deadline; changed bounds conflict.")},
        "/v1/work-items/{item_id}/task-grants/{grant_id}/revoke":{"post":operation("Revoke a task grant", "TaskGrantRevocation", source=True, parameters=[ITEM_ID,grant_id])},
        "/v1/task-grants/{grant_id}/assertion":{"post":operation("Issue a short-lived task assertion", "TaskAssertionResponse", parameters=[grant_id], description="Requires a bootstrap agent token with casework:grants:assert, exact single Casework audience, and the registered agent principal/client. Profile headers and grant-bearing tokens are refused. Fresh eligibility and source checks precede issuance; assertion lifetime is at most 60 seconds and never exceeds the original grant deadline.")},
        "/v1/task-grants/{grant_id}/status":{"get":operation("Check current resource-bound task authority", "TaskGrantStatus", parameters=[grant_id], description="Requires a service token with casework:grants:status and the registered client for the grant resource. Returns fresh status after Directory and source checks. Consumers must compare every bound and enforce expiresAt. An unavailable check grants no authority.")},
    })
    for path in ["/v1/task-grants/{grant_id}/assertion", "/v1/task-grants/{grant_id}/status"]:
        for operation_value in paths[path].values():
            operation_value["parameters"] = [p for p in operation_value["parameters"] if p.get("name", "").lower() != "registry-casework-profile"]
    apply_operation_contract(paths, contract, catalog)
    paths["/v1/review-requests/{request_id}/result"]["get"]["responses"]["410"] = response(
        description="The retained result has expired."
    )
    paths["/v1/review-tasks/{task_id}/draft"]["get"]["responses"]["404"] = response(
        description="No private draft exists for this caller."
    )
    apply_review_validation_headers(paths)
    result = {
        "openapi": "3.1.0",
        "info": {"title": "Registry Casework API", "version": "v1alpha1", "description": "Implemented Casework HTTP contract for source work and unified reviews. Casework and source profiles are independent authority selections.", "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"}},
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
        documented_successes = {int(status) for status in operation["responses"]}
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
        if key in SOURCE_ATTEMPT_REFERENCE_OPERATIONS:
            response_503 = operation["responses"].get("503")
            if (
                response_503 is None
                or "work-item.source-unavailable" not in codes
            ):
                raise ValueError(
                    f"source attempt reference lacks source-unavailable response for {key}"
                )
            response_503["headers"]["Registry-Casework-Attempt"] = {
                "description": "Durable attempt UUID when this source mutation was stored but its post-write authoritative read was unavailable.",
                "schema": {"type": "string", "format": "uuid"},
                "x-present-for-problem-code": "work-item.source-unavailable",
            }


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
        expected_successes = set(rust["successStatuses"])
        actual_successes = {
            int(status) for status in responses if int(status) in expected_successes
        }
        if actual_successes != expected_successes:
            raise ValueError(f"generated success response drifted for {key}")
        expected_codes = set(rust["problems"])
        expected_codes.update(
            framework & {"request.method-not-allowed", "request.body-too-large"}
        )
        expected_by_status: dict[int, set[str]] = {}
        for code in expected_codes:
            status = catalog[code]["httpStatuses"][0]
            if status not in expected_successes:
                expected_by_status.setdefault(status, set()).add(code)
        actual_by_status = {
            int(status): schema_problem_codes(
                openapi, response["content"]["application/problem+json"]["schema"]
            )
            for status, response in responses.items()
            if int(status) >= 400 and int(status) not in expected_successes
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


def rust_snake_case_unit_enum_values(source: str, name: str) -> list[str]:
    match = re.search(
        rf'#\[serde\(rename_all = "snake_case"\)\]\s*pub enum {re.escape(name)}\s*\{{(?P<body>.*?)^\}}',
        source,
        re.S | re.M,
    )
    if not match:
        raise ValueError(f"Rust snake_case enum is missing: {name}")
    variants = re.findall(r"^\s*([A-Z][A-Za-z0-9]*)\s*,\s*$", match.group("body"), re.M)
    return [re.sub(r"(?<!^)(?=[A-Z])", "_", variant).lower() for variant in variants]


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
    if set(openapi_schemas["WorkItemPage"]["properties"]) != page_fields | {
        "servedQueues"
    }:
        raise ValueError("OpenAPI page shape drifted for WorkItemPage")
    for schema_name in (
        "HoldingsPage",
        "CaseloadPreviewPage",
        "DirectoryTargetPage",
    ):
        if set(openapi_schemas[schema_name]["properties"]) != page_fields:
            raise ValueError(f"OpenAPI page shape drifted for {schema_name}")
    if set(openapi_schemas["HistoryPage"]["properties"]) != page_fields:
        raise ValueError("OpenAPI page shape drifted for HistoryPage")
    model_source = (
        repository_root / "crates/registry-casework-core/src/model.rs"
    ).read_text(encoding="utf-8")
    if set(openapi_schemas["HistoryEntry"]["properties"]["kind"]["enum"]) != set(
        rust_snake_case_unit_enum_values(model_source, "HistoryKind")
    ):
        raise ValueError("OpenAPI HistoryKind values drifted from Rust")
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
        "reviewKinds",
        "reviewProducers",
        "calendars",
        "clocks",
        "inbox",
        "taskTemplates",
    }:
        raise ValueError("OpenAPI authored CaseworkProject shape drifted from Rust")
    if set(openapi_schemas["Description"]["properties"]) != {
        "projectId",
        "policyVersion",
        "queues",
        "sources",
        "calendars",
        "clocks",
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
    clock_runtime_source = (
        repository_root / "crates/registry-casework-core/src/clock_runtime.rs"
    ).read_text(encoding="utf-8")
    webhook_crypto_source = (
        repository_root / "crates/registry-platform-crypto/src/delivery_signature.rs"
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
    for marker in (
        "pub enum ClockNextEffect",
        "Reminder {",
        "Reassign {",
        '#[serde(rename = "queueId")]\n        queue_id: String',
    ):
        if marker not in clock_runtime_source:
            raise ValueError(f"OpenAPI clock next-effect contract drifted: {marker}")
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
        "(1..=1_000).contains(&limit)",
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
        "ReviewValidationReason::KindNotAllowed",
        "ReviewValidationReason::TextInvalid",
    ):
        if marker not in http_source:
            raise ValueError(f"review field validation response drifted: {marker}")


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
