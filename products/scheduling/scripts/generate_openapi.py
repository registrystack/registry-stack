#!/usr/bin/env python3
"""Generate the deterministic Registry Scheduling OpenAPI contract.

The document is hand-shaped here and then verified against the Rust truth
beside it, so neither side can drift alone. The verification follows the
Casework generator's discipline:

* the route inventory, and each operation's handler, authority profile, JSON
  body, idempotency key, path and query parameters, and success status, are
  read back out of `crates/registry-scheduling/src/http.rs`;
* the problem vocabulary, and each code's pinned type URI, title, detail, and
  HTTP status, are read from the `problem-catalog` example's output, never
  copied here;
* every wire document is verified field by field against the Rust struct it
  projects, snake_case to camelCase.

One contract is not Rust-owned yet: the per-operation problem mappings. The
`problem-catalog` example emits `entries` only, with no Casework-style
`operations` table, so the mappings are hand-shaped from the handler-by-handler
reading of the service and store flows and are verified in every way the
available truth allows (`verify_operation_problems`): every code must exist in
the exported catalog, its status in the document must be the code's pinned one,
each documented code must be produced somewhere in the runtime, and every code
an operation can answer with by rule must be present. Extending the exporter
with an operations contract is the follow-up that closes the remaining gap.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HTTP_SOURCE = "crates/registry-scheduling/src/http.rs"
SERVICE_SOURCE = "crates/registry-scheduling/src/service.rs"
STORE_SOURCE = "crates/registry-scheduling/src/store.rs"
CURSORS_SOURCE = "crates/registry-scheduling/src/cursors.rs"
AUTH_SOURCE = "crates/registry-scheduling/src/auth.rs"
CONFIG_SOURCE = "crates/registry-scheduling/src/config.rs"
NAMING_SOURCE = "crates/registry-scheduling-core/src/naming.rs"
WIRE_SOURCE = "crates/registry-scheduling-core/src/wire.rs"
MODEL_SOURCE = "crates/registry-scheduling-core/src/model.rs"
ADMISSION_SOURCE = "crates/registry-scheduling-core/src/admission.rs"
PROBLEM_SOURCE = "crates/registry-scheduling-core/src/problem.rs"
HTTPSEC_SOURCE = "crates/registry-platform-httpsec/src/server.rs"

# The committed document `--write` produces and `--check` verifies.
OUTPUT = "products/scheduling/generated/registry-scheduling.openapi.json"

# The routes the router answers, as literal paths. `verify_source` re-derives
# this set from the `axum` router, resolving the constants the router names
# through `crates/registry-scheduling-core/src/naming.rs`.
ROUTES = {
    "/healthz",
    "/readyz",
    "/v1/scheduling",
    "/v1/services",
    "/v1/offerings",
    "/v1/resources",
    "/v1/locations",
    "/v1/availability",
    "/v1/availability/explain",
    "/v1/holds",
    "/v1/holds/{hold_id}",
    "/v1/appointments",
    "/v1/appointments/{appointment_id}",
    "/v1/appointments/{appointment_id}/reschedule",
    "/v1/appointments/{appointment_id}/cancel",
    "/v1/appointments/{appointment_id}/history",
}

# The header name a mutating command carries, as `naming.rs` pins it.
HEADERS = {
    "IDEMPOTENCY_KEY_HEADER": "idempotency-key",
}

# The `request.*` family: the request-edge rejections the edge itself answers,
# on any route, under this product's own prefix. No documented operation
# answers `request.not-found`; it is the fallback for a route no operation
# claims.
EDGE_PROBLEMS = [
    "request.body-too-large",
    "request.invalid",
    "request.method-not-allowed",
    "request.not-found",
    "request.unprocessable",
    "request.unsupported-media-type",
]

# Vocabulary entries the runtime never reaches: there is no hook engine yet,
# no eligibility source yet, and the four refusals `precondition.failed` once
# carried are each answered by the code that names them.
UNPRODUCED_PROBLEMS = [
    "eligibility.unavailable",
    "hook.unavailable",
    "precondition.failed",
]
# `resource.unavailable` is produced, but only as the detailed code inside the
# explain document, so it is never a public problem either.
DETAILED_ONLY_PROBLEMS = ["resource.unavailable"]
# Vocabulary entries no documented operation answers.
RESERVED_PROBLEMS = UNPRODUCED_PROBLEMS + DETAILED_ONLY_PROBLEMS

# The wire documents, verified field by field against the Rust structs.
SCHEMA_STRUCTS = {
    WIRE_SOURCE: {
        "SchedulingServiceDocument": "SchedulingServiceDocument",
        "ServiceDocument": "ServiceDocument",
        "OfferingDocument": "OfferingDocument",
        "ReminderDocument": "ReminderDocument",
        "WindowDocument": "WindowDocument",
        "ResourceDocument": "ResourceDocument",
        "LocationDocument": "LocationDocument",
        "HoldDocument": "HoldDocument",
        "AppointmentDocument": "AppointmentDocument",
        "CreateAppointmentRequest": "CreateAppointmentRequest",
        "RescheduleAppointmentRequest": "RescheduleAppointmentRequest",
        "CancelAppointmentRequest": "CancelAppointmentRequest",
        "AppointmentHistoryEntryDocument": "AppointmentHistoryEntryDocument",
        "ExplainDocument": "ExplainDocument",
    },
    MODEL_SOURCE: {
        "AdmissionRequest": "AdmissionRequest",
        "PartyCounts": "PartyCounts",
    },
}

# The axum handler behind each operation. `verify_handler_wiring` reads the
# handler back out of http.rs and checks the document against what it does.
ROUTE_HANDLERS = {
    ("GET", "/healthz"): "healthz",
    ("GET", "/readyz"): "readyz",
    ("GET", "/v1/scheduling"): "scheduling",
    ("GET", "/v1/services"): "list_services",
    ("GET", "/v1/offerings"): "list_offerings",
    ("GET", "/v1/resources"): "list_resources",
    ("GET", "/v1/locations"): "list_locations",
    ("GET", "/v1/availability"): "availability",
    ("GET", "/v1/availability/explain"): "explain",
    ("POST", "/v1/holds"): "create_hold",
    ("DELETE", "/v1/holds/{hold_id}"): "release_hold",
    ("POST", "/v1/appointments"): "create_appointment",
    ("GET", "/v1/appointments/{appointment_id}"): "get_appointment",
    ("POST", "/v1/appointments/{appointment_id}/reschedule"): "reschedule_appointment",
    ("POST", "/v1/appointments/{appointment_id}/cancel"): "cancel_appointment",
    ("GET", "/v1/appointments/{appointment_id}/history"): "appointment_history",
}

OPERATION_IDS = {
    ("GET", "/healthz"): "getLiveness",
    ("GET", "/readyz"): "getReadiness",
    ("GET", "/v1/scheduling"): "describeScheduling",
    ("GET", "/v1/services"): "listServices",
    ("GET", "/v1/offerings"): "listOfferings",
    ("GET", "/v1/resources"): "listResources",
    ("GET", "/v1/locations"): "listLocations",
    ("GET", "/v1/availability"): "searchAvailability",
    ("GET", "/v1/availability/explain"): "explainAvailability",
    ("POST", "/v1/holds"): "createHold",
    ("DELETE", "/v1/holds/{hold_id}"): "releaseHold",
    ("POST", "/v1/appointments"): "createAppointment",
    ("GET", "/v1/appointments/{appointment_id}"): "getAppointment",
    ("POST", "/v1/appointments/{appointment_id}/reschedule"): "rescheduleAppointment",
    ("POST", "/v1/appointments/{appointment_id}/cancel"): "cancelAppointment",
    ("GET", "/v1/appointments/{appointment_id}/history"): "listAppointmentHistory",
}

# The per-operation problem mappings, hand-shaped from the handler-by-handler
# reading of the flows the handlers delegate to. Status is a property of the
# code, so each list below is grouped onto its pinned statuses by the catalog,
# never by hand.
#
# Every operation: the edge answers 405 for a foreign method and 413 for a body
# over the router's limit. Every authenticated operation: a missing, invalid,
# or expired bearer is authentication.refused, and a credential that does not
# carry the route's authority is profile.not-authorized. Every authenticated
# operation can also answer service.unavailable, whether or not its service
# method opens a store round trip: verifying the bearer needs the issuer's key
# material, and an issuer that cannot be reached is an outage on this side,
# answered with Retry-After rather than a challenge the caller cannot satisfy.
EDGE = ["request.body-too-large", "request.method-not-allowed"]
AUTHENTICATION = ["authentication.refused", "profile.not-authorized"]
JSON_BODY = [
    "request.invalid",
    "request.unprocessable",
    "request.unsupported-media-type",
]
QUERY = ["request.invalid"]
# A path segment naming a hold or an appointment is read into an identifier
# before the handler runs, so a segment that is not one is refused at the edge.
PATH = ["request.invalid"]
CURSOR = ["cursor.expired", "cursor.invalid"]
STORAGE = ["service.unavailable"]
AUTHORITY = ["operation.not-authorized"]
IDEMPOTENCY = ["idempotency.expired", "idempotency.key-reused"]
# An operation that resolves a caller-named offering against the deployed
# policy answers for one the policy does not publish. The offering listing is
# where a caller learns what exists, so naming the absence discloses nothing
# that listing would not.
OFFERING = ["request.not-found"]
# The refusal vocabulary the admission evaluator answers a booking ask with.
ADMISSION = [
    "booking.duplicate-active",
    "capacity.exhausted",
    "capability.unmatched",
    "horizon.outside",
    "location.closed",
    "party.capacity-inadequate",
    "policy.changed",
    "precondition.required",
    "prerequisite.missing",
    "revision.mismatch",
    "schedule.unpublished",
]

OPERATION_PROBLEMS = {
    ("GET", "/healthz"): EDGE,
    ("GET", "/readyz"): EDGE + STORAGE,
    ("GET", "/v1/scheduling"): EDGE + AUTHENTICATION + STORAGE,
    ("GET", "/v1/services"): EDGE + AUTHENTICATION + QUERY + CURSOR + STORAGE,
    ("GET", "/v1/offerings"): EDGE + AUTHENTICATION + QUERY + CURSOR + STORAGE,
    ("GET", "/v1/resources"): EDGE + AUTHENTICATION + QUERY + CURSOR + STORAGE,
    ("GET", "/v1/locations"): EDGE + AUTHENTICATION + QUERY + CURSOR + STORAGE,
    ("GET", "/v1/availability"): EDGE + AUTHENTICATION + QUERY + CURSOR + STORAGE + OFFERING,
    ("GET", "/v1/availability/explain"): EDGE + AUTHENTICATION + QUERY + STORAGE + OFFERING,
    ("POST", "/v1/holds"): EDGE + AUTHENTICATION + JSON_BODY + ADMISSION + IDEMPOTENCY + AUTHORITY
    + OFFERING + ["service.unavailable"],
    # A release carries no caller-chosen key, so `idempotency.key-reused` is
    # not reachable: the key and the request hash are both the hold's own id.
    ("DELETE", "/v1/holds/{hold_id}"): EDGE + AUTHENTICATION + PATH + AUTHORITY
    + ["hold.released", "idempotency.expired", "service.unavailable"],
    ("POST", "/v1/appointments"): EDGE + AUTHENTICATION + JSON_BODY + ADMISSION + IDEMPOTENCY + AUTHORITY
    + OFFERING + ["hold.expired", "hold.released", "service.unavailable"],
    ("GET", "/v1/appointments/{appointment_id}"): EDGE + AUTHENTICATION + PATH + AUTHORITY + STORAGE,
    # A reschedule resolves its offering from the appointment rather than from
    # the caller, so an unknown offering is operator state, not a refusal the
    # caller can read.
    ("POST", "/v1/appointments/{appointment_id}/reschedule"): EDGE + AUTHENTICATION + PATH + JSON_BODY
    + ADMISSION + IDEMPOTENCY + AUTHORITY + ["hold.released", "service.unavailable"],
    # Cancellation is guarded by the observed revision and the cutoff, never by
    # the policy revision, so it answers no admission refusal at all.
    ("POST", "/v1/appointments/{appointment_id}/cancel"): EDGE + AUTHENTICATION + PATH + JSON_BODY
    + IDEMPOTENCY + AUTHORITY
    + ["cancellation.cutoff-passed", "hold.released", "revision.mismatch", "service.unavailable"],
    ("GET", "/v1/appointments/{appointment_id}/history"): EDGE + AUTHENTICATION + PATH + AUTHORITY + QUERY
    + CURSOR + STORAGE,
}


def ref(name: str) -> dict:
    return {"$ref": f"#/components/schemas/{name}"}


def header_ref(name: str) -> dict:
    return {"$ref": f"#/components/headers/{name}"}


def obj(properties: dict, required: list[str] | None = None) -> dict:
    """A document the caller sends: closed, as the Rust request type reads it.

    A member the contract does not declare is either a caller mistake or a
    reach for a field the store owns, so the runtime answers it rather than
    passing it over.
    """
    result = {"type": "object", "additionalProperties": False, "properties": properties}
    if required:
        result["required"] = required
    return result


def answer(properties: dict, required: list[str] | None = None) -> dict:
    """A document the runtime sends: open, as the Rust answer type reads it.

    A client generated from this contract may be older than the deployment
    answering it. Closing an answer would make every additive change on the
    server a failed exchange for every client built before that change.
    """
    result = obj(properties, required)
    result["additionalProperties"] = True
    return result


def array(items: dict) -> dict:
    return {"type": "array", "items": items}


def nullable(schema: dict) -> dict:
    return {"anyOf": [schema, {"type": "null"}]}


IDEMPOTENCY_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
    "pattern": "^[!-~]+$",
}
CURSOR_SCHEMA = {"type": "string", "maxLength": 256}
LIMIT_SCHEMA = {"type": "integer", "minimum": 1, "maximum": 200, "default": 50}
INSTANT_SCHEMA = {"type": "string", "format": "date-time"}
UUID_SCHEMA = {"type": "string", "format": "uuid"}
# The router's request body limit, as `registry-platform-httpsec` pins it.
MAXIMUM_BODY_BYTES = 1_048_576


def parameter(name: str, where: str, description: str, schema: dict | None = None, required: bool = True) -> dict:
    return {"name": name, "in": where, "required": required, "description": description, "schema": schema or {"type": "string"}}


TRACEPARENT = parameter(
    "traceparent",
    "header",
    "Optional W3C trace context continued in the response.",
    required=False,
)
IDEMPOTENCY = parameter(
    "Idempotency-Key",
    "header",
    "Caller-selected ASCII graphic key bound to this exact request. An exact retry replays the first answer, a changed request is idempotency.key-reused, and a receipt retained past its window is idempotency.expired.",
    IDEMPOTENCY_SCHEMA,
)
HOLD_ID = parameter("hold_id", "path", "The hold's identifier.", UUID_SCHEMA)
APPOINTMENT_ID = parameter("appointment_id", "path", "The appointment's identifier.", UUID_SCHEMA)
CURSOR_QUERY = parameter(
    "cursor",
    "query",
    "Opaque 15-minute cursor bound to this listing. A malformed, unknown, or foreign cursor is cursor.invalid; an expired one is cursor.expired, and the listing restarts from its first page. Deduplicate entries by id.",
    CURSOR_SCHEMA,
    required=False,
)
LIMIT_QUERY = parameter(
    "limit",
    "query",
    "Page size from 1 through 200; the default is 50 and larger values are served as 200.",
    LIMIT_SCHEMA,
    required=False,
)
OFFERING_QUERY = parameter(
    "offering",
    "query",
    "Required offering identifier. An offering the deployed policy does not publish is request.not-found.",
    {"type": "string", "minLength": 1},
)


def response(schema_name: str | None = None, description: str = "Success") -> dict:
    result = {
        "description": description,
        "headers": {
            "cache-control": header_ref("CacheControlHeader"),
            "traceparent": header_ref("TraceparentHeader"),
        },
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
    # An operation can reach one refusal down more than one path, and the
    # groups above name every path it has. A code the operation answers is
    # documented once however many groups carry it.
    for code in dict.fromkeys(codes):
        entry = catalog[code]
        by_status.setdefault(entry["httpStatuses"][0], []).append(entry)
    result = {}
    for status, entries in sorted(by_status.items()):
        variants = [problem_variant(entry) for entry in entries]
        schema = variants[0] if len(variants) == 1 else {"oneOf": variants}
        value = {
            "description": "Problem response: "
            + ", ".join(entry["code"] for entry in entries),
            "headers": {
                "cache-control": header_ref("CacheControlHeader"),
                "traceparent": header_ref("TraceparentHeader"),
            },
            "content": {"application/problem+json": {"schema": schema}},
        }
        if status == 401:
            value["headers"]["WWW-Authenticate"] = {
                "description": "Bearer authentication challenge.",
                "schema": {"const": "Bearer"},
            }
        if status == 503:
            value["headers"]["Retry-After"] = {
                "description": "Seconds before retrying the unavailable dependency; the runtime answers 5.",
                "schema": {"type": "integer", "minimum": 0},
            }
        result[str(status)] = value
    return result


def operation(
    summary: str,
    schema_name: str | None = None,
    *,
    authority: str = "reads-scope",
    body: str | None = None,
    parameters: list[dict] | None = None,
    status: str = "200",
    description: str | None = None,
    idempotency: bool = False,
) -> dict:
    """One authenticated operation, in the shape the edge actually answers."""
    params = [TRACEPARENT]
    if idempotency:
        params.append(IDEMPOTENCY)
    params.extend(parameters or [])
    result = {
        "summary": summary,
        "security": [{"bearerAuth": []}],
        "x-scheduling-authority": authority,
        "parameters": params,
        "responses": {status: response(schema_name)},
    }
    if description:
        result["description"] = description
    if body:
        result["requestBody"] = {
            "required": True,
            "content": {"application/json": {"schema": ref(body)}},
        }
        result["x-maximum-body-bytes"] = MAXIMUM_BODY_BYTES
    return result


def unauthenticated(summary: str, description: str, schema_name: str | None = None) -> dict:
    return {
        "summary": summary,
        "description": description,
        "security": [],
        "x-scheduling-authority": "unauthenticated",
        "parameters": [TRACEPARENT],
        "responses": {"200": response(schema_name)},
    }


def page(item_schema_name: str) -> dict:
    """`PageDocument<T>` with its item type named; the wire type is generic."""
    return answer(
        {"items": array(ref(item_schema_name)), "nextCursor": nullable({"type": "string"})},
        ["items", "nextCursor"],
    )


def schemas(problem_entries: list[dict]) -> dict:
    text = {"type": "string"}
    # u32 quantities and u64 revision counters, as the wire types pin them.
    count = {"type": "integer", "minimum": 0}
    revision = {"type": "integer", "format": "int64", "minimum": 0}
    instant = INSTANT_SCHEMA
    mode = {"type": "string", "enum": ["exact-time", "arrival-window"]}
    appointment_state = {"type": "string", "enum": ["confirmed", "cancelled"]}
    party = obj({"recipients": count, "attendees": count}, ["recipients", "attendees"])
    admission = obj(
        {
            "offering": text,
            "start": instant,
            "party": ref("PartyCounts"),
            "channel": nullable(text),
            "duplicateKey": nullable(text),
            "policyRevision": revision,
            "windowRevision": nullable(revision),
            "capabilities": array(text),
            "prerequisites": array(text),
        },
        ["offering", "start", "party", "policyRevision", "capabilities", "prerequisites"],
    )
    result = {
        "SchedulingServiceDocument": answer(
            {"schedulingId": text, "policyRevision": revision, "policyDigest": text},
            ["schedulingId", "policyRevision", "policyDigest"],
        ),
        "ServiceDocument": answer({"id": text, "label": text}, ["id", "label"]),
        "ServicePage": page("ServiceDocument"),
        "ReminderDocument": answer({"minutesBefore": count}, ["minutesBefore"]),
        "WindowDocument": answer(
            {"id": text, "revision": revision, "start": instant, "end": instant, "units": count},
            ["id", "revision", "start", "end", "units"],
        ),
        "OfferingDocument": answer(
            {
                "id": text,
                "service": text,
                "label": text,
                "mode": mode,
                "location": text,
                "leadTimeMinutes": count,
                "horizonDays": count,
                "cancellationCutoffMinutes": count,
                "durationMinutes": nullable(count),
                "bufferBeforeMinutes": nullable(count),
                "bufferAfterMinutes": nullable(count),
                "startIncrementMinutes": nullable(count),
                "maxRecipients": nullable(count),
                "window": nullable(ref("WindowDocument")),
                "reminders": array(ref("ReminderDocument")),
                "requiresCapabilities": array(text),
                "prerequisites": array(text),
            },
            [
                "id",
                "service",
                "label",
                "mode",
                "location",
                "leadTimeMinutes",
                "horizonDays",
                "cancellationCutoffMinutes",
                "reminders",
                "requiresCapabilities",
                "prerequisites",
            ],
        ),
        "OfferingPage": page("OfferingDocument"),
        "ResourceDocument": answer(
            {
                "resourceId": text,
                "pool": text,
                "capabilities": array(text),
                "available": {"type": "boolean"},
            },
            ["resourceId", "pool", "capabilities", "available"],
        ),
        "ResourcePage": page("ResourceDocument"),
        "LocationDocument": answer({"locationId": text, "timezone": text}, ["locationId", "timezone"]),
        "LocationPage": page("LocationDocument"),
        "AvailabilitySlot": answer(
            {"kind": {"const": "slot"}, "start": instant, "end": instant, "free": count},
            ["kind", "start", "end", "free"],
        ),
        "AvailabilityWindow": answer(
            {
                "kind": {"const": "window"},
                "window": text,
                "start": instant,
                "end": instant,
                "remaining": count,
                "channelRemaining": nullable(count),
            },
            ["kind", "window", "start", "end", "remaining"],
        ),
        "AvailabilityEntry": {
            "oneOf": [ref("AvailabilitySlot"), ref("AvailabilityWindow")],
            "discriminator": {"propertyName": "kind"},
        },
        "AvailabilityPage": page("AvailabilityEntry"),
        "HoldDocument": answer(
            {
                "holdId": text,
                "offering": text,
                "start": instant,
                "end": instant,
                "resource": nullable(text),
                "units": count,
                "expiresAt": instant,
                "policyRevision": revision,
            },
            ["holdId", "offering", "start", "end", "units", "expiresAt", "policyRevision"],
        ),
        "PartyCounts": party,
        "AdmissionRequest": admission,
        "CreateAppointmentRequest": {
            "type": "object",
            "additionalProperties": False,
            "minProperties": 1,
            "properties": {"hold": nullable(text), "admission": nullable(ref("AdmissionRequest"))},
            "description": "Exactly one of hold or admission: confirming a held allocation, or a direct create. Both, or neither, is request.invalid.",
        },
        "RescheduleAppointmentRequest": obj(
            {"observedRevision": revision, "admission": ref("AdmissionRequest")},
            ["observedRevision", "admission"],
        ),
        "CancelAppointmentRequest": obj(
            {"observedRevision": revision, "reason": nullable(text)},
            ["observedRevision"],
        ),
        "AppointmentState": appointment_state,
        "AppointmentDocument": answer(
            {
                "appointmentId": text,
                "offering": text,
                "start": instant,
                "end": instant,
                "resource": nullable(text),
                "units": count,
                "channel": nullable(text),
                "revision": revision,
                "state": ref("AppointmentState"),
                "policyRevision": revision,
                "createdAt": instant,
                "cancelledAt": nullable(instant),
            },
            [
                "appointmentId",
                "offering",
                "start",
                "end",
                "units",
                "revision",
                "state",
                "policyRevision",
                "createdAt",
            ],
        ),
        "AppointmentHistoryEntryDocument": answer(
            {
                "eventId": text,
                "kind": {
                    "type": "string",
                    "description": "The lifecycle step the store recorded: held, confirmed, consumed, released, rescheduled, or cancelled.",
                },
                "revision": revision,
                "occurredAt": instant,
                "actor": nullable(text),
                "detail": {},
            },
            ["eventId", "kind", "revision", "occurredAt", "detail"],
        ),
        "AppointmentHistoryPage": page("AppointmentHistoryEntryDocument"),
        "ExplainDocument": answer(
            {
                "offering": text,
                "start": instant,
                "publicCode": text,
                "detailedCode": text,
                "explanation": text,
            },
            ["offering", "start"],
        ),
        "Problem": obj(
            {
                "type": {"type": "string", "format": "uri"},
                "title": text,
                "status": {"type": "integer"},
                "detail": text,
                "code": {"type": "string", "enum": [entry["code"] for entry in problem_entries]},
                "traceId": text,
            },
            ["type", "title", "status", "detail", "code", "traceId"],
        ),
    }
    result.update(
        {
            problem_component_name(entry["code"]): problem_variant_schema(entry)
            for entry in problem_entries
        }
    )
    return result


def document(contract: dict) -> dict:
    entries = contract["entries"]
    catalog = catalog_of(contract)
    paths = {
        "/healthz": {"get": unauthenticated(
            "Liveness",
            "Process is live. No authentication, no storage, no policy.",
        )},
        "/readyz": {"get": unauthenticated(
            "Readiness",
            "Asks the Scheduling store to answer. A store that cannot answer is service.unavailable, with Retry-After.",
        )},
        "/v1/scheduling": {"get": operation(
            "Describe this Scheduling deployment",
            "SchedulingServiceDocument",
            description="Answers the deployment identifier, the current authored policy revision, and its digest, so a caller can detect that the policy it read has since moved. Reading it grants no catalogue, availability, or booking authority.",
        )},
        "/v1/services": {"get": operation(
            "List the service catalogue",
            "ServicePage",
            parameters=[CURSOR_QUERY, LIMIT_QUERY],
            description="Sorted by identifier. A page is a 15-minute view of a live catalogue; follow nextCursor until it is absent.",
        )},
        "/v1/offerings": {"get": operation(
            "List the published offering catalogue",
            "OfferingPage",
            parameters=[CURSOR_QUERY, LIMIT_QUERY],
            description="The public view of the authored policy, sorted by identifier. Exact-time offerings carry durationMinutes, bufferBeforeMinutes, bufferAfterMinutes, startIncrementMinutes, and maxRecipients; arrival-window offerings carry window. A field the offering's mode does not use is null, never zero.",
        )},
        "/v1/resources": {"get": operation(
            "List the backing resource pool members",
            "ResourcePage",
            parameters=[CURSOR_QUERY, LIMIT_QUERY],
            description="A pool is its concrete members, never an independent counter. available carries no reason: why a member is unavailable is private staff information, and the public answer to a caller is capacity.exhausted.",
        )},
        "/v1/locations": {"get": operation(
            "List the locations",
            "LocationPage",
            parameters=[CURSOR_QUERY, LIMIT_QUERY],
            description="Each location carries the IANA timezone its published openings expand in.",
        )},
        "/v1/availability": {"get": operation(
            "Search published availability",
            "AvailabilityPage",
            parameters=[
                OFFERING_QUERY,
                parameter(
                    "start",
                    "query",
                    "Earliest answerable start, defaulting to now.",
                    INSTANT_SCHEMA,
                    required=False,
                ),
                parameter(
                    "end",
                    "query",
                    "Latest answerable start. An end earlier than one minute after start is raised to it, and one further ahead than the 62-day span allows is clipped to it.",
                    INSTANT_SCHEMA,
                    required=False,
                ),
                parameter(
                    "cursor",
                    "query",
                    "Opaque 15-minute cursor bound to this offering, its range, and the instant the last page ended at. A malformed, unknown, or foreign cursor is cursor.invalid; an expired one is cursor.expired. Deduplicate entries by their start.",
                    CURSOR_SCHEMA,
                    required=False,
                ),
                LIMIT_QUERY,
            ],
            description="Bounded availability. Exact-time offerings answer in grid slots and arrival-window offerings answer in published windows; only entries with capacity left are listed, so a slot nobody can serve is not availability. A search spans at most 62 days from start, and a wider ask continues by cursor.",
        )},
        "/v1/availability/explain": {"get": operation(
            "Explain one start's refusal",
            "ExplainDocument",
            authority="explain-scope",
            parameters=[
                OFFERING_QUERY,
                parameter("start", "query", "The start to explain.", INSTANT_SCHEMA),
            ],
            description="The separately authorized explanation of one start: the problem code every caller may see, the detailed code only this path discloses, and the refusal in words. A start that admits as things stand answers with no codes at all. The probe is a minimal party, so the answer explains the calendar and the capacity, never another caller's booking. resource.unavailable is disclosed here and never on the public path, whose answer is capacity.exhausted.",
        )},
        "/v1/holds": {"post": operation(
            "Reserve an admission",
            "HoldDocument",
            authority="task-grant",
            status="201",
            body="AdmissionRequest",
            idempotency=True,
            description="Reserves supply instead of committing it and answers the hold with its expiry. The caller must carry a complete task grant whose scheduling permission names the offering's service, its location, and hold.create; readable availability is not authority to book. The hold expires on its own, so its capacity returns without a release.",
        )},
        "/v1/holds/{hold_id}": {"delete": operation(
            "Release a hold",
            authority="task-grant",
            status="204",
            parameters=[HOLD_ID],
            description="Gives a hold's capacity back before it expires, under the task grant that names hold.release. The hold's own identifier is the idempotency key, so a retried release answers as the first one did; a receipt retained past its window is idempotency.expired. A claim that is not an active hold is hold.released, whether unknown, already confirmed, or already released, and a grant naming another holder is operation.not-authorized.",
        )},
        "/v1/appointments": {"post": operation(
            "Confirm a hold or book directly",
            "AppointmentDocument",
            authority="task-grant",
            status="201",
            body="CreateAppointmentRequest",
            idempotency=True,
            description="Carries exactly one of hold or admission. Confirming transfers the hold's own reservation, so capacity is re-checked only for identity: the hold must still be active and unexpired, its policy revision still current, and its holder still the caller. A direct create is evaluated against the live ledger like a hold, and commits instead of reserving. Both branches demand a complete task grant naming the offering's service, location, and appointment.create.",
        )},
        "/v1/appointments/{appointment_id}": {"get": operation(
            "Read one owned appointment",
            "AppointmentDocument",
            parameters=[APPOINTMENT_ID],
            description="Answers only to the caller that owns the booking. Another caller's appointment, a hold, and an unknown identifier are all operation.not-authorized, so existence is never disclosed.",
        )},
        "/v1/appointments/{appointment_id}/reschedule": {"post": operation(
            "Move an owned appointment",
            "AppointmentDocument",
            authority="task-grant",
            body="RescheduleAppointmentRequest",
            idempotency=True,
            parameters=[APPOINTMENT_ID],
            description="Re-books the appointment under the task grant that names appointment.reschedule, with a fresh admission evaluation; the appointment it replaces is excluded from the conflict checks, so a reschedule never competes with itself. The policy guard wins over the revision guard: a caller whose observed revision is also stale learns the policy moved first.",
        )},
        "/v1/appointments/{appointment_id}/cancel": {"post": operation(
            "Cancel an owned appointment",
            "AppointmentDocument",
            authority="task-grant",
            body="CancelAppointmentRequest",
            idempotency=True,
            parameters=[APPOINTMENT_ID],
            description="Releases the appointment's capacity and records the reason, under the task grant that names appointment.cancel. It is guarded by observedRevision and the offering's cancellation cutoff, never by the policy revision, so an appointment is always cancellable under the policy that currently governs its offering.",
        )},
        "/v1/appointments/{appointment_id}/history": {"get": operation(
            "Read an owned appointment's history",
            "AppointmentHistoryPage",
            parameters=[APPOINTMENT_ID, CURSOR_QUERY, LIMIT_QUERY],
            description="Newest first, one bounded page at a time. Each step carries the revision it produced, the pseudonymized actor reference when it had one, and the detail the store recorded. Existence is never disclosed: another caller's appointment answers operation.not-authorized.",
        )},
    }
    for key, codes in OPERATION_PROBLEMS.items():
        method, path = key
        paths[path][method.lower()]["responses"].update(problem_responses(codes, catalog))
        paths[path][method.lower()]["operationId"] = OPERATION_IDS[key]
    result = {
        "openapi": "3.1.0",
        "info": {
            "title": "Registry Scheduling API",
            "version": "v1alpha1",
            "description": "Implemented Scheduling HTTP contract: published openings, exact-time offerings over interchangeable resource pools, published arrival windows with channel subquotas, holds, and accountable bookings. Mutating authority is a complete task grant; every refusal is one problem from the closed vocabulary.",
            "license": {"name": "Apache-2.0", "identifier": "Apache-2.0"},
        },
        "servers": [{
            "url": "https://scheduling.example.test",
            "description": "Operator-managed TLS endpoint in front of the private Scheduling runtime.",
        }],
        "paths": paths,
        "components": {
            "headers": {
                "CacheControlHeader": {
                    "description": "Every answer is marked no-store, so a booking view is never served from a cache.",
                    "schema": {"const": "no-store"},
                },
                "TraceparentHeader": {
                    "description": "W3C trace context for the request and response.",
                    "schema": {"type": "string"},
                },
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                    "description": "A fresh access token from the configured issuer, for this deployment's audience, signed by a key the issuer published. Catalogue, availability, and owned-record reads demand the configured reads scope (scheduling-read by default); the explain path demands the configured explain scope (scheduling-explain by default), which is never the reads scope. A mutating route demands no scope at all: its authority is the complete task grant the token carries, whose scheduling permissions the service checks against the offering's service and location and the action the route performs (hold.create, hold.release, appointment.create, appointment.reschedule, appointment.cancel). A token with partial grant claims is refused rather than half-trusted.",
                },
            },
            "schemas": schemas(entries),
        },
        "x-registry-scheduling-edge-problems": EDGE_PROBLEMS,
        "x-registry-scheduling-reserved-problems": RESERVED_PROBLEMS,
    }
    return result


# --- Rust truth -------------------------------------------------------------
#
# Every verification below reads the Rust sources, or the problem catalog the
# `problem-catalog` example emits, and compares it with the hand-shaped
# document. Nothing here trusts the document's own words.


def rust_function(source: str, name: str) -> tuple[str, str]:
    """One Rust function or method, split into its signature and its body."""
    match = re.search(
        rf"(?:pub )?(?:async )?fn {re.escape(name)}\((?P<parameters>[^)]*)\)(?P<rest>.*?)(?=\n(?:pub )?(?:async )?fn |\n#\[|\Z)",
        source,
        re.S,
    )
    if not match:
        raise ValueError(f"Rust function is missing: {name}")
    text = match.group(0)
    signature, body = text.split("{", 1)
    return signature, body


def route_inventory(http_source: str, naming_source: str) -> dict[tuple[str, str], str]:
    """The (method, path) -> handler table, read back out of the axum router."""
    signature, body = rust_function(http_source, "router")
    constants: dict[str, str] = {}
    for source in (naming_source, http_source):
        constants.update(
            {
                name: value
                for name, value in re.findall(
                    r'(?:pub )?const ([A-Z_][A-Z0-9_]*): &str = "([^"]*)";', source
                )
            }
        )
    inventory: dict[tuple[str, str], str] = {}
    for expression, method, handler in re.findall(
        r'\.route\(\s*("[^"]+"|[A-Z_][A-Z0-9_]*),\s*(get|post|put|delete)\(([a-z_][a-z0-9_]*)\)\)',
        body,
    ):
        path = expression[1:-1] if expression.startswith('"') else constants[expression]
        inventory[(method.upper(), path)] = handler
    return inventory


def query_struct(http_source: str, name: str) -> dict[str, tuple[bool, str]]:
    """One axum `Query` struct's fields as (required, type family) triples."""
    match = re.search(rf"struct {re.escape(name)}\s*\{{(?P<body>.*?)^\}}", http_source, re.S | re.M)
    if not match:
        raise ValueError(f"Rust query struct is missing: {name}")
    fields: dict[str, tuple[bool, str]] = {}
    for field_name, field_type in re.findall(
        r"(?:#\[serde\([^\)]*\)\]\s*)?\n\s*([a-z_]+):\s*([^,\n]+),", match.group("body")
    ):
        optional = re.match(r"^Option<(.+)>$", field_type)
        base = optional.group(1) if optional else field_type
        family = "date-time" if base.startswith("DateTime<") else (
            "integer" if base in ("usize", "u32", "u64") else "string"
        )
        fields[camel_case(field_name)] = (not bool(optional), family)
    return fields


def handler_wiring(
    http_source: str,
    service_source: str,
    inventory: dict[tuple[str, str], str],
    variants: dict[str, str],
) -> dict[tuple[str, str], dict]:
    """What each handler does, as the router and its own body state it."""
    wiring = {}
    for key, handler in inventory.items():
        signature, body = rust_function(http_source, handler)
        # The extractors sit between the signature's first paren and its last,
        # so a multi-line parameter list is read whole.
        parameters = signature[signature.index("(") + 1 : signature.rindex(")")]
        json_body = re.search(r"Json\(\w+\):\s*Json<([A-Za-z0-9_]+)>", parameters)
        query = re.search(r"Query\(\w+\):\s*Query<([A-Za-z0-9_]+)>", parameters)
        path_parameters = re.findall(r"Path\((\w+)\):\s*Path<([A-Za-z0-9_:]+)>", parameters)
        authority = "unauthenticated"
        for function, value in (
            ("authenticate_read", "reads-scope"),
            ("authenticate_explain", "explain-scope"),
            ("authenticate_mutate", "task-grant"),
        ):
            if f"{function}(&state" in body:
                authority = value
        service = re.search(r"state\.service\.([a-z_]+)\(", body)
        method_name = service.group(1) if service else None
        # A handler with no service call behind it (the infrastructure routes)
        # answers nothing the service could refuse.
        infallible = (
            "-> Result<" not in rust_function(service_source, method_name)[0]
            if method_name
            else None
        )
        wiring[key] = {
            "handler": handler,
            "authority": authority,
            "body": json_body.group(1) if json_body else None,
            "query": query.group(1) if query else None,
            "path_parameters": path_parameters,
            "idempotency_key": "idempotency_key(&headers)?" in body,
            "service_method": method_name,
            "service_infallible": infallible,
            "success_status": (
                204
                if "StatusCode::NO_CONTENT" in body
                else 201
                if "StatusCode::CREATED" in body
                else 200
            ),
            "problem_codes": [problem_code(variants, name, key) for name in re.findall(r"ProblemCode::([A-Z][A-Za-z0-9]*)", body)],
        }
    return wiring


def problem_code(variants: dict[str, str], name: str, key: tuple[str, str]) -> str:
    """One handler-named variant, or a visible failure if it is not a code."""
    if name not in variants:
        raise ValueError(f"{key} names {name}, which is no problem in the vocabulary")
    return variants[name]


def verify_handler_wiring(
    repository_root: Path, paths: dict, variants: dict[str, str]
) -> None:
    """Check every operation against what its handler actually does."""
    http_source = production_source(repository_root, HTTP_SOURCE)
    service_source = production_source(repository_root, SERVICE_SOURCE)
    naming_source = production_source(repository_root, NAMING_SOURCE)
    inventory = route_inventory(http_source, naming_source)
    if set(inventory) != set(ROUTE_HANDLERS):
        raise ValueError(
            "OpenAPI route inventory drifted from the router; "
            f"undocumented={sorted(set(inventory) - set(ROUTE_HANDLERS))}, "
            f"unserved={sorted(set(ROUTE_HANDLERS) - set(inventory))}"
        )
    for (method, path), handler in inventory.items():
        if ROUTE_HANDLERS[(method, path)] != handler:
            raise ValueError(f"OpenAPI handler drifted for {(method, path)}: {handler}")
    if set(ROUTE_HANDLERS) != set(OPERATION_IDS):
        raise ValueError("every operation must carry an operationId")
    wiring = handler_wiring(http_source, service_source, inventory, variants)
    for key, derived in wiring.items():
        method, path = key
        operation = paths[path][method.lower()]
        if operation.get("operationId") != OPERATION_IDS[key]:
            raise ValueError(f"OpenAPI operationId drifted for {key}")
        expected_security = [] if derived["authority"] == "unauthenticated" else [{"bearerAuth": []}]
        if operation["security"] != expected_security:
            raise ValueError(f"OpenAPI security drifted from the handler for {key}")
        if operation["x-scheduling-authority"] != derived["authority"]:
            raise ValueError(f"OpenAPI authority drifted from the handler for {key}")
        has_body = "requestBody" in operation
        if has_body != bool(derived["body"]):
            raise ValueError(f"OpenAPI request body drifted from the handler for {key}")
        if has_body:
            if derived["body"] not in operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]:
                raise ValueError(f"OpenAPI request body schema drifted from the handler for {key}")
            if operation["x-maximum-body-bytes"] != MAXIMUM_BODY_BYTES:
                raise ValueError(f"OpenAPI request body bound drifted from the router for {key}")
        elif "x-maximum-body-bytes" in operation:
            raise ValueError(f"OpenAPI names a body bound on a bodyless operation for {key}")
        names = [parameter["name"] for parameter in operation["parameters"]]
        if ("Idempotency-Key" in names) != derived["idempotency_key"]:
            raise ValueError(f"OpenAPI idempotency key drifted from the handler for {key}")
        if derived["idempotency_key"]:
            idempotency = next(
                parameter for parameter in operation["parameters"] if parameter["name"] == "Idempotency-Key"
            )
            if not idempotency["required"] or idempotency["schema"] != IDEMPOTENCY_SCHEMA:
                raise ValueError(f"OpenAPI idempotency key bound drifted from the handler for {key}")
        template_names = re.findall(r"\{([a-z_]+)\}", path)
        rust_path_names = [name for name, _ in derived["path_parameters"]]
        if template_names != rust_path_names:
            raise ValueError(f"OpenAPI path parameters drifted from the handler for {key}")
        for name in template_names:
            parameter = next(item for item in operation["parameters"] if item["name"] == name)
            if not parameter["required"] or parameter["schema"] != UUID_SCHEMA:
                raise ValueError(f"OpenAPI path parameter schema drifted for {key}: {name}")
        query_fields = query_struct(http_source, derived["query"]) if derived["query"] else {}
        documented_query = {
            parameter["name"]: parameter
            for parameter in operation["parameters"]
            if parameter["in"] == "query"
        }
        if set(documented_query) != set(query_fields):
            raise ValueError(f"OpenAPI query parameters drifted from the handler for {key}")
        for name, (required, family) in query_fields.items():
            schema = documented_query[name]["schema"]
            actual = "date-time" if schema.get("format") == "date-time" else schema["type"]
            if documented_query[name]["required"] != required or actual != family:
                raise ValueError(f"OpenAPI query parameter {name} drifted from the handler for {key}")
        successes = [status for status in operation["responses"] if int(status) < 400]
        if successes != [str(derived["success_status"])]:
            raise ValueError(
                f"OpenAPI success status drifted from the handler for {key}; "
                f"documented={successes}, handler={derived['success_status']}"
            )
        documented_problems = [
            status for status in operation["responses"] if int(status) >= 400
        ]
        unavailable = "503" in documented_problems
        unauthenticated = derived["authority"] == "unauthenticated"
        # A fallible service method opens a store round trip, so its operation
        # must document service.unavailable. An authenticated operation must
        # document it too even when its service method cannot fail, because
        # verifying the bearer reaches the issuer's key material and an issuer
        # outage is answered with Retry-After, never with a challenge the
        # caller cannot satisfy. Only an unauthenticated operation over an
        # infallible service method answers no 503 at all.
        if derived["service_infallible"] is True and unavailable and unauthenticated:
            raise ValueError(f"an unauthenticated infallible operation documents 503 for {key}")
        if derived["service_infallible"] is False and not unavailable:
            raise ValueError(f"a fallible service method documents no 503 for {key}")
        if not unauthenticated and not unavailable:
            raise ValueError(f"an authenticated operation documents no 503 for {key}")
        if not documented_problems and derived["authority"] != "unauthenticated":
            raise ValueError(f"an authenticated operation answers no refusal for {key}")
        for code in derived["problem_codes"]:
            if code not in OPERATION_PROBLEMS[key]:
                raise ValueError(f"handler names {code} but the document does not answer it for {key}")


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


def verify_operation_problems(
    openapi: dict, contract: dict, catalog: dict[str, dict], variants: dict[str, str]
) -> None:
    """Check the hand-shaped per-operation mappings against the catalog.

    Status is a property of the code in Scheduling, so the document's status
    grouping is compared with the status the catalog pins for each code, and
    every documented code must be produced somewhere in the runtime.
    """
    documented = {
        (method.upper(), path)
        for path, path_item in openapi["paths"].items()
        for method in path_item
    }
    if documented != set(OPERATION_PROBLEMS):
        raise ValueError(
            "OpenAPI problem inventory drifted; "
            f"documented_only={sorted(documented - set(OPERATION_PROBLEMS))}, "
            f"unmapped={sorted(set(OPERATION_PROBLEMS) - documented)}"
        )
    for code in EDGE_PROBLEMS + RESERVED_PROBLEMS:
        if code not in catalog:
            raise ValueError(f"declared problem is outside the Rust vocabulary: {code}")
    produced = produced_problem_codes(_root(), variants)
    reserved = set(RESERVED_PROBLEMS)
    if set(UNPRODUCED_PROBLEMS) & produced:
        raise ValueError("a problem documented as unproduced is produced by the runtime")
    for key, codes in OPERATION_PROBLEMS.items():
        method, path = key
        operation = openapi["paths"][path][method.lower()]
        for code in codes:
            if code not in catalog:
                raise ValueError(f"problem code is outside the Rust vocabulary: {code}")
            if code in reserved:
                raise ValueError(f"reserved problem documented as an operation answer: {code}")
            if code not in produced:
                raise ValueError(f"no runtime path produces {code}, documented for {key}")
        expected_by_status: dict[int, set[str]] = {}
        for code in codes:
            expected_by_status.setdefault(catalog[code]["httpStatuses"][0], set()).add(code)
        actual_by_status = {
            int(status): schema_problem_codes(
                openapi, response["content"]["application/problem+json"]["schema"]
            )
            for status, response in operation["responses"].items()
            if int(status) >= 400
        }
        if actual_by_status != expected_by_status:
            raise ValueError(
                f"per-operation problem mapping drifted for {key}; "
                f"documented={actual_by_status}, expected={expected_by_status}"
            )
        required = {"request.body-too-large", "request.method-not-allowed"}
        if operation["x-scheduling-authority"] != "unauthenticated":
            # Authentication itself reaches the issuer's key material, so an
            # authenticated operation answers service.unavailable even when it
            # never opens the store.
            required |= {
                "authentication.refused",
                "profile.not-authorized",
                "service.unavailable",
            }
        if operation.get("requestBody"):
            required |= {"request.invalid", "request.unprocessable", "request.unsupported-media-type"}
        if any(parameter["in"] == "query" for parameter in operation["parameters"]):
            required |= {"request.invalid"}
        # A path segment is read into its identifier before the handler runs,
        # so a segment that is not one is refused at the edge, ahead of
        # authentication and ahead of the store.
        if any(parameter["in"] == "path" for parameter in operation["parameters"]):
            required |= {"request.invalid"}
        if any(parameter["name"] == "Idempotency-Key" for parameter in operation["parameters"]):
            required |= {"request.invalid"}
        if not required <= set(codes):
            raise ValueError(
                f"per-operation problem mapping lacks the codes its wiring requires for {key}: "
                f"{sorted(required - set(codes))}"
            )
    answered = {code for codes in OPERATION_PROBLEMS.values() for code in codes}
    if answered != set(catalog) - reserved:
        raise ValueError(
            "documented problem coverage drifted from the closed vocabulary; "
            f"unanswered={sorted(set(catalog) - reserved - answered)}, "
            f"unknown={sorted(answered - set(catalog))}"
        )


def production_source(repository_root: Path, relative: str) -> str:
    """A source file up to its test module: production sites only."""
    source = (repository_root / relative).read_text(encoding="utf-8")
    return source.split("#[cfg(test)]", 1)[0]


def produced_problem_codes(repository_root: Path, variants: dict[str, str]) -> set[str]:
    """The codes the runtime and the core name outside the vocabulary itself.

    A code with no production site cannot reach a caller, so it may not be
    documented as an operation's answer.
    """
    produced = set()
    for relative in (HTTP_SOURCE, SERVICE_SOURCE, STORE_SOURCE, CURSORS_SOURCE, ADMISSION_SOURCE):
        source = production_source(repository_root, relative)
        produced |= {
            variants[name] for name in re.findall(r"ProblemCode::([A-Z][A-Za-z0-9]*)", source)
        }
    return produced


def load_rust_contract(repository_root: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="registry-scheduling-openapi-") as directory:
        output = Path(directory) / "problem-catalog.json"
        subprocess.run(
            [
                "cargo",
                "run",
                "--locked",
                "--quiet",
                "-p",
                "registry-scheduling-core",
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
    if set(contract) != {"entries"}:
        raise ValueError(f"Rust problem catalog fields drifted: {sorted(contract)}")
    codes = [entry["code"] for entry in contract["entries"]]
    if codes != sorted(set(codes)):
        raise ValueError("Rust problem catalog codes are not unique and sorted")
    if any(len(entry["httpStatuses"]) != 1 for entry in contract["entries"]):
        raise ValueError("each Scheduling problem must have exactly one HTTP status")
    return contract


def camel_case(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part.title() for part in tail)


def code_variant(code: str) -> str:
    """The Rust variant name a problem code spells: `hold.expired` -> `HoldExpired`."""
    return "".join(part.title() for part in re.split(r"[.-]", code))


def rust_struct_fields(source: str, name: str) -> set[str]:
    match = re.search(rf"pub struct {re.escape(name)}(?:<[^>]+>)?\s*\{{(?P<body>.*?)^\}}", source, re.S | re.M)
    if not match:
        raise ValueError(f"Rust DTO is missing: {name}")
    return set(re.findall(r"^\s*pub\s+([a-z_]+)\s*:", match.group("body"), re.M))


def rust_serde_attributes(source: str, name: str, keyword: str = "struct") -> str:
    """The serde attribute list immediately above one Rust DTO declaration."""
    declaration = re.search(
        rf"^pub {keyword} {re.escape(name)}(?:<[^>]+>)?\s*[{{(]", source, re.M
    )
    if not declaration:
        raise ValueError(f"Rust DTO is missing: {name}")
    attribute = re.search(r"#\[serde\(([^()]*)\)\]\s*\Z", source[: declaration.start()], re.S)
    if not attribute:
        raise ValueError(f"Rust DTO carries no serde attributes: {name}")
    return attribute.group(1)


def rust_refuses_unknown_members(source: str, name: str, keyword: str = "struct") -> bool:
    return "deny_unknown_fields" in rust_serde_attributes(source, name, keyword)


def schema_is_closed(schema: dict) -> bool:
    return schema.get("additionalProperties") is False


def rust_kebab_case_unit_enum_values(source: str, name: str) -> list[str]:
    match = re.search(
        rf'#\[serde\(rename_all = "kebab-case"\)\]\s*pub enum {re.escape(name)}\s*\{{(?P<body>.*?)^\}}',
        source,
        re.S | re.M,
    )
    if not match:
        raise ValueError(f"Rust kebab-case enum is missing: {name}")
    variants = re.findall(r"^\s*([A-Z][A-Za-z0-9]*)\s*,?\s*$", match.group("body"), re.M)
    return [re.sub(r"(?<!^)(?=[A-Z])", "-", variant).lower() for variant in variants]


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
            # Openness follows the wire type, and the wire type follows the
            # direction: a request the runtime reads is closed, an answer a
            # client reads is open.
            refuses = rust_refuses_unknown_members(source, rust_name)
            if refuses != schema_is_closed(openapi_schemas[schema_name]):
                raise ValueError(
                    f"OpenAPI openness drifted from {rust_name}; "
                    f"rust_refuses_unknown_members={refuses}, "
                    f"schema_is_closed={schema_is_closed(openapi_schemas[schema_name])}"
                )
    wire = production_source(repository_root, WIRE_SOURCE)
    page_fields = {camel_case(field) for field in rust_struct_fields(wire, "PageDocument")}
    for schema_name in (
        "ServicePage",
        "OfferingPage",
        "ResourcePage",
        "LocationPage",
        "AvailabilityPage",
        "AppointmentHistoryPage",
    ):
        if set(openapi_schemas[schema_name]["properties"]) != page_fields:
            raise ValueError(f"OpenAPI page shape drifted for {schema_name}")
        if set(openapi_schemas[schema_name]["required"]) != page_fields:
            raise ValueError(f"OpenAPI page required fields drifted for {schema_name}")
        if rust_refuses_unknown_members(wire, "PageDocument") != schema_is_closed(
            openapi_schemas[schema_name]
        ):
            raise ValueError(f"OpenAPI page openness drifted from PageDocument for {schema_name}")
    if set(openapi_schemas["OfferingDocument"]["properties"]["mode"]["enum"]) != set(
        rust_kebab_case_unit_enum_values(wire, "SchedulingModeDocument")
    ):
        raise ValueError("OpenAPI offering mode values drifted from Rust")
    if set(openapi_schemas["AppointmentState"]["enum"]) != set(
        rust_kebab_case_unit_enum_values(wire, "AppointmentStateDocument")
    ):
        raise ValueError("OpenAPI appointment state values drifted from Rust")
    entry_match = re.search(
        r"#\[serde\((?P<attributes>[^\)]*)\)\]\s*pub enum AvailabilityEntry\s*\{(?P<body>.*?)^\}",
        wire,
        re.S | re.M,
    )
    if not entry_match:
        raise ValueError("Rust availability entry is missing")
    attributes = entry_match.group("attributes")
    body = entry_match.group("body")
    for text in ('tag = "kind"', 'rename_all_fields = "camelCase"'):
        if text not in attributes:
            raise ValueError(f"OpenAPI availability entries drifted from Rust: {text}")
    # An availability entry is an answer, so both variants stay open.
    if "deny_unknown_fields" in attributes:
        raise ValueError("Rust availability entries refuse a member a later deployment added")
    variants = re.findall(r"^\s*([A-Z][A-Za-z0-9]*)\s*\{", body, re.M)
    expected = {re.sub(r"(?<!^)(?=[A-Z])", "-", variant).lower() for variant in variants}
    if expected != {"slot", "window"}:
        raise ValueError(f"OpenAPI availability variants drifted from Rust: {sorted(expected)}")
    for marker in ("free: u32", "channel_remaining: Option<u32>", "window: String"):
        if marker not in body:
            raise ValueError(f"OpenAPI availability entry field drifted from Rust: {marker}")
    if {
        variant["$ref"].rsplit("/", 1)[1]
        for variant in openapi_schemas["AvailabilityEntry"]["oneOf"]
    } != {"AvailabilitySlot", "AvailabilityWindow"}:
        raise ValueError("OpenAPI availability entry variants drifted from Rust")
    for variant, kind in (
        (openapi_schemas["AvailabilitySlot"], "slot"),
        (openapi_schemas["AvailabilityWindow"], "window"),
    ):
        if variant["properties"]["kind"]["const"] != kind:
            raise ValueError("OpenAPI availability discriminator drifted from Rust")
        if schema_is_closed(variant):
            raise ValueError(f"OpenAPI availability variant is closed against Rust: {kind}")
    explain = openapi_schemas["ExplainDocument"]
    for field in ("publicCode", "detailedCode", "explanation"):
        if field in explain["required"] or "anyOf" in explain["properties"][field]:
            raise ValueError(f"OpenAPI explain projection drifted for {field}")
    if wire.count('skip_serializing_if = "Option::is_none"') != 3:
        raise ValueError("OpenAPI explain optionality drifted from Rust")
    create = openapi_schemas["CreateAppointmentRequest"]
    if set(create["properties"]) != {"hold", "admission"} or create["minProperties"] != 1:
        raise ValueError("OpenAPI exclusive create shape drifted from Rust")


def marker(source: str, text: str, origin: str) -> None:
    if text not in source:
        raise ValueError(f"OpenAPI bound drifted from Rust in {origin}: {text}")


def verify_source(repository_root: Path) -> None:
    """Check the bounds and edge behaviour the document states, in Rust."""
    http_source = production_source(repository_root, HTTP_SOURCE)
    naming_source = production_source(repository_root, NAMING_SOURCE)
    service_source = production_source(repository_root, SERVICE_SOURCE)
    store_source = production_source(repository_root, STORE_SOURCE)
    cursors_source = production_source(repository_root, CURSORS_SOURCE)
    auth_source = production_source(repository_root, AUTH_SOURCE)
    config_source = production_source(repository_root, CONFIG_SOURCE)
    admission_source = production_source(repository_root, ADMISSION_SOURCE)
    problem_source = production_source(repository_root, PROBLEM_SOURCE)
    httpsec_source = production_source(repository_root, HTTPSEC_SOURCE)

    inventory = route_inventory(http_source, naming_source)
    paths = {path for _, path in inventory}
    if paths != ROUTES:
        raise ValueError(
            "maintained OpenAPI route inventory drifted; "
            f"undocumented={sorted(paths - ROUTES)}, "
            f"unserved={sorted(ROUTES - paths)}"
        )
    for constant, value in HEADERS.items():
        marker(naming_source, f'pub const {constant}: &str = "{value}";', "naming")
    marker(naming_source, "pub const MAXIMUM_IDEMPOTENCY_KEY_BYTES: usize = 128;", "naming")
    marker(naming_source, 'pub const CURSOR_QUERY_PARAMETER: &str = "cursor";', "naming")
    marker(naming_source, 'pub const LIMIT_QUERY_PARAMETER: &str = "limit";', "naming")
    marker(cursors_source, "pub const CURSOR_LIFETIME_MINUTES: i64 = 15;", "cursors")
    marker(cursors_source, "const MAXIMUM_CURSOR_BYTES: usize = 256;", "cursors")
    marker(service_source, "pub const DEFAULT_PAGE_LIMIT: usize = 50;", "service")
    marker(service_source, "pub const MAXIMUM_PAGE_LIMIT: usize = 200;", "service")
    marker(service_source, "const MAXIMUM_AVAILABILITY_SPAN_DAYS: i64 = 62;", "service")
    for action in (
        "HOLD_CREATE_ACTION",
        "HOLD_RELEASE_ACTION",
        "APPOINTMENT_CREATE_ACTION",
        "APPOINTMENT_RESCHEDULE_ACTION",
        "APPOINTMENT_CANCEL_ACTION",
    ):
        marker(service_source, f"pub const {action}: &str = ", "service")
    marker(config_source, 'fn default_reads_scope() -> String {\n    "scheduling-read".to_owned()', "config")
    marker(config_source, 'fn default_explain_scope() -> String {\n    "scheduling-explain".to_owned()', "config")
    marker(httpsec_source, "pub const DEFAULT_REQUEST_BODY_LIMIT_BYTES: usize = 1024 * 1024;", "httpsec")
    problem_body = re.search(
        r"#\[serde\(rename_all = \"camelCase\"\)\]\s*pub struct ProblemBody\s*\{(?P<body>.*?)^\}",
        httpsec_source,
        re.S | re.M,
    )
    if not problem_body:
        raise ValueError("the problem envelope is missing from the platform")
    fields = set(re.findall(r"^\s*pub\s+([a-z_]+)\s*:", problem_body.group("body"), re.M))
    if fields != {"type_uri", "title", "status", "detail", "code", "trace_id"}:
        raise ValueError(f"problem envelope fields drifted; actual={sorted(fields)}")
    for text in (
        "async fn route_not_found()",
        "async fn method_not_allowed()",
        "fn normalize_framework_rejection",
        "StatusCode::BAD_REQUEST => Some(ProblemCode::RequestInvalid)",
        "StatusCode::PAYLOAD_TOO_LARGE => Some(ProblemCode::RequestBodyTooLarge)",
        "StatusCode::UNSUPPORTED_MEDIA_TYPE => Some(ProblemCode::RequestUnsupportedMediaType)",
        "StatusCode::UNPROCESSABLE_ENTITY => Some(ProblemCode::RequestUnprocessable)",
        "problem_response(ProblemCode::RequestNotFound)",
        "problem_response(ProblemCode::RequestMethodNotAllowed)",
        "byte.is_ascii_graphic()",
        "value.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES",
        "parse_bearer_token(authorization)",
        'status == StatusCode::UNAUTHORIZED',
        '"Bearer"',
        "status == StatusCode::SERVICE_UNAVAILABLE",
        'RETRY_AFTER,\n            "5"',
        'CACHE_CONTROL,\n        "no-store"',
    ):
        marker(http_source, text, "http")
    for text in (
        "pub async fn authenticate_read",
        "pub async fn authenticate_explain",
        "pub async fn authenticate_mutate",
        "grant_claims(&verified.claims",
        ".ok_or(AuthenticationError::Profile)",
    ):
        marker(auth_source, text, "auth")
    for text in (
        "pub enum CommitError",
        "WHERE actor_issuer=$1 AND actor_subject=$2 AND scope=$3 AND idempotency_key=$4",
    ):
        marker(store_source, text, "store")
    # The commitment verdict, not the store, names the caller's problem.
    for text in (
        "CommitError::KeyReused => ProblemCode::IdempotencyKeyReused",
        "CommitError::KeyExpired => ProblemCode::IdempotencyExpired",
        "CommitError::HoldCeiling => ProblemCode::CapacityExhausted",
        "CommitError::Unauthorized => ProblemCode::OperationNotAuthorized",
        "CommitError::RevisionMismatch => ProblemCode::RevisionMismatch",
        "CommitError::CutoffPassed => ProblemCode::CancellationCutoffPassed",
    ):
        marker(service_source, text, "service")
    for text in (
        "pub enum AdmissionRefusal",
        "pub const fn public_code(&self) -> ProblemCode",
        "Self::ResourceUnavailable { .. } => ProblemCode::CapacityExhausted",
        "Self::DuplicateKeyRequired { .. } => ProblemCode::PreconditionRequired",
        "pub const fn detailed_code(&self) -> ProblemCode",
        "Self::ResourceUnavailable { .. } => ProblemCode::ResourceUnavailable",
    ):
        marker(admission_source, text, "admission")
    for text in (
        "pub const fn is_detailed_only(self) -> bool",
        "matches!(self, Self::ResourceUnavailable)",
        "pub fn type_uri(code: &str) -> String",
        "SCHEDULING_PROBLEM_TYPE_BASE",
    ):
        marker(problem_source, text, "problem")


def _root() -> Path:
    return Path(__file__).resolve().parents[3]


def catalog_of(contract: dict) -> dict[str, dict]:
    return {entry["code"]: entry for entry in contract["entries"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="verify the committed document instead of writing it")
    args = parser.parse_args()
    repository_root = _root()
    output = repository_root / OUTPUT
    try:
        contract = load_rust_contract(repository_root)
        variants = {code_variant(entry["code"]): entry["code"] for entry in contract["entries"]}
        verify_source(repository_root)
        openapi = document(contract)
        verify_handler_wiring(repository_root, openapi["paths"], variants)
        verify_dto_schemas(repository_root, openapi)
        verify_operation_problems(openapi, contract, catalog_of(contract), variants)
        rendered = json.dumps(openapi, indent=2, sort_keys=True) + "\n"
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"OpenAPI source check failed: {error}", file=sys.stderr)
        return 1
    if args.check:
        if not output.exists() or output.read_text(encoding="utf-8") != rendered:
            print(f"{output.relative_to(repository_root)} is stale; regenerate it", file=sys.stderr)
            return 1
        print("Registry Scheduling OpenAPI is current.")
        return 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    print(output.relative_to(repository_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
