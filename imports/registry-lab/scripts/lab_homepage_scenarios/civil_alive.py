#!/usr/bin/env python3
"""Civil evidence scenario: prove alive status without row access."""

from __future__ import annotations

from typing import Any

from .common import (
    PURPOSE,
    auth_header_pair,
    configured_credential,
    display_auth_header_pair,
    env_url,
    evaluation_body,
    http_json,
    observed_answer,
    ok_status,
    request_source,
    result_item,
    runtime_bearer_credential,
    service_url,
    source_response,
    standard_error_result,
)


SCENARIO_ID = "alive-proof"
SUBJECT_ID = "NID-1001"
SUBJECT_NAME = "Miguel Santos"
CLAIM_ID = "person-is-alive"
EVIDENCE_SERVICE_NAME = "Civil vital status evidence service"
DISCOVERY_REUSED = {
    "evidence_service": EVIDENCE_SERVICE_NAME,
    "lookup_key": "national_id",
    "data_boundary": "evidence result only",
}


def story() -> dict[str, Any]:
    return {
        "id": SCENARIO_ID,
        "title": "Can a benefits service verify Miguel is alive without reading his civil registry record?",
        "short_title": "Evidence without row access",
        "proves": "A service can request a decision-ready fact while the raw civil record stays protected.",
        "domain": "Civil registry",
        "availability": "hosted",
        "intro": (
            "You are a benefits service reviewing Miguel's application. You need one fact: whether Miguel is alive. "
            "You should not receive his full civil registry record."
        ),
        "actor": "Benefits service",
        "subject": {"name": SUBJECT_NAME, "identifier": SUBJECT_ID},
        "boundary": {
            "allowed": "Ask for evidence that Miguel is alive.",
            "not_allowed": "Read Miguel's full civil registry row.",
        },
        "steps": [
            {
                "id": "discover",
                "label": "Find available evidence checks",
                "prompt": "First, ask the Relay what civil evidence checks it advertises.",
                "button": "Run discovery",
                "request_summary": "GET the civil evidence offerings using the public evidence-only demo credential.",
            },
            {
                "id": "prepare-evidence",
                "label": "Ask the alive question",
                "prompt": "Next, reuse the discovered evidence service and lookup key to ask only the alive-status question.",
                "button": "Check if Miguel is alive",
                "request_summary": "POST a person-is-alive request for Miguel to the Notary, using national_id as the lookup key.",
                "reuses": [
                    {"label": "Evidence service", "value": EVIDENCE_SERVICE_NAME},
                    {"label": "Lookup key", "value": "national_id"},
                    {"label": "Boundary", "value": "Ask for evidence, not rows"},
                ],
            },
            {
                "id": "deny-row",
                "label": "Try full-record access",
                "prompt": "Finally, try the request the benefits service should not be able to make with this credential.",
                "button": "Try full-record access",
                "request_summary": "GET the civil registry row endpoint with the same evidence-only credential and show the denial.",
            },
        ],
        "receipt": [
            {"label": "Needed answer", "value": "Is Miguel alive?"},
            {"label": "Answer exposed", "value": "Yes"},
            {"label": "Full registry row exposed", "value": "No"},
            {"label": "Access boundary tested", "value": "Denied as expected"},
        ],
    }


def preview_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id == "discover":
        credential = configured_credential(config, "civil-evidence-only")
        display_name, display_value = display_auth_header_pair(credential)
        url = service_url(config, "civil-evidence-only", "/metadata/evidence-offerings")
        return request_source("GET", url, {display_name: display_value})
    if step_id == "prepare-evidence":
        credential = runtime_bearer_credential("civil-notary-evidence", "CIVIL_EVIDENCE_CLIENT_BEARER")
        display_name, display_value = display_auth_header_pair(credential)
        url = env_url("CIVIL_EVIDENCE_URL", "http://127.0.0.1:4321", "/v1/evaluations")
        body = evaluation_body(SUBJECT_ID, CLAIM_ID)
        return request_source(
            "POST",
            url,
            {display_name: display_value, "Content-Type": "application/json", "Data-Purpose": PURPOSE},
            body,
            internal=True,
        )
    if step_id == "deny-row":
        credential = configured_credential(config, "civil-evidence-only")
        display_name, display_value = display_auth_header_pair(credential)
        url = service_url(config, "civil-evidence-only", "/v1/datasets/civil_registry/entities/civil_person/records?limit=1")
        return request_source("GET", url, {display_name: display_value, "Data-Purpose": PURPOSE})
    return {}


def run_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id == "discover":
        return _run_discovery(config, step_id)
    if step_id == "prepare-evidence":
        return _run_evaluation(step_id)
    if step_id == "deny-row":
        return _run_row_denial(config, step_id)
    return standard_error_result(step_id)


def _run_discovery(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    credential = configured_credential(config, "civil-evidence-only")
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    url = service_url(config, "civil-evidence-only", "/metadata/evidence-offerings")
    result = http_json("GET", url, {auth_name: auth_value})
    return {
        "step_id": step_id,
        "friendly": _summarize_discovery(result.body, result.status),
        "request_source": request_source("GET", url, {display_name: display_value}),
        "response_source": source_response(result),
    }


def _run_evaluation(step_id: str) -> dict[str, Any]:
    credential = runtime_bearer_credential("civil-notary-evidence", "CIVIL_EVIDENCE_CLIENT_BEARER")
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    url = env_url("CIVIL_EVIDENCE_URL", "http://127.0.0.1:4321", "/v1/evaluations")
    body = evaluation_body(SUBJECT_ID, CLAIM_ID)
    headers = {auth_name: auth_value, "Content-Type": "application/json", "Data-Purpose": PURPOSE}
    result = http_json("POST", url, headers, body)
    return {
        "step_id": step_id,
        "friendly": _summarize_evaluation(result),
        "request_source": request_source(
            "POST",
            url,
            {display_name: display_value, "Content-Type": "application/json", "Data-Purpose": PURPOSE},
            body,
            internal=True,
        ),
        "response_source": {
            "reused_from_discovery": DISCOVERY_REUSED,
            "http": source_response(result),
        },
    }


def _run_row_denial(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    credential = configured_credential(config, "civil-evidence-only")
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    url = service_url(config, "civil-evidence-only", "/v1/datasets/civil_registry/entities/civil_person/records?limit=1")
    result = http_json("GET", url, {auth_name: auth_value, "Data-Purpose": PURPOSE})
    return {
        "step_id": step_id,
        "friendly": _summarize_row_denial(result),
        "request_source": request_source("GET", url, {display_name: display_value, "Data-Purpose": PURPOSE}),
        "response_source": source_response(result),
    }


def _summarize_discovery(body: Any, status: int | None) -> dict[str, Any]:
    offerings = []
    if isinstance(body, dict):
        for dataset in body.get("datasets", []):
            if isinstance(dataset, dict):
                offerings.extend(dataset.get("evidence_offerings", []))
        if isinstance(body.get("evidence_offerings"), list):
            offerings.extend(body["evidence_offerings"])
    first = offerings[0] if offerings and isinstance(offerings[0], dict) else {}
    return {
        "title": "The Relay advertises a civil evidence path.",
        "message": (
            "The benefits service can discover an evidence service before it asks for any person data. "
            "Discovery tells the client what can be checked, not Miguel's civil registry row."
        ),
        "status": "done" if ok_status(status) else "needs_attention",
        "facts": [
            {"label": "HTTP status", "value": status if status is not None else "No response"},
            {"label": "Evidence service", "value": first.get("title") or EVIDENCE_SERVICE_NAME},
            {"label": "Lookup key", "value": ", ".join(first.get("lookup_keys", [])) or "national_id"},
            {"label": "Reused next", "value": "Evidence service + lookup key"},
            {"label": "Raw person row returned", "value": "No"},
        ],
    }


def _summarize_evaluation(result) -> dict[str, Any]:
    item = result_item(result.body, CLAIM_ID)
    answer = observed_answer(item)
    ok = ok_status(result.status)
    return {
        "title": "Miguel passes the alive check." if ok and answer is True else "The alive check needs attention.",
        "message": (
            "The Notary returned the answer the service needed, without sending back the civil registry row."
            if ok
            else "The Notary request did not return the expected evidence result. Inspect the response source to see what happened."
        ),
        "status": "done" if ok else "needs_attention",
        "facts": [
            {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
            {"label": "From Step 1", "value": EVIDENCE_SERVICE_NAME},
            {"label": "Lookup key reused", "value": "national_id"},
            {"label": "Subject", "value": f"{SUBJECT_NAME} ({SUBJECT_ID})"},
            {"label": "Answer", "value": "Yes" if answer is True else ("No" if answer is False else "Unknown")},
            {"label": "Not requested", "value": "Birth record, household, address, or raw civil row"},
        ],
    }


def _summarize_row_denial(result) -> dict[str, Any]:
    body = result.body if isinstance(result.body, dict) else {}
    denied = result.status in (401, 403)
    code = body.get("code") or ("auth.scope_denied" if denied else "")
    return {
        "title": "The full-record request is denied." if denied else "The boundary check needs attention.",
        "message": (
            "The same evidence-only credential cannot read civil registry rows. "
            "That is the privacy boundary this story is making visible."
            if denied
            else "The row-read request did not return the expected denial. Inspect the technical response."
        ),
        "status": "denied_as_expected" if denied else "needs_attention",
        "facts": [
            {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
            {"label": "Result", "value": "Denied as expected" if denied else "Unexpected result"},
            {"label": "Reason", "value": code or result.error or "Unknown"},
            {"label": "Boundary preserved", "value": "Yes" if denied else "Check required"},
        ],
    }
