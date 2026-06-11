#!/usr/bin/env python3
"""Combined support eligibility scenario."""

from __future__ import annotations

from typing import Any

from .common import (
    PURPOSE,
    auth_header_pair,
    display_auth_header_pair,
    env_url,
    evaluation_body,
    friendly_unavailable,
    http_json,
    observed_answer,
    ok_status,
    request_source,
    result_item,
    runtime_bearer_credential,
    source_response,
    standard_error_result,
)


SCENARIO_ID = "combined-support"
SERVICE_NAME = "Combined Support Notary"
TOKEN_ENV = "SHARED_EVIDENCE_CLIENT_BEARER"
URL_ENV = "SHARED_EVIDENCE_URL"
DEFAULT_URL = "http://127.0.0.1:4323"
POSITIVE_SUBJECT = "NID-1001"
NEGATIVE_SUBJECT = "NID-1002"


CLAIMS = {
    "civil-subclaim": ("civil-record-present", POSITIVE_SUBJECT, "Civil record found"),
    "social-subclaim": ("social-program-active", POSITIVE_SUBJECT, "Active social support"),
    "health-subclaim": ("health-service-available", POSITIVE_SUBJECT, "Health service available"),
    "final-positive": ("eligible-for-combined-support", POSITIVE_SUBJECT, "Eligible for combined support"),
    "negative-control": ("eligible-for-combined-support", NEGATIVE_SUBJECT, "Similar applicant fails"),
}


def story() -> dict[str, Any]:
    return {
        "id": SCENARIO_ID,
        "title": "Can a caseworker ask one eligibility question across civil, social, and health evidence?",
        "short_title": "Combined support eligibility",
        "proves": "A Notary can compose subclaims from multiple authorities into one decision-ready evidence result.",
        "domain": "Social protection",
        "availability": "local-only",
        "availability_note": "Runs on the local lab profile with the shared eligibility Notary on port 4323 (SHARED_EVIDENCE_CLIENT_BEARER).",
        "intro": (
            "A caseworker reviews Miguel's support application. The final answer depends on civil status, an active social program, "
            "and district service availability, but the caseworker should not receive source rows from every registry."
        ),
        "actor": "Caseworker",
        "subject": {"name": "Miguel Santos", "identifier": POSITIVE_SUBJECT},
        "boundary": {
            "allowed": "Ask whether required subclaims are satisfied.",
            "not_allowed": "Copy civil, household, and health source rows into the response.",
        },
        "steps": [
            {
                "id": "discover",
                "label": "Discover combined evidence claims",
                "prompt": "Start by asking the local Notary what claims it can evaluate.",
                "button": "Discover claims",
                "request_summary": "GET /v1/claims from the local shared eligibility Notary.",
            },
            {
                "id": "civil-subclaim",
                "label": "Evaluate civil subclaim",
                "prompt": "Check that Miguel has a civil record for the combined decision.",
                "button": "Run civil subclaim",
                "request_summary": "POST a civil-record-present evaluation for NID-1001.",
            },
            {
                "id": "social-subclaim",
                "label": "Evaluate social subclaim",
                "prompt": "Check whether Miguel has active program support.",
                "button": "Run social subclaim",
                "request_summary": "POST a social-program-active evaluation for NID-1001.",
                "reuses": [{"label": "Subject", "value": POSITIVE_SUBJECT}],
            },
            {
                "id": "health-subclaim",
                "label": "Evaluate service-availability subclaim",
                "prompt": "Check the applicant service-availability projection for Miguel's district.",
                "button": "Run health subclaim",
                "request_summary": "POST a health-service-available evaluation for NID-1001.",
            },
            {
                "id": "final-positive",
                "label": "Evaluate final eligibility",
                "prompt": "Ask the combined question after the subclaims are visible.",
                "button": "Run combined check",
                "request_summary": "POST eligible-for-combined-support for NID-1001.",
                "reuses": [
                    {"label": "Civil", "value": "record present"},
                    {"label": "Social", "value": "program active"},
                    {"label": "Health", "value": "service available"},
                ],
            },
            {
                "id": "negative-control",
                "label": "Run a negative control",
                "prompt": "Use a similar applicant whose health service availability is false.",
                "button": "Run negative control",
                "request_summary": "POST eligible-for-combined-support for NID-1002 and show why the final answer changes.",
            },
        ],
        "receipt": [
            {"label": "Positive subject", "value": POSITIVE_SUBJECT},
            {"label": "Expected final answer", "value": "Eligible"},
            {"label": "Negative control", "value": NEGATIVE_SUBJECT},
            {"label": "Source rows copied", "value": "No"},
        ],
    }


def run_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id == "discover":
        return _discover(step_id)
    if step_id in CLAIMS:
        claim_id, subject, label = CLAIMS[step_id]
        return _evaluate(step_id, claim_id, subject, label)
    return standard_error_result(step_id)


def _headers(credential: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    return (
        {auth_name: auth_value, "Data-Purpose": PURPOSE},
        {display_name: display_value, "Data-Purpose": PURPOSE},
    )


def _discover(step_id: str) -> dict[str, Any]:
    credential = runtime_bearer_credential("shared-evidence", TOKEN_ENV)
    url = env_url(URL_ENV, DEFAULT_URL, "/v1/claims")
    real_headers, display_headers = _headers(credential)
    if not credential.get("token"):
        return {
            "step_id": step_id,
            "friendly": friendly_unavailable(SERVICE_NAME, TOKEN_ENV, url),
            "request_source": request_source("GET", url, display_headers, internal=True),
            "response_source": {"note": "No local token configured, so the request was not sent."},
        }
    result = http_json("GET", url, real_headers)
    claims = result.body.get("claims", []) if isinstance(result.body, dict) else []
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The local Notary advertises combined claims." if ok_status(result.status) else "Claim discovery needs attention.",
            "message": "This catalog tells the caseworker which subclaims and final claims can be evaluated.",
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Claims advertised", "value": len(claims) if isinstance(claims, list) else "Check source"},
                {"label": "Availability", "value": "Local-only"},
            ],
        },
        "request_source": request_source("GET", url, display_headers, internal=True),
        "response_source": source_response(result),
    }


def _evaluate(step_id: str, claim_id: str, subject: str, label: str) -> dict[str, Any]:
    credential = runtime_bearer_credential("shared-evidence", TOKEN_ENV)
    url = env_url(URL_ENV, DEFAULT_URL, "/v1/evaluations")
    real_headers, display_headers = _headers(credential)
    real_headers["Content-Type"] = "application/json"
    display_headers["Content-Type"] = "application/json"
    body = evaluation_body(subject, claim_id)
    if not credential.get("token"):
        return {
            "step_id": step_id,
            "friendly": friendly_unavailable(SERVICE_NAME, TOKEN_ENV, url),
            "request_source": request_source("POST", url, display_headers, body, internal=True),
            "response_source": {"note": "No local token configured, so the request was not sent."},
        }
    result = http_json("POST", url, real_headers, body)
    item = result_item(result.body, claim_id)
    answer = observed_answer(item)
    return {
        "step_id": step_id,
        "friendly": {
            "title": f"{label}: {'yes' if answer is True else 'no' if answer is False else 'check source'}.",
            "message": (
                "The Notary response gives the caseworker a claim result without copying the underlying registry rows."
            ),
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Subject", "value": subject},
                {"label": "Claim", "value": claim_id},
                {"label": "Answer", "value": "Yes" if answer is True else ("No" if answer is False else "Unknown")},
                {"label": "Raw source rows included", "value": "No"},
            ],
        },
        "request_source": request_source("POST", url, display_headers, body, internal=True),
        "response_source": source_response(result),
    }
