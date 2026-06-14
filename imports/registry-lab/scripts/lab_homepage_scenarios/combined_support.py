#!/usr/bin/env python3
"""Combined support eligibility scenario."""

from __future__ import annotations

from typing import Any

from .attestations import attestation
from .common import (
    PURPOSE,
    attestation_response,
    auth_header_pair,
    display_auth_header_pair,
    env_url,
    evaluation_body,
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

PUBLIC_ATTESTATIONS = [
    attestation("vital-status-attestation"),
    attestation("program-enrollment-attestation"),
    attestation("service-availability-attestation"),
]
ATTESTATION_BY_STEP = {
    "civil-subclaim": PUBLIC_ATTESTATIONS[0],
    "social-subclaim": PUBLIC_ATTESTATIONS[1],
    "health-subclaim": PUBLIC_ATTESTATIONS[2],
    "final-positive": attestation("combined-support-eligibility-attestation"),
    "negative-control": attestation("combined-support-eligibility-attestation"),
}


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
        "title": "Can an SP MIS assemble support evidence across civil, social, and health authorities?",
        "short_title": "Combined Support Attestations",
        "proves": "An SP MIS can combine source attestations into a local case-file decision without copying source rows.",
        "domain": "Social protection",
        "availability": "hosted",
        "availability_state": {"state": "hosted", "label": "Hosted", "runnable": True},
        "availability_note": "",
        "intro": (
            "A caseworker reviews Miguel's support application. The final answer depends on civil status, programme enrollment, "
            "and district service availability, but the caseworker should not receive source rows from every registry."
        ),
        "actor": "Caseworker",
        "subject": {"name": "Miguel Santos", "identifier": POSITIVE_SUBJECT},
        "requester": {"name": "Social Protection MIS", "purpose": PURPOSE},
        "requested_attestations": PUBLIC_ATTESTATIONS,
        "lookup_profile": {"id": "by-national-id", "label": "National ID lookup", "identifier_scheme": "national_id"},
        "non_disclosure": [
            "Full civil record",
            "Household or programme source rows",
            "Facility registry rows and clinical records",
        ],
        "proof_facts": [
            "Each source-backed sub-result is returned as minimized evidence.",
            "The SP MIS owns the final eligibility decision.",
            "Service availability is framed as a source projection, not clinical data.",
        ],
        "boundary": {
            "allowed": "Request the attestations needed for a support case file.",
            "not_allowed": "Copy civil, household, and health source rows into the response.",
        },
        "steps": [
            {
                "id": "discover",
                "label": "Discover combined attestations",
                "prompt": "Start by asking the shared eligibility Notary what attestations it can evaluate.",
                "button": "Discover attestations",
                "request_summary": "GET the shared eligibility Notary catalogue.",
            },
            {
                "id": "civil-subclaim",
                "label": "Request civil status evidence",
                "prompt": "Check that Miguel has civil evidence for the combined decision.",
                "button": "Request civil evidence",
                "request_summary": "POST the civil status evidence request for Miguel.",
            },
            {
                "id": "social-subclaim",
                "label": "Request programme enrollment evidence",
                "prompt": "Check whether Miguel has active programme support.",
                "button": "Request enrollment evidence",
                "request_summary": "POST the programme enrollment evidence request for Miguel.",
                "reuses": [{"label": "Subject", "value": POSITIVE_SUBJECT}],
            },
            {
                "id": "health-subclaim",
                "label": "Request service availability evidence",
                "prompt": "Check the service availability projection for Miguel's district.",
                "button": "Request availability evidence",
                "request_summary": "POST the Service Availability Attestation request for Miguel's district projection.",
            },
            {
                "id": "final-positive",
                "label": "Assemble the SP MIS decision",
                "prompt": "Ask the combined question after the attestations are visible.",
                "button": "Assemble case file",
                "request_summary": "POST the combined support decision request for Miguel.",
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
                "request_summary": "POST the combined support decision request for the negative control and show why the final answer changes.",
            },
        ],
        "receipt": [
            {"label": "Positive subject", "value": POSITIVE_SUBJECT},
            {"label": "Expected final answer", "value": "Eligible"},
            {"label": "Negative control", "value": NEGATIVE_SUBJECT},
            {"label": "Source rows copied", "value": "No"},
        ],
    }


def preview_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    credential = runtime_bearer_credential("shared-evidence", TOKEN_ENV)
    _, display_headers = _headers(credential)
    if step_id == "discover":
        url = env_url(URL_ENV, DEFAULT_URL, "/v1/claims")
        return request_source("GET", url, display_headers, internal=True)
    if step_id in CLAIMS:
        claim_id, subject, _label = CLAIMS[step_id]
        url = env_url(URL_ENV, DEFAULT_URL, "/v1/evaluations")
        body = evaluation_body(subject, claim_id)
        display_headers["Content-Type"] = "application/json"
        return request_source("POST", url, display_headers, body, internal=True)
    return {}


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
            "friendly": _friendly_missing_token(url),
            "request_source": request_source("GET", url, display_headers, internal=True),
            "response_source": {"note": "No runtime token configured, so the request was not sent."},
        }
    result = http_json("GET", url, real_headers)
    claims = result.body.get("claims", []) if isinstance(result.body, dict) else []
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The Notary advertises combined attestations." if ok_status(result.status) else "Attestation discovery needs attention.",
            "message": "This catalog tells the caseworker which source evidence and final decision checks can be evaluated.",
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Attestations advertised", "value": len(claims) if isinstance(claims, list) else "Check source"},
                {"label": "Availability", "value": "Hosted"},
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
            "friendly": _friendly_missing_token(url),
            "request_source": request_source("POST", url, display_headers, body, internal=True),
            "response_source": {"note": "No runtime token configured, so the request was not sent."},
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
                {"label": "Requested evidence", "value": _public_evidence_name(step_id)},
                {"label": "Answer", "value": "Yes" if answer is True else ("No" if answer is False else "Unknown")},
                {"label": "Raw source rows included", "value": "No"},
            ],
        },
        "request_source": request_source("POST", url, display_headers, body, internal=True),
        "response_source": {
            "attestation_response": attestation_response(
                ATTESTATION_BY_STEP[step_id],
                subject_type="Person",
                subject_id=subject,
                lookup_profile="by-national-id",
                claim_id=_public_claim_name(step_id),
                claim_value=answer,
            ),
            "http": source_response(result),
        },
    }


def _public_evidence_name(step_id: str) -> str:
    return {
        "civil-subclaim": "Civil Status Evidence",
        "social-subclaim": "Program Enrollment Attestation",
        "health-subclaim": "Service Availability Attestation",
        "final-positive": "SP MIS case-file decision",
        "negative-control": "SP MIS case-file decision",
    }.get(step_id, "Attestation")


def _public_claim_name(step_id: str) -> str:
    return {
        "civil-subclaim": "civil_record_present",
        "social-subclaim": "program_enrollment_active",
        "health-subclaim": "service_available",
        "final-positive": "combined_support_eligible",
        "negative-control": "combined_support_eligible",
    }.get(step_id, "attestation_satisfied")


def _friendly_missing_token(url: str) -> dict[str, Any]:
    return {
        "title": f"{SERVICE_NAME} token is not configured.",
        "message": (
            f"This scenario can run when {TOKEN_ENV} is set for the lab-homepage process. "
            "The UI keeps the story visible so users can inspect the request shape while deployment wiring is checked."
        ),
        "status": "needs_attention",
        "facts": [
            {"label": "Endpoint", "value": url},
            {"label": "Required token env", "value": TOKEN_ENV},
            {"label": "Availability", "value": "Hosted"},
        ],
    }
