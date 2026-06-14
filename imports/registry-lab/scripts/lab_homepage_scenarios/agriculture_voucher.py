#!/usr/bin/env python3
"""Agriculture voucher evidence scenario."""

from __future__ import annotations

from typing import Any

from .attestations import attestation
from .common import (
    AGRI_PURPOSE,
    attestation_response,
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


SCENARIO_ID = "agriculture-voucher"
SERVICE_NAME = "Agriculture Notary"
TOKEN_ENV = "AGRI_EVIDENCE_CLIENT_BEARER"
URL_ENV = "AGRI_EVIDENCE_URL"
DEFAULT_URL = "http://127.0.0.1:4342"
CLAIM_ID = "eligible-for-climate-smart-input-voucher"
REASON_CLAIM_ID = "voucher-eligibility-reason-code"
POSITIVE_SUBJECT = "FARMER-1001"
PARCEL_CONTROL = "FARMER-1002"
REDEEMED_CONTROL = "FARMER-1003"
PUBLIC_ATTESTATIONS = [
    attestation("agricultural-entitlement-attestation"),
    attestation("benefit-conflict-attestation"),
]


def story() -> dict[str, Any]:
    return {
        "id": SCENARIO_ID,
        "title": "Can a supplier request agricultural entitlement evidence without exporting the agriculture workbook?",
        "short_title": "Agricultural Entitlement Attestation",
        "proves": "Workbook-backed registries can produce governed attestations with positive and negative controls.",
        "domain": "Agriculture",
        "availability": "local-only",
        "availability_state": {"state": "local-only", "label": "Local only", "runnable": False},
        "availability_note": "Runs on the local lab profile with the agriculture services started (AGRI_EVIDENCE_CLIENT_BEARER).",
        "intro": (
            "Amina Kone wants to redeem a climate-smart input voucher. The supplier needs eligibility evidence, "
            "not copies of farmer, parcel, entitlement, and redemption rows."
        ),
        "actor": "Input supplier",
        "subject": {"name": "Amina Kone", "identifier": POSITIVE_SUBJECT},
        "requester": {"name": "Voucher redemption desk", "purpose": AGRI_PURPOSE},
        "requested_attestations": PUBLIC_ATTESTATIONS,
        "lookup_profile": {"id": "by-source-record-id", "label": "Farmer registry ID lookup", "identifier_scheme": "farmer_id"},
        "non_disclosure": [
            "Full farmer workbook",
            "Unrelated parcel rows",
            "Payment or redemption history beyond the requested conflict fact",
        ],
        "proof_facts": [
            "The Notary returns entitlement and conflict facts as minimized evidence.",
            "Negative controls prove the answer is not a blanket approval.",
            "Agriculture remains local-only until hosted validation is available.",
        ],
        "boundary": {
            "allowed": "Request entitlement and conflict attestations.",
            "not_allowed": "Export the agriculture workbook or unrelated farmer rows.",
        },
        "steps": [
            {
                "id": "discover",
                "label": "Discover agriculture attestations",
                "prompt": "Start by asking the local agriculture Notary what attestations it can evaluate.",
                "button": "Discover attestations",
                "request_summary": "GET the local Agriculture Notary catalogue.",
            },
            {
                "id": "positive-voucher",
                "label": "Request Amina's entitlement attestation",
                "prompt": "Check the positive control: Amina should be eligible for review.",
                "button": "Request attestation",
                "request_summary": "POST an Agricultural Entitlement Attestation request for FARMER-1001.",
                "reuses": [{"label": "Lookup profile", "value": "by-source-record-id"}, {"label": "Attestation", "value": "Agricultural Entitlement Attestation"}],
            },
            {
                "id": "inactive-parcel-control",
                "label": "Run inactive parcel control",
                "prompt": "Check a farmer whose parcel status should block eligibility.",
                "button": "Evaluate FARMER-1002",
                "request_summary": "POST an Agricultural Entitlement Attestation request for FARMER-1002.",
            },
            {
                "id": "redeemed-control",
                "label": "Run already-redeemed control",
                "prompt": "Check a farmer whose voucher has already been redeemed.",
                "button": "Evaluate FARMER-1003",
                "request_summary": "POST an Agricultural Entitlement Attestation request for FARMER-1003.",
            },
            {
                "id": "reason-code",
                "label": "Ask for the reason code",
                "prompt": "For the failed redeemed case, ask for a friendly reason code.",
                "button": "Get reason code",
                "request_summary": "POST a Benefit Conflict Attestation request for FARMER-1003 with value disclosure.",
            },
        ],
        "receipt": [
            {"label": "Positive control", "value": "FARMER-1001 eligible"},
            {"label": "Negative control", "value": "FARMER-1003 already redeemed"},
            {"label": "Workbook exported", "value": "No"},
            {"label": "Scenario availability", "value": "Local-only"},
        ],
    }


def _preview_evaluate(claim_id: str, subject: str, disclosure: str) -> dict[str, Any]:
    credential = runtime_bearer_credential("agri-evidence", TOKEN_ENV)
    _, display_headers = _headers(credential)
    url = env_url(URL_ENV, DEFAULT_URL, "/v1/evaluations")
    display_headers["Content-Type"] = "application/json"
    body = evaluation_body(subject, claim_id, id_scheme="farmer_id", disclosure=disclosure)
    return request_source("POST", url, display_headers, body, internal=True)


def preview_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id == "discover":
        credential = runtime_bearer_credential("agri-evidence", TOKEN_ENV)
        _, display_headers = _headers(credential)
        url = env_url(URL_ENV, DEFAULT_URL, "/v1/claims")
        return request_source("GET", url, display_headers, internal=True)
    if step_id == "positive-voucher":
        return _preview_evaluate(CLAIM_ID, POSITIVE_SUBJECT, "predicate")
    if step_id == "inactive-parcel-control":
        return _preview_evaluate(CLAIM_ID, PARCEL_CONTROL, "predicate")
    if step_id == "redeemed-control":
        return _preview_evaluate(CLAIM_ID, REDEEMED_CONTROL, "predicate")
    if step_id == "reason-code":
        return _preview_evaluate(REASON_CLAIM_ID, REDEEMED_CONTROL, "value")
    return {}


def run_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id == "discover":
        return _discover(step_id)
    if step_id == "positive-voucher":
        return _evaluate(step_id, CLAIM_ID, POSITIVE_SUBJECT, "Amina is eligible", "predicate")
    if step_id == "inactive-parcel-control":
        return _evaluate(step_id, CLAIM_ID, PARCEL_CONTROL, "Inactive parcel control", "predicate")
    if step_id == "redeemed-control":
        return _evaluate(step_id, CLAIM_ID, REDEEMED_CONTROL, "Already-redeemed control", "predicate")
    if step_id == "reason-code":
        return _evaluate(step_id, REASON_CLAIM_ID, REDEEMED_CONTROL, "Reason code", "value")
    return standard_error_result(step_id)


def _headers(credential: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    return (
        {auth_name: auth_value, "Data-Purpose": AGRI_PURPOSE},
        {display_name: display_value, "Data-Purpose": AGRI_PURPOSE},
    )


def _discover(step_id: str) -> dict[str, Any]:
    credential = runtime_bearer_credential("agri-evidence", TOKEN_ENV)
    url = env_url(URL_ENV, DEFAULT_URL, "/v1/claims")
    real_headers, display_headers = _headers(credential)
    if not credential.get("token"):
        return {
            "step_id": step_id,
            "friendly": friendly_unavailable(SERVICE_NAME, TOKEN_ENV, url),
            "request_source": request_source("GET", url, display_headers, internal=True),
            "response_source": {"note": "No local agriculture token configured, so the request was not sent."},
        }
    result = http_json("GET", url, real_headers)
    claims = result.body.get("claims", []) if isinstance(result.body, dict) else []
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The agriculture Notary advertises voucher attestations." if ok_status(result.status) else "Agriculture discovery needs attention.",
            "message": "The supplier can discover the attestation catalogue before asking about a farmer.",
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Attestations advertised", "value": len(claims) if isinstance(claims, list) else "Check source"},
                {"label": "Availability", "value": "Local-only"},
            ],
        },
        "request_source": request_source("GET", url, display_headers, internal=True),
        "response_source": source_response(result),
    }


def _evaluate(step_id: str, claim_id: str, subject: str, label: str, disclosure: str) -> dict[str, Any]:
    credential = runtime_bearer_credential("agri-evidence", TOKEN_ENV)
    url = env_url(URL_ENV, DEFAULT_URL, "/v1/evaluations")
    real_headers, display_headers = _headers(credential)
    real_headers["Content-Type"] = "application/json"
    display_headers["Content-Type"] = "application/json"
    body = evaluation_body(subject, claim_id, id_scheme="farmer_id", disclosure=disclosure)
    if not credential.get("token"):
        return {
            "step_id": step_id,
            "friendly": friendly_unavailable(SERVICE_NAME, TOKEN_ENV, url),
            "request_source": request_source("POST", url, display_headers, body, internal=True),
            "response_source": {"note": "No local agriculture token configured, so the request was not sent."},
        }
    result = http_json("POST", url, real_headers, body)
    item = result_item(result.body, claim_id)
    answer = observed_answer(item)
    return {
        "step_id": step_id,
        "friendly": {
            "title": f"{label}: {_display_answer(answer)}.",
            "message": "The evidence result is enough for the supplier workflow without exporting workbook rows.",
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Farmer", "value": subject},
                {"label": "Requested attestation", "value": _public_attestation_name(claim_id)},
                {"label": "Answer", "value": _display_answer(answer)},
                {"label": "Workbook rows exported", "value": "No"},
            ],
        },
        "request_source": request_source("POST", url, display_headers, body, internal=True),
        "response_source": {
            "attestation_response": attestation_response(
                _public_attestation(claim_id),
                subject_type="Farmer",
                subject_id=subject,
                lookup_profile="by-source-record-id",
                claim_id=_public_claim_name(claim_id),
                claim_value=answer,
                match_method="source_record_id_exact",
            ),
            "http": source_response(result),
        },
    }


def _display_answer(answer: Any) -> str:
    if answer is True:
        return "Eligible"
    if answer is False:
        return "Not eligible"
    if answer is None:
        return "Unknown"
    return str(answer)


def _public_attestation_name(claim_id: str) -> str:
    if claim_id == REASON_CLAIM_ID:
        return "Benefit Conflict Attestation"
    return "Agricultural Entitlement Attestation"


def _public_attestation(claim_id: str) -> dict[str, Any]:
    if claim_id == REASON_CLAIM_ID:
        return PUBLIC_ATTESTATIONS[1]
    return PUBLIC_ATTESTATIONS[0]


def _public_claim_name(claim_id: str) -> str:
    if claim_id == REASON_CLAIM_ID:
        return "benefit_conflict_reason"
    return "agricultural_entitlement_active"
