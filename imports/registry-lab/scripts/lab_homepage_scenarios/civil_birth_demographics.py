#!/usr/bin/env python3
"""Civil Relay demographic vital-status lookup scenario."""

from __future__ import annotations

import os
from typing import Any

from .attestations import attestation
from .common import (
    CLAIM_RESULT_FORMAT,
    auth_header_pair,
    claims_catalog,
    configured_credential,
    display_auth_header_pair,
    evaluation_body_from_claim_metadata,
    http_json,
    joined_url,
    observed_answer,
    ok_status,
    person_profile,
    request_source,
    result_item,
    source_response,
    standard_error_result,
    target_input_facts,
)


SCENARIO_ID = "civil-birth-demographics"
SERVICE_NAME = "Civil Notary"
CREDENTIAL_ID = "civil-notary-evidence"
DEFAULT_URL = "http://127.0.0.1:4321"
PURPOSE = "https://demo.example.gov/purpose/decentralized-evidence-demo"

CLAIM_ID = "civil-person-is-alive-by-demographics"
PUBLIC_ATTESTATION = attestation("vital-status-attestation")
SUBJECT_NAME = "Miguel Santos"
SUBJECT_PROFILE = person_profile(
    "",
    attributes={
        "given_name": "Miguel",
        "family_name": "Santos",
        "birthdate": "2016-01-15",
    },
)

EXPECTED_CLAIMS_BODY = {
    "data": [
        {
            "id": CLAIM_ID,
            "target_inputs": [
                {
                    "target_type": "Person",
                    "method": "configured_demographic_lookup",
                    "groups": [
                        {
                            "inputs": [
                                {
                                    "path": "target.attributes.given_name",
                                    "kind": "attribute",
                                    "name": "given_name",
                                    "label": "Given name",
                                },
                                {
                                    "path": "target.attributes.family_name",
                                    "kind": "attribute",
                                    "name": "family_name",
                                    "label": "Family name",
                                },
                                {
                                    "path": "target.attributes.birthdate",
                                    "kind": "attribute",
                                    "name": "birthdate",
                                    "label": "Birthdate",
                                },
                            ]
                        }
                    ],
                }
            ],
        }
    ]
}


def story() -> dict[str, Any]:
    return {
        "id": SCENARIO_ID,
        "title": "Can an SP MIS check Miguel's vital status with name and date of birth instead of an ID?",
        "short_title": "Civil Lookup Without an ID",
        "proves": "The Civil Notary publishes a Relay-backed demographic input contract and accepts a vital-status lookup with given name, family name, and birthdate.",
        "domain": "Civil registry",
        "availability": "hosted",
        "availability_state": {"state": "hosted", "label": "Hosted", "runnable": True},
        "intro": (
            "You are checking Miguel's vital status when the caller does not have a national ID. The Explorer first "
            "asks the Notary what target inputs the claim accepts, then sends only the demographic fields the Notary published."
        ),
        "actor": "Social Protection MIS",
        "requester": {"name": "Social Protection MIS", "purpose": PURPOSE},
        "subject": {"name": SUBJECT_NAME, "identifier": "No ID supplied"},
        "requested_attestations": [PUBLIC_ATTESTATION],
        "lookup_profile": {"id": "by-demographics", "label": "Name and date of birth"},
        "non_disclosure": [
            "National ID",
            "Full civil registry row",
            "Unrequested household, address, or relationship attributes",
        ],
        "proof_facts": [
            "The Notary publishes target_inputs in claim discovery.",
            "The evaluation request contains demographic attributes only.",
            "The response is a minimized vital-status attestation result from a Relay-backed source.",
        ],
        "boundary": {
            "allowed": "Ask for the Vital Status Attestation using the published demographic input contract.",
            "not_allowed": "Invent an identifier lookup, read a civil registry row, or send extra personal attributes.",
        },
        "steps": [
            {
                "id": "discover",
                "label": "Discover the input contract",
                "prompt": "Ask the Civil Notary which target inputs it accepts for the demographic vital-status claim.",
                "button": "Discover Civil claim inputs",
                "request_summary": "GET /v1/claims and inspect the target_inputs for the demographic vital-status claim.",
            },
            {
                "id": "lookup",
                "label": "Lookup without an ID",
                "prompt": "Use the published contract to ask whether Miguel is alive using only name and date of birth.",
                "button": "Check by name and date of birth",
                "request_summary": "POST an evaluation with target.attributes.given_name, family_name, and birthdate, not target.identifiers.",
                "reuses": [
                    {"label": "Attestation", "value": PUBLIC_ATTESTATION["display_name"]},
                    {"label": "Lookup profile", "value": "by-demographics"},
                    {"label": "Boundary", "value": "Ask with target_inputs, not an ID fallback"},
                ],
            },
        ],
        "receipt": [
            {"label": "ID number sent", "value": "No"},
            {"label": "Target inputs", "value": "Given name + family name + birthdate"},
            {"label": "Contract source", "value": "Notary /v1/claims discovery"},
            {"label": "Raw civil row exposed", "value": "No"},
        ],
    }


def preview_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    credential = _credential(config)
    display_headers = _display_headers(credential)
    if step_id == "discover":
        return request_source("GET", _claims_url(config), display_headers, internal=True)
    if step_id == "lookup":
        body, selection = _evaluation_body(EXPECTED_CLAIMS_BODY)
        return request_source(
            "POST",
            _evaluations_url(config),
            {**display_headers, "Content-Type": "application/json"},
            body,
            internal=True,
            target_input_selection=selection,
        )
    return {}


def run_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id == "discover":
        return _discover(config, step_id)
    if step_id == "lookup":
        return _lookup(config, step_id)
    return standard_error_result(step_id)


def _credential(config: dict[str, Any]) -> dict[str, Any]:
    credential = {
        **configured_credential(config, CREDENTIAL_ID),
        "id": CREDENTIAL_ID,
        "env": "CIVIL_EVIDENCE_CLIENT_BEARER",
        "token": os.environ.get("CIVIL_EVIDENCE_CLIENT_BEARER", ""),
        "auth_scheme": "bearer",
        "display_policy": "runtime-hidden",
    }
    if not credential.get("service_url"):
        credential["service_url"] = os.environ.get("CIVIL_EVIDENCE_URL") or DEFAULT_URL
    return credential


def _headers(credential: dict[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    return {auth_name: auth_value, "Data-Purpose": PURPOSE}, {display_name: display_value, "Data-Purpose": PURPOSE}


def _display_headers(credential: dict[str, Any]) -> dict[str, str]:
    _, display_headers = _headers(credential)
    return display_headers


def _base_url(config: dict[str, Any]) -> str:
    return str(_credential(config).get("service_url") or DEFAULT_URL)


def _claims_url(config: dict[str, Any]) -> str:
    return joined_url(_base_url(config), "/v1/claims")


def _evaluations_url(config: dict[str, Any]) -> str:
    return joined_url(_base_url(config), "/v1/evaluations")


def _evaluation_body(claims_body: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    return evaluation_body_from_claim_metadata(
        claims_body,
        SUBJECT_PROFILE,
        [CLAIM_ID],
        disclosure="predicate",
        fmt=CLAIM_RESULT_FORMAT,
    )


def _missing_token_result(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    credential = _credential(config)
    return {
        "step_id": step_id,
        "friendly": {
            "title": f"{SERVICE_NAME} credential is not configured.",
            "message": "Set the Civil Notary evidence credential before running this hosted scenario.",
            "status": "needs_attention",
            "facts": [
                {"label": "Endpoint", "value": _base_url(config)},
                {"label": "Required token env", "value": credential.get("env", "CIVIL_EVIDENCE_CLIENT_BEARER")},
            ],
        },
        "request_source": preview_step(config, step_id),
        "response_source": {"note": "No Civil Notary evidence credential configured, so the request was not sent."},
    }


def _discover(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    credential = _credential(config)
    if not credential.get("token"):
        return _missing_token_result(config, step_id)
    real_headers, display_headers = _headers(credential)
    result = http_json("GET", _claims_url(config), real_headers)
    claims = claims_catalog(result.body)
    claim_ids = {claim.get("id") for claim in claims if isinstance(claim, dict)}
    facts = target_input_facts(result.body, [CLAIM_ID])
    published = CLAIM_ID in claim_ids and any(fact.get("label") == "Input metadata" for fact in facts)
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The Civil Notary publishes the demographic input contract." if published else "Civil claim discovery needs attention.",
            "message": (
                "The target_inputs metadata says this claim can be evaluated with given name, family name, and birthdate."
                if published
                else "The demographic claim or its target_inputs metadata was not present in /v1/claims."
            ),
            "status": "done" if published else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Claim", "value": CLAIM_ID if CLAIM_ID in claim_ids else "Missing"},
            ]
            + facts,
        },
        "request_source": request_source("GET", _claims_url(config), display_headers, internal=True),
        "response_source": source_response(result),
    }


def _lookup(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    credential = _credential(config)
    if not credential.get("token"):
        return _missing_token_result(config, step_id)
    real_headers, display_headers = _headers(credential)
    discovery = http_json("GET", _claims_url(config), real_headers)
    body, selection = _evaluation_body(discovery.body)
    if selection.get("source") != "target_inputs":
        return {
            "step_id": step_id,
            "friendly": {
                "title": "The Civil Notary has not published the demographic input contract.",
                "message": "The Explorer did not send the evaluation because /v1/claims did not describe the required target inputs.",
                "status": "needs_attention",
                "facts": [
                    {"label": "HTTP status", "value": discovery.status if discovery.status is not None else "No response"},
                    {"label": "Claim", "value": CLAIM_ID},
                    {"label": "Evaluation sent", "value": "No"},
                ]
                + target_input_facts(discovery.body, [CLAIM_ID]),
            },
            "request_source": request_source("GET", _claims_url(config), display_headers, internal=True),
            "response_source": source_response(discovery),
        }

    result = http_json(
        "POST",
        _evaluations_url(config),
        {**real_headers, "Content-Type": "application/json"},
        body,
    )
    return {
        "step_id": step_id,
        "friendly": _summarize_lookup(result),
        "request_source": request_source(
            "POST",
            _evaluations_url(config),
            {**display_headers, "Content-Type": "application/json"},
            body,
            internal=True,
            target_input_selection=selection,
        ),
        "response_source": source_response(result),
    }


def _summarize_lookup(result) -> dict[str, Any]:
    item = result_item(result.body, CLAIM_ID)
    answer = observed_answer(item)
    ok = ok_status(result.status)
    matched = ok and answer is True
    reason = ""
    if isinstance(result.body, dict):
        reason = result.body.get("code") or result.body.get("title") or ""
    reason = reason or result.error or "None"
    if matched:
        title = "The vital status was checked without sending an ID."
        message = "The Notary evaluated the claim from the published demographic inputs and returned only the requested attestation result."
        status = "done"
    elif result.status == 409:
        title = "The demographic lookup was not uniquely available."
        message = (
            "The request shape is valid, but the live Civil Relay search did not produce one usable record. "
            "That is still safer than falling back to an invented identifier lookup."
        )
        status = "denied_as_expected"
    else:
        title = "The Civil demographic lookup needs attention."
        message = "The Notary did not return the expected vital-status result. Inspect the response source."
        status = "needs_attention"
    return {
        "title": title,
        "message": message,
        "status": status,
        "facts": [
            {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
            {"label": "Subject", "value": SUBJECT_NAME},
            {"label": "Lookup key", "value": "Given name + family name + birthdate"},
            {"label": "Identifier sent", "value": "No"},
            {"label": "Answer", "value": "Yes" if answer is True else ("No" if answer is False else "Unknown")},
            {"label": "Reason", "value": reason},
        ],
    }
