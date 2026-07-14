#!/usr/bin/env python3
"""Source-free self-attested Notary scenario."""

from __future__ import annotations

from typing import Any

from .common import (
    CLAIM_RESULT_FORMAT,
    auth_header_pair,
    configured_credential,
    display_auth_header_pair,
    evaluation_body,
    http_json,
    ok_status,
    request_source,
    result_item,
    service_url,
    source_response,
    standard_error_result,
)


SCENARIO_ID = "self-attested-declaration"
CREDENTIAL_ID = "self-attested-evidence"
CLAIM_ID = "applicant-declaration"
SUBJECT_ID = "demo-applicant"
PURPOSE = "application-processing"


def story() -> dict[str, Any]:
    return {
        "id": SCENARIO_ID,
        "title": "Can an application use a declaration without consulting a registry?",
        "short_title": "Self-attested declaration",
        "proves": "A Notary-only deployment can evaluate an applicant declaration with no Relay or registry source.",
        "domain": "Application processing",
        "availability": "hosted",
        "availability_state": {"state": "hosted", "label": "Hosted", "runnable": True},
        "intro": "You are testing the source-free Notary topology. The applicant supplies the declaration directly.",
        "actor": "Application service",
        "subject": {"name": "Demo applicant", "identifier": SUBJECT_ID},
        "requester": {"name": "Application service", "purpose": PURPOSE},
        "requested_attestations": [],
        "lookup_profile": {"id": "none", "label": "No registry lookup", "identifier_scheme": "applicant_id"},
        "non_disclosure": ["No registry row exists in this journey", "No Relay credential is used"],
        "proof_facts": [
            "The claim uses evidence_mode self_attested.",
            "The Notary evaluates only the applicant declaration.",
        ],
        "boundary": {
            "allowed": "Evaluate the applicant declaration for application processing.",
            "not_allowed": "Consult a registry or infer a registry-backed fact.",
        },
        "steps": [
            {
                "id": "discover",
                "label": "Discover the declaration claim",
                "prompt": "Ask the self-attested Notary which declaration it can evaluate.",
                "button": "Run discovery",
                "request_summary": "GET the self-attested Notary claim catalogue.",
            },
            {
                "id": "evaluate",
                "label": "Evaluate the declaration",
                "prompt": "Submit the synthetic applicant declaration for the allowed purpose.",
                "button": "Evaluate declaration",
                "request_summary": "POST the applicant declaration directly to the Notary.",
                "reuses": [
                    {"label": "Claim", "value": CLAIM_ID},
                    {"label": "Acquisition path", "value": "self_attested"},
                    {"label": "Registry consulted", "value": "No"},
                ],
            },
        ],
        "receipt": [
            {"label": "Claim evaluated", "value": "Applicant declaration"},
            {"label": "Registry consulted", "value": "No"},
            {"label": "Relay required", "value": "No"},
        ],
    }


def preview_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    credential = configured_credential(config, CREDENTIAL_ID)
    display_name, display_value = display_auth_header_pair(credential)
    if step_id == "discover":
        return request_source(
            "GET",
            service_url(config, CREDENTIAL_ID, "/v1/claims"),
            {display_name: display_value},
        )
    if step_id == "evaluate":
        return request_source(
            "POST",
            service_url(config, CREDENTIAL_ID, "/v1/evaluations"),
            {display_name: display_value, "Content-Type": "application/json", "Data-Purpose": PURPOSE},
            evaluation_body(SUBJECT_ID, CLAIM_ID, id_scheme="applicant_id"),
        )
    return {}


def run_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id not in {"discover", "evaluate"}:
        return standard_error_result(step_id)
    credential = configured_credential(config, CREDENTIAL_ID)
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    if step_id == "discover":
        url = service_url(config, CREDENTIAL_ID, "/v1/claims")
        result = http_json("GET", url, {auth_name: auth_value})
        claims = result.body.get("data") if isinstance(result.body, dict) else []
        claim_ids = {
            str(item.get("id")) for item in claims if isinstance(item, dict)
        } if isinstance(claims, list) else set()
        return {
            "step_id": step_id,
            "friendly": {
                "status": "done" if ok_status(result.status) and CLAIM_ID in claim_ids else "needs_attention",
                "title": "The self-attested declaration is available.",
                "message": "Discovery exposes a source-free claim and does not advertise a registry acquisition path.",
                "facts": [
                    {"label": "Claim", "value": CLAIM_ID},
                    {"label": "Registry consulted", "value": "No"},
                ],
            },
            "request_source": request_source("GET", url, {display_name: display_value}),
            "response_source": source_response(result),
        }
    url = service_url(config, CREDENTIAL_ID, "/v1/evaluations")
    body = evaluation_body(SUBJECT_ID, CLAIM_ID, id_scheme="applicant_id")
    headers = {auth_name: auth_value, "Content-Type": "application/json", "Data-Purpose": PURPOSE}
    result = http_json("POST", url, headers, body)
    answer = result_item(result.body, CLAIM_ID)
    return {
        "step_id": step_id,
        "friendly": {
            "status": "done" if ok_status(result.status) and answer.get("satisfied") is True else "needs_attention",
            "title": "The declaration was evaluated without a registry.",
            "message": "The Notary used only the applicant-provided declaration.",
            "facts": [
                {"label": "Satisfied", "value": answer.get("satisfied")},
                {"label": "Acquisition path", "value": "self_attested"},
                {"label": "Registry consulted", "value": "No"},
            ],
        },
        "request_source": request_source(
            "POST",
            url,
            {display_name: display_value, "Content-Type": "application/json", "Data-Purpose": PURPOSE},
            body,
        ),
        "response_source": source_response(result),
    }
