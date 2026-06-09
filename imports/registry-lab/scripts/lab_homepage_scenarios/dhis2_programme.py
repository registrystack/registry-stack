#!/usr/bin/env python3
"""DHIS2 programme participation scenario based on the Bruno walkthrough."""

from __future__ import annotations

import time
from typing import Any

from .common import (
    auth_header_pair,
    configured_credential,
    display_auth_header_pair,
    http_json,
    joined_url,
    observed_answer,
    ok_status,
    request_source,
    result_item,
    simulated_request_source,
    simulated_response,
    source_response,
    standard_error_result,
)


SCENARIO_ID = "dhis2-programme-vc"
SUBJECT_ID = "PQfMcpmXeFE"
NEGATIVE_SUBJECT_ID = "vOxUH373fy5"
RECONCILIATION_REF = f"dhis2:tracked-entity:{SUBJECT_ID}"
PURPOSE = "https://demo.example.gov/purpose/dhis2-openfn-health-evidence"
CLAIM_RESULT_FORMAT = "application/vnd.registry-notary.claim-result+json"
SD_JWT_FORMAT = "application/dc+sd-jwt"
CCCEV_FORMAT = 'application/ld+json; profile="cccev"'
VC_PROFILE = "dhis2_programme_participation_sd_jwt"
HOLDER_DID = "did:jwk:eyJrdHkiOiJFZDI1NTE5IiwieCI6ImRoaXMyLWRlbW8taG9sZGVyIn0"
PROGRAMME_CLAIMS = [
    "dhis2-tracked-entity-first-name",
    "dhis2-tracked-entity-last-name",
    "dhis2-child-age-band",
    "dhis2-programme-code",
    "dhis2-child-program-active",
    "dhis2-reconciliation-ref",
]


def story() -> dict[str, Any]:
    return {
        "id": SCENARIO_ID,
        "title": "Can a DHIS2 programme record become holder-bound evidence without exposing tracker data?",
        "short_title": "DHIS2 programme participation VC",
        "proves": "A Notary can turn DHIS2 tracker facts into evidence, preview a holder-bound VC, and reconcile later with fresh online evidence.",
        "availability": "hosted",
        "intro": (
            "A programme team needs to prove that a child is active in a DHIS2 programme. "
            "The service should see the specific evidence claims and holder-binding shape, not raw DHIS2 tracker records."
        ),
        "actor": "Programme service",
        "subject": {"name": "DHIS2 tracked entity", "identifier": SUBJECT_ID},
        "boundary": {
            "allowed": "Ask the DHIS2 Notary for programme participation evidence.",
            "not_allowed": "Export raw DHIS2 tracker data or wallet private keys.",
        },
        "steps": [
            {
                "id": "discover",
                "label": "Discover DHIS2 evidence claims",
                "prompt": "Start with the Notary claim catalog so users can see what the DHIS2 demo supports.",
                "button": "Discover claims",
                "request_summary": "GET /v1/claims on the hosted DHIS2 Notary with the public demo bearer token.",
            },
            {
                "id": "evaluate-programme",
                "label": "Evaluate programme participation claims",
                "prompt": "Ask for the six claims Bruno uses before creating the programme participation credential.",
                "button": "Evaluate programme",
                "request_summary": "POST the DHIS2 tracked entity id with value disclosure and SD-JWT VC format.",
                "reuses": [
                    {"label": "Tracked entity", "value": SUBJECT_ID},
                    {"label": "Disclosure", "value": "value"},
                    {"label": "Format", "value": SD_JWT_FORMAT},
                ],
            },
            {
                "id": "preview-vc",
                "label": "Preview the holder-bound VC request",
                "prompt": "Bruno creates an Ed25519 holder proof before it calls /v1/credentials. The playground shows that request shape without generating a private key.",
                "button": "Preview VC",
                "request_summary": "Simulate the holder-bound credential request and wallet card. The raw proof and credential value stay hidden.",
                "reuses": [
                    {"label": "Credential profile", "value": VC_PROFILE},
                    {"label": "Claims", "value": "Six DHIS2 programme claims"},
                ],
            },
            {
                "id": "reconcile",
                "label": "Reconcile with fresh online evidence",
                "prompt": "Use the reconciliation reference to ask the Notary for a fresh predicate answer.",
                "button": "Reconcile evidence",
                "request_summary": "POST dhis2-child-program-active with predicate disclosure using the reconciliation reference.",
                "reuses": [{"label": "Reconciliation ref", "value": RECONCILIATION_REF}],
            },
            {
                "id": "negative-control",
                "label": "Run the inactive control",
                "prompt": "Check the Bruno negative subject to prove the Notary is not returning a blanket yes.",
                "button": "Run negative control",
                "request_summary": "POST dhis2-child-program-active for vOxUH373fy5 and expect the claim to be false.",
            },
            {
                "id": "render-cccev",
                "label": "Render CCCEV JSON-LD",
                "prompt": "For developers, render the same programme participation evidence as CCCEV JSON-LD.",
                "button": "Render CCCEV",
                "request_summary": "Evaluate the six DHIS2 claims in CCCEV format, then render the evaluation as JSON-LD.",
            },
        ],
        "receipt": [
            {"label": "Positive tracked entity", "value": SUBJECT_ID},
            {"label": "Programme active", "value": "Yes"},
            {"label": "Credential shape", "value": "Holder-bound SD-JWT VC"},
            {"label": "Fresh reconciliation", "value": "Yes"},
            {"label": "Raw tracker row exposed", "value": "No"},
        ],
    }


def run_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    if step_id == "discover":
        return _discover(config, step_id)
    if step_id == "evaluate-programme":
        return _evaluate_programme(config, step_id)
    if step_id == "preview-vc":
        return _preview_vc(config, step_id)
    if step_id == "reconcile":
        return _evaluate_single(config, step_id, RECONCILIATION_REF, "Fresh reconciliation", True)
    if step_id == "negative-control":
        return _evaluate_single(config, step_id, NEGATIVE_SUBJECT_ID, "Inactive programme control", False)
    if step_id == "render-cccev":
        return _render_cccev(config, step_id)
    return standard_error_result(step_id)


def _credential(config: dict[str, Any]) -> dict[str, Any]:
    return configured_credential(config, "dhis2-bearer")


def _url(config: dict[str, Any], path: str) -> str:
    credential = _credential(config)
    return joined_url(str(credential.get("service_url", "https://dhis2-notary.lab.registrystack.org")), path)


def _headers(config: dict[str, Any], extra: dict[str, str] | None = None) -> tuple[dict[str, str], dict[str, str]]:
    credential = _credential(config)
    auth_name, auth_value = auth_header_pair(credential)
    display_name, display_value = display_auth_header_pair(credential)
    real = {auth_name: auth_value, **(extra or {})}
    display = {display_name: display_value, **(extra or {})}
    return real, display


def _tracked_entity_body(subject: str, claims: list[str], disclosure: str, fmt: str) -> dict[str, Any]:
    return {
        "target": {
            "type": "TrackedEntity",
            "identifiers": [{"scheme": "dhis2_tracked_entity", "value": subject}],
        },
        "claims": claims,
        "disclosure": disclosure,
        "format": fmt,
    }


def _discover(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    url = _url(config, "/v1/claims")
    real_headers, display_headers = _headers(config)
    result = http_json("GET", url, real_headers)
    claims = result.body.get("claims", []) if isinstance(result.body, dict) else []
    claim_ids = {item.get("id") for item in claims if isinstance(item, dict)}
    programme_claims_present = all(claim in claim_ids for claim in PROGRAMME_CLAIMS)
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The DHIS2 Notary advertises programme evidence claims." if ok_status(result.status) else "DHIS2 claim discovery needs attention.",
            "message": "The catalogue shows the claims that can be computed from DHIS2 through the Notary.",
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Claims advertised", "value": len(claims) if isinstance(claims, list) else "Check source"},
                {"label": "Programme claims present", "value": "Yes" if programme_claims_present else "Check source"},
                {"label": "Token", "value": "Public DHIS2 demo bearer"},
            ],
        },
        "request_source": request_source("GET", url, display_headers),
        "response_source": source_response(result),
    }


def _evaluate_programme(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    url = _url(config, "/v1/evaluations")
    body = _tracked_entity_body(SUBJECT_ID, PROGRAMME_CLAIMS, "value", SD_JWT_FORMAT)
    real_headers, display_headers = _headers(config, {"Content-Type": "application/json", "Data-Purpose": PURPOSE})
    result = http_json("POST", url, real_headers, body)
    facts = _programme_facts(result.body)
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The programme participation claims are ready." if ok_status(result.status) else "Programme evaluation needs attention.",
            "message": "The response contains claim-level evidence for the credential workflow, without exposing the raw DHIS2 tracker row.",
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Tracked entity", "value": SUBJECT_ID},
                {"label": "Claims returned", "value": facts["claim_count"]},
                {"label": "Programme active", "value": facts["active"]},
                {"label": "Reconciliation ref", "value": facts["reconciliation_ref"]},
            ],
        },
        "request_source": request_source("POST", url, display_headers, body),
        "response_source": source_response(result),
    }


def _programme_facts(body: Any) -> dict[str, Any]:
    results = body.get("results", []) if isinstance(body, dict) else []
    by_claim = {item.get("claim_id"): item for item in results if isinstance(item, dict)}
    active = observed_answer(by_claim.get("dhis2-child-program-active", {}))
    reconciliation_ref = observed_answer(by_claim.get("dhis2-reconciliation-ref", {}))
    return {
        "claim_count": len(results) if isinstance(results, list) else "Check source",
        "active": "Yes" if active is True else ("No" if active is False else "Unknown"),
        "reconciliation_ref": reconciliation_ref or RECONCILIATION_REF,
    }


def _preview_vc(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    url = _url(config, "/v1/credentials")
    issued_at = int(time.time())
    request_body = {
        "evaluation_id": "[evaluation id from Step 2]",
        "credential_profile": VC_PROFILE,
        "format": SD_JWT_FORMAT,
        "claims": PROGRAMME_CLAIMS,
        "disclosure": "value",
        "holder": {
            "binding": "did",
            "id": HOLDER_DID,
            "proof": "[Ed25519 holder proof generated by Bruno, hidden in this playground]",
        },
    }
    credential_preview = {
        "credential_profile": VC_PROFILE,
        "format": SD_JWT_FORMAT,
        "issuer": "did:web:dhis2-notary.lab.registrystack.org",
        "vct": "https://dhis2-notary.lab.registrystack.org/credentials/dhis2/programme-participation/v1",
        "holder": HOLDER_DID,
        "subject": SUBJECT_ID,
        "claims": {
            "dhis2-child-age-band": "5_to_17",
            "dhis2-programme-code": "DHIS2_CHILD_PROGRAM",
            "dhis2-child-program-active": True,
            "dhis2-reconciliation-ref": RECONCILIATION_REF,
        },
        "issued_at_unix": issued_at,
        "expires_at_unix": issued_at + 365 * 24 * 60 * 60,
        "raw_credential": "[holder-bound SD-JWT VC hidden]",
    }
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The holder-bound credential shape is ready to inspect.",
            "message": "Bruno signs the holder proof with Ed25519. The playground keeps that private-key operation simulated and shows the request shape and wallet-facing result.",
            "status": "done",
            "facts": [
                {"label": "Credential profile", "value": VC_PROFILE},
                {"label": "Holder DID", "value": HOLDER_DID[:30] + "..."},
                {"label": "Programme active", "value": "Yes"},
                {"label": "Raw credential printed", "value": "No"},
            ],
        },
        "request_source": simulated_request_source(url, request_body),
        "response_source": simulated_response(credential_preview),
    }


def _evaluate_single(config: dict[str, Any], step_id: str, subject: str, label: str, expected: bool) -> dict[str, Any]:
    url = _url(config, "/v1/evaluations")
    body = _tracked_entity_body(subject, ["dhis2-child-program-active"], "predicate", CLAIM_RESULT_FORMAT)
    real_headers, display_headers = _headers(config, {"Content-Type": "application/json", "Data-Purpose": PURPOSE})
    result = http_json("POST", url, real_headers, body)
    item = result_item(result.body, "dhis2-child-program-active")
    answer = observed_answer(item)
    return {
        "step_id": step_id,
        "friendly": {
            "title": f"{label}: {'active' if answer is True else 'not active' if answer is False else 'check source'}.",
            "message": "The Notary recomputes the predicate from DHIS2-backed evidence and returns a decision-ready answer.",
            "status": "done" if ok_status(result.status) and answer is expected else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Tracked entity", "value": subject},
                {"label": "Expected", "value": "Active" if expected else "Not active"},
                {"label": "Observed", "value": "Active" if answer is True else ("Not active" if answer is False else "Unknown")},
                {"label": "Source count", "value": item.get("provenance", {}).get("source_count", "Check source")},
            ],
        },
        "request_source": request_source("POST", url, display_headers, body),
        "response_source": source_response(result),
    }


def _render_cccev(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    eval_url = _url(config, "/v1/evaluations")
    eval_body = _tracked_entity_body(SUBJECT_ID, PROGRAMME_CLAIMS, "value", CCCEV_FORMAT)
    real_headers, display_headers = _headers(
        config,
        {"Accept": CCCEV_FORMAT, "Content-Type": "application/json", "Data-Purpose": PURPOSE},
    )
    eval_result = http_json("POST", eval_url, real_headers, eval_body)
    if not ok_status(eval_result.status):
        return {
            "step_id": step_id,
            "friendly": {
                "title": "CCCEV evaluation needs attention.",
                "message": "The Notary did not create a CCCEV-bound evaluation. Inspect the response source for the exact status.",
                "status": "needs_attention",
                "facts": [
                    {"label": "HTTP status", "value": eval_result.status if eval_result.status is not None else "No response"},
                    {"label": "Format", "value": CCCEV_FORMAT},
                ],
            },
            "request_source": request_source("POST", eval_url, display_headers, eval_body),
            "response_source": source_response(eval_result),
        }

    evaluation_id = _first_evaluation_id(eval_result.body)
    render_url = _url(config, f"/v1/evaluations/{evaluation_id}/render")
    render_body = {"claims": PROGRAMME_CLAIMS, "disclosure": "value", "format": CCCEV_FORMAT}
    render_headers, render_display_headers = _headers(config, {"Content-Type": "application/json"})
    render_result = http_json("POST", render_url, render_headers, render_body)
    graph = render_result.body.get("@graph", []) if isinstance(render_result.body, dict) else []
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The DHIS2 evidence rendered as CCCEV JSON-LD." if ok_status(render_result.status) else "CCCEV render needs attention.",
            "message": "This is the developer view: the same programme evidence can be represented as interoperable CCCEV JSON-LD.",
            "status": "done" if ok_status(render_result.status) else "needs_attention",
            "facts": [
                {"label": "Evaluation HTTP status", "value": eval_result.status},
                {"label": "Render HTTP status", "value": render_result.status if render_result.status is not None else "No response"},
                {"label": "Evidence nodes", "value": len(graph) if isinstance(graph, list) else "Check source"},
                {"label": "Format", "value": CCCEV_FORMAT},
            ],
        },
        "request_source": {
            "evaluation": request_source("POST", eval_url, display_headers, eval_body),
            "render": request_source("POST", render_url, render_display_headers, render_body),
        },
        "response_source": {
            "evaluation": source_response(eval_result),
            "render": source_response(render_result),
        },
    }


def _first_evaluation_id(body: Any) -> str:
    results = body.get("results", []) if isinstance(body, dict) else []
    if results and isinstance(results[0], dict):
        return str(results[0].get("evaluation_id", ""))
    return ""
