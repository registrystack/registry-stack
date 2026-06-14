#!/usr/bin/env python3
"""Simulated wallet credential explorer scenario."""

from __future__ import annotations

import time
from typing import Any

from .attestations import attestation
from .common import (
    http_json,
    joined_url,
    ok_status,
    request_source,
    simulated_request_source,
    simulated_response,
    source_response,
    standard_error_result,
)


SCENARIO_ID = "wallet-credential"
SUBJECT_ID = "NID-2001"
SUBJECT_NAME = "Maria Santos"
CLAIM_ID = "person-is-alive"
HOLDER_DID = "did:jwk:eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImxhYiIsInkiOiJ3YWxsZXQifQ"
PUBLIC_ATTESTATION = attestation("vital-status-attestation")


def story() -> dict[str, Any]:
    return {
        "id": SCENARIO_ID,
        "title": "What would Maria see when a Vital Status credential lands in her wallet?",
        "short_title": "Wallet credential explorer",
        "proves": "A non-developer can inspect a credential as a wallet card, while developers can inspect issuer metadata and holder binding.",
        "domain": "Credentials",
        "availability": "hosted",
        "availability_state": {"state": "hosted", "label": "Hosted", "runnable": True},
        "intro": (
            "Maria is an adult demo citizen. This scenario simulates the wallet client so the demo stays easy to run, "
            "then shows the credential in a friendly wallet-style viewer."
        ),
        "actor": "Demo citizen wallet",
        "subject": {"name": SUBJECT_NAME, "identifier": SUBJECT_ID},
        "requester": {"name": "Maria's wallet", "purpose": "OID4VCI citizen credential preview"},
        "requested_attestations": [PUBLIC_ATTESTATION],
        "lookup_profile": {"id": "by-national-id", "label": "National ID lookup", "identifier_scheme": "national_id"},
        "non_disclosure": [
            "Full civil registry row",
            "Wallet private key",
            "Raw credential value in the friendly card",
        ],
        "proof_facts": [
            "Credential is holder-bound to the wallet DID.",
            "The playground hides holder proof material.",
            "The issuer advertises the credential profile through OID4VCI metadata.",
        ],
        "boundary": {
            "allowed": "Issue a Vital Status credential to Maria's wallet.",
            "not_allowed": "Expose the full civil registry record or wallet proof secret.",
        },
        "steps": [
            {
                "id": "issuer-metadata",
                "label": "Read issuer metadata",
                "prompt": "First, let the wallet discover what the Citizen Notary can issue.",
                "button": "Load issuer metadata",
                "request_summary": "GET the issuer metadata from the hosted Citizen Notary.",
            },
            {
                "id": "credential-offer",
                "label": "Build the credential offer",
                "prompt": "Next, fetch the offer URL a wallet would import after login.",
                "button": "Fetch offer",
                "request_summary": "GET the OID4VCI credential-offer endpoint for the Vital Status credential configuration.",
                "reuses": [
                    {"label": "Issuer", "value": "Citizen Notary"},
                    {"label": "Credential type", "value": "Vital Status credential"},
                ],
            },
            {
                "id": "holder-key",
                "label": "Create a holder key",
                "prompt": "The wallet creates a holder key locally. This step is simulated so no device secret is generated or shown.",
                "button": "Simulate holder key",
                "request_summary": "Simulate wallet key creation and keep the private key out of the source view.",
            },
            {
                "id": "nonce",
                "label": "Request a nonce",
                "prompt": "The wallet asks the issuer for a nonce before it proves control of the holder key.",
                "button": "Request nonce",
                "request_summary": "POST a nonce request to the issuer. If the endpoint is unavailable, the UI explains that clearly.",
                "reuses": [{"label": "Holder binding", "value": "DID created in Step 3"}],
            },
            {
                "id": "credential-preview",
                "label": "Explore the wallet credential",
                "prompt": "Finally, look at the credential as a user-facing card, with source available only on demand.",
                "button": "Show credential",
                "request_summary": "Simulate the credential response the wallet would store for Maria.",
                "reuses": [
                    {"label": "Subject", "value": SUBJECT_ID},
                    {"label": "Holder DID", "value": HOLDER_DID[:26] + "..."},
                ],
            },
        ],
        "receipt": [
            {"label": "Wallet subject", "value": f"{SUBJECT_NAME} ({SUBJECT_ID})"},
            {"label": "Credential", "value": "Vital Status credential"},
            {"label": "Holder-bound", "value": "Yes"},
            {"label": "Private wallet key exposed", "value": "No"},
        ],
    }


def preview_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    wallet = config.get("wallet", {})
    issuer = str(wallet.get("issuer", "https://citizen-notary.lab.registrystack.org")).rstrip("/")
    credential_config = str(wallet.get("credential_configuration_id", "person_is_alive_sd_jwt"))
    if step_id == "issuer-metadata":
        url = joined_url(issuer, "/.well-known/openid-credential-issuer")
        return request_source("GET", url, {})
    if step_id == "credential-offer":
        url = wallet.get("offer_url") or joined_url(
            issuer,
            f"/oid4vci/credential-offer?credential_configuration_id={credential_config}",
        )
        return request_source("GET", str(url), {})
    if step_id == "holder-key":
        return simulated_request_source("wallet://holder-key", {"operation": "create holder key"})
    if step_id == "nonce":
        body = {
            "credential_configuration_id": credential_config,
            "holder_did": HOLDER_DID,
            "issuer_session": "[authenticated issuance session simulated]",
        }
        return simulated_request_source("wallet://issuer-session/nonce", body)
    if step_id == "credential-preview":
        return simulated_request_source(
            "wallet://credential-request",
            {"credential_configuration_id": credential_config, "holder_did": HOLDER_DID, "proof": "[wallet proof hidden]"},
        )
    return {}


def run_step(config: dict[str, Any], step_id: str) -> dict[str, Any]:
    wallet = config.get("wallet", {})
    issuer = str(wallet.get("issuer", "https://citizen-notary.lab.registrystack.org")).rstrip("/")
    credential_config = str(wallet.get("credential_configuration_id", "person_is_alive_sd_jwt"))
    if step_id == "issuer-metadata":
        return _issuer_metadata(step_id, issuer, credential_config)
    if step_id == "credential-offer":
        return _credential_offer(step_id, wallet, issuer, credential_config)
    if step_id == "holder-key":
        return _holder_key(step_id)
    if step_id == "nonce":
        return _nonce(step_id, issuer, credential_config)
    if step_id == "credential-preview":
        return _credential_preview(step_id, issuer, credential_config)
    return standard_error_result(step_id)


def _issuer_metadata(step_id: str, issuer: str, credential_config: str) -> dict[str, Any]:
    url = joined_url(issuer, "/.well-known/openid-credential-issuer")
    result = http_json("GET", url, {})
    body = result.body if isinstance(result.body, dict) else {}
    supported = body.get("credential_configurations_supported", {})
    config_present = isinstance(supported, dict) and credential_config in supported
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The issuer advertises the wallet credential." if config_present or ok_status(result.status) else "Issuer metadata needs attention.",
            "message": (
                "The wallet can discover the credential issuer and the supported credential configuration before requesting anything."
                if ok_status(result.status)
                else "The hosted issuer metadata endpoint did not respond as expected. Inspect the technical response."
            ),
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Issuer", "value": body.get("credential_issuer") or issuer},
                {"label": "Credential configuration", "value": credential_config},
                {"label": "Configuration advertised", "value": "Yes" if config_present else "Check source"},
            ],
        },
        "request_source": request_source("GET", url, {}),
        "response_source": source_response(result),
    }


def _credential_offer(step_id: str, wallet: dict[str, Any], issuer: str, credential_config: str) -> dict[str, Any]:
    url = wallet.get("offer_url") or joined_url(
        issuer,
        f"/oid4vci/credential-offer?credential_configuration_id={credential_config}",
    )
    result = http_json("GET", str(url), {})
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The offer endpoint returned a wallet handoff." if ok_status(result.status) else "The offer endpoint needs attention.",
            "message": (
                "In the real hosted flow, this offer is imported into the wallet after Maria signs in."
                if ok_status(result.status)
                else "The offer endpoint did not return a successful response. The wallet scenario can still continue with simulation."
            ),
            "status": "done" if ok_status(result.status) else "needs_attention",
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Offer type", "value": "OID4VCI credential offer"},
                {"label": "Subject selected for story", "value": f"{SUBJECT_NAME} ({SUBJECT_ID})"},
            ],
        },
        "request_source": request_source("GET", str(url), {}),
        "response_source": source_response(result),
    }


def _holder_key(step_id: str) -> dict[str, Any]:
    body = {"holder_did": HOLDER_DID, "private_key": "[never shown by this playground]"}
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The wallet now has a holder identity.",
            "message": "The public holder DID can be used in a proof. The private key stays in the wallet and is not printed here.",
            "status": "done",
            "facts": [
                {"label": "Holder DID", "value": HOLDER_DID[:42] + "..."},
                {"label": "Private key exposed", "value": "No"},
                {"label": "Why it matters", "value": "The issued credential can be holder-bound."},
            ],
        },
        "request_source": simulated_request_source("wallet://holder-key", {"operation": "create holder key"}),
        "response_source": simulated_response(body),
    }


def _nonce(step_id: str, issuer: str, credential_config: str) -> dict[str, Any]:
    body = {
        "credential_configuration_id": credential_config,
        "holder_did": HOLDER_DID,
        "issuer_session": "[authenticated issuance session simulated]",
    }
    nonce = {
        "c_nonce": "wallet-demo-nonce-2026",
        "c_nonce_expires_in": 300,
        "issuer": issuer,
        "note": "The hosted issuer provides the real nonce inside the authenticated issuance session.",
    }
    return {
        "step_id": step_id,
        "friendly": {
            "title": "The issuer nonce is ready for the simulated wallet session.",
            "message": "The wallet uses this challenge when proving control of the holder key. The real hosted flow gets this value inside the authenticated issuance session, so this playground simulates that session boundary.",
            "status": "done",
            "facts": [
                {"label": "Operation", "value": "Simulated authenticated issuer session"},
                {"label": "Holder DID reused", "value": HOLDER_DID[:26] + "..."},
                {"label": "Nonce expires in", "value": "300 seconds"},
                {"label": "Proof secret shown", "value": "No"},
            ],
        },
        "request_source": simulated_request_source("wallet://issuer-session/nonce", body),
        "response_source": simulated_response(nonce),
    }


def _credential_preview(step_id: str, issuer: str, credential_config: str) -> dict[str, Any]:
    issued_at = int(time.time())
    credential = {
        "issuer": issuer,
        "credential_configuration_id": credential_config,
        "subject": {"national_id": SUBJECT_ID, "name": SUBJECT_NAME},
        "claim": {"person-is-alive": True},
        "holder": HOLDER_DID,
        "issued_at_unix": issued_at,
        "expires_at_unix": issued_at + 90 * 24 * 60 * 60,
        "raw_sd_jwt": "[simulated playground credential value hidden]",
    }
    return {
        "step_id": step_id,
        "friendly": {
            "title": "Maria's wallet card is ready to inspect.",
            "message": "The friendly view shows the issuer, subject, claim, and holder binding without exposing a raw credential secret.",
            "status": "done",
            "facts": [
                {"label": "Credential", "value": "Vital Status credential"},
                {"label": "Subject", "value": f"{SUBJECT_NAME} ({SUBJECT_ID})"},
                {"label": "Vital status current", "value": "Yes"},
                {"label": "Holder-bound", "value": "Yes"},
                {"label": "Raw credential printed", "value": "No"},
            ],
        },
        "request_source": simulated_request_source(
            "wallet://credential-request",
            {"credential_configuration_id": credential_config, "holder_did": HOLDER_DID, "proof": "[wallet proof hidden]"},
        ),
        "response_source": simulated_response(credential),
    }
