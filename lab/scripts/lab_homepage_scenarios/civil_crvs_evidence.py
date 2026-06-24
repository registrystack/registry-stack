#!/usr/bin/env python3
"""CRVS Birth Evidence and Marriage Evidence guided scenarios."""

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


SERVICE_NAME = "Civil Notary"
CREDENTIAL_ID = "civil-notary-evidence"
DEFAULT_URL = "http://127.0.0.1:4321"
PURPOSE = "https://demo.example.gov/purpose/civil-certificate-evidence"


def _registration_target_inputs(target_type: str) -> list[dict[str, Any]]:
    return [
        {
            "target_type": target_type,
            "method": "certificate_registration_number",
            "groups": [
                {
                    "inputs": [
                        {
                            "path": "target.identifiers.registration_number",
                            "kind": "identifier",
                            "name": "registration_number",
                            "label": "Registration number",
                        }
                    ]
                }
            ],
        }
    ]


def _birth_demographic_target_inputs() -> list[dict[str, Any]]:
    return [
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
                            "path": "target.attributes.surname",
                            "kind": "attribute",
                            "name": "surname",
                            "label": "Surname",
                        },
                        {
                            "path": "target.attributes.birth_date",
                            "kind": "attribute",
                            "name": "birth_date",
                            "label": "Birth date",
                        },
                    ]
                }
            ],
        }
    ]


def _claims_body(claim_id: str, target_inputs: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "data": [
            {
                "id": claim_id,
                "target_inputs": target_inputs,
            }
        ]
    }


class CrvsEvidenceScenario:
    def __init__(
        self,
        *,
        scenario_id: str,
        short_title: str,
        title: str,
        claim_id: str,
        subject_name: str,
        registration_number: str,
        target_type: str,
        attestation_id: str,
        evidence_label: str,
        profile_attributes: dict[str, Any] | None = None,
        target_inputs: list[dict[str, Any]] | None = None,
        lookup_profile_id: str = "registration-number",
        lookup_profile_label: str = "Registration number",
        lookup_key_label: str = "Registration number",
        target_input_receipt: str = "Registration number",
    ) -> None:
        self.SCENARIO_ID = scenario_id
        self.short_title = short_title
        self.title = title
        self.claim_id = claim_id
        self.subject_name = subject_name
        self.registration_number = registration_number
        self.target_type = target_type
        self.public_attestation = attestation(attestation_id)
        self.evidence_label = evidence_label
        self.profile_attributes = profile_attributes or {}
        self.lookup_profile_id = lookup_profile_id
        self.lookup_profile_label = lookup_profile_label
        self.lookup_key_label = lookup_key_label
        self.target_input_receipt = target_input_receipt
        self.expected_claims_body = _claims_body(claim_id, target_inputs or _registration_target_inputs(target_type))

    def story(self) -> dict[str, Any]:
        return {
            "id": self.SCENARIO_ID,
            "title": self.title,
            "short_title": self.short_title,
            "proves": f"The Civil Notary can discover and evaluate a minimized {self.evidence_label} claim from the local lab UI.",
            "domain": "Civil registry",
            "availability": "hosted",
            "availability_state": {"state": "hosted", "label": "Hosted", "runnable": True},
            "intro": (
                f"The Explorer asks which inputs the {self.evidence_label} claim accepts, then sends the registration number "
                "using only the target inputs published for that claim."
            ),
            "actor": "Evidence requesting service",
            "requester": {"name": "Evidence requesting service", "purpose": PURPOSE},
            "subject": {"name": self.subject_name, "identifier": self.registration_number},
            "requested_attestations": [self.public_attestation],
            "lookup_profile": {"id": self.lookup_profile_id, "label": self.lookup_profile_label},
            "non_disclosure": [
                "Full civil registry row",
                "Unrequested personal attributes",
                "Certificate source record fields beyond the requested result",
            ],
            "proof_facts": [
                "The Notary publishes target_inputs in claim discovery.",
                f"The evaluation request uses {self.target_input_receipt}.",
                "The response is a minimized claim result.",
            ],
            "boundary": {
                "allowed": f"Ask for {self.public_attestation['display_name']} using the published input contract.",
                "not_allowed": "Read certificate rows directly or send fields the claim did not request.",
            },
            "steps": [
                {
                    "id": "discover",
                    "label": "Discover the input contract",
                    "prompt": "Ask the Civil Notary which target inputs this evidence claim accepts.",
                    "button": "Discover claim inputs",
                    "request_summary": "GET /v1/claims and inspect target_inputs for the evidence claim.",
                },
                {
                    "id": "evaluate",
                    "label": "Evaluate the evidence claim",
                    "prompt": f"Use the published contract to evaluate the claim with {self.lookup_profile_label.lower()}.",
                    "button": "Evaluate evidence claim",
                    "request_summary": f"POST an evaluation with {self.target_input_receipt}.",
                    "reuses": [
                        {"label": "Attestation", "value": self.public_attestation["display_name"]},
                        {"label": "Lookup profile", "value": self.lookup_profile_label},
                    ],
                },
            ],
            "receipt": [
                {"label": "Target inputs", "value": self.target_input_receipt},
                {"label": "Contract source", "value": "Notary /v1/claims discovery"},
                {"label": "Raw civil row exposed", "value": "No"},
            ],
        }

    def preview_step(self, config: dict[str, Any], step_id: str) -> dict[str, Any]:
        credential = _credential(config)
        display_headers = _display_headers(credential)
        if step_id == "discover":
            return request_source("GET", _claims_url(config), display_headers, internal=True)
        if step_id == "evaluate":
            body, selection = self._evaluation_body(self.expected_claims_body)
            return request_source(
                "POST",
                _evaluations_url(config),
                {**display_headers, "Content-Type": "application/json"},
                body,
                internal=True,
                target_input_selection=selection,
            )
        return {}

    def run_step(self, config: dict[str, Any], step_id: str) -> dict[str, Any]:
        if step_id == "discover":
            return self._discover(config, step_id)
        if step_id == "evaluate":
            return self._evaluate(config, step_id)
        return standard_error_result(step_id)

    def _profile(self) -> dict[str, Any]:
        return person_profile(
            self.registration_number,
            id_scheme="registration_number",
            attributes=self.profile_attributes,
            target_type=self.target_type,
        )

    def _evaluation_body(self, claims_body: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        return evaluation_body_from_claim_metadata(
            claims_body,
            self._profile(),
            [self.claim_id],
            disclosure="value",
            fmt=CLAIM_RESULT_FORMAT,
        )

    def _discover(self, config: dict[str, Any], step_id: str) -> dict[str, Any]:
        credential = _credential(config)
        if not credential.get("token"):
            return _missing_token_result(config, step_id, self.preview_step(config, step_id))
        real_headers, display_headers = _headers(credential)
        result = http_json("GET", _claims_url(config), real_headers)
        claims = claims_catalog(result.body)
        claim_ids = {claim.get("id") for claim in claims if isinstance(claim, dict)}
        facts = target_input_facts(result.body, [self.claim_id])
        published = self.claim_id in claim_ids and any(fact.get("label") == "Input metadata" for fact in facts)
        return {
            "step_id": step_id,
            "friendly": {
                "title": "The Civil Notary publishes the evidence input contract." if published else "Evidence claim discovery needs attention.",
                "message": (
                    "The target_inputs metadata says this claim can be evaluated with a registration number."
                    if published
                    else "The evidence claim or its target_inputs metadata was not present in /v1/claims."
                ),
                "status": "done" if published else "needs_attention",
                "facts": [
                    {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                    {"label": "Claim", "value": self.claim_id if self.claim_id in claim_ids else "Missing"},
                ]
                + facts,
            },
            "request_source": request_source("GET", _claims_url(config), display_headers, internal=True),
            "response_source": source_response(result),
        }

    def _evaluate(self, config: dict[str, Any], step_id: str) -> dict[str, Any]:
        credential = _credential(config)
        if not credential.get("token"):
            return _missing_token_result(config, step_id, self.preview_step(config, step_id))
        real_headers, display_headers = _headers(credential)
        discovery = http_json("GET", _claims_url(config), real_headers)
        body, selection = self._evaluation_body(discovery.body)
        if selection.get("source") != "target_inputs":
            return {
                "step_id": step_id,
                "friendly": {
                    "title": "The Civil Notary has not published the evidence input contract.",
                    "message": "The Explorer did not send the evaluation because /v1/claims did not describe the required target inputs.",
                    "status": "needs_attention",
                    "facts": [
                        {"label": "HTTP status", "value": discovery.status if discovery.status is not None else "No response"},
                        {"label": "Claim", "value": self.claim_id},
                        {"label": "Evaluation sent", "value": "No"},
                    ]
                    + target_input_facts(discovery.body, [self.claim_id]),
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
            "friendly": self._summarize_evaluation(result),
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

    def _summarize_evaluation(self, result) -> dict[str, Any]:
        item = result_item(result.body, self.claim_id)
        answer = observed_answer(item)
        ok = ok_status(result.status)
        if ok:
            title = f"The {self.evidence_label} claim was evaluated."
            message = "The Notary returned a minimized claim result from the published target input."
            status = "done"
        else:
            title = f"The {self.evidence_label} evaluation needs attention."
            message = "The Notary did not return the expected evidence result. Inspect the response source."
            status = "needs_attention"
        return {
            "title": title,
            "message": message,
            "status": status,
            "facts": [
                {"label": "HTTP status", "value": result.status if result.status is not None else "No response"},
                {"label": "Subject", "value": self.subject_name},
                {"label": "Lookup key", "value": self.lookup_key_label},
                {"label": "Answer", "value": "Yes" if answer is True else ("No" if answer is False else "Returned" if ok else "Unknown")},
            ],
        }


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


def _missing_token_result(config: dict[str, Any], step_id: str, preview: dict[str, Any]) -> dict[str, Any]:
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
        "request_source": preview,
        "response_source": {"note": "No Civil Notary evidence credential configured, so the request was not sent."},
    }


BIRTH = CrvsEvidenceScenario(
    scenario_id="civil-birth-evidence",
    short_title="Birth Evidence",
    title="Can a service request Birth Evidence using a registration number?",
    claim_id="birth.certificate_summary",
    subject_name="Birth registration B-2016-N-1001",
    registration_number="B-2016-N-1001",
    target_type="Person",
    attestation_id="birth-certificate-attestation",
    evidence_label="Birth Evidence",
)

BIRTH_DEMOGRAPHICS = CrvsEvidenceScenario(
    scenario_id="civil-birth-evidence-demographics",
    short_title="Birth Evidence by Demographics",
    title="Can a service request Birth Evidence using name and date of birth?",
    claim_id="birth.certificate_summary_by_demographics",
    subject_name="Rafael Aquino",
    registration_number="Rafael Aquino, born 2019-01-15",
    target_type="Person",
    attestation_id="birth-certificate-attestation",
    evidence_label="Birth Evidence",
    profile_attributes={
        "given_name": "Rafael",
        "surname": "Aquino",
        "birth_date": "2019-01-15",
    },
    target_inputs=_birth_demographic_target_inputs(),
    lookup_profile_id="by-demographics",
    lookup_profile_label="Name and date of birth",
    lookup_key_label="Demographics",
    target_input_receipt="target.attributes.given_name, surname, and birth_date",
)

MARRIAGE = CrvsEvidenceScenario(
    scenario_id="civil-marriage-evidence",
    short_title="Marriage Evidence",
    title="Can a service request Marriage Evidence using a registration number?",
    claim_id="marriage.certificate_summary",
    subject_name="Marriage registration MR-2026-2001",
    registration_number="MR-2026-2001",
    target_type="Marriage",
    attestation_id="marriage-certificate-attestation",
    evidence_label="Marriage Evidence",
)
