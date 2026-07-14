#!/usr/bin/env python3
"""Allowlisted Claims Explorer helpers for the Registry Lab homepage."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from . import discovery
from .common import (
    CLAIM_RESULT_FORMAT,
    ExplorerInputError,
    auth_header_pair,
    credential_by_id,
    credential_display,
    credential_for_execution,
    display_auth_header_pair,
    error_payload,
    http_json,
    joined_url,
    require_keys,
    request_source,
    safe_curl,
    service_url,
    source_response,
    unknown_id_error,
)


SELF_ATTESTED_SERVICE_ID = "self-attested-notary"
SELF_ATTESTED_CLAIM_ID = "applicant-declaration"
SELF_ATTESTED_PURPOSE = "application-processing"
CLAIM_SERVICE_ORDER = [SELF_ATTESTED_SERVICE_ID]

CLAIM_SERVICES: dict[str, dict[str, Any]] = {
    SELF_ATTESTED_SERVICE_ID: {
        "id": SELF_ATTESTED_SERVICE_ID,
        "label": "Self-attested Notary",
        "service_id": SELF_ATTESTED_SERVICE_ID,
        "base_url": "https://self-attested-notary.lab.registrystack.org",
        "client_credential_id": "self-attested-evidence",
        "default_subject": "demo-applicant",
        "default_identifier_scheme": "applicant_id",
        "default_purpose": SELF_ATTESTED_PURPOSE,
        "related_registry_ids": [],
        "availability": "hosted",
        "default_claim": SELF_ATTESTED_CLAIM_ID,
        "claims": {
            SELF_ATTESTED_CLAIM_ID: {
                "id": SELF_ATTESTED_CLAIM_ID,
                "title": "Applicant declaration",
                "value_type": "boolean",
                "default_disclosure": "predicate",
                "allowed_disclosures": ["predicate", "redacted"],
                "formats": [CLAIM_RESULT_FORMAT],
                "relay_fields_used": [],
                "source": {
                    "acquisition_path": "self_attested",
                    "authority": "applicant",
                    "registry_consulted": False,
                },
            }
        },
    }
}


def claim_service_ids() -> list[str]:
    return list(CLAIM_SERVICE_ORDER)


def _claim_service_catalog(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not config:
        return CLAIM_SERVICES
    services = discovery.discover_claim_services(config, CLAIM_SERVICES, CLAIM_SERVICE_ORDER)
    for service in services.values():
        _apply_credential_defaults(config, service)
    return services


def _apply_credential_defaults(config: dict[str, Any], service: dict[str, Any]) -> None:
    credential = credential_by_id(config, str(service.get("client_credential_id", "")))
    for key in ("default_purpose", "default_subject", "default_identifier_scheme"):
        value = str(credential.get(key, "")).strip()
        if value:
            service[key] = value


def claim_service_config(service_id: str) -> dict[str, Any]:
    return claim_service_config_for({}, service_id)


def claim_service_config_for(config: dict[str, Any], service_id: str) -> dict[str, Any]:
    services = _claim_service_catalog(config)
    if service_id not in services:
        raise ExplorerInputError(
            "explorer.unknown_claim_service",
            "Unknown claim service id.",
            field="service_id",
            allowed=claim_service_ids(),
        )
    return services[service_id]


def claim_catalog_payload(config: dict[str, Any]) -> dict[str, Any]:
    services = _claim_service_catalog(config)
    return {
        "ok": True,
        "claim_services": [_service_summary(services[service_id], config) for service_id in CLAIM_SERVICE_ORDER],
        "default_service_id": SELF_ATTESTED_SERVICE_ID,
        "default_format": CLAIM_RESULT_FORMAT,
    }


def claim_metadata_payload(config: dict[str, Any], service_id: str) -> dict[str, Any]:
    if service_id not in CLAIM_SERVICES:
        return unknown_id_error("claim_service", service_id, claim_service_ids())
    service = claim_service_config_for(config, service_id)
    payload = _service_summary(service, config)
    payload["claims"] = deepcopy(list(service["claims"].values()))
    return {"ok": True, "claim_service": payload}


def default_self_attested_claims_payload(
    config: dict[str, Any], *, run_live: bool = False, timeout: float = 8.0
) -> dict[str, Any]:
    service = claim_service_config_for(config, SELF_ATTESTED_SERVICE_ID)
    request = build_evaluation_request(
        config,
        SELF_ATTESTED_SERVICE_ID,
        SELF_ATTESTED_CLAIM_ID,
        subject=service["default_subject"],
        identifier_scheme=service["default_identifier_scheme"],
        disclosure="predicate",
        result_format=CLAIM_RESULT_FORMAT,
        purpose=service["default_purpose"],
    )
    if not run_live:
        return {
            **request,
            "mode": "preview",
            "answer": _preview_evaluation_answer(SELF_ATTESTED_CLAIM_ID),
            "source": deepcopy(service["claims"][SELF_ATTESTED_CLAIM_ID]["source"]),
            "response_source": {
                "status": "preview",
                "headers": {"content-type": "application/json; charset=utf-8"},
                "body": {"results": [_preview_evaluation_answer(SELF_ATTESTED_CLAIM_ID)]},
                "error": "",
            },
        }
    return run_evaluation(
        config,
        SELF_ATTESTED_SERVICE_ID,
        {
            "claim_id": SELF_ATTESTED_CLAIM_ID,
            "subject": service["default_subject"],
            "identifier_scheme": service["default_identifier_scheme"],
            "disclosure": "predicate",
            "format": CLAIM_RESULT_FORMAT,
            "purpose": service["default_purpose"],
        },
        timeout=timeout,
    )


def retry_unavailable_payload(service: dict[str, Any]) -> dict[str, Any]:
    return {
        "title": f"{service['label']} is unavailable from this homepage process.",
        "message": "The explorer can retry the same allowlisted evaluation when the service and demo token are available.",
        "retry": {
            "service_id": service["id"],
            "claim_id": service["default_claim"],
            "subject": service["default_subject"],
        },
    }


def validate_evaluation_input(
    service_id: str, body: dict[str, Any], config: dict[str, Any] | None = None
) -> dict[str, Any]:
    require_keys(
        body,
        {"claim_id", "subject", "identifier_scheme", "target", "disclosure", "format", "purpose"},
    )
    service = claim_service_config_for(config or {}, service_id)
    claim_id = str(body.get("claim_id", service["default_claim"]))
    if claim_id not in service["claims"]:
        raise ExplorerInputError(
            "explorer.unsupported_claim",
            "This claim is not available for the selected claim service.",
            field="claim_id",
            allowed=sorted(service["claims"]),
        )
    claim = service["claims"][claim_id]
    target = body.get("target")
    if target is not None and not isinstance(target, dict):
        raise ExplorerInputError("explorer.invalid_target", "Target must be an object.", field="target")
    subject, identifier_scheme = _subject_from_target(target if isinstance(target, dict) else {})
    subject = str(body.get("subject", "")).strip() or subject
    if not subject:
        raise ExplorerInputError("explorer.missing_subject", "Subject value is required.", field="subject")
    identifier_scheme = (
        str(body.get("identifier_scheme", "")).strip()
        or identifier_scheme
        or service["default_identifier_scheme"]
    )
    disclosure = str(body.get("disclosure", claim["default_disclosure"]))
    if disclosure not in claim["allowed_disclosures"]:
        raise ExplorerInputError(
            "explorer.unsupported_disclosure",
            "This disclosure value is not supported for the selected claim.",
            field="disclosure",
            allowed=claim["allowed_disclosures"],
        )
    result_format = str(body.get("format", CLAIM_RESULT_FORMAT))
    if result_format not in claim["formats"]:
        raise ExplorerInputError(
            "explorer.unsupported_format",
            "This format is not supported for the selected claim.",
            field="format",
            allowed=claim["formats"],
        )
    purpose = str(body.get("purpose", "")).strip() or str(service["default_purpose"])
    return {
        "service": service,
        "claim": claim,
        "claim_id": claim_id,
        "subject": subject,
        "identifier_scheme": identifier_scheme,
        "target": deepcopy(target) if isinstance(target, dict) else None,
        "disclosure": disclosure,
        "format": result_format,
        "purpose": purpose,
    }


def build_evaluation_request(
    config: dict[str, Any],
    service_id: str,
    claim_id: str,
    *,
    subject: str,
    identifier_scheme: str,
    disclosure: str,
    result_format: str,
    purpose: str,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validation_body: dict[str, Any] = {
        "claim_id": claim_id,
        "subject": subject,
        "identifier_scheme": identifier_scheme,
        "disclosure": disclosure,
        "format": result_format,
        "purpose": purpose,
    }
    if target is not None:
        validation_body["target"] = target
    validated = validate_evaluation_input(service_id, validation_body, config)
    service = validated["service"]
    credential = credential_for_execution(config, service["client_credential_id"])
    display_name, display_value = display_auth_header_pair(credential)
    body = evaluation_body(
        validated["subject"],
        validated["claim_id"],
        id_scheme=validated["identifier_scheme"],
        disclosure=validated["disclosure"],
        result_format=validated["format"],
        target=validated["target"],
    )
    headers = {
        display_name: display_value,
        "Content-Type": "application/json",
        "Data-Purpose": validated["purpose"],
    }
    url = evaluation_url(config, service)
    return {
        "ok": True,
        "service_id": service_id,
        "claim_id": validated["claim_id"],
        "claim": deepcopy(validated["claim"]),
        "request_source": request_source("POST", url, headers, body),
        "curl": safe_curl("POST", url, headers, body),
        "technical": {
            "disclosure": validated["disclosure"],
            "format": validated["format"],
            "credential_id": service["client_credential_id"],
        },
    }


def run_evaluation(
    config: dict[str, Any], service_id: str, body: dict[str, Any], *, timeout: float = 8.0
) -> dict[str, Any]:
    validated = validate_evaluation_input(service_id, body, config)
    built = build_evaluation_request(
        config,
        service_id,
        validated["claim_id"],
        subject=validated["subject"],
        identifier_scheme=validated["identifier_scheme"],
        disclosure=validated["disclosure"],
        result_format=validated["format"],
        purpose=validated["purpose"],
        target=validated["target"],
    )
    service = validated["service"]
    credential = credential_for_execution(config, service["client_credential_id"])
    if not credential.get("token"):
        answer = _preview_evaluation_answer(validated["claim_id"])
        return {
            **built,
            "mode": "preview",
            "answer": answer,
            "source": deepcopy(validated["claim"]["source"]),
            "data_minimization": data_minimization_readout(validated["claim"]),
            "unavailable": retry_unavailable_payload(service),
            "response_source": {
                "status": "preview",
                "headers": {"content-type": "application/json; charset=utf-8"},
                "body": {"results": [answer]},
                "error": "",
            },
        }
    headers = _execution_headers(credential, built["request_source"]["headers"])
    result = http_json(
        "POST",
        evaluation_url(config, service),
        headers,
        built["request_source"]["body"],
        timeout=timeout,
    )
    return {
        **built,
        "mode": "live" if result.status is not None else "retry",
        "answer": _answer_from_response(result.body, validated["claim_id"]),
        "source": deepcopy(validated["claim"]["source"]),
        "data_minimization": data_minimization_readout(validated["claim"]),
        "response_source": source_response(result),
    }


def evaluation_body(
    subject: str,
    claim_id: str,
    *,
    id_scheme: str,
    disclosure: str,
    result_format: str = CLAIM_RESULT_FORMAT,
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "target": deepcopy(target)
        if target is not None
        else {"type": "Person", "identifiers": [{"scheme": id_scheme, "value": subject}]},
        "claims": [claim_id],
        "disclosure": disclosure,
        "format": result_format,
    }


def _subject_from_target(target: dict[str, Any]) -> tuple[str, str]:
    identifiers = target.get("identifiers")
    if isinstance(identifiers, list):
        for identifier in identifiers:
            if not isinstance(identifier, dict):
                continue
            scheme = str(identifier.get("scheme") or "").strip()
            value = str(identifier.get("value") or "").strip()
            if scheme and value:
                return value, scheme
    return "", ""


def data_minimization_readout(claim: dict[str, Any]) -> dict[str, Any]:
    returned_count = 1 if claim.get("default_disclosure") in {"predicate", "value", "redacted"} else 0
    return {
        "source_fields_used": 0,
        "returned_to_service": returned_count,
        "raw_row_returned": "not applicable",
        "Source fields used": 0,
        "Returned to relying service": returned_count,
        "Raw row returned": "not applicable",
    }


def claim_service_error_payload(service_id: str) -> dict[str, Any]:
    return unknown_id_error("claim_service", service_id, claim_service_ids())


def invalid_evaluation_payload(error: ExplorerInputError) -> dict[str, Any]:
    return error.payload()


def evaluation_url(config: dict[str, Any], service: dict[str, Any]) -> str:
    return service_url(
        config,
        service["client_credential_id"],
        "/v1/evaluations",
        fallback_base_url=service["base_url"],
    )


def controlled_exception_payload(error: Exception) -> dict[str, Any]:
    if isinstance(error, ExplorerInputError):
        return error.payload()
    return error_payload("explorer.invalid_evaluation", "The explorer evaluation request is invalid.")


def _service_summary(service: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": service["id"],
        "label": service["label"],
        "service_id": service["service_id"],
        "base_url": service["base_url"],
        "default_claim": service["default_claim"],
        "default_subject": service["default_subject"],
        "default_identifier_scheme": service["default_identifier_scheme"],
        "default_purpose": service["default_purpose"],
        "related_registry_ids": [],
        "availability": service["availability"],
        "credential": credential_display(config, service["client_credential_id"]),
        "discovery": deepcopy(service.get("discovery", {"status": "overlay", "source": "overlay"})),
        "claims": [deepcopy(claim) for claim in service["claims"].values()],
    }


def _execution_headers(credential: dict[str, Any], display_headers: dict[str, str]) -> dict[str, str]:
    auth_name, auth_value = auth_header_pair(credential)
    headers = dict(display_headers)
    headers[auth_name] = auth_value
    return headers


def _preview_evaluation_answer(claim_id: str) -> dict[str, Any]:
    return {
        "claim_id": claim_id,
        "satisfied": True,
        "preview": True,
        "source": "self_attested",
    }


def _answer_from_response(body: Any, claim_id: str) -> dict[str, Any]:
    if not isinstance(body, dict):
        return {}
    results = body.get("results") or body.get("claim_results") or []
    if isinstance(results, list):
        for item in results:
            if isinstance(item, dict) and item.get("claim_id") == claim_id:
                return item
        if results and isinstance(results[0], dict):
            return results[0]
    return body
